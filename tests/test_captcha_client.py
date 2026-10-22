"""Client tests for the human CAPTCHA sign-in hand-off.

The mocked portal enforces what the real one does: /Home/Login only accepts the
antiforgery token from the form page and the session cookie that page set, and a
CAPTCHA refusal names the CAPTCHA. Proofs must be single-use and never leak.
"""

import json
import logging
import traceback
import urllib.parse

import pytest
import requests
import requests_mock

from custom_components.pseg.const import OKTA_HOST, PORTAL_BASE_URL, PORTAL_HOST
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegLoginRedirected,
    PsegLoginRejected,
    PsegSecurityStepRequired,
    PsegTransientError,
)

AF_TOKEN = "af-token-9f3c"
SESSION_COOKIE = "session-cookie-a71e"
PROOF = "proof-secret-4b2d-once"
LOGIN_PAGE = (
    "<html><form>"
    f'<input type="hidden" name="__RequestVerificationToken" value="{AF_TOKEN}">'
    "</form></html>"
)
DASHBOARD = "<html><title>Dashboard</title>Dashboard</html>"


def _client() -> PsegClient:
    client = PsegClient(email="user@example.com", password="synthetic-password")
    # requests_mock bypasses requests' Set-Cookie extraction, so seed the same
    # session cookie the login form page sets; the POST pairing check then proves
    # the proof request reuses the jar that rendered the form.
    client.session.cookies.set(
        "ASP.NET_SessionId", SESSION_COOKIE, domain=PORTAL_HOST, path="/", secure=True
    )
    return client


def _mock_login_page(m: requests_mock.Mocker) -> None:
    m.get(
        f"{PORTAL_BASE_URL}/",
        text=LOGIN_PAGE,
        headers={"Set-Cookie": f"ASP.NET_SessionId={SESSION_COOKIE}; Path=/"},
    )


def _mock_dashboard(m: requests_mock.Mocker) -> None:
    m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD)


def _assert_af_pairing(request: requests.PreparedRequest) -> None:
    """The POST must carry the form token in body and header, plus the form cookie."""
    body = urllib.parse.parse_qs(request.body or "")
    assert body["__RequestVerificationToken"] == [AF_TOKEN]
    assert request.headers["RequestVerificationToken"] == AF_TOKEN
    assert f"ASP.NET_SessionId={SESSION_COOKIE}" in request.headers["Cookie"]


def _captcha_reply(m: requests_mock.Mocker, message: str = "Please provide a valid login captcha.") -> None:
    m.post(
        f"{PORTAL_BASE_URL}/Home/Login",
        json={"Data": {"LoginErrorMessage": message, "RecaptchaOnLogin": True}},
    )


def test_captcha_error_message_raises_structured_captcha() -> None:
    """The real account's exact error is classified as a solvable CAPTCHA."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        _captcha_reply(m)
        with pytest.raises(PsegCaptchaRequired):
            client.login_local()
        body = urllib.parse.parse_qs(m.request_history[-1].body or "")
    assert "g-recaptcha-response" not in body


def test_recaptcha_flag_raises_structured_captcha() -> None:
    """The RecaptchaOnLogin flag alone is enough to route to the human step."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"Data": {"RecaptchaOnLogin": True}},
        )
        with pytest.raises(PsegCaptchaRequired):
            client.login_local()


def test_captcha_phrase_outside_data_is_still_structured_captcha() -> None:
    """The observed server phrase is honoured even when it is not in Data."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={
                "Success": False,
                "Message": "Please provide a valid login captcha.",
            },
        )
        with pytest.raises(PsegCaptchaRequired):
            client.login_local()


def test_structured_success_with_incidental_phrase_still_signs_in() -> None:
    """A success whose page text happens to carry the phrase is not sent to CAPTCHA."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        _mock_dashboard(m)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={
                "Data": {"RedirectUrl": "/Dashboard"},
                "Message": "Please provide a valid login captcha.",
            },
        )
        assert client.login_local() is True
    assert client.sso_renewals == 1


def test_wrong_password_is_not_mislabelled_as_captcha() -> None:
    """Invalid credentials stay a plain rejection, never a CAPTCHA step."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"Data": {"LoginErrorMessage": "Invalid email address or password"}},
        )
        with pytest.raises(PsegLoginRejected) as err:
            client.login_local()
    assert not isinstance(err.value, PsegCaptchaRequired)
    assert not isinstance(err.value, PsegSecurityStepRequired)


def test_security_question_is_not_a_captcha() -> None:
    """A security question or password change has its own structured rejection."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"Data": {"SecretQuestionError": True}},
        )
        with pytest.raises(PsegSecurityStepRequired) as err:
            client.login_local()
    assert not isinstance(err.value, PsegCaptchaRequired)


def test_prepared_proof_signs_in_once_with_paired_antiforgery_state() -> None:
    """One prepared challenge, one proof, one verified dashboard — no second login."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        _mock_dashboard(m)
        post = m.post(f"{PORTAL_BASE_URL}/Home/Login", json={"Data": {}})

        client.prepare_login_captcha()
        assert client.submit_login_captcha(PROOF) is True

        assert post.call_count == 1
        _assert_af_pairing(m.request_history[-2])
        body = urllib.parse.parse_qs(m.request_history[-2].body or "")
        assert body["g-recaptcha-response"] == [PROOF]
        assert m.request_history[-1].url == f"{PORTAL_BASE_URL}/Dashboard"

    assert client.sso_renewals == 1
    assert client.session_established_at is not None
    assert client._pending_login_token == ""


def test_submit_without_prepare_fetches_its_own_antiforgery_token() -> None:
    """A lost pending token is re-read from the form, never guessed."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        _mock_dashboard(m)
        post = m.post(f"{PORTAL_BASE_URL}/Home/Login", json={"Data": {}})

        client.submit_login_captcha(PROOF)

        assert post.call_count == 1
        _assert_af_pairing(m.request_history[-2])


def test_empty_proof_is_rejected_before_any_request() -> None:
    """Home Assistant never posts a blank proof."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        with pytest.raises(ValueError):
            client.submit_login_captcha("   ")
        assert m.called is False


def test_network_error_on_proof_is_not_retried() -> None:
    """A proof whose reply was lost may already be spent: exactly one POST, no retry."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        post = m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            exc=requests.ConnectionError("connection reset"),
        )
        with pytest.raises(PsegTransientError):
            client.submit_login_captcha(PROOF)

    assert post.call_count == 1


def test_proof_never_appears_in_logs_errors_diagnostics_or_cookies(caplog) -> None:
    """The one-use proof stays out of every diagnostic surface."""
    caplog.set_level(logging.DEBUG)
    client = _client()
    error_text = ""
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"Data": {"LoginErrorMessage": "Please provide a valid login captcha."}},
        )
        with pytest.raises(PsegCaptchaRequired) as err:
            client.submit_login_captcha(PROOF)
        error_text = repr(err.value)

    serialized = json.dumps(client.export_cookies(), sort_keys=True)
    for surface in (caplog.text, error_text, serialized, client.auth_diagnostics()):
        assert PROOF not in surface
    assert all(PROOF not in str(value) for value in vars(client).values())


def test_successful_proof_is_not_kept_on_the_client(caplog) -> None:
    """After a successful hand-off the proof is gone from memory and logs."""
    caplog.set_level(logging.DEBUG)
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        _mock_dashboard(m)
        m.post(f"{PORTAL_BASE_URL}/Home/Login", json={"Data": {}})
        client.prepare_login_captcha()
        client.submit_login_captcha(PROOF)

    assert PROOF not in caplog.text
    assert PROOF not in json.dumps(client.export_cookies())
    assert all(PROOF not in str(value) for value in vars(client).values())


def test_proof_post_redirect_to_okta_never_forwards_the_proof() -> None:
    """A 307 after the proof POST must not replay the proof onto the Okta host."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        post = m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            status_code=307,
            headers={"Location": f"https://{OKTA_HOST}/synthetic-proof-route"},
        )
        okta = m.post(
            f"https://{OKTA_HOST}/synthetic-proof-route",
            text="must not receive the proof",
        )
        with pytest.raises(PsegLoginRedirected) as err:
            client.submit_login_captcha(PROOF)

    assert post.call_count == 1
    assert okta.call_count == 0
    message = str(err.value) + repr(err.value)
    assert PROOF not in message
    assert "synthetic-proof-route" not in message


def test_transport_error_never_chains_the_proof_into_any_surface(caplog) -> None:
    """requests state can echo the POST body; the raised error must not carry it.

    A raw transport exception (message, __cause__, __context__, formatted traceback)
    can include a partial status line or request body, and that body holds the proof.
    """
    caplog.set_level(logging.DEBUG)
    client = _client()
    raw = requests.ConnectionError(
        f"307 Temporary Redirect for url: /Home/Login; body g-recaptcha-response={PROOF}"
    )
    raw.__cause__ = RuntimeError(f"cause carries {PROOF}")
    raw.__context__ = RuntimeError(f"context carries {PROOF}")

    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        post = m.post(f"{PORTAL_BASE_URL}/Home/Login", exc=raw)
        with pytest.raises(PsegTransientError) as err:
            client.submit_login_captcha(PROOF)

    error = err.value
    assert post.call_count == 1  # ambiguous failure: never retried
    surfaces = {
        "message": str(error),
        "repr": repr(error),
        "traceback": "".join(traceback.format_exception(error)),
        "logs": caplog.text,
        "diagnostics": client.auth_diagnostics(),
        "cookies": json.dumps(client.export_cookies()),
    }
    for name, surface in surfaces.items():
        assert PROOF not in surface, f"proof leaked into {name}"
    assert error.__cause__ is None
    assert error.__context__ is None


def test_transport_error_keeps_only_the_exception_class() -> None:
    """The safe message names the failure type, not the raw request state."""
    client = _client()
    with requests_mock.Mocker(session=client.session) as m:
        _mock_login_page(m)
        m.post(f"{PORTAL_BASE_URL}/Home/Login", exc=requests.Timeout("timed out"))
        with pytest.raises(PsegTransientError, match=r"\(Timeout\)"):
            client.submit_login_captcha(PROOF)

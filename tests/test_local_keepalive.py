"""Local-mode GET-only keepalive, cadence and the bounded cookie renewal."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
from unittest.mock import patch

from freezegun import freeze_time
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
import requests_mock

from custom_components.pseg.const import (
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_OKTA_SESSION_EXPIRED,
    AUTH_REASON_PORTAL_SESSION_EXPIRED,
    AUTH_REASON_REMEMBER_ME_REJECTED,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_RENEWAL_ADMISSION,
    DOMAIN,
    LOCAL_KEEPALIVE_INTERVAL_MINUTES,
    PORTAL_BASE_URL,
    PORTAL_HOST,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegOktaSessionExpired,
    PsegTransientError,
)

EMAIL = "fixture@example.invalid"
PASSWORD = "synthetic-secret-7731"
COOKIE_SECRET = "synthetic-cookie-9182"
PORTAL_COOKIE = f"MM_SID={COOKIE_SECRET}"
REMEMBER_PORTAL = f"MM_SID={COOKIE_SECRET}; MM_RememberMe=remember-token"
METER = "12345"
LOGGED_OUT_REDIRECT = {"status_code": 302, "headers": {"Location": "/"}}
PORTAL_HOME = "<html><body>Welcome</body></html>"
DASHBOARD = "<html><body>Dashboard</body></html>"
DASHBOARD_WITH_TOKEN = (
    '<html><input name="__RequestVerificationToken" value="af"/>Dashboard</html>'
)
DAILY_CHART = {
    "Data": {
        "series": [
            {
                "name": f"Meter #{METER}",
                "data": [{"y": 4.0, "hs": {"start": "10/22/2026"}}],
            }
        ]
    }
}
LOGIN_OK = {"AjaxResults": [], "Data": {}}
CAPTCHA_JSON = {"Data": {"RecaptchaOnLogin": True}}
LOGIN_PAGE_WITH_TOKEN = (
    '<html><form action="/Home/Login">'
    '<input name="LoginEmail"/><input id="LoginPassword"/>'
    '<input name="__RequestVerificationToken" value="af"/></form></html>'
)
SAML_AUTOPOST = (
    f'<form method="POST" action="{PORTAL_BASE_URL}/Saml/okta-prod/Acs">'
    '<input type="hidden" name="SAMLResponse" value="assertion"/></form>'
)


def test_keepalive_never_posts_a_saved_login_even_in_a_mixed_jar() -> None:
    """A mixed Okta+local jar renews on the portal, so its timer is GET-only."""
    client = PsegClient(okta_cookies="idx=x", email=EMAIL, password=PASSWORD)
    # The saved login is the usable renewal path: classify it as local even
    # though an Okta session cookie is still in the jar (review r1 finding 1).
    assert client.has_okta_session is True
    assert client.is_local_mode is True
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text="<html>home</html>")
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAML_AUTOPOST)
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()

    assert login.call_count == 0
    assert sso.call_count == 0
    assert client.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED


def test_three_minute_get_keepalive_keeps_local_session_alive() -> None:
    """A GET every 3 minutes survives an hour; one observed lapse was ~9-10 min."""
    client = PsegClient(email=EMAIL, password=PASSWORD, portal_cookies=PORTAL_COOKIE)
    assert client.is_local_mode is True
    portal = {"now": 0.0, "last_seen": 0.0}

    def dashboard(_request, context):
        if portal["now"] - portal["last_seen"] > 600:
            context.status_code = 302
            context.headers["Location"] = "/"
            return ""
        portal["last_seen"] = portal["now"]
        return DASHBOARD

    with (
        freeze_time("2026-10-22 12:00:00") as frozen,
        requests_mock.Mocker(session=client.session) as m,
    ):
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=dashboard)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAML_AUTOPOST)

        for _ in range(20):  # one hour at the coordinator's 3-minute cadence
            frozen.tick(timedelta(minutes=3))
            portal["now"] += 180
            assert client.keepalive() is True

        # Stop touching the portal: the idle expiry the old 10-min timer hit.
        frozen.tick(timedelta(seconds=601))
        portal["now"] += 601
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()

    assert login.call_count == 0
    assert sso.call_count == 0
    assert client.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED
    assert client.idle_gap_seconds == 601.0


def test_mixed_jar_uses_the_three_minute_get_keepalive() -> None:
    """Okta cookie + saved MyMeter login is portal-only: 3-min GET, never SSO.

    The client is host-restricted to the portal, so the old 10-minute SSO cadence
    let MM_SID lapse and then reauthed instead of warming the portal session.
    """
    client = PsegClient(
        okta_cookies="idx=okta-session",
        email=EMAIL,
        password=PASSWORD,
        portal_cookies=PORTAL_COOKIE,
    )
    assert client.has_okta_session is True
    assert client.has_login is True
    assert client.is_local_mode is True
    portal = {"now": 0.0, "last_seen": 0.0}

    def dashboard(_request, context):
        if portal["now"] - portal["last_seen"] > 600:
            context.status_code = 302
            context.headers["Location"] = "/"
            return ""
        portal["last_seen"] = portal["now"]
        return DASHBOARD

    with (
        freeze_time("2026-10-22 12:00:00") as frozen,
        requests_mock.Mocker(session=client.session) as m,
    ):
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=dashboard)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAML_AUTOPOST)

        for _ in range(20):  # one hour at the coordinator's 3-minute cadence
            frozen.tick(timedelta(minutes=3))
            portal["now"] += 180
            assert client.keepalive() is True

        # Stop touching the portal: the observed ~9-10 minute lapse the old timer hit.
        frozen.tick(timedelta(seconds=601))
        portal["now"] += 601
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()

    assert login.call_count == 0
    assert sso.call_count == 0
    assert client.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED
    assert client.idle_gap_seconds == 601.0


def test_keepalive_cadence_is_local_for_a_mixed_jar(hass: HomeAssistant) -> None:
    """A mixed Okta+local jar is scheduled on the 3-minute local interval."""
    mixed = PsegClient(okta_cookies="idx=x", email=EMAIL, password=PASSWORD)
    coord = PsegDataUpdateCoordinator(hass, mixed, {}, config_entry=None)

    assert coord.keepalive_interval() == timedelta(
        minutes=LOCAL_KEEPALIVE_INTERVAL_MINUTES
    )


def test_local_keepalive_is_get_only() -> None:
    """The local timer never POSTs /Home/Login, even with a saved password."""
    client = PsegClient(email=EMAIL, password=PASSWORD, portal_cookies=PORTAL_COOKIE)
    with requests_mock.Mocker(session=client.session) as m:
        dash = m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAML_AUTOPOST)
        for _ in range(5):
            assert client.keepalive() is True

    assert dash.call_count == 5
    assert login.call_count == 0
    assert sso.call_count == 0


def test_credentialless_local_keepalive_never_touches_okta() -> None:
    client = PsegClient(portal_cookies=PORTAL_COOKIE)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAML_AUTOPOST)
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()

    assert sso.called is False
    assert client.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED


def test_captcha_latch_blocks_a_second_credential_post() -> None:
    """One CAPTCHA demand latches the client until a human sign-in succeeds."""
    client = PsegClient(email=EMAIL, password=PASSWORD)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT, {"text": DASHBOARD}],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        login = m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            [{"json": CAPTCHA_JSON}, {"json": LOGIN_OK}],
        )

        with pytest.raises(PsegCaptchaRequired):
            client.ensure_session()
        assert login.call_count == 1
        assert client.auth_reason == AUTH_REASON_CAPTCHA_REQUIRED

        with pytest.raises(PsegCaptchaRequired):
            client.ensure_session()
        assert login.call_count == 1  # latched: the password is not posted again

        # The human proof goes through the config flow's own submit path.
        assert client.submit_login_captcha("human-proof") is True

    assert login.call_count == 2
    assert client._captcha_latched is False
    assert client.auth_reason is None


def test_keepalive_after_captcha_latch_sends_nothing() -> None:
    client = PsegClient(email=EMAIL, password=PASSWORD, portal_cookies=PORTAL_COOKIE)
    client._latch_captcha()
    with requests_mock.Mocker(session=client.session) as m:
        m.register_uri(requests_mock.ANY, requests_mock.ANY, text="unexpected")
        with pytest.raises(PsegCaptchaRequired):
            client.keepalive()
        assert m.request_history == []

    assert client.auth_reason == AUTH_REASON_CAPTCHA_REQUIRED


def test_okta_only_keepalive_still_uses_the_sso_round_trip() -> None:
    """Okta entries keep their 10-minute SAML keepalive unchanged."""
    client = PsegClient(okta_cookies="idx=x", portal_cookies=PORTAL_COOKIE)
    assert client.is_local_mode is False
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAML_AUTOPOST)
        m.post(f"{PORTAL_BASE_URL}/Saml/okta-prod/Acs", text="ok")
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        assert client.keepalive() is True

    assert login.call_count == 0
    assert client.sso_renewals == 1
    assert client.auth_reason is None


async def test_local_keepalive_captcha_starts_one_reauth(
    hass: HomeAssistant, caplog
) -> None:
    """A latched local keepalive reports captcha_required and reauth starts once."""
    caplog.set_level(logging.DEBUG)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
    )
    entry.add_to_hass(hass)
    client = PsegClient(email=EMAIL, password=PASSWORD)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    def latched() -> bool:
        client._mark_auth_failure(AUTH_REASON_CAPTCHA_REQUIRED)
        client.idle_gap_seconds = 192.0
        raise PsegCaptchaRequired("MyMeter is waiting for a solved CAPTCHA")

    with patch.object(client, "keepalive", side_effect=latched):
        await coord._async_keepalive(None)
        await hass.async_block_till_done()
        await coord._async_keepalive(None)
        await hass.async_block_till_done()

    assert coord.status == "auth_required"
    assert "captcha_required" in caplog.text
    assert "192 s ago" in caplog.text
    assert "Okta session expired" not in caplog.text
    flows = [
        flow
        for flow in hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        if flow["context"]["source"] == "reauth"
    ]
    assert len(flows) == 1
    assert flows[0]["context"]["entry_id"] == entry.entry_id


def test_okta_reason_is_reserved_for_okta_sessions() -> None:
    """A local client never reports okta_session_expired from the keepalive."""
    local = PsegClient(portal_cookies=PORTAL_COOKIE)
    with requests_mock.Mocker(session=local.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        with pytest.raises(PsegOktaSessionExpired):
            local.keepalive()
    assert local.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED
    assert local.auth_reason != AUTH_REASON_OKTA_SESSION_EXPIRED

    okta = PsegClient(okta_cookies=f"idx=x; sid={COOKIE_SECRET}")
    assert okta.has_okta_session is True
    assert okta.is_local_mode is False


# --- Bounded, cookie-only renewal on a typed local expiry (1.5.0 auth hardening) ---


def _remember_client() -> PsegClient:
    """Local client with a Remember Me cookie and this entry's known meter id."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    client.set_expected_meter_ids({METER})
    return client


def _mock_renewal(m, dashboard_responses) -> dict:
    """Mock the cookie-renewal sequence plus its DAILY identity check."""
    calls = {}
    calls["dashboard"] = m.get(
        f"{PORTAL_BASE_URL}/Dashboard", dashboard_responses
    )
    calls["home"] = m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
    calls["chart"] = m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
    calls["chart_data"] = m.get(
        f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=DAILY_CHART
    )
    calls["login"] = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
    calls["sso"] = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAML_AUTOPOST)
    return calls


def test_local_keepalive_renews_once_on_a_typed_expiry() -> None:
    """A sign-in page lets the portal re-issue MM_SID; the DAILY meter proves it."""
    client = _remember_client()
    with requests_mock.Mocker(session=client.session) as m:
        calls = _mock_renewal(
            m,
            [
                LOGGED_OUT_REDIRECT,  # the keepalive probe: typed auth expiry
                {"text": DASHBOARD_WITH_TOKEN},  # the renewal's own GET
            ],
        )
        assert client.keepalive() is True

    assert client.sso_renewals == 1
    assert client.last_sso_renewal is not None
    assert client.auth_reason is None
    assert client.okta_session_expired_at is None
    assert client.has_remember_me is True
    assert client.cookies_confirmed is True
    # Exactly one read-only DAILY chart, never the hourly leg or account writes.
    assert calls["chart"].call_count == 1
    assert calls["chart_data"].call_count == 1
    assert "UsageInterval=6" in calls["chart"].last_request.text
    assert calls["login"].call_count == 0
    assert calls["sso"].call_count == 0
    assert client._renewal_admission.sequences == 1


def test_keepalive_renewal_rolls_back_when_the_meter_does_not_match() -> None:
    """A renewed session that lands on another meter is never published or kept."""
    client = _remember_client()
    other_meter = {
        "Data": {
            "series": [
                {
                    "name": "Meter #99999",
                    "data": [{"y": 4.0, "hs": {"start": "10/22/2026"}}],
                }
            ]
        }
    }
    with requests_mock.Mocker(session=client.session) as m:
        calls = _mock_renewal(
            m, [LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}]
        )
        calls["chart_data"] = m.get(
            f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=other_meter
        )
        assert client.keepalive() is False

    # Transaction rolled back: no success stamp, no counter, no jar replacement.
    assert client.sso_renewals == 0
    assert client.last_sso_renewal is None
    assert client.auth_reason is None
    assert client.okta_session_expired_at is None
    assert client.idle_gap_seconds is None
    assert [c.value for c in client.session.cookies if c.name == "MM_SID"] == [
        COOKIE_SECRET
    ]
    assert client.has_remember_me is True
    assert client.cookies_confirmed is False
    # The attempt is still spent: the retry costs one of the two slots.
    assert client._renewal_admission.sequences == 1


def test_keepalive_renewal_requires_a_known_meter_identity() -> None:
    """Without a known meter id the session cannot be confirmed, so no chart read."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        calls = _mock_renewal(
            m, [LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}]
        )
        assert client.keepalive() is False

    assert calls["chart"].call_count == 0
    assert client.sso_renewals == 0
    assert client.cookies_confirmed is False


def test_keepalive_renewal_rolls_back_on_a_network_error() -> None:
    """A network failure restores the confirmed jar and telemetry, and is bounded."""
    client = _remember_client()
    with requests_mock.Mocker(session=client.session) as m:
        calls = _mock_renewal(
            m,
            [
                LOGGED_OUT_REDIRECT,
                {"exc": requests.ConnectionError("synthetic network down")},
            ],
        )
        assert client.keepalive() is False
        # A second call inside the 15-minute cooldown sends only the probe.
        assert client.keepalive() is False

    # One home fetch: the probe's own 302 hop, never a renewal landing retry.
    assert calls["home"].call_count == 1
    assert calls["chart"].call_count == 0
    assert client.sso_renewals == 0
    assert client.auth_reason is None
    assert [c.value for c in client.session.cookies if c.name == "MM_SID"] == [
        COOKIE_SECRET
    ]
    assert client._renewal_admission.sequences == 1
    assert client._in_keepalive is False


def test_terminal_rejection_is_not_retried_and_keeps_the_confirmed_jar() -> None:
    """A refused Remember Me cookie stops the generation; the first failure stays."""
    client = _remember_client()
    with requests_mock.Mocker(session=client.session) as m:
        # Probe, renewal GET, landing fallback, renewal GET again -> rejected.
        calls = _mock_renewal(
            m,
            [LOGGED_OUT_REDIRECT] * 4,
        )
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()
        first_failure = client.okta_session_expired_at
        assert client.auth_reason == AUTH_REASON_REMEMBER_ME_REJECTED
        assert client._renewal_admission.terminal_reason == AUTH_REASON_REMEMBER_ME_REJECTED
        assert calls["dashboard"].call_count == 3
        # Three 302 hops to "/" plus exactly one explicit landing retry.
        assert calls["home"].call_count == 4

        # Second tick: one probe, no renewal HTTP, and the first failure is stable.
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()
        assert calls["dashboard"].call_count == 4
        assert calls["home"].call_count == 5
        assert client.okta_session_expired_at == first_failure
        assert client.auth_reason == AUTH_REASON_REMEMBER_ME_REJECTED
        assert calls["login"].call_count == 0
        assert calls["sso"].call_count == 0

    # The confirmed jar (with MM_SID) is retained, never replaced by a partial one.
    assert [c.value for c in client.session.cookies if c.name == "MM_SID"] == [
        COOKIE_SECRET
    ]
    assert client.has_remember_me is True
    assert client.sso_renewals == 0
    assert client._renewal_admission.sequences == 1


def test_absent_remember_me_cookie_never_starts_an_http_renewal() -> None:
    """No cookie means no renewal request at all, even with a saved password."""
    client = PsegClient(email=EMAIL, password=PASSWORD, portal_cookies=PORTAL_COOKIE)
    with requests_mock.Mocker(session=client.session) as m:
        calls = _mock_renewal(m, [LOGGED_OUT_REDIRECT])
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()

    assert calls["dashboard"].call_count == 1  # the probe only
    assert calls["home"].call_count == 1  # the probe's own 302 hop
    assert calls["chart"].call_count == 0
    assert calls["login"].call_count == 0
    assert calls["sso"].call_count == 0
    assert client.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED
    assert client._renewal_admission.sequences == 0


def test_captcha_latch_spends_no_renewal_attempt() -> None:
    """A latched CAPTCHA is a terminal refusal: no request, no reserved slot."""
    client = _remember_client()
    client._latch_captcha()
    with requests_mock.Mocker(session=client.session) as m:
        m.register_uri(requests_mock.ANY, requests_mock.ANY, text="unexpected")
        with pytest.raises(PsegCaptchaRequired):
            client.keepalive()
        assert m.request_history == []

    assert client.auth_reason == AUTH_REASON_CAPTCHA_REQUIRED
    assert client._renewal_admission.sequences == 0


def test_transient_attempt_then_cooldown_then_one_retry_then_exhausted() -> None:
    """Two sequences per generation, at least 15 minutes apart, then auth required."""
    client = _remember_client()
    with freeze_time("2026-10-23 12:00:00") as frozen, requests_mock.Mocker(
        session=client.session
    ) as m:
        calls = _mock_renewal(
            m,
            [
                LOGGED_OUT_REDIRECT,  # t0 probe
                {"exc": requests.ConnectionError},  # t0 renewal: transient
                LOGGED_OUT_REDIRECT,  # t+5 probe; cooldown refuses the renewal
                LOGGED_OUT_REDIRECT,  # t+16 probe
                {"text": DASHBOARD_WITH_TOKEN},  # t+16 retry succeeds
                LOGGED_OUT_REDIRECT,  # t+40 probe; budget exhausted
            ],
        )
        assert client.keepalive() is False
        assert client._renewal_admission.sequences == 1

        frozen.tick(timedelta(minutes=5))
        assert client.keepalive() is False
        assert client._renewal_admission.sequences == 1
        assert client.auth_reason is None

        frozen.tick(timedelta(minutes=11))
        assert client.keepalive() is True
        assert client._renewal_admission.sequences == 2
        assert client.sso_renewals == 1

        frozen.tick(timedelta(minutes=24))
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()

    # Exactly two renewal chart reads across the whole generation.
    assert calls["chart"].call_count == 1
    assert client.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED
    # First failure of the exhausted episode, measured from the confirmed success.
    assert client.idle_gap_seconds == 1440.0
    assert calls["login"].call_count == 0
    assert calls["sso"].call_count == 0


def test_verified_cookie_rotation_rearms_but_keeps_the_global_gap() -> None:
    """A rotated MM_RememberMe starts a new generation; 15 minutes still apply."""
    client = _remember_client()
    rotate = {"on": True}

    def chart_data(_request, _context):
        if rotate["on"]:
            client.session.cookies.set(
                "MM_RememberMe", "rotated-token", domain=PORTAL_HOST, path="/"
            )
        return DAILY_CHART

    with freeze_time("2026-10-23 12:00:00") as frozen, requests_mock.Mocker(
        session=client.session
    ) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                LOGGED_OUT_REDIRECT,
                {"text": DASHBOARD_WITH_TOKEN},  # t0 renewal rotates the cookie
                LOGGED_OUT_REDIRECT,  # t+5 probe: cooldown still applies
                LOGGED_OUT_REDIRECT,  # t+16 probe
                {"text": DASHBOARD_WITH_TOKEN},  # t+16 renewal (no rotation)
            ],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        chart_data_mock = m.get(
            f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=chart_data
        )
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)

        assert client.keepalive() is True
        # Verified replacement: the generation restarted, the clock did not.
        assert client._renewal_admission.sequences == 0
        assert client._renewal_admission.last_sequence_at is not None
        assert [c.value for c in client.session.cookies if c.name == "MM_RememberMe"] == [
            "rotated-token"
        ]

        rotate["on"] = False
        frozen.tick(timedelta(minutes=5))
        assert client.keepalive() is False
        assert client._renewal_admission.sequences == 0

        frozen.tick(timedelta(minutes=11))
        assert client.keepalive() is True
        assert client._renewal_admission.sequences == 1

    assert chart_data_mock.call_count == 2
    assert login.call_count == 0
    assert client.sso_renewals == 2

def test_poll_shares_the_cookie_renewal_budget_with_the_keepalive() -> None:
    """The poll cannot bypass the cap: it spends and is refused by the same state."""
    client = _remember_client()
    with freeze_time("2026-10-23 12:00:00") as frozen, requests_mock.Mocker(
        session=client.session
    ) as m:
        dash = m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                LOGGED_OUT_REDIRECT,  # poll renewal: typed expiry
                {"exc": requests.ConnectionError},  # transient failure
                LOGGED_OUT_REDIRECT,  # immediate second poll: cooldown, no renewal
                {"text": DASHBOARD_WITH_TOKEN},  # retry after the 15-minute gap
            ],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        m.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=DAILY_CHART)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)

        with pytest.raises(PsegTransientError):
            client._renew()
        assert dash.call_count == 2
        assert client._renewal_admission.sequences == 1

        # The retry window is still open, so this is a transient wait: HA keeps its
        # poll schedule for the earned attempt instead of demanding a sign-in.
        with pytest.raises(PsegTransientError):
            client._renew()
        assert dash.call_count == 2  # refused before any HTTP
        assert client._renewal_admission.sequences == 1

        frozen.tick(timedelta(minutes=16))
        assert client._renew() is True
        assert client._renewal_admission.sequences == 2
        assert client.sso_renewals == 1

    assert login.call_count == 0


def test_poll_fallback_to_the_saved_login_survives_a_spent_cookie_budget() -> None:
    """The poll keeps its permitted password fallback; the timer still never posts."""
    client = PsegClient(
        portal_cookies=REMEMBER_PORTAL, email=EMAIL, password=PASSWORD
    )
    client._renewal_admission.record_outcome(AUTH_REASON_REMEMBER_ME_REJECTED)
    with requests_mock.Mocker(session=client.session) as m:
        dash = m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        # The permitted existing fallback is retained for the poll path.
        assert client._renew() is True

    assert login.call_count == 1
    assert dash.call_count == 1  # only the post-login confirmation
    assert client.has_remember_me is True

    client._mark_session_ok()
    client._renewal_admission.record_outcome(AUTH_REASON_REMEMBER_ME_REJECTED)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        post = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()
    # The timer path refused the terminal generation without posting credentials.
    assert post.call_count == 0
    assert client.auth_reason == AUTH_REASON_REMEMBER_ME_REJECTED


def test_keepalive_flag_and_lock_are_released_after_every_outcome() -> None:
    """The in-keepalive flag never leaks, so a later poll may still sign in."""
    client = _remember_client()
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, {"exc": requests.ConnectionError}],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        assert client.keepalive() is False
    assert client._in_keepalive is False
    # The client lock is free: another thread can take it immediately.
    acquired = client._lock.acquire(timeout=1)
    assert acquired is True
    client._lock.release()


def test_transient_renewal_restores_telemetry_and_the_confirmed_jar() -> None:
    """A transient failure is not a new auth failure and does not drop MM_SID."""
    client = _remember_client()
    client._mark_session_ok()
    with freeze_time("2026-10-23 12:00:00") as frozen:
        with requests_mock.Mocker(session=client.session) as m:
            m.get(
                f"{PORTAL_BASE_URL}/Dashboard",
                [LOGGED_OUT_REDIRECT, {"exc": requests.ConnectionError}],
            )
            m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
            frozen.tick(timedelta(seconds=600))
            assert client.keepalive() is False

    assert client.auth_reason is None
    assert client.okta_session_expired_at is None
    assert client.idle_gap_seconds is None
    assert client.last_portal_success_at is not None
    assert client.sso_renewals == 0
    assert client.cookies_confirmed is False
    assert [c.value for c in client.session.cookies if c.name == "MM_SID"] == [
        COOKIE_SECRET
    ]


async def test_keepalive_persists_the_budget_but_never_an_unconfirmed_jar(
    hass: HomeAssistant,
) -> None:
    """A transient renewal spends a slot; the restored jar is not written to the entry."""
    original = [
        {
            "name": "MM_SID",
            "value": "OLD_SID",
            "domain": PORTAL_HOST,
            "path": "/",
            "secure": True,
        },
        {
            "name": "MM_RememberMe",
            "value": "REMEMBER",
            "domain": PORTAL_HOST,
            "path": "/",
            "secure": True,
        },
    ]
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={"cookies": [dict(c) for c in original]},
    )
    entry.add_to_hass(hass)
    client = PsegClient(cookie_list=[dict(c) for c in original])
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    def transient_keepalive() -> bool:
        client._renewal_admission.reserve(datetime.now(UTC))
        client.cookies_confirmed = False
        return False

    with patch.object(client, "keepalive", side_effect=transient_keepalive):
        await coord._async_keepalive(None)
        await hass.async_block_till_done()

    assert entry.data["cookies"] == original
    admission = entry.data[CONF_RENEWAL_ADMISSION]
    assert admission["sequences"] == 1
    assert admission["terminal_reason"] is None
    # No cookie value, name or fingerprint in the persisted metadata.
    assert "REMEMBER" not in str(admission)
    assert "OLD_SID" not in str(admission)


def test_loaded_budget_and_identity_guard_come_from_the_entry(hass: HomeAssistant) -> None:
    """A reloaded entry keeps its exhausted budget and its meter-id guard."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={
            CONF_RENEWAL_ADMISSION: {
                "sequences": 1,
                "last_sequence_at": "2026-10-23T12:00:00+00:00",
                "terminal_reason": AUTH_REASON_REMEMBER_ME_REJECTED,
            }
        },
    )
    entry.add_to_hass(hass)
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    assert coord._renewal_admission.terminal_reason == AUTH_REASON_REMEMBER_ME_REJECTED
    assert client._renewal_admission is coord._renewal_admission
    assert client._renewal_admission.blocked_reason(datetime.now(UTC)) == "terminal"
    assert METER in client._expected_meter_ids


async def test_retired_coordinator_does_not_write_stale_renewal_metadata(
    hass: HomeAssistant,
) -> None:
    """After reauth replaced the jar, the old coordinator's state must not win."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={"cookies": [{"name": "MM_SID", "value": "OLD", "domain": PORTAL_HOST, "path": "/"}]},
    )
    entry.add_to_hass(hass)
    client = PsegClient(portal_cookies="MM_SID=OLD")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord._renewal_admission.reserve(datetime.now(UTC))
    patcher = patch.object(client, "keepalive", return_value=True)
    patcher.start()
    # Reauth committed a fresh jar; this coordinator is now retired.
    hass.config_entries.async_update_entry(
        entry,
        data={
            **entry.data,
            "cookies": [
                {"name": "MM_SID", "value": "NEW", "domain": PORTAL_HOST, "path": "/"}
            ],
        },
    )

    try:
        await coord._async_keepalive(None)
        await hass.async_block_till_done()
    finally:
        patcher.stop()

    # The retired coordinator did not add its stale budget to the fresh entry.
    assert CONF_RENEWAL_ADMISSION not in entry.data
    assert entry.data["cookies"][0]["value"] == "NEW"

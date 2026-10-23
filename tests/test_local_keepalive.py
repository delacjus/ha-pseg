"""Local-mode GET-only keepalive, cadence and the CAPTCHA latch (1.4.2)."""

from __future__ import annotations

from datetime import timedelta
import logging
from unittest.mock import patch

from freezegun import freeze_time
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests_mock

from custom_components.pseg.const import (
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_OKTA_SESSION_EXPIRED,
    AUTH_REASON_PORTAL_SESSION_EXPIRED,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    DOMAIN,
    LOCAL_KEEPALIVE_INTERVAL_MINUTES,
    PORTAL_BASE_URL,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegOktaSessionExpired,
)

EMAIL = "fixture@example.invalid"
PASSWORD = "synthetic-secret-7731"
COOKIE_SECRET = "synthetic-cookie-9182"
PORTAL_COOKIE = f"MM_SID={COOKIE_SECRET}"
LOGGED_OUT_REDIRECT = {"status_code": 302, "headers": {"Location": "/"}}
PORTAL_HOME = "<html><body>Welcome</body></html>"
DASHBOARD = "<html><body>Dashboard</body></html>"
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
    """MM_SID lapses after ~10 idle minutes; a GET every 3 minutes survives an hour."""
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

        # Stop touching the portal: the same idle expiry the old 10-min timer hit.
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

        # Stop touching the portal: the ~10-minute idle expiry the old timer hit.
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

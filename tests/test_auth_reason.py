"""Typed auth reasons, idle-gap telemetry and reason-aware coordinator text (1.4.2)."""

from __future__ import annotations

from datetime import timedelta
import logging
from unittest.mock import patch

from freezegun import freeze_time
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests_mock

from custom_components.pseg.const import (
    ATTR_AUTH_IDLE_GAP,
    ATTR_AUTH_REASON,
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_OKTA_SESSION_EXPIRED,
    AUTH_REASON_PORTAL_SESSION_EXPIRED,
    AUTH_REASON_REMEMBER_ME_REJECTED,
    AUTH_REASON_SECURITY_STEP,
    AUTH_REASONS,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    DOMAIN,
    KEEPALIVE_INTERVAL_MINUTES,
    LOCAL_KEEPALIVE_INTERVAL_MINUTES,
    PORTAL_BASE_URL,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegLoginRejected,
    PsegOktaSessionExpired,
    PsegSecurityStepRequired,
)
from custom_components.pseg.sensor import PsegConnectionStatusSensor

EMAIL = "fixture@example.invalid"
PASSWORD = "synthetic-secret-7731"
COOKIE_SECRET = "synthetic-cookie-9182"
REMEMBER_PORTAL = f"MM_SID=dead; MM_RememberMe={COOKIE_SECRET}"
LOGGED_OUT_REDIRECT = {"status_code": 302, "headers": {"Location": "/"}}
PORTAL_HOME = "<html><body>Welcome</body></html>"
DASHBOARD = "<html><body>Dashboard</body></html>"
OKTA_WIDGET = '<html><script>new OktaSignIn({stateToken: "x"})</script></html>'
LOGIN_OK = {"AjaxResults": [], "Data": {}}


def _entry(hass: HomeAssistant, **data) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={"cookies": [], **data},
    )
    entry.add_to_hass(hass)
    return entry


def test_auth_reason_values_are_the_documented_set() -> None:
    """The typed reason vocabulary is closed: coordinator text maps these values."""
    assert AUTH_REASONS == {
        "portal_session_expired",
        "captcha_required",
        "remember_me_rejected",
        "security_step",
        "okta_session_expired",
    }
    fresh = PsegClient(email=EMAIL, password=PASSWORD)
    assert fresh.auth_reason is None
    assert fresh.idle_gap_seconds is None


def test_captcha_demand_records_captcha_reason() -> None:
    """A CAPTCHA refusal is a CAPTCHA reason, not a phantom Okta expiry."""
    client = PsegClient(email=EMAIL, password=PASSWORD)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"Data": {"LoginErrorMessage": "Please provide a valid login captcha."}},
        )
        with pytest.raises(PsegCaptchaRequired):
            client.ensure_session()

    assert client.auth_reason == AUTH_REASON_CAPTCHA_REQUIRED
    # Kept for compatibility with existing attributes/automations.
    assert client.okta_session_expired_at is not None


def test_security_step_records_security_step_reason() -> None:
    client = PsegClient(email=EMAIL, password=PASSWORD)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"Data": {"SecretQuestionError": "choose a question"}},
        )
        with pytest.raises(PsegSecurityStepRequired):
            client.ensure_session()

    assert client.auth_reason == AUTH_REASON_SECURITY_STEP


def test_refused_saved_login_records_credential_rejection_reason() -> None:
    client = PsegClient(email=EMAIL, password=PASSWORD)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"Data": {"LoginErrorMessage": "Invalid email address or password"}},
        )
        with pytest.raises(PsegLoginRejected):
            client.ensure_session()

    assert client.auth_reason == AUTH_REASON_REMEMBER_ME_REJECTED


def test_rejected_remember_me_records_credential_rejection_reason() -> None:
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        with pytest.raises(PsegOktaSessionExpired):
            client.ensure_session()

    assert client.auth_reason == AUTH_REASON_REMEMBER_ME_REJECTED
    assert client.has_remember_me is False


def test_okta_widget_records_okta_reason() -> None:
    client = PsegClient(okta_cookies="idx=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=OKTA_WIDGET)
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()

    assert client.auth_reason == AUTH_REASON_OKTA_SESSION_EXPIRED


def test_credentialless_local_entry_never_probes_okta() -> None:
    """Portal-only, no saved sign-in: a lapsed session is portal_session_expired."""
    client = PsegClient(portal_cookies=f"MM_SID={COOKIE_SECRET}")
    assert client.is_local_mode is True
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=OKTA_WIDGET)
        with pytest.raises(PsegOktaSessionExpired):
            client.ensure_session()

    assert sso.called is False
    assert client.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED


def test_idle_gap_records_seconds_since_last_portal_success(caplog) -> None:
    """The next failure says how long the portal sat idle (idle vs absolute expiry)."""
    caplog.set_level(logging.DEBUG)
    client = PsegClient(portal_cookies=f"MM_SID={COOKIE_SECRET}")
    with freeze_time("2026-10-22 12:00:00") as frozen:
        client._mark_session_ok()
        frozen.tick(timedelta(seconds=615))
        with requests_mock.Mocker(session=client.session) as m:
            m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
            m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
            with pytest.raises(PsegOktaSessionExpired):
                client.ensure_session()

    assert client.auth_reason == AUTH_REASON_PORTAL_SESSION_EXPIRED
    assert client.idle_gap_seconds == 615.0
    assert "615" in caplog.text and "portal_session_expired" in caplog.text
    assert COOKIE_SECRET not in caplog.text
    # Success clears the failure state again.
    client._mark_session_ok()
    assert client.auth_reason is None and client.idle_gap_seconds is None


def test_auth_failure_paths_never_log_credentials_or_cookies(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    client = PsegClient(email=EMAIL, password=PASSWORD, portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"Data": {"RecaptchaOnLogin": True}},
        )
        with pytest.raises(PsegOktaSessionExpired):
            client.ensure_session()

    assert PASSWORD not in caplog.text
    assert COOKIE_SECRET not in caplog.text
    assert EMAIL not in caplog.text


def test_status_sensor_exposes_reason_and_idle_gap(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    client = PsegClient(portal_cookies=f"MM_SID={COOKIE_SECRET}")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    sensor = PsegConnectionStatusSensor(coord, entry)

    client.auth_reason = AUTH_REASON_CAPTCHA_REQUIRED
    client.idle_gap_seconds = 612.0
    attrs = sensor.extra_state_attributes

    assert attrs[ATTR_AUTH_REASON] == AUTH_REASON_CAPTCHA_REQUIRED
    assert attrs[ATTR_AUTH_IDLE_GAP] == 612.0
    assert attrs["okta_session_expired_at"] is None


async def test_local_poll_failure_is_not_labelled_okta(hass: HomeAssistant) -> None:
    """Local-mode repair/notification text names the real cause, never Okta."""
    entry = _entry(
        hass,
        **{CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
    )
    client = PsegClient(email=EMAIL, password=PASSWORD)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    def captcha_failure(days_back: int = 14):
        client._mark_auth_failure(AUTH_REASON_CAPTCHA_REQUIRED)
        raise PsegCaptchaRequired("MyMeter requires a solved CAPTCHA")

    with (
        patch.object(client, "fetch_energy_data", side_effect=captcha_failure),
        patch(
            "custom_components.pseg.coordinator.persistent_notification.async_create"
        ) as notify,
    ):
        with pytest.raises(ConfigEntryAuthFailed) as err:
            await coord._async_update_data()

    raised = str(err.value)
    notification = str(notify.call_args.kwargs["message"])
    assert "CAPTCHA" in raised and "Okta" not in raised
    assert "CAPTCHA" in notification and "Okta" not in notification
    assert PASSWORD not in raised + notification
    assert coord.status == "auth_required"


async def test_poll_auth_failure_logs_typed_reason_and_idle_gap(
    hass: HomeAssistant, caplog
) -> None:
    caplog.set_level(logging.DEBUG)
    entry = _entry(
        hass,
        **{CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
    )
    client = PsegClient(email=EMAIL, password=PASSWORD)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    def expired(days_back: int = 14):
        client._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
        client.idle_gap_seconds = 601.0
        raise PsegOktaSessionExpired("portal session expired")

    with patch.object(client, "fetch_energy_data", side_effect=expired):
        with pytest.raises(ConfigEntryAuthFailed):
            await coord._async_update_data()

    assert "portal_session_expired" in caplog.text
    assert "601 s ago" in caplog.text
    assert PASSWORD not in caplog.text


def test_keepalive_interval_is_per_mode(hass: HomeAssistant) -> None:
    """Local portal sessions are touched every 3 min; Okta mode keeps 10 min."""
    entry = _entry(hass)
    local = PsegDataUpdateCoordinator(
        hass, PsegClient(portal_cookies="MM_SID=x"), {}, config_entry=entry
    )
    okta = PsegDataUpdateCoordinator(
        hass, PsegClient(okta_cookies="idx=x"), {}, config_entry=entry
    )

    assert local.keepalive_interval() == timedelta(
        minutes=LOCAL_KEEPALIVE_INTERVAL_MINUTES
    )
    assert okta.keepalive_interval() == timedelta(minutes=KEEPALIVE_INTERVAL_MINUTES)

    with patch("custom_components.pseg.coordinator.async_track_time_interval") as track:
        track.return_value = lambda: None
        local.start_keepalive()
    assert track.call_args.args[2] == timedelta(
        minutes=LOCAL_KEEPALIVE_INTERVAL_MINUTES
    )

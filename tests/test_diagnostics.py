"""Tests for PSE&G diagnostics redaction and telemetry output."""

from homeassistant.components.diagnostics import REDACTED
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pseg.const import (
    CONF_COOKIE,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.diagnostics import async_get_config_entry_diagnostics
from custom_components.pseg.pseg_client import PsegClient


async def test_diagnostics_redacts_sensitive_data(hass: HomeAssistant) -> None:
    """Test that diagnostics redacts session cookies, tokens, and passwords."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={
            CONF_OKTA_COOKIES: "idx=secret_okta_token_123; sid=session_token",
            CONF_PORTAL_COOKIES: "MM_SID=secret_portal_session_456",
            CONF_COOKIE: "raw_secret_cookie_789",
            "cookies": [{"name": "MM_SID", "value": "secret_val"}],
            "password": "leaked_plaintext_password",
        },
    )
    entry.add_to_hass(hass)

    client = PsegClient(
        okta_cookies="idx=secret_okta_token_123",
        portal_cookies="MM_SID=secret_portal_session_456",
    )
    client.session_established_at = "2026-10-20T12:00:00Z"
    client.last_sso_renewal = "2026-10-20T12:30:00Z"
    client.sso_renewals = 2
    client.last_keepalive = "2026-10-20T13:00:00Z"
    client.okta_session_expired_at = None

    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord.status = "connected"
    coord.auth_required = False
    coord.last_successful_update = "2026-10-20T13:00:00Z"
    coord.data = {
        "meter": "Meter 12345",
        "__RequestVerificationToken": "secret_token_abc",
        "SAMLResponse": "secret_saml_data",
        "latest_kwh": 15.5,
    }

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord

    diag = await async_get_config_entry_diagnostics(hass, entry)

    # Check redaction
    entry_data = diag["entry"]["data"]
    assert entry_data[CONF_OKTA_COOKIES] == REDACTED
    assert entry_data[CONF_PORTAL_COOKIES] == REDACTED
    assert entry_data[CONF_COOKIE] == REDACTED
    assert entry_data["cookies"] == REDACTED
    assert entry_data["password"] == REDACTED

    # Ensure no secret strings leaked into output
    diag_str = str(diag)
    assert "secret_okta_token_123" not in diag_str
    assert "secret_portal_session_456" not in diag_str
    assert "raw_secret_cookie_789" not in diag_str
    assert "secret_val" not in diag_str
    assert "leaked_plaintext_password" not in diag_str
    assert "secret_token_abc" not in diag_str
    assert "secret_saml_data" not in diag_str

    # Check session telemetry attributes
    telemetry = diag["session_telemetry"]
    assert telemetry["session_established_at"] == "2026-10-20T12:00:00Z"
    assert telemetry["last_sso_renewal"] == "2026-10-20T12:30:00Z"
    assert telemetry["sso_renewals"] == 2
    assert telemetry["last_keepalive"] == "2026-10-20T13:00:00Z"
    assert telemetry["okta_session_expired_at"] is None

"""Tests for PSE&G diagnostics redaction and telemetry output."""

from homeassistant.components.diagnostics import REDACTED
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pseg.const import (
    CONF_COOKIE,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_STATISTICS_IMPORT_ENABLED,
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


async def test_diagnostics_redacts_captcha_proof_fields(hass: HomeAssistant) -> None:
    """A stray CAPTCHA proof mirrored into entry data is redacted like a password."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={
            "captcha_response": "proof-must-not-leak-6c1f",
            "g-recaptcha-response": "proof-must-not-leak-6c1f",
            "mymeter_email": "me@example.com",
        },
    )
    entry.add_to_hass(hass)

    diag = await async_get_config_entry_diagnostics(hass, entry)

    assert diag["entry"]["data"]["captcha_response"] == REDACTED
    assert diag["entry"]["data"]["g-recaptcha-response"] == REDACTED
    assert "proof-must-not-leak-6c1f" not in str(diag)


async def test_diagnostics_never_exposes_meter_ids(hass: HomeAssistant) -> None:
    """Meter identity is account data: no meter id may appear anywhere in diagnostics."""
    meter = "88776655"
    other = "88776666"
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=meter,
        title=f"PSE&G ({meter})",
        data={
            "meter_id": meter,
            "known_meter_ids": [meter, other],
            "cookies": [],
        },
    )
    entry.add_to_hass(hass)

    client = PsegClient(portal_cookies="MM_SID=session")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord.data = {
        "meter": f"Electric Meter {meter}",
        "meter_ids": [meter, other],
        "latest_kwh": 12.5,
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord

    diag = await async_get_config_entry_diagnostics(hass, entry)

    assert meter not in str(diag)
    assert other not in str(diag)
    assert diag["entry"]["unique_id"] == REDACTED
    assert diag["entry"]["title"] == REDACTED
    assert diag["entry"]["data"]["meter_id"] == REDACTED
    assert diag["entry"]["data"]["known_meter_ids"] == REDACTED
    assert diag["coordinator"]["data"]["meter"] == REDACTED
    assert diag["coordinator"]["data"]["meter_ids"] == REDACTED


async def test_diagnostics_for_entry_that_is_not_loaded(hass: HomeAssistant) -> None:
    """A SETUP_RETRY entry has no coordinator; diagnostics still return redacted entry data."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: "idx=secret_okta_token_123"},
    )
    entry.add_to_hass(hass)

    diag = await async_get_config_entry_diagnostics(hass, entry)

    assert diag["entry"]["data"][CONF_OKTA_COOKIES] == REDACTED
    assert diag["coordinator"] is None
    assert diag["session_telemetry"] is None
    assert diag["statistics"] is None
    assert "secret_okta_token_123" not in str(diag)


async def test_diagnostics_statistics_summary_is_value_free(hass: HomeAssistant) -> None:
    """Hourly diagnostics expose counts, fixed reasons and booleans only."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={},
        options={CONF_STATISTICS_IMPORT_ENABLED: False},
    )
    entry.add_to_hass(hass)
    client = PsegClient(portal_cookies="MM_SID=session")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord.data = {
        "statistics_granularity": "mixed",
        "hourly_complete_days": 2,
        "hourly_incomplete_days": 1,
        "hourly_records": [
            {"start": "2026-10-20T04:00:00+00:00", "kwh": 99.9}
        ],
        "daily_records": [{"date": "2026-10-20", "kwh": 88.8}],
    }
    coord._hourly_summary = {
        "complete_days": 2,
        "incomplete_days": 1,
        "promoted_last_run": 2,
        "reason_counts": {"missing_hours": 1, "raw_secret_value": 5},
    }
    coord.last_statistics_import = "2026-10-22T05:00:00+00:00"

    await coord._stats_state.async_load()
    await coord._stats_state.async_begin(
        {
            "created_at": "2026-10-22T05:00:00+00:00",
            "first_start": "2026-10-20T04:00:00+00:00",
            "series": {
                "pseg:12345_energy_consumption": [
                    ["2026-10-20T04:00:00+00:00", 1.0, 1.0]
                ],
                "pseg:12345_energy_cost": [
                    ["2026-10-20T04:00:00+00:00", 0.25, 0.25]
                ],
            },
            "promoted": {
                "pseg:12345_energy_consumption": {
                    "2026-10-20": {"total_kwh": 1.0, "total_cost": 0.25}
                },
                "pseg:12345_energy_cost": {
                    "2026-10-20": {"total_kwh": 1.0, "total_cost": 0.25}
                },
            },
        }
    )
    committed_id = await coord._stats_state.async_begin(
        {
            "created_at": "2026-10-22T05:00:00+00:00",
            "first_start": "2026-10-19T04:00:00+00:00",
            "series": {
                "pseg:12345_energy_consumption": [
                    ["2026-10-19T04:00:00+00:00", 1.0, 1.0]
                ],
                "pseg:12345_energy_cost": [
                    ["2026-10-19T04:00:00+00:00", 0.25, 0.25]
                ],
            },
            "promoted": {
                "pseg:12345_energy_consumption": {
                    "2026-10-19": {"total_kwh": 1.0, "total_cost": 0.25}
                },
                "pseg:12345_energy_cost": {
                    "2026-10-19": {"total_kwh": 1.0, "total_cost": 0.25}
                },
            },
        }
    )
    await coord._stats_state.async_commit(committed_id)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord

    diag = await async_get_config_entry_diagnostics(hass, entry)
    summary = diag["statistics"]

    assert summary["paused"] is True
    assert summary["granularity"] == "mixed"
    assert summary["complete_days"] == 2
    assert summary["incomplete_days"] == 1
    assert summary["promoted_days"] == 1
    assert summary["promoted_last_run"] == 2
    assert summary["reason_counts"] == {"missing_hours": 1}
    assert summary["pending_recovery"] is True
    assert summary["last_import"] == "2026-10-22T05:00:00+00:00"

    assert diag["coordinator"]["data"]["hourly_records"] == REDACTED
    assert diag["coordinator"]["data"]["daily_records"] == REDACTED
    assert "99.9" not in str(diag)
    assert "88.8" not in str(diag)
    assert "raw_secret_value" not in str(diag)

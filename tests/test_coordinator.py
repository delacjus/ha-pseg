"""Tests for PSE&G DataUpdateCoordinator error taxonomy, keepalive, and session persistence."""

from datetime import UTC, datetime
from unittest.mock import patch

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests

from custom_components.pseg.const import (
    CONF_OKTA_COOKIES,
    DOMAIN,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import (
    PsegClient,
    PsegOktaSessionExpired,
    PsegTransientError,
)


async def test_transient_network_error_raises_update_failed(hass: HomeAssistant) -> None:
    """Test transient network error raises UpdateFailed, NOT ConfigEntryAuthFailed."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: "idx=test"},
    )
    entry.add_to_hass(hass)

    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with patch.object(client, "fetch_energy_data", side_effect=PsegTransientError("Connection reset")):
        with pytest.raises(UpdateFailed, match="Transient error communicating with PSE&G"):
            await coord._async_update_data()

    assert coord.status == "error"
    assert coord.auth_required is False


async def test_request_exception_raises_update_failed(hass: HomeAssistant) -> None:
    """Test requests.RequestException raises UpdateFailed, NOT ConfigEntryAuthFailed."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: "idx=test"},
    )
    entry.add_to_hass(hass)

    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with patch.object(client, "fetch_energy_data", side_effect=requests.RequestException("503 Gateway")):
        with pytest.raises(UpdateFailed, match="Transient error communicating with PSE&G"):
            await coord._async_update_data()

    assert coord.status == "error"
    assert coord.auth_required is False


async def test_okta_session_expired_raises_config_entry_auth_failed(hass: HomeAssistant) -> None:
    """Test Okta widget or expired session raises ConfigEntryAuthFailed and creates repair issue."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: "idx=test"},
    )
    entry.add_to_hass(hass)

    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with patch.object(client, "fetch_energy_data", side_effect=PsegOktaSessionExpired("Widget encountered")):
        with pytest.raises(ConfigEntryAuthFailed, match="Okta session expired"):
            await coord._async_update_data()

    assert coord.auth_required is True
    assert coord.status == "auth_required"

    issue = ir.async_get(hass).async_get_issue(DOMAIN, f"reauth_required_{entry.entry_id}")
    assert issue is not None
    assert issue.severity == ir.IssueSeverity.ERROR


async def test_successful_update_dismisses_auth_issues_and_persists_cookies(hass: HomeAssistant) -> None:
    """Test successful update clears auth issues and updates entry with rotated cookies."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: "idx=test"},
    )
    entry.add_to_hass(hass)

    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord.auth_required = True
    coord._raise_auth_issues("Initial expired state")

    sample_data = {
        "meter": "Meter 12345",
        "latest_kwh": 10.0,
        "latest_cost": 2.47,
        "history_14d": [{"date": "2026-10-20", "kwh": 10.0, "cost": 2.47}],
    }

    # Simulate rotated cookies in jar
    client.session.cookies.set("MM_SID", "new_rotated_session", domain="mysmartenergy.nj.pseg.com", path="/")

    with (
        patch.object(client, "fetch_energy_data", return_value=sample_data),
        patch.object(coord, "async_record_statistics", return_value=None),
    ):
        data = await coord._async_update_data()

    assert data["latest_kwh"] == 10.0
    assert coord.auth_required is False
    assert coord.status == "connected"

    # Issue dismissed
    issue = ir.async_get(hass).async_get_issue(DOMAIN, f"reauth_required_{entry.entry_id}")
    assert issue is None

    # Rotated cookie persisted to entry data
    assert "cookies" in entry.data
    persisted_cookies = {c["name"]: c["value"] for c in entry.data["cookies"]}
    assert persisted_cookies.get("MM_SID") == "new_rotated_session"


async def test_keepalive_handles_transient_error_without_raising(hass: HomeAssistant) -> None:
    """Test keepalive runs without raising exceptions on network blips."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: "idx=test"},
    )
    entry.add_to_hass(hass)

    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with patch.object(client, "keepalive", side_effect=requests.ConnectionError("network down")):
        # Should not raise
        await coord._async_keepalive(datetime.now(UTC))

    assert coord.auth_required is False


async def test_keepalive_detects_expired_okta_session(hass: HomeAssistant) -> None:
    """Test keepalive transitions to auth_required when Okta session is expired."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: "idx=test"},
    )
    entry.add_to_hass(hass)

    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    def mock_expired_keepalive():
        client.okta_session_expired_at = datetime.now(UTC).isoformat()
        return False

    with patch.object(client, "keepalive", side_effect=mock_expired_keepalive):
        await coord._async_keepalive(datetime.now(UTC))

    assert coord.auth_required is True
    assert coord.status == "auth_required"


async def test_keepalive_expiry_starts_reauth_once(hass: HomeAssistant) -> None:
    """Okta expiry seen by the keepalive starts one reauth flow and a non-fixable issue."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with patch.object(client, "keepalive", side_effect=PsegOktaSessionExpired("widget")):
        await coord._async_keepalive(datetime.now(UTC))
        await hass.async_block_till_done()
        await coord._async_keepalive(datetime.now(UTC))
        await hass.async_block_till_done()

    assert coord.status == "auth_required"
    flows = [
        f
        for f in hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        if f["context"]["source"] == "reauth"
    ]
    assert len(flows) == 1
    assert flows[0]["context"]["entry_id"] == entry.entry_id

    issue = ir.async_get(hass).async_get_issue(DOMAIN, f"reauth_required_{entry.entry_id}")
    assert issue is not None
    assert issue.is_fixable is False


async def test_retired_poll_auth_failure_does_not_start_reauth(hass: HomeAssistant) -> None:
    """An in-flight poll on an unloaded coordinator reports UpdateFailed, not reauth."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord._stopped = True

    with (
        patch.object(client, "fetch_energy_data", side_effect=PsegOktaSessionExpired("widget")),
        pytest.raises(UpdateFailed),
    ):
        await coord._async_update_data()

    assert coord.auth_required is False
    assert ir.async_get(hass).async_get_issue(DOMAIN, f"reauth_required_{entry.entry_id}") is None


async def test_backfill_of_old_range_leaves_sensor_data_alone(hass: HomeAssistant) -> None:
    """Backfill only imports statistics; latest_* sensor values stay from the poll."""
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, {})
    polled = {
        "meter": "Meter 1",
        "latest_date": "2026-10-20",
        "latest_kwh": 12.0,
        "latest_cost": 3.0,
        "previous_date": "2026-10-19",
        "history_14d": [{"date": "2026-10-20", "kwh": 12.0, "cost": 3.0}],
    }
    coord.async_set_updated_data(dict(polled))
    coord._last_valid_data = coord.data
    pushes: list = []
    coord.async_add_listener(lambda: pushes.append(dict(coord.data)))

    history = [
        {"date": "2024-01-01", "kwh": 1.0, "cost": 0.25},
        {"date": "2024-01-02", "kwh": 2.0, "cost": 0.5},
    ]
    with (
        patch.object(client, "fetch_history_range", return_value=history),
        patch.object(coord, "async_record_statistics") as record,
    ):
        assert await coord.async_backfill_history("2024-01-01", "2024-01-02") == 2

    record.assert_awaited_once()
    assert coord.data == polled
    assert coord._last_valid_data == polled
    assert pushes == []

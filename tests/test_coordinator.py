"""Tests for PSE&G DataUpdateCoordinator error taxonomy, keepalive, and session persistence."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests

from custom_components.pseg.const import (
    AUTH_REASON_OKTA_SESSION_EXPIRED,
    CONF_KNOWN_METER_IDS,
    CONF_METER_ID,
    CONF_OKTA_COOKIES,
    DOMAIN,
    OKTA_HOST,
)
from custom_components.pseg.coordinator import (
    PsegDataUpdateCoordinator,
    PsegStatisticsConflictError,
)
from custom_components.pseg.pseg_client import (
    PsegClient,
    PsegOktaSessionExpired,
    PsegTransientError,
)
from custom_components.pseg.sensor import (
    PsegConnectionStatusSensor,
    PsegElectricityConsumptionSensor,
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


async def test_recovered_keepalive_clears_sticky_auth_state(hass: HomeAssistant) -> None:
    """A keepalive that succeeds again clears auth_required/status and the prompt.

    Before this fix only a successful poll cleared them, so a session that recovered
    kept showing "auth required" (plus repair/notification) until the next 4-hour poll.
    """
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    # A failed poll left the sticky state behind.
    client._mark_auth_failure(AUTH_REASON_OKTA_SESSION_EXPIRED)
    coord.auth_required = True
    coord.status = "auth_required"
    coord._raise_auth_issues("Authentication expired")
    await hass.async_block_till_done()
    notification_id = f"pseg_reauth_{entry.entry_id}"
    assert ir.async_get(hass).async_get_issue(DOMAIN, f"reauth_required_{entry.entry_id}")

    def recovered() -> bool:
        client._mark_session_ok()  # the portal served /Dashboard again
        return True

    with (
        patch.object(client, "keepalive", side_effect=recovered),
        patch(
            "custom_components.pseg.coordinator.persistent_notification.async_dismiss"
        ) as dismiss,
    ):
        await coord._async_keepalive(datetime.now(UTC))
        await hass.async_block_till_done()

    assert coord.auth_required is False
    assert coord.status == "connected"
    assert ir.async_get(hass).async_get_issue(DOMAIN, f"reauth_required_{entry.entry_id}") is None
    dismiss.assert_called_once_with(hass, notification_id=notification_id)


async def test_transient_keepalive_does_not_clear_sticky_auth_state(hass: HomeAssistant) -> None:
    """A keepalive that only hits a network blip is not proof the session recovered."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord.auth_required = True
    coord.status = "auth_required"
    coord._raise_auth_issues("Authentication expired")

    with patch.object(client, "keepalive", return_value=False):
        await coord._async_keepalive(datetime.now(UTC))

    assert coord.auth_required is True
    assert coord.status == "auth_required"


async def test_stale_keepalive_does_not_clear_auth_state(hass: HomeAssistant) -> None:
    """A keepalive from a retired coordinator must not clear the fresh entry's state."""
    old_jar = [{"name": "idx", "value": "OLD", "domain": OKTA_HOST, "path": "/", "secure": True}]
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: "idx=test", "cookies": old_jar},
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord.auth_required = True
    coord.status = "auth_required"
    coord._raise_auth_issues("Authentication expired")
    # Reauth replaced the jar: this coordinator's session is now stale.
    hass.config_entries.async_update_entry(
        entry,
        data={
            **entry.data,
            "cookies": [
                {"name": "idx", "value": "NEW", "domain": OKTA_HOST, "path": "/", "secure": True}
            ],
        },
    )

    with patch.object(client, "keepalive", return_value=True):
        await coord._async_keepalive(datetime.now(UTC))
        await hass.async_block_till_done()

    assert coord.auth_required is True
    assert coord.status == "auth_required"
    assert ir.async_get(hass).async_get_issue(DOMAIN, f"reauth_required_{entry.entry_id}") is not None


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


async def test_first_refresh_during_startup_defers_statistics(hass: HomeAssistant) -> None:
    """During bootstrap the import waits for HA started instead of blocking setup.

    The recorder only commits after HA has started, and HA only starts after setup,
    so an inline commit wait here deadlocked startup for 120 s (live 2026-10-21).
    """
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    sample = {"meter": "Meter #12345", "history_14d": [{"date": "2026-10-20", "kwh": 10.0, "cost": 2.47}]}

    hass.set_state(CoreState.starting)
    with (
        patch.object(client, "fetch_energy_data", return_value=sample),
        patch.object(coord, "async_record_statistics", return_value=None) as record,
    ):
        data = await coord._async_update_data()
        assert data["history_14d"] == sample["history_14d"]
        record.assert_not_awaited()

        hass.set_state(CoreState.running)
        hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
        await hass.async_block_till_done()

    record.assert_awaited_once_with(sample["history_14d"], meter_id="12345")


async def test_successful_poll_learns_meters_without_retiring_session(hass: HomeAssistant) -> None:
    """A legacy entry persists newly observed meters through the cookie update path."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="111",
        data={CONF_OKTA_COOKIES: "idx=test", CONF_METER_ID: "222"},
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    with patch.object(
        client, "fetch_energy_data", return_value={"meter_ids": ["333"]}
    ):
        await coord._async_update_data()
        assert set(entry.data[CONF_KNOWN_METER_IDS]) == {"111", "222", "333"}
        assert coord._is_stale() is False
        await coord._async_update_data()
    assert coord._is_stale() is False


async def test_unload_cancels_deferred_statistics_import(hass: HomeAssistant) -> None:
    """Entry unload removes the HA-started callback before it can import."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    with patch.object(
        PsegDataUpdateCoordinator, "async_config_entry_first_refresh", new_callable=AsyncMock
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    coord = hass.data[DOMAIN][entry.entry_id]
    sample = {"meter": "Meter #12345", "history_14d": [{"date": "2026-10-20", "kwh": 10.0}]}
    hass.set_state(CoreState.starting)
    with (
        patch.object(coord.client, "fetch_energy_data", return_value=sample),
        patch.object(coord, "async_record_statistics", new_callable=AsyncMock) as record,
        patch("custom_components.pseg.async_unload_entry", AsyncMock(return_value=True)),
    ):
        await coord._async_update_data()
        record.assert_not_awaited()
        assert await hass.config_entries.async_unload(entry.entry_id)
        hass.set_state(CoreState.running)
        hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
        await hass.async_block_till_done()
    record.assert_not_awaited()


async def test_stale_coordinator_skips_deferred_statistics_import(hass: HomeAssistant) -> None:
    """A replaced cookie jar retires a queued import at startup."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    sample = {"meter": "Meter #12345", "history_14d": [{"date": "2026-10-20", "kwh": 10.0}]}
    hass.set_state(CoreState.starting)
    with (
        patch.object(client, "fetch_energy_data", return_value=sample),
        patch.object(coord, "async_record_statistics", new_callable=AsyncMock) as record,
    ):
        await coord._async_update_data()
        hass.config_entries.async_update_entry(entry, data={**entry.data, "cookies": []})
        assert coord._is_stale() is True
        hass.set_state(CoreState.running)
        hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
        await hass.async_block_till_done()
    record.assert_not_awaited()


async def test_deferred_import_carries_hourly_records(hass: HomeAssistant) -> None:
    """A startup-deferred import keeps the hourly records and their granularity."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    hourly = [{"start": datetime(2026, 10, 20, 4, 0, tzinfo=UTC), "kwh": 10.0}]
    sample = {
        "meter": "Meter #12345",
        "history_14d": [{"date": "2026-10-20", "kwh": 10.0, "cost": 2.47}],
        "daily_records": [{"date": "2026-10-20", "kwh": 10.0, "cost": 2.47}],
        "hourly_records": hourly,
        "hourly_granularity": "hourly",
    }

    hass.set_state(CoreState.starting)
    with (
        patch.object(client, "fetch_energy_data", return_value=sample),
        patch.object(coord, "async_record_statistics", return_value=None) as record,
    ):
        await coord._async_update_data()
        record.assert_not_awaited()

        hass.set_state(CoreState.running)
        hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
        await hass.async_block_till_done()

    record.assert_awaited_once_with(
        sample["daily_records"],
        meter_id="12345",
        hourly_records=hourly,
        hourly_granularity="hourly",
    )


async def test_poll_uses_daily_records_not_hybrid_history(hass: HomeAssistant) -> None:
    """Statistics validation always receives the authoritative daily records."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    hybrid = [{"date": "2026-10-20", "kwh": 23.98, "cost": 5.92}]
    daily = [{"date": "2026-10-20", "kwh": 24.02, "cost": 5.93}]
    hourly = [{"start": datetime(2026, 10, 20, 4, 0, tzinfo=UTC), "kwh": 1.0}]
    sample = {
        "meter": "Meter #12345",
        "history_14d": hybrid,
        "daily_records": daily,
        "hourly_records": hourly,
        "hourly_granularity": "hourly",
    }

    with (
        patch.object(client, "fetch_energy_data", return_value=sample),
        patch.object(coord, "async_record_statistics", return_value=None) as record,
    ):
        data = await coord._async_update_data()

    assert data["history_14d"] == hybrid
    record.assert_awaited_once_with(
        daily,
        meter_id="12345",
        hourly_records=hourly,
        hourly_granularity="hourly",
    )


async def test_statistics_conflict_does_not_fail_the_poll(hass: HomeAssistant) -> None:
    """A rejected conflicting import is logged; sensor data still updates."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    sample = {
        "meter": "Meter #12345",
        "latest_kwh": 10.0,
        "history_14d": [{"date": "2026-10-20", "kwh": 10.0, "cost": 2.47}],
        "daily_records": [{"date": "2026-10-20", "kwh": 10.0, "cost": 2.47}],
    }

    with (
        patch.object(client, "fetch_energy_data", return_value=sample),
        patch.object(
            coord,
            "async_record_statistics",
            side_effect=PsegStatisticsConflictError("conflict"),
        ),
    ):
        data = await coord._async_update_data()

    assert data["latest_kwh"] == 10.0
    assert coord.status == "connected"
    assert coord.auth_required is False


async def test_consumption_sensor_exposes_hourly_provenance(hass: HomeAssistant) -> None:
    """The sensor reports explicit granularity and completeness attributes."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345", data={CONF_OKTA_COOKIES: "idx=test"}
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord.async_set_updated_data(
        {
            "latest_kwh": 10.0,
            "history_14d": [],
            "statistics_granularity": "hourly",
            "hourly_complete_days": 3,
            "hourly_incomplete_days": 1,
        }
    )

    consumption = PsegElectricityConsumptionSensor(coord, entry)
    attrs = consumption.extra_state_attributes
    assert attrs["statistics_granularity"] == "hourly"
    assert attrs["statistics_hourly_complete_days"] == 3
    assert attrs["statistics_hourly_incomplete_days"] == 1
    assert attrs["statistics_last_import"] is None

    status = PsegConnectionStatusSensor(coord, entry)
    assert status.extra_state_attributes["statistics_imports_enabled"] is True

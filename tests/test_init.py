"""Tests for PSE&G integration setup, unload, migration, and services."""

from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pseg import (
    async_migrate_entry,
    async_setup,
)
from custom_components.pseg.const import (
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
)
from custom_components.pseg.pseg_client import PsegTransientError


async def test_migration_v1_to_v2_strips_credentials(hass: HomeAssistant) -> None:
    """Test migration from version 1 to 2 strips passwords and companion add-on URLs."""
    legacy_data = {
        "username": "test_user@example.com",
        "password": "super_secret_password_123",
        "mfa_method": "sms",
        "mfa_code": "123456",
        "auth_server_url": "http://10.0.1.51:8000",
        "cookie": "MM_SID=old_portal_cookie_999",
    }
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=1,
        unique_id="12345678",
        data=legacy_data,
    )
    entry.add_to_hass(hass)

    assert await async_migrate_entry(hass, entry) is True

    # Version bumped to 2
    assert entry.version == 2

    # Insecure keys completely stripped
    assert "username" not in entry.data
    assert "password" not in entry.data
    assert "mfa_method" not in entry.data
    assert "mfa_code" not in entry.data
    assert "auth_server_url" not in entry.data

    # Legacy cookie migrated to portal_cookies
    assert entry.data.get(CONF_PORTAL_COOKIES) == "MM_SID=old_portal_cookie_999"


async def test_backfill_service_registered_once(hass: HomeAssistant) -> None:
    """Test pseg.backfill_history is registered once in async_setup and handles no active entries."""
    assert await async_setup(hass, {}) is True
    assert hass.services.has_service(DOMAIN, "backfill_history")

    # Calling with zero active entries logs warning, does not crash
    await hass.services.async_call(
        DOMAIN,
        "backfill_history",
        {"start_date": "2026-01-01", "end_date": "2026-01-10"},
        blocking=True,
    )


async def test_backfill_service_multiple_entries(hass: HomeAssistant) -> None:
    """Test pseg.backfill_history executes across all active entries."""
    assert await async_setup(hass, {}) is True

    coord1 = MagicMock()
    coord1.async_backfill_history = AsyncMock(return_value=10)
    coord2 = MagicMock()
    coord2.async_backfill_history = AsyncMock(return_value=15)

    hass.data[DOMAIN] = {
        "entry_1": coord1,
        "entry_2": coord2,
    }

    await hass.services.async_call(
        DOMAIN,
        "backfill_history",
        {"start_date": "2026-01-01", "end_date": "2026-01-10"},
        blocking=True,
    )

    coord1.async_backfill_history.assert_awaited_once_with(
        start_date="2026-01-01", end_date="2026-01-10"
    )
    coord2.async_backfill_history.assert_awaited_once_with(
        start_date="2026-01-01", end_date="2026-01-10"
    )


async def test_setup_and_unload_entry(hass: HomeAssistant) -> None:
    """Test setup and unload of config entry starts and cancels keepalive."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345678",
        data={
            CONF_OKTA_COOKIES: "idx=test_token",
            CONF_PORTAL_COOKIES: "MM_SID=test_portal",
        },
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.async_config_entry_first_refresh",
            new_callable=AsyncMock,
        ),
        patch(
            "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.start_keepalive"
        ) as mock_start_keepalive,
        patch(
            "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.stop_keepalive"
        ) as mock_stop_keepalive,
    ):
        assert await hass.config_entries.async_setup(entry.entry_id) is True
        await hass.async_block_till_done()
        assert mock_start_keepalive.call_count == 1
        assert entry.entry_id in hass.data[DOMAIN]

        assert await hass.config_entries.async_unload(entry.entry_id) is True
        await hass.async_block_till_done()
        assert mock_stop_keepalive.call_count == 1
        assert entry.entry_id not in hass.data[DOMAIN]


async def test_failed_first_refresh_registers_nothing(hass: HomeAssistant) -> None:
    """A not-ready entry must not leave a coordinator for services/diagnostics or a timer."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345678", data={CONF_OKTA_COOKIES: "idx=a"}
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            side_effect=PsegTransientError("portal 503"),
        ),
        patch(
            "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.start_keepalive"
        ) as mock_start_keepalive,
    ):
        assert await hass.config_entries.async_setup(entry.entry_id) is False
        await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert entry.entry_id not in hass.data.get(DOMAIN, {})
    assert mock_start_keepalive.call_count == 0


async def test_unload_cancels_keepalive_timer(hass: HomeAssistant) -> None:
    """The keepalive timer is tied to the entry lifecycle via async_on_unload."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345678", data={CONF_OKTA_COOKIES: "idx=a"}
    )
    entry.add_to_hass(hass)
    with patch(
        "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.async_config_entry_first_refresh",
        new_callable=AsyncMock,
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    coord = hass.data[DOMAIN][entry.entry_id]
    assert coord._unsub_keepalive is not None

    with patch("custom_components.pseg.async_unload_entry", AsyncMock(return_value=True)):
        assert await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()
    assert coord._unsub_keepalive is None


async def test_async_setup_registers_energy_card_js(hass: HomeAssistant) -> None:
    """The card is auto-loaded on dashboards via add_extra_js_url (upstream 1.0.1)."""
    hass.http = MagicMock()
    hass.http.async_register_static_paths = AsyncMock()
    with patch("homeassistant.components.frontend.add_extra_js_url") as add_js:
        assert await async_setup(hass, {}) is True
    registered = [cfg.url_path for cfg in hass.http.async_register_static_paths.call_args.args[0]]
    assert "/pseg/pseg-energy-card.js" in registered
    add_js.assert_called_once_with(hass, "/pseg/pseg-energy-card.js")


async def test_async_setup_without_frontend_skips_card(hass: HomeAssistant) -> None:
    """No frontend data (minimal install/tests) must not fail integration setup."""
    hass.http = MagicMock()
    hass.http.async_register_static_paths = AsyncMock()
    assert await async_setup(hass, {}) is True


async def test_async_setup_registers_set_cost_mode_service(hass: HomeAssistant) -> None:
    """The set_cost_mode admin service is registered during async_setup."""
    assert await async_setup(hass, {}) is True
    assert hass.services.has_service(DOMAIN, "set_cost_mode")


async def test_set_cost_mode_nonadmin_unauthorized(hass: HomeAssistant) -> None:
    """Calling set_cost_mode from a non-admin context raises Unauthorized."""
    from homeassistant.core import Context
    from homeassistant.exceptions import Unauthorized
    import pytest
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, entry_id="test-admin-check", data={})
    entry.add_to_hass(hass)
    from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
    from custom_components.pseg.pseg_client import PsegClient

    coord = PsegDataUpdateCoordinator(hass, PsegClient(), {}, config_entry=entry)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord
    assert await async_setup(hass, {})

    await hass.auth.async_create_user("test-owner")
    nonadmin = await hass.auth.async_create_user("test-nonadmin")
    assert not nonadmin.is_admin

    with pytest.raises(Unauthorized):
        await hass.services.async_call(
            DOMAIN,
            "set_cost_mode",
            {"cost_mode": "evidence", "entry_id": entry.entry_id},
            blocking=True,
            context=Context(user_id=nonadmin.id),
        )

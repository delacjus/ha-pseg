"""The PSE&G Energy integration."""

from __future__ import annotations

import logging
from pathlib import Path

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryAuthFailed
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_COOKIE,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    DEFAULT_PRICE_PER_KWH,
    DOMAIN,
)
from .coordinator import PsegDataUpdateCoordinator
from .pseg_client import PsegClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BUTTON]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up PSE&G integration wide configuration and register Lovelace and brand resources."""
    component_path = Path(__file__).parent
    frontend_path = component_path / "frontend" / "pseg-energy-card.js"
    icon_path = component_path / "icon.png"
    logo_path = component_path / "logo.png"

    def _get_static_paths() -> list[tuple[str, str]]:
        paths = []
        if frontend_path.exists():
            paths.append(("/pseg/pseg-energy-card.js", str(frontend_path)))
        if icon_path.exists():
            paths.append(("/pseg/icon.png", str(icon_path)))
        if logo_path.exists():
            paths.append(("/pseg/logo.png", str(logo_path)))
        return paths

    static_paths = await hass.async_add_executor_job(_get_static_paths)

    if static_paths:
        try:
            from homeassistant.components.http import StaticPathConfig
            configs = [StaticPathConfig(url, path, False) for url, path in static_paths]
            await hass.http.async_register_static_paths(configs)
            _LOGGER.debug("Registered static paths for PSE&G resources")
        except Exception as err:
            _LOGGER.debug("Could not register static paths: %s", err)

    async def async_backfill_service(call: ServiceCall) -> None:
        """Handle backfill history service call once across all active entries."""
        start_date = call.data.get("start_date")
        end_date = call.data.get("end_date")

        coordinators = list(hass.data.get(DOMAIN, {}).values())
        if not coordinators:
            _LOGGER.warning("No active PSE&G integration entry found for backfill")
            return

        for coord in coordinators:
            try:
                count = await coord.async_backfill_history(start_date=start_date, end_date=end_date)
                _LOGGER.info("PSE&G backfill service completed: %d records imported", count)
            except Exception as err:
                _LOGGER.error("Error running PSE&G backfill service: %s", err)

    if not hass.services.has_service(DOMAIN, "backfill_history"):
        hass.services.async_register(DOMAIN, "backfill_history", async_backfill_service)

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up PSE&G from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    okta_cookies = entry.data.get(CONF_OKTA_COOKIES, "")
    portal_cookies = entry.data.get(CONF_PORTAL_COOKIES, "")
    if not portal_cookies and CONF_COOKIE in entry.data:
        portal_cookies = entry.data[CONF_COOKIE]
    cookie_list = entry.data.get("cookies")
    price_per_kwh = entry.options.get(CONF_PRICE_PER_KWH, DEFAULT_PRICE_PER_KWH)

    client = PsegClient(
        okta_cookies=okta_cookies,
        portal_cookies=portal_cookies,
        cookie_list=cookie_list,
        price_per_kwh=price_per_kwh,
    )
    coordinator = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    hass.data[DOMAIN][entry.entry_id] = coordinator

    try:
        await coordinator.async_config_entry_first_refresh()
    except ConfigEntryAuthFailed:
        coordinator.auth_required = True
        coordinator.status = "auth_required"
        raise

    coordinator.start_keepalive()

    # No update listener: cookie persistence updates entry.data on every rotation and
    # must not reload. Options reload via OptionsFlowWithReload; reauth/reconfigure via
    # async_update_reload_and_abort.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a PSE&G config entry and stop background keepalive."""
    coordinator: PsegDataUpdateCoordinator | None = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if coordinator:
        coordinator.stop_keepalive()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate config entry data to current schema."""
    _LOGGER.debug("Migrating PSE&G config entry from version %s", config_entry.version)

    if config_entry.version == 1:
        new_data = dict(config_entry.data)
        # Strip legacy credentials and author add-on urls
        for legacy_key in ("username", "password", "mfa_method", "mfa_code", "auth_server_url"):
            new_data.pop(legacy_key, None)

        if "cookie" in new_data and CONF_PORTAL_COOKIES not in new_data:
            new_data[CONF_PORTAL_COOKIES] = new_data["cookie"]

        hass.config_entries.async_update_entry(
            config_entry,
            data=new_data,
            version=2,
        )
        _LOGGER.info("Migrated PSE&G entry to version 2 (stripped stored credentials and add-on URLs)")

    return True

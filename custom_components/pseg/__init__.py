"""The PSE&G Energy integration."""

from __future__ import annotations

import logging
from pathlib import Path

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .captcha_helper import async_ensure_helper_view
from .const import (
    CONF_COOKIE,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
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
            if frontend_path.exists():
                # Load the card on every dashboard without a manual Lovelace
                # resource (upstream 1.0.1). frontend is an after_dependency, so it
                # is set up first whenever present; without it (minimal installs,
                # tests) skip rather than fail setup. The card guards
                # customElements.define, so a manual resource loading it too is harmless.
                from homeassistant.components.frontend import add_extra_js_url

                try:
                    add_extra_js_url(hass, "/pseg/pseg-energy-card.js")
                except KeyError:
                    _LOGGER.debug("Frontend not loaded; energy card not auto-registered")
        except Exception as err:
            _LOGGER.debug("Could not register static paths: %s", err)

    # Public instructions/bookmarklet page for the human CAPTCHA step; the config
    # flow also ensures it, so a first-time setup works before this runs.
    await async_ensure_helper_view(hass)

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

    async def async_set_cost_mode_service(call: ServiceCall) -> None:
        """Handle set_cost_mode service call."""
        cost_mode = call.data.get("cost_mode") or call.data.get("mode")
        if not cost_mode or not isinstance(cost_mode, str):
            raise ValueError("cost_mode is required and must be a string")
        cost_mode = cost_mode.lower().strip()
        from .const import COST_MODE_EVIDENCE, COST_MODE_IMPORT, COST_MODE_OFF

        if cost_mode == COST_MODE_IMPORT:
            raise ValueError("Cost mode 'import' is reserved and refused in v1.7.0")
        if cost_mode not in (COST_MODE_OFF, COST_MODE_EVIDENCE):
            raise ValueError(f"Invalid cost mode '{cost_mode}': expected 'off' or 'evidence'")

        target_entry_id = call.data.get("entry_id")
        coordinators = list(hass.data.get(DOMAIN, {}).values())
        if target_entry_id:
            coordinators = [
                c
                for c in coordinators
                if c.config_entry and c.config_entry.entry_id == target_entry_id
            ]

        if not coordinators:
            _LOGGER.warning("No active PSE&G integration entry found to set cost mode")
            return

        for coord in coordinators:
            try:
                await coord.async_set_cost_mode(cost_mode)
                _LOGGER.info("Set PSE&G cost mode to %s", cost_mode)
            except Exception as err:
                _LOGGER.error("Error setting PSE&G cost mode: %s", err)

    if not hass.services.has_service(DOMAIN, "set_cost_mode"):
        from homeassistant.helpers.service import async_register_admin_service
        import voluptuous as vol

        cost_mode_schema = vol.Schema(
            {
                vol.Optional("cost_mode"): cv.string,
                vol.Optional("mode"): cv.string,
                vol.Optional("entry_id"): cv.string,
            },
            extra=vol.ALLOW_EXTRA,
        )
        async_register_admin_service(
            hass,
            DOMAIN,
            "set_cost_mode",
            async_set_cost_mode_service,
            schema=cost_mode_schema,
        )

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
        email=entry.data.get(CONF_MYMETER_EMAIL, ""),
        password=entry.data.get(CONF_MYMETER_PASSWORD, ""),
    )
    coordinator = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    try:
        await coordinator.async_config_entry_first_refresh()
    except BaseException as err:
        if isinstance(err, ConfigEntryAuthFailed):
            coordinator.auth_required = True
            coordinator.status = "auth_required"
        # Failed setup never reaches the ordinary unload registration. Preserve
        # policy and any renewal-verified jar first, then retire the owner.
        coordinator.stop_keepalive()
        raise

    # Register only once the entry is usable: a not-ready entry must not leave a
    # stale coordinator behind for the backfill service or diagnostics.
    hass.data[DOMAIN][entry.entry_id] = coordinator
    coordinator.start_keepalive()
    entry.async_on_unload(coordinator.stop_keepalive)

    @callback
    def _on_hass_stopping(_event: Event) -> None:
        from .cost_evidence import fire_all_active_watchdogs

        fire_all_active_watchdogs()

    entry.async_on_unload(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _on_hass_stopping))

    # No update listener: cookie persistence updates entry.data on every rotation and
    # must not reload. Options reload via OptionsFlowWithReload; reauth/reconfigure via
    # async_update_reload_and_abort.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a PSE&G config entry (keepalive is cancelled via async_on_unload)."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        from .cost_evidence import cleanup_entry_evidence

        cleanup_entry_evidence(hass, entry.entry_id)
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
        _LOGGER.info(
            "Migrated PSE&G entry to version 2 (stripped stored credentials and add-on URLs)"
        )

    return True

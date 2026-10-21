"""Diagnostics support for PSE&G."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_COOKIE, CONF_OKTA_COOKIES, CONF_PORTAL_COOKIES, DOMAIN
from .coordinator import PsegDataUpdateCoordinator

TO_REDACT = {
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_COOKIE,
    "cookies",
    "password",
    "token",
    "__RequestVerificationToken",
    "SAMLResponse",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    entry_info = {
        "entry_id": entry.entry_id,
        "version": entry.version,
        "unique_id": entry.unique_id,
        "state": entry.state.value,
        "data": async_redact_data(dict(entry.data), TO_REDACT),
        "options": dict(entry.options),
    }
    # The coordinator is only registered after a successful first refresh.
    coordinator: PsegDataUpdateCoordinator | None = hass.data.get(DOMAIN, {}).get(
        entry.entry_id
    )
    if coordinator is None:
        return {"entry": entry_info, "session_telemetry": None, "coordinator": None}
    client = coordinator.client

    return {
        "entry": entry_info,
        "session_telemetry": {
            "session_established_at": client.session_established_at,
            "last_sso_renewal": client.last_sso_renewal,
            "sso_renewals": client.sso_renewals,
            "last_keepalive": client.last_keepalive,
            "okta_session_expired_at": client.okta_session_expired_at,
        },
        "coordinator": {
            "status": coordinator.status,
            "auth_required": coordinator.auth_required,
            "last_successful_update": coordinator.last_successful_update,
            "data": async_redact_data(dict(coordinator.data or {}), TO_REDACT),
        },
    }

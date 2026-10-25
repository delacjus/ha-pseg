"""Diagnostics support for PSE&G."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import REDACTED, async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_CAPTCHA_RESPONSE,
    CONF_COOKIE,
    CONF_KNOWN_METER_IDS,
    CONF_METER_ID,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
)
from .coordinator import PsegDataUpdateCoordinator

TO_REDACT = {
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_COOKIE,
    "cookies",
    "password",
    "mymeter_email",
    "mymeter_password",
    "token",
    CONF_CAPTCHA_RESPONSE,
    "g-recaptcha-response",
    "__RequestVerificationToken",
    "SAMLResponse",
    # Meter identity is account data: the unique_id is the meter id, and poll data
    # carries the meter name and every meter id on the account.
    CONF_METER_ID,
    CONF_KNOWN_METER_IDS,
    "meter",
    "meter_ids",
    "contributing_meter_ids",
    # Raw hourly/daily chart arrays: diagnostics reports only the small summary.
    "hourly_records",
    "daily_records",
}


def _meter_values(entry: ConfigEntry) -> set[str]:
    """Every meter identifier this entry knows, as strings."""
    values: set[str] = set()
    known = entry.data.get(CONF_KNOWN_METER_IDS)
    candidates: list[Any] = [entry.unique_id, entry.data.get(CONF_METER_ID)]
    if isinstance(known, (list, tuple, set, frozenset)):
        candidates.extend(known)
    for value in candidates:
        if value:
            values.add(str(value))
    return values


def _title_contains_meter(title: str, meters: set[str]) -> bool:
    return any(meter in title for meter in meters)


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    meters = _meter_values(entry)
    title = entry.title
    entry_info = {
        "entry_id": entry.entry_id,
        "version": entry.version,
        # The unique_id is the meter id (the stable statistics key) for every entry
        # this integration creates.
        "unique_id": REDACTED,
        "title": (
            REDACTED
            if title and _title_contains_meter(title, meters)
            else title
        ),
        "state": entry.state.value,
        "data": async_redact_data(dict(entry.data), TO_REDACT),
        "options": dict(entry.options),
    }
    # The coordinator is only registered after a successful first refresh.
    coordinator: PsegDataUpdateCoordinator | None = hass.data.get(DOMAIN, {}).get(
        entry.entry_id
    )
    if coordinator is None:
        return {
            "entry": entry_info,
            "session_telemetry": None,
            "coordinator": None,
            "statistics": None,
            "hourly_contract_sample": None,
        }
    client = coordinator.client

    return {
        "entry": entry_info,
        "session_telemetry": {
            "session_established_at": client.session_established_at,
            "last_sso_renewal": client.last_sso_renewal,
            "sso_renewals": client.sso_renewals,
            "last_keepalive": client.last_keepalive,
            "okta_session_expired_at": client.okta_session_expired_at,
            "auth_reason": client.auth_reason,
            "idle_gap_seconds": client.idle_gap_seconds,
            "last_portal_success_at": client.last_portal_success_at,
            # Presence only: no cookie value, length, hash or fingerprint.
            "has_remember_me": client.has_remember_me,
        },
        "coordinator": {
            "status": coordinator.status,
            "auth_required": coordinator.auth_required,
            "last_successful_update": coordinator.last_successful_update,
            "data": async_redact_data(dict(coordinator.data or {}), TO_REDACT),
        },
        # Counts, fixed reason codes and booleans only: no raw points or meter ids.
        "statistics": await coordinator.async_statistics_summary(),
        "hourly_contract_sample": client.hourly_contract_sample,
    }

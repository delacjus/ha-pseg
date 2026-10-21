"""Entry lifecycle tests: reloads, cookie persistence, entity ids (review r1 H2/H3/M7/L11/L12)."""

from __future__ import annotations

from collections.abc import Generator
import logging
from unittest.mock import patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.pseg as pkg
from custom_components.pseg.const import (
    CONF_METER_ID,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    DOMAIN,
    PORTAL_HOST,
)
from custom_components.pseg.pseg_client import PsegClient

METER = "12345678"
DATA = {
    "meter": f"Electric Meter {METER}",
    "last_updated": "x",
    "latest_date": "2026-10-20",
    "latest_kwh": 5.0,
    "latest_cost": 1.0,
    "previous_date": "2026-10-19",
    "previous_kwh": 4.0,
    "previous_cost": 1.0,
    "history_14d": [{"date": "2026-10-20", "kwh": 5.0, "cost": 1.0}],
    "temperature_range": "",
    "temperature_avg": 50.0,
    "total_records": 1,
}


def _entry(hass: HomeAssistant, **data) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        title=f"PSE&G ({METER})",
        data={
            CONF_OKTA_COOKIES: "idx=a",
            CONF_PORTAL_COOKIES: "",
            CONF_METER_ID: METER,
            **data,
        },
    )
    entry.add_to_hass(hass)
    return entry


@pytest.fixture
def setup_calls() -> Generator[dict[str, int]]:
    """Count async_setup_entry calls (each reload is one more)."""
    calls = {"n": 0}
    orig = pkg.async_setup_entry

    async def counting(hass, entry):
        calls["n"] += 1
        return await orig(hass, entry)

    with patch.object(pkg, "async_setup_entry", counting):
        yield calls


@pytest.fixture
def portal() -> Generator[None]:
    """Stub portal calls and statistics import."""
    with (
        patch.object(PsegClient, "fetch_energy_data", return_value=dict(DATA)),
        patch.object(PsegClient, "ensure_session", return_value=True),
        patch.object(PsegClient, "keepalive", return_value=True),
        patch(
            "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.async_record_statistics"
        ),
    ):
        yield


async def test_cookie_rotation_does_not_reload_entry(
    hass: HomeAssistant, setup_calls, portal
) -> None:
    """Persisting rotated cookies must update entry.data without reloading the entry."""
    entry = _entry(hass)
    rotation = {"n": 0}

    def export(self):
        rotation["n"] += 1
        return [
            {
                "name": "MM_SID",
                "value": f"v{rotation['n']}",
                "domain": PORTAL_HOST,
                "path": "/",
                "secure": True,
            }
        ]

    with patch.object(PsegClient, "export_cookies", export):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        coord = hass.data[DOMAIN][entry.entry_id]
        await coord._async_keepalive(None)
        await hass.async_block_till_done()
        await coord._async_keepalive(None)
        await hass.async_block_till_done()

    assert setup_calls["n"] == 1
    assert entry.state is ConfigEntryState.LOADED
    assert entry.data["cookies"][0]["value"] == "v3"


async def test_options_change_reloads_once(hass: HomeAssistant, setup_calls, portal) -> None:
    """Changing the price option reloads the entry exactly once."""
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={CONF_PRICE_PER_KWH: 0.3}
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()

    assert setup_calls["n"] == 2
    assert hass.data[DOMAIN][entry.entry_id].client.price_per_kwh == 0.3


async def test_reauth_reloads_once_without_update_listener_warning(
    hass: HomeAssistant, setup_calls, portal, caplog
) -> None:
    """Reauth must reload once and not trip the 2026.12 update-listener deprecation."""
    caplog.set_level(logging.WARNING)
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={CONF_OKTA_COOKIES: "idx=fresh", CONF_PORTAL_COOKIES: ""},
    )
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()

    assert setup_calls["n"] == 2
    assert "update listener" not in caplog.text
    assert entry.data[CONF_OKTA_COOKIES] == "idx=fresh"

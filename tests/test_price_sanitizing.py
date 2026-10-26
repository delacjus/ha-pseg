"""A previously saved price_per_kwh option can never poison costs or statistics.

PR #1 rejects new negative/non-finite rates in the options flow. The option is
re-read on every setup and every poll, so an already stored bad value must be
sanitized by the same shared rule rather than trusted.
"""

from __future__ import annotations

from datetime import UTC, datetime
import math
from unittest.mock import AsyncMock, patch

from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pseg.const import (
    CONF_OKTA_COOKIES,
    CONF_PRICE_PER_KWH,
    DEFAULT_PRICE_PER_KWH,
    DOMAIN,
    classify_price_per_kwh,
    sanitized_price_per_kwh,
)
from custom_components.pseg.coordinator import (
    PsegDataUpdateCoordinator,
    build_external_statistics,
)
from custom_components.pseg.pseg_client import PsegClient

INVALID_SAVED_RATES = [
    pytest.param(-0.25, id="negative"),
    pytest.param(float("nan"), id="nan"),
    pytest.param(float("inf"), id="inf"),
    pytest.param("-1e9", id="negative-numeric-string"),
    pytest.param("not-a-rate", id="non-numeric-string"),
]


def _meter(name: str, days: list[tuple[str, float]]) -> dict:
    points = []
    for start, value in days:
        x = int(datetime.strptime(start, "%m/%d/%Y").replace(tzinfo=UTC).timestamp() * 1000)
        points.append({"x": x, "y": value, "hs": {"start": start, "end": start}, "v": False})
    return {"name": name, "type": "column", "data": points}


CHART = {"Data": {"series": [_meter("Meter #111 (RS)", [("10/20/2026", 10.0)])]}}


def _entry(saved_rate: object) -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345678",
        data={CONF_OKTA_COOKIES: "idx=test"},
        options={CONF_PRICE_PER_KWH: saved_rate},
    )


def _assert_daily_rows_survive(records: list[dict]) -> None:
    """The same builder the coordinator uses must keep finite, non-negative rows."""
    _consumption_meta, consumption_rows, _cost_meta, cost_rows = build_external_statistics(
        records,
        "111",
        price_per_kwh=DEFAULT_PRICE_PER_KWH,
    )
    assert len(consumption_rows) == len(records) == 1
    assert len(cost_rows) == len(records) == 1
    assert consumption_rows[0]["state"] == 10.0
    assert math.isfinite(cost_rows[0]["state"])
    assert cost_rows[0]["state"] >= 0


@pytest.mark.parametrize(
    ("saved", "reason"),
    [
        (-0.25, "negative"),
        (float("nan"), "not a finite number"),
        (float("inf"), "not a finite number"),
        ("not-a-rate", "not a number"),
        (None, "not a number"),
        (True, "not a number"),
        (10**400, "not a number"),
    ],
)
def test_shared_rule_classifies_saved_rates(saved: object, reason: str) -> None:
    """One rule: finite and >= 0 is usable, everything else names only a reason."""
    rate, problem = classify_price_per_kwh(saved)
    assert rate is None
    assert problem == reason
    assert sanitized_price_per_kwh(saved) == DEFAULT_PRICE_PER_KWH


@pytest.mark.parametrize("saved", [0, 0.0, 0.3125, "0.31"])
def test_shared_rule_keeps_usable_rates(saved: object) -> None:
    """Zero and ordinary numbers (or the string the form coerces) are unchanged."""
    expected = float(saved)
    assert classify_price_per_kwh(saved) == (expected, None)
    assert sanitized_price_per_kwh(saved) == expected


@pytest.mark.parametrize("saved", INVALID_SAVED_RATES)
async def test_saved_invalid_rate_is_defaulted_on_setup(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    saved: object,
) -> None:
    """Setup hands the client the default, not a saved negative/NaN/inf/string."""
    import custom_components.pseg as pkg

    seen: list[float] = []
    real_client = PsegClient

    def factory(**kwargs):
        seen.append(kwargs.get("price_per_kwh"))
        return real_client(**kwargs)

    monkeypatch.setattr(pkg, "PsegClient", factory)
    entry = _entry(saved)
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.pseg.coordinator.PsegDataUpdateCoordinator."
            "async_config_entry_first_refresh",
            new_callable=AsyncMock,
        ),
        patch("custom_components.pseg.coordinator.PsegDataUpdateCoordinator.start_keepalive"),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id) is True
        await hass.async_block_till_done()

    assert seen == [DEFAULT_PRICE_PER_KWH]
    # Setup sanitizes quietly; the first refresh (patched out here) logs the one
    # warning, which test_saved_invalid_rate_is_defaulted_on_every_poll checks.
    warnings = [r for r in caplog.records if "saved price per kWh" in r.getMessage()]
    assert warnings == []
    assert entry.options[CONF_PRICE_PER_KWH] is saved


@pytest.mark.parametrize("saved", INVALID_SAVED_RATES)
async def test_saved_invalid_rate_is_defaulted_on_every_poll(
    hass: HomeAssistant,
    caplog: pytest.LogCaptureFixture,
    saved: object,
) -> None:
    """Two refreshes both use the default; no negative/NaN cost, no dropped rows."""
    entry = _entry(saved)
    entry.add_to_hass(hass)
    # A stale client rate proves the poll actually re-applies the option.
    client = PsegClient(okta_cookies="idx=test", price_per_kwh=0.5)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with (
        patch.object(
            client,
            "fetch_energy_data",
            side_effect=lambda *_args, **_kwargs: client._parse_chart_data(CHART),
        ),
        patch.object(coord, "async_record_statistics", new_callable=AsyncMock) as record,
    ):
        first = await coord._async_update_data()
        second = await coord._async_update_data()

    assert client.price_per_kwh == DEFAULT_PRICE_PER_KWH
    for data in (first, second):
        assert math.isfinite(data["latest_cost"])
        assert data["latest_cost"] >= 0
        _assert_daily_rows_survive(data["history_14d"])
    assert record.await_count >= 2
    # The warning is per bad saved option, not per poll.
    warnings = [r for r in caplog.records if "saved price per kWh" in r.getMessage()]
    assert len(warnings) == 1
    assert str(saved) not in warnings[0].getMessage()


async def test_saved_zero_rate_is_kept(hass: HomeAssistant) -> None:
    """Zero is valid data: it stays zero instead of being replaced by the default."""
    entry = _entry(0.0)
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test", price_per_kwh=0.5)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with (
        patch.object(
            client,
            "fetch_energy_data",
            side_effect=lambda *_args, **_kwargs: client._parse_chart_data(CHART),
        ),
        patch.object(coord, "async_record_statistics", new_callable=AsyncMock),
    ):
        data = await coord._async_update_data()

    assert client.price_per_kwh == 0.0
    assert data["latest_kwh"] == 10.0
    assert data["latest_cost"] == 0.0
    _assert_daily_rows_survive(data["history_14d"])


async def test_saved_valid_rate_reaches_the_poll(hass: HomeAssistant) -> None:
    """A valid saved rate still replaces whatever the client last used."""
    entry = _entry("0.3125")
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies="idx=test", price_per_kwh=0.5)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with (
        patch.object(
            client,
            "fetch_energy_data",
            side_effect=lambda *_args, **_kwargs: client._parse_chart_data(CHART),
        ),
        patch.object(coord, "async_record_statistics", new_callable=AsyncMock),
    ):
        data = await coord._async_update_data()

    assert client.price_per_kwh == 0.3125
    assert data["latest_cost"] == round(10.0 * 0.3125, 2)

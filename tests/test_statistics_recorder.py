"""External statistics against the real recorder (ported from review r1 probes).

These exercise the actual recorder queries and import queue, so they catch baseline
and ordering bugs that mocked `_async_get_last_stat_before` tests cannot.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)

from custom_components.pseg.coordinator import PsegDataUpdateCoordinator

CONSUMPTION_ID = "pseg:m1_energy_consumption"
COST_ID = "pseg:m1_energy_cost"


def _recs(start: str, n: int, kwh: float = 10.0) -> list[dict]:
    d0 = datetime.strptime(start, "%Y-%m-%d")
    return [
        {
            "date": (d0 + timedelta(days=i)).strftime("%Y-%m-%d"),
            "kwh": kwh,
            "cost": round(kwh * 0.25, 2),
        }
        for i in range(n)
    ]


async def _sums(hass: HomeAssistant, statistic_id: str = CONSUMPTION_ID) -> list[tuple[str, float]]:
    rows = await hass.async_add_executor_job(
        statistics_during_period,
        hass,
        datetime(2020, 1, 1, tzinfo=UTC),
        None,
        {statistic_id},
        "hour",
        None,
        {"sum", "state"},
    )
    return [
        (datetime.fromtimestamp(r["start"], UTC).date().isoformat(), r["sum"])
        for r in rows.get(statistic_id, [])
    ]


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock, enable_custom_integrations):
    """Recorder must be set up before hass for these tests."""
    yield


class _Client:
    price_per_kwh = 0.25


@pytest.fixture
async def coord(hass: HomeAssistant) -> PsegDataUpdateCoordinator:
    return PsegDataUpdateCoordinator(hass, _Client(), {})


async def test_concurrent_imports_chain_sums(coord, hass) -> None:
    """Concurrent backfill + poll imports must not both read the pre-import baseline."""
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)

    await asyncio.gather(
        coord.async_record_statistics(_recs("2026-09-01", 44), meter_id="m1"),
        coord.async_record_statistics(_recs("2026-10-02", 14), meter_id="m1"),
    )
    await async_wait_recording_done(hass)

    sums = await _sums(hass)
    values = [v for _, v in sums]
    assert values == sorted(values), f"sum goes backwards: {sums}"
    assert dict(sums)["2026-10-15"] == 450.0

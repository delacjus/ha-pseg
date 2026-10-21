"""External statistics against the real recorder (ported from review r1 probes).

These exercise the actual recorder queries and import queue, so they catch baseline
and ordering bugs that mocked `_async_get_last_stat_before` tests cannot.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)

from custom_components.pseg import coordinator as coord_mod
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


async def test_rolling_polls_are_cumulative(coord, hass) -> None:
    """Same-window re-poll then a shifted window keep a strictly cumulative chain."""
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)
    await coord.async_record_statistics(_recs("2026-10-02", 14), meter_id="m1")
    await async_wait_recording_done(hass)

    assert [v for _, v in await _sums(hass)] == [10.0 * (i + 1) for i in range(15)]


@pytest.mark.parametrize(
    "time_zone", ["America/New_York", "UTC", "US/Pacific", "Europe/Berlin"]
)
async def test_same_window_repoll_idempotent_in_any_ha_time_zone(
    coord, hass, time_zone
) -> None:
    """Rows start at America/New_York midnight; HA's own zone must not shift the baseline."""
    await hass.config.async_set_time_zone(time_zone)
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)

    sums = await _sums(hass)
    assert sums[0] == ("2026-10-01", 10.0)
    assert sums[-1] == ("2026-10-14", 140.0)
    cost = await _sums(hass, COST_ID)
    assert cost[-1] == ("2026-10-14", 35.0)


async def test_baseline_query_failure_aborts_import(coord, hass) -> None:
    """A failed recorder query must abort the import, not rebase the chain at 0."""
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)

    def boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    with (
        patch.object(coord_mod, "statistics_during_period", boom),
        pytest.raises(HomeAssistantError, match="database is locked"),
    ):
        await coord.async_record_statistics(_recs("2026-10-02", 14), meter_id="m1")
    await async_wait_recording_done(hass)

    assert [v for _, v in await _sums(hass)] == [10.0 * (i + 1) for i in range(14)]


async def test_poll_survives_statistics_failure(hass) -> None:
    """The poll still returns sensor data when the statistics import aborts."""
    client = MagicMock()
    client.price_per_kwh = 0.25
    client.fetch_energy_data.return_value = {
        "meter": "Meter 1",
        "history_14d": _recs("2026-10-01", 2),
        "latest_kwh": 10.0,
    }
    client.export_cookies.return_value = []
    coord = PsegDataUpdateCoordinator(hass, client, {})

    def boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    with patch.object(coord_mod, "statistics_during_period", boom):
        data = await coord._async_update_data()
    assert data["latest_kwh"] == 10.0


async def test_partial_backfill_rechains_newer_rows(coord, hass) -> None:
    """Backfill ending before existing data must re-chain the newer rows (no negative step)."""
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)

    await coord.async_record_statistics(_recs("2026-09-01", 30), meter_id="m1")
    await async_wait_recording_done(hass)

    sums = dict(await _sums(hass))
    assert sums["2026-09-30"] == 300.0
    assert sums["2026-10-01"] == 310.0
    assert sums["2026-10-14"] == 440.0
    cost = dict(await _sums(hass, COST_ID))
    assert cost["2026-10-14"] == 110.0


async def test_backfill_with_gap_rechains_newer_rows(coord, hass) -> None:
    """A gap between the backfill end and newer rows still yields a monotonic chain."""
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)

    await coord.async_record_statistics(_recs("2026-09-01", 20), meter_id="m1")
    await async_wait_recording_done(hass)

    sums = await _sums(hass)
    values = [v for _, v in sums]
    assert values == sorted(values)
    assert dict(sums)["2026-09-20"] == 200.0
    assert dict(sums)["2026-10-01"] == 210.0
    assert dict(sums)["2026-10-14"] == 340.0

    # A later rolling poll continues from the re-chained sums.
    await coord.async_record_statistics(_recs("2026-10-02", 14), meter_id="m1")
    await async_wait_recording_done(hass)
    assert dict(await _sums(hass))["2026-10-15"] == 350.0

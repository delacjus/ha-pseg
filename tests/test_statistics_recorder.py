"""External statistics against the real recorder (ported from review r1 probes).

These exercise the actual recorder queries and import queue, so they catch baseline
and ordering bugs that mocked `_async_get_last_stat_before` tests cannot.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
import urllib.parse

from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)
import requests_mock

from custom_components.pseg import coordinator as coord_mod
from custom_components.pseg.const import PORTAL_BASE_URL
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient, PsegTransientError

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


async def test_reimport_missing_day_keeps_existing_row_in_chain(coord, hass) -> None:
    """A day missing from a re-fetched window keeps its stored value inside the chain."""
    await coord.async_record_statistics(_recs("2026-09-01", 44), meter_id="m1")
    await async_wait_recording_done(hass)

    refetch = [r for r in _recs("2026-09-01", 44, kwh=20.0) if r["date"] != "2026-09-15"]
    await coord.async_record_statistics(refetch, meter_id="m1")
    await async_wait_recording_done(hass)

    sums = await _sums(hass)
    values = [v for _, v in sums]
    assert values == sorted(values), f"negative step: {sums}"
    by_day = dict(sums)
    assert by_day["2026-09-14"] == 280.0
    assert by_day["2026-09-15"] == 290.0  # stored 10 kWh kept, not dropped from the chain
    assert by_day["2026-09-16"] == 310.0
    assert by_day["2026-10-14"] == 870.0


def _chart_mocker(m, empty_chunk_start: str | None) -> None:
    """Portal stub: 20 kWh/day for the requested range, one chunk optionally empty."""
    state: dict = {}

    def chart(req, ctx):
        q = urllib.parse.parse_qs(req.text)
        state["range"] = (q["Start"][0], q["End"][0])
        return ""

    def data(req, ctx):
        start, end = state["range"]
        if start == empty_chunk_start:
            return {"Data": None, "AjaxResults": []}
        d = datetime.strptime(start, "%Y-%m-%d")
        d1 = datetime.strptime(end, "%Y-%m-%d")
        pts = []
        while d <= d1:
            pts.append({"y": 20.0, "hs": {"start": d.strftime("%m/%d/%Y")}})
            d += timedelta(days=1)
        return {"Data": {"series": [{"name": "Electric Meter 1", "data": pts}]}}

    m.get(f"{PORTAL_BASE_URL}/Dashboard", text='<input name="__RequestVerificationToken" value="t"/>')
    m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=chart)
    m.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=data)


async def test_backfill_with_empty_middle_chunk_aborts_without_import(hass) -> None:
    """An empty chunk between populated chunks aborts the backfill; history untouched."""
    client = PsegClient(portal_cookies="MM_SID=x", price_per_kwh=0.25)
    coord = PsegDataUpdateCoordinator(hass, client, {})
    await coord.async_record_statistics(_recs("2026-03-01", 228), meter_id="m1")
    await async_wait_recording_done(hass)
    before = await _sums(hass)

    with requests_mock.Mocker() as m, patch.object(coord, "_get_meter_id", return_value="m1"):
        _chart_mocker(m, empty_chunk_start="2026-05-31")
        with pytest.raises(PsegTransientError, match="no data"):
            await coord.async_backfill_history("2026-03-01", "2026-10-14")
    await async_wait_recording_done(hass)

    assert await _sums(hass) == before


@pytest.mark.parametrize(
    ("empty_chunk_start", "expected_days"),
    [
        ("2026-03-01", 63),  # leading chunk 03-01..05-30 empty -> 05-31..08-01 imported
        ("2026-05-31", 91),  # trailing chunk 05-31..08-01 empty -> 03-01..05-30 imported
    ],
)
async def test_backfill_with_empty_leading_or_trailing_chunk_imports(
    hass, empty_chunk_start, expected_days
) -> None:
    """Empty edges (before the meter existed / not published yet) are not an outage."""
    client = PsegClient(portal_cookies="MM_SID=x", price_per_kwh=0.25)
    coord = PsegDataUpdateCoordinator(hass, client, {})
    with requests_mock.Mocker() as m, patch.object(coord, "_get_meter_id", return_value="m1"):
        _chart_mocker(m, empty_chunk_start=empty_chunk_start)
        count = await coord.async_backfill_history("2026-03-01", "2026-08-01")
    await async_wait_recording_done(hass)
    assert count == expected_days
    assert len(await _sums(hass)) == expected_days


async def test_failed_second_read_imports_nothing(coord, hass) -> None:
    """If the cost read fails after the consumption read, neither series is written."""
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)
    before = (await _sums(hass), await _sums(hass, COST_ID))

    real = coord_mod._async_get_stats_from
    calls = {"n": 0}

    async def fail_second(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise coord_mod.PsegStatisticsError("cost read failed")
        return await real(*args, **kwargs)

    with (
        patch.object(coord_mod, "_async_get_stats_from", fail_second),
        pytest.raises(coord_mod.PsegStatisticsError),
    ):
        await coord.async_record_statistics(_recs("2026-09-01", 30, kwh=5.0), meter_id="m1")
    await async_wait_recording_done(hass)

    assert (await _sums(hass), await _sums(hass, COST_ID)) == before


async def test_backfill_with_different_daily_values_numeric_trace(coord, hass) -> None:
    """Exact sums after an older backfill at a different rate, then a rolling poll."""
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)
    await coord.async_record_statistics(_recs("2026-09-01", 30, kwh=5.0), meter_id="m1")
    await async_wait_recording_done(hass)
    sums = dict(await _sums(hass))
    assert (sums["2026-09-30"], sums["2026-10-01"], sums["2026-10-14"]) == (150.0, 160.0, 290.0)

    await coord.async_record_statistics(_recs("2026-10-02", 14), meter_id="m1")
    await async_wait_recording_done(hass)
    assert dict(await _sums(hass))["2026-10-15"] == 300.0

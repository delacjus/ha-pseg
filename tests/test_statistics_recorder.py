"""External statistics against the real recorder (ported from review r1 probes).

These exercise the actual recorder queries and import queue, so they catch baseline
and ordering bugs that mocked `_async_get_last_stat_before` tests cannot.
"""

from __future__ import annotations

import asyncio
import copy
from datetime import UTC, date, datetime, timedelta
import json
import threading
from unittest.mock import AsyncMock, MagicMock, patch
import urllib.parse

from homeassistant.components.recorder import get_instance, statistics as recorder_stats
from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.components.recorder.tasks import RecorderTask
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import storage
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)
import requests_mock
from sqlalchemy.exc import SQLAlchemyError

from custom_components.pseg import coordinator as coord_mod
from custom_components.pseg.const import (
    CONF_STATISTICS_IMPORT_ENABLED,
    DOMAIN,
    PORTAL_BASE_URL,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator, PsegStatisticsError
from custom_components.pseg.pseg_client import PsegClient, PsegTransientError
from custom_components.pseg.statistics_hourly import (
    expected_hour_starts,
    ny_day_of,
    ny_midnight_utc,
)

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

    def attach_renewal_admission(self, admission, runtime=None, token=None) -> None:
        self.admission = admission

    def set_expected_meter_ids(self, meter_ids) -> None:
        self.expected_meter_ids = frozenset(meter_ids)

    def pending_confirmed_snapshot(self):
        return None

    def clear_confirmed_snapshot(self, snapshot_id) -> None:
        self.cleared_snapshot = snapshot_id


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
    client.export_cookies_and_auth_reason.return_value = ([], None)
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
        return {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}

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


class _SlowRecorderTask(RecorderTask):
    """Occupies the recorder thread so queued imports commit late (busy/slow database)."""

    commit_before = False

    def __init__(
        self,
        reached: threading.Event | None = None,
        release: threading.Event | None = None,
    ) -> None:
        self.reached = reached or threading.Event()
        self.release = release or threading.Event()

    def run(self, instance) -> None:
        self.reached.set()
        self.release.wait(timeout=10.0)


async def test_import_waits_for_recorder_commit_before_next_baseline(coord, hass) -> None:
    """With a busy recorder, the next import must not read the previous import's baseline early."""
    await coord.async_record_statistics(_recs("2026-10-01", 14), meter_id="m1")
    await async_wait_recording_done(hass)

    reached = threading.Event()
    release = threading.Event()
    get_instance(hass).queue_task(
        _SlowRecorderTask(reached=reached, release=release)
    )
    await hass.async_add_executor_job(reached.wait, 10.0)

    real_add = coord_mod.async_add_external_statistics

    def unblock_recorder(*args, **kwargs):
        release.set()
        return real_add(*args, **kwargs)

    with patch.object(
        coord_mod, "async_add_external_statistics", side_effect=unblock_recorder
    ):
        await asyncio.gather(
            coord.async_record_statistics(_recs("2026-09-01", 44), meter_id="m1"),
            coord.async_record_statistics(_recs("2026-10-02", 14), meter_id="m1"),
        )
    await async_wait_recording_done(hass)

    sums = await _sums(hass)
    assert [v for _, v in sums] == [10.0 * (i + 1) for i in range(45)]


async def test_recorder_commit_wait_times_out_and_releases_locks(coord, hass) -> None:
    """A recorder that never commits must not hang polls/backfills with the locks held."""
    never: asyncio.Future = hass.loop.create_future()

    async def hang() -> None:
        await never

    instance = get_instance(hass)
    with (
        patch.object(coord_mod, "RECORDER_COMMIT_TIMEOUT", 0.2),
        patch.object(instance, "async_block_till_done", hang),
        pytest.raises(coord_mod.PsegStatisticsError, match="did not commit"),
    ):
        await asyncio.wait_for(
            coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1"), 5
        )
    assert not coord._stats_lock.locked()
    assert not coord._update_lock.locked()
    never.cancel()


async def test_hung_commit_wait_does_not_freeze_poll_or_backfill(hass) -> None:
    """Even if the whole wait hangs, poll still updates sensors and backfill fails fast."""
    client = MagicMock()
    client.price_per_kwh = 0.25
    client.fetch_energy_data.return_value = {
        "meter": "Meter 1",
        "history_14d": _recs("2026-10-01", 2),
        "latest_kwh": 10.0,
    }
    client.fetch_history_range.return_value = _recs("2026-09-01", 5)
    client.export_cookies_and_auth_reason.return_value = ([], None)
    coord = PsegDataUpdateCoordinator(hass, client, {})

    async def hang(_hass) -> None:
        await asyncio.Event().wait()  # never set

    with (
        patch.object(coord_mod, "RECORDER_COMMIT_TIMEOUT", 0.2),
        patch.object(coord_mod, "_async_wait_for_recorder_commit", hang),
    ):
        data = await asyncio.wait_for(coord._async_update_data(), 5)
        assert data["latest_kwh"] == 10.0
        with pytest.raises(coord_mod.PsegStatisticsError):
            await asyncio.wait_for(coord.async_backfill_history("2026-09-01", "2026-09-05"), 5)
    assert not coord._update_lock.locked()
    assert not coord._stats_lock.locked()


# --- Hourly promotion: recorder-backed migration and recovery ---


def _hourly(
    day_str: str,
    kwh: float = 1.0,
    *,
    skip: frozenset[int] = frozenset(),
) -> list[dict]:
    """Build one canonical New York day of hourly points (24/23/25 starts)."""
    return [
        {
            "start": start,
            "kwh": kwh,
            "label": None,
            "label_ok": True,
            "interval_ok": True,
            "interval_reason": None,
        }
        for index, start in enumerate(
            expected_hour_starts(date.fromisoformat(day_str))
        )
        if index not in skip
    ]


def _daily_with(records: list[dict], day: str, kwh: float) -> list[dict]:
    """Replace one day's authoritative daily total (and its estimated cost)."""
    out = [dict(record) for record in records]
    for record in out:
        if record["date"] == day:
            record["kwh"] = kwh
            record["cost"] = round(kwh * 0.25, 2)
    return out


async def _rows(
    hass: HomeAssistant, statistic_id: str = CONSUMPTION_ID
) -> list[tuple[datetime, float, float]]:
    """Return every stored row as (start UTC, state, cumulative sum)."""
    result = await hass.async_add_executor_job(
        statistics_during_period,
        hass,
        datetime(2020, 1, 1, tzinfo=UTC),
        None,
        {statistic_id},
        "hour",
        None,
        {"sum", "state"},
    )
    return sorted(
        (
            datetime.fromtimestamp(row["start"], UTC),
            float(row["state"]),
            float(row["sum"]),
        )
        for row in result.get(statistic_id, [])
    )


def _day_rows(
    rows: list[tuple[datetime, float, float]], day: str
) -> list[tuple[datetime, float, float]]:
    return [row for row in rows if ny_day_of(row[0]) == date.fromisoformat(day)]


def _last_sum_by_day(
    rows: list[tuple[datetime, float, float]],
) -> dict[date, float]:
    return {ny_day_of(start): total for start, _, total in rows}


async def test_complete_hourly_day_replaces_daily_midnight_row(coord, hass) -> None:
    """A complete day overwrites the midnight daily row with the first hour value."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)

    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    rows = await _rows(hass)
    day_rows = _day_rows(rows, "2026-10-02")
    assert len(day_rows) == 24
    assert day_rows[0][0] == ny_midnight_utc(date(2026, 10, 2))
    assert day_rows[0][1] == 1.0  # not the 24 kWh daily total
    assert _last_sum_by_day(rows)[date(2026, 10, 2)] == 34.0
    assert rows[-1][2] == 44.0  # the whole chain is not double counted

    cost_rows = await _rows(hass, COST_ID)
    assert _last_sum_by_day(cost_rows)[date(2026, 10, 2)] == 8.5
    assert _last_sum_by_day(cost_rows)[date(2026, 10, 3)] == 11.0


async def test_repeat_hourly_import_is_idempotent(coord, hass) -> None:
    """A second identical poll writes nothing and keeps the hourly day intact."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    hourly = _hourly("2026-10-02")

    await coord.async_record_statistics(
        daily, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
    )
    await async_wait_recording_done(hass)
    first = (await _rows(hass), await _rows(hass, COST_ID))

    await coord.async_record_statistics(
        daily, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
    )
    await async_wait_recording_done(hass)

    assert (await _rows(hass), await _rows(hass, COST_ID)) == first
    assert not coord._stats_state.has_pending()
    assert not coord._stats_state.has_pending()


async def test_fall_dst_day_promotes_25_hours(coord, hass) -> None:
    """2025-11-02 New York has 25 hourly starts and promotes all of them."""
    await coord.async_record_statistics(_recs("2025-11-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)

    daily = _daily_with(_recs("2025-11-01", 3), "2025-11-02", 25.0)
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2025-11-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    day_rows = _day_rows(await _rows(hass), "2025-11-02")
    assert len(day_rows) == 25
    assert day_rows[0][0] == datetime(2025, 11, 2, 4, 0, tzinfo=UTC)
    assert day_rows[-1][0] == datetime(2025, 11, 3, 4, 0, tzinfo=UTC)
    assert _last_sum_by_day(await _rows(hass))[date(2025, 11, 3)] == 45.0


async def test_spring_dst_day_promotes_23_hours(coord, hass) -> None:
    """2026-03-08 New York has 23 hourly starts and promotes all of them."""
    await coord.async_record_statistics(_recs("2026-03-07", 3), meter_id="m1")
    await async_wait_recording_done(hass)

    daily = _daily_with(_recs("2026-03-07", 3), "2026-03-08", 23.0)
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-03-08"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    day_rows = _day_rows(await _rows(hass), "2026-03-08")
    assert len(day_rows) == 23
    assert day_rows[0][0] == datetime(2026, 3, 8, 5, 0, tzinfo=UTC)
    assert day_rows[-1][0] == datetime(2026, 3, 9, 3, 0, tzinfo=UTC)


async def test_incomplete_hourly_day_still_imports_authoritative_daily(
    coord, hass
) -> None:
    """With no hourly provenance the corrected daily row is imported as today."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)

    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 25.0)
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02", skip=frozenset({7})),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    day_rows = _day_rows(await _rows(hass), "2026-10-02")
    assert len(day_rows) == 1
    assert day_rows[0][1] == 25.0
    assert _last_sum_by_day(await _rows(hass))[date(2026, 10, 3)] == 45.0


async def test_sparse_hourly_day_keeps_daily_row(coord, hass) -> None:
    """Three points are never treated as a complete day."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)

    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    sparse = _hourly("2026-10-02")[:3]
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=sparse,
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    day_rows = _day_rows(await _rows(hass), "2026-10-02")
    assert len(day_rows) == 1
    assert day_rows[0][1] == 24.0


async def test_zero_usage_hourly_day_promotes(coord, hass) -> None:
    """An explicit zero day promotes, with 24 zero states and an unmoved sum."""
    daily = [
        {"date": "2026-10-01", "kwh": 10.0, "cost": 2.5},
        {"date": "2026-10-02", "kwh": 0.0, "cost": 0.0},
        {"date": "2026-10-03", "kwh": 10.0, "cost": 2.5},
    ]
    await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02", 0.0),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    rows = await _rows(hass)
    day_rows = _day_rows(rows, "2026-10-02")
    assert len(day_rows) == 24
    assert all(row[1] == 0.0 for row in day_rows)
    assert _last_sum_by_day(rows)[date(2026, 10, 3)] == 20.0


async def test_daily_retry_equal_total_keeps_hourly(coord, hass) -> None:
    """A daily-only retry with the same total must not downgrade the day."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    day_rows = _day_rows(await _rows(hass), "2026-10-02")
    assert len(day_rows) == 24
    assert day_rows[0][1] == 1.0
    assert _last_sum_by_day(await _rows(hass))[date(2026, 10, 3)] == 44.0


async def test_daily_conflict_rejects_whole_import_before_writes(coord, hass) -> None:
    """A changed daily total for a promoted day aborts both series, unchanged."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)
    before = (await _rows(hass), await _rows(hass, COST_ID))

    conflicting = _daily_with(daily, "2026-10-02", 30.0)
    with pytest.raises(coord_mod.PsegStatisticsConflictError, match="rejected"):
        await coord.async_record_statistics(conflicting, meter_id="m1")
    await async_wait_recording_done(hass)

    assert (await _rows(hass), await _rows(hass, COST_ID)) == before


async def test_hourly_correction_replaces_day_and_rechains_newer_rows(
    coord, hass
) -> None:
    """Authoritative hourly correction replaces the day and re-chains later rows."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    await coord.async_record_statistics(
        _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0),
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    corrected_daily = _daily_with(_recs("2026-10-01", 4), "2026-10-02", 48.0)
    await coord.async_record_statistics(
        corrected_daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02", 2.0),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    rows = await _rows(hass)
    day_rows = _day_rows(rows, "2026-10-02")
    assert len(day_rows) == 24
    assert all(row[1] == 2.0 for row in day_rows)
    assert _last_sum_by_day(rows)[date(2026, 10, 4)] == 78.0
    cost_rows = await _rows(hass, COST_ID)
    assert _last_sum_by_day(cost_rows)[date(2026, 10, 4)] == 19.5


async def test_partial_hourly_for_promoted_day_keeps_hourly(coord, hass) -> None:
    """An incomplete later payload cannot downgrade an already promoted day."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)
    before = await _rows(hass)

    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02", skip=frozenset({4})),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    assert await _rows(hass) == before
    assert len(_day_rows(before, "2026-10-02")) == 24


@pytest.mark.parametrize("time_zone", ["UTC", "US/Pacific"])
async def test_hourly_promotion_independent_of_ha_time_zone(
    coord, hass, time_zone
) -> None:
    """Promotion follows New York midnights regardless of HA's configured zone."""
    await hass.config.async_set_time_zone(time_zone)
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)

    await coord.async_record_statistics(
        _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0),
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    day_rows = _day_rows(await _rows(hass), "2026-10-02")
    assert len(day_rows) == 24
    assert day_rows[0][0] == ny_midnight_utc(date(2026, 10, 2))


async def test_hourly_cost_keeps_sub_cent_precision(coord, hass) -> None:
    """24 hourly cost states at 0.247 are not rounded to 0.25 each."""
    coord.client.price_per_kwh = 0.247
    daily = [
        {"date": "2026-10-01", "kwh": 10.0, "cost": 2.47},
        {"date": "2026-10-02", "kwh": 24.0, "cost": 5.93},
        {"date": "2026-10-03", "kwh": 10.0, "cost": 2.47},
    ]
    await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    day_cost = _day_rows(await _rows(hass, COST_ID), "2026-10-02")
    assert len(day_cost) == 24
    assert day_cost[0][1] == pytest.approx(0.247)
    assert day_cost[-1][2] - 2.47 == pytest.approx(24 * 0.247)


async def test_journal_recovers_when_only_consumption_was_written(
    coord, hass
) -> None:
    """A crash between the two series leaves a journal that converges both series."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    real_add = coord_mod.async_add_external_statistics
    calls = {"count": 0}

    def fail_second(hass_arg, metadata, stats) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            real_add(hass_arg, metadata, stats)
            return
        raise RuntimeError("simulated crash between series")

    with (
        patch.object(coord_mod, "async_add_external_statistics", fail_second),
        pytest.raises(RuntimeError, match="simulated crash"),
    ):
        await coord.async_record_statistics(
            daily,
            meter_id="m1",
            hourly_records=_hourly("2026-10-02"),
            hourly_granularity="hourly",
        )
    await async_wait_recording_done(hass)

    assert len(_day_rows(await _rows(hass), "2026-10-02")) == 24
    assert len(_day_rows(await _rows(hass, COST_ID), "2026-10-02")) == 1
    assert coord._stats_state.has_pending()

    # The next normal daily poll (same authoritative total) runs recovery first.
    await coord.async_record_statistics(
        _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0), meter_id="m1"
    )
    await async_wait_recording_done(hass)

    assert len(_day_rows(await _rows(hass, COST_ID), "2026-10-02")) == 24
    assert not coord._stats_state.has_pending()
    assert not coord._stats_state.has_pending()
    assert _last_sum_by_day(await _rows(hass))[date(2026, 10, 3)] == 44.0


async def test_commit_timeout_keeps_journal_and_next_poll_recovers(coord, hass) -> None:
    """A commit barrier timeout leaves provenance pending; the next poll finishes it."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    real_wait = coord_mod._async_wait_for_recorder_commit
    calls = {"count": 0}

    async def timeout_once(hass_arg) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise TimeoutError
        await real_wait(hass_arg)

    with (
        patch.object(coord_mod, "_async_wait_for_recorder_commit", timeout_once),
        pytest.raises(coord_mod.PsegStatisticsError, match="did not commit"),
    ):
        await coord.async_record_statistics(
            daily,
            meter_id="m1",
            hourly_records=_hourly("2026-10-02"),
            hourly_granularity="hourly",
        )
    await async_wait_recording_done(hass)
    assert coord._stats_state.has_pending()

    await coord.async_record_statistics(
        _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0), meter_id="m1"
    )
    await async_wait_recording_done(hass)

    assert not coord._stats_state.has_pending()
    assert not coord._stats_state.has_pending()
    assert len(_day_rows(await _rows(hass), "2026-10-02")) == 24
    assert _last_sum_by_day(await _rows(hass))[date(2026, 10, 3)] == 44.0


async def test_disabled_imports_block_automatic_deferred_and_manual(
    hass: HomeAssistant,
) -> None:
    """The kill switch stops every statistics path and leaves keepalive alone."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="m1",
        data={},
        options={CONF_STATISTICS_IMPORT_ENABLED: False},
    )
    entry.add_to_hass(hass)
    client = MagicMock()
    client.price_per_kwh = 0.25
    client.fetch_history_range.return_value = _recs("2026-10-01", 3)
    client.fetch_energy_data.return_value = {
        "meter": "Meter #1",
        "history_14d": _recs("2026-10-01", 2),
        "daily_records": _recs("2026-10-01", 2),
        "hourly_records": [],
    }
    client.export_cookies_and_auth_reason.return_value = ([], None)
    client.keepalive.return_value = True
    client.okta_session_expired_at = None
    client.auth_reason = None
    client.idle_gap_seconds = None
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )

    assert coord.statistics_imports_enabled() is False
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    assert await _rows(hass) == []

    assert await coord.async_backfill_history("2026-10-01", "2026-10-03") == 0
    client.fetch_history_range.assert_not_called()

    hass.set_state(CoreState.starting)
    with patch.object(
        coord, "async_record_statistics", new_callable=AsyncMock
    ) as record:
        await coord._async_update_data()
        record.assert_not_awaited()
        hass.set_state(CoreState.running)
        hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
        await hass.async_block_till_done()
        record.assert_not_awaited()

    await coord._async_keepalive(datetime.now(UTC))
    client.keepalive.assert_called()
    assert coord.auth_required is False


async def test_multiaccount_hourly_promotions_stay_separate(hass) -> None:
    """Two meters promote independently under their own stable statistic ids."""
    one = PsegDataUpdateCoordinator(hass, _Client(), {})
    two = PsegDataUpdateCoordinator(hass, _Client(), {})
    daily = _recs("2026-10-01", 2)

    await one.async_record_statistics(
        _daily_with(daily, "2026-10-01", 24.0),
        meter_id="m1",
        hourly_records=_hourly("2026-10-01"),
        hourly_granularity="hourly",
    )
    await two.async_record_statistics(
        _daily_with(daily, "2026-10-01", 48.0),
        meter_id="m2",
        hourly_records=_hourly("2026-10-01", 2.0),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    assert len(_day_rows(await _rows(hass, "pseg:m1_energy_consumption"), "2026-10-01")) == 24
    assert len(_day_rows(await _rows(hass, "pseg:m2_energy_consumption"), "2026-10-01")) == 24
    assert _last_sum_by_day(
        await _rows(hass, "pseg:m1_energy_consumption")
    )[date(2026, 10, 2)] == 34.0
    assert _last_sum_by_day(
        await _rows(hass, "pseg:m2_energy_consumption")
    )[date(2026, 10, 2)] == 58.0



async def test_daily_cost_change_does_not_conflict_with_equal_energy(
    coord, hass, caplog
) -> None:
    """A changed estimated rate must not reject a day whose energy still matches."""
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)
    before_cost = await _rows(hass, COST_ID)

    changed_rate = [dict(record) for record in daily]
    for record in changed_rate:
        if record["date"] == "2026-10-02":
            record["cost"] = 7.00

    with caplog.at_level("DEBUG", logger="custom_components.pseg.coordinator"):
        await coord.async_record_statistics(changed_rate, meter_id="m1")
    await async_wait_recording_done(hass)

    assert "Keeping the promoted hourly cost" in caplog.text
    assert await _rows(hass, COST_ID) == before_cost
    assert len(_day_rows(await _rows(hass), "2026-10-02")) == 24


async def test_manual_backfill_equal_total_keeps_promoted_hourly(hass) -> None:
    """The action path uses the same reconciliation and never downgrades a day."""
    client = MagicMock()
    client.price_per_kwh = 0.25
    client.fetch_history_range.return_value = _daily_with(
        _recs("2026-10-01", 3), "2026-10-02", 24.0
    )
    coord = PsegDataUpdateCoordinator(hass, client, {})
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    await coord.async_record_statistics(
        _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0),
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    with patch.object(coord, "_get_meter_id", return_value="m1"):
        count = await coord.async_backfill_history("2026-10-01", "2026-10-03")
    await async_wait_recording_done(hass)

    assert count == 3
    assert len(_day_rows(await _rows(hass), "2026-10-02")) == 24
    assert _last_sum_by_day(await _rows(hass))[date(2026, 10, 3)] == 44.0


async def test_manual_backfill_conflict_rejects_before_writes(hass) -> None:
    """A conflicting manual backfill fails loudly and leaves both series intact."""
    client = MagicMock()
    client.price_per_kwh = 0.25
    coord = PsegDataUpdateCoordinator(hass, client, {})
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    await coord.async_record_statistics(
        _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0),
        meter_id="m1",
        hourly_records=_hourly("2026-10-02"),
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)
    before = (await _rows(hass), await _rows(hass, COST_ID))

    client.fetch_history_range.return_value = _daily_with(
        _recs("2026-10-01", 3), "2026-10-02", 30.0
    )
    with (
        patch.object(coord, "_get_meter_id", return_value="m1"),
        pytest.raises(coord_mod.PsegStatisticsConflictError, match="rejected"),
    ):
        await coord.async_backfill_history("2026-10-01", "2026-10-03")
    await async_wait_recording_done(hass)

    assert (await _rows(hass), await _rows(hass, COST_ID)) == before


async def test_retired_backfill_cannot_overwrite_new_promotion(hass) -> None:
    """An old coordinator stops before its next write; the new promotion wins."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    old = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    entry.async_on_unload(old.stop_keepalive)
    daily = _recs("2026-10-02", 1, 24)
    await old.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    client = MagicMock()
    client.price_per_kwh = 0.25
    client.fetch_history_range.return_value = _recs("2026-10-02", 1, 26)
    old.client = client
    reached = asyncio.Event()
    release = asyncio.Event()
    real_get = coord_mod._async_get_stats_from

    async def hold(hass_arg, statistic_id, start):
        rows = await real_get(hass_arg, statistic_id, start)
        if statistic_id == COST_ID:
            reached.set()
            await release.wait()
        return rows

    with patch.object(coord_mod, "_async_get_stats_from", hold):
        old_task = asyncio.create_task(
            old.async_backfill_history("2026-10-02", "2026-10-02"),
            name="old-service",
        )
        await asyncio.wait_for(reached.wait(), 5)
        await entry._async_process_on_unload(hass)
        assert old._stopped is True

        new = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
        new_task = asyncio.create_task(
            new.async_record_statistics(
                daily,
                meter_id="m1",
                hourly_records=_hourly("2026-10-02"),
                hourly_granularity="hourly",
            )
        )
        await asyncio.sleep(0)
        assert not new_task.done()  # blocked behind the old entry lock
        release.set()
        assert await asyncio.wait_for(old_task, 5) == 0
        await asyncio.wait_for(new_task, 5)

    await async_wait_recording_done(hass)
    rows = await _rows(hass)
    day_rows = _day_rows(rows, "2026-10-02")
    assert len(day_rows) == 24
    assert day_rows[0][1] == 1.0
    assert day_rows[0][2] == 1.0
    assert sum(row[1] for row in day_rows) == 24.0


async def test_retired_store_cannot_overwrite_new_provenance(hass) -> None:
    """Old coordinator Store I/O must not erase the new promotion."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    old = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    entry.async_on_unload(old.stop_keepalive)
    daily = _recs("2026-10-02", 2, 24)
    await old.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    reached = asyncio.Event()
    release = asyncio.Event()
    real_get = coord_mod._async_get_stats_from

    async def hold(hass_arg, statistic_id, start):
        rows = await real_get(hass_arg, statistic_id, start)
        if statistic_id == COST_ID:
            reached.set()
            await release.wait()
        return rows

    with patch.object(coord_mod, "_async_get_stats_from", hold):
        old_task = asyncio.create_task(
            old.async_record_statistics(
                daily,
                meter_id="m1",
                hourly_records=_hourly("2026-10-03"),
                hourly_granularity="hourly",
            ),
            name="old-hourly",
        )
        await asyncio.wait_for(reached.wait(), 5)
        await entry._async_process_on_unload(hass)
        new = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
        new_task = asyncio.create_task(
            new.async_record_statistics(
                daily,
                meter_id="m1",
                hourly_records=_hourly("2026-10-02"),
                hourly_granularity="hourly",
            )
        )
        await asyncio.sleep(0)
        assert not new_task.done()
        release.set()
        await asyncio.wait_for(old_task, 5)
        await asyncio.wait_for(new_task, 5)

    await async_wait_recording_done(hass)
    from custom_components.pseg.statistics_state import StatisticsStateStore

    disk = StatisticsStateStore(hass, entry.entry_id)
    await disk.async_load()
    assert set(disk.promoted(CONSUMPTION_ID)) == {"2026-10-02"}
    assert set(new._stats_state.promoted(CONSUMPTION_ID)) == {"2026-10-02"}


async def test_pause_during_final_read_prevents_write(hass) -> None:
    """Pausing while a read is in flight must stop the imminent write."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    reached = asyncio.Event()
    release = asyncio.Event()
    real_get = coord_mod._async_get_stats_from

    async def hold(hass_arg, statistic_id, start):
        rows = await real_get(hass_arg, statistic_id, start)
        if statistic_id == COST_ID:
            reached.set()
            await release.wait()
        return rows

    with patch.object(coord_mod, "_async_get_stats_from", hold):
        task = asyncio.create_task(
            coord.async_record_statistics(_recs("2026-10-02", 1), meter_id="m1")
        )
        await asyncio.wait_for(reached.wait(), 5)
        hass.config_entries.async_update_entry(
            entry, options={CONF_STATISTICS_IMPORT_ENABLED: False}
        )
        assert coord.statistics_imports_enabled() is False
        release.set()
        await asyncio.wait_for(task, 5)

    await async_wait_recording_done(hass)
    assert await _rows(hass) == []


async def test_recorder_series_failure_retains_journal_until_recovered(hass) -> None:
    """A swallowed recorder cost error must not commit provenance."""
    coord = PsegDataUpdateCoordinator(hass, _Client(), {})
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    real_import = recorder_stats.import_statistics

    def fail_cost(instance, metadata, stats, table):
        if metadata["statistic_id"] == COST_ID:
            raise SQLAlchemyError("injected recorder task failure")
        return real_import(instance, metadata, stats, table)

    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    with (
        patch.object(recorder_stats, "import_statistics", fail_cost),
        pytest.raises(PsegStatisticsError, match="did not persist"),
    ):
        await coord.async_record_statistics(
            daily,
            meter_id="m1",
            hourly_records=_hourly("2026-10-02"),
            hourly_granularity="hourly",
        )
    await async_wait_recording_done(hass)

    assert coord._stats_state.has_pending()
    assert len(_day_rows(await _rows(hass), "2026-10-02")) == 24
    assert len(_day_rows(await _rows(hass, COST_ID), "2026-10-02")) == 1

    await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    assert len(_day_rows(await _rows(hass, COST_ID), "2026-10-02")) == 24
    assert not coord._stats_state.has_pending()


async def test_journal_replays_same_batch_daily_correction(hass) -> None:
    """The journal covers daily corrections outside the promoted day too."""
    coord = PsegDataUpdateCoordinator(hass, _Client(), {})
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(
        _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0),
        "2026-10-01",
        20.0,
    )
    real_add = coord_mod.async_add_external_statistics

    def fail_cost(hass_arg, metadata, stats) -> None:
        if metadata["statistic_id"] == COST_ID:
            raise RuntimeError("simulated crash between series")
        real_add(hass_arg, metadata, stats)

    with (
        patch.object(coord_mod, "async_add_external_statistics", fail_cost),
        pytest.raises(RuntimeError, match="simulated crash"),
    ):
        await coord.async_record_statistics(
            daily,
            meter_id="m1",
            hourly_records=_hourly("2026-10-02"),
            hourly_granularity="hourly",
        )
    await async_wait_recording_done(hass)
    assert coord._stats_state.has_pending()

    await coord.async_record_statistics(_recs("2026-10-03", 1), meter_id="m1")
    await async_wait_recording_done(hass)

    rows = await _rows(hass)
    cost_rows = await _rows(hass, COST_ID)
    assert _day_rows(rows, "2026-10-01")[0][1] == 20.0
    assert _day_rows(cost_rows, "2026-10-01")[0][1] == 5.0
    assert _last_sum_by_day(rows)[date(2026, 10, 1)] == 20.0
    assert _last_sum_by_day(rows)[date(2026, 10, 2)] == 44.0
    assert _last_sum_by_day(rows)[date(2026, 10, 3)] == 54.0
    assert not coord._stats_state.has_pending()


async def test_cancelled_commit_wait_leaves_pending_and_recovers(hass) -> None:
    """Cancellation after queuing keeps the journal; the next attempt verifies it."""
    coord = PsegDataUpdateCoordinator(hass, _Client(), {})
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    entered = asyncio.Event()
    never = asyncio.Event()

    async def hang(_hass) -> None:
        entered.set()
        await never.wait()

    with patch.object(coord_mod, "_async_wait_for_recorder_commit", hang):
        task = asyncio.create_task(
            coord.async_record_statistics(
                daily,
                meter_id="m1",
                hourly_records=_hourly("2026-10-02"),
                hourly_granularity="hourly",
            )
        )
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    await async_wait_recording_done(hass)
    assert coord._stats_state.has_pending()

    await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    assert not coord._stats_state.has_pending()
    assert len(_day_rows(await _rows(hass), "2026-10-02")) == 24
    assert _last_sum_by_day(await _rows(hass))[date(2026, 10, 3)] == 44.0


async def test_cancelled_store_save_is_drained_before_newer_save(
    hass, tmp_path
) -> None:
    """A detached executor save cannot overwrite a newer coordinator's state."""
    coord = PsegDataUpdateCoordinator(hass, _Client(), {})
    store = coord._stats_state
    await store.async_load()
    disk = tmp_path / "store.json"
    store._store.__dict__["path"] = str(disk)
    calls: list[dict] = []
    entered = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()

    def write_wrapper(data) -> None:
        disk.write_text(
            json.dumps(
                {
                    "version": store._store.version,
                    "minor_version": store._store.minor_version,
                    "key": store._store.key,
                    "data": data,
                }
            )
        )

    def fake_write(wrapper) -> None:
        calls.append(copy.deepcopy(wrapper["data"]))
        loop.call_soon_threadsafe(entered.set)
        if not release.wait(15):
            raise TimeoutError("bounded synthetic write")
        write_wrapper(wrapper["data"])

    store._data["test_marker"] = "old"
    store._mark_dirty()
    with patch.object(store._store, "_write_data", fake_write):
        old_task = asyncio.create_task(store._async_save())
        await asyncio.wait_for(entered.wait(), 5)
        old_task.cancel()
        store._data["test_marker"] = "new"
        store._mark_dirty()
        new_task = asyncio.create_task(store._async_save())
        await asyncio.sleep(0)
        assert not new_task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await old_task
        await asyncio.wait_for(new_task, 5)

    assert [snapshot["test_marker"] for snapshot in calls] == ["old", "new"]


async def test_pause_during_pending_recovery_keeps_journal(hass) -> None:
    """A pause while recovery is verifying must not replay or commit."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    real_add = coord_mod.async_add_external_statistics

    def fail_cost(hass_arg, metadata, stats) -> None:
        if metadata["statistic_id"] == COST_ID:
            raise RuntimeError("simulated crash between series")
        real_add(hass_arg, metadata, stats)

    with (
        patch.object(coord_mod, "async_add_external_statistics", fail_cost),
        pytest.raises(RuntimeError, match="simulated crash"),
    ):
        await coord.async_record_statistics(
            daily,
            meter_id="m1",
            hourly_records=_hourly("2026-10-02"),
            hourly_granularity="hourly",
        )
    await async_wait_recording_done(hass)
    assert coord._stats_state.has_pending()

    entered = asyncio.Event()
    release = asyncio.Event()
    real_verify = coord._async_verify_mutation

    async def hold_verify(mutation):
        entered.set()
        await release.wait()
        return await real_verify(mutation)

    with patch.object(coord, "_async_verify_mutation", hold_verify):
        task = asyncio.create_task(
            coord.async_record_statistics(daily, meter_id="m1")
        )
        await asyncio.wait_for(entered.wait(), 5)
        hass.config_entries.async_update_entry(
            entry, options={CONF_STATISTICS_IMPORT_ENABLED: False}
        )
        release.set()
        await asyncio.wait_for(task, 5)
    await async_wait_recording_done(hass)

    assert coord._stats_state.has_pending()
    assert len(_day_rows(await _rows(hass, COST_ID), "2026-10-02")) == 1

    hass.config_entries.async_update_entry(
        entry, options={CONF_STATISTICS_IMPORT_ENABLED: True}
    )
    await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    assert not coord._stats_state.has_pending()
    assert len(_day_rows(await _rows(hass, COST_ID), "2026-10-02")) == 24


async def test_recorder_sum_mismatch_retains_journal(hass) -> None:
    """Rows with the wrong cumulative sum must not commit provenance."""
    coord = PsegDataUpdateCoordinator(hass, _Client(), {})
    await coord.async_record_statistics(_recs("2026-10-01", 3), meter_id="m1")
    await async_wait_recording_done(hass)
    real_import = recorder_stats.import_statistics

    def corrupt_cost(instance, metadata, stats, table):
        if metadata["statistic_id"] == COST_ID:
            stats = [{**row, "sum": row["sum"] - 1.0} for row in stats]
        return real_import(instance, metadata, stats, table)

    daily = _daily_with(_recs("2026-10-01", 3), "2026-10-02", 24.0)
    with (
        patch.object(recorder_stats, "import_statistics", corrupt_cost),
        pytest.raises(PsegStatisticsError, match="did not persist"),
    ):
        await coord.async_record_statistics(
            daily,
            meter_id="m1",
            hourly_records=_hourly("2026-10-02"),
            hourly_granularity="hourly",
        )
    await async_wait_recording_done(hass)
    assert coord._stats_state.has_pending()

    await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    assert not coord._stats_state.has_pending()
    assert _last_sum_by_day(await _rows(hass, COST_ID))[date(2026, 10, 3)] == 11.0


async def test_cancelled_journal_save_blocks_replay_until_durable(hass) -> None:
    """After an actual 5 s drain, recovery refuses until the journal bytes persist."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    old = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    store = old._stats_state
    daily = _recs("2026-10-02", 1, 24)
    entered = asyncio.Event()
    release = threading.Event()
    completed: list[dict] = []
    loop = asyncio.get_running_loop()
    real_write = store._store._write_data

    def held_write(wrapper) -> None:
        loop.call_soon_threadsafe(entered.set)
        if not release.wait(15):
            raise TimeoutError("bounded synthetic write")
        real_write(wrapper)
        completed.append(copy.deepcopy(wrapper["data"]))

    started = loop.time()
    try:
        with patch.object(store._store, "_write_data", held_write):
            task = asyncio.create_task(
                old.async_record_statistics(
                    daily,
                    meter_id="m1",
                    hourly_records=_hourly("2026-10-02"),
                    hourly_granularity="hourly",
                )
            )
            await asyncio.wait_for(entered.wait(), 3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 7)
            assert asyncio.get_running_loop().time() - started >= 4.5
            assert not completed

            old.stop_keepalive()
            new = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
            with pytest.raises(PsegStatisticsError, match="not durable"):
                await asyncio.wait_for(
                    new.async_record_statistics(daily, meter_id="m1"), 2
                )
            assert await _rows(hass) == []

            release.set()
            assert await asyncio.wait_for(
                new._stats_state.async_wait_durable(), 5
            )
    finally:
        release.set()
        async with asyncio.timeout(5):
            async with store._io_lock:
                pass

    assert new._stats_state.has_pending()
    await new.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)
    assert not new._stats_state.has_pending()
    assert len(await _rows(hass)) == len(await _rows(hass, COST_ID)) == 24

@pytest.mark.parametrize("hourly_mode", [False, True])
async def test_executor_save_expiry_refuses_and_cold_store_recovers(
    hass, tmp_path, hourly_mode
) -> None:
    """No recorder writes before durability; durable bytes recover after restart."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    old = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    store = old._stats_state
    disk = tmp_path / "journal.json"
    store._store.__dict__["path"] = str(disk)
    baseline = _recs("2026-10-01", 2)
    await old.async_record_statistics(baseline, meter_id="m1")
    await async_wait_recording_done(hass)
    corrected = _daily_with(
        _daily_with(baseline, "2026-10-02", 24.0), "2026-10-01", 20.0
    )
    hourly = _hourly("2026-10-02") if hourly_mode else []
    entered = asyncio.Event()
    release = threading.Event()
    completed: list[dict] = []
    loop = asyncio.get_running_loop()
    real_import = recorder_stats.import_statistics
    real_write = store._store._write_data
    cost_imports = {"count": 0}

    def blocked_write(wrapper) -> None:
        loop.call_soon_threadsafe(entered.set)
        if not release.wait(15):
            raise TimeoutError("bounded synthetic executor write")
        real_write(wrapper)
        completed.append(copy.deepcopy(wrapper["data"]))

    def record_cost(instance, metadata, stats, table):
        if metadata["statistic_id"] == COST_ID:
            cost_imports["count"] += 1
            raise SQLAlchemyError("independent recorder cost failure")
        return real_import(instance, metadata, stats, table)

    try:
        with patch.object(store._store, "_write_data", blocked_write):
            task = asyncio.create_task(
                old.async_record_statistics(
                    corrected,
                    meter_id="m1",
                    hourly_records=hourly,
                    hourly_granularity="hourly" if hourly_mode else "unavailable",
                )
            )
            await asyncio.wait_for(entered.wait(), 3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 7)
            assert not completed

            old.stop_keepalive()
            recovery = PsegDataUpdateCoordinator(
                hass, _Client(), {}, config_entry=entry
            )
            with (
                patch.object(recorder_stats, "import_statistics", record_cost),
                pytest.raises(PsegStatisticsError, match="not durable"),
            ):
                await asyncio.wait_for(
                    recovery.async_record_statistics(
                        _recs("2026-10-02", 1, 24.0), meter_id="m1"
                    ),
                    2,
                )
            await async_wait_recording_done(hass)

            # The blocked journal must prevent every recorder mutation.
            assert cost_imports["count"] == 0
            assert _day_rows(await _rows(hass), "2026-10-01")[0][1] == 10.0
            assert _day_rows(await _rows(hass, COST_ID), "2026-10-01")[0][1] == 2.5

            release.set()
            assert await asyncio.wait_for(
                recovery._stats_state.async_wait_durable(), 5
            )

        durable = json.loads(disk.read_text())["data"]
        assert durable["pending"]

        # The blocked writer already persisted the wrapper on release; load a
        # fresh Store instance as a new process would.
        recovery.stop_keepalive()
        hass.data[f"{DOMAIN}_statistics_runtimes"].pop(entry.entry_id)
        cold = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
        cold._stats_state._store.__dict__["path"] = str(disk)
        cold._stats_state._store._manager.async_invalidate(
            cold._stats_state._store.key
        )
        await cold._stats_state.async_load()
        await cold.async_record_statistics(
            _recs("2026-10-02", 1, 24.0), meter_id="m1"
        )
        await async_wait_recording_done(hass)

        energy = await _rows(hass)
        cost = await _rows(hass, COST_ID)
        assert not cold._stats_state.has_pending()
        assert _day_rows(energy, "2026-10-01")[0][1] == 20.0
        assert _day_rows(cost, "2026-10-01")[0][1] == 5.0
        assert len(_day_rows(energy, "2026-10-02")) == (
            24 if hourly_mode else 1
        )
        assert len(_day_rows(cost, "2026-10-02")) == (
            24 if hourly_mode else 1
        )
        assert energy[-1][2] == 44.0
        assert cost[-1][2] == 11.0
    finally:
        release.set()
        async with asyncio.timeout(5):
            async with store._io_lock:
                pass


async def test_failed_journal_save_blocks_recorder_and_recovers(hass) -> None:
    """A failed journal write is never followed by a recorder mutation."""
    coord = PsegDataUpdateCoordinator(hass, _Client(), {})
    daily = _recs("2026-10-02", 1, 24)
    state = {"fail": True}
    real_write = coord._stats_state._store._write_data

    def fail_write(wrapper) -> None:
        if state["fail"]:
            raise OSError("synthetic journal disk failure")
        real_write(wrapper)

    with (
        patch.object(coord._stats_state._store, "_write_data", fail_write),
        pytest.raises(PsegStatisticsError, match="journal"),
    ):
        await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    assert await _rows(hass) == []
    assert coord._stats_state.has_pending()

    state["fail"] = False
    await coord.async_record_statistics(daily, meter_id="m1")
    await async_wait_recording_done(hass)

    assert not coord._stats_state.has_pending()
    assert len(await _rows(hass)) == len(await _rows(hass, COST_ID)) == 1


def _cold_pseg_coordinator(hass, entry, disk):
    """Build a fresh coordinator whose Store loads the persisted scratch bytes."""
    old = hass.data[DOMAIN][entry.entry_id]
    old.stop_keepalive()
    hass.data[f"{DOMAIN}_statistics_runtimes"].pop(entry.entry_id, None)
    cold = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    cold._stats_state._store.__dict__["path"] = str(disk)
    hass.data[DOMAIN][entry.entry_id] = cold
    return cold


def _atomic_writer(disk, blocked, fault):
    """Production atomic writer redirected for a real filesystem failure test."""

    def prepared(mode, payload):
        target = blocked if fault["enabled"] else disk
        storage.write_utf8_file_atomic(str(target), payload, False, mode=mode)

    return prepared


@pytest.mark.parametrize("hourly_mode", [False, True])
async def test_real_atomic_write_failure_refuses_and_cold_store_unchanged(
    hass, tmp_path, hourly_mode
) -> None:
    """A swallowed/real write failure must not advance durability or write LTS."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    old = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    store = old._stats_state
    disk = tmp_path / "journal.json"
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    store._store.__dict__["path"] = str(disk)
    baseline = _recs("2026-10-01", 2)
    await old.async_record_statistics(baseline, meter_id="m1")
    await async_wait_recording_done(hass)
    baseline_bytes = disk.read_bytes()
    corrected = _daily_with(
        _daily_with(baseline, "2026-10-02", 24.0), "2026-10-01", 20.0
    )
    hourly = _hourly("2026-10-02") if hourly_mode else []
    fault = {"enabled": True}
    real_import = recorder_stats.import_statistics
    cost_imports = {"count": 0}

    def fail_cost(instance, metadata, stats, table):
        if metadata["statistic_id"] == COST_ID:
            cost_imports["count"] += 1
            raise SQLAlchemyError("real recorder cost failure")
        return real_import(instance, metadata, stats, table)

    with (
        patch.object(
            store._store,
            "_write_prepared_data",
            _atomic_writer(disk, blocked, fault),
        ),
        patch.object(recorder_stats, "import_statistics", fail_cost),
        pytest.raises(PsegStatisticsError, match="journal"),
    ):
        await old.async_record_statistics(
            corrected,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly" if hourly_mode else "unavailable",
        )
    await async_wait_recording_done(hass)

    assert cost_imports["count"] == 0
    assert _day_rows(await _rows(hass), "2026-10-01")[0][1:] == (10.0, 10.0)
    assert _day_rows(await _rows(hass, COST_ID), "2026-10-01")[0][1:] == (
        2.5,
        2.5,
    )
    assert disk.read_bytes() == baseline_bytes
    assert store._saved_revision < store._revision
    assert old._stats_state.has_pending()
    assert not json.loads(disk.read_text())["data"]["pending"]

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = old
    cold = _cold_pseg_coordinator(hass, entry, disk)
    await cold._stats_state.async_load()
    await cold.async_record_statistics(_recs("2026-10-02", 1, 24.0), meter_id="m1")
    await async_wait_recording_done(hass)

    assert _day_rows(await _rows(hass), "2026-10-01")[0][1:] == (10.0, 10.0)
    assert _day_rows(await _rows(hass, COST_ID), "2026-10-01")[0][1:] == (
        2.5,
        2.5,
    )


@pytest.mark.parametrize("hourly_mode", [False, True])
async def test_real_atomic_write_failure_restore_io_retry_converges(
    hass, tmp_path, hourly_mode
) -> None:
    """Restoring the atomic writer lets recovery replay the durable-intent batch."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    old = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    store = old._stats_state
    disk = tmp_path / "journal.json"
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    store._store.__dict__["path"] = str(disk)
    baseline = _recs("2026-10-01", 2)
    await old.async_record_statistics(baseline, meter_id="m1")
    await async_wait_recording_done(hass)
    corrected = _daily_with(
        _daily_with(baseline, "2026-10-02", 24.0), "2026-10-01", 20.0
    )
    hourly = _hourly("2026-10-02") if hourly_mode else []
    fault = {"enabled": True}

    with (
        patch.object(
            store._store,
            "_write_prepared_data",
            _atomic_writer(disk, blocked, fault),
        ),
        pytest.raises(PsegStatisticsError, match="journal"),
    ):
        await old.async_record_statistics(
            corrected,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly" if hourly_mode else "unavailable",
        )
    await async_wait_recording_done(hass)
    assert _day_rows(await _rows(hass), "2026-10-01")[0][1] == 10.0

    fault["enabled"] = False
    await old.async_record_statistics(
        corrected,
        meter_id="m1",
        hourly_records=hourly,
        hourly_granularity="hourly" if hourly_mode else "unavailable",
    )
    await async_wait_recording_done(hass)

    energy = await _rows(hass)
    cost = await _rows(hass, COST_ID)
    assert not old._stats_state.has_pending()
    assert _day_rows(energy, "2026-10-01")[0][1:] == (20.0, 20.0)
    assert _day_rows(cost, "2026-10-01")[0][1:] == (5.0, 5.0)
    assert energy[-1][2] == 44.0
    assert cost[-1][2] == 11.0


async def test_stale_readback_blocks_recorder_and_keeps_old_disk(hass, tmp_path) -> None:
    """A stale on-disk snapshot after a write is not durable proof."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    old = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    store = old._stats_state
    disk = tmp_path / "journal.json"
    store._store.__dict__["path"] = str(disk)
    await old.async_record_statistics(_recs("2026-10-01", 2), meter_id="m1")
    await async_wait_recording_done(hass)
    baseline_bytes = disk.read_bytes()
    real_write = store._store._write_data

    def stale_write(wrapper) -> None:
        real_write(wrapper)
        disk.write_bytes(baseline_bytes)

    with (
        patch.object(store._store, "_write_data", stale_write),
        pytest.raises(PsegStatisticsError, match="journal"),
    ):
        await old.async_record_statistics(
            _daily_with(_recs("2026-10-01", 2), "2026-10-01", 20.0),
            meter_id="m1",
        )
    await async_wait_recording_done(hass)

    assert _day_rows(await _rows(hass), "2026-10-01")[0][1] == 10.0
    assert disk.read_bytes() == baseline_bytes
    assert store._saved_revision < store._revision


async def test_silent_missing_write_is_not_durable(hass, tmp_path) -> None:
    """A writer that returns normally without changing disk must not advance."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="m1", data={})
    entry.add_to_hass(hass)
    old = PsegDataUpdateCoordinator(hass, _Client(), {}, config_entry=entry)
    store = old._stats_state
    disk = tmp_path / "journal.json"
    store._store.__dict__["path"] = str(disk)
    await old.async_record_statistics(_recs("2026-10-01", 2), meter_id="m1")
    await async_wait_recording_done(hass)
    baseline_bytes = disk.read_bytes()

    def silent_write(_wrapper) -> None:
        return None

    with (
        patch.object(store._store, "_write_data", silent_write),
        pytest.raises(PsegStatisticsError, match="journal"),
    ):
        await old.async_record_statistics(
            _daily_with(_recs("2026-10-01", 2), "2026-10-01", 20.0),
            meter_id="m1",
        )
    await async_wait_recording_done(hass)

    assert _day_rows(await _rows(hass), "2026-10-01")[0][1] == 10.0
    assert disk.read_bytes() == baseline_bytes
    assert store._saved_revision < store._revision


async def test_unreadable_existing_store_refuses_writes(hass, tmp_path) -> None:
    """An unreadable provenance file is not treated as an empty durable store."""
    coord = PsegDataUpdateCoordinator(hass, _Client(), {})
    store = coord._stats_state
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    store._store.__dict__["path"] = str(unreadable)

    await store.async_load()
    assert store._load_failed is True
    with pytest.raises(PsegStatisticsError, match="journal"):
        await coord.async_record_statistics(_recs("2026-10-02", 1), meter_id="m1")
    await async_wait_recording_done(hass)

    assert await _rows(hass) == []

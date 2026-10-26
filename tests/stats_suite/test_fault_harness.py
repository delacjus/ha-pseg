"""Tests for the physical fault-point substrate, barrier inventory, and recorder synchronization.

Validates:
1. Complete named semantic barrier inventory covering Store write/readback,
   recorder import and commit barriers for both series (consumption and cost),
   and before/after awaited operations in recording and recovery.
2. Physical durability: real on-disk HA Store and real SQLite recorder surviving
   cold reconstruction without warm cache reuse, with fresh recorder instance reopen.
3. Model comparison reads disk, not warm memory, asserting positive equality against disk.
4. Barrier controls (pause/resume, cancel, retire, bounded stall failure and resource cleanup).
5. Per-series fault injection retaining journal on partial failure.
"""

from __future__ import annotations

import asyncio
from datetime import date, datetime, timedelta
from pathlib import Path
import threading
from typing import Any

from homeassistant.components.recorder import get_instance
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)

from custom_components.pseg import coordinator as coord_mod
from custom_components.pseg.coordinator import (
    PsegDataUpdateCoordinator,
    PsegStatisticsError,
)
from custom_components.pseg.statistics_hourly import expected_hour_starts
from tests.support.stats_faults import (
    BARRIER_INVENTORY,
    BEFORE_BASELINE_READS,
    BEFORE_JOURNAL_SAVE,
    BEFORE_RECORDER_COMMIT,
    RECORDER_COMMIT_CONSUMPTION,
    RECORDER_COMMIT_COST,
    RECORDER_READBACK_CONSUMPTION,
    RECORDER_READBACK_COST,
    STORE_READBACK,
    STORE_WRITE_COMMIT,
    STORE_WRITE_PENDING,
    PhysicalDurabilitySubstrate,
    StatsFaultHarness,
    audit_barrier_inventory,
)
from tests.support.stats_model import (
    ReferenceStatisticsModel,
    compare_both_series,
)

CONSUMPTION_ID = "pseg:m1_energy_consumption"
COST_ID = "pseg:m1_energy_cost"


def _recs(start: str, n: int, kwh: float = 10.0) -> list[dict[str, Any]]:
    """Generate n daily invented records starting from start."""
    d0 = datetime.strptime(start, "%Y-%m-%d")
    return [
        {
            "date": (d0 + timedelta(days=i)).strftime("%Y-%m-%d"),
            "kwh": kwh,
            "cost": round(kwh * 0.25, 2),
        }
        for i in range(n)
    ]


def _hourly(day_str: str, kwh_per_hour: float = 1.0) -> list[dict[str, Any]]:
    """Generate canonical hourly points for one date."""
    return [
        {
            "start": start,
            "kwh": kwh_per_hour,
            "label": None,
            "label_ok": True,
            "interval_ok": True,
            "interval_reason": None,
        }
        for start in expected_hour_starts(date.fromisoformat(day_str))
    ]


def _daily_with(records: list[dict[str, Any]], day: str, kwh: float) -> list[dict[str, Any]]:
    """Replace one day total to match hourly sum."""
    out = [dict(r) for r in records]
    for r in out:
        if r["date"] == day:
            r["kwh"] = kwh
            r["cost"] = round(kwh * 0.25, 2)
    return out


@pytest.fixture
def recorder_db_url(tmp_path: Path):
    """Force an on-disk SQLite database file for recorder tests in this module."""
    db_file = tmp_path / "fault_recorder.db"
    return f"sqlite:///{db_file}"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock, enable_custom_integrations):
    """Recorder must be set up before hass for these tests."""
    yield


@pytest.fixture
def substrate(tmp_path: Path) -> PhysicalDurabilitySubstrate:
    """Provide a PhysicalDurabilitySubstrate configured with tmp_path."""
    return PhysicalDurabilitySubstrate(tmp_path, entry_id="m1")


@pytest.fixture
def coord(hass: HomeAssistant, substrate: PhysicalDurabilitySubstrate) -> PsegDataUpdateCoordinator:
    """Provide a coordinator attached to the physical on-disk store."""
    return substrate.create_coordinator(hass)


# -----------------------------------------------------------------------------
# 1. Semantic Barrier Inventory Completeness
# -----------------------------------------------------------------------------


def test_barrier_inventory_enumeration_and_both_series() -> None:
    """Verify that the named semantic barrier inventory enumerates both series completely."""
    audit = audit_barrier_inventory()
    assert audit["total_barriers"] == 36
    assert audit["categories"] == [
        "awaited_recording",
        "awaited_recovery",
        "recorder",
        "store",
    ]

    # Verify both series are explicitly covered
    assert "recorder_import_consumption" in audit["consumption_barriers"]
    assert "recorder_commit_consumption" in audit["consumption_barriers"]
    assert "recorder_readback_consumption" in audit["consumption_barriers"]

    assert "recorder_import_cost" in audit["cost_barriers"]
    assert "recorder_commit_cost" in audit["cost_barriers"]
    assert "recorder_readback_cost" in audit["cost_barriers"]

    # Verify physical Store barriers
    assert "store_readback" in audit["store_barriers"]
    assert "store_write_pending" in audit["store_barriers"]
    assert "store_write_commit" in audit["store_barriers"]

    # Verify inventory descriptors have explicit metadata
    for name, desc in BARRIER_INVENTORY.items():
        assert desc.name == name
        assert desc.category in audit["categories"]
        assert desc.series in ("consumption", "cost", "both", "none")
        assert desc.phase in ("recording", "recovery", "storage", "verification")
        assert len(desc.description) > 10


# -----------------------------------------------------------------------------
# 2. Physical Durability & Cold Reconstruction with DB Reopen
# -----------------------------------------------------------------------------


async def test_physical_store_and_sqlite_durability_cold_reconstruction(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Test that real temporary SQLite DB and on-disk Store survive cold reconstruction."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        # Import 2 days of baseline statistics with one promoted hourly day
        baseline = _daily_with(_recs("2026-10-01", 2, kwh=10.0), "2026-10-01", 24.0)
        hourly = _hourly("2026-10-01")
        await coord.async_record_statistics(
            baseline,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        # Verify physical SQLite database exists on disk and is non-empty
        substrate.verify_db_file()
        assert substrate.db_file.stat().st_size > 0

        # Verify physical Store file exists on disk and has valid JSON
        assert substrate.store_file.exists()
        store_data = substrate.read_store_json()
        assert store_data["version"] == 2
        assert "promoted" in store_data.get("data", store_data)

        # Verify recorder queries actually execute against the real database
        consumption_rows = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        cost_rows = await substrate.query_recorder_rows(hass, COST_ID)
        assert len(consumption_rows) == 25  # 24 hourly rows + 1 daily row
        assert len(cost_rows) == 25
        assert consumption_rows[-1][2] == 34.0  # 24.0 (day 1) + 10.0 (day 2)
        assert cost_rows[-1][2] == 8.5

        old_recorder_inst = get_instance(hass)

        # Perform cold reconstruction with real recorder reopen
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=True)
        harness.install(cold_coord)

        # Prove reopened DB path and Store path are identical, but instance is fresh
        assert cold_coord._stats_state._store.path == str(substrate.store_file)
        new_recorder_inst = get_instance(hass)
        assert new_recorder_inst is not old_recorder_inst
        assert new_recorder_inst.db_url == substrate.db_url

        # Prove queries execute on reopened coordinator and read back persisted rows
        reopened_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        reopened_cost = await substrate.query_recorder_rows(hass, COST_ID)
        assert reopened_consumption == consumption_rows
        assert reopened_cost == cost_rows

        # Positive equality check on cold state against disk
        disk_data = substrate.read_store_json().get("data", store_data)
        assert cold_coord._stats_state._data == disk_data
        assert bool(cold_coord._stats_state._data["promoted"])

        # Record next day on cold coordinator
        next_day = _recs("2026-10-03", 1, kwh=10.0)
        await cold_coord.async_record_statistics(next_day, meter_id="m1")
        await async_wait_recording_done(hass)

        updated_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        assert len(updated_consumption) == 26
        assert updated_consumption[-1][2] == 44.0

    finally:
        await harness.cleanup()


# -----------------------------------------------------------------------------
# 3. Model Comparison Reads Disk, Not Warm Memory (Positive Equality)
# -----------------------------------------------------------------------------


async def test_model_comparison_reads_disk_not_warm_memory(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Proves that cold reconstruction and model comparisons read physical disk, not warm memory."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        baseline = _daily_with(_recs("2026-10-01", 3, kwh=10.0), "2026-10-02", 24.0)
        hourly = _hourly("2026-10-02")
        await coord.async_record_statistics(
            baseline,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        # Intentionally tamper with warm memory before restart (simulate dirty unpersisted memory)
        substrate.tamper_warm_memory(
            coord,
            lambda data: data["pending"].update(
                {"tampered_key": {"fake": "dirty_memory_not_on_disk"}}
            ),
        )
        assert "tampered_key" in coord._stats_state._data["pending"]

        # Verify disk does NOT contain the warm tampering
        disk_wrapper = substrate.read_store_json()
        assert "tampered_key" not in disk_wrapper.get("data", {}).get("pending", {})

        # Cold reconstruct: fresh coordinator must load what is on physical disk
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=True)
        harness.install(cold_coord)

        # Negative check: warm tampering is NOT present in cold coordinator
        assert "tampered_key" not in cold_coord._stats_state._data["pending"]

        # Positive equality check: cold state data equals on-disk JSON data
        on_disk_data = disk_wrapper.get("data", disk_wrapper)
        assert cold_coord._stats_state._data == on_disk_data
        assert bool(cold_coord._stats_state._data["promoted"]), "Promoted data must not be empty"
        assert CONSUMPTION_ID in cold_coord._stats_state._data["promoted"]
        assert COST_ID in cold_coord._stats_state._data["promoted"]

        # Model comparison against independent ReferenceStatisticsModel reading physical recorder
        model = ReferenceStatisticsModel()
        model.record_daily(baseline)
        model.promote_hourly("2026-10-02", hourly)

        actual_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        actual_cost = await substrate.query_recorder_rows(hass, COST_ID)

        # Compare both series using independent reference model
        compare_both_series(
            actual_consumption=actual_consumption,
            actual_cost=actual_cost,
            expected_consumption=model.expected_rows_as_tuples(model.consumption_statistic_id),
            expected_cost=model.expected_rows_as_tuples(model.cost_statistic_id),
        )

    finally:
        await harness.cleanup()


# -----------------------------------------------------------------------------
# 4. Barrier Controls: Pause and Resume
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("one_shot", [False, True])
async def test_fault_controls_pause_and_resume(
    one_shot: bool,
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify that pause holds execution at named barrier until resumed."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        control = harness.pause_once if one_shot else harness.pause
        control(BEFORE_RECORDER_COMMIT)
        task = asyncio.create_task(
            coord.async_record_statistics(_recs("2026-10-01", 1), meter_id="m1"),
            name="test_pause_task",
        )

        await harness.wait_until_reached(BEFORE_RECORDER_COMMIT)

        assert harness.hits(BEFORE_RECORDER_COMMIT) == 1
        assert not task.done(), "Task should be paused at BEFORE_RECORDER_COMMIT"

        # Resume the barrier
        harness.resume(BEFORE_RECORDER_COMMIT)
        await asyncio.wait_for(task, timeout=5.0)
        await async_wait_recording_done(hass)

        assert len(await substrate.query_recorder_rows(hass, CONSUMPTION_ID)) == 1

    finally:
        await harness.cleanup()


# -----------------------------------------------------------------------------
# 5. Barrier Controls: Cancellation and Retirement
# -----------------------------------------------------------------------------


async def test_fault_controls_cancel(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify that cancel halts execution at named barrier cleanly."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        harness.cancel(BEFORE_JOURNAL_SAVE)
        with pytest.raises(asyncio.CancelledError):
            await coord.async_record_statistics(_recs("2026-10-01", 1), meter_id="m1")

        assert harness.hits(BEFORE_JOURNAL_SAVE) == 1
        await async_wait_recording_done(hass)
        assert await substrate.query_recorder_rows(hass, CONSUMPTION_ID) == []

    finally:
        await harness.cleanup()


async def test_fault_controls_retire(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify that retire stops coordinator from committing further mutations."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        # Retire right after journal save, before recorder import
        harness.retire(BEFORE_RECORDER_COMMIT)

        await coord.async_record_statistics(_recs("2026-10-01", 1), meter_id="m1")
        await async_wait_recording_done(hass)

        assert coord._stopped is True
        # Retired coordinator did not commit provenance
        assert not coord._stats_state.promoted(CONSUMPTION_ID)

    finally:
        await harness.cleanup()


# -----------------------------------------------------------------------------
# 6. Bounded Stall Failure and Resource Cleanup
# -----------------------------------------------------------------------------


async def test_stalled_barrier_times_out_and_cleans_up(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify that a stalled barrier fails within the <= 10s bound and cleans up cleanly."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    threads_before = {t.ident for t in threading.enumerate()}

    try:
        # Set a short bounded hold (0.3s <= 10.0s bound)
        harness.hold(STORE_READBACK, timeout=0.3)

        start_time = asyncio.get_running_loop().time()
        with pytest.raises((TimeoutError, PsegStatisticsError), match="stalled and timed out"):
            await coord._stats_state._async_verify_persisted(coord._stats_state._data)
        elapsed = asyncio.get_running_loop().time() - start_time

        assert elapsed < 10.0, f"Stalled barrier took {elapsed}s, exceeded 10.0s bound!"
        assert harness.hits(STORE_READBACK) == 1

        # Verify cleanup releases all resources and leaves no dangling tasks
        await harness.cleanup()

        loop = asyncio.get_running_loop()
        curr = asyncio.current_task()
        pending_test_tasks = [
            t
            for t in asyncio.all_tasks(loop)
            if t is not curr and not t.done() and "test" in (t.get_name() or "")
        ]
        assert not pending_test_tasks, f"Dangling test tasks found: {pending_test_tasks}"
        assert not harness._actions, "Harness actions were not cleaned up!"

        leaked_threads = [
            t
            for t in threading.enumerate()
            if t.ident not in threads_before and t.is_alive() and not t.daemon
        ]
        assert not leaked_threads, f"Leaked non-daemon threads: {leaked_threads}"

    finally:
        await harness.cleanup()


# -----------------------------------------------------------------------------
# 7. Per-Series Fault Injection: Consumption vs Cost
# -----------------------------------------------------------------------------


async def test_per_series_fault_injection_cost_failure_retains_journal(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify that a fault on the cost series retains the journal and halts completion."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        # Invariant: failure during cost series readback must fail mutation verify
        harness.fail(
            RECORDER_READBACK_COST,
            RuntimeError("Injected cost series verification fault"),
        )

        with pytest.raises(RuntimeError, match="Injected cost series"):
            await coord.async_record_statistics(_recs("2026-10-01", 1), meter_id="m1")
        await async_wait_recording_done(hass)

        # Journal was not cleared; pending mutation is retained
        assert coord._stats_state.has_pending()
        assert harness.hits(RECORDER_READBACK_CONSUMPTION) >= 1
        assert harness.hits(RECORDER_READBACK_COST) == 1

    finally:
        await harness.cleanup()


async def test_one_shot_pause_timeout_releases_waiter() -> None:
    """An unreleased one-shot pause fails explicitly and unregisters its waiter."""
    harness = StatsFaultHarness()
    harness.pause_once(BEFORE_RECORDER_COMMIT)
    action = harness._actions[BEFORE_RECORDER_COMMIT]
    action.timeout = 0.03  # Deliberate timeout sentinel, not an ordering sleep.
    try:
        with pytest.raises(
            TimeoutError, match="Barrier before_recorder_commit stalled and timed out"
        ):
            await harness._dispatch(BEFORE_RECORDER_COMMIT)
        assert action.event.is_set()
        assert not any(harness._waiters.values())
        assert harness.fired(BEFORE_RECORDER_COMMIT) == 1
    finally:
        await harness.cleanup()


@pytest.mark.parametrize(
    "barrier",
    [
        STORE_WRITE_PENDING,
        STORE_READBACK,
        STORE_WRITE_COMMIT,
        BEFORE_BASELINE_READS,
        RECORDER_COMMIT_CONSUMPTION,
        RECORDER_COMMIT_COST,
    ],
)
async def test_labels_reach_physical_boundaries(barrier, hass, substrate, coord, monkeypatch):
    """Observe real disk/DB at each contested seam, independently of label counts."""
    await coord.async_record_statistics(_recs("2026-10-01", 1), meter_id="m1")
    await async_wait_recording_done(hass)
    old_bytes = substrate.read_store_bytes()
    old_rows = {
        sid: await substrate.query_recorder_rows(hass, sid) for sid in (CONSUMPTION_ID, COST_ID)
    }
    baseline_calls = []

    def observe_baseline(name, original):
        async def observed(hass_arg, statistic_id, start):
            baseline_calls.append((name, statistic_id))
            return await original(hass_arg, statistic_id, start)

        return observed

    for name in ("_async_get_last_stat_before", "_async_get_stats_from"):
        monkeypatch.setattr(coord_mod, name, observe_baseline(name, getattr(coord_mod, name)))
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)
    task = None
    try:
        harness.pause_once(barrier)
        task = asyncio.create_task(
            coord.async_record_statistics(_recs("2026-10-02", 1), meter_id="m1"),
            name="test_boundary_operation",
        )
        await harness.wait_until_reached(barrier)
        assert not task.done()
        disk = substrate.read_store_json()["data"]
        if barrier == BEFORE_BASELINE_READS:
            assert baseline_calls == [], "baseline gate follows an unguarded prior-sum await"
            assert harness.hits(BEFORE_JOURNAL_SAVE) == 0
            assert not coord._stats_state.has_pending()
            assert substrate.read_store_bytes() == old_bytes
        elif barrier == STORE_WRITE_PENDING:
            assert coord._stats_state.has_pending(), "pending write gate precedes mutation creation"
            assert substrate.read_store_bytes() == old_bytes, (
                "pending write gate follows physical write"
            )
        elif barrier == STORE_READBACK:
            assert disk["pending"], "readback gate must follow physical pending save"
            assert coord._stats_state._saved_revision < coord._stats_state._revision
        elif barrier == STORE_WRITE_COMMIT:
            assert disk["pending"], "commit write must leave old physical journal until write"
            assert not coord._stats_state.has_pending(), (
                "commit write gate precedes memory transition"
            )
        else:
            assert disk["pending"]
            consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
            cost = await substrate.query_recorder_rows(hass, COST_ID)
            assert cost == old_rows[COST_ID], "cost committed before its own transaction gate"
            if barrier == RECORDER_COMMIT_CONSUMPTION:
                assert consumption == old_rows[CONSUMPTION_ID]
            else:
                assert len(consumption) == 2, "cost gate precedes consumption transaction commit"
                assert consumption[-1][2] == 20.0
        harness.resume(barrier)
        await asyncio.wait_for(task, timeout=10)
        await async_wait_recording_done(hass)
        assert harness.fired(barrier) == 1
        # Four awaited baseline reads, including both prior-sum reads.
        assert harness.hits(BEFORE_BASELINE_READS) == 4
        assert baseline_calls == [
            ("_async_get_last_stat_before", CONSUMPTION_ID),
            ("_async_get_last_stat_before", COST_ID),
            ("_async_get_stats_from", CONSUMPTION_ID),
            ("_async_get_stats_from", COST_ID),
        ]
        assert not substrate.read_store_json()["data"]["pending"]
        assert len(await substrate.query_recorder_rows(hass, CONSUMPTION_ID)) == 2
        assert len(await substrate.query_recorder_rows(hass, COST_ID)) == 2
    finally:
        harness.resume(barrier)
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await harness.cleanup()


async def test_physical_readback_stall_refuses_recorder_writes(hass, substrate, coord):
    """The production save must refuse to import when its real readback stalls."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)
    try:
        harness.hold(STORE_READBACK, timeout=0.03)
        with pytest.raises(PsegStatisticsError, match="Statistics journal is not durable"):
            await coord.async_record_statistics(_recs("2026-10-01", 1), meter_id="m1")
        assert harness.fired(STORE_READBACK) == 1
        assert substrate.read_store_json()["data"]["pending"]
        assert not substrate.read_store_json()["data"]["promoted"]
        assert await substrate.query_recorder_rows(hass, CONSUMPTION_ID) == []
        assert await substrate.query_recorder_rows(hass, COST_ID) == []
    finally:
        await harness.cleanup()

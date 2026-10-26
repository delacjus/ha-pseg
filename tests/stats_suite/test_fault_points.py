"""S2 fault-point convergence matrix tests for PSE&G statistics durability.

Proves:
1. Complete barrier inventory × fault kinds enumeration with verified impossible reasons.
2. Injected faults fire exactly once and prove they fired (unfired faults fail).
3. Intermediate physical state observation before recovery (no false completeness;
   journal retained on disk, not cleared prematurely).
4. Cold restart from physical Store/DB only (no warm memory reuse).
5. Healthy poll / recovery restores exact starts, states, and nondecreasing sums
   for BOTH series against the independent ReferenceStatisticsModel.
6. Both energy-first and cost-first series orderings.
7. First-series and second-series partial commit durability.
8. Strict date-only promotion convergence.
9. Ambiguous fall and nonexistent spring daily fallback.
10. Already-canonical aware 25-hour recovery without raw wall x re-parsing.
11. Pre-existing historical rows before fixture range remain unchanged.
12. Zero-flake repeatability across 10 fresh copies for cancellation and partial commit.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime, timedelta
import logging
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)
from sqlalchemy.exc import SQLAlchemyError

from custom_components.pseg.coordinator import (
    PsegDataUpdateCoordinator,
    PsegStatisticsError,
)
from custom_components.pseg.statistics_hourly import expected_hour_starts
from tests.stats_suite.fault_cases import (
    APPLICABLE_CASES,
    FAULT_KIND_CANCELLATION,
    FAULT_KIND_PAUSE,
    FAULT_KIND_READ_ERROR,
    FAULT_KIND_RETIRED_STALE,
    FAULT_KIND_SQLALCHEMY_ERROR,
    FAULT_KIND_TIMEOUT,
    FAULT_KIND_WRITE_ERROR,
    FAULT_MATRIX,
    IMPOSSIBLE_CASES,
    audit_fault_matrix,
    get_case,
)
from tests.support.stats_faults import (
    AFTER_JOURNAL_DISCARD,
    AFTER_JOURNAL_SAVE,
    AFTER_STORE_LOAD,
    BARRIER_INVENTORY,
    BEFORE_JOURNAL_COMMIT,
    BEFORE_JOURNAL_DISCARD,
    BEFORE_RECORDER_COMMIT,
    BEFORE_STORE_LOAD,
    RECORDER_COMMIT_CONSUMPTION,
    RECORDER_COMMIT_COST,
    RECORDER_IMPORT_CONSUMPTION,
    RECORDER_IMPORT_COST,
    STORE_READBACK,
    STORE_WRITE_COMMIT,
    PhysicalDurabilitySubstrate,
    StatsFaultHarness,
)
from tests.support.stats_model import (
    CONSUMPTION_STATISTIC_ID,
    COST_STATISTIC_ID,
    ReferenceStatisticsModel,
    assert_chained_nondecreasing,
    compare_both_series,
    ny_day_hours_utc,
)

CONSUMPTION_ID = "pseg:m1_energy_consumption"
COST_ID = "pseg:m1_energy_cost"

_LOGGER = logging.getLogger(__name__)

# Module-level registry tracking fault ID -> (barrier, trigger_count)
TRIGGER_REGISTRY: dict[str, tuple[str, int]] = {}


def _record_trigger(fault_id: str, barrier: str, count: int) -> None:
    TRIGGER_REGISTRY[fault_id] = (barrier, count)


def get_trigger_table() -> list[tuple[str, str, int]]:
    """Return list of recorded (fault_id, barrier, trigger_count) tuples."""
    return [(fid, b, c) for fid, (b, c) in sorted(TRIGGER_REGISTRY.items())]


def format_trigger_table_markdown() -> str:
    """Format recorded triggers into a markdown table."""
    lines = [
        "| Fault ID | Barrier | Triggers |",
        "|---|---|---|",
    ]
    for fid, barrier, count in get_trigger_table():
        lines.append(f"| `{fid}` | `{barrier}` | {count} |")
    return "\n".join(lines)


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


@pytest.fixture(autouse=True)
def _check_slow_matrix(request: pytest.FixtureRequest) -> None:
    """Skip tests marked slow unless -m slow was specified in the pytest run."""
    if request.node.get_closest_marker("slow"):
        markexpr = request.config.getoption("markexpr", default="")
        if "slow" not in markexpr:
            pytest.skip("Full matrix runs only when -m slow is specified")


# =============================================================================
# 1. Matrix Enumeration & Declaration Audit
# =============================================================================


def test_matrix_enumeration_and_barrier_descriptors_completeness() -> None:
    """Verify all 252 combinations are declared with explicit reasons for impossible cases."""
    audit = audit_fault_matrix()
    assert audit["total_cases"] == 252
    assert audit["applicable_count"] == 85
    assert audit["impossible_count"] == 167
    assert audit["barriers_covered"] == 36
    assert len(audit["fault_kinds"]) == 7

    # Ensure all barriers in BARRIER_INVENTORY are fully covered
    all_case_barriers = {c.barrier for c in FAULT_MATRIX}
    assert all_case_barriers == set(BARRIER_INVENTORY.keys())

    # Every impossible combination must have an explicit reason
    for case in IMPOSSIBLE_CASES:
        assert case.impossible_reason is not None
        assert len(case.impossible_reason) > 15
        assert case.applicable is False


# =============================================================================
# 2. Fast Tier: Pending Journal Control
# =============================================================================


async def test_fast_tier_pending_journal_control(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Test pending journal durability at STORE_WRITE_COMMIT, intermediate state, and recovery."""
    case = get_case("store_write_commit__write_error")
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        # Pre-seed baseline day so Store file and SQLite DB are physically initialized
        initial_day = _recs("2026-09-30", 1, kwh=10.0)
        await coord.async_record_statistics(initial_day, meter_id="m1")
        await async_wait_recording_done(hass)

        # Inject write failure once when committing journal promotion to disk
        harness.fail_once(
            STORE_WRITE_COMMIT, OSError("Simulated disk write error at store_write_commit")
        )

        baseline = _daily_with(_recs("2026-10-01", 2, kwh=10.0), "2026-10-01", 24.0)
        hourly = _hourly("2026-10-01")

        with pytest.raises(RuntimeError, match="Statistics provenance commit is not durable"):
            await coord.async_record_statistics(
                baseline,
                meter_id="m1",
                hourly_records=hourly,
                hourly_granularity="hourly",
            )
        await async_wait_recording_done(hass)

        # 1. Prove the fault actually fired
        fired = harness.fired(STORE_WRITE_COMMIT)
        assert fired == 1, f"Fault {case.fault_id} was injected but never fired (fired={fired})"
        _record_trigger(case.fault_id, STORE_WRITE_COMMIT, fired)

        # 2. Intermediate physical state observation before recovery
        # SQLite DB has both series committed
        consumption_rows = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        cost_rows = await substrate.query_recorder_rows(hass, COST_ID)
        assert len(consumption_rows) == 26
        assert len(cost_rows) == 26

        # On-disk Store: pending journal is present; promoted is NOT committed
        store_json = substrate.read_store_json()
        disk_data = store_json.get("data", store_json)
        assert "pending" in disk_data and disk_data["pending"], "Journal was cleared early on disk!"
        assert not disk_data.get("promoted"), "Promoted state was committed despite write failure!"

        # 3. Cold restart from physical Store/DB only
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=True)
        harness.install(cold_coord)

        # 4. Healthy poll completes recovery
        healthy_baseline = _daily_with(_recs("2026-10-01", 2, kwh=10.0), "2026-10-01", 24.0)
        await cold_coord.async_record_statistics(
            healthy_baseline,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        # 5. Exact starts, states, and sums compared for BOTH series against ReferenceStatisticsModel
        model = ReferenceStatisticsModel()
        model.record_daily(initial_day + healthy_baseline)
        model.promote_hourly("2026-10-01", hourly)

        final_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        final_cost = await substrate.query_recorder_rows(hass, COST_ID)

        compare_both_series(
            actual_consumption=final_consumption,
            actual_cost=final_cost,
            expected_consumption=model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            expected_cost=model.expected_rows_as_tuples(COST_STATISTIC_ID),
        )
        assert_chained_nondecreasing(final_consumption)
        assert_chained_nondecreasing(final_cost)

        # 6. Journal cleared only after both series physically verify
        final_disk_data = substrate.read_store_json().get("data", {})
        assert not final_disk_data.get("pending"), (
            "Journal was not cleared after successful recovery!"
        )
        assert bool(final_disk_data.get("promoted")), "Promoted state is missing after recovery!"

    finally:
        await harness.cleanup()


# =============================================================================
# 3. Fast Tier: Partial-Series Commit Control
# =============================================================================


async def test_fast_tier_partial_series_commit_control(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Test second-series partial commit failure, intermediate observation, and recovery."""
    case = get_case("recorder_commit_cost__sqlalchemy_error")
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        # Inject SQLAlchemyError on cost series import/commit
        harness.fail_once(
            RECORDER_IMPORT_COST,
            SQLAlchemyError("Simulated DB connection error committing cost series"),
        )

        baseline = _daily_with(_recs("2026-10-01", 2, kwh=10.0), "2026-10-01", 24.0)
        hourly = _hourly("2026-10-01")

        with pytest.raises((SQLAlchemyError, PsegStatisticsError)):
            await coord.async_record_statistics(
                baseline,
                meter_id="m1",
                hourly_records=hourly,
                hourly_granularity="hourly",
            )
        await async_wait_recording_done(hass)

        # 1. Prove the fault actually fired
        fired = harness.fired(RECORDER_IMPORT_COST)
        assert fired == 1, f"Fault {case.fault_id} was injected but never fired (fired={fired})"
        _record_trigger(case.fault_id, RECORDER_COMMIT_COST, fired)

        # 2. Intermediate physical state observation
        consumption_rows = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        cost_rows = await substrate.query_recorder_rows(hass, COST_ID)
        # First series committed; second series failed
        assert len(consumption_rows) == 25, "First series (consumption) should be committed"
        assert len(cost_rows) == 0, "Second series (cost) must NOT be committed"

        # Journal retained on disk
        store_json = substrate.read_store_json()
        disk_data = store_json.get("data", store_json)
        assert bool(disk_data.get("pending")), (
            "Journal was cleared early on partial commit failure!"
        )
        assert not disk_data.get("promoted"), "Promoted state was committed prematurely!"

        # 3. Cold restart from physical Store/DB only
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=True)
        harness.install(cold_coord)

        # 4. Healthy poll recovers the missing second series
        healthy_baseline = _daily_with(_recs("2026-10-01", 2, kwh=10.0), "2026-10-01", 24.0)
        await cold_coord.async_record_statistics(
            healthy_baseline,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        # 5. Exact comparison for BOTH series against ReferenceStatisticsModel
        model = ReferenceStatisticsModel()
        model.record_daily(healthy_baseline)
        model.promote_hourly("2026-10-01", hourly)

        final_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        final_cost = await substrate.query_recorder_rows(hass, COST_ID)

        compare_both_series(
            actual_consumption=final_consumption,
            actual_cost=final_cost,
            expected_consumption=model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            expected_cost=model.expected_rows_as_tuples(COST_STATISTIC_ID),
        )
        assert_chained_nondecreasing(final_consumption)
        assert_chained_nondecreasing(final_cost)

        # 6. Journal cleared only after both series verify
        final_disk_data = substrate.read_store_json().get("data", {})
        assert not final_disk_data.get("pending"), "Journal remained pending after recovery!"
        assert bool(final_disk_data.get("promoted")), "Promoted data missing after recovery!"

    finally:
        await harness.cleanup()


# =============================================================================
# 4. Fast Tier: Cost-First Series Ordering Partial Commit
# =============================================================================


async def test_fast_tier_cost_first_ordering_partial_commit(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Test cost-first series ordering with first-series (cost) commit and second-series (consumption) fault."""
    case = get_case("recorder_commit_consumption__sqlalchemy_error")
    harness = StatsFaultHarness(coord, substrate, series_order="cost_first")
    harness.install(coord)

    try:
        # Cost-first ordering: consumption fails on second import
        harness.fail_once(
            RECORDER_IMPORT_CONSUMPTION,
            SQLAlchemyError("Simulated DB error committing consumption in cost-first mode"),
        )

        baseline = _daily_with(_recs("2026-10-01", 2, kwh=10.0), "2026-10-01", 24.0)
        hourly = _hourly("2026-10-01")

        with pytest.raises((SQLAlchemyError, PsegStatisticsError)):
            await coord.async_record_statistics(
                baseline,
                meter_id="m1",
                hourly_records=hourly,
                hourly_granularity="hourly",
            )
        await async_wait_recording_done(hass)

        fired = harness.fired(RECORDER_IMPORT_CONSUMPTION)
        assert fired == 1, f"Fault {case.fault_id} was injected but never fired (fired={fired})"
        _record_trigger(case.fault_id, RECORDER_COMMIT_CONSUMPTION, fired)

        # Intermediate physical state: cost committed, consumption not committed
        consumption_rows = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        cost_rows = await substrate.query_recorder_rows(hass, COST_ID)
        assert len(cost_rows) == 25, "Cost series should be committed in cost-first mode"
        assert len(consumption_rows) == 0, "Consumption series should not be committed"

        # Journal retained
        assert substrate.read_store_json().get("data", {}).get("pending")

        # Cold restart and recovery
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=True)
        harness.install(cold_coord)

        healthy_baseline = _daily_with(_recs("2026-10-01", 2, kwh=10.0), "2026-10-01", 24.0)
        await cold_coord.async_record_statistics(
            healthy_baseline,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        model = ReferenceStatisticsModel()
        model.record_daily(healthy_baseline)
        model.promote_hourly("2026-10-01", hourly)

        final_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        final_cost = await substrate.query_recorder_rows(hass, COST_ID)

        compare_both_series(
            actual_consumption=final_consumption,
            actual_cost=final_cost,
            expected_consumption=model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            expected_cost=model.expected_rows_as_tuples(COST_STATISTIC_ID),
        )

    finally:
        await harness.cleanup()


# =============================================================================
# 5. Fast Tier: 10 Fresh Copies Zero-Flake Repeatability
# =============================================================================


async def test_repeat_cancellation_and_partial_commit_10_fresh_copies_no_flakes(
    hass: HomeAssistant,
    tmp_path: Path,
) -> None:
    """Repeat cancellation and partial-commit across 10 fresh isolated copies without flakes."""
    for iteration in range(10):
        sub = PhysicalDurabilitySubstrate(tmp_path, entry_id=f"m_{iteration}")
        test_coord = sub.create_coordinator(hass)
        harness = StatsFaultHarness(test_coord, sub)
        harness.install(test_coord)

        try:
            if iteration % 2 == 0:
                # Even iterations: cancellation at BEFORE_RECORDER_COMMIT
                harness.cancel_once(BEFORE_RECORDER_COMMIT)
                with pytest.raises(asyncio.CancelledError):
                    await test_coord.async_record_statistics(
                        _recs("2026-10-01", 1), meter_id=f"m_{iteration}"
                    )
                assert harness.fired(BEFORE_RECORDER_COMMIT) == 1
            else:
                # Odd iterations: partial commit at RECORDER_IMPORT_COST
                harness.fail_once(RECORDER_IMPORT_COST, SQLAlchemyError("Transient DB error"))
                with pytest.raises((SQLAlchemyError, PsegStatisticsError)):
                    await test_coord.async_record_statistics(
                        _recs("2026-10-01", 1), meter_id=f"m_{iteration}"
                    )
                assert harness.fired(RECORDER_IMPORT_COST) == 1

            await async_wait_recording_done(hass)

            # Cold reconstruct and verify clean recovery
            harness.uninstall()
            cold = await sub.cold_reconstruct(test_coord, hass, reopen_db=False)
            harness.install(cold)

            await cold.async_record_statistics(_recs("2026-10-01", 1), meter_id=f"m_{iteration}")
            await async_wait_recording_done(hass)

            cons = await sub.query_recorder_rows(hass, f"pseg:m_{iteration}_energy_consumption")
            cost = await sub.query_recorder_rows(hass, f"pseg:m_{iteration}_energy_cost")
            assert len(cons) == 1
            assert len(cost) == 1
            assert cons[0][2] == 10.0
            assert cost[0][2] == 2.5

        finally:
            await harness.cleanup()


# =============================================================================
# 6. Fast Tier: Strict Date-Only Promotion Convergence
# =============================================================================


async def test_strict_date_only_promotion_convergence(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify strict date-only promotion converges cleanly across fault and restart."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        # Step 1: Initial daily import of two dates
        baseline = _recs("2026-10-01", 2, kwh=24.0)
        await coord.async_record_statistics(baseline, meter_id="m1")
        await async_wait_recording_done(hass)

        assert len(await substrate.query_recorder_rows(hass, CONSUMPTION_ID)) == 2

        # Step 2: Promote 2026-10-01 to hourly, fault on BEFORE_JOURNAL_COMMIT
        harness.fail_once(BEFORE_JOURNAL_COMMIT, OSError("Simulated commit barrier failure"))
        hourly = _hourly("2026-10-01", kwh_per_hour=1.0)

        with pytest.raises((OSError, PsegStatisticsError)):
            await coord.async_record_statistics(
                baseline,
                meter_id="m1",
                hourly_records=hourly,
                hourly_granularity="hourly",
            )
        await async_wait_recording_done(hass)
        assert harness.fired(BEFORE_JOURNAL_COMMIT) == 1

        # Intermediate: pending journal present
        assert substrate.read_store_json().get("data", {}).get("pending")

        # Step 3: Cold restart and healthy poll
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=True)
        harness.install(cold_coord)

        await cold_coord.async_record_statistics(
            baseline,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        model = ReferenceStatisticsModel()
        model.record_daily(baseline)
        model.promote_hourly("2026-10-01", hourly)

        final_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        final_cost = await substrate.query_recorder_rows(hass, COST_ID)

        compare_both_series(
            actual_consumption=final_consumption,
            actual_cost=final_cost,
            expected_consumption=model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            expected_cost=model.expected_rows_as_tuples(COST_STATISTIC_ID),
        )
        # 24 hourly rows for day 1 + 1 daily row for day 2 = 25 rows
        assert len(final_consumption) == 25
        assert len(final_cost) == 25

    finally:
        await harness.cleanup()


# =============================================================================
# 7. Fast Tier: Ambiguous Fall & Nonexistent Spring Daily Fallback
# =============================================================================


async def test_ambiguous_fall_and_nonexistent_spring_daily_fallback(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify fall ambiguous and spring nonexistent hourly points fall back to daily across fault."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        # Fall DST: 2026-11-01 has 25 hours. Provide 24 ambiguous points (no fold).
        fall_day = "2026-11-01"
        fall_daily = [{"date": fall_day, "kwh": 25.0, "cost": 6.25}]
        # 24 starts missing the repeated fold -> validator rejects as incomplete / dst_ambiguous
        midnight_utc = datetime(2026, 11, 1, 4, 0, 0, tzinfo=UTC)
        ambiguous_starts = [midnight_utc + timedelta(hours=h) for h in range(24)]
        ambiguous_hourly = [
            {
                "start": st,
                "kwh": 1.0,
                "label": None,
                "label_ok": True,
                "interval_ok": True,
                "interval_reason": None,
            }
            for st in ambiguous_starts
        ]

        # Fault once during recording
        harness.fail_once(BEFORE_RECORDER_COMMIT, PsegStatisticsError("Simulated pre-commit abort"))

        with pytest.raises(PsegStatisticsError):
            await coord.async_record_statistics(
                fall_daily,
                meter_id="m1",
                hourly_records=ambiguous_hourly,
                hourly_granularity="hourly",
            )
        await async_wait_recording_done(hass)
        assert harness.fired(BEFORE_RECORDER_COMMIT) == 1

        # Cold restart
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=False)
        harness.install(cold_coord)

        # Healthy poll: falls back to daily representation
        await cold_coord.async_record_statistics(
            fall_daily,
            meter_id="m1",
            hourly_records=ambiguous_hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        # Stays daily (1 row for the day, not 24 or 25)
        consumption_rows = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        cost_rows = await substrate.query_recorder_rows(hass, COST_ID)
        assert len(consumption_rows) == 1
        assert len(cost_rows) == 1
        assert consumption_rows[0][1] == 25.0
        assert cost_rows[0][1] == 6.25

    finally:
        await harness.cleanup()


# =============================================================================
# 8. Fast Tier: Canonical Aware 25-Hour Recovery (No Wall-x Reparsing)
# =============================================================================


async def test_canonical_aware_25_hour_recovery_no_reparsing(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify 2026 fall 25-hour day promotes with canonical aware starts and survives fault."""
    from unittest.mock import patch

    patch_now = patch(
        "homeassistant.util.dt.utcnow",
        return_value=datetime(2026, 11, 10, tzinfo=UTC),
    )
    patch_now.start()
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        fall_day = "2026-11-01"
        fall_daily = [{"date": fall_day, "kwh": 25.0, "cost": 6.25}]

        # Independent canonical 25 UTC starts for 2026-11-01
        starts_25 = ny_day_hours_utc(date(2026, 11, 1))
        assert len(starts_25) == 25, "2026-11-01 must have exactly 25 canonical hourly starts"

        aware_25_hourly = [
            {
                "start": st,
                "kwh": 1.0,
                "label": None,
                "label_ok": True,
                "interval_ok": True,
                "interval_reason": None,
            }
            for st in starts_25
        ]

        # Fault once at STORE_WRITE_COMMIT
        harness.fail_once(STORE_WRITE_COMMIT, OSError("Store commit failure on 25h promotion"))

        with pytest.raises(RuntimeError, match="Statistics provenance commit is not durable"):
            await coord.async_record_statistics(
                fall_daily,
                meter_id="m1",
                hourly_records=aware_25_hourly,
                hourly_granularity="hourly",
            )
        await async_wait_recording_done(hass)
        assert harness.fired(STORE_WRITE_COMMIT) == 1

        # Intermediate: rows in DB, pending in Store
        intermediate_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        assert len(intermediate_consumption) == 25

        # Verify persisted starts are NEVER re-parsed as raw wall x
        # Raw wall x would fold 05:00Z and 06:00Z into duplicate 01:00 bare hour.
        for st, _, _ in intermediate_consumption:
            assert st.tzinfo is not None, f"Persisted start {st} lost timezone awareness!"
            assert st.tzinfo == UTC, f"Persisted start {st} is not in UTC!"

        # Cold reconstruct and recover
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=True)
        harness.install(cold_coord)

        await cold_coord.async_record_statistics(
            fall_daily,
            meter_id="m1",
            hourly_records=aware_25_hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        model = ReferenceStatisticsModel()
        model.promote_hourly(fall_day, aware_25_hourly)

        final_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        final_cost = await substrate.query_recorder_rows(hass, COST_ID)

        compare_both_series(
            actual_consumption=final_consumption,
            actual_cost=final_cost,
            expected_consumption=model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            expected_cost=model.expected_rows_as_tuples(COST_STATISTIC_ID),
        )
        assert len(final_consumption) == 25
        assert_chained_nondecreasing(final_consumption)
        assert_chained_nondecreasing(final_cost)

    finally:
        patch_now.stop()
        await harness.cleanup()


# =============================================================================
# 9. Fast Tier: Historical Rows Before Fixture Range Remain Unchanged
# =============================================================================


async def test_historical_rows_before_fixture_remain_unchanged(
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Verify historical rows before the fixture range remain completely untouched across fault."""
    harness = StatsFaultHarness(coord, substrate)
    harness.install(coord)

    try:
        # Pre-populate historical baseline in September 2026 (prior to October fixture range)
        historical_records = _recs("2026-09-01", 3, kwh=15.0)
        await coord.async_record_statistics(historical_records, meter_id="m1")
        await async_wait_recording_done(hass)

        hist_consumption_before = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        hist_cost_before = await substrate.query_recorder_rows(hass, COST_ID)
        assert len(hist_consumption_before) == 3
        assert len(hist_cost_before) == 3

        # Inject fault into new October data import
        harness.fail_once(
            BEFORE_RECORDER_COMMIT, PsegStatisticsError("Abort during October import")
        )
        october_records = _recs("2026-10-01", 2, kwh=10.0)

        with pytest.raises(PsegStatisticsError):
            await coord.async_record_statistics(october_records, meter_id="m1")
        await async_wait_recording_done(hass)
        assert harness.fired(BEFORE_RECORDER_COMMIT) == 1

        # Cold reconstruct
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=False)
        harness.install(cold_coord)

        # Complete October import cleanly
        await cold_coord.async_record_statistics(october_records, meter_id="m1")
        await async_wait_recording_done(hass)

        all_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        all_cost = await substrate.query_recorder_rows(hass, COST_ID)

        # Historical 3 rows must remain exactly identical to before
        assert all_consumption[:3] == hist_consumption_before
        assert all_cost[:3] == hist_cost_before

    finally:
        await harness.cleanup()


# =============================================================================
# 10. Slow Tier: Full Matrix Convergence Across Representative Barriers
# =============================================================================


async def _assert_matrix_intermediate(
    case, substrate, hass, initial_day, initial_hourly, baseline, hourly
):
    """Independent fault-phase contract: old / partial / verified / provenance committed."""
    barrier, kind = case.barrier, case.fault_kind
    old = ReferenceStatisticsModel()
    old.record_daily(initial_day)
    old.promote_hourly("2026-09-30", initial_hourly)
    complete = ReferenceStatisticsModel()
    complete.record_daily(initial_day + baseline)
    complete.promote_hourly("2026-09-30", initial_hourly)
    complete.promote_hourly("2026-10-01", hourly)
    ids = (CONSUMPTION_ID, COST_ID)
    expected = {sid: old.expected_rows_as_tuples(sid) for sid in ids}
    pending, promoted = False, False
    discard = barrier in (BEFORE_JOURNAL_DISCARD, AFTER_JOURNAL_DISCARD)
    recovery = barrier.startswith(("before_recovery_", "after_recovery_"))
    early = barrier in (
        BEFORE_STORE_LOAD,
        AFTER_STORE_LOAD,
        "before_recover_pending",
        "after_recover_pending",
        "before_baseline_reads",
        "after_baseline_reads",
        "before_journal_save",
        "store_write_pending",
    )
    if discard:
        pending = barrier == BEFORE_JOURNAL_DISCARD and kind != FAULT_KIND_PAUSE
    elif kind == FAULT_KIND_PAUSE:
        promoted = True
        expected = {sid: complete.expected_rows_as_tuples(sid) for sid in ids}
    elif recovery:
        pending = True
        if barrier in ("before_recovery_commit", "before_recovery_replay"):
            if barrier == "before_recovery_commit" or kind == FAULT_KIND_RETIRED_STALE:
                expected = {sid: complete.expected_rows_as_tuples(sid) for sid in ids}
            if barrier == "before_recovery_commit" and kind == FAULT_KIND_RETIRED_STALE:
                pending, promoted = False, True
    elif early:
        pass
    elif barrier == "after_journal_save" and kind == FAULT_KIND_RETIRED_STALE:
        pass  # Production durably discards the journal before any recorder import.
    else:
        pending = True
        if barrier not in (STORE_READBACK, RECORDER_IMPORT_CONSUMPTION, RECORDER_IMPORT_COST):
            expected = {sid: complete.expected_rows_as_tuples(sid) for sid in ids}
            if barrier in (RECORDER_COMMIT_CONSUMPTION, RECORDER_COMMIT_COST):
                failed = CONSUMPTION_ID if barrier == RECORDER_COMMIT_CONSUMPTION else COST_ID
                expected[failed] = old.expected_rows_as_tuples(failed)

    disk = substrate.read_store_json()["data"]
    assert bool(disk["pending"]) is pending, (
        f"{case.fault_id}: intermediate physical pending must be {pending}; journal cleared early"
    )
    for sid in ids:
        assert set(disk["promoted"][sid]) == (
            {"2026-09-30", "2026-10-01"} if promoted else {"2026-09-30"}
        ), f"{case.fault_id}: premature or missing physical promotion for {sid}"
    if pending:
        assert len(disk["pending"]) == 1
        mutation = next(iter(disk["pending"].values()))
        for sid in ids:
            assert set(mutation["promoted"][sid]) == {"2026-10-01"}
            rows = [
                (datetime.fromisoformat(st), state, total)
                for st, state, total in mutation["series"][sid]
            ]
            assert rows == complete.expected_rows_as_tuples(sid)[24:]
    compare_both_series(
        actual_consumption=await substrate.query_recorder_rows(hass, CONSUMPTION_ID),
        actual_cost=await substrate.query_recorder_rows(hass, COST_ID),
        expected_consumption=expected[CONSUMPTION_ID],
        expected_cost=expected[COST_ID],
    )


# Every applicable row in the declared matrix; nothing is hand-picked.
MATRIX_SAMPLE_CASES = [c.fault_id for c in APPLICABLE_CASES]


@pytest.mark.slow
@pytest.mark.parametrize("fault_id", MATRIX_SAMPLE_CASES)
async def test_full_matrix_applicable_fault_convergence(
    fault_id: str,
    hass: HomeAssistant,
    substrate: PhysicalDurabilitySubstrate,
    coord: PsegDataUpdateCoordinator,
) -> None:
    """Parametrized slow-tier test verifying full matrix applicable fault points converge."""
    case = get_case(fault_id)
    assert case.applicable is True

    # 1. Pre-seed baseline day with promoted hourly rows so Store file and SQLite DB are initialized
    initial_day = _daily_with(_recs("2026-09-30", 1, kwh=24.0), "2026-09-30", 24.0)
    initial_hourly = _hourly("2026-09-30")
    await coord.async_record_statistics(
        initial_day,
        meter_id="m1",
        hourly_records=initial_hourly,
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    # 2. Attach fault harness to coordinator
    harness = StatsFaultHarness(coord, substrate, series_order=case.series_order)
    harness.install(coord)

    try:
        barrier = case.barrier
        kind = case.fault_kind

        baseline = _daily_with(_recs("2026-10-01", 2, kwh=10.0), "2026-10-01", 24.0)
        hourly = _hourly("2026-10-01")

        def _apply_fault() -> None:
            if kind == FAULT_KIND_WRITE_ERROR:
                harness.fail_once(barrier, OSError(f"Simulated write error at {barrier}"))
            elif kind == FAULT_KIND_READ_ERROR:
                harness.fail_once(barrier, OSError(f"Simulated read error at {barrier}"))
            elif kind == FAULT_KIND_SQLALCHEMY_ERROR:
                harness.fail_once(barrier, SQLAlchemyError(f"Simulated DB error at {barrier}"))
            elif kind == FAULT_KIND_TIMEOUT:
                harness.fail_once(barrier, TimeoutError(f"Barrier {barrier} timed out"))
            elif kind == FAULT_KIND_CANCELLATION:
                harness.cancel_once(barrier)
            elif kind == FAULT_KIND_RETIRED_STALE:
                harness.retire_once(barrier)
            elif kind == FAULT_KIND_PAUSE:
                harness.pause_once(barrier)

        is_recovery_barrier = barrier.startswith("before_recovery_") or barrier.startswith(
            "after_recovery_"
        )

        # Reset store loaded cache if testing load barriers so disk load executes
        if barrier in (BEFORE_STORE_LOAD, STORE_READBACK, AFTER_STORE_LOAD):
            coord._stats_state._loaded = False

        async def attempt(operation):
            if kind == FAULT_KIND_PAUSE:
                task = asyncio.create_task(operation, name="test_matrix_pause")
                try:
                    await harness.wait_until_reached(barrier)
                    assert not task.done(), f"Pause {barrier} did not suspend the operation"
                    harness.resume(barrier)
                    # No exception swallowing: resumed work must actually complete.
                    await asyncio.wait_for(task, timeout=10.0)
                    assert not task.cancelled(), f"Resumed operation {barrier} was cancelled"
                finally:
                    harness.resume(barrier)
                    if not task.done():
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
            else:
                try:
                    await operation
                except (
                    OSError,
                    SQLAlchemyError,
                    TimeoutError,
                    asyncio.CancelledError,
                    PsegStatisticsError,
                ):
                    pass
                except RuntimeError as err:
                    assert barrier == STORE_WRITE_COMMIT
                    assert str(err) == "Statistics provenance commit is not durable"

        if is_recovery_barrier:
            # Journal the actual intended mutation, with no imports, before faulting recovery.
            harness.fail_once(AFTER_JOURNAL_SAVE, OSError("seed pending recovery journal"))
            with pytest.raises(PsegStatisticsError, match="seed pending"):
                await coord.async_record_statistics(
                    baseline, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
                )
            _apply_fault()
            await attempt(coord._async_recover_pending())
        else:
            if barrier in (BEFORE_JOURNAL_DISCARD, AFTER_JOURNAL_DISCARD):
                harness.retire_once(AFTER_JOURNAL_SAVE)
            _apply_fault()
            await attempt(
                coord.async_record_statistics(
                    baseline, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
                )
            )

        await async_wait_recording_done(hass)
        fired = harness.fired(barrier)
        assert fired == 1, (
            f"Fault {case.fault_id} must fire exactly once (fired={fired}, hits={harness.hits(barrier)})"
        )
        _record_trigger(case.fault_id, barrier, fired)

        # Assert physical disk and BOTH SQLite series BEFORE cold reconstruction/healing.
        await _assert_matrix_intermediate(
            case, substrate, hass, initial_day, initial_hourly, baseline, hourly
        )

        # Cold reconstruct
        harness.uninstall()
        cold_coord = await substrate.cold_reconstruct(coord, hass, reopen_db=False)
        harness.install(cold_coord)

        # Healthy recovery poll
        await cold_coord.async_record_statistics(
            baseline,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        # Compare both series against reference model
        model = ReferenceStatisticsModel()
        model.record_daily(initial_day + baseline)
        model.promote_hourly("2026-09-30", initial_hourly)
        model.promote_hourly("2026-10-01", hourly)

        final_consumption = await substrate.query_recorder_rows(hass, CONSUMPTION_ID)
        final_cost = await substrate.query_recorder_rows(hass, COST_ID)

        compare_both_series(
            actual_consumption=final_consumption,
            actual_cost=final_cost,
            expected_consumption=model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            expected_cost=model.expected_rows_as_tuples(COST_STATISTIC_ID),
        )
        assert_chained_nondecreasing(final_consumption)
        assert_chained_nondecreasing(final_cost)

        # Journal must be clear
        assert not substrate.read_store_json().get("data", {}).get("pending")

    finally:
        await harness.cleanup()

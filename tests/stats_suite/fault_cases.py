"""Declared fault cases and applicability matrix for PSE&G statistics durability tests.

Enumerates all 34 named semantic barriers against 7 fault kinds:
(write_error, read_error, sqlalchemy_error, timeout, cancellation, retired_stale, pause).
Every impossible combination contains an explicit, verified domain reason explaining why
the seam cannot physically encounter or exhibit that specific fault kind.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from tests.support.stats_faults import BARRIER_INVENTORY

FAULT_KIND_WRITE_ERROR = "write_error"
FAULT_KIND_READ_ERROR = "read_error"
FAULT_KIND_SQLALCHEMY_ERROR = "sqlalchemy_error"
FAULT_KIND_TIMEOUT = "timeout"
FAULT_KIND_CANCELLATION = "cancellation"
FAULT_KIND_RETIRED_STALE = "retired_stale"
FAULT_KIND_PAUSE = "pause"

ALL_FAULT_KINDS: tuple[str, ...] = (
    FAULT_KIND_WRITE_ERROR,
    FAULT_KIND_READ_ERROR,
    FAULT_KIND_SQLALCHEMY_ERROR,
    FAULT_KIND_TIMEOUT,
    FAULT_KIND_CANCELLATION,
    FAULT_KIND_RETIRED_STALE,
    FAULT_KIND_PAUSE,
)


@dataclass(frozen=True)
class FaultCase:
    """Declared fault case defining barrier, fault kind, applicability and reason."""

    fault_id: str
    barrier: str
    fault_kind: str
    applicable: bool
    impossible_reason: str | None = None
    description: str = ""
    series_order: str = "consumption_first"
    partial_series: str | None = None
    is_fast_control: bool = False


def _evaluate_case(barrier: str, kind: str) -> tuple[bool, str | None, str]:
    desc = BARRIER_INVENTORY[barrier]
    cat = desc.category

    # 1. WRITE_ERROR
    if kind == FAULT_KIND_WRITE_ERROR:
        if barrier in ("store_write_pending", "store_write_commit"):
            return True, None, f"Physical disk write failure while saving {barrier} to Store JSON."
        if cat == "store":
            return (
                False,
                "Store readback is a read-only operation; no disk write occurs at this barrier.",
                "",
            )
        if cat == "recorder":
            return (
                False,
                "Recorder operations interact with the SQLite database via SQLAlchemy, not raw store disk write calls.",
                "",
            )
        return (
            False,
            "Awaited seam point is an async coordination boundary; disk write operations occur only at physical store write barriers.",
            "",
        )

    # 2. READ_ERROR
    if kind == FAULT_KIND_READ_ERROR:
        if barrier == "store_readback":
            return True, None, "Physical disk read failure loading Store provenance JSON from disk."
        if cat == "store":
            return (
                False,
                "Store write barrier is an atomic disk write; no disk readback is performed at this seam.",
                "",
            )
        if cat == "recorder":
            return (
                False,
                "Recorder read operations query SQLite via SQLAlchemy; disk read errors at recorder level manifest as SQLAlchemyError.",
                "",
            )
        return (
            False,
            "Awaited seam point is an async coordination boundary; physical store reads occur at STORE_READBACK.",
            "",
        )

    # 3. SQLALCHEMY_ERROR
    if kind == FAULT_KIND_SQLALCHEMY_ERROR:
        if barrier in (
            "recorder_import_consumption",
            "recorder_import_cost",
            "recorder_commit_consumption",
            "recorder_commit_cost",
            "recorder_commit_barrier",
            "recorder_readback_consumption",
            "recorder_readback_cost",
            "before_baseline_reads",
        ):
            return True, None, f"SQLAlchemy engine or database error during {barrier}."
        if cat == "store":
            return (
                False,
                "Store operations interact directly with the on-disk JSON file, not SQLAlchemy or the recorder database.",
                "",
            )
        return (
            False,
            "Coordination seam does not execute database queries or interact with SQLAlchemy session/engine.",
            "",
        )

    # 4. TIMEOUT
    if kind == FAULT_KIND_TIMEOUT:
        if barrier in (
            "store_readback",
            "before_store_load",
            "before_recover_pending",
            "before_baseline_reads",
            "before_journal_save",
            "before_recorder_commit",
            "before_mutation_verify",
            "before_journal_commit",
            "recorder_commit_barrier",
            "before_recovery_durability_wait",
            "before_recovery_verify",
            "before_recovery_replay",
            "before_recovery_commit",
        ):
            return True, None, f"Timeout while awaiting {barrier}."
        if barrier in (
            "recorder_import_consumption",
            "recorder_import_cost",
            "before_recorder_import",
            "after_recorder_import",
        ):
            return (
                False,
                "async_add_external_statistics is a non-awaited synchronous dispatch call in Home Assistant; cannot await or timeout.",
                "",
            )
        if barrier.startswith("after_"):
            return (
                False,
                "Post-operation hook occurs after the awaited task has already completed; timeout cannot be triggered post-completion.",
                "",
            )
        return (
            False,
            "Direct store write or read operation is an atomic primitive without an internal timeout wrapper.",
            "",
        )

    # 5. CANCELLATION
    if kind == FAULT_KIND_CANCELLATION:
        if barrier in (
            "recorder_import_consumption",
            "recorder_import_cost",
            "before_recorder_import",
            "after_recorder_import",
        ):
            return (
                False,
                "async_add_external_statistics is synchronous and not an awaited coroutine; cannot be cancelled via asyncio.",
                "",
            )
        if barrier.startswith("after_"):
            return (
                False,
                "Post-operation hook occurs after the awaited task has already completed; cancellation cannot abort finished task.",
                "",
            )
        return True, None, f"asyncio.CancelledError injected while awaiting {barrier}."

    # 6. RETIRED_STALE
    if kind == FAULT_KIND_RETIRED_STALE:
        if barrier in (
            "after_store_load",
            "after_recover_pending",
            "after_baseline_reads",
            "after_journal_save",
            "after_recorder_commit",
            "before_recovery_durability_wait",
            "before_recovery_verify",
            "before_recovery_replay",
            "before_recovery_commit",
        ):
            return True, None, f"Coordinator retired or stopped at checkpoint {barrier}."
        if cat in ("store", "recorder"):
            return (
                False,
                "Coordinator retirement is evaluated at coordination boundaries in coordinator logic, not inside store/recorder storage primitives.",
                "",
            )
        return (
            False,
            "Seam point is not a coordinator lifecycle gate where _can_mutate_statistics() is checked.",
            "",
        )

    # 7. PAUSE
    if kind == FAULT_KIND_PAUSE:
        if barrier in (
            "recorder_import_consumption",
            "recorder_import_cost",
            "before_recorder_import",
            "after_recorder_import",
        ):
            return (
                False,
                "async_add_external_statistics is a synchronous non-coroutine call; cannot be paused with an asyncio event.",
                "",
            )
        return True, None, f"Execution paused at barrier {barrier} and subsequently resumed."

    raise ValueError(f"Unknown fault kind: {kind}")


def _build_cases() -> tuple[FaultCase, ...]:
    cases: list[FaultCase] = []
    for barrier in BARRIER_INVENTORY:
        for kind in ALL_FAULT_KINDS:
            applicable, reason, desc = _evaluate_case(barrier, kind)
            fault_id = f"{barrier}__{kind}"
            is_fast = fault_id in (
                "store_write_commit__write_error",
                "recorder_commit_cost__sqlalchemy_error",
                "before_recorder_commit__cancellation",
                "after_journal_save__retired_stale",
            )
            series_order = (
                "cost_first"
                if "cost" in barrier and not barrier.endswith("consumption")
                else "consumption_first"
            )
            partial = (
                "consumption"
                if "consumption" in barrier
                else ("cost" if "cost" in barrier else None)
            )
            cases.append(
                FaultCase(
                    fault_id=fault_id,
                    barrier=barrier,
                    fault_kind=kind,
                    applicable=applicable,
                    impossible_reason=reason,
                    description=desc or (reason or ""),
                    series_order=series_order,
                    partial_series=partial,
                    is_fast_control=is_fast,
                )
            )
    return tuple(cases)


FAULT_MATRIX: tuple[FaultCase, ...] = _build_cases()
APPLICABLE_CASES: tuple[FaultCase, ...] = tuple(c for c in FAULT_MATRIX if c.applicable)
IMPOSSIBLE_CASES: tuple[FaultCase, ...] = tuple(c for c in FAULT_MATRIX if not c.applicable)
FAST_TIER_CASES: tuple[FaultCase, ...] = tuple(c for c in FAULT_MATRIX if c.is_fast_control)

_CASES_BY_ID: dict[str, FaultCase] = {c.fault_id: c for c in FAULT_MATRIX}


def get_case(fault_id: str) -> FaultCase:
    """Retrieve declared fault case by fault ID."""
    if fault_id not in _CASES_BY_ID:
        raise KeyError(f"Unknown fault ID: {fault_id}")
    return _CASES_BY_ID[fault_id]


def audit_fault_matrix() -> dict[str, Any]:
    """Audit the completeness, uniqueness, and consistency of declared fault cases."""
    assert len(FAULT_MATRIX) == len(BARRIER_INVENTORY) * len(ALL_FAULT_KINDS)
    assert len(_CASES_BY_ID) == len(FAULT_MATRIX), "Duplicate fault_id found in matrix"
    assert len(APPLICABLE_CASES) == 82
    assert len(IMPOSSIBLE_CASES) == 156

    for case in IMPOSSIBLE_CASES:
        assert case.impossible_reason is not None, f"Missing impossible reason for {case.fault_id}"
        assert len(case.impossible_reason) > 15, f"Impossible reason too short for {case.fault_id}"

    for case in APPLICABLE_CASES:
        assert case.impossible_reason is None, (
            f"Applicable case {case.fault_id} has impossible_reason"
        )
        assert len(case.description) > 10

    return {
        "total_cases": len(FAULT_MATRIX),
        "applicable_count": len(APPLICABLE_CASES),
        "impossible_count": len(IMPOSSIBLE_CASES),
        "fast_tier_count": len(FAST_TIER_CASES),
        "barriers_covered": len(BARRIER_INVENTORY),
        "fault_kinds": list(ALL_FAULT_KINDS),
    }


# Focused S5 detectors. Kept here because P3-06 permits detector additions only
# in the case modules. The mutation catalog collects these exact nodes explicitly;
# importing this data module does not install fixtures into other test modules.
@pytest.fixture
def recorder_db_url(tmp_path):
    """Use the same physical SQLite path as PhysicalDurabilitySubstrate."""
    return f"sqlite:///{tmp_path / 'fault_recorder.db'}"


@pytest.fixture(autouse=True)
def writer_recorder(recorder_mock, enable_custom_integrations):
    """Start the real recorder before the coordinator's hass fixture."""
    yield


async def test_writer_refuses_a_dropped_physical_journal(hass, tmp_path):
    """Acknowledged Store writes that lose journal bytes must not change DB rows."""
    from unittest.mock import patch

    from pytest_homeassistant_custom_component.components.recorder.common import (
        async_wait_recording_done,
    )

    from custom_components.pseg.coordinator import PsegStatisticsError
    from tests.stats_suite.reference_cases import make_daily_records
    from tests.support.stats_faults import PhysicalDurabilitySubstrate
    from tests.support.stats_model import CONSUMPTION_STATISTIC_ID, COST_STATISTIC_ID

    substrate = PhysicalDurabilitySubstrate(tmp_path)
    coord = substrate.create_coordinator(hass)
    await coord.async_record_statistics(make_daily_records("2026-10-01", 1), meter_id="m1")
    before = substrate.read_store_bytes()
    ids = (CONSUMPTION_STATISTIC_ID, COST_STATISTIC_ID)
    rows_before = [await substrate.query_recorder_rows(hass, sid) for sid in ids]
    real_write = coord._stats_state._store._write_data
    dropped = []

    def drop_pending(wrapper):
        if wrapper["data"]["pending"]:
            dropped.append(True)
            return
        real_write(wrapper)

    with patch.object(coord._stats_state._store, "_write_data", drop_pending):
        try:
            await coord.async_record_statistics(
                make_daily_records("2026-10-01", 1, 20.0), meter_id="m1"
            )
        except PsegStatisticsError:
            pass
        await async_wait_recording_done(hass)
        assert dropped, "Physical pending-write fault never fired"
        assert substrate.read_store_bytes() == before, "Unverified journal changed disk provenance"
        for sid, expected in zip(ids, rows_before, strict=True):
            assert await substrate.query_recorder_rows(hass, sid) == expected, (
                "Recorder changed without a physically durable journal"
            )


@pytest.mark.parametrize("day", ["2026-10-01", "2026-11-01"], ids=["normal", "fall25"])
async def test_writer_partial_sql_failure_and_cold_replay(hass, tmp_path, day):
    """Check intermediate disk state, then force exact replay after reopening DB."""
    from datetime import UTC, datetime
    from unittest.mock import patch

    from homeassistant.components.recorder import statistics as recorder_stats
    from pytest_homeassistant_custom_component.components.recorder.common import (
        async_wait_recording_done,
    )
    from sqlalchemy.exc import SQLAlchemyError

    from custom_components.pseg.coordinator import PsegStatisticsError
    from tests.stats_suite.reference_cases import make_canonical_hourly_records
    from tests.support.stats_faults import PhysicalDurabilitySubstrate
    from tests.support.stats_model import (
        CONSUMPTION_STATISTIC_ID,
        COST_STATISTIC_ID,
        ReferenceStatisticsModel,
        compare_both_series,
    )

    substrate = PhysicalDurabilitySubstrate(tmp_path)
    coord = substrate.create_coordinator(hass)
    hourly = make_canonical_hourly_records(day)
    daily = [{"date": day, "kwh": float(len(hourly)), "cost": len(hourly) * 0.25}]
    real_import = recorder_stats.import_statistics
    fired = []

    def fail_cost(instance, metadata, stats, table):
        if metadata["statistic_id"] == COST_STATISTIC_ID:
            fired.append(True)
            raise SQLAlchemyError("Synthetic cost SQL failure at real recorder task")
        return real_import(instance, metadata, stats, table)

    with patch("homeassistant.util.dt.utcnow", return_value=datetime(2026, 11, 10, tzinfo=UTC)):
        with patch.object(recorder_stats, "import_statistics", fail_cost):
            try:
                await coord.async_record_statistics(
                    daily, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
                )
            except PsegStatisticsError:
                pass
            await async_wait_recording_done(hass)

        # These assertions precede recovery: a later healthy poll cannot conceal
        # false completeness or premature clearing after a swallowed SQL error.
        assert len(fired) == 1, "Real cost SQL fault must fire exactly once"
        assert len(await substrate.query_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)) == len(hourly)
        assert await substrate.query_recorder_rows(hass, COST_STATISTIC_ID) == []
        disk = substrate.read_store_json()["data"]
        assert disk["pending"], "Intermediate physical journal cleared with cost DB empty"
        assert not disk["promoted"], "Intermediate disk promotion falsely claims both series"

        cold = await substrate.cold_reconstruct(coord, hass, reopen_db=True)
        # Recover directly, without a new hourly poll that could repair a bad
        # replay and hide canonical-start reinterpretation or omitted cost rows.
        try:
            await cold._async_recover_pending()
        except PsegStatisticsError:
            pass
        await async_wait_recording_done(hass)
        model = ReferenceStatisticsModel()
        model.record_daily(daily)
        model.promote_hourly(day, hourly)
        compare_both_series(
            await substrate.query_recorder_rows(hass, CONSUMPTION_STATISTIC_ID),
            await substrate.query_recorder_rows(hass, COST_STATISTIC_ID),
            model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            model.expected_rows_as_tuples(COST_STATISTIC_ID),
        )
        assert not substrate.read_store_json()["data"]["pending"]
        assert set(substrate.read_store_json()["data"]["promoted"]) == {
            CONSUMPTION_STATISTIC_ID, COST_STATISTIC_ID,
        }


@pytest.mark.parametrize("control", ["pause", "retire"])
async def test_writer_control_after_durable_journal(hass, tmp_path, control):
    """Changing the live control during journal I/O must leave both DBs empty."""
    from unittest.mock import patch

    from pytest_homeassistant_custom_component.components.recorder.common import (
        async_wait_recording_done,
    )

    from custom_components.pseg.const import CONF_STATISTICS_IMPORT_ENABLED
    from tests.stats_suite.reference_cases import make_daily_records
    from tests.support.stats_faults import PhysicalDurabilitySubstrate
    from tests.support.stats_model import CONSUMPTION_STATISTIC_ID, COST_STATISTIC_ID

    substrate = PhysicalDurabilitySubstrate(tmp_path)
    coord = substrate.create_coordinator(hass)
    real_begin = coord._stats_state.async_begin
    observed = []

    async def begin_then_control(mutation):
        mutation_id = await real_begin(mutation)
        assert substrate.read_store_json()["data"]["pending"], "Journal not physical at control change"
        observed.append(True)
        if control == "pause":
            hass.config_entries.async_update_entry(
                coord.config_entry, options={CONF_STATISTICS_IMPORT_ENABLED: False}
            )
        else:
            coord.stop_keepalive()
        return mutation_id

    with patch.object(coord._stats_state, "async_begin", begin_then_control):
        await coord.async_record_statistics(make_daily_records("2026-10-01", 1), meter_id="m1")
    await async_wait_recording_done(hass)
    assert observed == [True]
    for sid in (CONSUMPTION_STATISTIC_ID, COST_STATISTIC_ID):
        assert await substrate.query_recorder_rows(hass, sid) == [], (
            f"Physical recorder mutated after {control} during journal I/O"
        )
    assert not substrate.read_store_json()["data"]["pending"]
    assert not substrate.read_store_json()["data"]["promoted"]


async def test_writer_verifies_only_after_physical_commit(hass, tmp_path):
    """Hold real recorder imports until the production commit barrier is entered."""
    import threading
    from unittest.mock import patch

    from homeassistant.components.recorder import get_instance
    from homeassistant.components.recorder.tasks import RecorderTask
    from pytest_homeassistant_custom_component.components.recorder.common import (
        async_wait_recording_done,
    )

    from custom_components.pseg import coordinator as cm
    from tests.stats_suite.reference_cases import make_daily_records
    from tests.support.stats_faults import PhysicalDurabilitySubstrate
    from tests.support.stats_model import CONSUMPTION_STATISTIC_ID, COST_STATISTIC_ID

    substrate = PhysicalDurabilitySubstrate(tmp_path)
    coord = substrate.create_coordinator(hass)
    reached, release = threading.Event(), threading.Event()
    real_add = cm.async_add_external_statistics
    real_wait = cm._async_wait_for_recorder_commit
    real_verify = coord._async_verify_mutation
    queued, checked = [], []

    class HoldRecorder(RecorderTask):
        commit_before = False

        def run(self, instance):
            reached.set()
            assert release.wait(10.0), "Bounded recorder gate was never released"

    def queue_behind_gate(*args):
        if not queued:
            get_instance(hass).queue_task(HoldRecorder())
        queued.append(True)
        return real_add(*args)

    async def release_at_commit(hass_arg):
        assert await hass.async_add_executor_job(reached.wait, 10.0), "Recorder gate never reached"
        release.set()
        await real_wait(hass_arg)

    async def physical_verify(mutation):
        # Independent DB queries while the recorder queue is held must be empty
        # if the production barrier was removed. Assert actual DB rows, not a
        # mocked barrier-call flag or an in-memory completion indicator.
        for sid, state in ((CONSUMPTION_STATISTIC_ID, 10.0), (COST_STATISTIC_ID, 2.5)):
            rows = await substrate.query_recorder_rows(hass, sid)
            assert len(rows) == 1 and rows[0][1:] == (state, state), (
                "Verification reached before physical recorder commit"
            )
        assert substrate.read_store_json()["data"]["pending"]
        checked.append(True)
        return await real_verify(mutation)

    try:
        with (
            patch.object(cm, "async_add_external_statistics", queue_behind_gate),
            patch.object(cm, "_async_wait_for_recorder_commit", release_at_commit),
            patch.object(coord, "_async_verify_mutation", physical_verify),
        ):
            await coord.async_record_statistics(make_daily_records("2026-10-01", 1), meter_id="m1")
        assert queued == [True, True] and checked == [True]
        assert not substrate.read_store_json()["data"]["pending"]
    finally:
        release.set()
        await async_wait_recording_done(hass)

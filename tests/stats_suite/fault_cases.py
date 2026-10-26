"""Declared fault cases and applicability matrix for PSE&G statistics durability tests.

Enumerates all 34 named semantic barriers against 7 fault kinds:
(write_error, read_error, sqlalchemy_error, timeout, cancellation, retired_stale, pause).
Every impossible combination contains an explicit, verified domain reason explaining why
the seam cannot physically encounter or exhibit that specific fault kind.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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

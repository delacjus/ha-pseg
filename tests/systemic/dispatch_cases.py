"""Case matrix for the P2-06 dispatch-boundary and ownership sweep.

The matrix is derived from the generated inventory (:mod:`tests.support.boundaries`)
so every inventoried boundary has exactly one retirement-fence case, and every
retirement transition is exercised. Fast cases cover the mandatory fence, redirect,
stage-transition, credential-POST, first and last-before-persist representatives; the
complete sweep is marked ``slow``.

Test-only: no production edits.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence

from tests.support.boundaries import (
    ALL_BOUNDARY_CLASSES,
    EXCLUSIONS,
    FLOW_PLANS,
    FLOWS,
    SWEEP_OPERATIONS,
    Boundary,
    BoundaryClass,
    FenceCase,
    FenceEvidence,
    Leg,
    compare_inventory,
    generated_boundaries,
)

#: Retirement transitions exercised for each flow. L/S/H exclude the same-cookie
#: handoff (their healthy same-cookie handoff is refused by the sign-in proof, so no
#: owner is replaced); flow R's Remember-Me credential renews and commits.
TRANSITION_ROTATION: Mapping[str, tuple[str, ...]] = {
    "L": ("unload", "reload", "stop", "cancel"),
    "R": ("unload", "reload", "handoff", "stop", "cancel"),
    "S": ("unload", "reload", "stop", "cancel"),
    "H": ("unload", "reload", "stop", "cancel"),
}

REQUIRED_INVARIANTS: tuple[str, ...] = ("I1", "I2", "I5", "I9")

MANDATORY_FENCE_CLASSES: tuple[BoundaryClass, ...] = (
    BoundaryClass.FIRST,
    BoundaryClass.MID_GET,
    BoundaryClass.CREDENTIAL_POST,
    BoundaryClass.REDIRECT,
    BoundaryClass.STAGE_TRANSITION,
    BoundaryClass.LAST_BEFORE_PERSIST,
)


def boundary_for(flow: str, operation: str, index: int) -> Boundary:
    """Return one generated boundary by flow, operation and plan index."""
    return generated_boundaries(flow)[operation][index]


def _first_boundary(flow: str, operation: str, boundary_class: BoundaryClass) -> Boundary:
    for boundary in generated_boundaries(flow)[operation]:
        if boundary_class in boundary.classes:
            return boundary
    raise KeyError(f"{flow}:{operation} has no {boundary_class} boundary")


def _case(
    case_id: str,
    flow: str,
    operation: str,
    boundary: Boundary,
    transition: str,
    notes: str = "",
) -> FenceCase:
    return FenceCase(
        case_id=case_id,
        flow=flow,
        operation=operation,
        boundary=boundary,
        transition=transition,
        tier="fast",
        notes=notes,
    )


#: Mandatory fast representatives: one per boundary class plus the redirect/stage
#: fence controls the acceptance command repeats ten times.
FAST_CASES: tuple[FenceCase, ...] = (
    _case(
        "fast_first_poll_unload",
        "L",
        "poll",
        _first_boundary("L", "poll", BoundaryClass.FIRST),
        "unload",
        "first mid-flight GET of a poll retires the owner and unloads the entry",
    ),
    _case(
        "fast_mid_get_poll_cancel",
        "L",
        "poll",
        boundary_for("L", "poll", 0),
        "cancel",
        "first poll GET cancelled and replaced by an authorized successor",
    ),
    _case(
        "fast_redirect_boundary_reload",
        "S",
        "auth_renewal",
        _first_boundary("S", "auth_renewal", BoundaryClass.REDIRECT),
        "reload",
        "the signed-out landing redirect hop is in flight when the owner reloads",
    ),
    _case(
        "fast_stage_transition_handoff",
        "R",
        "poll",
        _first_boundary("R", "poll", BoundaryClass.STAGE_TRANSITION),
        "handoff",
        "the Chart->ChartData stage transition is in flight during a same-cookie handoff",
    ),
    _case(
        "fast_credential_post_stop",
        "L",
        "auth_renewal",
        _first_boundary("L", "auth_renewal", BoundaryClass.CREDENTIAL_POST),
        "stop",
        "the local credential POST is in flight when the entry is stopped",
    ),
    _case(
        "fast_last_before_persist_cancel",
        "L",
        "poll",
        _first_boundary("L", "poll", BoundaryClass.LAST_BEFORE_PERSIST),
        "cancel",
        "the last leg before persistence is in flight when the refresh is cancelled",
    ),
)


def slow_transition(flow: str, index: int) -> str:
    """Deterministically rotate retirement transitions over a flow's boundaries."""
    rotation = TRANSITION_ROTATION[flow]
    return rotation[index % len(rotation)]


#: Per-flow operations kept out of the retirement sweep, with the reason recorded in
#: :data:`tests.support.boundaries.EXCLUSIONS`.
SWEEP_EXCLUSIONS: Mapping[str, tuple[str, ...]] = {}


def sweepable_boundaries(flow: str) -> tuple[tuple[str, Boundary], ...]:
    """Every boundary covered by the retirement sweep for a flow."""
    entries: list[tuple[str, Boundary]] = []
    skipped = SWEEP_EXCLUSIONS.get(flow, ())
    for operation in SWEEP_OPERATIONS:
        if operation in skipped:
            continue
        for boundary in generated_boundaries(flow).get(operation, ()):
            entries.append((operation, boundary))
    return tuple(entries)


def slow_case_matrix() -> tuple[FenceCase, ...]:
    """Build the complete slow retirement sweep."""
    cases: list[FenceCase] = []
    for flow in FLOWS:
        for index, (operation, boundary) in enumerate(sweepable_boundaries(flow)):
            transition = slow_transition(flow, index)
            cases.append(
                FenceCase(
                    case_id=f"slow_{flow}_{operation}_{boundary.method.lower()}"
                    f"_{boundary.path.strip('/').replace('/', '_')}_{boundary.leg}_{transition}",
                    flow=flow,
                    operation=operation,
                    boundary=boundary,
                    transition=transition,
                    tier="slow",
                    notes=f"{flow} {operation} boundary {boundary.boundary_id}",
                )
            )
    return tuple(cases)


SLOW_CASES: tuple[FenceCase, ...] = slow_case_matrix()

#: Boundaries that are inventoried but cannot be retirement-fenced in flight.
EXCLUDED_OPERATIONS: tuple[str, ...] = ("setup", "reauth", "reconfigure")


def inventory_summary() -> dict[str, dict[str, int]]:
    """Return per-flow boundary counts by class (a boundary may have several)."""
    summary: dict[str, dict[str, int]] = {}
    for flow in FLOWS:
        counts: Counter[str] = Counter()
        for boundaries in generated_boundaries(flow).values():
            for boundary in boundaries:
                for boundary_class in boundary.classes:
                    counts[str(boundary_class)] += 1
                counts["all"] += 1
        summary[flow] = dict(counts)
    return summary


def inventory_boundary_counts() -> dict[str, int]:
    """Return the number of generated boundaries per flow and operation."""
    counts: dict[str, int] = {}
    for flow in FLOWS:
        for operation, boundaries in generated_boundaries(flow).items():
            counts[f"{flow}:{operation}"] = len(boundaries)
    return counts


def case_class_coverage(cases: Sequence[FenceCase]) -> dict[str, int]:
    """Count the boundary classes covered by a case sequence."""
    counts: Counter[str] = Counter()
    for case in cases:
        for boundary_class in case.boundary.classes:
            counts[str(boundary_class)] += 1
    return dict(counts)


def sweep_coverage_problems(cases: Sequence[FenceCase] = SLOW_CASES) -> list[str]:
    """Return coverage gaps for the slow sweep (empty means complete)."""
    problems: list[str] = []
    covered: Counter[tuple[str, str]] = Counter()
    for case in cases:
        covered[(case.flow, case.boundary.boundary_id)] += 1
    for flow in FLOWS:
        for operation, boundary in sweepable_boundaries(flow):
            key = (flow, boundary.boundary_id)
            if covered[key] != 1:
                problems.append(
                    f"{flow}:{operation}:{boundary.boundary_id} covered {covered[key]}x"
                )
    for boundary_class in ALL_BOUNDARY_CLASSES:
        if not any(boundary_class in case.boundary.classes for case in cases):
            problems.append(f"no slow case covers {boundary_class}")
    for flow in FLOWS:
        transitions = {case.transition for case in cases if case.flow == flow}
        expected = set(TRANSITION_ROTATION[flow])
        if transitions != expected:
            problems.append(f"{flow}: transitions {sorted(transitions)} != {sorted(expected)}")
    return problems


def requirement_problems(cases: Sequence[FenceCase]) -> list[str]:
    """Return missing mandatory fast representatives."""
    problems: list[str] = []
    covered_classes = {boundary_class for case in cases for boundary_class in case.boundary.classes}
    for boundary_class in MANDATORY_FENCE_CLASSES:
        if boundary_class not in covered_classes:
            problems.append(f"no fast case covers {boundary_class}")
    transitions = {case.transition for case in cases}
    for transition in ("unload", "reload", "stop", "cancel", "handoff"):
        if transition not in transitions:
            problems.append(f"no fast case exercises {transition}")
    return problems


def evidence_problems(evidence: FenceEvidence) -> list[str]:
    """Return contract violations for one executed fence case."""
    problems: list[str] = []
    if not evidence.owner_retired:
        problems.append(f"{evidence.case_id}: owner was not retired through production")
    if evidence.later_dispatches:
        problems.append(f"{evidence.case_id}: {evidence.later_dispatches} later dispatches")
    if evidence.post_retirement_attempts:
        problems.append(
            f"{evidence.case_id}: {evidence.post_retirement_attempts} post-retirement attempts"
        )
    if evidence.oracle_codes:
        problems.append(f"{evidence.case_id}: oracle codes {list(evidence.oracle_codes)}")
    if len(evidence.ending_steps) != 4:
        problems.append(f"{evidence.case_id}: incomplete ending {list(evidence.ending_steps)}")
    if evidence.parked_outcome in (None, "pending", "gated"):
        problems.append(f"{evidence.case_id}: parked send did not complete")
    return problems


def plan_without(
    flow: str,
    predicate: Callable[[Leg], bool],
) -> dict[str, tuple[Leg, ...]]:
    """Return a copy of a flow plan with matching legs removed (negative proofs)."""
    return {
        operation: tuple(leg for leg in legs if not predicate(leg))
        for operation, legs in FLOW_PLANS[flow].items()
    }


def is_stage_transition_leg(leg: Leg, legs: Sequence[Leg]) -> bool:
    """True for a ChartData leg that follows a Chart POST in the same plan."""
    method, path, _ = leg
    if method != "GET" or not path.endswith("/Dashboard/ChartData"):
        return False
    index = list(legs).index(leg)
    if index == 0:
        return False
    previous = legs[index - 1]
    return previous[0] == "POST" and previous[1].endswith("/Chart")


def is_redirect_leg(leg: Leg) -> bool:
    """True for a planned redirect hop."""
    return bool(leg[2])


def missing_boundary_ids(flow: str, plan: Mapping[str, Sequence[Leg]]) -> list[str]:
    """Return the boundaries the unmutated dry-run plan has but ``plan`` lost."""
    problems = compare_inventory(flow, FLOW_PLANS[flow], plan=plan)
    lost: set[str] = set()
    for problem in problems:
        for marker in ("ungenerated observed boundary ", "missing observed boundary "):
            if marker in problem:
                lost.add(problem.split(marker, 1)[1])
    return sorted(lost)


def case_tiers() -> dict[str, int]:
    """Return the fast/slow case counts."""
    return {"fast": len(FAST_CASES), "slow": len(SLOW_CASES)}


def all_cases() -> tuple[FenceCase, ...]:
    """Return fast and slow cases."""
    return (*FAST_CASES, *SLOW_CASES)


__all__ = [
    "EXCLUDED_OPERATIONS",
    "EXCLUSIONS",
    "FAST_CASES",
    "MANDATORY_FENCE_CLASSES",
    "REQUIRED_INVARIANTS",
    "SLOW_CASES",
    "SWEEP_EXCLUSIONS",
    "TRANSITION_ROTATION",
    "all_cases",
    "boundary_for",
    "case_class_coverage",
    "case_tiers",
    "evidence_problems",
    "inventory_boundary_counts",
    "inventory_summary",
    "is_redirect_leg",
    "is_stage_transition_leg",
    "missing_boundary_ids",
    "plan_without",
    "requirement_problems",
    "slow_case_matrix",
    "slow_transition",
    "sweep_coverage_problems",
    "sweepable_boundaries",
]

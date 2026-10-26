"""P2-06: G1 request-boundary and ownership sweep.

Proves the production dispatch fence across the actual L/R/S/H dispatch boundaries:

* a dry run of real lifecycle traces produces the boundary inventory, and the
  inventory equals the declaratively generated plan for every applicable flow;
* at every swept boundary a real scripted response is parked in flight, the owning
  generation is retired through a real lifecycle transition (unload, reload,
  same-cookie human handoff, cancel, stop), the response is released, and no later
  dispatch by the retired generation is observed;
* retirement before the very first request is covered by a factory gate released
  before the real client executes its ownership fence;
* every case runs the mandatory ``run_case`` follow-on and invokes the oracle for
  I1, I2, I5 and I9; the observer never enforces the fence - the production ownership
  check does.

Fast tier: inventory plus the mandatory fence/redirect/stage/credential-post
representatives, the pre-fence case, the H exemption case, the current-owner 307/308
control and the old-status control. The complete boundary sweep is marked ``slow``.
"""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant
import pytest

from tests.support.boundaries import (
    ALL_BOUNDARY_CLASSES,
    EXCLUSIONS,
    FLOWS,
    OPERATIONS,
    BoundaryClass,
    compare_inventory,
    dry_run_flow,
    generated_boundaries,
    observed_boundaries,
    run_current_owner_307_control,
    run_fence_case,
    run_human_exemption_case,
    run_old_status_control,
    run_pre_fence_case,
    unattached_exemption_probe,
)
from tests.systemic.dispatch_cases import (
    FAST_CASES,
    MANDATORY_FENCE_CLASSES,
    REQUIRED_INVARIANTS,
    SLOW_CASES,
    case_class_coverage,
    case_tiers,
    evidence_problems,
    inventory_boundary_counts,
    inventory_summary,
    is_redirect_leg,
    missing_boundary_ids,
    plan_without,
    requirement_problems,
    sweep_coverage_problems,
)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock: Any, enable_custom_integrations: Any) -> Any:
    yield


# ---------------------------------------------------------------------------
# Inventory: dry run == generated plan
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flow", FLOWS)
async def test_dry_run_boundary_inventory_matches_generated(
    hass: HomeAssistant,
    flow: str,
) -> None:
    """The real trace's boundary IDs equal the generated inventory for every flow."""
    slices = await dry_run_flow(hass, flow)
    problems = compare_inventory(flow, slices)
    assert not problems, f"{flow} inventory drift: {problems}"

    expected = generated_boundaries(flow)
    for operation in OPERATIONS:
        if operation not in expected:
            assert operation not in slices, f"{flow}: unexpected operation {operation}"
            continue
        assert operation in slices, f"{flow}: dry run skipped declared operation {operation}"
        observed = observed_boundaries(flow, {operation: slices[operation]})[operation]
        declared = expected[operation]
        assert {b.boundary_id for b in observed} == {b.boundary_id for b in declared}
        assert {b.classes for b in observed} == {b.classes for b in declared}


def test_generated_inventory_covers_every_operation_and_class() -> None:
    """Every declared operation produces boundaries and all six classes are present."""
    counts = inventory_boundary_counts()
    summary = inventory_summary()
    print("P2-06 inventory:", counts)

    assert any(summary[flow]["all"] > 0 for flow in FLOWS)

    for flow in FLOWS:
        for operation in OPERATIONS:
            if operation == "unload":
                # The unload transition itself must not dispatch anything.
                assert counts[f"{flow}:{operation}"] == 0
                continue
            if operation == "auth_renewal" and flow == "H":
                assert counts.get(f"{flow}:{operation}") is None
                continue
            assert counts[f"{flow}:{operation}"] > 0, f"{flow}:{operation} has no boundaries"

    observed_classes = {
        boundary_class
        for flow in FLOWS
        for boundaries in generated_boundaries(flow).values()
        for boundary in boundaries
        for boundary_class in boundary.classes
    }
    assert observed_classes == set(ALL_BOUNDARY_CLASSES), (
        f"inventory misses boundary classes: {set(ALL_BOUNDARY_CLASSES) - observed_classes}"
    )
    assert EXCLUSIONS, "applicability exclusions must be documented"


def test_slow_matrix_covers_every_swept_boundary_once() -> None:
    """The slow sweep covers every applicable boundary exactly once, all transitions."""
    from tests.systemic.dispatch_cases import SWEEP_EXCLUSIONS

    assert SWEEP_EXCLUSIONS == {"S": ("keepalive",)}
    assert "s_keepalive_sso" in EXCLUSIONS
    problems = sweep_coverage_problems()
    assert not problems, f"slow sweep coverage gaps: {problems}"
    tiers = case_tiers()
    assert tiers["fast"] == len(FAST_CASES)
    assert tiers["slow"] == len(SLOW_CASES)
    assert tiers["slow"] >= 60, f"full sweep is unexpectedly small: {tiers}"


def test_fast_representatives_cover_mandatory_classes_and_transitions() -> None:
    """Fast cases must cover every boundary class and every retirement transition."""
    assert not requirement_problems(FAST_CASES)
    covered = case_class_coverage(FAST_CASES)
    for boundary_class in MANDATORY_FENCE_CLASSES:
        assert covered[str(boundary_class)] > 0


# ---------------------------------------------------------------------------
# Generator sensitivity (negative proofs a and b)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flow", ["L", "S"])
def test_negative_proof_omitted_stage_transition_breaks_inventory(flow: str) -> None:
    """Omitting a Chart->ChartData boundary from generation must break the inventory."""
    plan = plan_without(
        flow,
        lambda leg: leg[0] == "GET" and leg[1].endswith("/Dashboard/ChartData"),
    )
    lost = missing_boundary_ids(flow, plan)
    assert lost, "removing the ChartData legs did not change the generated inventory"
    assert any("ChartData" in boundary_id for boundary_id in lost)
    stage_ids = {
        boundary.boundary_id
        for boundaries in generated_boundaries(flow).values()
        for boundary in boundaries
        if BoundaryClass.STAGE_TRANSITION in boundary.classes
    }
    assert stage_ids <= set(lost), f"stage-transition boundaries not detected as lost: {lost}"


@pytest.mark.parametrize("flow", ["L", "S"])
def test_negative_proof_omitted_redirect_breaks_inventory(flow: str) -> None:
    """Omitting the redirect hop from generation must break the inventory."""
    plan = plan_without(flow, is_redirect_leg)
    lost = missing_boundary_ids(flow, plan)
    assert lost, "removing the redirect hops did not change the generated inventory"
    redirect_ids = {
        boundary.boundary_id
        for boundaries in generated_boundaries(flow).values()
        for boundary in boundaries
        if BoundaryClass.REDIRECT in boundary.classes
    }
    assert redirect_ids
    assert redirect_ids <= set(lost), f"redirect boundaries not detected as lost: {lost}"


# ---------------------------------------------------------------------------
# Fast mandatory fence representatives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", FAST_CASES, ids=[case.case_id for case in FAST_CASES])
async def test_fast_dispatch_fence_representative(
    hass: HomeAssistant,
    caplog: Any,
    case: Any,
) -> None:
    """Park one real boundary, retire the owner, release, prove the fence held."""
    evidence = await run_fence_case(hass, case, caplog=caplog)
    problems = evidence_problems(evidence)
    assert not problems, problems
    assert evidence.parked_sequence > 0
    assert set(evidence.boundary_classes) & {str(c) for c in MANDATORY_FENCE_CLASSES}
    print(f"P2-06 fast evidence {case.case_id}: {evidence.to_dict()}")


async def test_fast_retirement_before_first_request(
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """A factory gate released before the ownership fence proves the first send is refused."""
    facts = await run_pre_fence_case(hass, caplog=caplog)
    assert facts["first_request_blocked"] is True
    assert facts["generation"] != facts["successor_generation"]
    assert facts["post_retirement_attempts"] == 0
    assert facts["i5_checked"] is True
    assert facts["i9_facts"] == {"dead_schedule": False}
    assert len(facts["ending_steps"]) == 4
    print(f"P2-06 pre-fence evidence: {facts}")


async def test_fast_human_handoff_exemption_and_reconfigure_usable(
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """H human verification and the reconfigure reload stay usable under the exemption."""
    facts = await run_human_exemption_case(hass, caplog=caplog)
    assert len(facts["human_generations"]) >= 1
    assert facts["human_dispatches"] >= 1
    assert facts["owner_generation"] not in facts["human_generations"]
    assert facts["reconfigure_dispatches"] > 0
    assert facts["post_retirement_attempts"] == 0
    assert facts["i5_checked"] is True
    assert len(facts["ending_steps"]) == 4
    print(f"P2-06 human exemption evidence: {facts}")


async def test_fast_current_owner_307_control(hass: HomeAssistant, caplog: Any) -> None:
    """A current owner's 307 SAML re-POST still succeeds and keeps its body."""
    facts = await run_current_owner_307_control(hass, caplog=caplog)
    assert facts["re_post_sequence"] == facts["acs_sequence"] + 1
    assert facts["body_digest"]
    assert facts["post_retirement_attempts"] == 0
    assert facts["i5_checked"] is True
    assert len(facts["ending_steps"]) == 4
    print(f"P2-06 307/308 control evidence: {facts}")


async def test_fast_old_status_cannot_win_after_successor(
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """A blocked old request released after successor setup cannot win the status."""
    facts = await run_old_status_control(hass, caplog=caplog)
    assert facts["successor_status"] == "connected"
    assert facts["successor_last_update_success"] is True
    assert facts["retired_generation"] != facts["successor_generation"]
    assert facts["post_retirement_attempts"] == 0
    assert len(facts["ending_steps"]) == 4
    print(f"P2-06 old-status evidence: {facts}")


def test_fast_unattached_human_exemption_rule() -> None:
    """Only explicit unattached-human traffic escapes I1; attached retired traffic does not."""
    exempt_codes, attached_codes = unattached_exemption_probe()
    assert exempt_codes == []
    assert attached_codes == ["I1"]


# ---------------------------------------------------------------------------
# Full sweep (slow)
# ---------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.parametrize("case", SLOW_CASES, ids=[case.case_id for case in SLOW_CASES])
async def test_slow_full_boundary_retirement_sweep(
    hass: HomeAssistant,
    caplog: Any,
    case: Any,
) -> None:
    """Every applicable boundary x rotating retirement transition, with follow-on."""
    evidence = await run_fence_case(hass, case, caplog=caplog)
    problems = evidence_problems(evidence)
    assert not problems, problems
    assert set(evidence.boundary_classes)
    assert evidence.boundary_id == case.boundary.boundary_id
    assert set(REQUIRED_INVARIANTS) == {"I1", "I2", "I5", "I9"}
    assert evidence.oracle_codes == ()
    assert len(evidence.ending_steps) == 4
    print(f"P2-06 slow evidence {case.case_id}: {evidence.to_dict()}")

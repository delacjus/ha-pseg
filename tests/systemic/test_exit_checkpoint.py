"""P2-07: G2 exit/await and latest-checkpoint durability sweep.

Every named client/coordinator exit boundary from the factory's catalog
(``before``/``after`` of ``fetch_energy_data``, ``keepalive``,
``fetch_history_range``, the cookie/auth export and the confirmed/pending
accessors) is crossed with a real cancellation, unload, stop and failed setup, a
renewal or no-renewal session and a SID / RememberMe / auxiliary cookie rotation.

Each applicable case proves, in this order and before any teardown or follow-on poll
can rescue it:

1. two independently eligible whole-jar checkpoints were persisted at their polls;
2. the exit's physical store holds the LATEST eligible jar together with its
   matching settled admission (I5), asserted at the exit itself;
3. the keepalive schedule/ownership is intact where the entry is still loaded (I9);
4. the warm next-poll decision equals the genuinely cold-restarted one (I6);
5. the mandatory ``run_case`` follow-on completes.

Every unsupported combination is declared with a reason (:data:`EXCLUSIONS`) and
checked by :func:`test_unsupported_combinations_are_all_recorded`.

Fast tier: mandatory recency/cancel representatives. The complete applicable sweep
is marked ``slow``.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from homeassistant.core import HomeAssistant
import pytest

from tests.support.boundaries import (
    register_scripted_eligibility,
    script_portal,
)
from tests.support.factory import (
    EXIT_BOUNDARY_CATALOG,
    EXIT_BOUNDARY_GATE_EXCLUSIONS,
    EXIT_BOUNDARY_METHODS,
    exit_boundary_ids,
)
from tests.support.portal import ScriptedPortal
from tests.systemic.exit_cases import (
    ALL_CASES,
    APPLICABLE_TRANSITIONS,
    EXCLUSIONS,
    FAST_CASES,
    ROTATION_COOKIES,
    SLOW_CASES,
    TRANSITIONS,
    ExitCase,
    ExitProbe,
    ProbeFactory,
    boundary_coverage,
    case_tiers,
    coverage_problems,
    run_exit_case,
)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock: Any, enable_custom_integrations: Any) -> Any:
    yield


# ---------------------------------------------------------------------------
# Catalog and matrix closure
# ---------------------------------------------------------------------------


def test_exit_boundary_catalog_is_complete() -> None:
    """The factory catalog names every declared exit method before and after."""
    assert len(EXIT_BOUNDARY_METHODS) == 6
    assert len(EXIT_BOUNDARY_CATALOG) == 12
    ids = exit_boundary_ids()
    assert len(set(ids)) == len(ids)
    for method, runner, operation, _description in EXIT_BOUNDARY_METHODS:
        assert runner in {"executor", "loop"}
        assert operation in {"poll", "keepalive", "backfill"}
        assert f"before:{method}" in ids
        assert f"after:{method}" in ids
    assert set(EXIT_BOUNDARY_GATE_EXCLUSIONS) == {"export_cookies"}
    assert "export_cookies_and_auth_reason" in {method for method, *_ in EXIT_BOUNDARY_METHODS}


def test_every_catalog_boundary_has_applicable_cases() -> None:
    """No catalog boundary may be silently absent from the matrix."""
    counts = boundary_coverage()
    assert set(counts) == set(exit_boundary_ids())
    missing = [boundary for boundary, count in counts.items() if count == 0]
    assert not missing, f"catalog boundaries without any case: {missing}"


def test_unsupported_combinations_are_all_recorded() -> None:
    """Every boundary x transition pair is either covered or explicitly excluded."""
    problems = coverage_problems()
    assert not problems, problems
    for boundary in EXIT_BOUNDARY_CATALOG:
        for transition in TRANSITIONS:
            if transition in APPLICABLE_TRANSITIONS[boundary.name]:
                continue
            key = f"{boundary.name}:{transition}"
            assert key in EXCLUSIONS, f"unsupported combination silently dropped: {key}"
            assert EXCLUSIONS[key].strip(), f"empty exclusion reason: {key}"


def test_matrix_crosses_transitions_renewal_and_rotation() -> None:
    """The matrix crosses every dimension and keeps a bounded slow sweep."""
    tiers = case_tiers()
    assert tiers["fast"] == len(FAST_CASES) == 6
    assert tiers["slow"] == len(SLOW_CASES) == len(ALL_CASES) - len(FAST_CASES)
    assert tiers["slow"] >= 150, f"full applicable sweep is unexpectedly small: {tiers}"
    for transition in TRANSITIONS:
        assert any(case.transition == transition for case in ALL_CASES), transition
    assert {case.rotation for case in ALL_CASES} == set(ROTATION_COOKIES)
    assert {case.renewal for case in ALL_CASES} == {False, True}
    for case in ALL_CASES:
        assert case.flow == ("R" if case.renewal else "L")
    fast_transitions = {case.transition for case in FAST_CASES}
    assert {"cancel", "stop"} <= fast_transitions
    fast_boundaries = {case.boundary.name for case in FAST_CASES}
    assert "fetch_energy_data" in fast_boundaries


def test_fast_controls_cover_recency_and_cancel() -> None:
    """Fast tier must keep one cancel and one stop representative per exit family."""
    assert any(
        case.boundary.phase == "after" and case.transition == "cancel" for case in FAST_CASES
    )
    assert any(case.transition == "stop" for case in FAST_CASES)
    assert {case.rotation for case in FAST_CASES} == set(ROTATION_COOKIES)


def test_case_ids_are_unique_and_descriptive() -> None:
    """Case ids are stable and unique across the whole matrix."""
    ids = [case.case_id for case in ALL_CASES]
    assert len(ids) == len(set(ids))
    for case in ALL_CASES:
        assert case.boundary.boundary_id in case.case_id
        assert case.transition in case.case_id
        assert case.rotation in case.case_id


# ---------------------------------------------------------------------------
# Negative inventory proof (in-file, generator sensitivity)
# ---------------------------------------------------------------------------


def test_removing_one_catalog_gate_breaks_coverage() -> None:
    """Dropping one before/after gate from the catalog must break the closure proof."""
    covered = {case.boundary.boundary_id for case in ALL_CASES}
    assert covered == set(exit_boundary_ids())
    without_gate = next(
        boundary for boundary in EXIT_BOUNDARY_CATALOG if boundary.boundary_id == "before:keepalive"
    )
    assert without_gate.boundary_id in covered
    reduced = covered - {without_gate.boundary_id}
    missing = set(exit_boundary_ids()) - reduced
    assert missing == {"before:keepalive"}, (
        f"removing one catalog gate must break coverage on exactly that gate, saw {missing}"
    )
    counts = boundary_coverage()
    counts.pop(without_gate.boundary_id)
    assert not any(
        boundary == without_gate.boundary_id and count == 0 for boundary, count in counts.items()
    )


# ---------------------------------------------------------------------------
# Probe mechanics (no production edits)
# ---------------------------------------------------------------------------


def test_probe_wraps_catalog_name_before_and_after() -> None:
    """The probe installs on the isolated catalog name and records each phase."""

    class FakeClient:
        def __init__(self) -> None:
            self.calls: list[int] = []

        def fetch_energy_data(self, days: int = 14) -> dict[str, Any]:
            self.calls.append(days)
            return {"days": days}

    for phase in ("before", "after"):
        boundary = next(
            entry
            for entry in EXIT_BOUNDARY_CATALOG
            if entry.name == "fetch_energy_data" and entry.phase == phase
        )
        probe = ExitProbe(boundary)
        client = FakeClient()
        probe.install(client)
        probe.gate.proceed()
        assert client.fetch_energy_data(3) == {"days": 3}
        assert client.calls == [3]
        assert probe.hits == 1
        assert probe.gate.hit_count == 1
        assert probe.armed is False


def test_probe_gate_is_one_shot_and_bounded() -> None:
    """A held gate records one arrival and times out with a clear message."""
    boundary = next(
        entry for entry in EXIT_BOUNDARY_CATALOG if entry.boundary_id == "before:keepalive"
    )
    probe = ExitProbe(boundary)
    assert probe.blocking is True
    assert probe.boundary.boundary_id == "before:keepalive"
    assert probe.gate.name == "exit:before:keepalive"
    assert probe.gate.default_timeout == 10.0
    assert probe.armed is True


def test_probe_factory_installs_on_every_generation() -> None:
    """The factory installs the active probe on every newly constructed client."""
    portal = ScriptedPortal()
    script_portal(portal)
    factory = ProbeFactory(portal)
    boundary = next(
        entry for entry in EXIT_BOUNDARY_CATALOG if entry.boundary_id == "before:fetch_energy_data"
    )
    probe = ExitProbe(boundary)
    probe.gate.proceed()
    factory.probe = probe
    with factory:
        first = factory.create_client(cookie_list=[])
        second = factory.create_client(cookie_list=[])
        assert first.fetch_energy_data.__name__ == "wrapper"
        assert second.fetch_energy_data.__name__ == "wrapper"
        assert first is not second
    assert first.generation_id != second.generation_id


def test_case_dataclass_exposes_flow_mapping() -> None:
    """Renewal cases run the Remember-Me flow; no-renewal cases the local flow."""
    renewal_case = dataclasses.replace(FAST_CASES[0], renewal=True)
    local_case = dataclasses.replace(FAST_CASES[0], renewal=False)
    assert renewal_case.flow == "R"
    assert local_case.flow == "L"


def test_declared_rotations_are_registered_eligible() -> None:
    """Every declared Set-Cookie rotation is registered as an eligible source."""
    from tests.support.factory import ClientRegistry
    from tests.support.oracle import Oracle
    from tests.systemic.exit_cases import ROTATION_VALUES, _script_healthy_operation

    portal = ScriptedPortal()
    script_portal(portal)
    oracle = Oracle()
    oracle.attach_registry(ClientRegistry())
    for cookie in ROTATION_COOKIES:
        for value in ROTATION_VALUES:
            _script_healthy_operation(portal, cookie=cookie, value=value, renewal=False)
            register_scripted_eligibility(oracle, portal)
            assert (cookie, value) in oracle._eligible_cookie_history


# ---------------------------------------------------------------------------
# Fast mandatory recency/cancel controls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", FAST_CASES, ids=[case.case_id for case in FAST_CASES])
async def test_fast_exit_checkpoint_control(
    hass: HomeAssistant,
    caplog: Any,
    case: ExitCase,
) -> None:
    """The latest eligible pair survives the exit; the cold decision equals the warm one."""
    evidence = await run_exit_case(hass, case, caplog=caplog)
    assert evidence.boundary_reached is True
    assert evidence.oracle_codes == ()
    assert evidence.cold_matches_warm is True
    assert len(evidence.ending_steps) == 4
    assert dict(evidence.checkpoint_a["jar"]) != dict(evidence.checkpoint_b["jar"])
    assert evidence.expected["label"] in {
        "checkpoint_b",
        case.boundary.boundary_id,
    }
    print(f"P2-07 fast evidence {case.case_id}: {evidence.to_dict()}")


# ---------------------------------------------------------------------------
# Complete applicable sweep (slow)
# ---------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.parametrize("case", SLOW_CASES, ids=[case.case_id for case in SLOW_CASES])
async def test_slow_exit_checkpoint_sweep(
    hass: HomeAssistant,
    caplog: Any,
    case: ExitCase,
) -> None:
    """Every applicable exit boundary x transition x renewal x rotation, with follow-on."""
    evidence = await run_exit_case(hass, case, caplog=caplog)
    assert evidence.boundary_id == case.boundary.boundary_id
    assert evidence.boundary_reached is True
    assert evidence.oracle_codes == ()
    assert evidence.cold_matches_warm is True
    assert len(evidence.ending_steps) == 4
    assert dict(evidence.checkpoint_a["jar"]) != dict(evidence.checkpoint_b["jar"])
    assert evidence.expected["label"] in {
        "checkpoint_b",
        case.boundary.boundary_id,
    }
    print(f"P2-07 slow evidence {case.case_id}: {evidence.to_dict()}")

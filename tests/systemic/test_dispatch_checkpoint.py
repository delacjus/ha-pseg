"""Gate B counterexamples: independent G1 checkpoint and reachable setup.

Each test here pins one reviewer finding from the Gate B audit:

* B2 - I5 compares physical storage with an expectation declared *before* the
  fault from the case's declared replies and admission contract. A stale write
  seeded after the retirement transition must fail, and a response that only
  completes after retirement must never advance the checkpoint.
* B5 - every later setup boundary is reached and parked inside a real setup with
  ``SETUP_IN_PROGRESS`` and an active production renewal token, then retired with
  the same primitive the accepted pre-first-request case uses.

The module is fast: it reuses the fast fence cases and adds no slow matrix.
"""

from dataclasses import replace
from typing import Any

from homeassistant.core import HomeAssistant
import pytest
import requests

from custom_components.pseg.const import CONF_RENEWAL_ADMISSION
from tests.support import boundaries as bm
from tests.support.lifecycle import LifecycleDriver, Snapshot
from tests.support.portal import Gate, Reply
from tests.systemic.dispatch_cases import FAST_CASES, SLOW_CASES, boundary_for
from tests.systemic.findings import GATE_B_DISPATCH_FINDINGS


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock: Any, enable_custom_integrations: Any) -> Any:
    yield


@pytest.mark.parametrize("surface", ["cookies", "admission"])
async def test_stale_write_is_rejected_at_i5(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    request: pytest.FixtureRequest,
) -> None:
    """The live B2 seed fails I5 even though the parked reply declares valid cookies."""
    assert request.node.nodeid in GATE_B_DISPATCH_FINDINGS["B2"]["fast_cases"]
    original_prepare = bm.prepare_operation
    original_transition = bm.apply_transition
    evidence: dict[str, Any] = {}

    def prepare(portal: bm.FencePortal, operation: str) -> None:
        original_prepare(portal, operation)
        bm.replace_route(
            portal,
            ("GET", bm.PORTAL_BASE_URL + "/Dashboard"),
            Reply.ok(
                body=bm.DASHBOARD_HTML,
                cookies={"MM_AuxUtil": "SYNTH_GATEB_STALE"},
                reply_id="gateb-valid-cookie",
            ),
        )

    async def transition(driver: LifecycleDriver, which: str) -> bm.TransitionOutcome:
        oracle = next(o for o in driver._observers if isinstance(o, bm.Oracle))
        expected = oracle.expectation_state.latest_checkpoint
        assert dict(expected.admission) == {
            "sequences": 0,
            "last_sequence_at": None,
            "terminal_reason": None,
            "retry_eligible": False,
        }
        assert "MM_AuxUtil" not in expected.jar
        assert ("MM_AuxUtil", "SYNTH_GATEB_STALE") not in oracle._eligible_cookie_history
        evidence.update(driver=driver, oracle=oracle, expected=expected)
        outcome = await original_transition(driver, which)
        data = dict(driver.entry.data)
        if surface == "cookies":
            data["cookies"] = [
                *data["cookies"],
                {
                    "name": "MM_AuxUtil",
                    "value": "SYNTH_GATEB_STALE",
                    "domain": bm.PORTAL_HOST,
                    "path": "/",
                    "secure": True,
                },
            ]
        else:
            data[CONF_RENEWAL_ADMISSION] = {
                **data[CONF_RENEWAL_ADMISSION],
                "terminal_reason": "captcha_required",
            }
        driver.hass.config_entries.async_update_entry(driver.entry, data=data)
        return outcome

    monkeypatch.setattr(bm, "prepare_operation", prepare)
    monkeypatch.setattr(bm, "apply_transition", transition)
    case = next(c for c in FAST_CASES if c.case_id == "fast_first_poll_unload")
    try:
        with pytest.raises(AssertionError, match="I5 latest checkpoint at retirement"):
            await bm.run_fence_case(hass, case)
        assert evidence["expected"].jar == {"MM_SID": "SYNTH_LOCAL_SID"}
        assert ("MM_AuxUtil", "SYNTH_GATEB_STALE") not in evidence[
            "oracle"
        ]._eligible_cookie_history
    finally:
        if "driver" in evidence:
            await evidence["driver"].unload()


async def test_completed_rotation_is_the_independent_latest_checkpoint(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid daily proof before retirement must replace the initial whole jar."""
    original_prepare = bm.prepare_operation
    original_transition = bm.apply_transition
    captured: list[Any] = []

    def prepare(portal: bm.FencePortal, operation: str) -> None:
        original_prepare(portal, operation)
        bm.replace_route(
            portal,
            ("GET", bm.PORTAL_BASE_URL + "/Dashboard"),
            Reply.ok(
                body=bm.DASHBOARD_HTML,
                cookies={"MM_AuxUtil": "SYNTH_GATEB_LATEST"},
                reply_id="gateb-completed-cookie",
            ),
        )

    async def transition(driver: LifecycleDriver, which: str) -> bm.TransitionOutcome:
        oracle = next(o for o in driver._observers if isinstance(o, bm.Oracle))
        checkpoint = oracle.expectation_state.latest_checkpoint
        assert dict(checkpoint.jar) == {
            "MM_SID": "SYNTH_LOCAL_SID",
            "MM_AuxUtil": "SYNTH_GATEB_LATEST",
        }
        assert checkpoint.admission["sequences"] == 0
        captured.append(checkpoint)
        return await original_transition(driver, which)

    monkeypatch.setattr(bm, "prepare_operation", prepare)
    monkeypatch.setattr(bm, "apply_transition", transition)
    case = replace(
        next(c for c in FAST_CASES if c.case_id == "fast_first_poll_unload"),
        case_id="gateb-completed-rotation",
        boundary=boundary_for("L", "poll", 3),
    )
    result = await bm.run_fence_case(hass, case)
    assert captured and result.oracle_codes == ()
    assert len(result.ending_steps) == 4


async def test_retired_in_flight_reply_cannot_advance_the_checkpoint(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A response that only completes after retirement cannot advance the checkpoint.

    The reload's authorized successor consumes the healthy replies first. The
    parked old-owned send is then served a reply that declares a valid cookie
    while it is still inside the adapter, so it completes after retirement. The
    declared expectation must ignore that completion: if the model credited it,
    I5 would disagree with the unchanged physical store.
    """
    original_prepare = bm.prepare_operation
    original_transition = bm.apply_transition
    original_latest = bm._latest_checkpoint
    captured: list[Any] = []
    drivers: list[LifecycleDriver] = []
    portals: list[bm.FencePortal] = []

    def prepare(portal: bm.FencePortal, operation: str) -> None:
        original_prepare(portal, operation)
        portals.append(portal)

    async def transition(driver: LifecycleDriver, which: str) -> Any:
        outcome = await original_transition(driver, which)
        # The successor has finished its own requests; the queued stale reply can
        # now only be consumed by the parked send that already entered the adapter.
        bm.replace_route(
            portals[-1],
            ("GET", bm.PORTAL_BASE_URL + "/Dashboard"),
            [
                Reply.ok(
                    body=bm.DASHBOARD_HTML,
                    cookies={"MM_AuxUtil": "SYNTH_GB_RETIRED"},
                    reply_id="gateb-retired-cookie",
                ),
                Reply.ok(body=bm.DASHBOARD_HTML, reply_id="gateb-successor-clean"),
            ],
        )
        return outcome

    def latest(driver: LifecycleDriver, snapshot: Snapshot) -> Any:
        if driver not in drivers:
            drivers.append(driver)
        state = original_latest(driver, snapshot)
        captured.append(state)
        return state

    monkeypatch.setattr(bm, "prepare_operation", prepare)
    monkeypatch.setattr(bm, "apply_transition", transition)
    monkeypatch.setattr(bm, "_latest_checkpoint", latest)
    case = replace(
        next(c for c in FAST_CASES if c.case_id == "fast_first_poll_unload"),
        case_id="gateb-retired-in-flight",
        transition="reload",
    )
    result = await bm.run_fence_case(hass, case)
    assert result.oracle_codes == ()
    retired = [
        dispatch
        for dispatch in portals[-1].dispatches
        if dispatch.reply_id == "gateb-retired-cookie"
    ]
    assert retired, "the parked retired send never consumed its declared reply"
    assert retired[0].generation_id != result.successor_generation
    assert retired[0].outcome == "gateb-retired-cookie"
    oracle = next(observer for observer in drivers[-1]._observers if isinstance(observer, bm.Oracle))
    assert ("MM_AuxUtil", "SYNTH_GB_RETIRED") not in oracle._eligible_cookie_history
    assert captured, "the case never declared its latest checkpoint"
    expected_jar = dict(captured[-1].latest_checkpoint.jar)
    assert "MM_AuxUtil" not in expected_jar
    persisted = await drivers[-1].snapshot()
    persisted_jar = {
        str(cookie["name"]): str(cookie["value"]) for cookie in persisted.persisted_jar
    }
    assert "MM_AuxUtil" not in persisted_jar
    assert persisted_jar == expected_jar


def test_fence_oracle_keeps_quarantine_and_retirement_hooks() -> None:
    """Withholding eager eligibility must not hide I3 quarantine or retirement."""
    portal = bm.FencePortal()
    oracle = bm.Oracle()
    bm._attach_fence_oracle(portal, oracle)
    portal.script(
        ("GET", "/failed"),
        Reply(
            status_code=500,
            body=b"fault",
            cookies={"MM_AuxUtil": "SYNTH_QUARANTINE"},
            valid=False,
            cookie_eligible=False,
            reply_id="quarantine-invalid",
        ),
    )
    portal.script(("GET", "/eligible"), Reply.ok(body="ok", cookies={"MM_SID": "SYNTH_EAGER"}))
    portal.script(("GET", "/next"), Reply.ok(body="ok"))
    session = requests.Session()
    portal.mount_on(session, generation_id="quarantine-gen")
    try:
        session.get(f"{bm.PORTAL_BASE_URL}/failed")
        session.get(f"{bm.PORTAL_BASE_URL}/eligible")
        session.get(f"{bm.PORTAL_BASE_URL}/next", cookies={"MM_AuxUtil": "SYNTH_QUARANTINE"})
    finally:
        session.close()
    portal.retire("quarantine-gen")

    assert any(str(v.code) == "I3" for v in oracle.violations)
    assert ("MM_SID", "SYNTH_EAGER") not in oracle._eligible_cookie_history
    assert "quarantine-gen" in oracle._retired_generations


def test_each_setup_boundary_has_a_real_sweep_case() -> None:
    """No setup boundary borrows unreachability from a different parked case."""
    assert "setup" not in bm.EXCLUSIONS
    setup_pin = (
        "tests/systemic/test_dispatch_fence.py::"
        "test_fast_dispatch_fence_representative[fast_setup_chartdata_unload]"
    )
    assert setup_pin in GATE_B_DISPATCH_FINDINGS["B5"]["fast_cases"]
    assert setup_pin in {
        f"tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative"
        f"[{case.case_id}]"
        for case in FAST_CASES
    }
    for flow in bm.FLOWS:
        expected = {b.boundary_id for b in bm.generated_boundaries(flow)["setup"]}
        cases = [c for c in SLOW_CASES if c.flow == flow and c.operation == "setup"]
        assert {c.boundary.boundary_id for c in cases} == expected
        assert len(cases) == len(expected) == 5
        assert all(c.tier == "slow" for c in cases)
        # The sweep must reach later setup requests, not only the first.
        assert {c.boundary.leg for c in cases} == {1, 2}
    assert any(
        c.operation == "setup" and c.boundary.leg > 1 and c.boundary.path.endswith("/ChartData")
        for c in SLOW_CASES
    )
    assert any(c.operation == "setup" and c.boundary.leg == 1 for c in FAST_CASES)


@pytest.mark.parametrize("runner", ["fence", "pre_fence", "old_status"])
async def test_g1_gate_releases_and_drains_after_body_failure(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, runner: str
) -> None:
    """All G1 gate callers release and drain even when the parked body fails."""
    original_wait = Gate.wait_arrived
    original_proceed = Gate.proceed
    original_setup = LifecycleDriver.setup
    drivers: list[LifecycleDriver] = []
    released: list[Gate] = []
    parked: list[Gate] = []

    async def setup(driver: LifecycleDriver) -> bool:
        if driver not in drivers:
            drivers.append(driver)
        return await original_setup(driver)

    def wait(gate: Gate, timeout: float | None = None) -> None:
        original_wait(gate, timeout)
        parked.append(gate)
        raise ValueError("Gate B parked body fault")

    def proceed(gate: Gate) -> None:
        released.append(gate)
        original_proceed(gate)

    monkeypatch.setattr(LifecycleDriver, "setup", setup)
    monkeypatch.setattr(Gate, "wait_arrived", wait)
    monkeypatch.setattr(Gate, "proceed", proceed)
    try:
        with pytest.raises(ValueError, match="Gate B parked body fault"):
            if runner == "fence":
                await bm.run_fence_case(
                    hass, next(c for c in FAST_CASES if c.case_id == "fast_first_poll_unload")
                )
            elif runner == "pre_fence":
                await bm.run_pre_fence_case(hass)
            else:
                await bm.run_old_status_control(hass)
        assert len(parked) == 1 and parked[0] in released
        assert drivers
        assert all(d.outcome not in {"pending", "gated"} for d in drivers[0].portal.dispatches)
    finally:
        for driver in drivers:
            await driver.unload()

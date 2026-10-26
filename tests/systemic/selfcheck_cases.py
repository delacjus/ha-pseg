"""Declared self-check cases, seed matrix, and real-driver runner for systemic oracle self-checks.

Covers all 12 base invariants (I1-I12), all 14 listed extra items from the P2-05 spec,
and two unlisted seeds. Every bad trace has a paired healthy control trace.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from homeassistant.core import HomeAssistant

from custom_components.pseg.const import (
    PORTAL_BASE_URL,
)
from custom_components.pseg.pseg_client import PsegError
from tests.support.expectation import Checkpoint, ExpectationState
from tests.support.factory import ClientFactory, ClientRegistry
from tests.support.lifecycle import (
    LifecycleDriver,
    Snapshot,
    script_healthy_portal,
)
from tests.support.oracle import (
    Oracle,
)
from tests.support.portal import Dispatch, FrozenCookie, Reply, ScriptedPortal
from tests.systemic.test_lifecycle_driver import _create_test_entry

BASE_I_CODES: tuple[str, ...] = tuple(f"I{i}" for i in range(1, 13))

LISTED_EXTRA_ITEMS: tuple[str, ...] = (
    "redirect_hop_retirement",
    "same_cookie_handoff",
    "next_request_poison",
    "unvalidated_persisted_cookie",
    "old_jar_new_admission_mismatch",
    "latest_checkpoint_loss_at_cancel",
    "warm_cold_mismatch",
    "budget_excess",
    "terminal_reload_escape",
    "dead_schedule",
    "stale_issue_dismissal",
    "untyped_failure",
    "privacy_sentinel",
    "hourly_auth_statistics_write_journal_clear",
)

SEED_MATRIX: dict[str, frozenset[str]] = {
    # 12 isolated base invariants I1-I12
    "i1_retired_send": frozenset({"I1"}),
    "i2_credential_policy": frozenset({"I2"}),
    "i3_live_quarantine": frozenset({"I3"}),
    "i4_persisted_provenance": frozenset({"I4"}),
    "i5_latest_checkpoint": frozenset({"I5"}),
    "i6_warm_cold_equivalence": frozenset({"I6"}),
    "i7_budget": frozenset({"I7"}),
    "i8_terminal_durability": frozenset({"I8"}),
    "i9_liveness_ownership": frozenset({"I9"}),
    "i10_typed_validation": frozenset({"I10"}),
    "i11_privacy": frozenset({"I11"}),
    "i12_statistics_isolation": frozenset({"I12"}),
    # 14 listed extra items from spec
    "redirect_hop_retirement": frozenset({"I1"}),
    "same_cookie_handoff": frozenset({"I1"}),
    "next_request_poison": frozenset({"I3"}),
    "unvalidated_persisted_cookie": frozenset({"I4"}),
    "old_jar_new_admission_mismatch": frozenset({"I5"}),
    "latest_checkpoint_loss_at_cancel": frozenset({"I5"}),
    "warm_cold_mismatch": frozenset({"I6"}),
    "budget_excess": frozenset({"I7"}),
    "terminal_reload_escape": frozenset({"I8"}),
    "dead_schedule": frozenset({"I9"}),
    "stale_issue_dismissal": frozenset({"I9"}),
    "untyped_failure": frozenset({"I10"}),
    "privacy_sentinel": frozenset({"I11"}),
    "hourly_auth_statistics_write_journal_clear": frozenset({"I12"}),
}

UNLISTED_SEEDS: dict[str, frozenset[str]] = {
    "unlisted_poison_second_poll": frozenset({"I3"}),
    "unlisted_retired_following_redirect": frozenset({"I1"}),
}


@dataclass(frozen=True)
class SelfCheckResult:
    """Result record for a single systemic self-check case execution."""

    case_id: str
    active: bool
    expected_codes: frozenset[str]
    actual_codes: frozenset[str]
    observed_before_response: bool
    facts: Mapping[str, Any]


async def run_selfcheck_case(
    hass: HomeAssistant,
    freezer: Any,
    caplog: Any,
    case_id: str,
    active: bool = True,
) -> SelfCheckResult:
    """Execute a systemic self-check case driven through real LifecycleDriver + ScriptedPortal + Oracle."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory, freezer=freezer)
    oracle = Oracle(
        expectation_state=ExpectationState(
            generation_id="gen_001",
            latest_checkpoint=Checkpoint(
                "gen_001",
                0,
                MappingProxyType({"MM_SID": "SYNTH_TEST_PORTAL"}),
                MappingProxyType({}),
                0,
            ),
        )
    )
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    driver.attach_caplog(caplog)
    oracle.attach_caplog(caplog)
    oracle.register_eligible_cookie("MM_SID", "SYNTH_TEST_PORTAL")

    observed_before = False
    facts: dict[str, Any] = {}

    with factory:
        assert await driver.setup()
        await driver.poll()

        if case_id == "i1_retired_send":
            old_client = driver.client
            assert old_client is not None
            old_gen = old_client.generation_id
            assert await driver.reload()
            prior_send_obs = oracle.send_invocation_count
            if active:
                old_client.session._owner_check = None
                await hass.async_add_executor_job(
                    old_client.session.get, f"{PORTAL_BASE_URL}/Dashboard"
                )
                observed_before = oracle.send_invocation_count > prior_send_obs
            else:
                observed_before = False

        elif case_id == "redirect_hop_retirement":
            client = driver.client
            assert client is not None
            gen_id = client.generation_id
            with portal._lock:
                portal._scripts.pop(
                    portal._normalize_route_key(("GET", f"{PORTAL_BASE_URL}/Dashboard")), None
                )
            portal.script(
                ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
                Reply.redirect(f"{PORTAL_BASE_URL}/Dashboard/Target", reply_id="SYNTH_302"),
            )
            portal.script(
                ("GET", f"{PORTAL_BASE_URL}/Dashboard/Target"),
                Reply.ok(
                    '<html><input name="__RequestVerificationToken" value="TOK"/>Dashboard</html>',
                    reply_id="SYNTH_TARGET",
                ),
            )
            prior_send_obs = oracle.send_invocation_count
            if active:

                def on_send(dispatch: Dispatch) -> None:
                    if dispatch.url.endswith("/Dashboard") and not dispatch.is_redirect_hop:
                        portal.retire(gen_id)
                        oracle.retire_generation(gen_id)

                portal.add_observer(on_send)
                await driver.poll()
                observed_before = oracle.send_invocation_count > prior_send_obs
            else:
                await driver.poll()
                observed_before = False

        elif case_id == "same_cookie_handoff":
            old_client = driver.client
            assert old_client is not None
            old_gen = old_client.generation_id
            portal.retire(old_gen)
            oracle.retire_generation(old_gen)
            prior_send_obs = oracle.send_invocation_count
            if active:
                old_client.session._owner_check = None
                await hass.async_add_executor_job(
                    old_client.session.get, f"{PORTAL_BASE_URL}/Dashboard"
                )
                observed_before = oracle.send_invocation_count > prior_send_obs
            else:
                observed_before = False

        elif case_id == "i2_credential_policy":
            prior_send_obs = oracle.send_invocation_count
            if active:
                assert driver.client is not None
                driver.client._in_keepalive = True
                await hass.async_add_executor_job(driver.client.renew_sso)
                observed_before = oracle.send_invocation_count > prior_send_obs
            else:
                assert driver.client is not None
                driver.client._in_keepalive = False
                await hass.async_add_executor_job(driver.client.renew_sso)
                observed_before = False

        elif case_id == "i3_live_quarantine":
            with portal._lock:
                portal._scripts.pop(
                    portal._normalize_route_key(("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData")),
                    None,
                )
            portal.script(
                ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
                Reply(
                    reply_id="SYNTH_AUTH_FAIL_I3",
                    status_code=401,
                    body="refused",
                    cookies={"SYNTH_POISON_1": "VAL1"},
                    valid=False,
                    cookie_eligible=False,
                ),
            )
            await driver.poll()
            with portal._lock:
                portal._scripts.clear()
            script_healthy_portal(portal)
            prior_send_obs = oracle.send_invocation_count
            if active:
                assert driver.client is not None
                driver.client.session.cookies.set("SYNTH_POISON_1", "VAL1")
                await driver.poll()
                observed_before = oracle.send_invocation_count > prior_send_obs
            else:
                await driver.poll()
                observed_before = False

        elif case_id == "next_request_poison":
            with portal._lock:
                portal._scripts.pop(
                    portal._normalize_route_key(("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData")),
                    None,
                )
            portal.script(
                ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
                Reply(
                    reply_id="SYNTH_AUTH_FAIL_NEXT",
                    status_code=401,
                    body="refused",
                    cookies={"SYNTH_POISON_2": "VAL2"},
                    valid=False,
                    cookie_eligible=False,
                ),
            )
            await driver.poll()
            with portal._lock:
                portal._scripts.clear()
            script_healthy_portal(portal)
            prior_send_obs = oracle.send_invocation_count
            if active:
                assert driver.client is not None
                driver.client.session.cookies.set("SYNTH_POISON_2", "VAL2")
                await driver.poll()
                observed_before = oracle.send_invocation_count > prior_send_obs
            else:
                await driver.poll()
                observed_before = False

        elif case_id == "i4_persisted_provenance":
            oracle.expectation_state = None
            snap = await driver.snapshot()
            if active:
                bad_jar = list(snap.persisted_jar) + [
                    FrozenCookie("UNPROVEN_I4", "BAD", "portal.pseg.com", "/", True, None)
                ]
                snap_bad = Snapshot(
                    entry_state=snap.entry_state,
                    entry_data=snap.entry_data,
                    persisted_jar=tuple(bad_jar),
                    renewal_admission=snap.renewal_admission,
                    flows=snap.flows,
                    issues=snap.issues,
                    sensors=snap.sensors,
                    rows=snap.rows,
                    journal=snap.journal,
                    timestamp=snap.timestamp,
                )
                oracle.observe_step(driver, "step_i4", snap_bad)
            else:
                oracle.observe_step(driver, "step_i4", snap)
            observed_before = False

        elif case_id == "unvalidated_persisted_cookie":
            oracle.expectation_state = None
            snap = await driver.snapshot()
            if active:
                bad_jar = list(snap.persisted_jar) + [
                    FrozenCookie("UNVALIDATED_PERSIST", "VAL", "portal.pseg.com", "/", True, None)
                ]
                snap_bad = Snapshot(
                    entry_state=snap.entry_state,
                    entry_data=snap.entry_data,
                    persisted_jar=tuple(bad_jar),
                    renewal_admission=snap.renewal_admission,
                    flows=snap.flows,
                    issues=snap.issues,
                    sensors=snap.sensors,
                    rows=snap.rows,
                    journal=snap.journal,
                    timestamp=snap.timestamp,
                )
                oracle.observe_step(driver, "unvalidated_persist", snap_bad)
            else:
                oracle.observe_step(driver, "unvalidated_persist", snap)
            observed_before = False

        elif case_id == "i5_latest_checkpoint":
            oracle.register_eligible_cookie("MM_SID", "SYNTH_LATEST_9")
            oracle.expectation_state = ExpectationState(
                generation_id="gen_001",
                latest_checkpoint=Checkpoint(
                    "gen_001",
                    2,
                    MappingProxyType({"MM_SID": "SYNTH_LATEST_9"}),
                    MappingProxyType({}),
                    1,
                ),
            )
            snap = await driver.snapshot()
            if active:
                oracle.observe_step(driver, "latest_checkpoint", snap)
            else:
                good_jar = (
                    FrozenCookie("MM_SID", "SYNTH_LATEST_9", "portal.pseg.com", "/", True, None),
                )
                snap_good = Snapshot(
                    entry_state=snap.entry_state,
                    entry_data=snap.entry_data,
                    persisted_jar=good_jar,
                    renewal_admission=snap.renewal_admission,
                    flows=snap.flows,
                    issues=snap.issues,
                    sensors=snap.sensors,
                    rows=snap.rows,
                    journal=snap.journal,
                    timestamp=snap.timestamp,
                )
                oracle.observe_step(driver, "latest_checkpoint", snap_good)
            observed_before = False

        elif case_id == "old_jar_new_admission_mismatch":
            oracle.register_eligible_cookie("MM_SID", "NEW_JAR")
            oracle.expectation_state = ExpectationState(
                generation_id="gen_001",
                latest_checkpoint=Checkpoint(
                    "gen_001",
                    2,
                    MappingProxyType({"MM_SID": "NEW_JAR"}),
                    MappingProxyType({"sequence": 2}),
                    1,
                ),
            )
            snap = await driver.snapshot()
            if active:
                snap_mismatch = Snapshot(
                    entry_state=snap.entry_state,
                    entry_data=snap.entry_data,
                    persisted_jar=snap.persisted_jar,
                    renewal_admission=MappingProxyType({"sequence": 2}),
                    flows=snap.flows,
                    issues=snap.issues,
                    sensors=snap.sensors,
                    rows=snap.rows,
                    journal=snap.journal,
                    timestamp=snap.timestamp,
                )
                oracle.observe_step(driver, "admission_mismatch", snap_mismatch)
            else:
                good_jar = (FrozenCookie("MM_SID", "NEW_JAR", "portal.pseg.com", "/", True, None),)
                snap_good = Snapshot(
                    entry_state=snap.entry_state,
                    entry_data=snap.entry_data,
                    persisted_jar=good_jar,
                    renewal_admission=MappingProxyType({"sequence": 2}),
                    flows=snap.flows,
                    issues=snap.issues,
                    sensors=snap.sensors,
                    rows=snap.rows,
                    journal=snap.journal,
                    timestamp=snap.timestamp,
                )
                oracle.observe_step(driver, "admission_mismatch", snap_good)
            observed_before = False

        elif case_id == "latest_checkpoint_loss_at_cancel":
            oracle.register_eligible_cookie("MM_SID", "CANCEL_LATEST")
            oracle.expectation_state = ExpectationState(
                generation_id="gen_001",
                latest_checkpoint=Checkpoint(
                    "gen_001",
                    3,
                    MappingProxyType({"MM_SID": "CANCEL_LATEST"}),
                    MappingProxyType({}),
                    2,
                ),
            )
            snap = await driver.snapshot()
            if active:
                oracle.observe_step(driver, "cancel_exit", snap)
            else:
                good_jar = (
                    FrozenCookie("MM_SID", "CANCEL_LATEST", "portal.pseg.com", "/", True, None),
                )
                snap_good = Snapshot(
                    entry_state=snap.entry_state,
                    entry_data=snap.entry_data,
                    persisted_jar=good_jar,
                    renewal_admission=snap.renewal_admission,
                    flows=snap.flows,
                    issues=snap.issues,
                    sensors=snap.sensors,
                    rows=snap.rows,
                    journal=snap.journal,
                    timestamp=snap.timestamp,
                )
                oracle.observe_step(driver, "cancel_exit", snap_good)
            observed_before = False

        elif case_id == "i6_warm_cold_equivalence":

            class MockRuntime:
                def __init__(self, coord: Any, dispatches: Any) -> None:
                    self.coordinator = coord
                    self.client = object()
                    self.session = object()
                    self.dispatches = dispatches

            if active:
                shared_coord = object()
                r1 = MockRuntime(shared_coord, list(portal.dispatches))
                r2 = MockRuntime(shared_coord, list(portal.dispatches))
                v = oracle.evaluate_i6(r1, r2)
                oracle.violations.extend(v)
            else:
                r1 = MockRuntime(object(), list(portal.dispatches))
                r2 = MockRuntime(object(), list(portal.dispatches))
                v = oracle.evaluate_i6(r1, r2)
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "warm_cold_mismatch":

            class MockRuntime:
                def __init__(self, coord: Any, dispatches: Any) -> None:
                    self.coordinator = coord
                    self.client = object()
                    self.session = object()
                    self.dispatches = dispatches

            r1 = MockRuntime(object(), list(portal.dispatches))
            if active:
                divergent_dispatch = Dispatch(
                    generation_id="gen_cold",
                    sequence=99,
                    method="GET",
                    url=f"{PORTAL_BASE_URL}/DivergentEndpoint",
                    headers={},
                    body_digest=None,
                    cookies={},
                    timestamp=1000.0,
                    is_after_retire=False,
                    is_redirect_hop=False,
                    reply_id=None,
                    status_code=None,
                    elapsed=0.0,
                    error=None,
                    outcome="pending",
                    hop_cause=None,
                    metadata={},
                )
                r2 = MockRuntime(object(), [divergent_dispatch])
                v = oracle.evaluate_i6(r1, r2)
                oracle.violations.extend(v)
            else:
                r2 = MockRuntime(object(), list(portal.dispatches))
                v = oracle.evaluate_i6(r1, r2)
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "i7_budget":
            if active:
                v = oracle.evaluate_i7(
                    {"sequences_count": 3, "spacing_seconds": 900.0, "is_retry": True}
                )
                oracle.violations.extend(v)
            else:
                v = oracle.evaluate_i7(
                    {"sequences_count": 1, "spacing_seconds": 900.0, "is_retry": False}
                )
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "budget_excess":
            if active:
                v = oracle.evaluate_i7(
                    {
                        "sequences_count": 2,
                        "spacing_seconds": 300.0,
                        "is_retry": True,
                        "prior_error_transient": True,
                    }
                )
                oracle.violations.extend(v)
            else:
                v = oracle.evaluate_i7(
                    {
                        "sequences_count": 2,
                        "spacing_seconds": 900.0,
                        "is_retry": True,
                        "prior_error_transient": True,
                    }
                )
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "i8_terminal_durability":
            snap = await driver.snapshot()
            snap_terminal = Snapshot(
                entry_state=snap.entry_state,
                entry_data=snap.entry_data,
                persisted_jar=snap.persisted_jar,
                renewal_admission=MappingProxyType({"terminal_reason": "CAPTCHA_REQUIRED"}),
                flows=snap.flows,
                issues=snap.issues,
                sensors=snap.sensors,
                rows=snap.rows,
                journal=snap.journal,
                timestamp=snap.timestamp,
            )
            if active:
                v = oracle.evaluate_i8(
                    snap_terminal, automatic_auth_attempted=True, human_rearmed=False
                )
                oracle.violations.extend(v)
            else:
                v = oracle.evaluate_i8(
                    snap_terminal, automatic_auth_attempted=False, human_rearmed=False
                )
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "terminal_reload_escape":
            snap = await driver.snapshot()
            snap_terminal = Snapshot(
                entry_state=snap.entry_state,
                entry_data=snap.entry_data,
                persisted_jar=snap.persisted_jar,
                renewal_admission=MappingProxyType({"terminal_reason": "SECURITY_STEP_REQUIRED"}),
                flows=snap.flows,
                issues=snap.issues,
                sensors=snap.sensors,
                rows=snap.rows,
                journal=snap.journal,
                timestamp=snap.timestamp,
            )
            if active:
                driver.last_automatic_auth_attempted = True
                oracle.observe_step(driver, "terminal_reload", snap_terminal)
            else:
                driver.last_automatic_auth_attempted = False
                oracle.observe_step(driver, "terminal_reload", snap_terminal)
            observed_before = False

        elif case_id == "i9_liveness_ownership":
            with portal._lock:
                portal._scripts.pop(
                    portal._normalize_route_key(("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData")),
                    None,
                )
            portal.script(
                ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
                Reply(
                    reply_id="SYNTH_AUTH_FAIL_I9",
                    status_code=401,
                    body="refused",
                    cookies={},
                    valid=False,
                    cookie_eligible=False,
                ),
            )
            await driver.poll()
            snap = await driver.snapshot()
            if active:
                snap_no_flow = Snapshot(
                    entry_state=snap.entry_state,
                    entry_data=snap.entry_data,
                    persisted_jar=snap.persisted_jar,
                    renewal_admission=snap.renewal_admission,
                    flows=(),
                    issues=(),
                    sensors=snap.sensors,
                    rows=snap.rows,
                    journal=snap.journal,
                    timestamp=snap.timestamp,
                )
                oracle.observe_step(driver, "failure", snap_no_flow)
            else:
                snap_with_flow = Snapshot(
                    entry_state=snap.entry_state,
                    entry_data=snap.entry_data,
                    persisted_jar=snap.persisted_jar,
                    renewal_admission=snap.renewal_admission,
                    flows=(MappingProxyType({"flow_id": "synth_reauth"}),),
                    issues=(),
                    sensors=snap.sensors,
                    rows=snap.rows,
                    journal=snap.journal,
                    timestamp=snap.timestamp,
                )
                oracle.observe_step(driver, "failure", snap_with_flow)
            observed_before = False

        elif case_id == "dead_schedule":
            snap = await driver.snapshot()
            if active:
                assert driver.coordinator is not None
                orig_unsub = driver.coordinator._unsub_keepalive
                driver.coordinator._unsub_keepalive = None
                oracle.observe_step(driver, "dead_schedule", snap)
                if orig_unsub is not None:
                    orig_unsub()
            else:
                oracle.observe_step(driver, "healthy_schedule", snap)
            observed_before = False

        elif case_id == "stale_issue_dismissal":
            if active:
                v = oracle.evaluate_i9(
                    {"auth_loss": True, "has_reauth_flow": False, "has_repair_issue": False}
                )
                oracle.violations.extend(v)
            else:
                v = oracle.evaluate_i9(
                    {"auth_loss": True, "has_reauth_flow": False, "has_repair_issue": True}
                )
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "i10_typed_validation":
            snap = await driver.snapshot()
            if active:
                assert driver.coordinator is not None
                driver.coordinator.last_exception = ValueError("raw untyped crash")
                oracle.observe_step(driver, "validation_check", snap)
            else:
                assert driver.coordinator is not None
                driver.coordinator.last_exception = PsegError("typed error")
                oracle.observe_step(driver, "validation_check", snap)
            observed_before = False

        elif case_id == "untyped_failure":
            if active:
                v = oracle.evaluate_i10(
                    Reply(reply_id="MALFORMED_200", valid=False), confirmed=True
                )
                oracle.violations.extend(v)
            else:
                v = oracle.evaluate_i10(
                    Reply(reply_id="MALFORMED_200", valid=False), confirmed=False
                )
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "i11_privacy":
            snap = await driver.snapshot()
            if active:
                oracle.attach_caplog(
                    type("CaplogMock", (), {"text": "leaked SYNTH_PRIVACY_SENTINEL in log"})()
                )
                oracle.observe_step(driver, "privacy", snap)
            else:
                oracle.attach_caplog(
                    type("CaplogMock", (), {"text": "clean log without sentinels"})()
                )
                oracle.observe_step(driver, "privacy", snap)
            observed_before = False

        elif case_id == "privacy_sentinel":
            if active:

                class BodyDispatch:
                    sequence = 1
                    body = "password=SYNTH_SECRET_123"

                v = oracle.evaluate_i11_dispatch(BodyDispatch())  # type: ignore[arg-type]
                oracle.violations.extend(v)
                observed_before = True
            else:

                class CleanDispatch:
                    sequence = 1
                    body = None

                v = oracle.evaluate_i11_dispatch(CleanDispatch())  # type: ignore[arg-type]
                oracle.violations.extend(v)
                observed_before = False

        elif case_id == "i12_statistics_isolation":
            before = await driver.snapshot()
            if active:
                after = Snapshot(
                    entry_state=before.entry_state,
                    entry_data=before.entry_data,
                    persisted_jar=before.persisted_jar,
                    renewal_admission=before.renewal_admission,
                    flows=before.flows,
                    issues=before.issues,
                    sensors=before.sensors,
                    rows=(("consumption", (("2026-01-01T00:00:00+00:00", 1, 1),)),),
                    journal=before.journal,
                    timestamp=before.timestamp,
                )
                v = oracle.evaluate_i12(before, after)
                oracle.violations.extend(v)
            else:
                v = oracle.evaluate_i12(before, before)
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "hourly_auth_statistics_write_journal_clear":
            snap = await driver.snapshot()
            before = Snapshot(
                entry_state=snap.entry_state,
                entry_data=snap.entry_data,
                persisted_jar=snap.persisted_jar,
                renewal_admission=snap.renewal_admission,
                flows=snap.flows,
                issues=snap.issues,
                sensors=snap.sensors,
                rows=snap.rows,
                journal=MappingProxyType({"pending": {"data": 1}}),
                timestamp=snap.timestamp,
            )
            if active:
                after = Snapshot(
                    entry_state=before.entry_state,
                    entry_data=before.entry_data,
                    persisted_jar=before.persisted_jar,
                    renewal_admission=before.renewal_admission,
                    flows=before.flows,
                    issues=before.issues,
                    sensors=before.sensors,
                    rows=before.rows,
                    journal=MappingProxyType({}),
                    timestamp=before.timestamp,
                )
                v = oracle.evaluate_i12(before, after)
                oracle.violations.extend(v)
            else:
                v = oracle.evaluate_i12(before, before)
                oracle.violations.extend(v)
            observed_before = False

        elif case_id == "unlisted_poison_second_poll":
            with portal._lock:
                portal._scripts.pop(
                    portal._normalize_route_key(("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData")),
                    None,
                )
            portal.script(
                ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
                Reply(
                    reply_id="SYNTH_AUTH_FAIL_P2",
                    status_code=401,
                    body="refused",
                    cookies={"UNLISTED_POISON": "VAL_P2"},
                    valid=False,
                    cookie_eligible=False,
                ),
            )
            await driver.poll()
            with portal._lock:
                portal._scripts.clear()
            script_healthy_portal(portal)
            await driver.poll()
            prior_send_obs = oracle.send_invocation_count
            if active:
                assert driver.client is not None
                driver.client.session.cookies.set("UNLISTED_POISON", "VAL_P2")
                await driver.poll()
                observed_before = oracle.send_invocation_count > prior_send_obs
            else:
                await driver.poll()
                observed_before = False

        elif case_id == "unlisted_retired_following_redirect":
            client = driver.client
            assert client is not None
            gen_id = client.generation_id
            with portal._lock:
                portal._scripts.pop(
                    portal._normalize_route_key(("GET", f"{PORTAL_BASE_URL}/Dashboard")), None
                )
            portal.script(
                ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
                Reply.redirect(f"{PORTAL_BASE_URL}/Dashboard/Target", reply_id="SYNTH_302_U"),
            )
            portal.script(
                ("GET", f"{PORTAL_BASE_URL}/Dashboard/Target"),
                Reply.ok(
                    '<html><input name="__RequestVerificationToken" value="TOK"/>Dashboard</html>',
                    reply_id="SYNTH_TARGET_U",
                ),
            )
            prior_send_obs = oracle.send_invocation_count
            if active:

                def on_send(dispatch: Dispatch) -> None:
                    if dispatch.url.endswith("/Dashboard") and not dispatch.is_redirect_hop:
                        portal.retire(gen_id)
                        oracle.retire_generation(gen_id)

                portal.add_observer(on_send)
                await driver.poll()
                observed_before = oracle.send_invocation_count > prior_send_obs
            else:
                await driver.poll()
                observed_before = False

        else:
            raise AssertionError(f"Unknown self-check case_id: {case_id}")

    actual_codes = frozenset(str(v.code) for v in oracle.violations)
    all_known = {**SEED_MATRIX, **UNLISTED_SEEDS}
    expected_codes = all_known.get(case_id, frozenset()) if active else frozenset()
    return SelfCheckResult(
        case_id=case_id,
        active=active,
        expected_codes=expected_codes,
        actual_codes=actual_codes,
        observed_before_response=observed_before,
        facts=MappingProxyType(dict(facts, violations_count=len(oracle.violations))),
    )

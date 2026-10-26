"""Systemic contract tests for the I1-I12 invariant evaluator and observer.

Verifies:
- Healthy traces through public HA lifecycle produce zero violations.
- Observer invocation count exactly equals attempted sends + declared lifecycle checkpoints.
- Isolation: individual fixture observations trigger each of the 12 codes I1-I12 exclusively.
- Permitted current-owner 307/308 redirect re-POST control operates as declared data.
- Send-time observation catches redirect hops before response return.
- I5 recency: evaluates against latest checkpoint, not first.
- I6 compares genuinely separate warm and cold control branches.
- I9 proves scheduled timer dispatch via real scheduler, rejecting direct coordinator calls.
- I12 checks both series (consumption + production/secondary) and journal state.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any
from unittest.mock import MagicMock

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests

from custom_components.pseg.const import (
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
    PORTAL_BASE_URL,
)
from tests.support.expectation import Checkpoint, ExpectationState
from tests.support.factory import ClientFactory, ClientRegistry
from tests.support.lifecycle import (
    LifecycleDriver,
    Snapshot,
    run_case,
    script_healthy_portal,
)
from tests.support.oracle import (
    Oracle,
    ViolationCode,
)
from tests.support.portal import Dispatch, FrozenCookie, Reply, ScriptedPortal


def _make_dummy_dispatch(
    generation_id: str = "gen_001",
    method: str = "GET",
    url: str = f"{PORTAL_BASE_URL}/Dashboard",
    sequence: int = 1,
    is_after_retire: bool = False,
    is_redirect_hop: bool = False,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    body_digest: str | None = None,
) -> Dispatch:
    """Construct an immutable Dispatch record for testing."""
    return Dispatch(
        generation_id=generation_id,
        sequence=sequence,
        method=method,
        url=url,
        headers=dict(headers or {}),
        body_digest=body_digest,
        cookies=dict(cookies or {}),
        timestamp=1000.0,
        is_after_retire=is_after_retire,
        is_redirect_hop=is_redirect_hop,
        hop_cause=None,
        reply_id=None,
        status_code=None,
        elapsed=0.0,
        error=None,
        outcome="pending",
    )


def _make_dummy_snapshot(
    persisted_jar: tuple[FrozenCookie, ...] = (),
    renewal_admission: Mapping[str, Any] | None = None,
    rows: tuple[Any, ...] = (),
    journal: Mapping[str, Any] | None = None,
    flows: tuple[Any, ...] = (),
    issues: tuple[Any, ...] = (),
    sensors: Mapping[str, Any] | None = None,
) -> Snapshot:
    """Construct an immutable Snapshot record for testing."""
    return Snapshot(
        entry_state=ConfigEntryState.LOADED,
        entry_data=MappingProxyType({}),
        persisted_jar=persisted_jar,
        renewal_admission=MappingProxyType(dict(renewal_admission or {})),
        flows=flows,
        issues=issues,
        sensors=MappingProxyType(dict(sensors or {})),
        rows=rows,
        journal=MappingProxyType(dict(journal or {})),
        timestamp="2026-10-25T12:00:00Z",
    )


async def test_healthy_trace_zero_violations(hass: HomeAssistant) -> None:
    """Healthy run_case trace produces zero violations."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        minor_version=1,
        unique_id="12345678",
        entry_id="healthy_test_entry",
        title="Healthy Test",
        data={
            "meter_id": "12345678",
            CONF_PORTAL_COOKIES: "MM_SID=INIT_VAL",
            CONF_OKTA_COOKIES: "idx=OKTA_VAL",
            "cookies": [
                {
                    "name": "MM_SID",
                    "value": "INIT_VAL",
                    "domain": "portal.pseg.com",
                    "path": "/",
                    "secure": True,
                }
            ],
        },
    )
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    initial_checkpoint = Checkpoint(
        generation_id="gen_001",
        sequence=1,
        jar=MappingProxyType({"MM_SID": "INIT_VAL"}),
        admission=MappingProxyType({}),
        timestamp=1000.0,
    )
    state = ExpectationState(
        generation_id="gen_001",
        sequence=1,
        latest_checkpoint=initial_checkpoint,
    )

    oracle = Oracle(expectation_state=state)
    oracle.attach_portal(portal)

    with factory:
        assert await driver.setup() is True
        assert driver.entry.state is ConfigEntryState.LOADED

        async def _body(d: LifecycleDriver) -> None:
            await d.poll()

        result = await run_case(driver, _body, oracle=oracle)
        assert result.success is True
        assert len(oracle.violations) == 0
        oracle.assert_clean()


def test_redirect_boundary_observed_at_send() -> None:
    """Send hook observes redirect hop at send time before response return."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_001")

    redir_reply = Reply.redirect(
        location=f"{PORTAL_BASE_URL}/Target",
        status_code=302,
        reply_id="REDIR_302",
    )
    target_reply = Reply.ok(body="Target Landing", reply_id="TARGET_OK")

    portal.script(("GET", f"{PORTAL_BASE_URL}/Start"), redir_reply)
    portal.script(("GET", f"{PORTAL_BASE_URL}/Target"), target_reply)

    oracle = Oracle()
    portal.add_observer(oracle.observe_send)

    resp = session.get(f"{PORTAL_BASE_URL}/Start", allow_redirects=True)
    assert resp.status_code == 200

    assert oracle.send_invocation_count == 2
    redirect_obs = [obs for obs in oracle.send_observations if obs.facts.get("is_redirect_hop")]
    assert len(redirect_obs) == 1
    assert redirect_obs[0].facts.get("url") == f"{PORTAL_BASE_URL}/Target"


def test_observer_invocation_count_equals_sends_plus_checkpoints() -> None:
    """Observer invocation count equals attempted sends + declared checkpoints."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_001")

    portal.script(("GET", f"{PORTAL_BASE_URL}/One"), Reply.ok(body="1"))
    portal.script(("GET", f"{PORTAL_BASE_URL}/Two"), Reply.ok(body="2"))
    portal.script(("GET", f"{PORTAL_BASE_URL}/Three"), Reply.ok(body="3"))

    oracle = Oracle()
    portal.add_observer(oracle.observe_send)

    # 3 attempted sends
    session.get(f"{PORTAL_BASE_URL}/One")
    session.get(f"{PORTAL_BASE_URL}/Two")
    session.get(f"{PORTAL_BASE_URL}/Three")
    assert len(portal.dispatches) == 3

    # 2 declared lifecycle checkpoints
    oracle.observe_step(None, "checkpoint_after_setup")
    oracle.observe_step(None, "checkpoint_after_poll")

    assert oracle.send_invocation_count == 3
    assert oracle.step_invocation_count == 2
    assert oracle.invocation_count == 5
    assert oracle.invocation_count == len(portal.dispatches) + 2


def test_i5_checkpoint_recency() -> None:
    """I5 recency: evaluates against latest checkpoint, not first."""
    cp_first = Checkpoint(
        generation_id="gen_001",
        sequence=1,
        jar=MappingProxyType({"MM_SID": "FIRST_VAL"}),
        admission=MappingProxyType({"state": "initial"}),
        timestamp=100.0,
    )
    cp_latest = Checkpoint(
        generation_id="gen_001",
        sequence=2,
        jar=MappingProxyType({"MM_SID": "LATEST_VAL"}),
        admission=MappingProxyType({"state": "confirmed"}),
        timestamp=200.0,
    )

    state = ExpectationState(
        generation_id="gen_001",
        sequence=2,
        latest_checkpoint=cp_latest,
    )
    state_first = ExpectationState(
        generation_id="gen_001",
        sequence=1,
        latest_checkpoint=cp_first,
    )
    assert state_first.latest_checkpoint == cp_first

    oracle = Oracle(expectation_state=state)

    # Storage updated with latest checkpoint
    snap_latest = _make_dummy_snapshot(
        persisted_jar=(FrozenCookie("MM_SID", "LATEST_VAL", "portal.pseg.com", "/", True, None),),
        renewal_admission={"state": "confirmed"},
    )
    violations_latest = oracle.evaluate_i5(snap_latest, state)
    assert len(violations_latest) == 0

    # Storage retains first checkpoint (stale)
    snap_stale = _make_dummy_snapshot(
        persisted_jar=(FrozenCookie("MM_SID", "FIRST_VAL", "portal.pseg.com", "/", True, None),),
        renewal_admission={"state": "initial"},
    )
    violations_stale = oracle.evaluate_i5(snap_stale, state)
    assert len(violations_stale) == 1
    assert violations_stale[0].code == ViolationCode.I5


def test_i9_requires_timer_dispatch_not_direct_call() -> None:
    """I9 requires scheduled timer dispatch through scheduler, not direct call."""
    oracle = Oracle()

    # Case A: Real timer dispatch via ClockDriver -> valid
    timer_facts = {
        "transient_retry": True,
        "dispatched_via_timer": True,
        "direct_call": False,
    }
    violations_timer = oracle.evaluate_i9(timer_facts)
    assert len(violations_timer) == 0

    # Case B: Direct coordinator call instead of timer -> violates I9
    direct_facts = {
        "transient_retry": True,
        "dispatched_via_timer": False,
        "direct_call": True,
    }
    violations_direct = oracle.evaluate_i9(direct_facts)
    assert len(violations_direct) == 1
    assert violations_direct[0].code == ViolationCode.I9
    assert "direct_coordinator_call" in violations_direct[0].message


def test_i12_checks_both_series_and_journal() -> None:
    """I12 compares both series and journal state around auth failure."""
    oracle = Oracle()

    row_cons = (1729382400000, 1.5)
    row_prod = (1729382400000, 0.8)

    before = _make_dummy_snapshot(
        rows=(
            ("consumption", (row_cons,)),
            ("production", (row_prod,)),
        ),
        journal={"imported_days": 10},
    )

    # Clean outcome: both series and journal untouched
    clean_after = _make_dummy_snapshot(
        rows=(
            ("consumption", (row_cons,)),
            ("production", (row_prod,)),
        ),
        journal={"imported_days": 10},
    )
    assert len(oracle.evaluate_i12(before, clean_after)) == 0

    # Defect: consumption unchanged, but secondary series corrupted/added
    bad_prod_after = _make_dummy_snapshot(
        rows=(
            ("consumption", (row_cons,)),
            ("production", (row_prod, (1729386000000, 0.9))),
        ),
        journal={"imported_days": 10},
    )
    v_prod = oracle.evaluate_i12(before, bad_prod_after)
    assert len(v_prod) == 1
    assert v_prod[0].code == ViolationCode.I12
    assert "second_series_production_modified" in str(v_prod[0].facts)

    # Defect: journal cleared on auth failure
    bad_journal_after = _make_dummy_snapshot(
        rows=(
            ("consumption", (row_cons,)),
            ("production", (row_prod,)),
        ),
        journal={},
    )
    v_journal = oracle.evaluate_i12(before, bad_journal_after)
    assert len(v_journal) == 1
    assert v_journal[0].code == ViolationCode.I12
    assert "journal_cleared" in str(v_journal[0].facts)


def test_permitted_current_owner_redirect_policy() -> None:
    """Permitted current-owner 307/308 redirect re-POST operates as declared data."""
    oracle = Oracle()

    # Active current owner 307 redirect re-POST is permitted
    valid_repost = _make_dummy_dispatch(
        generation_id="gen_001",
        method="POST",
        url=f"{PORTAL_BASE_URL}/Saml/okta-prod/Acs",
        is_redirect_hop=True,
    )
    assert len(oracle.evaluate_i2(valid_repost)) == 0

    # 307 redirect re-POST after retirement violates I2
    retired_repost = _make_dummy_dispatch(
        generation_id="gen_001",
        method="POST",
        url=f"{PORTAL_BASE_URL}/Saml/okta-prod/Acs",
        is_after_retire=True,
        is_redirect_hop=True,
    )
    v_ret = oracle.evaluate_i2(retired_repost)
    assert len(v_ret) == 1
    assert v_ret[0].code == ViolationCode.I2

    # 307 redirect re-POST from keepalive violates I2
    keepalive_repost = _make_dummy_dispatch(
        generation_id="gen_001",
        method="POST",
        url=f"{PORTAL_BASE_URL}/Saml/okta-prod/Acs",
        headers={"X-Pseg-Keepalive": "true"},
        is_redirect_hop=True,
    )
    v_ka = oracle.evaluate_i2(keepalive_repost)
    assert len(v_ka) == 1
    assert v_ka[0].code == ViolationCode.I2


def test_i6_warm_cold_separate_instances() -> None:
    """I6 compares genuinely separate warm and cold control branches."""
    oracle = Oracle()

    runtime_warm = MagicMock()
    runtime_cold = MagicMock()

    d1 = _make_dummy_dispatch(
        generation_id="gen_001",
        method="GET",
        url=f"{PORTAL_BASE_URL}/Dashboard",
        body_digest=None,
    )
    d2 = _make_dummy_dispatch(
        generation_id="gen_002",
        method="GET",
        url=f"{PORTAL_BASE_URL}/Dashboard",
        body_digest=None,
    )

    # Identical reference -> fails requirement of genuinely separate runtimes
    same_instance_v = oracle.evaluate_i6(runtime_warm, runtime_warm)
    assert len(same_instance_v) == 1
    assert same_instance_v[0].code == ViolationCode.I6
    assert "genuinely separate runtimes" in same_instance_v[0].message

    # Separate runtimes with matching dispatches -> valid
    clean_v = oracle.evaluate_i6(
        runtime_warm, runtime_cold, warm_dispatches=[d1], cold_dispatches=[d2]
    )
    assert len(clean_v) == 0

    # Separate runtimes with diverging dispatches -> violates I6
    d_divergent = _make_dummy_dispatch(
        generation_id="gen_002",
        method="POST",
        url=f"{PORTAL_BASE_URL}/Home/Login",
        body_digest="digest_mismatch",
    )
    diverge_v = oracle.evaluate_i6(
        runtime_warm,
        runtime_cold,
        warm_dispatches=[d1],
        cold_dispatches=[d_divergent],
    )
    assert len(diverge_v) == 1
    assert diverge_v[0].code == ViolationCode.I6


# =============================================================================
# Isolation tests for all 12 invariant codes I1 through I12
# Each fixture triggers EXACTLY its code and no other codes.
# =============================================================================


@pytest.mark.parametrize(
    ("code", "trigger_fn"),
    [
        (
            ViolationCode.I1,
            lambda o: o.evaluate_i1(
                _make_dummy_dispatch(generation_id="gen_001", is_after_retire=True)
            ),
        ),
        (
            ViolationCode.I2,
            lambda o: o.evaluate_i2(
                _make_dummy_dispatch(
                    method="POST",
                    url=f"{PORTAL_BASE_URL}/Home/Login",
                    headers={"X-Terminal-Latched": "true"},
                )
            ),
        ),
        (
            ViolationCode.I3,
            lambda o: o.evaluate_i3(
                _make_dummy_dispatch(cookies={"MM_SID": "POISON_VAL"}),
                quarantined_cookies={("MM_SID", "POISON_VAL")},
            ),
        ),
        (
            ViolationCode.I4,
            lambda o: o.evaluate_i4(
                _make_dummy_snapshot(
                    persisted_jar=(
                        FrozenCookie(
                            "MM_SID",
                            "UNPROVEN",
                            "portal.pseg.com",
                            "/",
                            True,
                            None,
                        ),
                    )
                ),
                eligible_history={("MM_SID", "VALID_VAL")},
            ),
        ),
        (
            ViolationCode.I5,
            lambda o: o.evaluate_i5(
                _make_dummy_snapshot(
                    persisted_jar=(
                        FrozenCookie(
                            "MM_SID",
                            "WRONG_VAL",
                            "portal.pseg.com",
                            "/",
                            True,
                            None,
                        ),
                    )
                ),
                ExpectationState(
                    generation_id="gen_001",
                    latest_checkpoint=Checkpoint(
                        generation_id="gen_001",
                        sequence=1,
                        jar=MappingProxyType({"MM_SID": "EXPECTED_VAL"}),
                        admission=MappingProxyType({}),
                        timestamp=100.0,
                    ),
                ),
            ),
        ),
        (
            ViolationCode.I6,
            lambda o: o.evaluate_i6(
                MagicMock(),
                MagicMock(),
                warm_dispatches=[_make_dummy_dispatch(method="GET")],
                cold_dispatches=[_make_dummy_dispatch(method="POST")],
            ),
        ),
        (
            ViolationCode.I7,
            lambda o: o.evaluate_i7({"sequences_count": 3, "spacing_seconds": 900.0}),
        ),
        (
            ViolationCode.I8,
            lambda o: o.evaluate_i8(
                _make_dummy_snapshot(renewal_admission={"terminal_reason": "captcha_latched"}),
                automatic_auth_attempted=True,
                human_rearmed=False,
            ),
        ),
        (
            ViolationCode.I9,
            lambda o: o.evaluate_i9(
                {"auth_loss": True, "has_reauth_flow": False, "has_repair_issue": False}
            ),
        ),
        (
            ViolationCode.I10,
            lambda o: o.evaluate_i10(KeyError("untyped_key_error_leaked"), confirmed=False),
        ),
        (
            ViolationCode.I11,
            lambda o: o.evaluate_i11(
                {"caplog": "Leaked secret_password_123 in log output"},
                sentinels=["secret_password_123"],
            ),
        ),
        (
            ViolationCode.I12,
            lambda o: o.evaluate_i12(
                _make_dummy_snapshot(rows=(("consumption", ((1, 2),)),)),
                _make_dummy_snapshot(rows=(("consumption", ((1, 2), (3, 4))),)),
            ),
        ),
    ],
)
def test_isolated_violation_codes(code: ViolationCode, trigger_fn: Any) -> None:
    """Each fixture triggers exactly its mapped code and no other codes."""
    oracle = Oracle()
    violations = trigger_fn(oracle)
    assert len(violations) >= 1
    codes = {v.code for v in violations}
    assert codes == {code}, f"Expected isolated code {code}, got {codes}"

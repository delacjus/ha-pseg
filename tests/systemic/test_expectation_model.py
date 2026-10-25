"""Systemic tests for the independent response corpus, flows, and expectation model.

Verifies:
1. AST scan of support modules strictly forbids production imports (except allowed consts).
2. Mechanical completeness of all vocabulary members (builder, explicit outcome, positive control).
3. Applicability and exclusions declared with reasons.
4. Table traces proving:
   - Unvalidated 200 cannot advance eligibility or checkpoint.
   - Failed optional response cannot advance eligibility or checkpoint; daily fallback succeeds.
   - Healthy hourly rotation advances latest checkpoint.
   - Same-cookie and new-cookie human transitions are both modeled.
5. Synthetic meter schema fidelity without copying production validation logic.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.support.corpus import (
    EXCLUSION_RULES,
    VOCABULARY,
    ExpectedOutcome,
    FlowMode,
    PositiveControl,
    ResponseKind,
    Stage,
    get_expected_outcome,
    get_positive_control,
    get_synthetic_builder,
    is_applicable,
)
from tests.support.expectation import (
    ExpectationState,
    apply_step,
    apply_trace,
    transition_cold_restart,
    transition_human_rearm,
    transition_reload,
    transition_stop,
    transition_unload,
)
from tests.support.flows import (
    FlowStep,
    build_mode_l_trace,
    create_captcha_terminal_trace,
    create_failed_optional_trace,
    create_healthy_hourly_rotation_trace,
    create_http_401_auth_loss_trace,
    create_meter_match_positive_control_trace,
    create_meter_mismatch_trace,
    create_poison_cookie_quarantine_trace,
    create_quarantine_recovery_trace,
    create_rotation_before_daily_trace,
    create_send_after_retire_trace,
    create_unvalidated_200_trace,
)
from tests.support.portal import Reply
from tests.support.synthetic import (
    build_synthetic_daily_chart,
    build_synthetic_hourly_chart,
)

# ---------------------------------------------------------------------------
# 1. AST Scan: Forbidden Production Imports Guard
# ---------------------------------------------------------------------------

SUPPORT_MODULES = [
    Path("tests/support/synthetic.py"),
    Path("tests/support/corpus.py"),
    Path("tests/support/flows.py"),
    Path("tests/support/expectation.py"),
]

ALLOWED_CUSTOM_COMPONENTS_IMPORTS = {
    "custom_components.pseg.const": {"OKTA_HOST", "PORTAL_BASE_URL", "PORTAL_HOST"}
}


def test_support_modules_ast_no_forbidden_production_imports() -> None:
    """Verify that support modules do not import or call production parsers, validators, or policies."""
    repo_root = Path(__file__).resolve().parent.parent.parent

    for rel_path in SUPPORT_MODULES:
        full_path = repo_root / rel_path
        assert full_path.exists(), f"Support file {full_path} missing"

        tree = ast.parse(full_path.read_text(encoding="utf-8"), filename=str(rel_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("custom_components"), (
                        f"Forbidden direct import '{alias.name}' in {rel_path}"
                    )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod.startswith("custom_components"):
                    allowed_names = ALLOWED_CUSTOM_COMPONENTS_IMPORTS.get(mod)
                    assert allowed_names is not None, f"Forbidden import from '{mod}' in {rel_path}"
                    for alias in node.names:
                        assert alias.name in allowed_names, (
                            f"Forbidden import symbol '{alias.name}' from '{mod}' in {rel_path}"
                        )


# ---------------------------------------------------------------------------
# 2. Mechanical Completeness Test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("category", list(VOCABULARY.keys()))
def test_mechanical_completeness_of_all_vocabulary_members(category: str) -> None:
    """Enumerate every vocabulary member and assert it has a builder, explicit outcome, and positive control."""
    members = VOCABULARY[category]
    assert len(members) > 0, f"Vocabulary category '{category}' is empty"

    for member in members:
        # 1. Check synthetic builder
        builder = get_synthetic_builder(category, member)
        assert callable(builder), f"Missing builder for {category}:{member}"
        synth_artifact = builder()
        assert synth_artifact is not None, f"Builder for {category}:{member} returned None"

        # 2. Check explicit expected outcome
        outcome = get_expected_outcome(category, member)
        assert isinstance(outcome, ExpectedOutcome), (
            f"Expected outcome for {category}:{member} must be ExpectedOutcome, got {type(outcome)}"
        )
        assert isinstance(outcome.valid, bool), (
            f"Outcome valid must be bool for {category}:{member}"
        )
        assert isinstance(outcome.cookie_eligible, bool), (
            f"Outcome cookie_eligible must be bool for {category}:{member}"
        )
        assert len(outcome.action) > 0, f"Outcome action must be declared for {category}:{member}"
        assert len(outcome.description) > 0, (
            f"Outcome description must be declared for {category}:{member}"
        )

        # 3. Check valid positive control
        control = get_positive_control(category, member)
        assert isinstance(control, PositiveControl), (
            f"Positive control for {category}:{member} must be PositiveControl, got {type(control)}"
        )
        assert control.is_positive_control is True, (
            f"Control for {category}:{member} must be flagged is_positive_control"
        )
        assert control.expected_valid is True, (
            f"Positive control for {category}:{member} must have expected_valid=True"
        )
        assert control.reply is not None, (
            f"Positive control for {category}:{member} must provide a non-None reply/trace"
        )


# ---------------------------------------------------------------------------
# 3. Applicability and Exclusions Test
# ---------------------------------------------------------------------------


def test_applicability_and_exclusions_have_declared_reasons() -> None:
    """Verify that all exclusions have declared non-empty reasons and correctly classify applicability."""
    assert len(EXCLUSION_RULES) >= 8, (
        f"Expected comprehensive exclusions, got {len(EXCLUSION_RULES)}"
    )

    for rule in EXCLUSION_RULES:
        assert len(rule.category) > 0, f"Exclusion rule missing category: {rule}"
        assert rule.member is not None, f"Exclusion rule missing member: {rule}"
        assert len(rule.context) > 0, f"Exclusion rule missing context: {rule}"
        assert len(rule.reason.strip()) > 10, f"Exclusion rule has inadequate reason: {rule}"

        # Verify is_applicable reflects this rule
        applicable, reason = is_applicable(rule.category, rule.member, rule.context)
        assert applicable is False, (
            f"Expected exclusion for {rule.category}:{rule.member} in {rule.context}"
        )
        assert reason == rule.reason

    # Verify an applicable case returns True
    applicable, reason = is_applicable("stages", Stage.DASHBOARD_VERIFY_TOKEN, "mode:L")
    assert applicable is True
    assert reason == "Applicable"


# ---------------------------------------------------------------------------
# 4. Table Trace Proofs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "poison_kind",
    [ResponseKind.MAINTENANCE, ResponseKind.ROOT_ARRAY, ResponseKind.MISSING_TOKEN],
)
def test_unvalidated_200_cannot_advance_checkpoint_or_eligibility(poison_kind: str) -> None:
    """Table trace proof: an unvalidated 200 cannot advance eligibility or the checkpoint."""
    trace = create_unvalidated_200_trace(poison_kind=poison_kind)
    initial_state = ExpectationState(generation_id="GEN_001")

    final_state = apply_trace(initial_state, trace)

    # Invariant: latest_checkpoint MUST NOT ADVANCE (remains None)
    assert final_state.latest_checkpoint is None, (
        f"Unvalidated 200 ({poison_kind}) illegally created a checkpoint!"
    )
    # Invariant: zero reply IDs validated
    assert len(final_state.validated_reply_ids) == 0
    # Invariant: dashboard was NOT validated
    assert final_state.dashboard_validated is False
    # Invariant: poisoned cookies were NOT adopted
    assert (
        "SYNTH_POISON_SID_001" not in str(final_state.history_events)
        or final_state.latest_checkpoint is None
    )


@pytest.mark.parametrize("failure_status", [500, 503, 404])
def test_failed_optional_response_cannot_advance_checkpoint_or_eligibility_daily_fallback_succeeds(
    failure_status: int,
) -> None:
    """Table trace proof: a failed optional response cannot advance eligibility or checkpoint; daily fallback succeeds."""
    trace = create_failed_optional_trace(failure_status=failure_status)
    initial_state = ExpectationState(generation_id="GEN_001")

    # Step 1: Dashboard
    s1 = apply_step(initial_state, trace[0], timestamp=100.0)
    assert s1.dashboard_validated is True
    assert s1.latest_checkpoint is None  # Daily chart not yet received

    # Step 2: Daily ChartData -> establishes daily checkpoint
    s2 = apply_step(s1, trace[1], timestamp=110.0)
    assert s2.daily_validated is True
    assert s2.latest_checkpoint is not None
    daily_checkpoint = s2.latest_checkpoint
    assert daily_checkpoint.jar["MM_SID"] == "SYNTH_VALID_SID_001"
    assert daily_checkpoint.timestamp == 110.0

    # Step 3: Optional Hourly leg fails
    s3 = apply_step(s2, trace[2], timestamp=120.0)

    # Invariants:
    # 1. Daily fallback succeeded
    assert s3.daily_fallback_succeeded is True
    # 2. Checkpoint remains exactly at the daily checkpoint
    assert s3.latest_checkpoint == daily_checkpoint, (
        "Failed optional response illegally altered or advanced latest_checkpoint!"
    )
    assert s3.latest_checkpoint.timestamp == 110.0
    # 3. Poisoned hourly cookie was NOT adopted
    assert "SYNTH_HOURLY_POISON_SID_002" not in s3.latest_checkpoint.jar


def test_healthy_hourly_rotation_advances_latest_checkpoint() -> None:
    """Table trace proof: healthy hourly rotation advances the latest checkpoint."""
    trace = create_healthy_hourly_rotation_trace()
    initial_state = ExpectationState(generation_id="GEN_001")

    # Steps 1 & 2: Dashboard and Daily establish initial checkpoint
    s1 = apply_step(initial_state, trace[0], timestamp=100.0)
    s2 = apply_step(s1, trace[1], timestamp=110.0)
    daily_checkpoint = s2.latest_checkpoint
    assert daily_checkpoint is not None
    assert daily_checkpoint.jar["MM_SID"] == "SYNTH_INIT_SID_001"
    assert daily_checkpoint.timestamp == 110.0

    # Step 3: Hourly ChartData with rotation advances latest checkpoint
    s3 = apply_step(s2, trace[2], timestamp=120.0)
    hourly_checkpoint = s3.latest_checkpoint
    assert hourly_checkpoint is not None

    # Invariants:
    # 1. Latest checkpoint advanced beyond daily
    assert hourly_checkpoint != daily_checkpoint
    assert hourly_checkpoint.sequence > daily_checkpoint.sequence
    assert hourly_checkpoint.timestamp == 120.0
    # 2. Rotated cookie is adopted in latest checkpoint
    assert hourly_checkpoint.jar["MM_SID"] == "SYNTH_ROTATED_SID_002"


def test_same_cookie_and_new_cookie_human_transitions() -> None:
    """Table trace proof: both same-cookie and new-cookie human (H) transitions are modeled."""
    # Establish active state with an initial checkpoint
    initial_state = ExpectationState(generation_id="GEN_OLD")
    trace_l = build_mode_l_trace()
    active_old = apply_trace(initial_state, trace_l, base_timestamp=500.0)
    assert active_old.latest_checkpoint is not None
    old_jar = active_old.latest_checkpoint.jar
    assert "MM_SID" in old_jar

    # 1. Model Same-Cookie Human Transition
    retired_old_1, active_new_same = transition_human_rearm(
        active_old,
        new_generation_id="GEN_NEW_SAME",
        same_cookie=True,
        timestamp=600.0,
    )

    assert retired_old_1.is_retired is True
    assert active_new_same.is_retired is False
    assert active_new_same.is_human_rearmed is True
    assert active_new_same.generation_id == "GEN_NEW_SAME"
    assert active_new_same.latest_checkpoint is not None
    # Invariant: retains same verified cookie jar
    assert active_new_same.latest_checkpoint.jar == old_jar

    # 2. Model New-Cookie Human Transition
    fresh_cookies = {"MM_SID": "SYNTH_BRAND_NEW_SID", "idx": "SYNTH_BRAND_NEW_IDX"}
    retired_old_2, active_new_fresh = transition_human_rearm(
        active_old,
        new_generation_id="GEN_NEW_FRESH",
        same_cookie=False,
        new_cookies=fresh_cookies,
        timestamp=700.0,
    )

    assert retired_old_2.is_retired is True
    assert active_new_fresh.is_retired is False
    assert active_new_fresh.is_human_rearmed is True
    assert active_new_fresh.generation_id == "GEN_NEW_FRESH"
    assert active_new_fresh.latest_checkpoint is not None
    # Invariant: adopts the new cookie jar
    assert active_new_fresh.latest_checkpoint.jar["MM_SID"] == "SYNTH_BRAND_NEW_SID"
    assert active_new_fresh.latest_checkpoint.jar["idx"] == "SYNTH_BRAND_NEW_IDX"


# ---------------------------------------------------------------------------
# 5. Synthetic Schema Contract Test
# ---------------------------------------------------------------------------


def test_synthetic_meter_schema_contract() -> None:
    """Verify synthetic meter schema conforms to accepted contract without copying production validation."""
    daily_payload = build_synthetic_daily_chart(
        meter_id="SYNTH_METER_TEST", kwh=18.75, date_str="10/24/2026"
    )
    assert "Data" in daily_payload
    assert "series" in daily_payload["Data"]
    series = daily_payload["Data"]["series"]
    assert len(series) == 1
    meter_entry = series[0]
    assert "name" in meter_entry
    assert "SYNTH_METER_TEST" in meter_entry["name"]
    assert len(meter_entry["data"]) == 1
    pt = meter_entry["data"][0]
    assert isinstance(pt["x"], int)
    assert pt["y"] == 18.75
    assert pt["hs"]["start"] == "10/24/2026"
    assert pt["hs"]["end"] == "10/24/2026"

    hourly_payload = build_synthetic_hourly_chart(meter_id="SYNTH_METER_HOURLY", num_hours=24)
    hourly_series = hourly_payload["Data"]["series"][0]
    assert len(hourly_series["data"]) == 24
    for pt in hourly_series["data"]:
        assert isinstance(pt["x"], int)
        assert pt["y"] == 1.0
        assert " " in pt["hs"]["start"]
        assert " " in pt["hs"]["end"]


# ---------------------------------------------------------------------------
# 6. R2 Closure Proofs (F1-F4)
# ---------------------------------------------------------------------------


def test_rotation_before_daily_lands_in_checkpoint() -> None:
    """F1 Proof: Dashboard rotation before daily lands in the persistent checkpoint."""
    trace = create_rotation_before_daily_trace()
    initial_state = ExpectationState(generation_id="GEN_001")

    # Step 1: Dashboard with rotation
    s1 = apply_step(initial_state, trace[0], timestamp=100.0)
    assert s1.dashboard_validated is True
    assert s1.latest_checkpoint is None  # Dashboard alone does not checkpoint
    assert s1.pending_session_jar.get("MM_SID") == "SYNTH_DASH_ROTATED_SID"
    assert s1.pending_session_jar.get("idx") == "SYNTH_DASH_IDX"

    # Step 2: Daily ChartData with no new cookies
    s2 = apply_step(s1, trace[1], timestamp=110.0)
    assert s2.daily_validated is True
    assert s2.latest_checkpoint is not None

    # Invariant: the rotation cookie from Dashboard landed in the checkpoint!
    assert s2.latest_checkpoint.jar.get("MM_SID") == "SYNTH_DASH_ROTATED_SID"
    assert s2.latest_checkpoint.jar.get("idx") == "SYNTH_DASH_IDX"
    assert s2.latest_checkpoint.timestamp == 110.0


def test_poison_cookie_never_reaches_checkpoint_after_later_valid_steps() -> None:
    """F1 Proof: An invalid 200 setting a poison cookie never reaches any checkpoint, including after later valid steps."""
    trace = create_poison_cookie_quarantine_trace(poison_cookie_val="SYNTH_UNIQUE_POISON_999")
    initial_state = ExpectationState(generation_id="GEN_001")

    # Steps 1 & 2: Establish initial valid checkpoint
    s1 = apply_step(initial_state, trace[0], timestamp=100.0)
    s2 = apply_step(s1, trace[1], timestamp=110.0)
    init_checkpoint = s2.latest_checkpoint
    assert init_checkpoint is not None
    assert init_checkpoint.jar.get("MM_SID") == "SYNTH_INITIAL_GOOD_SID"

    # Step 3: Invalid 200 setting poison cookie (must enter quarantine and rollback)
    s3 = apply_step(s2, trace[2], timestamp=120.0)
    assert s3.is_quarantined is True
    assert s3.latest_checkpoint == init_checkpoint
    assert "SYNTH_UNIQUE_POISON_999" not in s3.latest_checkpoint.jar
    assert "SYNTH_UNIQUE_POISON_999" not in s3.pending_session_jar.values()

    # Step 4: Later valid step
    s4 = apply_step(s3, trace[3], timestamp=130.0)
    assert s4.latest_checkpoint is not None
    assert s4.latest_checkpoint != init_checkpoint
    assert s4.latest_checkpoint.jar.get("MM_SID") == "SYNTH_LATER_VALID_SID"

    # Invariant: poison cookie NEVER reached any checkpoint!
    assert "SYNTH_UNIQUE_POISON_999" not in s4.latest_checkpoint.jar


def test_quarantine_recovery_behaves_per_production() -> None:
    """F1 Proof: Recovery from quarantine clears quarantine and advances checkpoint."""
    trace = create_quarantine_recovery_trace()
    initial_state = ExpectationState(generation_id="GEN_001")

    s1 = apply_step(initial_state, trace[0], timestamp=100.0)
    s2 = apply_step(s1, trace[1], timestamp=110.0)
    assert s2.is_quarantined is False
    assert s2.latest_checkpoint is not None

    # Step 3: Failed stage enters quarantine
    s3 = apply_step(s2, trace[2], timestamp=120.0)
    assert s3.is_quarantined is True
    assert s3.latest_checkpoint == s2.latest_checkpoint

    # Step 4: Recovery step clears quarantine and updates checkpoint
    s4 = apply_step(s3, trace[3], timestamp=130.0)
    assert s4.is_quarantined is False
    assert s4.latest_checkpoint is not None
    assert s4.latest_checkpoint.jar.get("MM_SID") == "SYNTH_RECOVERED_GOOD_SID"


def test_meter_identity_mismatch_cannot_advance_checkpoint() -> None:
    """F2 Proof: Declaring mismatching meters cannot advance checkpoint and enters quarantine."""
    trace = create_meter_mismatch_trace()
    initial_state = ExpectationState(
        generation_id="GEN_001",
        expected_meters=("SYNTH_METER_PRIMARY",),
    )

    # Step 1: Matching Dashboard
    s1 = apply_step(initial_state, trace[0], timestamp=100.0)
    assert s1.dashboard_validated is True
    assert s1.active_meters == ("SYNTH_METER_PRIMARY",)
    assert s1.latest_checkpoint is None

    # Step 2: Mismatching Daily ChartData
    s2 = apply_step(s1, trace[1], timestamp=110.0)

    # Invariants:
    # 1. Checkpoint MUST NOT ADVANCE (remains None)
    assert s2.latest_checkpoint is None
    # 2. State entered quarantine
    assert s2.is_quarantined is True
    # 3. Active meters NOT overwritten by foreign meter
    assert s2.active_meters == ("SYNTH_METER_PRIMARY",)
    # 4. Violation recorded in history
    assert any("violation:meter_identity_mismatch" in ev for ev in s2.history_events)


def test_meter_identity_positive_control_advances_checkpoint() -> None:
    """F2 Positive Control: Matching meters advance checkpoint cleanly."""
    trace = create_meter_match_positive_control_trace()
    initial_state = ExpectationState(
        generation_id="GEN_001",
        expected_meters=("SYNTH_METER_PRIMARY",),
    )

    final_state = apply_trace(initial_state, trace)
    assert final_state.latest_checkpoint is not None
    assert final_state.active_meters == ("SYNTH_METER_PRIMARY",)
    assert final_state.is_quarantined is False
    assert not any("violation:meter_identity_mismatch" in ev for ev in final_state.history_events)


def test_http_401_is_auth_loss_not_terminal() -> None:
    """F3 Proof: HTTP 401 is auth loss, NOT terminal latch, and sets mode-specific renewal expectation."""
    initial_state = ExpectationState(generation_id="GEN_001")

    # Mode L: expect local credential renewal
    trace_l = create_http_401_auth_loss_trace(flow_mode=FlowMode.L)
    state_l = apply_trace(initial_state, trace_l)
    assert state_l.is_terminal is False, "HTTP 401 illegally set is_terminal!"
    assert state_l.pending_renewal_expectation == "expect_local_credential_renewal"

    # Mode R: expect Remember Me renewal
    trace_r = create_http_401_auth_loss_trace(flow_mode=FlowMode.R)
    state_r = apply_trace(initial_state, trace_r)
    assert state_r.is_terminal is False, "HTTP 401 illegally set is_terminal!"
    assert state_r.pending_renewal_expectation == "expect_remember_me_renewal"

    # Mode S: expect Okta SSO renewal
    trace_s = create_http_401_auth_loss_trace(flow_mode=FlowMode.S)
    state_s = apply_trace(initial_state, trace_s)
    assert state_s.is_terminal is False, "HTTP 401 illegally set is_terminal!"
    assert state_s.pending_renewal_expectation == "expect_okta_sso_renewal"

    # Mode H: expect human reauth
    trace_h = create_http_401_auth_loss_trace(flow_mode=FlowMode.H)
    state_h = apply_trace(initial_state, trace_h)
    assert state_h.is_terminal is False, "HTTP 401 illegally set is_terminal!"
    assert state_h.pending_renewal_expectation == "expect_human_reauth"


def test_captcha_is_terminal_and_blocks_credential_post() -> None:
    """F3 Proof: CAPTCHA is terminal latch and blocks subsequent credential POST expectations."""
    trace = create_captcha_terminal_trace()
    initial_state = ExpectationState(generation_id="GEN_001")

    # Step 1: CAPTCHA challenge
    s1 = apply_step(initial_state, trace[0], timestamp=100.0)
    assert s1.is_terminal is True, "CAPTCHA challenge failed to set is_terminal!"
    assert s1.pending_renewal_expectation == "blocked_terminal_human_rearm_required"

    # Step 2: Attempted credential POST while terminal
    s2 = apply_step(s1, trace[1], timestamp=110.0)
    assert s2.is_terminal is True
    assert s2.latest_checkpoint is None
    assert any("violation:credential_post_while_terminal" in ev for ev in s2.history_events)


def test_generation_retirement_transitions() -> None:
    """F4 Proof: Reload, unload, stop, and cold restart all retire the generation."""
    initial_state = ExpectationState(generation_id="GEN_001")

    r_reload = transition_reload(initial_state)
    assert r_reload.is_retired is True
    assert "retired_by_reload" in r_reload.history_events

    r_unload = transition_unload(initial_state)
    assert r_unload.is_retired is True
    assert "retired_by_unload" in r_unload.history_events

    r_stop = transition_stop(initial_state)
    assert r_stop.is_retired is True
    assert "retired_by_stop" in r_stop.history_events

    r_cold = transition_cold_restart(initial_state)
    assert r_cold.is_retired is True
    assert "retired_by_cold_restart" in r_cold.history_events


def test_send_after_retire_is_violation_and_never_checkpoints() -> None:
    """F4 Proof: A send attempted after retirement is recorded as a violation and never checkpoints."""
    trace = create_send_after_retire_trace()
    active_state = ExpectationState(generation_id="GEN_001")
    retired_state = transition_reload(active_state)
    assert retired_state.is_retired is True

    after_send = apply_step(retired_state, trace[0], timestamp=200.0)

    # Invariants:
    # 1. Generation remains retired
    assert after_send.is_retired is True
    # 2. Checkpoint NEVER created or advanced
    assert after_send.latest_checkpoint is None
    # 3. Recorded as explicit send_after_retire violation
    assert any("violation:send_after_retire" in ev for ev in after_send.history_events)


def test_human_mode_cannot_checkpoint_before_dashboard_validation() -> None:
    """A human (H) jar is not checkpointed until the Dashboard verify step validates it."""
    human_cookies = {"MM_SID": "SYNTH_HUMAN_UNVERIFIED_SID"}
    step = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_H_DAILY_FIRST",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body="{}",
            cookies=human_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        flow_mode=FlowMode.H,
    )
    state = apply_step(ExpectationState(generation_id="GEN_H"), step, timestamp=100.0)
    assert state.dashboard_validated is False
    assert state.latest_checkpoint is None

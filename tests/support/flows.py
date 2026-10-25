"""Flow sequence definitions, mode traces, and transition scenarios for systemic testing.

Defines flow modes L (local), R (RememberMe), S (legacy SSO), and H (unattached human),
along with positive controls and adversarial trace scenarios.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import json
from types import MappingProxyType
from typing import Any

from .corpus import (
    ExpectedOutcome,
    Position,
    PositiveControl,
    ResponseKind,
    Stage,
    build_stage_reply,
)
from .portal import Reply
from .synthetic import (
    build_synthetic_captcha_html,
    build_synthetic_cookies,
    build_synthetic_daily_chart,
    build_synthetic_dashboard_html,
    build_synthetic_hourly_chart,
    build_synthetic_maintenance_html,
    build_synthetic_root_array,
    synth_id,
)


class FlowMode:
    """Supported flow modes."""

    L = "L"  # Local email/password
    R = "R"  # RememberMe renewal
    S = "S"  # Legacy SSO
    H = "H"  # Human reauth / CAPTCHA handoff

    ALL = (L, R, S, H)


@dataclass(frozen=True, slots=True)
class FlowStep:
    """An individual step in a systemic flow trace."""

    stage: str
    reply: Reply
    position: str = Position.POST_PROOF
    flow_mode: str = FlowMode.L
    metadata: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


# ---------------------------------------------------------------------------
# Flow Mode Registry: Synthetic Builders, Expected Outcomes, Positive Controls
# ---------------------------------------------------------------------------


def get_flow_mode_builder(mode: str) -> Callable[[], tuple[FlowStep, ...]]:
    """Retrieve synthetic trace builder for a flow mode."""
    if mode == FlowMode.L:
        return lambda: build_mode_l_trace()
    if mode == FlowMode.R:
        return lambda: build_mode_r_trace()
    if mode == FlowMode.S:
        return lambda: build_mode_s_trace()
    if mode == FlowMode.H:
        return lambda: build_mode_h_trace()
    raise KeyError(f"Unknown flow mode: {mode}")


def get_flow_mode_outcome(mode: str) -> ExpectedOutcome:
    """Retrieve explicit expected outcome for a flow mode."""
    if mode in (FlowMode.L, FlowMode.R, FlowMode.S):
        return ExpectedOutcome(
            valid=True,
            cookie_eligible=True,
            action="flow_authenticated",
            description=f"Mode {mode} establishes authenticated session and checkpoints.",
        )
    if mode == FlowMode.H:
        return ExpectedOutcome(
            valid=True,
            cookie_eligible=True,
            action="human_rearm_settled",
            description="Mode H human re-arm settles authentication latch.",
        )
    raise KeyError(f"Unknown flow mode: {mode}")


def get_flow_mode_positive_control(mode: str) -> PositiveControl:
    """Retrieve verified valid positive control for a flow mode."""
    builder = get_flow_mode_builder(mode)
    steps = builder()
    outcome = get_flow_mode_outcome(mode)
    return PositiveControl(
        category="flow_modes",
        member=mode,
        reply=steps,
        expected_outcome=outcome,
    )


# ---------------------------------------------------------------------------
# Standard Mode Traces
# ---------------------------------------------------------------------------


def build_mode_l_trace() -> tuple[FlowStep, ...]:
    """Build healthy Mode L (local email/password) trace."""
    sid_cookies = build_synthetic_cookies("sid")
    rm_cookies = build_synthetic_cookies("remember_me")
    all_cookies = {**sid_cookies, **rm_cookies}

    step1 = FlowStep(
        stage=Stage.LOGIN_FORM_GET,
        reply=build_stage_reply(Stage.LOGIN_FORM_GET, valid=True),
        position=Position.PRE_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id=synth_id("REP_L_DASH"),
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=all_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step3 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id=synth_id("REP_L_DAILY"),
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart()),
            cookies=all_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    return (step1, step2, step3)


def build_mode_r_trace() -> tuple[FlowStep, ...]:
    """Build healthy Mode R (Remember-Me renewal) trace."""
    rm_cookies = build_synthetic_cookies("remember_me")
    new_sid = build_synthetic_cookies("sid")
    combined = {**rm_cookies, **new_sid}

    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id=synth_id("REP_R_DASH"),
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=combined,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.R,
    )
    step2 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id=synth_id("REP_R_DAILY"),
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart()),
            cookies=combined,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.R,
    )
    return (step1, step2)


def build_mode_s_trace() -> tuple[FlowStep, ...]:
    """Build healthy Mode S (legacy Okta SSO) trace."""
    okta_cookies = build_synthetic_cookies("sid")

    step1 = FlowStep(
        stage=Stage.SAML_ACS,
        reply=build_stage_reply(Stage.SAML_ACS, valid=True),
        position=Position.PRE_PROOF,
        flow_mode=FlowMode.S,
    )
    step2 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id=synth_id("REP_S_DASH"),
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=okta_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.S,
    )
    step3 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id=synth_id("REP_S_DAILY"),
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart()),
            cookies=okta_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.S,
    )
    return (step1, step2, step3)


def build_mode_h_trace() -> tuple[FlowStep, ...]:
    """Build healthy Mode H (Human reauth) trace."""
    cookies = build_synthetic_cookies("sid")
    step = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id=synth_id("REP_H_REARM"),
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"human_rearm": True, "meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.H,
    )
    return (step,)


# ---------------------------------------------------------------------------
# Required Table Trace Scenarios
# ---------------------------------------------------------------------------


def create_unvalidated_200_trace(
    poison_kind: str = ResponseKind.MAINTENANCE,
) -> tuple[FlowStep, ...]:
    """Build trace with an unvalidated 200 containing poisoned cookies.

    Proves an unvalidated 200 cannot advance eligibility or the checkpoint.
    """
    poison_cookies = {"MM_SID": "SYNTH_POISON_SID_001", "idx": "SYNTH_POISON_IDX_001"}
    if poison_kind == ResponseKind.MAINTENANCE:
        body = build_synthetic_maintenance_html()
        hdrs = {"Content-Type": "text/html"}
    elif poison_kind == ResponseKind.ROOT_ARRAY:
        body = json.dumps(build_synthetic_root_array())
        hdrs = {"Content-Type": "application/json"}
    else:
        body = "<html><body>Missing token page</body></html>"
        hdrs = {"Content-Type": "text/html"}

    poison_reply = Reply(
        reply_id="SYNTH_REP_POISON_200",
        status_code=200,
        headers=hdrs,
        body=body,
        cookies=poison_cookies,
        valid=False,  # Unvalidated 200 declared invalid
        cookie_eligible=False,  # Poisoned cookies must NOT be eligible
        metadata={"poison": True, "kind": poison_kind},
    )

    return (
        FlowStep(
            stage=Stage.DASHBOARD_VERIFY_TOKEN,
            reply=poison_reply,
            position=Position.POST_PROOF,
            flow_mode=FlowMode.L,
        ),
    )


def create_failed_optional_trace(
    failure_status: int = 500,
) -> tuple[FlowStep, ...]:
    """Build trace with valid Daily statistics but failed optional Hourly leg.

    Proves a failed optional response cannot advance eligibility or checkpoint,
    while successful daily fallback is preserved.
    """
    valid_cookies = {"MM_SID": "SYNTH_VALID_SID_001"}
    poison_hourly_cookies = {"MM_SID": "SYNTH_HOURLY_POISON_SID_002"}

    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_DASH_VALID",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=valid_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_DAILY_VALID",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart(meter_id="SYNTH_METER_001", kwh=24.5)),
            cookies=valid_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    # Optional Hourly leg fails
    step3 = FlowStep(
        stage=Stage.HOURLY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_HOURLY_FAILED",
            status_code=failure_status,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"error": "Hourly service unavailable"}),
            cookies=poison_hourly_cookies,
            valid=False,
            cookie_eligible=False,
            metadata={"optional_failure": True},
        ),
        position=Position.OPTIONAL,
        flow_mode=FlowMode.L,
    )

    return (step1, step2, step3)


def create_healthy_hourly_rotation_trace() -> tuple[FlowStep, ...]:
    """Build trace where healthy hourly rotation advances latest checkpoint.

    Proves healthy hourly rotation advances the latest checkpoint.
    """
    initial_cookies = {"MM_SID": "SYNTH_INIT_SID_001"}
    rotated_cookies = {"MM_SID": "SYNTH_ROTATED_SID_002"}

    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_ROT_DASH",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=initial_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_ROT_DAILY",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart()),
            cookies=initial_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step3 = FlowStep(
        stage=Stage.HOURLY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_ROT_HOURLY",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_hourly_chart()),
            cookies=rotated_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",), "rotation": True},
        ),
        position=Position.OPTIONAL,
        flow_mode=FlowMode.L,
    )

    return (step1, step2, step3)


def create_same_cookie_human_trace() -> tuple[FlowStep, ...]:
    """Build trace modeling same-cookie human handoff transition."""
    shared_cookies = {"MM_SID": "SYNTH_SHARED_SID_001", "idx": "SYNTH_SHARED_IDX_001"}
    step = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_SAME_COOKIE_HANDOFF",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=shared_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"human_transition": "same_cookie", "meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.H,
    )
    return (step,)


def create_new_cookie_human_trace() -> tuple[FlowStep, ...]:
    """Build trace modeling new-cookie human handoff transition."""
    fresh_cookies = {"MM_SID": "SYNTH_FRESH_SID_999", "idx": "SYNTH_FRESH_IDX_999"}
    step = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_NEW_COOKIE_HANDOFF",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=fresh_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"human_transition": "new_cookie", "meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.H,
    )
    return (step,)


def create_rotation_before_daily_trace() -> tuple[FlowStep, ...]:
    """Build trace where Dashboard rotates cookie before Daily chart.

    Proves the rotation cookie accumulated in pending session jar lands in the
    persisted checkpoint even though Dashboard alone did not checkpoint.
    """
    dash_cookies = {"MM_SID": "SYNTH_DASH_ROTATED_SID", "idx": "SYNTH_DASH_IDX"}

    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_DASH_ROT_001",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=dash_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_DAILY_NO_COOKIES",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart(meter_id="SYNTH_METER_001", kwh=20.0)),
            cookies={},  # No cookies set on daily leg
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    return (step1, step2)


def create_poison_cookie_quarantine_trace(
    poison_cookie_val: str = "SYNTH_POISON_SID_666",
) -> tuple[FlowStep, ...]:
    """Build trace with initial valid checkpoint, an invalid 200 with poison cookie, then a later valid step.

    Proves an invalid 200 setting a poison cookie never reaches any checkpoint,
    including after later valid steps (unique poison control).
    """
    initial_cookies = {"MM_SID": "SYNTH_INITIAL_GOOD_SID"}
    poison_cookies = {"MM_SID": poison_cookie_val}
    later_cookies = {"MM_SID": "SYNTH_LATER_VALID_SID"}

    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_POISON_CTRL_DASH",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=initial_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_POISON_CTRL_DAILY",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart(meter_id="SYNTH_METER_001", kwh=10.0)),
            cookies=initial_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    # Step 3: Invalid 200 setting poison cookie
    step3 = FlowStep(
        stage=Stage.HOURLY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_POISON_HOURLY_200",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_maintenance_html(),
            cookies=poison_cookies,
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.MAINTENANCE, "poison": True},
        ),
        position=Position.OPTIONAL,
        flow_mode=FlowMode.L,
    )
    # Step 4: Later valid step
    step4 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_POISON_CTRL_LATER_VALID",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart(meter_id="SYNTH_METER_001", kwh=15.0)),
            cookies=later_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )

    return (step1, step2, step3, step4)


def create_quarantine_recovery_trace() -> tuple[FlowStep, ...]:
    """Build trace showing recovery from a quarantined failed stage per production rules."""
    init_cookies = {"MM_SID": "SYNTH_RECOVER_INIT_SID"}
    transient_cookies = {"MM_POISON": "SYNTH_QUARANTINED_BAD_VAL"}
    recovered_cookies = {"MM_SID": "SYNTH_RECOVERED_GOOD_SID"}

    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_REC_DASH_1",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies=init_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_REC_DAILY_1",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart(meter_id="SYNTH_METER_001")),
            cookies=init_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    # Transient failure with unconfirmed cookies
    step3 = FlowStep(
        stage=Stage.HOURLY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_REC_HOURLY_FAIL",
            status_code=500,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"error": "Server Error"}),
            cookies=transient_cookies,
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_500},
        ),
        position=Position.OPTIONAL,
        flow_mode=FlowMode.L,
    )
    # Recovery poll
    step4 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_REC_DAILY_RECOVERY",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart(meter_id="SYNTH_METER_001", kwh=30.0)),
            cookies=recovered_cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    return (step1, step2, step3, step4)


def create_meter_mismatch_trace() -> tuple[FlowStep, ...]:
    """Build trace where reply declares a mismatching meter identity."""
    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_METER_DASH",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies={"MM_SID": "SYNTH_METER_SID"},
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_PRIMARY",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_METER_MISMATCH",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart(meter_id="SYNTH_METER_FOREIGN")),
            cookies={"MM_SID": "SYNTH_MISMATCH_SID"},
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_FOREIGN",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    return (step1, step2)


def create_meter_match_positive_control_trace() -> tuple[FlowStep, ...]:
    """Build positive control trace where declared meters match established identity."""
    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_METER_POS_DASH",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies={"MM_SID": "SYNTH_METER_POS_SID"},
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_PRIMARY",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.DAILY_CHART_DATA,
        reply=Reply(
            reply_id="SYNTH_REP_METER_POS_DAILY",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(build_synthetic_daily_chart(meter_id="SYNTH_METER_PRIMARY")),
            cookies={"MM_SID": "SYNTH_METER_POS_SID"},
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_PRIMARY",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    return (step1, step2)


def create_http_401_auth_loss_trace(flow_mode: str = FlowMode.L) -> tuple[FlowStep, ...]:
    """Build trace with HTTP 401 proving auth loss is NOT terminal latch."""
    step1 = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_401_AUTH_LOSS",
            status_code=401,
            headers={},
            body="Unauthorized",
            cookies={},
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_401},
        ),
        position=Position.PRE_PROOF,
        flow_mode=flow_mode,
    )
    return (step1,)


def create_captcha_terminal_trace() -> tuple[FlowStep, ...]:
    """Build trace where CAPTCHA is terminal and blocks credential POST."""
    step1 = FlowStep(
        stage=Stage.LOGIN_FORM_GET,
        reply=Reply(
            reply_id="SYNTH_REP_CAPTCHA_TERMINAL",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_captcha_html(),
            cookies={},
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.CAPTCHA, "is_terminal": True},
        ),
        position=Position.PRE_PROOF,
        flow_mode=FlowMode.L,
    )
    step2 = FlowStep(
        stage=Stage.LOGIN_FORM_GET,
        reply=Reply(
            reply_id="SYNTH_REP_POST_CREDENTIALS",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="Attempted credential POST",
            cookies={},
            valid=True,
            cookie_eligible=True,
            metadata={"credential_post": True},
        ),
        position=Position.PRE_PROOF,
        flow_mode=FlowMode.L,
    )
    return (step1, step2)


def create_send_after_retire_trace() -> tuple[FlowStep, ...]:
    """Build trace attempting a send after generation retirement."""
    step = FlowStep(
        stage=Stage.DASHBOARD_VERIFY_TOKEN,
        reply=Reply(
            reply_id="SYNTH_REP_AFTER_RETIRE_SEND",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_dashboard_html(),
            cookies={"MM_SID": "SYNTH_RETIRED_SEND_SID"},
            valid=True,
            cookie_eligible=True,
            metadata={"meters": ("SYNTH_METER_001",)},
        ),
        position=Position.POST_PROOF,
        flow_mode=FlowMode.L,
    )
    return (step,)

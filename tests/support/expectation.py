"""Pure expectation model and deterministic state transitions for systemic testing.

Maintains verified meter identity, eligible checkpoints, admission status, retirement,
and human transitions as pure declared data without importing production parsers,
validators, or policy classifiers.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .corpus import FlowMode, Position, ResponseKind, Stage
from .flows import FlowStep
from .portal import Reply, _freeze_cookies, _freeze_metadata


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """Immutable persistent state checkpoint representing the latest eligible session state."""

    generation_id: str
    sequence: int
    jar: MappingProxyType[str, str]
    admission: MappingProxyType[str, Any]
    timestamp: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "jar", _freeze_cookies(self.jar))
        object.__setattr__(self, "admission", _freeze_metadata(self.admission))


@dataclass(frozen=True, slots=True)
class KindEffect:
    """Declared expected effect of a response kind."""

    kind: str
    valid: bool
    is_terminal: bool
    is_auth_loss: bool
    is_transient: bool
    is_redirect: bool
    action: str
    description: str = ""


# Declared per-kind effects table:
# Production references:
# - Auth loss: 401/403/302_login in pseg_client.py:2240-2255 (_raise_for_chart_auth raises PsegOktaSessionExpired)
# - Terminal: CAPTCHA/security_step in pseg_client.py:325, 330, 600-605, 627-635 (_latch_captcha, _security_step_latched)
# - Transient: 404, 429, 500, 503, timeout, connection in pseg_client.py:2050-2070, 2100-2115 (PsegTransientError)
# - Redirect: 307, 308 in pseg_client.py:230-265 (separate redirect hops preserving POST body)
KIND_EFFECTS: MappingProxyType[str, KindEffect] = MappingProxyType(
    {
        ResponseKind.VALID_SUCCESS: KindEffect(
            kind=ResponseKind.VALID_SUCCESS,
            valid=True,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=False,
            is_redirect=False,
            action="advance",
            description="Valid successful response",
        ),
        ResponseKind.HTTP_307: KindEffect(
            kind=ResponseKind.HTTP_307,
            valid=True,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=False,
            is_redirect=True,
            action="redirect_hop",
            description="Temporary redirect preserving POST body",
        ),
        ResponseKind.HTTP_308: KindEffect(
            kind=ResponseKind.HTTP_308,
            valid=True,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=False,
            is_redirect=True,
            action="redirect_hop",
            description="Permanent redirect preserving POST body",
        ),
        ResponseKind.HTTP_401: KindEffect(
            kind=ResponseKind.HTTP_401,
            valid=False,
            is_terminal=False,
            is_auth_loss=True,
            is_transient=False,
            is_redirect=False,
            action="auth_loss",
            description="HTTP 401 Unauthorized - session expired, renewal expected",
        ),
        ResponseKind.HTTP_403: KindEffect(
            kind=ResponseKind.HTTP_403,
            valid=False,
            is_terminal=False,
            is_auth_loss=True,
            is_transient=False,
            is_redirect=False,
            action="auth_loss",
            description="HTTP 403 Forbidden - session expired, renewal expected",
        ),
        ResponseKind.HTTP_302_LOGIN: KindEffect(
            kind=ResponseKind.HTTP_302_LOGIN,
            valid=False,
            is_terminal=False,
            is_auth_loss=True,
            is_transient=False,
            is_redirect=False,
            action="auth_loss",
            description="HTTP 302 Redirect to Login - session expired, renewal expected",
        ),
        ResponseKind.CAPTCHA: KindEffect(
            kind=ResponseKind.CAPTCHA,
            valid=False,
            is_terminal=True,
            is_auth_loss=True,
            is_transient=False,
            is_redirect=False,
            action="terminal_captcha",
            description="CAPTCHA required - terminal latch stops automatic auth",
        ),
        ResponseKind.SECURITY_STEP: KindEffect(
            kind=ResponseKind.SECURITY_STEP,
            valid=False,
            is_terminal=True,
            is_auth_loss=True,
            is_transient=False,
            is_redirect=False,
            action="terminal_security_step",
            description="Security step challenge - terminal latch stops automatic auth",
        ),
        ResponseKind.HTTP_404: KindEffect(
            kind=ResponseKind.HTTP_404,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="transient_error",
            description="HTTP 404 Not Found - transient route issue",
        ),
        ResponseKind.HTTP_429: KindEffect(
            kind=ResponseKind.HTTP_429,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="rate_limited",
            description="HTTP 429 Too Many Requests - transient backoff required",
        ),
        ResponseKind.HTTP_500: KindEffect(
            kind=ResponseKind.HTTP_500,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="transient_error",
            description="HTTP 500 Internal Server Error - transient outage",
        ),
        ResponseKind.HTTP_503: KindEffect(
            kind=ResponseKind.HTTP_503,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="transient_error",
            description="HTTP 503 Service Unavailable - transient outage",
        ),
        ResponseKind.TIMEOUT: KindEffect(
            kind=ResponseKind.TIMEOUT,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="transient_timeout",
            description="Network timeout - transient retry",
        ),
        ResponseKind.CONNECTION_ERROR: KindEffect(
            kind=ResponseKind.CONNECTION_ERROR,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="transient_connection_error",
            description="Connection error - transient retry",
        ),
        ResponseKind.MAINTENANCE: KindEffect(
            kind=ResponseKind.MAINTENANCE,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="maintenance",
            description="Portal maintenance page - unvalidated 200",
        ),
        ResponseKind.MISSING_TOKEN: KindEffect(
            kind=ResponseKind.MISSING_TOKEN,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="missing_token",
            description="Missing antiforgery token on dashboard",
        ),
        ResponseKind.UNRELATED: KindEffect(
            kind=ResponseKind.UNRELATED,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="unrelated_page",
            description="Unrelated HTML page served",
        ),
        ResponseKind.EMPTY: KindEffect(
            kind=ResponseKind.EMPTY,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="empty_payload",
            description="Empty response body",
        ),
        ResponseKind.ALL_INVALID: KindEffect(
            kind=ResponseKind.ALL_INVALID,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="all_invalid_series",
            description="Chart data with all invalid readings",
        ),
        ResponseKind.ROOT_ARRAY: KindEffect(
            kind=ResponseKind.ROOT_ARRAY,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="malformed_json",
            description="Root JSON array instead of object",
        ),
        ResponseKind.ROOT_STRING: KindEffect(
            kind=ResponseKind.ROOT_STRING,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="malformed_json",
            description="Root JSON string instead of object",
        ),
        ResponseKind.ROOT_NULL: KindEffect(
            kind=ResponseKind.ROOT_NULL,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="malformed_json",
            description="Root JSON null instead of object",
        ),
        ResponseKind.ROOT_NUMBER: KindEffect(
            kind=ResponseKind.ROOT_NUMBER,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="malformed_json",
            description="Root JSON number instead of object",
        ),
        ResponseKind.TRUNCATED_JSON: KindEffect(
            kind=ResponseKind.TRUNCATED_JSON,
            valid=False,
            is_terminal=False,
            is_auth_loss=False,
            is_transient=True,
            is_redirect=False,
            action="malformed_json",
            description="Truncated JSON payload causing decode error",
        ),
    }
)

AUTH_LOSS_RENEWAL_EXPECTATIONS: MappingProxyType[str, str] = MappingProxyType(
    {
        FlowMode.L: "expect_local_credential_renewal",
        FlowMode.R: "expect_remember_me_renewal",
        FlowMode.S: "expect_okta_sso_renewal",
        FlowMode.H: "expect_human_reauth",
    }
)


def lookup_kind_effect(reply: Reply, stage: str | None = None) -> KindEffect:
    """Look up declared effect of a reply without re-deriving policy dynamically."""
    kind = reply.metadata.get("kind")
    if kind and kind in KIND_EFFECTS:
        return KIND_EFFECTS[kind]

    # Explicit 307 / 308 redirects
    if reply.status_code == 307:
        return KIND_EFFECTS[ResponseKind.HTTP_307]
    if reply.status_code == 308:
        return KIND_EFFECTS[ResponseKind.HTTP_308]

    # Status-based kinds lookup
    if reply.status_code == 401:
        return KIND_EFFECTS[ResponseKind.HTTP_401]
    if reply.status_code == 403:
        return KIND_EFFECTS[ResponseKind.HTTP_403]
    if reply.status_code == 302:
        return KIND_EFFECTS[ResponseKind.HTTP_302_LOGIN]
    if reply.status_code == 404:
        return KIND_EFFECTS[ResponseKind.HTTP_404]
    if reply.status_code == 429:
        return KIND_EFFECTS[ResponseKind.HTTP_429]
    if reply.status_code == 500:
        return KIND_EFFECTS[ResponseKind.HTTP_500]
    if reply.status_code == 503:
        return KIND_EFFECTS[ResponseKind.HTTP_503]

    if reply.valid:
        return KIND_EFFECTS[ResponseKind.VALID_SUCCESS]

    return KIND_EFFECTS[ResponseKind.EMPTY]


@dataclass(frozen=True, slots=True)
class ExpectationState:
    """Immutable expectation state tracking systemic invariants and eligibility."""

    generation_id: str
    sequence: int = 0
    active_meters: tuple[str, ...] = ()
    expected_meters: tuple[str, ...] = ()
    latest_checkpoint: Checkpoint | None = None
    pending_session_jar: MappingProxyType[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )
    is_quarantined: bool = False
    settled_admission: MappingProxyType[str, Any] = field(
        default_factory=lambda: MappingProxyType({})
    )
    is_retired: bool = False
    is_terminal: bool = False
    is_human_rearmed: bool = False
    dashboard_validated: bool = False
    daily_validated: bool = False
    hourly_validated: bool = False
    daily_fallback_succeeded: bool = False
    history_events: tuple[str, ...] = ()
    validated_reply_ids: tuple[str, ...] = ()
    pending_renewal_expectation: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "pending_session_jar", _freeze_cookies(self.pending_session_jar))
        object.__setattr__(self, "settled_admission", _freeze_metadata(self.settled_admission))


def apply_step(
    state: ExpectationState,
    step: FlowStep,
    timestamp: float = 0.0,
) -> ExpectationState:
    """Apply a single step to an expectation state according to pure declared contracts."""
    new_seq = state.sequence + 1
    reply = step.reply

    # 1. Dispatch fence / Retirement check: zero new sends permitted once retired
    # Production ref: pseg_client.py:1020-1028 (_check_active_owner) and coordinator.py:666-668
    if state.is_retired:
        return ExpectationState(
            generation_id=state.generation_id,
            sequence=new_seq,
            active_meters=state.active_meters,
            expected_meters=state.expected_meters,
            latest_checkpoint=state.latest_checkpoint,
            pending_session_jar=state.pending_session_jar,
            is_quarantined=state.is_quarantined,
            settled_admission=state.settled_admission,
            is_retired=True,
            is_terminal=state.is_terminal,
            is_human_rearmed=state.is_human_rearmed,
            dashboard_validated=state.dashboard_validated,
            daily_validated=state.daily_validated,
            hourly_validated=state.hourly_validated,
            daily_fallback_succeeded=state.daily_fallback_succeeded,
            history_events=state.history_events
            + (f"violation:send_after_retire:{reply.reply_id}",),
            validated_reply_ids=state.validated_reply_ids,
            pending_renewal_expectation=state.pending_renewal_expectation,
        )

    # 2. Terminal latch fence: stops any automatic credential POST
    # Production ref: pseg_client.py:631-650 (_refuse_if_captcha_latched, _refuse_if_security_step_latched)
    if state.is_terminal and (
        step.stage in (Stage.LOGIN_FORM_GET, Stage.LOGIN_POST, Stage.SAML_ACS)
        or bool(reply.metadata.get("credential_post"))
    ):
        return ExpectationState(
            generation_id=state.generation_id,
            sequence=new_seq,
            active_meters=state.active_meters,
            expected_meters=state.expected_meters,
            latest_checkpoint=state.latest_checkpoint,
            pending_session_jar=state.pending_session_jar,
            is_quarantined=state.is_quarantined,
            settled_admission=state.settled_admission,
            is_retired=state.is_retired,
            is_terminal=True,
            is_human_rearmed=state.is_human_rearmed,
            dashboard_validated=state.dashboard_validated,
            daily_validated=state.daily_validated,
            hourly_validated=state.hourly_validated,
            daily_fallback_succeeded=state.daily_fallback_succeeded,
            history_events=state.history_events
            + (f"violation:credential_post_while_terminal:{reply.reply_id}",),
            validated_reply_ids=state.validated_reply_ids,
            pending_renewal_expectation="blocked_terminal_human_rearm_required",
        )

    # 3. Look up expected effect from declared per-kind table
    effect = lookup_kind_effect(reply, step.stage)

    # 4. Invalid / failed response handling:
    # Production ref: pseg_client.py:1014-1018 (_restore_cookie_leg) & coordinator.py:734-750 (_persist_confirmed_session)
    # The session jar rolls back to the pre-stage snapshot (quarantine). Checkpoint MUST NOT advance.
    if not effect.valid or not reply.valid:
        is_term = state.is_terminal or effect.is_terminal
        renewal_exp = state.pending_renewal_expectation
        if effect.is_terminal:
            renewal_exp = "blocked_terminal_human_rearm_required"
        elif effect.is_auth_loss:
            renewal_exp = AUTH_LOSS_RENEWAL_EXPECTATIONS.get(
                step.flow_mode, "expect_auth_loss_handling"
            )

        fallback_ok = state.daily_fallback_succeeded or (
            step.position == Position.OPTIONAL and state.daily_validated
        )

        return ExpectationState(
            generation_id=state.generation_id,
            sequence=new_seq,
            active_meters=state.active_meters,
            expected_meters=state.expected_meters,
            latest_checkpoint=state.latest_checkpoint,  # MUST NOT ADVANCE
            pending_session_jar=state.pending_session_jar,  # ROLLED BACK / QUARANTINED
            is_quarantined=True,  # QUARANTINE ACTIVE
            settled_admission=state.settled_admission,
            is_retired=state.is_retired,
            is_terminal=is_term,
            is_human_rearmed=state.is_human_rearmed,
            dashboard_validated=state.dashboard_validated,
            daily_validated=state.daily_validated,
            hourly_validated=state.hourly_validated,
            daily_fallback_succeeded=fallback_ok,
            history_events=state.history_events
            + (
                f"step_{new_seq}:{step.stage}:{reply.reply_id}:status={reply.status_code}:quarantined=True:terminal={is_term}",
            ),
            validated_reply_ids=state.validated_reply_ids,
            pending_renewal_expectation=renewal_exp,
        )

    # 5. Valid response handling:
    # A. Meter identity check (Production ref: pseg_client.py:999-1002 & 1515-1545)
    declared_meters = reply.metadata.get("meters")
    established_meters = state.expected_meters or state.active_meters

    if declared_meters and established_meters:
        if set(declared_meters).isdisjoint(set(established_meters)):
            # Meter identity mismatch! Production raises PsegTransientError / rejects confirmation.
            # Eligibility and checkpoint MUST NOT advance. Quarantined.
            return ExpectationState(
                generation_id=state.generation_id,
                sequence=new_seq,
                active_meters=state.active_meters,
                expected_meters=state.expected_meters,
                latest_checkpoint=state.latest_checkpoint,  # MUST NOT ADVANCE
                pending_session_jar=state.pending_session_jar,  # ROLLED BACK
                is_quarantined=True,
                settled_admission=state.settled_admission,
                is_retired=state.is_retired,
                is_terminal=state.is_terminal,
                is_human_rearmed=state.is_human_rearmed,
                dashboard_validated=state.dashboard_validated,
                daily_validated=state.daily_validated,
                hourly_validated=state.hourly_validated,
                daily_fallback_succeeded=state.daily_fallback_succeeded,
                history_events=state.history_events
                + (
                    f"violation:meter_identity_mismatch:{reply.reply_id}:declared={declared_meters}:expected={established_meters}",
                ),
                validated_reply_ids=state.validated_reply_ids,
                pending_renewal_expectation=state.pending_renewal_expectation,
            )

    new_active_meters = state.active_meters
    new_expected_meters = state.expected_meters
    if declared_meters:
        declared_tuple = tuple(declared_meters)
        if not established_meters:
            new_active_meters = declared_tuple
            new_expected_meters = declared_tuple
        else:
            new_active_meters = established_meters
            new_expected_meters = established_meters

    # B. Accumulate pending session jar across valid responses
    # Production ref: requests.Session cookie accumulation and pseg_client.py:477-484
    new_pending_jar = dict(state.pending_session_jar)
    if not new_pending_jar and state.latest_checkpoint:
        new_pending_jar.update(state.latest_checkpoint.jar)
    if reply.cookies:
        new_pending_jar.update(reply.cookies)

    new_validated_ids = state.validated_reply_ids + (reply.reply_id,)
    new_dashboard_val = state.dashboard_validated or (step.stage == Stage.DASHBOARD_VERIFY_TOKEN)
    new_daily_val = state.daily_validated or (step.stage == Stage.DAILY_CHART_DATA)
    new_hourly_val = state.hourly_validated or (step.stage == Stage.HOURLY_CHART_DATA)

    # C. Checkpoint determination:
    # Production ref:
    # - _confirm_login_dashboard / Mode H: dashboard verification checkpoints confirmed session
    # - _confirm_meter_identity / Mode L, R, S: requires Dashboard + Daily chart confirmation
    # - Hourly rotation: advances checkpoint with whole accumulated jar
    new_checkpoint = state.latest_checkpoint
    should_checkpoint = False

    if step.flow_mode == FlowMode.H and new_dashboard_val and reply.cookie_eligible:
        should_checkpoint = True
    elif step.stage == Stage.DAILY_CHART_DATA and new_dashboard_val and reply.cookie_eligible:
        should_checkpoint = True
    elif (
        step.stage == Stage.HOURLY_CHART_DATA
        and state.latest_checkpoint is not None
        and bool(reply.metadata.get("rotation"))
        and reply.cookie_eligible
    ):
        should_checkpoint = True
    elif (
        step.stage == Stage.HISTORY_CHUNK
        and state.latest_checkpoint is not None
        and bool(reply.metadata.get("rotation"))
        and reply.cookie_eligible
    ):
        should_checkpoint = True
    elif (
        new_dashboard_val
        and new_daily_val
        and state.latest_checkpoint is None
        and reply.cookie_eligible
    ):
        should_checkpoint = True

    if should_checkpoint:
        new_checkpoint = Checkpoint(
            generation_id=state.generation_id,
            sequence=new_seq,
            jar=MappingProxyType(new_pending_jar),
            admission=state.settled_admission,
            timestamp=timestamp,
        )

    # Valid confirmed checkpoint clears quarantine
    quarantine_active = False if should_checkpoint else state.is_quarantined

    return ExpectationState(
        generation_id=state.generation_id,
        sequence=new_seq,
        active_meters=new_active_meters,
        expected_meters=new_expected_meters,
        latest_checkpoint=new_checkpoint,
        pending_session_jar=MappingProxyType(new_pending_jar),
        is_quarantined=quarantine_active,
        settled_admission=state.settled_admission,
        is_retired=state.is_retired,
        is_terminal=state.is_terminal,
        is_human_rearmed=state.is_human_rearmed or bool(reply.metadata.get("human_rearm")),
        dashboard_validated=new_dashboard_val,
        daily_validated=new_daily_val,
        hourly_validated=new_hourly_val,
        daily_fallback_succeeded=state.daily_fallback_succeeded,
        history_events=state.history_events
        + (
            f"step_{new_seq}:{step.stage}:{reply.reply_id}:status={reply.status_code}:checkpoint_advanced={should_checkpoint}",
        ),
        validated_reply_ids=new_validated_ids,
        pending_renewal_expectation=state.pending_renewal_expectation,
    )


def apply_trace(
    initial_state: ExpectationState,
    trace: Sequence[FlowStep],
    base_timestamp: float = 1000.0,
) -> ExpectationState:
    """Apply an entire sequence of flow steps to the expectation state."""
    state = initial_state
    for i, step in enumerate(trace):
        state = apply_step(state, step, timestamp=base_timestamp + (i * 10.0))
    return state


def transition_reload(state: ExpectationState) -> ExpectationState:
    """Retire active generation due to config entry reload."""
    return ExpectationState(
        generation_id=state.generation_id,
        sequence=state.sequence + 1,
        active_meters=state.active_meters,
        expected_meters=state.expected_meters,
        latest_checkpoint=state.latest_checkpoint,
        pending_session_jar=state.pending_session_jar,
        is_quarantined=state.is_quarantined,
        settled_admission=state.settled_admission,
        is_retired=True,
        is_terminal=state.is_terminal,
        is_human_rearmed=state.is_human_rearmed,
        dashboard_validated=state.dashboard_validated,
        daily_validated=state.daily_validated,
        hourly_validated=state.hourly_validated,
        daily_fallback_succeeded=state.daily_fallback_succeeded,
        history_events=state.history_events + ("retired_by_reload",),
        validated_reply_ids=state.validated_reply_ids,
        pending_renewal_expectation=state.pending_renewal_expectation,
    )


def transition_unload(state: ExpectationState) -> ExpectationState:
    """Retire active generation due to config entry unload."""
    return ExpectationState(
        generation_id=state.generation_id,
        sequence=state.sequence + 1,
        active_meters=state.active_meters,
        expected_meters=state.expected_meters,
        latest_checkpoint=state.latest_checkpoint,
        pending_session_jar=state.pending_session_jar,
        is_quarantined=state.is_quarantined,
        settled_admission=state.settled_admission,
        is_retired=True,
        is_terminal=state.is_terminal,
        is_human_rearmed=state.is_human_rearmed,
        dashboard_validated=state.dashboard_validated,
        daily_validated=state.daily_validated,
        hourly_validated=state.hourly_validated,
        daily_fallback_succeeded=state.daily_fallback_succeeded,
        history_events=state.history_events + ("retired_by_unload",),
        validated_reply_ids=state.validated_reply_ids,
        pending_renewal_expectation=state.pending_renewal_expectation,
    )


def transition_stop(state: ExpectationState) -> ExpectationState:
    """Retire active generation due to Home Assistant stop."""
    return ExpectationState(
        generation_id=state.generation_id,
        sequence=state.sequence + 1,
        active_meters=state.active_meters,
        expected_meters=state.expected_meters,
        latest_checkpoint=state.latest_checkpoint,
        pending_session_jar=state.pending_session_jar,
        is_quarantined=state.is_quarantined,
        settled_admission=state.settled_admission,
        is_retired=True,
        is_terminal=state.is_terminal,
        is_human_rearmed=state.is_human_rearmed,
        dashboard_validated=state.dashboard_validated,
        daily_validated=state.daily_validated,
        hourly_validated=state.hourly_validated,
        daily_fallback_succeeded=state.daily_fallback_succeeded,
        history_events=state.history_events + ("retired_by_stop",),
        validated_reply_ids=state.validated_reply_ids,
        pending_renewal_expectation=state.pending_renewal_expectation,
    )


def transition_cold_restart(state: ExpectationState) -> ExpectationState:
    """Retire active generation due to cold restart."""
    return ExpectationState(
        generation_id=state.generation_id,
        sequence=state.sequence + 1,
        active_meters=state.active_meters,
        expected_meters=state.expected_meters,
        latest_checkpoint=state.latest_checkpoint,
        pending_session_jar=state.pending_session_jar,
        is_quarantined=state.is_quarantined,
        settled_admission=state.settled_admission,
        is_retired=True,
        is_terminal=state.is_terminal,
        is_human_rearmed=state.is_human_rearmed,
        dashboard_validated=state.dashboard_validated,
        daily_validated=state.daily_validated,
        hourly_validated=state.hourly_validated,
        daily_fallback_succeeded=state.daily_fallback_succeeded,
        history_events=state.history_events + ("retired_by_cold_restart",),
        validated_reply_ids=state.validated_reply_ids,
        pending_renewal_expectation=state.pending_renewal_expectation,
    )


def transition_human_rearm(
    state: ExpectationState,
    new_generation_id: str,
    same_cookie: bool,
    new_cookies: Mapping[str, str] | None = None,
    timestamp: float = 2000.0,
) -> tuple[ExpectationState, ExpectationState]:
    """Execute human rearm transition, retiring the old generation and establishing the new one.

    Returns: (retired_old_state, active_new_state)
    """
    # Retire old generation
    retired_old = ExpectationState(
        generation_id=state.generation_id,
        sequence=state.sequence + 1,
        active_meters=state.active_meters,
        expected_meters=state.expected_meters,
        latest_checkpoint=state.latest_checkpoint,
        pending_session_jar=state.pending_session_jar,
        is_quarantined=state.is_quarantined,
        settled_admission=state.settled_admission,
        is_retired=True,
        is_terminal=False,
        is_human_rearmed=False,
        dashboard_validated=state.dashboard_validated,
        daily_validated=state.daily_validated,
        hourly_validated=state.hourly_validated,
        daily_fallback_succeeded=state.daily_fallback_succeeded,
        history_events=state.history_events + ("retired_by_human_rearm",),
        validated_reply_ids=state.validated_reply_ids,
        pending_renewal_expectation=None,
    )

    # Establish new generation
    if same_cookie:
        jar = state.latest_checkpoint.jar if state.latest_checkpoint else MappingProxyType({})
    else:
        jar = _freeze_cookies(new_cookies or {})

    new_checkpoint = Checkpoint(
        generation_id=new_generation_id,
        sequence=1,
        jar=jar,
        admission=state.settled_admission,
        timestamp=timestamp,
    )

    active_new = ExpectationState(
        generation_id=new_generation_id,
        sequence=1,
        active_meters=state.active_meters,
        expected_meters=state.expected_meters,
        latest_checkpoint=new_checkpoint,
        pending_session_jar=jar,
        is_quarantined=False,
        settled_admission=state.settled_admission,
        is_retired=False,
        is_terminal=False,
        is_human_rearmed=True,
        dashboard_validated=True,
        daily_validated=True,
        hourly_validated=False,
        daily_fallback_succeeded=False,
        history_events=(f"started:{new_generation_id}:same_cookie={same_cookie}",),
        validated_reply_ids=(),
        pending_renewal_expectation=None,
    )

    return retired_old, active_new

"""Independent response corpus and vocabulary definitions for systemic testing.

Declared response specifications, error models, and expected outcomes completely
independent of production parsing, validation, or policy logic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from types import MappingProxyType
from typing import Any

from custom_components.pseg.const import PORTAL_BASE_URL

from .portal import Reply
from .synthetic import (
    build_synthetic_all_invalid_chart,
    build_synthetic_captcha_html,
    build_synthetic_cookies,
    build_synthetic_daily_chart,
    build_synthetic_dashboard_html,
    build_synthetic_hourly_chart,
    build_synthetic_login_form,
    build_synthetic_maintenance_html,
    build_synthetic_missing_token_html,
    build_synthetic_root_array,
    build_synthetic_root_null,
    build_synthetic_root_number,
    build_synthetic_root_string,
    build_synthetic_saml_acs,
    build_synthetic_security_step_html,
    build_synthetic_truncated_json,
    build_synthetic_unrelated_html,
    synth_id,
)


class Stage:
    """Stage vocabulary members."""

    DASHBOARD_VERIFY_TOKEN = "dashboard_verify_token"
    DAILY_CHART_DATA = "daily_chart_data"
    HOURLY_CHART = "hourly_chart"
    HOURLY_CHART_DATA = "hourly_chart_data"
    HISTORY_CHUNK = "history_chunk"
    LOGIN_FORM_GET = "login_form_get"
    SAML_ACS = "saml_acs"

    ALL = (
        DASHBOARD_VERIFY_TOKEN,
        DAILY_CHART_DATA,
        HOURLY_CHART,
        HOURLY_CHART_DATA,
        HISTORY_CHUNK,
        LOGIN_FORM_GET,
        SAML_ACS,
    )


class ResponseKind:
    """Response kind vocabulary members."""

    # Status / redirect kinds
    HTTP_401 = "401"
    HTTP_403 = "403"
    HTTP_302_LOGIN = "302_login"
    HTTP_307 = "307"
    HTTP_308 = "308"
    HTTP_404 = "404"
    HTTP_429 = "429"
    HTTP_500 = "500"
    HTTP_503 = "503"

    # Content / payload kinds
    MAINTENANCE = "maintenance"
    MISSING_TOKEN = "missing_token"
    UNRELATED = "unrelated"
    EMPTY = "empty"
    ALL_INVALID = "all_invalid"
    ROOT_ARRAY = "root_array"
    ROOT_STRING = "root_string"
    ROOT_NULL = "root_null"
    ROOT_NUMBER = "root_number"
    TRUNCATED_JSON = "truncated_json"

    # Transport error kinds
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"

    # Terminal challenge kinds
    CAPTCHA = "captcha"
    SECURITY_STEP = "security_step"

    # Positive control kind
    VALID_SUCCESS = "valid_success"

    ALL = (
        HTTP_401,
        HTTP_403,
        HTTP_302_LOGIN,
        HTTP_307,
        HTTP_308,
        HTTP_404,
        HTTP_429,
        HTTP_500,
        HTTP_503,
        MAINTENANCE,
        MISSING_TOKEN,
        UNRELATED,
        EMPTY,
        ALL_INVALID,
        ROOT_ARRAY,
        ROOT_STRING,
        ROOT_NULL,
        ROOT_NUMBER,
        TRUNCATED_JSON,
        TIMEOUT,
        CONNECTION_ERROR,
        CAPTCHA,
        SECURITY_STEP,
        VALID_SUCCESS,
    )


class HttpStatus:
    """HTTP status code vocabulary members."""

    STATUS_200 = 200
    STATUS_302 = 302
    STATUS_307 = 307
    STATUS_308 = 308
    STATUS_401 = 401
    STATUS_403 = 403
    STATUS_404 = 404
    STATUS_429 = 429
    STATUS_500 = 500
    STATUS_503 = 503

    ALL = (
        STATUS_200,
        STATUS_302,
        STATUS_307,
        STATUS_308,
        STATUS_401,
        STATUS_403,
        STATUS_404,
        STATUS_429,
        STATUS_500,
        STATUS_503,
    )


class CookieKind:
    """Cookie kind vocabulary members."""

    NONE = "none"
    SID = "sid"
    REMEMBER_ME = "remember_me"
    AUX = "aux"

    ALL = (NONE, SID, REMEMBER_ME, AUX)


class Position:
    """Position vocabulary members."""

    PRE_PROOF = "pre_proof"
    POST_PROOF = "post_proof"
    OPTIONAL = "optional"

    ALL = (PRE_PROOF, POST_PROOF, OPTIONAL)


class FlowMode:
    """Flow mode vocabulary members."""

    L = "L"  # Local email/password
    R = "R"  # RememberMe renewal
    S = "S"  # Legacy SSO
    H = "H"  # Human reauth / CAPTCHA

    ALL = (L, R, S, H)


VOCABULARY = MappingProxyType(
    {
        "stages": Stage.ALL,
        "kinds": ResponseKind.ALL,
        "statuses": HttpStatus.ALL,
        "cookie_kinds": CookieKind.ALL,
        "positions": Position.ALL,
        "flow_modes": FlowMode.ALL,
    }
)


@dataclass(frozen=True, slots=True)
class ExpectedOutcome:
    """Declared expected outcome specification for an HTTP interaction."""

    valid: bool
    cookie_eligible: bool
    action: str
    error_type: str | None = None
    is_transient: bool = False
    is_terminal: bool = False
    description: str = ""


@dataclass(frozen=True, slots=True)
class PositiveControl:
    """A verified valid positive control paired with a vocabulary member."""

    category: str
    member: Any
    reply: Reply | Any
    expected_outcome: ExpectedOutcome
    is_positive_control: bool = True

    @property
    def expected_valid(self) -> bool:
        return self.expected_outcome.valid


@dataclass(frozen=True, slots=True)
class ExclusionRule:
    """Declared exclusion rule with reason."""

    category: str
    member: Any
    context: str
    reason: str


EXCLUSION_RULES = (
    ExclusionRule(
        category="stages",
        member=Stage.LOGIN_FORM_GET,
        context="mode:S",
        reason="SSO mode uses Okta SAML SignIn endpoint, not the local MyMeter login form GET.",
    ),
    ExclusionRule(
        category="stages",
        member=Stage.SAML_ACS,
        context="mode:L",
        reason="Local mode authenticates via /Home/Login POST, not Okta SAML ACS autopost.",
    ),
    ExclusionRule(
        category="stages",
        member=Stage.SAML_ACS,
        context="mode:R",
        reason="Remember-Me mode bypasses Okta and uses portal RememberMe cookie directly.",
    ),
    ExclusionRule(
        category="positions",
        member=Position.OPTIONAL,
        context="stage:dashboard_verify_token",
        reason="Dashboard verification is a mandatory authentication gateway, never an optional leg.",
    ),
    ExclusionRule(
        category="positions",
        member=Position.OPTIONAL,
        context="stage:daily_chart_data",
        reason="Daily chart data is mandatory for statistics authority and cannot be marked optional.",
    ),
    ExclusionRule(
        category="kinds",
        member=ResponseKind.HTTP_307,
        context="stage:login_form_get",
        reason="GET requests do not preserve credentials via 307 re-POST; 307 applies to POST bodies only.",
    ),
    ExclusionRule(
        category="kinds",
        member=ResponseKind.HTTP_308,
        context="stage:login_form_get",
        reason="GET requests do not preserve credentials via 308 re-POST; 308 applies to POST bodies only.",
    ),
    ExclusionRule(
        category="cookie_kinds",
        member=CookieKind.REMEMBER_ME,
        context="mode:S",
        reason="SSO mode relies solely on Okta idx/sid cookies; portal RememberMe cookie is not used.",
    ),
    ExclusionRule(
        category="kinds",
        member=ResponseKind.TRUNCATED_JSON,
        context="stage:dashboard_verify_token",
        reason="Dashboard returns HTML, not JSON; truncated JSON is only applicable to chart endpoints.",
    ),
    ExclusionRule(
        category="kinds",
        member=ResponseKind.ROOT_ARRAY,
        context="stage:dashboard_verify_token",
        reason="Dashboard endpoint returns HTML document, not JSON array.",
    ),
    ExclusionRule(
        category="kinds",
        member=ResponseKind.CAPTCHA,
        context="stage:daily_chart_data",
        reason="CAPTCHA challenge occurs on portal gateway/login pages, not data chart endpoints.",
    ),
    ExclusionRule(
        category="kinds",
        member=ResponseKind.SECURITY_STEP,
        context="stage:daily_chart_data",
        reason="Security step challenge occurs during authentication, not data chart endpoints.",
    ),
)


def is_applicable(category: str, member: Any, context: str) -> tuple[bool, str]:
    """Check if a vocabulary member is applicable in the given context."""
    for rule in EXCLUSION_RULES:
        if (
            rule.category == category
            and str(rule.member) == str(member)
            and rule.context in context
        ):
            return False, rule.reason
    return True, "Applicable"


# ---------------------------------------------------------------------------
# Synthetic builders for Stages
# ---------------------------------------------------------------------------


def build_stage_reply(stage: str, valid: bool = True, **kwargs: Any) -> Reply:
    """Build a synthetic Reply for a given stage."""
    rid = synth_id(f"REP_{stage.upper()[:10]}")
    cookies = build_synthetic_cookies("sid")
    hdrs = dict(kwargs.get("headers", {}))

    if stage == Stage.DASHBOARD_VERIFY_TOKEN:
        body = build_synthetic_dashboard_html() if valid else build_synthetic_maintenance_html()
        hdrs.setdefault("Content-Type", "text/html; charset=utf-8")
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=body,
            cookies=cookies if valid else {},
            valid=valid,
            cookie_eligible=valid,
            metadata={"stage": stage, "meters": ("SYNTH_METER_001",)},
        )

    if stage == Stage.DAILY_CHART_DATA:
        body = (
            json.dumps(build_synthetic_daily_chart())
            if valid
            else json.dumps(build_synthetic_root_array())
        )
        hdrs.setdefault("Content-Type", "application/json")
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=body,
            cookies=cookies if valid else {},
            valid=valid,
            cookie_eligible=valid,
            metadata={"stage": stage, "meters": ("SYNTH_METER_001",)},
        )

    if stage == Stage.HOURLY_CHART:
        # POST /Dashboard/Chart setup
        hdrs.setdefault("Content-Type", "text/plain")
        return Reply(
            reply_id=rid,
            status_code=200 if valid else 500,
            headers=hdrs,
            body="ok" if valid else "error",
            cookies=cookies if valid else {},
            valid=valid,
            cookie_eligible=valid,
            metadata={"stage": stage},
        )

    if stage == Stage.HOURLY_CHART_DATA:
        body = (
            json.dumps(build_synthetic_hourly_chart())
            if valid
            else json.dumps(build_synthetic_all_invalid_chart())
        )
        hdrs.setdefault("Content-Type", "application/json")
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=body,
            cookies=cookies if valid else {},
            valid=valid,
            cookie_eligible=valid,
            metadata={"stage": stage, "meters": ("SYNTH_METER_001",)},
        )

    if stage == Stage.HISTORY_CHUNK:
        body = (
            json.dumps(build_synthetic_daily_chart())
            if valid
            else json.dumps(build_synthetic_root_null())
        )
        hdrs.setdefault("Content-Type", "application/json")
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=body,
            cookies=cookies if valid else {},
            valid=valid,
            cookie_eligible=valid,
            metadata={"stage": stage, "meters": ("SYNTH_METER_001",)},
        )

    if stage == Stage.LOGIN_FORM_GET:
        body = build_synthetic_login_form() if valid else build_synthetic_missing_token_html()
        hdrs.setdefault("Content-Type", "text/html; charset=utf-8")
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=body,
            cookies=cookies if valid else {},
            valid=valid,
            cookie_eligible=valid,
            metadata={"stage": stage},
        )

    if stage == Stage.SAML_ACS:
        body = build_synthetic_saml_acs(success=valid)
        hdrs.setdefault("Content-Type", "text/html; charset=utf-8")
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=body,
            cookies=cookies if valid else {},
            valid=valid,
            cookie_eligible=valid,
            metadata={"stage": stage},
        )

    raise ValueError(f"Unknown stage: {stage}")


# ---------------------------------------------------------------------------
# Synthetic builders for Kinds
# ---------------------------------------------------------------------------


def build_kind_reply(kind: str, stage: str = Stage.DASHBOARD_VERIFY_TOKEN) -> Reply:
    """Build a synthetic Reply for a given response kind."""
    rid = synth_id(f"REP_{kind.upper()[:10]}")
    hdrs: dict[str, Any] = {}

    if kind == ResponseKind.VALID_SUCCESS:
        return build_stage_reply(stage, valid=True)

    if kind == ResponseKind.HTTP_401:
        return Reply(
            reply_id=rid,
            status_code=401,
            body="Unauthorized",
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_401},
        )

    if kind == ResponseKind.HTTP_403:
        return Reply(
            reply_id=rid,
            status_code=403,
            body="Forbidden",
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_403},
        )

    if kind == ResponseKind.HTTP_302_LOGIN:
        hdrs["Location"] = f"{PORTAL_BASE_URL}/Home/Login"
        return Reply(
            reply_id=rid,
            status_code=302,
            headers=hdrs,
            body="Redirect to Login",
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_302_LOGIN},
        )

    if kind == ResponseKind.HTTP_307:
        hdrs["Location"] = f"{PORTAL_BASE_URL}/Landing"
        return Reply(
            reply_id=rid,
            status_code=307,
            headers=hdrs,
            body="Temporary Redirect",
            valid=True,
            cookie_eligible=True,
            metadata={"kind": ResponseKind.HTTP_307},
        )

    if kind == ResponseKind.HTTP_308:
        hdrs["Location"] = f"{PORTAL_BASE_URL}/Landing"
        return Reply(
            reply_id=rid,
            status_code=308,
            headers=hdrs,
            body="Permanent Redirect",
            valid=True,
            cookie_eligible=True,
            metadata={"kind": ResponseKind.HTTP_308},
        )

    if kind == ResponseKind.HTTP_404:
        return Reply(
            reply_id=rid,
            status_code=404,
            body="Not Found",
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_404},
        )

    if kind == ResponseKind.HTTP_429:
        return Reply(
            reply_id=rid,
            status_code=429,
            body="Too Many Requests",
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_429},
        )

    if kind == ResponseKind.HTTP_500:
        return Reply(
            reply_id=rid,
            status_code=500,
            body="Internal Server Error",
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_500},
        )

    if kind == ResponseKind.HTTP_503:
        return Reply(
            reply_id=rid,
            status_code=503,
            body="Service Unavailable",
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.HTTP_503},
        )

    if kind == ResponseKind.MAINTENANCE:
        hdrs["Content-Type"] = "text/html"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_maintenance_html(),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.MISSING_TOKEN:
        hdrs["Content-Type"] = "text/html"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_missing_token_html(),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.UNRELATED:
        hdrs["Content-Type"] = "text/html"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_unrelated_html(),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.EMPTY:
        return Reply(reply_id=rid, status_code=200, body="", valid=False, cookie_eligible=False)

    if kind == ResponseKind.ALL_INVALID:
        hdrs["Content-Type"] = "application/json"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=json.dumps(build_synthetic_all_invalid_chart()),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.ROOT_ARRAY:
        hdrs["Content-Type"] = "application/json"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=json.dumps(build_synthetic_root_array()),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.ROOT_STRING:
        hdrs["Content-Type"] = "application/json"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_root_string(),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.ROOT_NULL:
        hdrs["Content-Type"] = "application/json"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_root_null(),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.ROOT_NUMBER:
        hdrs["Content-Type"] = "application/json"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_root_number(),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.TRUNCATED_JSON:
        hdrs["Content-Type"] = "application/json"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_truncated_json(),
            valid=False,
            cookie_eligible=False,
        )

    if kind == ResponseKind.TIMEOUT:
        return Reply(
            reply_id=rid,
            status_code=0,
            body="",
            valid=False,
            cookie_eligible=False,
            metadata={"error": "requests.exceptions.Timeout"},
        )

    if kind == ResponseKind.CONNECTION_ERROR:
        return Reply(
            reply_id=rid,
            status_code=0,
            body="",
            valid=False,
            cookie_eligible=False,
            metadata={
                "kind": ResponseKind.CONNECTION_ERROR,
                "error": "requests.exceptions.ConnectionError",
            },
        )

    if kind == ResponseKind.CAPTCHA:
        hdrs["Content-Type"] = "text/html"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_captcha_html(),
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.CAPTCHA, "is_terminal": True},
        )

    if kind == ResponseKind.SECURITY_STEP:
        hdrs["Content-Type"] = "text/html"
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=hdrs,
            body=build_synthetic_security_step_html(),
            valid=False,
            cookie_eligible=False,
            metadata={"kind": ResponseKind.SECURITY_STEP, "is_terminal": True},
        )

    raise ValueError(f"Unknown kind: {kind}")


# ---------------------------------------------------------------------------
# Synthetic builders for Statuses
# ---------------------------------------------------------------------------


def build_status_reply(status: int, stage: str = Stage.DASHBOARD_VERIFY_TOKEN) -> Reply:
    """Build a synthetic Reply for a given HTTP status code."""
    rid = synth_id(f"REP_ST_{status}")
    hdrs: dict[str, Any] = {}

    if status in (302, 307, 308):
        hdrs["Location"] = f"{PORTAL_BASE_URL}/Target"
        # 307/308 in legitimate flow can be valid redirect hops
        return Reply(
            reply_id=rid,
            status_code=status,
            headers=hdrs,
            body=f"HTTP {status} Redirect",
            valid=status in (307, 308),
            cookie_eligible=status in (307, 308),
        )

    if status == 200:
        return build_stage_reply(stage, valid=True)

    return Reply(
        reply_id=rid,
        status_code=status,
        body=f"HTTP {status} Response",
        valid=False,
        cookie_eligible=False,
        metadata={"status": status},
    )


# ---------------------------------------------------------------------------
# Synthetic builders for Cookie Kinds
# ---------------------------------------------------------------------------


def build_cookie_kind_reply(cookie_kind: str, stage: str = Stage.DASHBOARD_VERIFY_TOKEN) -> Reply:
    """Build a synthetic Reply with the specified cookie kind."""
    cookies = build_synthetic_cookies(cookie_kind)
    rid = synth_id(f"REP_CK_{cookie_kind}")
    # none cookie jar is not eligible for persistent session jar
    eligible = cookie_kind != CookieKind.NONE
    reply = build_stage_reply(stage, valid=True)
    return Reply(
        reply_id=rid,
        status_code=reply.status_code,
        headers=reply.headers,
        body=reply.body,
        cookies=cookies,
        valid=True,
        cookie_eligible=eligible,
        metadata={"cookie_kind": cookie_kind},
    )


# ---------------------------------------------------------------------------
# Synthetic builders for Positions
# ---------------------------------------------------------------------------


def build_position_reply(position: str, stage: str = Stage.DASHBOARD_VERIFY_TOKEN) -> Reply:
    """Build a synthetic Reply for a given lifecycle position."""
    rid = synth_id(f"REP_POS_{position}")
    if position == Position.PRE_PROOF:
        # Pre-proof response before authentication proof
        return Reply(
            reply_id=rid,
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=build_synthetic_login_form(),
            cookies={},
            valid=True,
            cookie_eligible=False,
            metadata={"position": position},
        )
    if position == Position.POST_PROOF:
        # Confirmed authenticated response
        reply = build_stage_reply(stage, valid=True)
        return Reply(
            reply_id=rid,
            status_code=200,
            headers=reply.headers,
            body=reply.body,
            cookies=reply.cookies,
            valid=True,
            cookie_eligible=True,
            metadata={"position": position},
        )
    if position == Position.OPTIONAL:
        # Optional follow-on response (hourly leg)
        return build_stage_reply(Stage.HOURLY_CHART_DATA, valid=True)

    raise ValueError(f"Unknown position: {position}")


# ---------------------------------------------------------------------------
# Registry: Synthetic Builders, Expected Outcomes, Positive Controls
# ---------------------------------------------------------------------------


def get_synthetic_builder(category: str, member: Any) -> Callable[[], Any]:
    """Retrieve the synthetic builder for any vocabulary category and member."""
    if category == "stages":
        return lambda m=member: build_stage_reply(m, valid=True)
    if category == "kinds":
        return lambda m=member: build_kind_reply(m)
    if category == "statuses":
        return lambda m=member: build_status_reply(int(m))
    if category == "cookie_kinds":
        return lambda m=member: build_cookie_kind_reply(m)
    if category == "positions":
        return lambda m=member: build_position_reply(m)
    if category == "flow_modes":
        from .flows import get_flow_mode_builder

        return get_flow_mode_builder(member)
    raise KeyError(f"Unknown category: {category}")


def get_expected_outcome(category: str, member: Any) -> ExpectedOutcome:
    """Retrieve explicit expected outcome for any vocabulary category and member."""
    if category == "stages":
        return ExpectedOutcome(
            valid=True,
            cookie_eligible=True,
            action="advance_stage",
            description=f"Stage {member} successfully processed and validated.",
        )
    if category == "kinds":
        if member == ResponseKind.VALID_SUCCESS:
            return ExpectedOutcome(
                valid=True,
                cookie_eligible=True,
                action="advance",
                description="Valid success response",
            )
        if member in (ResponseKind.HTTP_307, ResponseKind.HTTP_308):
            return ExpectedOutcome(
                valid=True,
                cookie_eligible=True,
                action="follow_redirect",
                description="Legitimate redirect hop",
            )
        if member in (ResponseKind.HTTP_401, ResponseKind.HTTP_403, ResponseKind.HTTP_302_LOGIN):
            return ExpectedOutcome(
                valid=False,
                cookie_eligible=False,
                action="auth_failure",
                is_terminal=False,
                error_type="auth_loss",
                description="Auth loss / renewal expected (not terminal latch)",
            )
        if member in (ResponseKind.CAPTCHA, ResponseKind.SECURITY_STEP):
            return ExpectedOutcome(
                valid=False,
                cookie_eligible=False,
                action="terminal_challenge",
                is_terminal=True,
                error_type="terminal_step",
                description="Terminal CAPTCHA/security challenge - stops automatic auth until human rearm",
            )
        if member in (
            ResponseKind.HTTP_500,
            ResponseKind.HTTP_503,
            ResponseKind.TIMEOUT,
            ResponseKind.CONNECTION_ERROR,
        ):
            return ExpectedOutcome(
                valid=False,
                cookie_eligible=False,
                action="retry_transient",
                is_transient=True,
                error_type="transient",
                description="Transient server outage",
            )
        if member == ResponseKind.HTTP_429:
            return ExpectedOutcome(
                valid=False,
                cookie_eligible=False,
                action="rate_limited",
                is_transient=True,
                error_type="transient",
                description="Rate limited",
            )
        return ExpectedOutcome(
            valid=False,
            cookie_eligible=False,
            action="reject_invalid_data",
            error_type="malformed",
            description=f"Rejected {member} payload",
        )

    if category == "statuses":
        st = int(member)
        if st == 200:
            return ExpectedOutcome(
                valid=True, cookie_eligible=True, action="accept_200", description="HTTP 200 OK"
            )
        if st in (307, 308):
            return ExpectedOutcome(
                valid=True,
                cookie_eligible=True,
                action="redirect",
                description="Preserving redirect",
            )
        if st in (401, 403, 302):
            return ExpectedOutcome(
                valid=False,
                cookie_eligible=False,
                action="auth_required",
                is_terminal=False,
                description="Auth error (not terminal latch)",
            )
        return ExpectedOutcome(
            valid=False,
            cookie_eligible=False,
            action="status_error",
            is_transient=st in (429, 500, 503),
            description=f"HTTP {st} error",
        )

    if category == "cookie_kinds":
        if member == CookieKind.NONE:
            return ExpectedOutcome(
                valid=True,
                cookie_eligible=False,
                action="unauthenticated",
                description="Empty cookie jar cannot persist",
            )
        return ExpectedOutcome(
            valid=True,
            cookie_eligible=True,
            action="persist_eligible",
            description=f"Cookie kind {member} eligible for persistence",
        )

    if category == "positions":
        if member == Position.PRE_PROOF:
            return ExpectedOutcome(
                valid=True,
                cookie_eligible=False,
                action="establish_proof",
                description="Pre-proof cannot establish persistent session",
            )
        if member == Position.POST_PROOF:
            return ExpectedOutcome(
                valid=True,
                cookie_eligible=True,
                action="checkpoint_advance",
                description="Post-proof advances checkpoint",
            )
        return ExpectedOutcome(
            valid=True,
            cookie_eligible=True,
            action="optional_enrichment",
            description="Optional leg failure falls back cleanly",
        )

    if category == "flow_modes":
        from .flows import get_flow_mode_outcome

        return get_flow_mode_outcome(member)

    raise KeyError(f"Unknown category: {category}")


def get_positive_control(category: str, member: Any) -> PositiveControl:
    """Retrieve a verified valid positive control for any vocabulary member."""
    outcome = ExpectedOutcome(
        valid=True,
        cookie_eligible=True,
        action="positive_control_verified",
        description=f"Positive control for {category}:{member}",
    )

    if category == "stages":
        reply = build_stage_reply(member, valid=True)
        return PositiveControl(
            category=category, member=member, reply=reply, expected_outcome=outcome
        )

    if category == "kinds":
        reply = build_kind_reply(ResponseKind.VALID_SUCCESS)
        return PositiveControl(
            category=category, member=member, reply=reply, expected_outcome=outcome
        )

    if category == "statuses":
        reply = build_status_reply(HttpStatus.STATUS_200)
        return PositiveControl(
            category=category, member=member, reply=reply, expected_outcome=outcome
        )

    if category == "cookie_kinds":
        reply = build_cookie_kind_reply(CookieKind.SID)
        return PositiveControl(
            category=category, member=member, reply=reply, expected_outcome=outcome
        )

    if category == "positions":
        reply = build_position_reply(Position.POST_PROOF)
        return PositiveControl(
            category=category, member=member, reply=reply, expected_outcome=outcome
        )

    if category == "flow_modes":
        from .flows import get_flow_mode_positive_control

        return get_flow_mode_positive_control(member)

    raise KeyError(f"Unknown category: {category}")

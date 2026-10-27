"""G3 response-corpus cases for the P2-08 pairwise sweep.

Executable cases come from the checked-in covering
(``tests/systemic/response_covering.json``): every row names a stage, response
kind, cookie, position, flow, event and family.

``client``
    The declared reply is served to a **real standalone PsegClient** call (a raw
    next-request boundary): from the ACTUAL next-request Cookie headers it proves
    a failed/invalid reply's unique cookie is never carried again, and that
    parsing never leaks an untyped error (root-200 bodies reach typed PsegError).
    The exported jar then seeds a real HA entry; the shared ``run_case`` follow-on
    proves no later poll or cold restart resurrects the value.

``ha``
    The same reply inside a real HA lifecycle operation proves physical
    persistence cannot advance from an unvalidated reply (I4/I5), failures add no
    statistics rows or journal clear (I12), and the follow-on stays clean.

The mandatory findings (307/308 re-POST, healthy hourly rotation, auth-on-hourly
versus non-auth daily fallback, one follow-on-only post-proof poison, and the SSO
keepalive ACS relay) are covering rows here. The login handshake keeps both real
requests: ``login_form_get`` is ``GET /``, ``login_post`` is ``POST /Home/Login``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import dataclasses
from dataclasses import dataclass
import hashlib
from http.cookies import SimpleCookie
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests

from custom_components.pseg.const import DOMAIN, OKTA_HOST, PORTAL_BASE_URL
from custom_components.pseg.pseg_client import PsegClient, PsegError
from tests.support.boundaries import (
    BACKFILL_END,
    BACKFILL_START,
    LOGIN_HTML,
    METER_ID,
    create_flow_entry,
    register_initial_jar,
    register_scripted_eligibility,
    replace_route,
    script_portal,
)
from tests.support.corpus import (
    CookieKind,
    FlowMode,
    Position,
    ResponseKind,
    Stage,
    build_kind_reply,
)
from tests.support.expectation import Checkpoint, ExpectationState, apply_step
from tests.support.factory import ClientFactory, ClientRegistry
from tests.support.flows import FlowStep
from tests.support.lifecycle import LifecycleDriver, Snapshot, run_case
from tests.support.oracle import Oracle
from tests.support.portal import Dispatch, Reply, ScriptedPortal
from tests.support.synthetic import build_synthetic_daily_chart, build_synthetic_hourly_chart

PORTAL = PORTAL_BASE_URL

TRANSPORT_KINDS = (ResponseKind.TIMEOUT, ResponseKind.CONNECTION_ERROR)
ROOT_KINDS = (
    ResponseKind.ROOT_ARRAY,
    ResponseKind.ROOT_STRING,
    ResponseKind.ROOT_NULL,
    ResponseKind.ROOT_NUMBER,
    ResponseKind.TRUNCATED_JSON,
)
TERMINAL_KINDS = (ResponseKind.CAPTCHA, ResponseKind.SECURITY_STEP)
AUTH_LOSS_KINDS = (ResponseKind.HTTP_401, ResponseKind.HTTP_403, ResponseKind.HTTP_302_LOGIN)

#: Durable terminal reasons the declared challenge kinds settle in the admission.
#: Production literals: const.py ``AUTH_REASON_CAPTCHA_REQUIRED`` ("captcha_required",
#: :74) and ``AUTH_REASON_SECURITY_STEP`` ("security_step", :78); the client marks
#: them at pseg_client.py:648,662 and 1160,1163.
TERMINAL_ADMISSION_REASONS: Mapping[str, str] = MappingProxyType(
    {
        ResponseKind.CAPTCHA: "captcha_required",
        ResponseKind.SECURITY_STEP: "security_step",
    }
)

#: Fields of a settled renewal admission, declared by renewal_admission.py:80-147.
#: A durable admission that was never settled (an entry that had no renewal metadata
#: yet) settles to this zero form on its first policy finish.
SETTLED_ADMISSION_DEFAULTS: Mapping[str, Any] = MappingProxyType(
    {
        "sequences": 0,
        "last_sequence_at": None,
        "terminal_reason": None,
        "retry_eligible": False,
    }
)

#: A declared redirect carrying cookies is a handshake hop, not a login bounce.
DECLARED_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


COOKIE_NAMES: Mapping[str, str | None] = MappingProxyType(
    {
        CookieKind.NONE: None,
        CookieKind.SID: "MM_SID",
        CookieKind.REMEMBER_ME: "MM_RememberMe",
        CookieKind.AUX: "MM_AuxUtil",
    }
)

INITIAL_JARS: Mapping[str, tuple[dict[str, Any], ...]] = MappingProxyType(
    {
        FlowMode.L: (
            {
                "name": "MM_SID",
                "value": "SYNTH_G3_LOCAL_SID",
                "domain": "mysmartenergy.nj.pseg.com",
                "path": "/",
                "secure": True,
            },
        ),
        FlowMode.R: (
            {
                "name": "MM_RememberMe",
                "value": "SYNTH_G3_REMEMBERME",
                "domain": "mysmartenergy.nj.pseg.com",
                "path": "/",
                "secure": True,
            },
        ),
        FlowMode.S: (
            {
                "name": "idx",
                "value": "SYNTH_G3_OKTA_IDX",
                "domain": OKTA_HOST,
                "path": "/",
                "secure": True,
            },
        ),
        FlowMode.H: (
            {
                "name": "MM_SID",
                "value": "SYNTH_G3_HUMAN_SID",
                "domain": "mysmartenergy.nj.pseg.com",
                "path": "/",
                "secure": True,
            },
            {
                "name": "idx",
                "value": "SYNTH_G3_HUMAN_IDX",
                "domain": OKTA_HOST,
                "path": "/",
                "secure": True,
            },
        ),
    }
)

STAGE_PATHS: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        Stage.DASHBOARD_VERIFY_TOKEN: ("GET", "/Dashboard"),
        Stage.DAILY_CHART_DATA: ("GET", "/Dashboard/ChartData"),
        Stage.HOURLY_CHART: ("POST", "/Dashboard/Chart"),
        Stage.HOURLY_CHART_DATA: ("GET", "/Dashboard/ChartData"),
        Stage.HISTORY_CHUNK: ("GET", "/Dashboard/ChartData"),
        Stage.LOGIN_FORM_GET: ("GET", "/"),
        Stage.LOGIN_POST: ("POST", "/Home/Login"),
        Stage.SAML_ACS: ("POST", "/Saml/okta-prod/Acs"),
    }
)

HEALTHY_CHART = Reply.ok(body="{}", reply_id="SYNTH_G3_CHART_HEALTHY")
HEALTHY_DAILY = Reply.ok(
    body=(
        '{"Data": {"series": [{"name": "Meter #12345678", '
        '"data": [{"y": 1.5, "x": 1729382400000, "hs": {"start": "10/20/2026"}}]}]}}'
    ),
    reply_id="SYNTH_G3_DAILY_HEALTHY",
)
LANDING_REPLY = Reply.ok(body="<html>Landing</html>", reply_id="SYNTH_G3_LANDING")
HEALTHY_DASHBOARD = Reply.ok(
    body=(
        "<html><head><title>Dashboard</title></head><body>"
        '<input name="__RequestVerificationToken" value="SYNTH_G3_TOKEN"/>'
        "Dashboard</body></html>"
    ),
    reply_id="SYNTH_G3_DASHBOARD_HEALTHY",
)
HEALTHY_LOGIN_FORM = Reply.ok(body=LOGIN_HTML, reply_id="SYNTH_G3_LOGIN_FORM_HEALTHY")
DASHBOARD_BOUNCE = (
    Reply.redirect(location=f"{PORTAL}/", status_code=302),
    HEALTHY_DASHBOARD,
)


class ResponseCasePortal(ScriptedPortal):
    """Scripted transport that also raises the declared transport error kinds.

    P2-03 corpus declares ``timeout``/``connection_error`` as real transport
    errors. ``requests`` only produces them by raising from the adapter, so the
    declared reply raises here (after the attempted send was recorded and its
    cookies quarantined by the base class). No network, no production edit.

    Every reply this portal can serve is recorded in ``declared`` when it is
    scripted, so the independent expectation can replay the *declaration* of each
    consumed request instead of reading the persisted result it is checking.
    """

    def __init__(self) -> None:
        super().__init__()
        self.declared: dict[str, Reply] = {}

    def script(self, route: Any, reply_or_replies: Any) -> None:
        replies = (
            list(reply_or_replies)
            if isinstance(reply_or_replies, (list, tuple))
            else [reply_or_replies]
        )
        for reply in replies:
            self.declared[reply.reply_id] = reply
        super().script(route, reply_or_replies)

    def _build_response(
        self,
        request: requests.PreparedRequest,
        reply: Reply,
    ) -> requests.Response:
        error = reply.metadata.get("error")
        if error == "requests.exceptions.Timeout":
            raise requests.exceptions.Timeout(f"scripted timeout for reply {reply.reply_id}")
        if error == "requests.exceptions.ConnectionError":
            raise requests.exceptions.ConnectionError(
                f"scripted connection error for reply {reply.reply_id}"
            )
        return super()._build_response(request, reply)


# ---------------------------------------------------------------------------
# Case model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResponseCase:
    """One G3 covering row executed as a client or HA case."""

    case_id: str
    stage: str
    kind: str
    cookie: str
    position: str
    flow: str
    event: str
    family: str
    tier: str
    note: str = ""

    @property
    def poison(self) -> str:
        """Unique synthetic cookie value this case's reply declares."""
        digest = hashlib.sha256(self.case_id.encode()).hexdigest()[:10].upper()
        return f"SYNTH_G3_POISON_{digest}"

    @property
    def cookie_name(self) -> str | None:
        return COOKIE_NAMES[self.cookie]

    @property
    def reply_id(self) -> str:
        digest = hashlib.sha256(self.case_id.encode()).hexdigest()[:10].upper()
        return f"SYNTH_G3_REPLY_{digest}"

    @property
    def is_transport(self) -> bool:
        return self.kind in TRANSPORT_KINDS

    @property
    def is_terminal(self) -> bool:
        return self.kind in TERMINAL_KINDS

    @property
    def is_root_200(self) -> bool:
        return self.kind in ROOT_KINDS

    @property
    def reply_valid(self) -> bool:
        return bool(build_kind_reply(self.kind, self.stage).valid)

    @property
    def reply_cookie_eligible(self) -> bool:
        return bool(build_kind_reply(self.kind, self.stage).cookie_eligible)

    @property
    def advances(self) -> bool:
        """Declared rule: only a validated, eligible, post-proof reply confirms."""
        return (
            self.reply_valid
            and self.reply_cookie_eligible
            and self.position in (Position.POST_PROOF, Position.OPTIONAL)
        )

    @property
    def quarantined(self) -> bool:
        """Declared rule: an invalid reply's unique cookie can never be carried."""
        return not (self.reply_valid and self.reply_cookie_eligible)

    def to_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


COVERING = Path(__file__).with_name("response_covering.json")


def load_cases(path: str | Path = COVERING) -> tuple[ResponseCase, ...]:
    """Load every checked-in covering row as a case in stable order."""
    model = json.loads(Path(path).read_text(encoding="utf-8"))
    return tuple(
        ResponseCase(
            case_id=str(row["id"]),
            stage=str(row["stage"]),
            kind=str(row["kind"]),
            cookie=str(row["cookie"]),
            position=str(row["position"]),
            flow=str(row["flow"]),
            event=str(row["event"]),
            family=str(row["family"]),
            tier=str(row["tier"]),
            note=str(row.get("note", "")),
        )
        for row in model["rows"]
    )


def cases_for(tier: str) -> tuple[ResponseCase, ...]:
    """Return the cases of one tier."""
    return tuple(case for case in ALL_CASES if case.tier == tier)


def night_case_params(tuples: Iterable[Mapping[str, str]]) -> list[ResponseCase]:
    """Turn independent nightly tuples into collect-only case parameters.

    Flow/event/family derive from the stage: the login handshake is local-flow,
    the ACS is SSO-only, history is backfill, post-proof data is HA persistence.
    """
    cases: list[ResponseCase] = []
    for values in tuples:
        stage = values["stage"]
        position = values["position"]
        flow = FlowMode.S if stage == Stage.SAML_ACS else FlowMode.L
        event = "backfill" if stage == Stage.HISTORY_CHUNK else "poll"
        family = "ha" if position in (Position.POST_PROOF, Position.OPTIONAL) else "client"
        case_id = f"nightly::{stage}::{values['kind']}::{values['cookie']}::{position}"
        cases.append(
            ResponseCase(
                case_id=case_id,
                stage=stage,
                kind=values["kind"],
                cookie=values["cookie"],
                position=position,
                flow=flow,
                event=event,
                family=family,
                tier="nightly",
                note="exhaustive G3 collection (execution waits for P4 capacity)",
            )
        )
    return cases


# ---------------------------------------------------------------------------
# Reply and scripting
# ---------------------------------------------------------------------------


def build_case_reply(case: ResponseCase) -> Reply:
    """Build the declared reply with this case's unique cookie value.

    A declared ``valid_success`` chart reply is rendered by the same P2-03 builder
    with this entry's synthetic meter id: the corpus label ``Meter #SYNTH_METER_001``
    is not numeric, and production accepts only numeric meter series
    (``pseg_client._METER_SERIES``). The kind's declared validity still comes from
    the corpus; only the synthetic account identity is aligned, and invalid kinds
    keep their declared bodies.
    """
    base = build_kind_reply(case.kind, case.stage)
    name = case.cookie_name
    cookies = {name: case.poison} if name else {}
    metadata = dict(base.metadata)
    metadata.update({"g3_case": case.case_id, "stage": case.stage, "kind": case.kind})
    body = base.body
    headers = dict(base.headers)
    if case.kind == ResponseKind.VALID_SUCCESS:
        if case.stage in (Stage.DAILY_CHART_DATA, Stage.HISTORY_CHUNK):
            body = json.dumps(build_synthetic_daily_chart(meter_id=METER_ID))
            headers["Content-Type"] = "application/json"
        elif case.stage == Stage.HOURLY_CHART_DATA:
            body = json.dumps(build_synthetic_hourly_chart(meter_id=METER_ID))
            headers["Content-Type"] = "application/json"
    return Reply(
        reply_id=case.reply_id,
        status_code=base.status_code,
        headers=headers,
        body=body,
        cookies=cookies,
        valid=base.valid,
        cookie_eligible=base.cookie_eligible,
        metadata=metadata,
    )


def script_case_portal() -> ResponseCasePortal:
    """Return the healthy baseline portal plus the declared redirect target."""
    portal = ResponseCasePortal()
    script_portal(portal)
    replace_route(portal, ("GET", f"{PORTAL}/Landing"), LANDING_REPLY)
    replace_route(portal, ("POST", f"{PORTAL}/Landing"), LANDING_REPLY)
    return portal


def inject_case(portal: ScriptedPortal, case: ResponseCase, reply: Reply) -> None:
    """Serve the declared reply at the case's stage route (reusable single reply)."""
    stage = case.stage
    if stage == Stage.DASHBOARD_VERIFY_TOKEN:
        replace_route(portal, ("GET", f"{PORTAL}/Dashboard"), [reply, HEALTHY_DASHBOARD])
    elif stage == Stage.DAILY_CHART_DATA:
        replace_route(portal, ("GET", f"{PORTAL}/Dashboard/ChartData"), [reply, HEALTHY_DAILY])
    elif stage == Stage.HOURLY_CHART:
        replace_route(
            portal,
            ("POST", f"{PORTAL}/Dashboard/Chart"),
            [HEALTHY_CHART, reply, HEALTHY_CHART],
        )
    elif stage == Stage.HOURLY_CHART_DATA:
        replace_route(
            portal,
            ("GET", f"{PORTAL}/Dashboard/ChartData"),
            [HEALTHY_DAILY, reply, HEALTHY_DAILY],
        )
    elif stage == Stage.HISTORY_CHUNK:
        replace_route(portal, ("GET", f"{PORTAL}/Dashboard/ChartData"), [reply, HEALTHY_DAILY])
    elif stage == Stage.LOGIN_FORM_GET:
        # Production reads the login form with GET / during renewal
        # (pseg_client._login_form_token): the first root read is the signed-out
        # landing that starts the renewal, the declared reply answers the token read.
        replace_route(portal, ("GET", f"{PORTAL}/Dashboard"), DASHBOARD_BOUNCE)
        replace_route(
            portal, ("GET", f"{PORTAL}/"), [HEALTHY_LOGIN_FORM, reply, HEALTHY_LOGIN_FORM]
        )
    elif stage == Stage.LOGIN_POST:
        replace_route(portal, ("GET", f"{PORTAL}/Dashboard"), DASHBOARD_BOUNCE)
        replace_route(
            portal,
            ("POST", f"{PORTAL}/Home/Login"),
            [reply, Reply.redirect(location=f"{PORTAL}/Dashboard", status_code=302)],
        )
    elif stage == Stage.SAML_ACS:
        replace_route(portal, ("GET", f"{PORTAL}/Dashboard"), DASHBOARD_BOUNCE)
        replace_route(
            portal,
            ("POST", f"{PORTAL}/Saml/okta-prod/Acs"),
            [reply, Reply.redirect(location=f"{PORTAL}/Dashboard", status_code=302)],
        )
    else:  # pragma: no cover - guarded by the declared domain
        raise KeyError(stage)


def _stage_route(case: ResponseCase) -> tuple[str, str]:
    method, path = STAGE_PATHS[case.stage]
    return method, path


def _route_dispatches(case: ResponseCase, dispatches: Sequence[Dispatch]) -> list[Dispatch]:
    method, path = _stage_route(case)
    return [
        dispatch
        for dispatch in dispatches
        if dispatch.method == method and dispatch.url.split("?")[0].endswith(path)
    ]


def reply_consumed(case: ResponseCase, dispatches: Sequence[Dispatch]) -> bool:
    """Return True when the declared reply (or its transport error) was served."""
    matching = _route_dispatches(case, dispatches)
    if case.is_transport:
        return any(
            dispatch.outcome
            and (dispatch.outcome.startswith("error:") or dispatch.error is not None)
            for dispatch in matching
        )
    return any(dispatch.reply_id == case.reply_id for dispatch in matching)


def later_dispatches(case: ResponseCase, dispatches: Sequence[Dispatch]) -> list[Dispatch]:
    """Return every request after the first consumed case reply and its redirect chain.

    A redirect hop of the same issued request is the transport completing the
    invalid reply, not a new client dispatch (the P2-01/P2-06 in-flight rule).
    """
    for index, dispatch in enumerate(dispatches):
        consumed = (
            dispatch.reply_id == case.reply_id
            if not case.is_transport
            else bool(dispatch.outcome and dispatch.outcome.startswith("error:"))
        )
        if consumed and dispatch.method == _stage_route(case)[0]:
            if not dispatch.url.split("?")[0].endswith(_stage_route(case)[1]):
                continue
            chain = {dispatch.sequence}
            cursor = index + 1
            while cursor < len(dispatches):
                hop = dispatches[cursor]
                origin = str(hop.hop_cause or "")
                if hop.is_redirect_hop and any(origin == f"redirect:{seq}" for seq in chain):
                    chain.add(hop.sequence)
                cursor += 1
            return [item for item in dispatches[index + 1 :] if item.sequence not in chain]
    return []


def cookie_pairs(cookies: Iterable[Any]) -> set[tuple[str, str]]:
    """Return (name, value) pairs from frozen cookies or exported dicts."""
    pairs: set[tuple[str, str]] = set()
    for cookie in cookies:
        if isinstance(cookie, Mapping):
            pairs.add((str(cookie.get("name", "")), str(cookie.get("value", ""))))
        else:
            pairs.add((str(getattr(cookie, "name", "")), str(getattr(cookie, "value", ""))))
    return pairs


def _snapshot_pairs(snapshot: Snapshot) -> set[tuple[str, str]]:
    return cookie_pairs(snapshot.persisted_jar)


def _jar(snapshot: Snapshot) -> dict[str, str]:
    return dict(cookie_pairs(snapshot.persisted_jar))


def _exported(client: Any) -> set[tuple[str, str]]:
    return cookie_pairs(client.export_cookies())


def _expectation(
    jar: Mapping[str, str], admission: Mapping[str, Any], name: str
) -> ExpectationState:
    return ExpectationState(
        generation_id=f"{name}:expected",
        sequence=1,
        latest_checkpoint=Checkpoint(
            generation_id=f"{name}:expected",
            sequence=1,
            jar=MappingProxyType(dict(jar)),
            admission=MappingProxyType(dict(admission)),
            timestamp=0.0,
        ),
    )


def _declared_reply_cookies(reply: Reply) -> dict[str, str]:
    """Declared cookies of one reply, including its ``Set-Cookie`` header values.

    The SSO relay re-issues ``MM_SID`` through a header on the ACS redirect
    (tests/support/lifecycle.py:191-201), so a cookie map alone would miss a real
    declared rotation.
    """
    cookies = {str(name): str(value) for name, value in (reply.cookies or {}).items()}
    header = (reply.headers or {}).get("Set-Cookie")
    for value in header if isinstance(header, (list, tuple)) else (header,):
        if not value:
            continue
        parsed = SimpleCookie()
        parsed.load(str(value))
        cookies.update({name: morsel.value for name, morsel in parsed.items()})
    return cookies


def _declared_stage(dispatch: Dispatch, reply: Reply) -> str:
    """Declared stage of one consumed reply: request shape plus its own metadata."""
    path = urlparse(dispatch.url).path or "/"
    declared = (reply.metadata or {}).get("stage")
    if path == "/Dashboard":
        return Stage.DASHBOARD_VERIFY_TOKEN
    if path.endswith("/ChartData"):
        if declared in (
            Stage.DAILY_CHART_DATA,
            Stage.HOURLY_CHART_DATA,
            Stage.HISTORY_CHUNK,
        ):
            return str(declared)
        # The scripted healthy ChartData payload is the daily read.
        return Stage.DAILY_CHART_DATA
    if path == "/Dashboard/Chart":
        return Stage.HOURLY_CHART
    if path == "/Home/Login":
        return Stage.LOGIN_POST if dispatch.method == "POST" else Stage.LOGIN_FORM_GET
    if path == "/":
        return Stage.LOGIN_FORM_GET
    if "/Saml/" in path:
        return Stage.SAML_ACS if dispatch.method == "POST" else Stage.LOGIN_FORM_GET
    # A plain leg (the Chart selection POST, a landing hop) may carry cookies but
    # never confirms a checkpoint by itself.
    return "unconfirmed_leg"


def _case_route_dispatch(case: ResponseCase, dispatch: Dispatch) -> bool:
    method, path = STAGE_PATHS[case.stage]
    return dispatch.method == method and dispatch.url.split("?")[0].endswith(path)


def _expected_checkpoint(
    case: ResponseCase,
    baseline_jar: Mapping[str, str],
    baseline_admission: Mapping[str, Any],
    declared: Mapping[str, Reply],
    case_reply: Reply,
    dispatches: Sequence[Dispatch],
) -> tuple[dict[str, str], dict[str, Any]]:
    """Declare the latest whole jar and settled admission of one HA case.

    Inputs are the pre-operation baseline (replay input) and the *declared* reply
    of every attempted request; the persisted bytes this is checked against are
    never an input. The pure expectation model decides which declared reply may
    advance a checkpoint:

    * A declared redirect (the SSO relay's ACS hop) only adds its declared cookies
      to the pending jar.
    * Every other reply is applied at its declared stage, so an invalid, terminal
      or not-eligible reply quarantines and cannot confirm a new checkpoint.
    * The latest whole jar is the pending jar when the model ends confirmed, and
      the last confirmed checkpoint (the baseline when nothing was confirmed) when
      it ends quarantined, mirroring production's leg rollback.
    * The admission starts from the baseline. A declared *valid* reply means the
      operation reached production's update path, which commits the durable
      admission, so a never-settled baseline settles to the declared zero form; an
      operation whose every consumed reply was invalid never reaches that commit and
      keeps its baseline admission. A declared terminal challenge additionally adds
      its declared durable reason. No automatic renewal in the covering may spend a
      sequence (``sequences`` stays at the baseline value).
    """
    generation = f"{case.case_id}:expected"
    state = ExpectationState(
        generation_id=generation,
        latest_checkpoint=Checkpoint(
            generation_id=generation,
            sequence=0,
            jar=MappingProxyType(dict(baseline_jar)),
            admission=MappingProxyType(dict(baseline_admission)),
            timestamp=0.0,
        ),
        pending_session_jar=MappingProxyType(dict(baseline_jar)),
        settled_admission=MappingProxyType(dict(baseline_admission)),
    )
    saw_valid = False
    for dispatch in sorted(dispatches, key=lambda item: item.sequence):
        reply = declared.get(dispatch.reply_id or "")
        if reply is None:
            if not (case.is_transport and dispatch.reply_id is None):
                raise AssertionError(
                    f"{case.case_id}: a served request has no declared reply: "
                    f"{dispatch.method} {dispatch.url} ({dispatch.reply_id})"
                )
            if not _case_route_dispatch(case, dispatch):
                raise AssertionError(
                    f"{case.case_id}: an undeclared transport failure was served on "
                    f"{dispatch.method} {dispatch.url}"
                )
            reply = case_reply
        cookies = _declared_reply_cookies(reply)
        declared_reply = dataclasses.replace(reply, cookies=cookies)
        saw_valid = saw_valid or bool(reply.valid)
        if (
            (reply.metadata or {}).get("kind") is None
            and reply.status_code in DECLARED_REDIRECT_STATUSES
        ):
            state = dataclasses.replace(
                state,
                pending_session_jar=MappingProxyType(
                    {**state.pending_session_jar, **cookies}
                ),
            )
            continue
        state = apply_step(
            state,
            FlowStep(
                stage=_declared_stage(dispatch, reply),
                reply=declared_reply,
                flow_mode=case.flow,
            ),
        )

    admission = dict(baseline_admission)
    if saw_valid or case.is_terminal:
        for field, value in SETTLED_ADMISSION_DEFAULTS.items():
            admission.setdefault(field, value)
    if case.is_terminal:
        admission["terminal_reason"] = TERMINAL_ADMISSION_REASONS[case.kind]
    if state.is_quarantined:
        jar = dict(state.latest_checkpoint.jar)
    else:
        jar = dict(state.pending_session_jar)
    return jar, admission


def _exact_admission(
    snapshot: Snapshot, expected: Mapping[str, Any], label: str
) -> None:
    """Declare the durable admission exactly, including nullable-field presence.

    The frozen oracle's I5 loop iterates the *expected* keys only, so an empty
    expected admission would check nothing and a missing nullable field would read
    as ``None``. The declared admission is compared as a whole mapping instead:
    ``{}`` means the entry persisted no admission at all, and a declared
    ``last_sequence_at: None`` means the field is present and null.
    """
    persisted = dict(snapshot.renewal_admission)
    assert persisted == dict(expected), (
        f"{label}: the persisted durable admission is not exactly the declared "
        f"admission (declared {dict(expected)}, persisted {persisted})"
    )


def _successor_admission(
    admission: Mapping[str, Any],
    declared: Mapping[str, Reply],
    dispatches: Sequence[Dispatch],
) -> dict[str, Any]:
    """Declare the durable admission of the authorized successor.

    The successor runs on the restored healthy routes, so its own *declared* replies
    decide the settlement: a fresh never-settled exit legitimately becomes the zero
    form once a declared valid reply reaches production's update path, while an
    already settled admission keeps its values. The successor's persisted admission
    is never an input.
    """
    settled = dict(admission)
    saw_valid = False
    for dispatch in dispatches:
        reply = declared.get(dispatch.reply_id or "")
        if reply is not None:
            saw_valid = saw_valid or bool(reply.valid)
    if saw_valid:
        for field, value in SETTLED_ADMISSION_DEFAULTS.items():
            settled.setdefault(field, value)
    return settled


def _admission(driver: LifecycleDriver) -> dict[str, Any]:
    client = driver.client
    runtime = getattr(client, "_renewal_runtime", None) if client is not None else None
    if runtime is None:
        return {}
    return dict(runtime.admission_dict() or {})


def _build_client(portal: ScriptedPortal, flow: str) -> PsegClient:
    client = PsegClient(
        cookie_list=[dict(cookie) for cookie in INITIAL_JARS[flow]],
        email="SYNTH_G3_EMAIL" if flow == FlowMode.L else "",
        password="SYNTH_G3_PASSWORD" if flow == FlowMode.L else "",
    )
    portal.mount_on(client.session, generation_id="g3_client")
    return client


def _run_client_operation(client: PsegClient, event: str) -> Any:
    if event == "setup" or event == "poll":
        return client.fetch_energy_data(3)
    if event == "keepalive":
        return client.keepalive()
    if event == "backfill":
        return client.fetch_history_range(BACKFILL_START, BACKFILL_END)
    raise KeyError(event)


def _run_ha_operation(driver: LifecycleDriver, event: str) -> Any:
    if event == "poll":
        return driver.poll()
    if event == "keepalive":
        return driver.keepalive_tick()
    if event == "backfill":
        return driver.backfill(BACKFILL_START, BACKFILL_END)
    raise KeyError(event)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CaseEvidence:
    """Observable outcome of one G3 case."""

    case_id: str
    family: str
    tier: str
    stage: str
    kind: str
    cookie: str
    position: str
    flow: str
    event: str
    reply_consumed: bool
    advanced: bool
    quarantined: bool
    dispatches: int
    later_dispatches: int
    follow_on_steps: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Client-family execution
# ---------------------------------------------------------------------------


async def run_client_case(
    case: ResponseCase,
    hass: HomeAssistant,
) -> CaseEvidence:
    """Run one client-family case and hand the physical jar to the HA follow-on."""
    portal = script_case_portal()
    reply = build_case_reply(case)
    inject_case(portal, case, reply)
    client = _build_client(portal, case.flow)

    start = len(portal.dispatches)
    error: BaseException | None = None
    try:
        await hass.async_add_executor_job(_run_client_operation, client, case.event)
    except BaseException as err:  # noqa: BLE001 - the typed contract is the assertion
        error = err
    dispatches = tuple(portal.dispatches[start:])

    assert reply_consumed(case, dispatches), (
        f"{case.case_id}: the declared {case.kind} reply at '{case.stage}' was never "
        f"served during {case.event}; dispatches="
        f"{[(d.method, d.url, d.reply_id, d.outcome) for d in dispatches]}"
    )

    notes: list[str] = []
    if error is not None:
        assert isinstance(error, (PsegError, requests.RequestException)), (
            f"{case.case_id}: untyped entrypoint error {type(error).__name__}: {error}"
        )
        notes.append(type(error).__name__)
    if case.is_root_200 and case.stage in (Stage.DAILY_CHART_DATA, Stage.HISTORY_CHUNK):
        # A root-200 body must reach the typed validation path, never a raw
        # ValueError/JSONDecodeError from the parser.
        assert isinstance(error, PsegError), (
            f"{case.case_id}: root-200 body at '{case.stage}' did not raise a typed "
            f"PsegError (got {type(error).__name__ if error else 'success'}: {error})"
        )
        notes.append("typed_root_200")

    if case.kind in (ResponseKind.HTTP_307, ResponseKind.HTTP_308):
        hops = [dispatch for dispatch in dispatches if dispatch.is_redirect_hop]
        posts = [
            dispatch
            for dispatch in dispatches
            if dispatch.method == "POST" and dispatch.url.split("?")[0].endswith("/Dashboard/Chart")
        ]
        assert hops, f"{case.case_id}: no redirect hop was recorded for a {case.kind}"
        assert hops[0].method == "POST", (
            f"{case.case_id}: {case.kind} lost the POST method on the redirect hop"
        )
        assert hops[0].body_digest == posts[-1].body_digest, (
            f"{case.case_id}: {case.kind} did not preserve the credential body digest on "
            "the redirect hop"
        )
        notes.append("credential_repost")

    later = later_dispatches(case, dispatches)
    if case.quarantined:
        poison = (case.cookie_name, case.poison) if case.cookie_name else None
        if poison is not None:
            leaked = [
                (dispatch.method, dispatch.url)
                for dispatch in later
                if poison in set(dispatch.cookies.items())
            ]
            assert not leaked, (
                f"{case.case_id}: a failed/invalid reply's unique cookie was carried by "
                f"the actual next request(s) {leaked}"
            )
            assert poison not in _exported(client), (
                f"{case.case_id}: the failed/invalid reply's unique cookie survived in the "
                "client's exported session jar"
            )
        notes.append("quarantined")
    elif case.cookie_name:
        assert (case.cookie_name, case.poison) in _exported(client), (
            f"{case.case_id}: a validated eligible reply's cookie is missing from the exported jar"
        )
        notes.append("persisted_eligible")

    # HA handoff: the physical exported jar seeds a real entry, and the shared
    # follow-on proves no later poll or cold restart resurrects a quarantined value.
    entry = _handoff_entry(hass, case.flow, client.export_cookies())
    handoff_portal = script_case_portal()
    factory = ClientFactory(handoff_portal, registry=ClientRegistry())
    driver = LifecycleDriver(hass, entry, handoff_portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(handoff_portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    register_initial_jar(oracle, entry)
    register_scripted_eligibility(oracle, handoff_portal)

    try:
        with factory:
            result = await run_case(driver, None, case_name=case.case_id, oracle=oracle)
    finally:
        if driver.entry.state is ConfigEntryState.LOADED:
            await driver.unload()
    result.assert_complete()
    assert not oracle.violations, (
        f"{case.case_id}: oracle violations after the HA handoff "
        f"{[str(v.code) + ': ' + v.message for v in oracle.violations]}"
    )

    poison = (case.cookie_name, case.poison) if case.cookie_name else None
    if poison is not None:
        carried = [
            (dispatch.method, dispatch.url)
            for dispatch in handoff_portal.dispatches
            if poison in set(dispatch.cookies.items())
        ]
        snapshot = await driver.snapshot()
        if case.quarantined:
            assert not carried, (
                f"{case.case_id}: the follow-on carried a quarantined cookie after the HA "
                f"handoff in {carried}"
            )
            assert poison not in _snapshot_pairs(snapshot), (
                f"{case.case_id}: a quarantined cookie reached physical persistence"
            )
        else:
            assert carried or poison in _snapshot_pairs(snapshot), (
                f"{case.case_id}: the validated eligible cookie never reached the handed-off "
                "HA runtime; the handoff is not real"
            )

    if case.quarantined and not later:
        notes.append("follow_on_only")
    return CaseEvidence(
        case_id=case.case_id,
        family=case.family,
        tier=case.tier,
        stage=case.stage,
        kind=case.kind,
        cookie=case.cookie,
        position=case.position,
        flow=case.flow,
        event=case.event,
        reply_consumed=True,
        advanced=case.advances,
        quarantined=case.quarantined,
        dispatches=len(dispatches),
        later_dispatches=len(later),
        follow_on_steps=tuple(result.ending_steps),
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# HA-family execution
# ---------------------------------------------------------------------------


def _typed_failure(error: BaseException | None) -> bool:
    """Return True when a coordinator failure has a typed root cause."""
    if error is None:
        return True
    seen = 0
    current: BaseException | None = error
    while current is not None and seen < 10:
        if isinstance(current, PsegError):
            return True
        current = current.__cause__ or current.__context__
        seen += 1
    return isinstance(error, (ConfigEntryAuthFailed, HomeAssistantError))


async def run_ha_case(
    case: ResponseCase,
    hass: HomeAssistant,
    caplog: Any = None,
) -> CaseEvidence:
    """Run one HA-family case through persistence, I5/I12 and the shared follow-on."""
    portal = script_case_portal()
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = create_flow_entry(hass, case.flow)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    register_initial_jar(oracle, entry)
    if caplog is not None:
        driver.attach_caplog(caplog)
        oracle.attach_caplog(caplog)

    reply = build_case_reply(case)
    facts: dict[str, Any] = {}

    async def body(current: LifecycleDriver) -> None:
        before = await current.snapshot()
        baseline_jar = _jar(before)
        baseline_admission = dict(before.renewal_admission)

        if case.event == "setup":
            inject_case(portal, case, reply)
            register_scripted_eligibility(oracle, portal)
            oracle.expectation_state = _expectation(baseline_jar, baseline_admission, case.case_id)
            assert await current.setup() is False or current.entry.state.value == "loaded", (
                f"{case.case_id}: setup neither failed nor loaded"
            )
        else:
            assert await current.setup() is True, f"{case.case_id}: healthy setup failed"
            await current.poll()
            before = await current.snapshot()
            baseline_jar = _jar(before)
            baseline_admission = dict(before.renewal_admission)
            oracle.expectation_state = _expectation(baseline_jar, baseline_admission, case.case_id)
            inject_case(portal, case, reply)
            register_scripted_eligibility(oracle, portal)

        start = len(portal.dispatches)
        operation_error: BaseException | None = None
        if case.event != "setup":
            try:
                await _run_ha_operation(current, case.event)
            except BaseException as err:  # noqa: BLE001 - typed failure is asserted below
                operation_error = err
        dispatches = tuple(portal.dispatches[start:])
        if case.event == "setup":
            dispatches = tuple(portal.dispatches)

        assert reply_consumed(case, dispatches), (
            f"{case.case_id}: the declared {case.kind} reply at '{case.stage}' was never "
            f"served during {case.event}; dispatches="
            f"{[(d.method, d.url, d.reply_id, d.outcome) for d in dispatches]}"
        )

        after = await current.snapshot()
        later = later_dispatches(case, dispatches)
        facts["dispatches"] = len(dispatches)
        facts["later_dispatches"] = len(later)
        coordinator = current.coordinator
        last_error = getattr(coordinator, "last_exception", None)
        assert _typed_failure(last_error) and _typed_failure(operation_error), (
            f"{case.case_id}: an untyped error leaked: "
            f"operation={operation_error!r} coordinator={last_error!r}"
        )

        poison = (case.cookie_name, case.poison) if case.cookie_name else None
        expected_jar, expected_admission = _expected_checkpoint(
            case,
            baseline_jar,
            baseline_admission,
            portal.declared,
            reply,
            dispatches,
        )
        assert _jar(after) == expected_jar, (
            f"{case.case_id}: the persisted jar is not the latest whole jar the declared "
            f"replies allow (declared {expected_jar}, persisted {_jar(after)}, baseline "
            f"{baseline_jar})"
        )
        if expected_jar != baseline_jar:
            # Defense in depth on top of the whole-jar equality above: every persisted
            # value must still be a declared, validated, eligible cookie.
            provenance = oracle.evaluate_i4(after)
            assert not provenance, (
                f"{case.case_id}: the declared rotation persisted values no declared "
                f"eligible reply supplied (expected {expected_jar}, persisted "
                f"{_jar(after)}): {[v.message for v in provenance]}"
            )
        if case.quarantined:
            leaked = [
                (dispatch.method, dispatch.url)
                for dispatch in later_dispatches(case, dispatches)
                if poison in set(dispatch.cookies.items())
            ]
            assert not leaked, (
                f"{case.case_id}: a failed/invalid reply's unique cookie was carried by "
                f"the actual next request(s) {leaked}"
            )
            if poison is not None:
                assert poison not in _snapshot_pairs(after), (
                    f"{case.case_id}: a failed/invalid reply's cookie reached physical "
                    f"persistence: {_jar(after)}"
                )
            facts["quarantined"] = True
        elif case.advances and poison is not None:
            assert poison in _snapshot_pairs(after), (
                f"{case.case_id}: a validated, eligible, post-proof reply was not persisted: "
                f"{_jar(after)}"
            )
            facts["advanced"] = True
        oracle.expectation_state = _expectation(
            expected_jar, expected_admission, case.case_id
        )

        i5 = oracle.evaluate_i5(
            after,
            _expectation(expected_jar, expected_admission, f"{case.case_id}:i5"),
        )
        assert not i5, (
            f"{case.case_id}: I5 latest checkpoint "
            f"(declared jar {expected_jar} admission {expected_admission}, persisted jar "
            f"{_jar(after)} admission {dict(after.renewal_admission)}): "
            f"{[v.message for v in i5]}"
        )
        _exact_admission(after, expected_admission, case.case_id)

        # I12: an observed auth/transient failure must not add rows or clear the journal.
        failed = bool(
            operation_error is not None
            or getattr(coordinator, "last_update_success", True) is False
            or getattr(coordinator, "auth_required", False)
        )
        if failed and case.event != "setup":
            i12 = oracle.evaluate_i12(before, after)
            assert not i12, f"{case.case_id}: I12: {[v.message for v in i12]}"
            before_rows = dict(before.rows)
            after_rows = dict(after.rows)
            assert before_rows.keys() == after_rows.keys(), (
                f"{case.case_id}: statistics series changed during an auth/transient failure"
            )
            for series in before_rows:
                assert before_rows[series] == after_rows[series], (
                    f"{case.case_id}: statistics series '{series}' changed during a failure"
                )
            facts["i12"] = True

        if getattr(coordinator, "auth_required", False):
            facts["auth_loss"] = True

        if (
            case.event == "poll"
            and case.stage == Stage.HOURLY_CHART_DATA
            and not failed
            and not case.reply_valid
            and not case.is_terminal
            and case.kind in AUTH_LOSS_KINDS
        ):
            facts["auth_loss"] = True
        if (
            case.event == "poll"
            and case.stage == Stage.HOURLY_CHART_DATA
            and not failed
            and not case.reply_valid
            and case.kind not in AUTH_LOSS_KINDS
        ):
            data = getattr(coordinator, "data", None) or {}
            assert data.get("hourly_granularity") == "unavailable", (
                f"{case.case_id}: the daily fallback did not degrade the hourly "
                f"granularity (data={data.get('hourly_granularity')!r})"
            )
            facts["daily_fallback"] = True

        if case.is_terminal:
            client = current.client
            latched = bool(
                client is not None
                and (
                    getattr(client, "_captcha_latched", False)
                    or getattr(client, "_security_step_latched", False)
                )
            )
            terminal_reason = dict(after.renewal_admission).get("terminal_reason")
            assert latched or terminal_reason, (
                f"{case.case_id}: a declared terminal challenge left no latch or durable "
                "terminal admission"
            )
            facts["terminal"] = True

        facts["failed"] = failed
        facts["operation_error"] = type(operation_error).__name__ if operation_error else None

        # The mandatory follow-on always starts from the healthy declared baseline,
        # never from the case's injected reply.
        _restore_healthy_routes(portal)

        # Authorized successor for every non-terminal failure: a real reload from
        # the persisted jar, so the mandatory follow-on can run healthy.
        if not case.is_terminal and (failed or current.entry.state is not ConfigEntryState.LOADED):
            _restore_healthy_routes(portal)
            successor_start = len(portal.dispatches)
            assert await current.reload() is True, (
                f"{case.case_id}: the authorized successor did not reload from "
                f"{current.entry.state}"
            )
            await current.poll()
            successor = await current.snapshot()
            successor_admission = _successor_admission(
                expected_admission,
                portal.declared,
                tuple(portal.dispatches[successor_start:]),
            )
            oracle.expectation_state = _expectation(
                expected_jar, successor_admission, case.case_id
            )
            i5_successor = oracle.evaluate_i5(
                successor,
                _expectation(
                    expected_jar, successor_admission, f"{case.case_id}:successor"
                ),
            )
            assert not i5_successor, (
                f"{case.case_id}: the authorized successor from the persisted jar does "
                f"not match the declared latest checkpoint: "
                f"{[v.message for v in i5_successor]}"
            )
            _exact_admission(
                successor, successor_admission, f"{case.case_id}:successor"
            )

        for snapshot in (await current.snapshot(),):
            if case.quarantined and poison is not None:
                assert poison not in _snapshot_pairs(snapshot)

    try:
        with factory:
            result = await run_case(
                driver,
                body,
                case_name=case.case_id,
                terminal=case.is_terminal,
                oracle=oracle,
            )
    finally:
        if driver.entry.state is ConfigEntryState.LOADED:
            await driver.unload()
    result.assert_complete()
    assert not oracle.violations, (
        f"{case.case_id}: oracle violations "
        f"{[str(v.code) + ': ' + v.message for v in oracle.violations]}"
    )
    assert len(result.ending_steps) == 4

    notes = [
        note
        for note in (
            facts.get("operation_error"),
            "i12" if facts.get("i12") else None,
            "terminal" if facts.get("terminal") else None,
            "auth_loss" if facts.get("auth_loss") else None,
            "daily_fallback" if facts.get("daily_fallback") else None,
            "follow_on_only" if case.quarantined and not facts.get("later_dispatches") else None,
        )
        if note
    ]
    return CaseEvidence(
        case_id=case.case_id,
        family=case.family,
        tier=case.tier,
        stage=case.stage,
        kind=case.kind,
        cookie=case.cookie,
        position=case.position,
        flow=case.flow,
        event=case.event,
        reply_consumed=True,
        advanced=bool(facts.get("advanced")),
        quarantined=bool(facts.get("quarantined")),
        dispatches=int(facts.get("dispatches", 0)),
        later_dispatches=int(facts.get("later_dispatches", 0)),
        follow_on_steps=tuple(result.ending_steps),
        notes=tuple(notes),
    )


def _handoff_entry(
    hass: HomeAssistant, flow: str, cookies: Sequence[Mapping[str, Any]]
) -> MockConfigEntry:
    """Create the declared flow entry with the exported physical jar attached."""
    template = create_flow_entry(hass, flow)
    data = dict(template.data)
    data["cookies"] = [dict(cookie) for cookie in cookies]
    hass.config_entries._entries.pop(template.entry_id, None)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        minor_version=1,
        unique_id=METER_ID,
        title=f"PSE&G ({METER_ID})",
        options={},
        data=data,
    )
    entry.add_to_hass(hass)
    return entry


def _restore_healthy_routes(portal: ScriptedPortal) -> None:
    """Restore the healthy baseline routes before the mandatory follow-on."""
    replace_route(portal, ("GET", f"{PORTAL}/Dashboard"), HEALTHY_DASHBOARD)
    replace_route(portal, ("POST", f"{PORTAL}/Dashboard/Chart"), HEALTHY_CHART)
    replace_route(portal, ("GET", f"{PORTAL}/Dashboard/ChartData"), HEALTHY_DAILY)
    replace_route(portal, ("GET", f"{PORTAL}/"), HEALTHY_LOGIN_FORM)
    replace_route(portal, ("GET", f"{PORTAL}/Landing"), LANDING_REPLY)
    replace_route(portal, ("POST", f"{PORTAL}/Landing"), LANDING_REPLY)
    replace_route(
        portal,
        ("POST", f"{PORTAL}/Home/Login"),
        Reply.redirect(location=f"{PORTAL}/Dashboard", status_code=302),
    )


async def trace_case_dispatches(
    case: ResponseCase, hass: HomeAssistant
) -> tuple[Dispatch, ...]:
    """Return the raw dispatch trace of one client case's declared reply.

    The probe reuses the same portal, reply construction and real-client call as
    ``run_client_case``, so a focused stage assertion reads the request the client
    actually sent instead of a re-derived expectation. The declared failure is the
    point of the probe, so a typed error is expected; an untyped one still escapes.
    """
    portal = script_case_portal()
    reply = build_case_reply(case)
    inject_case(portal, case, reply)
    client = _build_client(portal, case.flow)
    try:
        await hass.async_add_executor_job(_run_client_operation, client, case.event)
    except (PsegError, requests.RequestException):
        pass
    return tuple(portal.dispatches)


ALL_CASES: tuple[ResponseCase, ...] = load_cases()
FAST_CASES: tuple[ResponseCase, ...] = cases_for("fast")
SLOW_CASES: tuple[ResponseCase, ...] = cases_for("slow")


def run_case_evidence(case: ResponseCase, hass: HomeAssistant, caplog: Any = None) -> Any:
    """Dispatch one case to its declared family runner."""
    if case.family == "client":
        return run_client_case(case, hass)
    return run_ha_case(case, hass, caplog)


async def run_focused_auth_case(
    hass, body, *, flow="R", entry_data=None, terminal=False, setup=True
):
    """Run a focused P2-10 assertion with the real transport and shared ending.

    Setup, physical entry persistence, generation registration and the cold
    reconstruction are identical to G1/G3. The callback supplies the narrow
    scenario; it does not replace client, coordinator or policy implementations.
    A failed body still attempts the ending, preserving its primary exception.
    """
    portal = ScriptedPortal()
    script_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = create_flow_entry(hass, flow)
    if entry_data:
        hass.config_entries.async_update_entry(entry, data={**entry.data, **entry_data})
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    register_initial_jar(oracle, entry)
    register_scripted_eligibility(oracle, portal)
    with factory:
        try:
            if setup:
                assert await driver.setup(), "focused auth setup failed"
            primary = None
            try:
                await body(driver, oracle)
            except Exception as err:
                primary = err
            # Healthy replies become available without changing live/persisted
            # cookies, admission or terminal latches.
            script_portal(portal)
            try:
                if driver.entry.state is not ConfigEntryState.LOADED:
                    assert await driver.reload(), "focused auth successor setup failed"
                ending = await run_case(driver, terminal=terminal, oracle=oracle)
                ending.assert_complete()
                oracle.assert_clean()
            except Exception:
                if primary is None:
                    raise
            if primary is not None:
                raise primary
            return ending
        finally:
            if driver.coordinator is not None:
                driver.coordinator.stop_keepalive()
            for progress in hass.config_entries.flow.async_progress():
                hass.config_entries.flow.async_abort(progress["flow_id"])


__all__ = [
    "ALL_CASES",
    "COOKIE_NAMES",
    "FAST_CASES",
    "INITIAL_JARS",
    "ROOT_KINDS",
    "SLOW_CASES",
    "STAGE_PATHS",
    "TERMINAL_KINDS",
    "TRANSPORT_KINDS",
    "CaseEvidence",
    "ResponseCase",
    "ResponseCasePortal",
    "build_case_reply",
    "cases_for",
    "cookie_pairs",
    "inject_case",
    "later_dispatches",
    "load_cases",
    "night_case_params",
    "reply_consumed",
    "run_case_evidence",
    "run_client_case",
    "run_ha_case",
    "script_case_portal",
    "trace_case_dispatches",
]

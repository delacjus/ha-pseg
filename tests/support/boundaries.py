"""Actual dispatch-boundary inventory, generation and retirement fences (P2-06).

The module dry-runs real L/R/S/H lifecycle traces through the production client and
records the dispatches that actually reach the scripted transport. Those dispatches
are classified into the six declared boundary classes, and the same classification
is derived from a static per-flow route plan (:data:`FLOW_PLANS`) so a dry run can be
compared with a generated inventory.

Retirement fences park one scripted response at the transport, record that the send
already entered the adapter, retire the owning generation through a production
lifecycle transition, release the parked response, and then prove the retired
generation issues no later dispatch. The gate lives *inside* the adapter, after the
production ownership fence in ``AllowlistedSession.send``; the observer never blocks
a send, so the production fence is what prevents every post-retirement request. The
pre-fence case parks the very first request *before* the real ownership fence runs
and proves the fence refuses it once the owner is retired.

Test-only: nothing here modifies ``custom_components/``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
from enum import StrEnum
import threading
from types import MappingProxyType
from typing import Any
import urllib.parse

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pseg.const import (
    CONF_METER_ID,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
    OKTA_HOST,
    PORTAL_HOST,
)

from .expectation import Checkpoint, ExpectationState
from .factory import ClientFactory, ClientRegistry
from .lifecycle import LifecycleDriver, Snapshot, run_case, script_healthy_portal
from .oracle import Oracle
from .portal import Dispatch, Gate, Reply, ScriptedPortal

PORTAL_BASE_URL = f"https://{PORTAL_HOST}"
OKTA_BASE_URL = f"https://{OKTA_HOST}"

METER_ID = "12345678"

DASHBOARD_HTML = (
    "<html><head><title>Dashboard</title></head><body>"
    '<input name="__RequestVerificationToken" type="hidden" value="SYNTH_FENCE_TOKEN"/>'
    "Dashboard</body></html>"
)
LOGIN_HTML = (
    "<html><body><form>"
    '<input name="__RequestVerificationToken" type="hidden" value="SYNTH_FENCE_LOGIN_TOKEN"/>'
    "</form></body></html>"
)
CHART_JSON = (
    '{"Data": {"series": [{"name": "Meter #12345678", '
    '"data": [{"y": 1.5, "x": 1729382400000, "hs": {"start": "10/20/2026"}}]}]}}'
)

BACKFILL_START = "2026-10-01"
BACKFILL_END = "2026-10-10"


class BoundaryClass(StrEnum):
    """The six required dispatch boundary classes."""

    FIRST = "first"
    MID_GET = "mid-get"
    CREDENTIAL_POST = "credential-post"
    REDIRECT = "redirect"
    STAGE_TRANSITION = "stage-transition"
    LAST_BEFORE_PERSIST = "last-before-persist"


ALL_BOUNDARY_CLASSES: tuple[BoundaryClass, ...] = tuple(BoundaryClass)

Leg = tuple[str, str, bool]  # (method, path, is_redirect_hop)


@dataclass(frozen=True, slots=True)
class Boundary:
    """One classified dispatch boundary of a flow trace."""

    boundary_id: str
    flow: str
    operation: str
    method: str
    path: str
    leg: int
    classes: tuple[BoundaryClass, ...]
    stage: str | None
    is_redirect_hop: bool

    @property
    def class_names(self) -> tuple[str, ...]:
        return tuple(str(c) for c in self.classes)


DASH = ("GET", "/Dashboard", False)
CHART = ("POST", "/Dashboard/Chart", False)
CHART_DATA = ("GET", "/Dashboard/ChartData", False)
LANDING_HOP = ("GET", "/", True)
LOGIN_FORM = ("GET", "/", False)
LOGIN_POST = ("POST", "/Home/Login", False)
SSO_SIGNIN = ("GET", "/Saml/okta-prod/SignIn", False)
SSO_ACS = ("POST", "/Saml/okta-prod/Acs", False)
SSO_ACS_HOP = ("GET", "/Dashboard", True)

HEALTHY_POLL: tuple[Leg, ...] = (DASH, CHART, CHART_DATA, CHART, CHART_DATA)
BACKFILL_SLICE: tuple[Leg, ...] = (DASH, CHART, CHART_DATA)

#: Declared per-flow, per-operation route plans. The dry run must reproduce exactly
#: these legs (method, path, redirect hop) for the inventory test to pass.
FLOW_PLANS: Mapping[str, Mapping[str, tuple[Leg, ...]]] = MappingProxyType(
    {
        "L": MappingProxyType(
            {
                "setup": HEALTHY_POLL,
                "poll": HEALTHY_POLL,
                "auth_renewal": (
                    DASH,
                    LANDING_HOP,
                    LOGIN_FORM,
                    LOGIN_POST,
                    DASH,
                    DASH,
                    CHART,
                    CHART_DATA,
                    CHART,
                    CHART_DATA,
                ),
                "keepalive": (DASH,),
                "backfill": BACKFILL_SLICE,
                "reauth": (DASH, DASH),
                "reconfigure": HEALTHY_POLL,
                "unload": (),
            }
        ),
        "R": MappingProxyType(
            {
                "setup": HEALTHY_POLL,
                "poll": HEALTHY_POLL,
                "auth_renewal": (
                    DASH,
                    LANDING_HOP,
                    DASH,
                    CHART,
                    CHART_DATA,
                    DASH,
                    CHART,
                    CHART_DATA,
                    CHART,
                    CHART_DATA,
                ),
                "keepalive": (DASH,),
                "backfill": BACKFILL_SLICE,
                "reauth": (
                    DASH,
                    DASH,
                    CHART,
                    CHART_DATA,
                    CHART,
                    CHART_DATA,
                    DASH,
                    CHART,
                    CHART_DATA,
                    CHART,
                    CHART_DATA,
                ),
                "reconfigure": HEALTHY_POLL,
                "unload": (),
            }
        ),
        "S": MappingProxyType(
            {
                "setup": HEALTHY_POLL,
                "poll": HEALTHY_POLL,
                "auth_renewal": (
                    DASH,
                    LANDING_HOP,
                    SSO_SIGNIN,
                    SSO_ACS,
                    SSO_ACS_HOP,
                    DASH,
                    DASH,
                    CHART,
                    CHART_DATA,
                    CHART,
                    CHART_DATA,
                ),
                "keepalive": (SSO_SIGNIN, SSO_ACS, SSO_ACS_HOP, DASH),
                "backfill": BACKFILL_SLICE,
                "reauth": (DASH, DASH),
                "reconfigure": HEALTHY_POLL,
                "unload": (),
            }
        ),
        "H": MappingProxyType(
            {
                "setup": HEALTHY_POLL,
                "poll": HEALTHY_POLL,
                "keepalive": (DASH,),
                "backfill": BACKFILL_SLICE,
                "reauth": (DASH, DASH),
                "reconfigure": HEALTHY_POLL,
                "unload": (),
            }
        ),
    }
)

FLOWS: tuple[str, ...] = ("L", "R", "S", "H")
OPERATIONS: tuple[str, ...] = (
    "setup",
    "poll",
    "auth_renewal",
    "keepalive",
    "backfill",
    "reauth",
    "reconfigure",
    "unload",
)

#: Operations whose boundaries are swept by parking a real dispatch and retiring its
#: owning generation. Setup is covered by the pre-fence factory gate case; reauth and
#: reconfigure run on unattached human/options generations (see EXCLUSIONS).
SWEEP_OPERATIONS: tuple[str, ...] = ("poll", "auth_renewal", "keepalive", "backfill")

RETIREMENT_TRANSITIONS: tuple[str, ...] = ("unload", "reload", "stop", "cancel", "handoff")

#: Transitions that retire an attached owner through a production path.
ATTACHED_TRANSITIONS: tuple[str, ...] = RETIREMENT_TRANSITIONS

EXCLUSIONS: Mapping[str, str] = MappingProxyType(
    {
        "setup": (
            "Initial-setup boundaries after the first request are not reachable for "
            "retirement: once the owner is retired before the first request, the "
            "production fence refuses it and HA aborts setup (SETUP_RETRY), so no later "
            "setup dispatch exists. The first-request boundary is covered by the "
            "pre-fence factory-gate case instead."
        ),
        "reauth": (
            "Human reauth verification generations are unattached: no coordinator owns "
            "them, no renewal token exists, and I1's explicit unattached-human exemption "
            "applies. Their dispatch is inventoried and exercised by the H exemption "
            "case, but they cannot be retired by an entry transition."
        ),
        "reconfigure": (
            "Options-flow verification runs before the reloaded entry exists; the "
            "generation it creates belongs to the successor setup, covered by the "
            "pre-fence first-request case. The reload itself is exercised as a retirement "
            "transition on attached boundaries."
        ),
        "s_keepalive_sso": (
            "S-mode keepalive performs the documented 10-minute Okta SAML round trip, "
            "which sends a POST to the ACS endpoint while the client is inside "
            "keepalive(). P2-04's I2 forbids every credential POST from keepalive (even "
            "the sanctioned SAML assertion), so any S keepalive trace raises I2 before a "
            "fence assertion can run. This is a P2-04 I2 rule-vs-product conflict, not a "
            "dispatch-fence failure: S keepalive is inventoried by the dry run but kept "
            "out of the retirement sweep until P2-04 resolves the rule."
        ),
        "handoff_l_r_s": (
            "Same-cookie human handoff retires and commits only when the handoff can "
            "prove a real renewal. L/S healthy same-cookie handoffs are refused by the "
            "sign-in proof (no renewal to prove), so no production owner is replaced and "
            "I1 is not applicable; the handoff transition is exercised on flow R, whose "
            "Remember-Me credential renews and commits."
        ),
    }
)


def normalize_path(url: str) -> str:
    """Return the scheme-less host path of a dispatched URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.path or "/"


def classify_legs(
    flow: str,
    operation: str,
    legs: Sequence[Leg],
) -> tuple[Boundary, ...]:
    """Classify an ordered leg sequence into boundary records."""
    boundaries: list[Boundary] = []
    seen: dict[tuple[str, str], int] = {}
    last_index = len(legs) - 1

    # A Chart POST opens a stage and its ChartData GET closes it: both legs are the
    # stage transition (the POST selects the range, the GET reads that range).
    stage_by_index: dict[int, str] = {}
    pair_index = 0
    for index in range(len(legs) - 1):
        first_method, first_path, _ = legs[index]
        next_method, next_path, _ = legs[index + 1]
        if (
            first_method.upper() == "POST"
            and first_path.endswith("/Chart")
            and next_method.upper() == "GET"
            and next_path.endswith("/ChartData")
        ):
            pair_index += 1
            label = f"{first_path}->{next_path}#{pair_index}"
            stage_by_index[index] = label
            stage_by_index[index + 1] = label

    for index, (method, path, hop) in enumerate(legs):
        method = method.upper()
        key = (method, path)
        seen[key] = seen.get(key, 0) + 1
        classes: list[BoundaryClass] = []
        stage = stage_by_index.get(index)
        if hop:
            classes.append(BoundaryClass.REDIRECT)
        if index == 0:
            classes.append(BoundaryClass.FIRST)
        if method == "POST" and any(
            marker in path for marker in ("/Home/Login", "/Acs", "/SignIn")
        ):
            classes.append(BoundaryClass.CREDENTIAL_POST)
        if stage is not None:
            classes.append(BoundaryClass.STAGE_TRANSITION)
        if index == last_index:
            classes.append(BoundaryClass.LAST_BEFORE_PERSIST)
        if method == "GET" and not hop and stage is None:
            classes.append(BoundaryClass.MID_GET)
        boundaries.append(
            Boundary(
                boundary_id=f"{flow}:{operation}:{method}:{path}:{seen[key]}",
                flow=flow,
                operation=operation,
                method=method,
                path=path,
                leg=seen[key],
                classes=tuple(classes),
                stage=stage,
                is_redirect_hop=hop,
            )
        )
    return tuple(boundaries)


def generated_boundaries(
    flow: str,
    plan: Mapping[str, Sequence[Leg]] | None = None,
) -> dict[str, tuple[Boundary, ...]]:
    """Generate the declared boundary inventory for a flow."""
    per_flow = plan if plan is not None else FLOW_PLANS[flow]
    return {
        operation: classify_legs(flow, operation, tuple(legs))
        for operation, legs in per_flow.items()
    }


def observed_legs(dispatches: Sequence[Dispatch]) -> tuple[Leg, ...]:
    """Convert real dispatches into classification legs."""
    return tuple(
        (dispatch.method.upper(), normalize_path(dispatch.url), dispatch.is_redirect_hop)
        for dispatch in dispatches
    )


def observed_boundaries(
    flow: str,
    slices: Mapping[str, Sequence[Dispatch]],
) -> dict[str, tuple[Boundary, ...]]:
    """Classify a dry run's per-operation dispatch slices."""
    return {
        operation: classify_legs(flow, operation, observed_legs(dispatches))
        for operation, dispatches in slices.items()
    }


def compare_inventory(
    flow: str,
    slices: Mapping[str, Sequence[Dispatch]] | Mapping[str, Sequence[Leg]],
    plan: Mapping[str, Sequence[Leg]] | None = None,
) -> list[str]:
    """Return human-readable differences between a dry run and the generated plan.

    ``slices`` may hold real dispatch tuples or plain leg tuples (used by the
    generator-sensitivity negative proofs).
    """
    per_flow = plan if plan is not None else FLOW_PLANS[flow]
    expected = generated_boundaries(flow, plan=per_flow)
    actual: dict[str, tuple[Boundary, ...]] = {}
    for operation, entries in slices.items():
        entries = tuple(entries)
        if entries and isinstance(entries[0], Dispatch):
            actual[operation] = classify_legs(flow, operation, observed_legs(entries))  # type: ignore[arg-type]
        else:
            actual[operation] = classify_legs(flow, operation, entries)  # type: ignore[arg-type]

    problems: list[str] = []
    for operation in sorted(set(expected) | set(actual)):
        expected_ops = expected.get(operation, ())
        actual_ops = actual.get(operation, ())
        expected_sig = [
            (boundary.boundary_id, boundary.class_names, boundary.stage)
            for boundary in expected_ops
        ]
        actual_sig = [
            (boundary.boundary_id, boundary.class_names, boundary.stage) for boundary in actual_ops
        ]
        for item in expected_sig:
            if item not in actual_sig:
                problems.append(f"{flow}:{operation}: missing observed boundary {item[0]}")
        for item in actual_sig:
            if item not in expected_sig:
                problems.append(f"{flow}:{operation}: ungenerated observed boundary {item[0]}")
    return problems


# ---------------------------------------------------------------------------
# Portal scripting and flow entries
# ---------------------------------------------------------------------------


def replace_route(
    portal: ScriptedPortal,
    route: tuple[str, str],
    replies: Reply | Sequence[Reply],
) -> None:
    """Replace any scripted replies for a route with new ones."""
    with portal._lock:
        portal._scripts.pop(portal._normalize_route_key(route), None)
    portal.script(route, replies)


def script_portal(portal: ScriptedPortal) -> None:
    """Script the healthy portal plus the login/landing routes for L/R/S."""
    script_healthy_portal(portal)
    replace_route(
        portal,
        ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
        Reply.ok(body=DASHBOARD_HTML, reply_id="SYNTH_FENCE_DASHBOARD"),
    )
    replace_route(
        portal,
        ("POST", f"{PORTAL_BASE_URL}/Dashboard/Chart"),
        Reply.ok(body="{}", reply_id="SYNTH_FENCE_CHART"),
    )
    replace_route(
        portal,
        ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
        Reply.ok(body=CHART_JSON, reply_id="SYNTH_FENCE_CHART_DATA"),
    )
    replace_route(
        portal,
        ("GET", f"{PORTAL_BASE_URL}/"),
        Reply.ok(body=LOGIN_HTML, reply_id="SYNTH_FENCE_LOGIN_FORM"),
    )
    replace_route(
        portal,
        ("POST", f"{PORTAL_BASE_URL}/Home/Login"),
        Reply.redirect(
            location=f"{PORTAL_BASE_URL}/Dashboard",
            status_code=302,
            reply_id="SYNTH_FENCE_LOGIN_POST",
        ),
    )


def install_auth_bounce(portal: ScriptedPortal) -> None:
    """Make the next /Dashboard answer a signed-out landing bounce.

    The bounce drives the real mode-specific renewal: L posts the saved local login,
    R re-issues MM_SID from the Remember-Me cookie, S runs the Okta SAML round trip.
    """
    replace_route(
        portal,
        ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
        [
            Reply.redirect(
                location=f"{PORTAL_BASE_URL}/",
                status_code=302,
                reply_id="SYNTH_FENCE_BOUNCE",
            ),
            Reply.ok(body=DASHBOARD_HTML, reply_id="SYNTH_FENCE_DASHBOARD_AFTER_RENEW"),
        ],
    )


def restore_healthy_dashboard(portal: ScriptedPortal) -> None:
    """Restore a single healthy /Dashboard reply after an auth bounce."""
    replace_route(
        portal,
        ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
        Reply.ok(body=DASHBOARD_HTML, reply_id="SYNTH_FENCE_DASHBOARD_HEALTHY"),
    )


def prepare_operation(portal: ScriptedPortal, operation: str) -> None:
    """Apply the scripting a non-setup operation needs before it runs."""
    if operation == "auth_renewal":
        install_auth_bounce(portal)
    else:
        restore_healthy_dashboard(portal)


def _portal_cookie(name: str, value: str, domain: str) -> dict[str, Any]:
    return {"name": name, "value": value, "domain": domain, "path": "/", "secure": True}


def create_flow_entry(hass: HomeAssistant, flow: str) -> MockConfigEntry:
    """Create the flow-mode entry with its declared pasted jar."""
    data: dict[str, Any] = {CONF_METER_ID: METER_ID}
    if flow == "L":
        data[CONF_OKTA_COOKIES] = ""
        data[CONF_PORTAL_COOKIES] = "MM_SID=SYNTH_LOCAL_SID"
        data["mymeter_email"] = "SYNTH_MYMETER_EMAIL"
        data["mymeter_password"] = "SYNTH_MYMETER_PASSWORD"
        data["cookies"] = [_portal_cookie("MM_SID", "SYNTH_LOCAL_SID", PORTAL_HOST)]
    elif flow == "R":
        data[CONF_OKTA_COOKIES] = ""
        data[CONF_PORTAL_COOKIES] = "MM_RememberMe=SYNTH_REMEMBERME"
        data["cookies"] = [_portal_cookie("MM_RememberMe", "SYNTH_REMEMBERME", PORTAL_HOST)]
    elif flow == "S":
        data[CONF_OKTA_COOKIES] = "idx=SYNTH_OKTA"
        data[CONF_PORTAL_COOKIES] = ""
        data["cookies"] = [_portal_cookie("idx", "SYNTH_OKTA", OKTA_HOST)]
    elif flow == "H":
        data[CONF_OKTA_COOKIES] = "idx=SYNTH_HUMAN_OKTA"
        data[CONF_PORTAL_COOKIES] = "MM_SID=SYNTH_HUMAN_SID"
        data["cookies"] = [_portal_cookie("MM_SID", "SYNTH_HUMAN_SID", PORTAL_HOST)]
    else:  # pragma: no cover - guarded by FLOWS
        raise KeyError(flow)

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


def declared_eligible_cookies(portal: ScriptedPortal) -> set[tuple[str, str]]:
    """Collect every cookie value a declared eligible reply may set."""
    found: set[tuple[str, str]] = set()
    with portal._lock:
        scripted = [reply for replies in portal._scripts.values() for reply in replies]
    for reply in scripted:
        if not (reply.valid and reply.cookie_eligible):
            continue
        for name, value in reply.cookies.items():
            found.add((str(name), str(value)))
        set_cookie = reply.headers.get("Set-Cookie")
        if set_cookie is None:
            continue
        raw_values = set_cookie if isinstance(set_cookie, (list, tuple)) else (set_cookie,)
        for raw in raw_values:
            for part in str(raw).split(";"):
                if "=" in part:
                    name, value = part.strip().split("=", 1)
                    found.add((name.strip(), value.strip()))
    return found


def register_initial_jar(oracle: Oracle, entry: MockConfigEntry) -> None:
    """Declare the entry's initial persisted jar as an eligible provenance source."""
    for cookie in entry.data.get("cookies", []):
        oracle.register_eligible_cookie(str(cookie["name"]), str(cookie["value"]))


def register_scripted_eligibility(oracle: Oracle, portal: ScriptedPortal) -> None:
    """Declare eligible scripted replies' cookies as provenance sources."""
    for name, value in declared_eligible_cookies(portal):
        oracle.register_eligible_cookie(name, value)


# ---------------------------------------------------------------------------
# Dry runs
# ---------------------------------------------------------------------------


async def _recorded(
    portal: ScriptedPortal,
    start: int,
) -> tuple[Dispatch, ...]:
    return tuple(portal.dispatches[start:])


async def dry_run_flow(
    hass: HomeAssistant,
    flow: str,
) -> dict[str, tuple[Dispatch, ...]]:
    """Execute one real L/R/S/H lifecycle trace and return per-operation dispatches."""
    portal = ScriptedPortal()
    script_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = create_flow_entry(hass, flow)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    slices: dict[str, tuple[Dispatch, ...]] = {}

    with factory:
        start = len(portal.dispatches)
        assert await driver.setup() is True, f"{flow}: setup failed"
        slices["setup"] = await _recorded(portal, start)

        start = len(portal.dispatches)
        await driver.poll()
        slices["poll"] = await _recorded(portal, start)

        if "auth_renewal" in FLOW_PLANS[flow]:
            install_auth_bounce(portal)
            start = len(portal.dispatches)
            await driver.poll()
            slices["auth_renewal"] = await _recorded(portal, start)
            restore_healthy_dashboard(portal)

        start = len(portal.dispatches)
        await driver.keepalive_tick()
        slices["keepalive"] = await _recorded(portal, start)

        start = len(portal.dispatches)
        await driver.backfill(BACKFILL_START, BACKFILL_END)
        slices["backfill"] = await _recorded(portal, start)

        start = len(portal.dispatches)
        await driver.human_reauth(same_cookies=True)
        slices["reauth"] = await _recorded(portal, start)

        start = len(portal.dispatches)
        await driver.reconfigure({})
        slices["reconfigure"] = await _recorded(portal, start)

        start = len(portal.dispatches)
        await driver.unload()
        slices["unload"] = await _recorded(portal, start)

    return slices


# ---------------------------------------------------------------------------
# Retirement-fence mechanics
# ---------------------------------------------------------------------------


class FencePortal(ScriptedPortal):
    """Scripted transport with a generation-scoped, one-shot before-send gate.

    The gate fires inside the adapter, after the production ownership fence and after
    the attempted send has been recorded. It never blocks a send on its own: only the
    production owner fence can prevent a later dispatch.
    """

    def __init__(self) -> None:
        super().__init__()
        self._tls = threading.local()
        self._fence_target: tuple[str | None, str, str, int] | None = None
        self._fence_seen = 0
        self._fence_gate = Gate("dispatch_fence", default_timeout=10.0)

    @property
    def fence_gate(self) -> Gate:
        return self._fence_gate

    def arm(
        self,
        *,
        generation_id: str | None,
        method: str,
        path: str,
        leg: int = 1,
    ) -> Gate:
        """Park the ``leg``-th matching before-send boundary of one generation."""
        with self._lock:
            self._fence_target = (generation_id, method.upper(), path, leg)
            self._fence_seen = 0
            self._fence_gate.reset()
            self._fence_gate.hold()
        return self._fence_gate

    def handle_send(
        self,
        generation_id: str,
        request: Any,
        stream: bool = False,
        timeout: Any = None,
    ) -> Any:
        self._tls.generation_id = generation_id
        try:
            return super().handle_send(generation_id, request, stream=stream, timeout=timeout)
        finally:
            self._tls.generation_id = None

    def _trigger_gates(self, phase: str, method: str | None, url: str, path: str) -> None:
        target = self._fence_target
        current = getattr(self._tls, "generation_id", None)
        if phase == "before_send" and target is not None and current is not None:
            generation_id, target_method, target_path, target_leg = target
            if (
                (generation_id is None or current == generation_id)
                and (method or "").upper() == target_method
                and path == target_path
            ):
                self._fence_seen += 1
                if self._fence_seen == target_leg:
                    with self._lock:
                        self._fence_target = None
                    self._fence_gate.arrive_and_wait()
                    return
        super()._trigger_gates(phase, method, url, path)


class PreFenceFactory(ClientFactory):
    """Factory that parks the first request *before* the real ownership fence runs."""

    def __init__(
        self,
        portal: ScriptedPortal,
        registry: ClientRegistry,
        gate: Gate,
    ) -> None:
        super().__init__(portal, registry=registry)
        self._pre_fence_gate: Gate | None = gate
        self.pre_fence_hits = 0

    def create_client(self, *args: Any, **kwargs: Any) -> Any:
        client = super().create_client(*args, **kwargs)
        gate = self._pre_fence_gate
        if gate is not None:
            self._pre_fence_gate = None
            original_send = client.session.send
            self_ref = self
            state = {"armed": True}

            def gated_send(request: Any, **send_kwargs: Any) -> Any:
                if state["armed"]:
                    state["armed"] = False
                    self_ref.pre_fence_hits += 1
                    gate.arrive_and_wait()
                return original_send(request, **send_kwargs)

            client.session.send = gated_send
        return client


@dataclass(frozen=True, slots=True)
class TransitionOutcome:
    """Observable facts of one retirement transition."""

    transition: str
    detail: MappingProxyType[str, Any]
    needs_successor: bool


async def apply_transition(driver: LifecycleDriver, transition: str) -> TransitionOutcome:
    """Apply a retirement transition to the current owner while a send is parked."""
    detail: dict[str, Any] = {}
    needs_successor = False
    if transition == "unload":
        detail["unloaded"] = await driver.unload()
        needs_successor = True
    elif transition == "reload":
        detail["reloaded"] = await driver.reload()
    elif transition == "stop":
        await driver.stop()
        detail["unloaded_after_stop"] = await driver.unload()
        needs_successor = True
    elif transition == "cancel":
        await driver.cancel_inflight()
        detail["reloaded_after_cancel"] = await driver.reload()
    elif transition == "handoff":
        result = await driver.human_reauth(same_cookies=True)
        detail["handoff_type"] = str(result.get("type"))
        detail["handoff_reason"] = result.get("reason")
        if result.get("type") is not FlowResultType.ABORT:
            raise AssertionError(
                "Same-cookie human handoff did not commit its renewal: "
                f"type={result.get('type')!r} reason={result.get('reason')!r} "
                f"errors={result.get('errors')!r}"
            )
    else:  # pragma: no cover - guarded by the case matrix
        raise KeyError(transition)
    return TransitionOutcome(
        transition=transition,
        detail=MappingProxyType(detail),
        needs_successor=needs_successor,
    )


@dataclass(frozen=True, slots=True)
class FenceCase:
    """One boundary-retirement fence case."""

    case_id: str
    flow: str
    operation: str
    boundary: Boundary
    transition: str
    tier: str = "slow"
    notes: str = ""


@dataclass(frozen=True, slots=True)
class FenceEvidence:
    """Evidence produced by one fence case."""

    case_id: str
    flow: str
    operation: str
    transition: str
    boundary_id: str
    boundary_classes: tuple[str, ...]
    parked_sequence: int
    parked_outcome: str | None
    later_dispatches: int
    post_retirement_attempts: int
    owner_retired: bool
    successor_generation: str | None
    oracle_codes: tuple[str, ...]
    ending_steps: tuple[str, ...]
    elapsed_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "flow": self.flow,
            "operation": self.operation,
            "transition": self.transition,
            "boundary_id": self.boundary_id,
            "boundary_classes": list(self.boundary_classes),
            "parked_sequence": self.parked_sequence,
            "parked_outcome": self.parked_outcome,
            "later_dispatches": self.later_dispatches,
            "post_retirement_attempts": self.post_retirement_attempts,
            "owner_retired": self.owner_retired,
            "successor_generation": self.successor_generation,
            "oracle_codes": list(self.oracle_codes),
            "ending_steps": list(self.ending_steps),
            "elapsed_seconds": self.elapsed_seconds,
        }


async def _start_operation(driver: LifecycleDriver, operation: str) -> None:
    if operation in ("poll", "auth_renewal"):
        await driver.poll()
    elif operation == "keepalive":
        await driver.keepalive_tick()
    elif operation == "backfill":
        await driver.backfill(BACKFILL_START, BACKFILL_END)
    else:  # pragma: no cover - guarded by SWEEP_OPERATIONS
        raise KeyError(operation)


def _latest_checkpoint(driver: LifecycleDriver, snapshot: Snapshot) -> ExpectationState:
    jar = {str(cookie["name"]): str(cookie["value"]) for cookie in snapshot.persisted_jar}
    generation = driver.client.generation_id if driver.client is not None else "gen_unknown"
    return ExpectationState(
        generation_id=generation,
        latest_checkpoint=Checkpoint(
            generation_id=generation,
            sequence=0,
            jar=MappingProxyType(jar),
            admission=MappingProxyType({}),
            timestamp=0.0,
        ),
    )


def _live_i9_facts(driver: LifecycleDriver) -> dict[str, Any]:
    coordinator = driver.coordinator
    loaded = driver.entry.state is ConfigEntryState.LOADED
    dead = bool(loaded and getattr(coordinator, "_unsub_keepalive", None) is None)
    return {"dead_schedule": dead}


def _assert_invariants(
    driver: LifecycleDriver,
    portal: FencePortal,
    oracle: Oracle,
    snapshot: Snapshot,
) -> dict[str, Any]:
    """Invoke I1, I2, I5 and I9 explicitly on live, post-case surfaces."""
    attempts = portal.recorded_i1_evidence
    i1: list[Any] = []
    for dispatch in attempts:
        i1.extend(oracle.evaluate_i1(dispatch, None))

    # I2 is a send-time invariant: the live observations are the authoritative
    # retirement-aware verdict. A second, retirement-agnostic evaluator then checks
    # each recorded credential POST for policy violations that do not depend on the
    # retirement this case created (the parked send was legitimately in flight).
    fresh = Oracle()
    i2_send_time = [v for obs in oracle.send_observations for v in obs.violations if v.code == "I2"]
    i2: list[Any] = list(i2_send_time)
    for dispatch in portal.dispatches:
        if dispatch.is_redirect_hop:
            # A hop's own response status is not the redirect that caused it; the
            # send-time observation (status unknown, current owner) is authoritative.
            continue
        if dispatch.method == "POST" and any(
            marker in dispatch.url for marker in ("/Home/Login", "/Acs", "/SignIn")
        ):
            i2.extend(fresh.evaluate_i2(dispatch, None))

    i5 = oracle.evaluate_i5(snapshot, oracle.expectation_state)
    i9 = oracle.evaluate_i9(_live_i9_facts(driver))

    assert not i1, f"I1 attempts after retirement: {[v.message for v in i1]}"
    assert not i2, f"I2 credential policy: {[v.message for v in i2]}"
    assert not i5, f"I5 latest checkpoint: {[v.message for v in i5]}"
    assert not i9, f"I9 ownership/liveness: {[v.message for v in i9]}"
    return {
        "post_retirement_attempts": len(attempts),
        "i2_observations": len(i2_send_time),
        "i5_checked": oracle.expectation_state is not None,
        "i9_facts": _live_i9_facts(driver),
    }


async def run_fence_case(
    hass: HomeAssistant,
    case: FenceCase,
    *,
    caplog: Any = None,
) -> FenceEvidence:
    """Park one real dispatch, retire its generation, and prove the fence holds."""
    portal = FencePortal()
    script_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = create_flow_entry(hass, case.flow)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    register_initial_jar(oracle, entry)
    register_scripted_eligibility(oracle, portal)
    if caplog is not None:
        driver.attach_caplog(caplog)
        oracle.attach_caplog(caplog)

    facts: dict[str, Any] = {}

    async def body(current: LifecycleDriver) -> None:
        assert await current.setup() is True, f"{case.case_id}: setup failed"
        await current.poll()
        prepare_operation(portal, case.operation)
        register_scripted_eligibility(oracle, portal)

        owner = current.client
        assert owner is not None, f"{case.case_id}: no client generation after setup"
        generation = owner.generation_id
        gate = portal.arm(
            generation_id=generation,
            method=case.boundary.method,
            path=case.boundary.path,
            leg=case.boundary.leg,
        )
        task = asyncio.ensure_future(_start_operation(current, case.operation))
        await hass.async_add_executor_job(gate.wait_arrived)

        parked_sequence = max(dispatch.sequence for dispatch in portal.dispatches)
        old_coordinator = current.coordinator
        outcome = await apply_transition(current, case.transition)

        gate.proceed()
        await asyncio.gather(task, return_exceptions=True)
        await hass.async_block_till_done()

        parked = next(
            dispatch for dispatch in portal.dispatches if dispatch.sequence == parked_sequence
        )
        later = [
            dispatch
            for dispatch in portal.dispatches
            if dispatch.sequence > parked_sequence and dispatch.generation_id == generation
        ]
        attempts = [
            dispatch
            for dispatch in portal.recorded_i1_evidence
            if dispatch.generation_id == generation
        ]
        retired = portal.get_retirement(generation)
        runtime = getattr(owner, "_renewal_runtime", None)
        token = getattr(owner, "_renewal_token", None)
        owner_inactive = bool(runtime is not None and not runtime.is_active(token))

        assert parked.outcome not in {"pending", "gated"}, (
            f"{case.case_id}: parked dispatch {parked.sequence} never completed "
            f"(outcome={parked.outcome!r})"
        )
        assert not parked.is_after_retire, (
            f"{case.case_id}: parked dispatch was already flagged as post-retirement"
        )
        assert retired is not None, f"{case.case_id}: retirement was not recorded"
        assert owner_inactive, (
            f"{case.case_id}: production ownership token is still active; the fence "
            "would not be a production fence"
        )
        assert not later, (
            f"{case.case_id}: retired generation {generation} dispatched "
            f"{[(d.sequence, d.method, d.url) for d in later]} after {parked.sequence}"
        )
        assert not attempts, (
            f"{case.case_id}: retired generation {generation} produced post-retirement "
            f"attempts {[(d.sequence, d.method) for d in attempts]}"
        )
        assert owner_inactive, f"{case.case_id}: owner token active after retirement"

        successor = current.client
        if outcome.needs_successor is False:
            assert current.coordinator is not None
            if case.transition in ("reload", "cancel", "handoff"):
                assert current.coordinator is not old_coordinator, (
                    f"{case.case_id}: successor coordinator reuses the retired runtime"
                )
                assert current.coordinator.last_update_success is True, (
                    f"{case.case_id}: the retired in-flight poll won the successor status"
                )
                assert current.coordinator.status == "connected", (
                    f"{case.case_id}: successor status is {current.coordinator.status!r}"
                )
            assert successor is not None and successor is not owner, (
                f"{case.case_id}: successor generation is the retired owner"
            )

        snapshot = await current.snapshot()
        oracle.expectation_state = _latest_checkpoint(current, snapshot)
        facts.update(
            {
                "generation": generation,
                "parked_sequence": parked.sequence,
                "parked_outcome": parked.outcome,
                "transition": outcome.detail,
                "owner_inactive": owner_inactive,
                "successor_generation": (
                    None
                    if outcome.needs_successor
                    else (successor.generation_id if successor else None)
                ),
            }
        )

    stopped = case.transition in ("unload", "stop")
    with factory:
        result = await run_case(
            driver,
            body,
            terminal=False,
            stopped=stopped,
            case_name=case.case_id,
            oracle=oracle,
        )
    result.assert_complete()
    assert result.success

    snapshot = await driver.snapshot()
    invariants = _assert_invariants(driver, portal, oracle, snapshot)
    assert not oracle.violations, (
        f"{case.case_id}: oracle violations {[v.code + ': ' + v.message for v in oracle.violations]}"
    )
    assert oracle.send_invocation_count == len(portal.dispatches), (
        f"{case.case_id}: oracle observed {oracle.send_invocation_count} sends but the "
        f"portal recorded {len(portal.dispatches)}"
    )

    return FenceEvidence(
        case_id=case.case_id,
        flow=case.flow,
        operation=case.operation,
        transition=case.transition,
        boundary_id=case.boundary.boundary_id,
        boundary_classes=case.boundary.class_names,
        parked_sequence=int(facts["parked_sequence"]),
        parked_outcome=facts["parked_outcome"],
        later_dispatches=0,
        post_retirement_attempts=int(invariants["post_retirement_attempts"]),
        owner_retired=bool(facts["owner_inactive"]),
        successor_generation=facts["successor_generation"],
        oracle_codes=tuple(str(v.code) for v in oracle.violations),
        ending_steps=tuple(result.ending_steps),
        elapsed_seconds=result.elapsed_time,
    )


# ---------------------------------------------------------------------------
# Pre-fence, human-exemption and current-owner control cases
# ---------------------------------------------------------------------------


async def run_pre_fence_case(hass: HomeAssistant, *, caplog: Any = None) -> dict[str, Any]:
    """Retire before the first request; the production fence must refuse it."""
    portal = ScriptedPortal()
    script_portal(portal)
    gate = Gate("pre_first_request", default_timeout=10.0)
    gate.hold()
    factory = PreFenceFactory(portal, ClientRegistry(), gate)
    entry = create_flow_entry(hass, "L")
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    register_initial_jar(oracle, entry)
    register_scripted_eligibility(oracle, portal)
    if caplog is not None:
        driver.attach_caplog(caplog)
        oracle.attach_caplog(caplog)

    facts: dict[str, Any] = {}

    async def body(current: LifecycleDriver) -> None:
        setup_task = asyncio.ensure_future(current.setup())
        await hass.async_add_executor_job(gate.wait_arrived)
        owner = current.client
        assert owner is not None, "pre-fence case has no constructing generation"
        generation = owner.generation_id
        assert factory.pre_fence_hits == 1
        assert len(portal.dispatches) == 0, (
            "the first request escaped before the ownership fence ran: "
            f"{[(d.method, d.url) for d in portal.dispatches]}"
        )

        runtime = owner._renewal_runtime
        assert runtime is not None, "constructed client has no production renewal runtime"
        # The same production call coordinator.stop_keepalive() makes.
        runtime.retire(owner._renewal_token)
        portal.retire(generation)

        gate.proceed()
        result = await asyncio.gather(setup_task, return_exceptions=True)
        await hass.async_block_till_done()

        assert result[0] is False, f"setup unexpectedly succeeded: {result[0]!r}"
        assert current.entry.state is ConfigEntryState.SETUP_RETRY
        assert not portal.dispatches, (
            f"retired generation still dispatched before its first request: "
            f"{[(d.method, d.url) for d in portal.dispatches]}"
        )
        assert not portal.recorded_i1_evidence
        assert not runtime.is_active(owner._renewal_token)

        successor_ok = await current.reload()
        assert successor_ok is True
        successor = current.client
        assert successor is not None and successor.generation_id != generation
        oracle.expectation_state = _latest_checkpoint(current, await current.snapshot())
        facts.update(
            {
                "generation": generation,
                "successor_generation": successor.generation_id,
                "first_request_blocked": True,
            }
        )

    with factory:
        result = await run_case(driver, body, case_name="pre_fence_first_request", oracle=oracle)
    result.assert_complete()
    assert result.success
    assert not oracle.violations, [str(v.code) + ": " + v.message for v in oracle.violations]
    snapshot = await driver.snapshot()
    invariants = _assert_invariants(driver, portal, oracle, snapshot)  # type: ignore[arg-type]
    return {**facts, **invariants, "ending_steps": list(result.ending_steps)}


async def run_human_exemption_case(hass: HomeAssistant, *, caplog: Any = None) -> dict[str, Any]:
    """An unattached human verification keeps dispatching under the I1 exemption."""
    portal = ScriptedPortal()
    script_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = create_flow_entry(hass, "H")
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    register_initial_jar(oracle, entry)
    register_scripted_eligibility(oracle, portal)
    if caplog is not None:
        driver.attach_caplog(caplog)
        oracle.attach_caplog(caplog)

    facts: dict[str, Any] = {}

    async def body(current: LifecycleDriver) -> None:
        assert await current.setup() is True
        await current.poll()
        owner = current.client
        assert owner is not None
        owner_generation = owner.generation_id
        before = {
            generation: len(portal.dispatches_for(generation))
            for generation in factory.registry.generations
        }

        flow_result = await current.entry.start_reauth_flow(hass)
        flow_id = flow_result["flow_id"]
        confirmed = await hass.config_entries.flow.async_configure(
            flow_id,
            user_input={
                CONF_OKTA_COOKIES: current.entry.data.get(CONF_OKTA_COOKIES, ""),
                CONF_PORTAL_COOKIES: current.entry.data.get(CONF_PORTAL_COOKIES, ""),
            },
        )
        await hass.async_block_till_done()
        hass.config_entries.flow.async_abort(flow_id)
        await hass.async_block_till_done()

        human_generations = [
            generation
            for generation in factory.registry.generations
            if generation != owner_generation
        ]
        assert human_generations, "human reauth did not build unattached verification clients"
        human_dispatches = sum(
            len(portal.dispatches_for(generation)) - before.get(generation, 0)
            for generation in human_generations
        )
        assert human_dispatches > 0, "unattached human verification never dispatched"
        for generation in human_generations:
            client = factory.registry.get(generation)
            assert client is not None
            assert client._renewal_runtime is None, (
                "human verification client unexpectedly owns a production runtime"
            )
        assert str(confirmed.get("type")) in {
            str(FlowResultType.FORM),
            str(FlowResultType.ABORT),
        }
        assert current.coordinator is not None
        assert current.coordinator.client is owner
        assert current.entry.state is ConfigEntryState.LOADED

        # Reconfigure (options flow + reload) stays usable under the same exemption.
        before_reconfigure = len(portal.dispatches)
        await current.reconfigure({})
        assert current.entry.state is ConfigEntryState.LOADED
        assert current.coordinator is not None
        assert current.coordinator.last_update_success is True
        reconfigure_dispatches = len(portal.dispatches) - before_reconfigure
        assert reconfigure_dispatches > 0

        snapshot = await current.snapshot()
        oracle.expectation_state = _latest_checkpoint(current, snapshot)
        facts.update(
            {
                "human_generations": tuple(human_generations),
                "human_dispatches": human_dispatches,
                "owner_generation": owner_generation,
                "flow_result": str(confirmed.get("type")),
                "reconfigure_dispatches": reconfigure_dispatches,
            }
        )

    with factory:
        result = await run_case(driver, body, case_name="human_exemption", oracle=oracle)
    result.assert_complete()
    assert result.success
    assert not oracle.violations, [str(v.code) + ": " + v.message for v in oracle.violations]
    snapshot = await driver.snapshot()
    invariants = _assert_invariants(driver, portal, oracle, snapshot)  # type: ignore[arg-type]
    return {**facts, **invariants, "ending_steps": list(result.ending_steps)}


async def run_current_owner_307_control(
    hass: HomeAssistant, *, caplog: Any = None
) -> dict[str, Any]:
    """A current owner's 307 re-POST still succeeds and is recorded as a redirect hop."""
    portal = ScriptedPortal()
    script_portal(portal)
    replace_route(
        portal,
        ("GET", f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn"),
        Reply.ok(
            body=(
                f'<form action="{PORTAL_BASE_URL}/Saml/okta-prod/Acs307">'
                '<input name="SAMLResponse" value="SYNTH_SAML_ASSERTION"/></form>'
            ),
            reply_id="SYNTH_FENCE_SIGNIN_307",
        ),
    )
    replace_route(
        portal,
        ("POST", f"{PORTAL_BASE_URL}/Saml/okta-prod/Acs307"),
        Reply.redirect(
            location=f"{PORTAL_BASE_URL}/Saml/okta-prod/Acs",
            status_code=307,
            reply_id="SYNTH_FENCE_ACS_307",
        ),
    )
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = create_flow_entry(hass, "S")
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    register_initial_jar(oracle, entry)
    register_scripted_eligibility(oracle, portal)
    if caplog is not None:
        driver.attach_caplog(caplog)
        oracle.attach_caplog(caplog)

    facts: dict[str, Any] = {}

    async def body(current: LifecycleDriver) -> None:
        assert await current.setup() is True
        client = current.client
        assert client is not None
        generation = client.generation_id
        assert portal.get_retirement(generation) is None
        renewed = await hass.async_add_executor_job(client.renew_sso)
        await hass.async_block_till_done()
        assert renewed is True
        await current.poll()
        assert current.coordinator is not None and current.coordinator.last_update_success

        acs_posts = [
            dispatch
            for dispatch in portal.dispatches_for(generation)
            if dispatch.method == "POST" and "/Acs" in dispatch.url
        ]
        assert len(acs_posts) == 2, (
            f"expected the 307 re-POST control, saw {[(d.method, d.url) for d in acs_posts]}"
        )
        causing, re_post = acs_posts
        assert causing.url.endswith("/Acs307") and causing.status_code == 307
        assert re_post.is_redirect_hop is True
        assert re_post.url.endswith("/Acs")
        assert re_post.body_digest == causing.body_digest, (
            "the 307 re-POST changed the SAML assertion body"
        )
        assert re_post.hop_cause == f"redirect:{causing.sequence}"
        assert not [
            violation
            for observation in oracle.send_observations
            for violation in observation.violations
            if violation.code == "I2"
        ], "the permitted current-owner 307 re-POST raised I2"
        assert portal.get_retirement(generation) is None
        assert client._renewal_runtime.is_active(client._renewal_token)

        snapshot = await current.snapshot()
        oracle.expectation_state = _latest_checkpoint(current, snapshot)
        facts.update(
            {
                "generation": generation,
                "acs_sequence": causing.sequence,
                "re_post_sequence": re_post.sequence,
                "body_digest": re_post.body_digest,
            }
        )

    with factory:
        result = await run_case(driver, body, case_name="current_owner_307", oracle=oracle)
    result.assert_complete()
    assert result.success
    assert not oracle.violations, [str(v.code) + ": " + v.message for v in oracle.violations]
    snapshot = await driver.snapshot()
    invariants = _assert_invariants(driver, portal, oracle, snapshot)  # type: ignore[arg-type]
    return {**facts, **invariants, "ending_steps": list(result.ending_steps)}


def unattached_exemption_probe() -> tuple[list[str], list[str]]:
    """Return (exempt, attached) I1 verdicts for identical retired dispatches."""
    oracle = Oracle()
    oracle.retire_generation("gen_human")
    exempt = oracle.evaluate_i1(
        Dispatch(
            generation_id="gen_human",
            sequence=1,
            method="POST",
            url=f"{PORTAL_BASE_URL}/Home/Login",
            is_after_retire=True,
            headers={"X-Unattached-Flow": "true"},
        )
    )
    attached = oracle.evaluate_i1(
        Dispatch(
            generation_id="gen_human",
            sequence=2,
            method="POST",
            url=f"{PORTAL_BASE_URL}/Home/Login",
            is_after_retire=True,
        )
    )
    return [str(v.code) for v in exempt], [str(v.code) for v in attached]


__all__ = [
    "ALL_BOUNDARY_CLASSES",
    "ATTACHED_TRANSITIONS",
    "BACKFILL_END",
    "BACKFILL_START",
    "Boundary",
    "BoundaryClass",
    "EXCLUSIONS",
    "FLOWS",
    "FLOW_PLANS",
    "FenceCase",
    "FenceEvidence",
    "FencePortal",
    "OPERATIONS",
    "PreFenceFactory",
    "RETIREMENT_TRANSITIONS",
    "SWEEP_OPERATIONS",
    "apply_transition",
    "classify_legs",
    "compare_inventory",
    "create_flow_entry",
    "declared_eligible_cookies",
    "dry_run_flow",
    "generated_boundaries",
    "install_auth_bounce",
    "observed_boundaries",
    "observed_legs",
    "prepare_operation",
    "register_initial_jar",
    "register_scripted_eligibility",
    "replace_route",
    "restore_healthy_dashboard",
    "run_current_owner_307_control",
    "run_fence_case",
    "run_human_exemption_case",
    "run_old_status_control",
    "run_pre_fence_case",
    "script_portal",
    "unattached_exemption_probe",
]


async def run_old_status_control(hass: HomeAssistant, *, caplog: Any = None) -> dict[str, Any]:
    """Release a blocked old request after successor setup; the old status cannot win."""
    portal = FencePortal()
    script_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = create_flow_entry(hass, "L")
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    register_initial_jar(oracle, entry)
    register_scripted_eligibility(oracle, portal)
    if caplog is not None:
        driver.attach_caplog(caplog)
        oracle.attach_caplog(caplog)

    facts: dict[str, Any] = {}

    async def body(current: LifecycleDriver) -> None:
        assert await current.setup() is True
        await current.poll()
        owner = current.client
        assert owner is not None
        generation = owner.generation_id
        old_coordinator = current.coordinator
        assert old_coordinator is not None
        jar_before = copy.deepcopy(list(current.entry.data.get("cookies", [])))

        gate = portal.arm(generation_id=generation, method="GET", path="/Dashboard", leg=1)
        task = asyncio.ensure_future(current.poll())
        await hass.async_add_executor_job(gate.wait_arrived)
        parked_sequence = max(dispatch.sequence for dispatch in portal.dispatches)

        await current.cancel_inflight()
        assert await current.reload() is True
        gate.proceed()
        await asyncio.gather(task, return_exceptions=True)
        await hass.async_block_till_done()

        successor = current.coordinator
        assert successor is not None and successor is not old_coordinator
        assert successor.last_update_success is True, (
            "the retired in-flight poll won the successor status"
        )
        assert successor.status == "connected"
        successor_client = current.client
        assert successor_client is not None and successor_client is not owner
        assert successor_client.generation_id != generation
        assert not [
            dispatch
            for dispatch in portal.dispatches
            if dispatch.sequence > parked_sequence and dispatch.generation_id == generation
        ], "the blocked old generation dispatched after the successor took over"
        assert list(current.entry.data.get("cookies", [])) == jar_before, (
            "the retired request rewrote the successor's persisted jar"
        )
        assert current.entry.state is ConfigEntryState.LOADED

        snapshot = await current.snapshot()
        oracle.expectation_state = _latest_checkpoint(current, snapshot)
        facts.update(
            {
                "retired_generation": generation,
                "successor_generation": successor_client.generation_id,
                "successor_status": successor.status,
                "successor_last_update_success": successor.last_update_success,
                "parked_sequence": parked_sequence,
            }
        )

    with factory:
        result = await run_case(driver, body, case_name="old_status_control", oracle=oracle)
    result.assert_complete()
    assert result.success
    assert not oracle.violations, [str(v.code) + ": " + v.message for v in oracle.violations]
    snapshot = await driver.snapshot()
    invariants = _assert_invariants(driver, portal, oracle, snapshot)  # type: ignore[arg-type]
    return {**facts, **invariants, "ending_steps": list(result.ending_steps)}

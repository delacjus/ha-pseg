"""Case matrix and runner for the P2-07 exit/await latest-checkpoint sweep.

Every case drives a real L/R entry through two independently eligible whole-jar
checkpoints (two validated rotations), then parks a live lifecycle operation at one
named before/after exit gate from :mod:`tests.support.factory`, applies a real exit
(cancel the refresh task, unload, stop, or a failed setup), and asserts at that exit
- before any teardown or follow-on poll can rescue the state - that physical storage
holds the latest eligible jar together with its matching settled admission. It then
compares the warm next-poll decision with the cold-restarted one (I6) and hands the
mandatory ``run_case`` follow-on.

``pending_confirmed_snapshot()`` is the production contract under test: an exit must
persist the immutable checkpoint published after the complete leg validates, never the
penultimate one and never a live jar mutation.

Test-only: nothing here modifies ``custom_components/``. The only shared edit is the
P2-01 exit-boundary catalog completed in :mod:`tests.support.factory`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
import dataclasses
from dataclasses import dataclass
import re
import threading
from types import MappingProxyType
from typing import Any

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant

from custom_components.pseg.const import PORTAL_BASE_URL
from tests.support.expectation import Checkpoint, ExpectationState
from tests.support.factory import (
    EXIT_BOUNDARY_CATALOG,
    EXIT_BOUNDARY_GATE_EXCLUSIONS,
    ClientFactory,
    ClientRegistry,
    ExitBoundary,
)
from tests.support.lifecycle import LifecycleDriver, Snapshot, run_case
from tests.support.oracle import Oracle
from tests.support.portal import Dispatch, Gate, Reply, ScriptedPortal

PORTAL = PORTAL_BASE_URL

DASHBOARD_HTML = (
    "<html><head><title>Dashboard</title></head><body>"
    '<input name="__RequestVerificationToken" type="hidden" value="SYNTH_EXIT_TOKEN"/>'
    "Dashboard</body></html>"
)
LANDING_HTML = (
    "<html><body><form>"
    '<input name="__RequestVerificationToken" type="hidden" value="SYNTH_EXIT_LOGIN_TOKEN"/>'
    "</form></body></html>"
)
CHART_JSON = (
    '{"Data": {"series": [{"name": "Meter #12345678", '
    '"data": [{"y": 1.5, "x": 1729382400000, "hs": {"start": "10/20/2026"}}]}]}}'
)

BACKFILL_START = "2026-10-01"
BACKFILL_END = "2026-10-10"

TRANSITIONS: tuple[str, ...] = ("cancel", "unload", "stop", "setup-failure")

#: Cookie names rotated by the declared responses (SID / RememberMe / auxiliary).
ROTATION_COOKIES: tuple[str, ...] = ("MM_SID", "MM_RememberMe", "MM_AuxUtil")

#: Declared rotation values: two prelude checkpoints plus the exit rotation.
ROTATION_VALUES: tuple[str, str, str] = (
    "SYNTH_CKPT_ONE",
    "SYNTH_CKPT_TWO",
    "SYNTH_CKPT_EXIT",
)

INITIAL_JARS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        # L: pasted local portal session cookie (no Remember-Me credential).
        "L": MappingProxyType({"MM_SID": "SYNTH_LOCAL_SID"}),
        # R: Remember-Me credential only; MM_SID is issued by a renewal.
        "R": MappingProxyType({"MM_RememberMe": "SYNTH_REMEMBERME"}),
    }
)

#: Transitions that each catalog boundary can genuinely exercise, with the reason
#: recorded for every excluded combination below.
APPLICABLE_TRANSITIONS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "fetch_energy_data": TRANSITIONS,
        "keepalive": ("unload", "stop"),
        "fetch_history_range": ("cancel", "unload", "stop"),
        "export_cookies_and_auth_reason": ("cancel", "unload", "stop"),
        "confirmed_cookies": ("stop",),
        "pending_confirmed_snapshot": ("stop",),
    }
)

EXCLUSIONS: Mapping[str, str] = MappingProxyType(
    {
        "keepalive:cancel": (
            "keepalive runs on the timer callback, not the coordinator refresh task: "
            "cancel_inflight() only unsubscribes the next scheduled refresh, so there is "
            "no in-flight poll to cancel at a keepalive boundary. Covered by unload/stop."
        ),
        "keepalive:setup-failure": (
            "the keepalive timer only starts after a successful setup; a failed setup "
            "never reaches a keepalive boundary."
        ),
        "fetch_history_range:setup-failure": (
            "backfill is a service call on a loaded entry; entry setup never runs the "
            "history leg, so a failed setup cannot reach this boundary."
        ),
        "export_cookies_and_auth_reason:setup-failure": (
            "the authenticated cookie/auth export runs after a successful poll or "
            "keepalive fetch; a failing setup raises on its first refresh and its exit "
            "handoff persists the already-confirmed session without any export."
        ),
        "confirmed_cookies:cancel": (
            "confirmed_cookies() is a synchronous event-loop accessor; a transition that "
            "needs the loop (cancel/unload) cannot interleave inside it without "
            "deadlocking, so only the synchronous production stop_keepalive() is used."
        ),
        "confirmed_cookies:unload": (
            "confirmed_cookies() is a synchronous event-loop accessor; unloading needs the "
            "loop, so only the synchronous production stop_keepalive() interleaves there."
        ),
        "confirmed_cookies:setup-failure": (
            "confirmed_cookies() is only reached by the authenticated persistence handoff "
            "on a loaded entry; a failed setup never calls it."
        ),
        "pending_confirmed_snapshot:cancel": (
            "pending_confirmed_snapshot() is a synchronous event-loop accessor; cancelling "
            "the refresh task needs the loop, so only the synchronous production "
            "stop_keepalive() interleaves there."
        ),
        "pending_confirmed_snapshot:unload": (
            "pending_confirmed_snapshot() is a synchronous event-loop accessor; unloading "
            "needs the loop, so only the synchronous production stop_keepalive() "
            "interleaves there."
        ),
        "pending_confirmed_snapshot:setup-failure": (
            "pending_confirmed_snapshot() is only read by the authenticated persistence "
            "handoff on a loaded entry; a failed setup never calls it."
        ),
        "export_cookies": EXIT_BOUNDARY_GATE_EXCLUSIONS["export_cookies"],
    }
)


# ---------------------------------------------------------------------------
# Declared checkpoint expectations
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExpectedCheckpoint:
    """One independently declared jar/admission pair at a named exit."""

    label: str
    jar: Mapping[str, str]
    admission: Mapping[str, Any]
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "jar": dict(self.jar),
            "admission": dict(self.admission),
            "sequence": self.sequence,
        }


def flow_for(renewal: bool) -> str:
    """Return the flow that carries the requested renewal dimension."""
    return "R" if renewal else "L"


def initial_jar(flow: str) -> dict[str, str]:
    """Return the entry's declared initial persisted jar."""
    return dict(INITIAL_JARS[flow])


def rotated_jar(base: Mapping[str, str], cookie: str, value: str) -> dict[str, str]:
    """Return the expected whole jar after one declared validated rotation."""
    jar = dict(base)
    jar[cookie] = value
    return jar


def _runtime_admission(client: Any) -> dict[str, Any]:
    runtime = getattr(client, "_renewal_runtime", None)
    if runtime is None:
        return {}
    return dict(runtime.admission_dict() or {})


def _jar_of(cookies: Sequence[Any]) -> dict[str, str]:
    return {str(cookie["name"]): str(cookie["value"]) for cookie in cookies}


def _snapshot_jar(snapshot: Snapshot) -> dict[str, str]:
    return _jar_of(snapshot.persisted_jar)


# ---------------------------------------------------------------------------
# Scripting
# ---------------------------------------------------------------------------


def _rotation_header(cookie: str, value: str) -> dict[str, str]:
    return {"Set-Cookie": f"{cookie}={value}; Path=/; Secure; HttpOnly"}


def _script_healthy_operation(
    portal: ScriptedPortal,
    *,
    cookie: str,
    value: str,
    renewal: bool,
    fail_chart_data: bool = False,
) -> None:
    """Script one operation with a declared validated rotation at its exit leg.

    ``renewal`` scripts a signed-out bounce first so the real mode-specific renewal
    runs (Remember-Me GET sequence for R). ``fail_chart_data`` makes the *second*
    daily chart read a typed transient so a setup attempt fails after the renewal
    already published its checkpoint.
    """
    from tests.support.boundaries import replace_route

    rotation = _rotation_header(cookie, value)
    if renewal:
        replace_route(
            portal,
            ("GET", f"{PORTAL}/Dashboard"),
            [
                Reply.redirect(
                    location=f"{PORTAL}/",
                    status_code=302,
                    reply_id="SYNTH_EXIT_BOUNCE",
                ),
                Reply.ok(
                    body=DASHBOARD_HTML,
                    headers=rotation,
                    reply_id="SYNTH_EXIT_DASHBOARD_RENEWED",
                ),
            ],
        )
    elif fail_chart_data:
        # A failed setup without a renewal never validates a chart, so it must not
        # rotate (or confirm) anything: the boundary is reached with checkpoint B.
        replace_route(
            portal,
            ("GET", f"{PORTAL}/Dashboard"),
            Reply.ok(body=DASHBOARD_HTML, reply_id="SYNTH_EXIT_DASHBOARD_FAILING"),
        )
    else:
        replace_route(
            portal,
            ("GET", f"{PORTAL}/Dashboard"),
            Reply.ok(
                body=DASHBOARD_HTML,
                headers=rotation,
                reply_id="SYNTH_EXIT_DASHBOARD",
            ),
        )
    replace_route(
        portal,
        ("POST", f"{PORTAL}/Dashboard/Chart"),
        Reply.ok(body="{}", reply_id="SYNTH_EXIT_CHART"),
    )
    rotated = Reply.ok(
        body=CHART_JSON,
        headers=rotation,
        reply_id="SYNTH_EXIT_CHART_DATA_ROTATED",
    )
    failed = Reply(
        status_code=500,
        body="",
        reply_id="SYNTH_EXIT_CHART_DATA_500",
        valid=False,
        cookie_eligible=False,
    )
    if not fail_chart_data:
        chart_data: list[Reply] = [rotated]
    elif renewal:
        # The renewal's own identity proof consumes the rotated read; the poll's
        # authoritative daily read then hits the typed transient.
        chart_data = [rotated, failed]
    else:
        # Without a renewal the first read is the daily leg: fail it immediately so
        # the hourly optional-leg fallback cannot rescue the setup attempt.
        chart_data = [failed]
    replace_route(portal, ("GET", f"{PORTAL}/Dashboard/ChartData"), chart_data)
    replace_route(
        portal,
        ("GET", f"{PORTAL}/"),
        Reply.ok(body=LANDING_HTML, reply_id="SYNTH_EXIT_LANDING"),
    )
    replace_route(
        portal,
        ("GET", f"{PORTAL}/Home/Login"),
        Reply.ok(body=LANDING_HTML, reply_id="SYNTH_EXIT_LOGIN_FORM"),
    )


def _script_plain_operation(portal: ScriptedPortal) -> None:
    """Script a plain healthy operation with no declared rotation (follow-on)."""
    from tests.support.boundaries import replace_route

    replace_route(
        portal,
        ("GET", f"{PORTAL}/Dashboard"),
        Reply.ok(body=DASHBOARD_HTML, reply_id="SYNTH_EXIT_DASHBOARD_PLAIN"),
    )
    replace_route(
        portal,
        ("POST", f"{PORTAL}/Dashboard/Chart"),
        Reply.ok(body="{}", reply_id="SYNTH_EXIT_CHART_PLAIN"),
    )
    replace_route(
        portal,
        ("GET", f"{PORTAL}/Dashboard/ChartData"),
        Reply.ok(body=CHART_JSON, reply_id="SYNTH_EXIT_CHART_DATA_PLAIN"),
    )


def _script_setup_failure(
    portal: ScriptedPortal, *, cookie: str, value: str, renewal: bool
) -> None:
    """Script a setup attempt whose chart read fails after any renewal checkpoint."""
    _script_healthy_operation(
        portal,
        cookie=cookie,
        value=value,
        renewal=renewal,
        fail_chart_data=True,
    )


# ---------------------------------------------------------------------------
# Boundary probe
# ---------------------------------------------------------------------------


class ExitProbe:
    """Wrap one catalog exit method with its before/after gate.

    Executor boundaries park the calling worker on a bounded gate so the test can
    apply a real lifecycle exit while the client is still inside the method. Loop
    boundaries (synchronous event-loop accessors) run one synchronous production
    transition inline instead, because awaiting there would deadlock the loop.
    """

    def __init__(
        self,
        boundary: ExitBoundary,
        *,
        on_loop_hit: Callable[[Any, Any], None] | None = None,
    ) -> None:
        self.boundary = boundary
        self.gate = Gate(f"exit:{boundary.boundary_id}", default_timeout=10.0)
        self.gate.hold()
        self.hits = 0
        self.armed = True
        self.finished = threading.Event()
        self._on_loop_hit = on_loop_hit
        self._local = threading.local()

    @property
    def blocking(self) -> bool:
        return self.boundary.runner == "executor"

    def install(self, client: Any) -> None:
        """Install the phase gate around one client instance's catalog method."""
        original = getattr(client, self.boundary.name)
        probe = self

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if getattr(probe._local, "active", False):
                return original(*args, **kwargs)
            probe._local.active = True
            try:
                if probe.boundary.phase == "before":
                    probe._hit(client, None)
                try:
                    result = original(*args, **kwargs)
                except BaseException:
                    if probe.boundary.phase == "after":
                        probe._hit(client, None)
                    raise
                if probe.boundary.phase == "after":
                    probe._hit(client, result)
                return result
            finally:
                probe._local.active = False
                probe.finished.set()

        setattr(client, self.boundary.name, wrapper)

    def _hit(self, client: Any, result: Any) -> None:
        if not self.armed:
            return
        self.armed = False
        self.hits += 1
        if self.blocking:
            self.gate.arrive_and_wait()
            return
        if self._on_loop_hit is not None:
            self._on_loop_hit(client, result)


class ProbeFactory(ClientFactory):
    """Factory that installs the active exit probe on every new client generation."""

    def __init__(self, portal: ScriptedPortal, registry: ClientRegistry | None = None) -> None:
        super().__init__(portal, registry=registry)
        self.probe: ExitProbe | None = None

    def create_client(self, *args: Any, **kwargs: Any) -> Any:
        client = super().create_client(*args, **kwargs)
        if self.probe is not None:
            self.probe.install(client)
        return client


# ---------------------------------------------------------------------------
# Case matrix
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExitCase:
    """One exit-boundary x transition x renewal x rotation case."""

    case_id: str
    boundary: ExitBoundary
    transition: str
    renewal: bool
    rotation: str
    tier: str = "slow"

    @property
    def flow(self) -> str:
        return flow_for(self.renewal)


@dataclass(frozen=True, slots=True)
class ExitEvidence:
    """Observable outcome of one exit case."""

    case_id: str
    boundary_id: str
    transition: str
    renewal: bool
    rotation: str
    flow: str
    boundary_reached: bool
    checkpoint_a: MappingProxyType[str, Any]
    checkpoint_b: MappingProxyType[str, Any]
    expected: MappingProxyType[str, Any]
    persisted: MappingProxyType[str, Any]
    cold_matches_warm: bool
    oracle_codes: tuple[str, ...]
    ending_steps: tuple[str, ...]
    elapsed_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "boundary_id": self.boundary_id,
            "transition": self.transition,
            "renewal": self.renewal,
            "rotation": self.rotation,
            "flow": self.flow,
            "boundary_reached": self.boundary_reached,
            "checkpoint_a": dict(self.checkpoint_a),
            "checkpoint_b": dict(self.checkpoint_b),
            "expected": dict(self.expected),
            "persisted": dict(self.persisted),
            "cold_matches_warm": self.cold_matches_warm,
            "oracle_codes": list(self.oracle_codes),
            "ending_steps": list(self.ending_steps),
            "elapsed_seconds": self.elapsed_seconds,
        }


def _case_id(boundary: ExitBoundary, transition: str, renewal: bool, rotation: str) -> str:
    renewal_tag = "renewal" if renewal else "no-renewal"
    return f"{boundary.boundary_id}::{transition}::{renewal_tag}::{rotation}"


FAST_KEYS: tuple[tuple[str, str, bool, str], ...] = (
    ("after:fetch_energy_data", "cancel", True, "MM_SID"),
    ("before:fetch_energy_data", "cancel", False, "MM_SID"),
    ("after:export_cookies_and_auth_reason", "cancel", True, "MM_AuxUtil"),
    ("after:pending_confirmed_snapshot", "stop", False, "MM_RememberMe"),
    ("before:confirmed_cookies", "stop", True, "MM_SID"),
    ("after:fetch_energy_data", "stop", False, "MM_RememberMe"),
)


def build_cases() -> tuple[ExitCase, ...]:
    """Build the complete applicable matrix in declaration order."""
    fast = set(FAST_KEYS)
    cases: list[ExitCase] = []
    for boundary in EXIT_BOUNDARY_CATALOG:
        for transition in APPLICABLE_TRANSITIONS[boundary.name]:
            for renewal in (False, True):
                for rotation in ROTATION_COOKIES:
                    key = (boundary.boundary_id, transition, renewal, rotation)
                    cases.append(
                        ExitCase(
                            case_id=_case_id(boundary, transition, renewal, rotation),
                            boundary=boundary,
                            transition=transition,
                            renewal=renewal,
                            rotation=rotation,
                            tier="fast" if key in fast else "slow",
                        )
                    )
    return tuple(cases)


ALL_CASES: tuple[ExitCase, ...] = build_cases()
FAST_CASES: tuple[ExitCase, ...] = tuple(case for case in ALL_CASES if case.tier == "fast")
SLOW_CASES: tuple[ExitCase, ...] = tuple(case for case in ALL_CASES if case.tier == "slow")

assert len(FAST_CASES) == len(FAST_KEYS), "fast case keys must name real cases"


def excluded_combinations() -> tuple[tuple[str, str], ...]:
    """Return every catalog boundary x transition pair with no case."""
    excluded: list[tuple[str, str]] = []
    for boundary in EXIT_BOUNDARY_CATALOG:
        for transition in TRANSITIONS:
            if transition not in APPLICABLE_TRANSITIONS[boundary.name]:
                excluded.append((boundary.boundary_id, transition))
    return tuple(excluded)


def coverage_problems() -> list[str]:
    """Return every coverage/exclusion-closure defect in the matrix."""
    problems: list[str] = []
    covered = {(case.boundary.boundary_id, case.transition) for case in ALL_CASES}
    for boundary in EXIT_BOUNDARY_CATALOG:
        for transition in TRANSITIONS:
            key = (boundary.boundary_id, transition)
            if key in covered:
                continue
            reason = EXCLUSIONS.get(f"{boundary.name}:{transition}")
            if reason is None:
                problems.append(f"unsupported combination without a reason: {key}")
            elif not reason.strip():
                problems.append(f"empty exclusion reason: {key}")
    for key in EXCLUSIONS:
        name = key.split(":", 1)[0]
        if name not in {boundary.name for boundary in EXIT_BOUNDARY_CATALOG}:
            continue
        transition = key.split(":", 1)[1]
        if (key, transition) in covered:  # pragma: no cover - defensive
            problems.append(f"exclusion reason for a supported combination: {key}")
    for case in ALL_CASES:
        if case.transition not in APPLICABLE_TRANSITIONS[case.boundary.name]:
            problems.append(f"case uses an unsupported transition: {case.case_id}")
        if case.rotation not in ROTATION_COOKIES:
            problems.append(f"case uses an undeclared rotation: {case.case_id}")
    for boundary_id, transition in excluded_combinations():
        if f"{boundary_id.split(':', 1)[1]}:{transition}" not in EXCLUSIONS:
            problems.append(f"excluded combination not recorded: {boundary_id}/{transition}")
    return problems


def boundary_coverage() -> dict[str, int]:
    """Count cases per catalog boundary id (closure is asserted by the suite)."""
    counts: dict[str, int] = {boundary.boundary_id: 0 for boundary in EXIT_BOUNDARY_CATALOG}
    for case in ALL_CASES:
        counts[case.boundary.boundary_id] += 1
    return counts


def case_tiers() -> dict[str, int]:
    """Return the fast/slow case counts."""
    return {"fast": len(FAST_CASES), "slow": len(SLOW_CASES)}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _RuntimeView:
    """Separate warm/cold runtime surface for the oracle's I6 comparison."""

    coordinator: Any
    client: Any
    dispatches: tuple[Dispatch, ...]

    @property
    def session(self) -> Any:
        return getattr(self.client, "session", None)


_VOLATILE_QUERY = re.compile(r"([?&])_=\d+")


def _normalized(dispatches: Sequence[Dispatch]) -> tuple[Dispatch, ...]:
    """Normalize the declared volatile ChartData clock parameter.

    Only a declared clock offset is normalized: the millisecond ``_`` cache-buster.
    Generation ids are normalized by the oracle itself.
    """
    return tuple(
        dataclasses.replace(dispatch, url=_VOLATILE_QUERY.sub(r"\1_=CLOCK", dispatch.url))
        for dispatch in dispatches
    )


async def _start_operation(driver: LifecycleDriver, operation: str) -> None:
    if operation == "poll":
        await driver.poll()
    elif operation == "keepalive":
        await driver.keepalive_tick()
    elif operation == "backfill":
        await driver.backfill(BACKFILL_START, BACKFILL_END)
    else:  # pragma: no cover - guarded by the catalog
        raise KeyError(operation)


def _expected_state(case: ExitCase, checkpoint: ExpectedCheckpoint) -> ExpectationState:
    return ExpectationState(
        generation_id=f"{case.case_id}:expected",
        sequence=checkpoint.sequence,
        latest_checkpoint=Checkpoint(
            generation_id=f"{case.case_id}:expected",
            sequence=checkpoint.sequence,
            jar=MappingProxyType(dict(checkpoint.jar)),
            admission=MappingProxyType(dict(checkpoint.admission)),
            timestamp=0.0,
        ),
    )


async def _assert_persisted_pair(
    driver: LifecycleDriver,
    oracle: Oracle,
    case: ExitCase,
    expected: ExpectedCheckpoint,
) -> Snapshot:
    """Assert the physical exit state holds exactly the expected latest pair."""
    snapshot = await driver.snapshot()
    persisted_jar = _snapshot_jar(snapshot)
    persisted_admission = dict(snapshot.renewal_admission)
    assert persisted_jar == dict(expected.jar), (
        f"{case.case_id}: physical jar at exit '{expected.label}' is not the latest "
        f"eligible checkpoint (expected {dict(expected.jar)}, persisted {persisted_jar})"
    )
    assert persisted_admission == dict(expected.admission), (
        f"{case.case_id}: physical admission at exit '{expected.label}' does not match "
        f"the latest checkpoint's settled admission (expected {dict(expected.admission)}, "
        f"persisted {persisted_admission})"
    )
    state = _expected_state(case, expected)
    oracle.expectation_state = state
    violations = oracle.evaluate_i5(snapshot, state)
    assert not violations, (
        f"{case.case_id}: I5 latest checkpoint at exit '{expected.label}': "
        f"{[violation.message for violation in violations]}"
    )
    return snapshot


def _capture_pending(
    client: Any,
    *,
    label: str,
    sequence: int,
    declared_jar: Mapping[str, str],
) -> ExpectedCheckpoint:
    """Capture the immutable checkpoint production published at the boundary."""
    snapshot = client.pending_confirmed_snapshot()
    assert snapshot is not None, (
        f"exit boundary '{label}' was reached with no immutable confirmed checkpoint "
        "published; the exit could only save the penultimate or a live jar"
    )
    assert snapshot["cookies_confirmed"] is True, (
        f"exit boundary '{label}' published an unconfirmed jar checkpoint"
    )
    assert snapshot["auth_reason"] is None, (
        f"exit boundary '{label}' published a checkpoint from a refused session: "
        f"{snapshot['auth_reason']!r}"
    )
    jar = _jar_of(snapshot["cookies"])
    assert jar == dict(declared_jar), (
        f"exit boundary '{label}' published a jar that is not the declared latest "
        f"eligible whole jar (declared {dict(declared_jar)}, published {jar})"
    )
    return ExpectedCheckpoint(
        label=label,
        jar=jar,
        admission=_runtime_admission(client),
        sequence=sequence,
    )


def _live_i9_facts(driver: LifecycleDriver) -> dict[str, Any]:
    coordinator = driver.coordinator
    loaded = driver.entry.state is ConfigEntryState.LOADED
    dead = bool(loaded and getattr(coordinator, "_unsub_keepalive", None) is None)
    return {"dead_schedule": dead}


async def run_exit_case(
    hass: HomeAssistant,
    case: ExitCase,
    *,
    caplog: Any = None,
) -> ExitEvidence:
    """Run one exit/await checkpoint case through the mandatory follow-on."""
    from tests.support.boundaries import (
        create_flow_entry,
        register_initial_jar,
        register_scripted_eligibility,
        script_portal,
    )

    portal = ScriptedPortal()
    script_portal(portal)
    factory = ProbeFactory(portal, registry=ClientRegistry())
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
    operation = case.boundary.operation
    transition = case.transition

    async def body(current: LifecycleDriver) -> None:
        assert await current.setup() is True, f"{case.case_id}: setup failed"
        base = initial_jar(case.flow)

        # Checkpoint A: first independently eligible whole-jar rotation.
        _script_healthy_operation(
            portal,
            cookie=case.rotation,
            value=ROTATION_VALUES[0],
            renewal=False,
        )
        register_scripted_eligibility(oracle, portal)
        jar_a = rotated_jar(base, case.rotation, ROTATION_VALUES[0])
        await current.poll()
        checkpoint_a = ExpectedCheckpoint(
            label="checkpoint_a",
            jar=jar_a,
            admission=_runtime_admission(current.client),
            sequence=1,
        )
        await _assert_persisted_pair(current, oracle, case, checkpoint_a)

        # Checkpoint B: a second, independently eligible rotation (latest).
        _script_healthy_operation(
            portal,
            cookie=case.rotation,
            value=ROTATION_VALUES[1],
            renewal=False,
        )
        register_scripted_eligibility(oracle, portal)
        jar_b = rotated_jar(base, case.rotation, ROTATION_VALUES[1])
        await current.poll()
        checkpoint_b = ExpectedCheckpoint(
            label="checkpoint_b",
            jar=jar_b,
            admission=_runtime_admission(current.client),
            sequence=2,
        )
        await _assert_persisted_pair(current, oracle, case, checkpoint_b)
        assert dict(checkpoint_a.jar) != dict(checkpoint_b.jar), (
            f"{case.case_id}: the two eligible checkpoints are indistinguishable"
        )

        # The exit leg rotates a third time; a renewal dimension adds its real
        # mode-specific renewal so the exit checkpoint's admission can differ.
        exit_jar = rotated_jar(base, case.rotation, ROTATION_VALUES[2])

        loop_hits: list[ExpectedCheckpoint] = []

        def on_loop_hit(client: Any, _result: Any) -> None:
            loop_hits.append(
                _capture_pending(
                    client,
                    label=case.boundary.boundary_id,
                    sequence=3,
                    declared_jar=exit_jar,
                )
            )
            # The only transition that can interleave inside a synchronous
            # event-loop accessor is the synchronously callable production stop.
            coordinator = current.coordinator
            assert coordinator is not None
            coordinator.stop_keepalive()

        probe = ExitProbe(case.boundary, on_loop_hit=on_loop_hit)
        factory.probe = probe

        expected: ExpectedCheckpoint
        if transition == "setup-failure":
            assert await current.unload() is True
            register_scripted_eligibility(oracle, portal)
            _script_setup_failure(
                portal,
                cookie=case.rotation,
                value=ROTATION_VALUES[2],
                renewal=case.renewal,
            )
            register_scripted_eligibility(oracle, portal)
            setup_task = asyncio.ensure_future(current.setup())
            try:
                try:
                    await hass.async_add_executor_job(probe.gate.wait_arrived, 5.0)
                except TimeoutError:
                    setup_task.cancel()
                    raise AssertionError(
                        f"{case.case_id}: exit boundary '{case.boundary.boundary_id}' was "
                        f"never reached during setup"
                    ) from None
                gate_expected = _expectation_at_boundary(
                    current, case, checkpoint_b, exit_jar, sequence=3
                )
            finally:
                probe.gate.proceed()
                result = await asyncio.wait_for(
                    asyncio.gather(setup_task, return_exceptions=True), timeout=20
                )
            await hass.async_block_till_done()
            assert result[0] is False, (
                f"{case.case_id}: the scripted setup failure unexpectedly succeeded"
            )
            assert current.entry.state is ConfigEntryState.SETUP_RETRY
            if case.renewal:
                # The failed attempt completed a real renewal before its chart leg
                # failed, so the failed-setup exit must persist that newest pair.
                expected = ExpectedCheckpoint(
                    label=case.boundary.boundary_id,
                    jar=exit_jar,
                    admission=_runtime_admission(current.client),
                    sequence=3,
                )
                assert dict(expected.admission) != dict(checkpoint_b.admission), (
                    f"{case.case_id}: the failed-setup checkpoint's settled admission "
                    "does not differ from the penultimate one"
                )
                if case.boundary.phase == "after":
                    assert dict(expected.jar) == dict(gate_expected.jar), (
                        f"{case.case_id}: the checkpoint published at the boundary is "
                        "not the one the failed setup must persist"
                    )
            else:
                expected = checkpoint_b
            await _assert_persisted_pair(current, oracle, case, expected)
            facts["setup_failure_state"] = current.entry.state.value
        else:
            if case.renewal:
                _script_healthy_operation(
                    portal,
                    cookie=case.rotation,
                    value=ROTATION_VALUES[2],
                    renewal=True,
                )
                register_scripted_eligibility(oracle, portal)
            else:
                _script_healthy_operation(
                    portal,
                    cookie=case.rotation,
                    value=ROTATION_VALUES[2],
                    renewal=False,
                )
                register_scripted_eligibility(oracle, portal)

            if probe.blocking:
                probe.install(current.client)
                task = asyncio.ensure_future(_start_operation(current, operation))
                try:
                    try:
                        await hass.async_add_executor_job(probe.gate.wait_arrived, 5.0)
                    except TimeoutError:
                        task.cancel()
                        raise AssertionError(
                            f"{case.case_id}: exit boundary '{case.boundary.boundary_id}' was "
                            f"never reached during {operation}"
                        ) from None
                    expected = _expectation_at_boundary(
                        current, case, checkpoint_b, exit_jar, sequence=3
                    )
                    if transition == "cancel":
                        task.cancel()
                        await asyncio.wait_for(
                            asyncio.gather(task, return_exceptions=True), timeout=20
                        )
                    elif transition == "unload":
                        assert await current.unload() is True
                    elif transition == "stop":
                        await current.stop()
                    await hass.async_block_till_done()
                    await _assert_persisted_pair(current, oracle, case, expected)
                    if transition == "stop":
                        assert await current.unload() is True
                finally:
                    probe.gate.proceed()
                    await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=20)
                await hass.async_add_executor_job(probe.finished.wait, 10.0)
                assert probe.finished.is_set(), (
                    f"{case.case_id}: the released exit operation did not finish at "
                    f"'{case.boundary.boundary_id}'"
                )
                await hass.async_block_till_done()
            else:
                probe.install(current.client)
                await _start_operation(current, operation)
                assert loop_hits, (
                    f"{case.case_id}: exit boundary '{case.boundary.boundary_id}' was "
                    f"never reached during {operation}"
                )
                expected = loop_hits[0]
                await _assert_persisted_pair(current, oracle, case, expected)
                assert await current.unload() is True

        assert probe.hits == 1, (
            f"{case.case_id}: exit boundary '{case.boundary.boundary_id}' gate fired "
            f"{probe.hits} times"
        )

        # I9 at the exit: no loaded coordinator may have lost its keepalive schedule.
        i9 = oracle.evaluate_i9(_live_i9_facts(current))
        assert not i9, f"{case.case_id}: I9 at exit: {[v.message for v in i9]}"

        # Authorized successor, then warm versus genuinely cold decision equivalence.
        _script_plain_operation(portal)
        if current.entry.state is ConfigEntryState.SETUP_RETRY:
            assert await current.reload() is True, (
                f"{case.case_id}: the authorized successor after a failed setup did not load"
            )
        elif current.entry.state is not ConfigEntryState.LOADED:
            assert await current.setup() is True
        warm_coordinator = current.coordinator
        warm_client = current.client
        assert warm_coordinator is not None and warm_client is not None
        start = len(portal.dispatches)
        await current.poll()
        warm_dispatches = tuple(portal.dispatches[start:])

        await current.cold_restart()
        cold_coordinator = current.coordinator
        cold_client = current.client
        assert cold_coordinator is not None and cold_client is not None
        start = len(portal.dispatches)
        await current.poll()
        cold_dispatches = tuple(portal.dispatches[start:])

        i6 = oracle.evaluate_i6(
            _RuntimeView(warm_coordinator, warm_client, _normalized(warm_dispatches)),
            _RuntimeView(cold_coordinator, cold_client, _normalized(cold_dispatches)),
        )
        assert not i6, (
            f"{case.case_id}: I6 cold decision differs: {[v.message for v in i6]}; "
            f"warm={[(d.method, d.url) for d in warm_dispatches]} "
            f"cold={[(d.method, d.url) for d in cold_dispatches]}"
        )
        assert [
            (dispatch.method, _VOLATILE_QUERY.sub("", dispatch.url)) for dispatch in warm_dispatches
        ] == [
            (dispatch.method, _VOLATILE_QUERY.sub("", dispatch.url)) for dispatch in cold_dispatches
        ], f"{case.case_id}: the warm and cold next-poll dispatches differ"
        assert cold_coordinator is not warm_coordinator
        assert cold_client is not warm_client

        i9_cold = oracle.evaluate_i9(_live_i9_facts(current))
        assert not i9_cold, f"{case.case_id}: I9 after cold restart: {[v.message for v in i9_cold]}"

        follow_on_snapshot = await current.snapshot()
        # The exit pair was asserted independently above; the follow-on baselines
        # I5 on the cold physical state so later healthy polls cannot look like a
        # regression to the oracle.
        follow_on_state = ExpectationState(
            generation_id=f"{case.case_id}:follow-on",
            sequence=4,
            latest_checkpoint=Checkpoint(
                generation_id=f"{case.case_id}:follow-on",
                sequence=4,
                jar=MappingProxyType(_snapshot_jar(follow_on_snapshot)),
                admission=MappingProxyType(dict(follow_on_snapshot.renewal_admission)),
                timestamp=0.0,
            ),
        )
        oracle.expectation_state = follow_on_state
        facts.update(
            {
                "checkpoint_a": checkpoint_a.to_dict(),
                "checkpoint_b": checkpoint_b.to_dict(),
                "expected": expected.to_dict(),
                "persisted": {
                    "jar": _snapshot_jar(follow_on_snapshot),
                    "admission": dict(follow_on_snapshot.renewal_admission),
                },
                "boundary_reached": probe.hits == 1,
                "cold_matches_warm": True,
            }
        )

    # The case body creates the authorized successor itself (and proves the warm/cold
    # decision equivalence), so the entry is always LOADED before the follow-on.
    with factory:
        result = await run_case(
            driver,
            body,
            case_name=case.case_id,
            oracle=oracle,
        )
    result.assert_complete()
    assert result.success
    assert not oracle.violations, (
        f"{case.case_id}: oracle violations "
        f"{[str(v.code) + ': ' + v.message for v in oracle.violations]}"
    )
    assert len(result.ending_steps) == 4

    return ExitEvidence(
        case_id=case.case_id,
        boundary_id=case.boundary.boundary_id,
        transition=transition,
        renewal=case.renewal,
        rotation=case.rotation,
        flow=case.flow,
        boundary_reached=bool(facts["boundary_reached"]),
        checkpoint_a=MappingProxyType(dict(facts["checkpoint_a"])),
        checkpoint_b=MappingProxyType(dict(facts["checkpoint_b"])),
        expected=MappingProxyType(dict(facts["expected"])),
        persisted=MappingProxyType(dict(facts["persisted"])),
        cold_matches_warm=bool(facts["cold_matches_warm"]),
        oracle_codes=tuple(str(v.code) for v in oracle.violations),
        ending_steps=tuple(result.ending_steps),
        elapsed_seconds=result.elapsed_time,
    )


def _expectation_at_boundary(
    driver: LifecycleDriver,
    case: ExitCase,
    checkpoint_b: ExpectedCheckpoint,
    exit_jar: Mapping[str, str],
    *,
    sequence: int,
) -> ExpectedCheckpoint:
    """Return the checkpoint the exit must persist for this boundary/phase."""
    client = driver.client
    assert client is not None
    snapshot = client.pending_confirmed_snapshot()
    if snapshot is not None:
        published = _jar_of(snapshot["cookies"])
        published_admission = _runtime_admission(client)
        if published == dict(checkpoint_b.jar) and published_admission == dict(
            checkpoint_b.admission
        ):
            # No newer eligible read was validated on this attempt: the checkpoint
            # published at the boundary is still the penultimate one.
            return checkpoint_b
        expected = _capture_pending(
            client,
            label=case.boundary.boundary_id,
            sequence=sequence,
            declared_jar=exit_jar,
        )
        if case.renewal:
            assert dict(expected.admission) != dict(checkpoint_b.admission), (
                f"{case.case_id}: the exit checkpoint's settled admission does not "
                "differ from the penultimate one; an old-admission exit would be invisible"
            )
        return expected
    return checkpoint_b


__all__ = [
    "ALL_CASES",
    "APPLICABLE_TRANSITIONS",
    "EXCLUSIONS",
    "FAST_CASES",
    "INITIAL_JARS",
    "ROTATION_COOKIES",
    "ROTATION_VALUES",
    "SLOW_CASES",
    "TRANSITIONS",
    "ExitCase",
    "ExitEvidence",
    "ExitProbe",
    "ProbeFactory",
    "boundary_coverage",
    "build_cases",
    "case_tiers",
    "coverage_problems",
    "excluded_combinations",
    "flow_for",
    "initial_jar",
    "rotated_jar",
    "run_exit_case",
]

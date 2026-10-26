"""Single invariant evaluator and observer for systemic testing (I1-I12).

Observes every attempted send at send-time (before response) and every declared
lifecycle checkpoint at step-time. Evaluates systemic invariants I1-I12 using
real surface evidence (raw Cookie headers, physical disk Store data, HA issues/flows,
recorder/journal snapshots, privacy surfaces) without repairing state or inferring
eligibility from production confirmation flags.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
import re
import threading
from types import MappingProxyType
from typing import Any

from homeassistant.config_entries import ConfigEntryState

from custom_components.pseg.pseg_client import PsegError

from .expectation import Checkpoint, ExpectationState
from .portal import Dispatch, ScriptedPortal, _freeze_value


class ViolationCode(StrEnum):
    """Stable invariant violation codes I1 through I12."""

    I1 = "I1"  # Dispatch fence: zero sends by retired generation
    I2 = "I2"  # Credential policy: no credential POST from keepalive/retired/latched/terminal
    I3 = "I3"  # Live quarantine: next request never carries cookie from failed response
    I4 = "I4"  # Persisted provenance: values came from eligible validated replies or initial jar
    I5 = "I5"  # Latest checkpoint: every exit persists latest eligible immutable jar and admission
    I6 = "I6"  # Warm/cold equivalence: same persisted inputs yield same policy decisions/dispatches
    I7 = "I7"  # Budget: <=2 sequences per RM generation, >=15m spacing, retry only on transient
    I8 = "I8"  # Terminal durability: CAPTCHA/security refusal blocks automatic auth across reload/restart
    I9 = "I9"  # HA liveness: transient gives scheduled timer retry; auth loss gives flow/issue
    I10 = "I10"  # Typed validation: no untyped entrypoint errors; malformed 200 never confirms
    I11 = "I11"  # Privacy: sentinels absent from logs/diagnostics/issues/states; POST body digest only
    I12 = (
        "I12"  # Statistics isolation: auth failure adds no rows to either series; journal preserved
    )


@dataclass(frozen=True, slots=True)
class Violation:
    """Immutable record of an invariant violation."""

    code: str
    message: str
    facts: MappingProxyType[str, Any]
    observation_type: str = "send"
    sequence: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "facts", _freeze_value(self.facts))


@dataclass(frozen=True, slots=True)
class Observation:
    """Immutable record of an observer invocation at send time or step time."""

    observation_type: str  # "send" | "step"
    sequence: int
    tag: str
    facts: MappingProxyType[str, Any]
    violations: tuple[Violation, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "facts", _freeze_value(self.facts))
        object.__setattr__(self, "violations", tuple(self.violations))


@dataclass(frozen=True, slots=True)
class PermittedRedirectPolicy:
    """Declared data encoding permitted current-owner redirect behaviour.

    Preserves the October 23 current-owner 307/308 redirect re-POST control:
    An active, non-retired, non-latched, non-terminal current-owner client
    handling a 307/308 redirect hop during SAML ACS authentication is permitted
    to re-POST credentials/assertions to the target host.
    """

    allowed_statuses: tuple[int, ...] = (307, 308)
    forbid_keepalive: bool = True
    # Okta (non-local) mode keepalive is a documented full SSO round trip every
    # 10 minutes (PsegClient.keepalive -> renew_sso): it relays Okta's SAML
    # assertion to the portal ACS endpoint but never posts the saved password.
    # Only that ACS POST, by an Okta-mode owner, is exempt from forbid_keepalive.
    permit_okta_keepalive_saml_acs: bool = True
    forbid_retired: bool = True
    forbid_terminal: bool = True
    forbid_latched: bool = True


PERMITTED_CURRENT_OWNER_REDIRECT_POLICY = PermittedRedirectPolicy()


def _cookie_name_val(c: Any) -> tuple[str, str]:
    """Extract name and value from either FrozenCookie or frozen mapping."""
    if isinstance(c, Mapping):
        return (str(c.get("name", "")), str(c.get("value", "")))
    return (str(getattr(c, "name", "")), str(getattr(c, "value", "")))


class Oracle:
    """Single invariant evaluator and observer for systemic testing (I1-I12)."""

    def __init__(
        self,
        expectation_state: ExpectationState | None = None,
        permitted_redirect_policy: PermittedRedirectPolicy = PERMITTED_CURRENT_OWNER_REDIRECT_POLICY,
    ) -> None:
        self._lock = threading.Lock()
        self._retired_generations: set[str] = set()
        self._quarantined_cookies: set[tuple[str, str]] = set()
        self._eligible_cookie_history: set[tuple[str, str]] = set()
        self._sentinels: set[str] = {"SYNTH_PRIVACY_SENTINEL"}
        self._caplog: Any | None = None
        self._registry: Any | None = None
        self._last_snapshot: Any | None = None
        self._sequence_counter = 0
        self.violations: list[Violation] = []
        self.send_observations: list[Observation] = []
        self.step_observations: list[Observation] = []
        self._expectation_state = None
        self.expectation_state = expectation_state
        self.permitted_redirect_policy = permitted_redirect_policy

    @property
    def expectation_state(self) -> ExpectationState | None:
        return self._expectation_state

    @expectation_state.setter
    def expectation_state(self, state: ExpectationState | None) -> None:
        self._expectation_state = state
        if state is not None and state.latest_checkpoint is not None:
            with self._lock:
                for k, v in state.latest_checkpoint.jar.items():
                    self._eligible_cookie_history.add((k, str(v)))

    @property
    def send_invocation_count(self) -> int:
        """Count of observer invocations at send time."""
        with self._lock:
            return len(self.send_observations)

    @property
    def step_invocation_count(self) -> int:
        """Count of observer invocations at declared lifecycle checkpoints."""
        with self._lock:
            return len(self.step_observations)

    @property
    def invocation_count(self) -> int:
        """Total observer invocation count: attempted sends + declared checkpoints."""
        with self._lock:
            return len(self.send_observations) + len(self.step_observations)

    def register_quarantined_cookie(self, name: str, value: str) -> None:
        """Register a quarantined cookie from a failed/invalid response."""
        with self._lock:
            self._quarantined_cookies.add((name, value))

    def register_eligible_cookie(self, name: str, value: str) -> None:
        """Register an eligible validated cookie into provenance history."""
        with self._lock:
            self._eligible_cookie_history.add((name, value))

    def register_sentinel(self, sentinel: str) -> None:
        """Register a privacy sentinel string that must not appear on any surface."""
        with self._lock:
            self._sentinels.add(sentinel)

    def retire_generation(self, generation_id: str) -> None:
        """Record retirement of a client generation."""
        with self._lock:
            self._retired_generations.add(generation_id)

    def attach_portal(self, portal: ScriptedPortal) -> None:
        """Attach send-time observer hook to ScriptedPortal and synchronize state."""
        portal.add_observer(self.observe_send)
        with self._lock:
            for k, v in getattr(portal, "_quarantined_cookies", set()):
                self._quarantined_cookies.add((k, v))
            for k, v in getattr(portal, "_eligible_cookies", set()):
                self._eligible_cookie_history.add((k, v))
            for target in getattr(portal, "_retired", {}):
                if target != "*":
                    self._retired_generations.add(target)

    def attach_registry(self, registry: Any) -> None:
        """Attach ClientRegistry for live client inspection."""
        with self._lock:
            self._registry = registry

    def attach_caplog(self, caplog: Any) -> None:
        """Attach pytest caplog fixture for I11 privacy scanning."""
        with self._lock:
            self._caplog = caplog

    def observe_send(self, dispatch: Dispatch) -> tuple[Violation, ...]:
        """Observe attempted send at send-time before scripted response."""
        with self._lock:
            self._sequence_counter += 1
            seq = self._sequence_counter

            # Evaluate send-time invariants
            violations_found: list[Violation] = []
            violations_found.extend(self.evaluate_i1(dispatch, self.expectation_state))
            violations_found.extend(
                self.evaluate_i2(
                    dispatch,
                    self.expectation_state,
                    self.permitted_redirect_policy,
                )
            )
            violations_found.extend(self.evaluate_i3(dispatch, self._quarantined_cookies))
            violations_found.extend(self.evaluate_i11_dispatch(dispatch))

            facts = {
                "sequence": dispatch.sequence,
                "generation_id": dispatch.generation_id,
                "method": dispatch.method,
                "url": dispatch.url,
                "is_redirect_hop": dispatch.is_redirect_hop,
                "is_after_retire": dispatch.is_after_retire,
                "cookies_count": len(dispatch.cookies),
                "has_body_digest": dispatch.body_digest is not None,
            }

            obs = Observation(
                observation_type="send",
                sequence=seq,
                tag=f"send:{dispatch.method}:{dispatch.url}",
                facts=MappingProxyType(facts),
                violations=tuple(violations_found),
            )
            self.send_observations.append(obs)
            self.violations.extend(violations_found)
            return tuple(violations_found)

    def observe_step(
        self,
        driver_or_state: Any,
        step_tag: str,
        snapshot: Any = None,
    ) -> tuple[Violation, ...]:
        """Observe declared lifecycle checkpoint at step-time, evaluating all applicable invariants."""
        with self._lock:
            self._sequence_counter += 1
            seq = self._sequence_counter

            violations_found: list[Violation] = []
            snap = snapshot
            driver = driver_or_state if hasattr(driver_or_state, "hass") else None
            state = (
                driver_or_state
                if isinstance(driver_or_state, ExpectationState)
                else self.expectation_state
            )

            if snap is not None:
                # I4: Persisted provenance
                violations_found.extend(self.evaluate_i4(snap, self._eligible_cookie_history))

                # I5: Latest checkpoint
                violations_found.extend(self.evaluate_i5(snap, state))

                # I8: Terminal durability
                terminal_reason = dict(getattr(snap, "renewal_admission", {})).get(
                    "terminal_reason"
                )
                if terminal_reason:
                    if getattr(driver, "last_automatic_auth_attempted", False):
                        violations_found.extend(
                            self.evaluate_i8(
                                snap, automatic_auth_attempted=True, human_rearmed=False
                            )
                        )

            # I9: HA liveness / ownership
            if driver is not None:
                coord = getattr(driver, "coordinator", None)
                # Check dead keepalive schedule
                if (
                    coord is not None
                    and getattr(driver.entry, "state", None) is ConfigEntryState.LOADED
                    and getattr(coord, "_unsub_keepalive", None) is None
                ):
                    violations_found.extend(self.evaluate_i9({"dead_schedule": True}))

                # Check timer advance dispatches
                if (
                    getattr(driver, "last_advance_timer_dispatches", None) == 0
                    and step_tag == "dead_schedule"
                ):
                    violations_found.extend(
                        self.evaluate_i9({"transient_retry": True, "dispatched_via_timer": False})
                    )

                # Check missing reauth flows/issues on auth failure
                is_auth_failure = (
                    step_tag == "failure"
                    or (coord is not None and getattr(coord, "auth_required", False))
                    or (
                        coord is not None
                        and getattr(coord, "last_update_success", True) is False
                        and "auth" in str(getattr(coord, "last_exception", "")).lower()
                    )
                )
                if is_auth_failure and snap is not None:
                    has_flow = bool(snap.flows)
                    has_issue = bool(snap.issues)
                    if not has_flow and not has_issue:
                        violations_found.extend(
                            self.evaluate_i9(
                                {
                                    "auth_loss": True,
                                    "has_reauth_flow": False,
                                    "has_repair_issue": False,
                                }
                            )
                        )

                # I10: Typed validation
                if coord is not None and getattr(coord, "last_exception", None) is not None:
                    violations_found.extend(self.evaluate_i10(coord.last_exception))

            # I11: Privacy scanning across real surfaces
            surfaces_to_scan: dict[str, Any] = {}
            if self._caplog is not None:
                surfaces_to_scan["caplog"] = getattr(self._caplog, "text", "")
            if snap is not None:
                surfaces_to_scan["issues"] = snap.issues
                surfaces_to_scan["sensors"] = snap.sensors
                surfaces_to_scan["entry_data"] = snap.entry_data
            if surfaces_to_scan:
                violations_found.extend(self.evaluate_i11(surfaces_to_scan))

            # I12: Statistics isolation
            if self._last_snapshot is not None and snap is not None:
                if step_tag == "failure" or (
                    driver is not None
                    and getattr(getattr(driver, "coordinator", None), "last_update_success", True)
                    is False
                ):
                    violations_found.extend(self.evaluate_i12(self._last_snapshot, snap))

            if snap is not None:
                self._last_snapshot = snap

            facts = {
                "step_tag": step_tag,
                "has_snapshot": snap is not None,
                "violations_count": len(violations_found),
            }

            obs = Observation(
                observation_type="step",
                sequence=seq,
                tag=f"step:{step_tag}",
                facts=MappingProxyType(facts),
                violations=tuple(violations_found),
            )
            self.step_observations.append(obs)
            self.violations.extend(violations_found)
            return tuple(violations_found)

    def __call__(
        self,
        driver_or_dispatch: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Unified invocation interface for portal hook or lifecycle runner."""
        if isinstance(driver_or_dispatch, Dispatch):
            return self.observe_send(driver_or_dispatch)
        step_tag = args[0] if args else kwargs.get("step_tag", "step")
        snapshot = args[1] if len(args) > 1 else kwargs.get("snapshot")
        return self.observe_step(driver_or_dispatch, step_tag, snapshot)

    # -------------------------------------------------------------------------
    # Invariant I1: Dispatch fence
    # -------------------------------------------------------------------------
    def evaluate_i1(
        self,
        dispatch: Dispatch,
        state: ExpectationState | None = None,
    ) -> list[Violation]:
        """I1: Zero new sends by retired generation, including 30x hops.

        Explicit exemption: unattached signup/CAPTCHA human flows.
        """
        is_retired = (
            dispatch.is_after_retire
            or dispatch.generation_id in self._retired_generations
            or (state is not None and state.is_retired)
        )
        if not is_retired:
            return []

        # Explicit exemption: unattached signup/CAPTCHA human flows
        is_exempt = (
            dispatch.generation_id.startswith("human_unattached")
            or dispatch.headers.get("X-Unattached-Flow") == "true"
            or dispatch.headers.get("X-Human-Exemption") == "true"
        )
        if is_exempt:
            return []

        return [
            Violation(
                code=ViolationCode.I1,
                message=(
                    f"I1 dispatch fence violation: send attempted by retired generation "
                    f"'{dispatch.generation_id}' on url '{dispatch.url}'"
                ),
                facts=MappingProxyType(
                    {
                        "generation_id": dispatch.generation_id,
                        "url": dispatch.url,
                        "sequence": dispatch.sequence,
                        "is_redirect_hop": dispatch.is_redirect_hop,
                    }
                ),
                observation_type="send",
                sequence=dispatch.sequence,
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I2: Credential policy
    # -------------------------------------------------------------------------
    def evaluate_i2(
        self,
        dispatch: Dispatch,
        state: ExpectationState | None = None,
        policy: PermittedRedirectPolicy | None = None,
    ) -> list[Violation]:
        """I2: No Login/ACS credential POST from keepalive/retired/latched/terminal.

        Encodes existing permitted October 23 current-owner 307/308 redirect re-POST.
        """
        p = policy or self.permitted_redirect_policy

        # Identify credential POST: POST to Login or SAML ACS
        is_cred_post = dispatch.method == "POST" and (
            "/Login" in dispatch.url
            or "/Acs" in dispatch.url
            or "/SignIn" in dispatch.url
            or dispatch.headers.get("X-Credential-Post") == "true"
        )
        if not is_cred_post:
            return []

        client = None
        if self._registry is not None:
            client = self._registry.get(dispatch.generation_id)

        # Check conditions against real client state and dispatch/state facts
        is_keepalive = (
            (client is not None and getattr(client, "_in_keepalive", False))
            or dispatch.headers.get("X-Pseg-Keepalive") == "true"
            or "/keepalive" in dispatch.url.lower()
        )
        is_retired = (
            dispatch.is_after_retire
            or dispatch.generation_id in self._retired_generations
            or (state is not None and state.is_retired)
        )
        is_terminal = (
            (
                client is not None
                and bool(
                    getattr(getattr(client, "_renewal_admission", None), "terminal_reason", None)
                )
            )
            or (
                state is not None
                and (
                    state.is_terminal
                    or state.pending_renewal_expectation == "blocked_terminal_human_rearm_required"
                )
            )
            or dispatch.headers.get("X-Terminal-Latched") == "true"
        )
        is_latched = (
            client is not None
            and (
                getattr(client, "_security_step_latched", False)
                or getattr(client, "_captcha_latched", False)
            )
        ) or dispatch.headers.get("X-Latched") == "true"

        is_okta_keepalive_saml = (
            p.permit_okta_keepalive_saml_acs
            and "/Acs" in dispatch.url
            and client is not None
            and getattr(client, "is_local_mode", True) is False
        )
        reasons: list[str] = []
        if is_keepalive and p.forbid_keepalive and not is_okta_keepalive_saml:
            reasons.append("from_keepalive")
        if is_retired and p.forbid_retired:
            reasons.append("generation_retired")
        if is_terminal and p.forbid_terminal:
            reasons.append("terminal_state")
        if is_latched and p.forbid_latched:
            reasons.append("latched_state")

        # Check October 23 current-owner redirect control
        if dispatch.is_redirect_hop:
            status_allowed = (
                dispatch.status_code is None or dispatch.status_code in p.allowed_statuses
            )
            if not status_allowed:
                reasons.append(f"disallowed_redirect_status_{dispatch.status_code}")

            if not reasons:
                # Permitted current-owner redirect re-POST
                return []
        else:
            # Regular credential POST (initial login or SSO renewal)
            if not reasons:
                # Permitted credential POST
                return []

        return [
            Violation(
                code=ViolationCode.I2,
                message=(
                    f"I2 credential policy violation: credential POST forbidden "
                    f"({', '.join(reasons)}) on url '{dispatch.url}'"
                ),
                facts=MappingProxyType(
                    {
                        "generation_id": dispatch.generation_id,
                        "url": dispatch.url,
                        "reasons": tuple(reasons),
                        "is_redirect_hop": dispatch.is_redirect_hop,
                    }
                ),
                observation_type="send",
                sequence=dispatch.sequence,
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I3: Live quarantine
    # -------------------------------------------------------------------------
    def evaluate_i3(
        self,
        dispatch: Dispatch,
        quarantined_cookies: set[tuple[str, str]] | None = None,
    ) -> list[Violation]:
        """I3: Next request never carries a unique value set by a failed/invalid reply."""
        q_cookies = (
            quarantined_cookies if quarantined_cookies is not None else self._quarantined_cookies
        )
        if not q_cookies:
            return []

        sent_items = set(dispatch.cookies.items())
        leaked = sent_items & q_cookies
        if not leaked:
            return []

        return [
            Violation(
                code=ViolationCode.I3,
                message=(
                    f"I3 live quarantine violation: request carries quarantined cookie(s) "
                    f"{sorted(leaked)} set by failed/invalid response"
                ),
                facts=MappingProxyType(
                    {
                        "generation_id": dispatch.generation_id,
                        "url": dispatch.url,
                        "leaked_cookies": tuple(sorted(leaked)),
                    }
                ),
                observation_type="send",
                sequence=dispatch.sequence,
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I4: Persisted provenance
    # -------------------------------------------------------------------------
    def evaluate_i4(
        self,
        snapshot: Any,
        eligible_history: set[tuple[str, str]] | None = None,
    ) -> list[Violation]:
        """I4: Persisted values came from declared eligible validated responses or initial jar.

        An empty eligible history must not accept everything.
        """
        history = (
            eligible_history if eligible_history is not None else self._eligible_cookie_history
        )
        persisted = getattr(snapshot, "persisted_jar", ())

        if not history:
            if persisted:
                unproven = [_cookie_name_val(c) for c in persisted]
                return [
                    Violation(
                        code=ViolationCode.I4,
                        message="I4 persisted provenance violation: empty eligible history rejected all persisted cookies",
                        facts=MappingProxyType({"unproven_cookies": tuple(unproven)}),
                        observation_type="step",
                    )
                ]
            return []

        unproven = []
        for c in persisted:
            c_tuple = _cookie_name_val(c)
            if c_tuple not in history:
                unproven.append(c_tuple)

        if not unproven:
            return []

        return [
            Violation(
                code=ViolationCode.I4,
                message=(
                    f"I4 persisted provenance violation: unproven cookie(s) {unproven} "
                    f"persisted in storage"
                ),
                facts=MappingProxyType({"unproven_cookies": tuple(unproven)}),
                observation_type="step",
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I5: Latest checkpoint
    # -------------------------------------------------------------------------
    def evaluate_i5(
        self,
        snapshot: Any,
        state: ExpectationState | None = None,
    ) -> list[Violation]:
        """I5: Every exit persists latest eligible immutable jar and admission.

        Must compare against LATEST checkpoint, not first.
        """
        st = state or self.expectation_state
        if st is None or st.latest_checkpoint is None:
            return []

        latest: Checkpoint = st.latest_checkpoint
        persisted_jar = dict(_cookie_name_val(c) for c in getattr(snapshot, "persisted_jar", ()))
        expected_jar = dict(latest.jar)

        # Check jar equivalence
        jar_matches = persisted_jar == expected_jar

        # Check settled admission
        persisted_admission = dict(getattr(snapshot, "renewal_admission", {}))
        expected_admission = dict(latest.admission)
        admission_matches = True
        for k, v in expected_admission.items():
            if persisted_admission.get(k) != v:
                admission_matches = False
                break

        if jar_matches and admission_matches:
            return []

        return [
            Violation(
                code=ViolationCode.I5,
                message=(
                    f"I5 latest checkpoint violation: physical storage does not match latest checkpoint "
                    f"(seq {latest.sequence})"
                ),
                facts=MappingProxyType(
                    {
                        "expected_seq": latest.sequence,
                        "jar_matches": jar_matches,
                        "admission_matches": admission_matches,
                        "persisted_jar": persisted_jar,
                        "expected_jar": expected_jar,
                    }
                ),
                observation_type="step",
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I6: Warm/cold equivalence
    # -------------------------------------------------------------------------
    def evaluate_i6(
        self,
        warm_runtime: Any,
        cold_runtime: Any,
        warm_dispatches: Sequence[Dispatch] | None = None,
        cold_dispatches: Sequence[Dispatch] | None = None,
    ) -> list[Violation]:
        """I6: Same persisted inputs yield same policy decisions/dispatches.

        Compares genuinely separate warm and cold control branches (two runtimes).
        """
        if warm_runtime is cold_runtime:
            return [
                Violation(
                    code=ViolationCode.I6,
                    message="I6 warm/cold equivalence requires genuinely separate runtimes, not two references to one runtime",
                    facts=MappingProxyType({"identical_instance": True}),
                    observation_type="step",
                )
            ]

        # Prove independent coordinator, client, session
        w_coord = getattr(warm_runtime, "coordinator", None)
        c_coord = getattr(cold_runtime, "coordinator", None)
        if w_coord is not None and c_coord is not None and w_coord is c_coord:
            return [
                Violation(
                    code=ViolationCode.I6,
                    message="I6 warm/cold equivalence requires distinct coordinators, but shared coordinator found",
                    facts=MappingProxyType({"shared_coordinator": True}),
                    observation_type="step",
                )
            ]

        w_client = getattr(warm_runtime, "client", None)
        c_client = getattr(cold_runtime, "client", None)
        if w_client is not None and c_client is not None and w_client is c_client:
            return [
                Violation(
                    code=ViolationCode.I6,
                    message="I6 warm/cold equivalence requires distinct clients, but shared client found",
                    facts=MappingProxyType({"shared_client": True}),
                    observation_type="step",
                )
            ]

        w_session = getattr(w_client, "session", None) or getattr(warm_runtime, "session", None)
        c_session = getattr(c_client, "session", None) or getattr(cold_runtime, "session", None)
        if w_session is not None and c_session is not None and w_session is c_session:
            return [
                Violation(
                    code=ViolationCode.I6,
                    message="I6 warm/cold equivalence requires distinct sessions, but shared session found",
                    facts=MappingProxyType({"shared_session": True}),
                    observation_type="step",
                )
            ]

        # Missing .dispatches is an error, not an empty list
        if warm_dispatches is None and not hasattr(warm_runtime, "dispatches"):
            return [
                Violation(
                    code=ViolationCode.I6,
                    message="I6 warm/cold equivalence requires .dispatches on warm runtime",
                    facts=MappingProxyType({"missing_warm_dispatches": True}),
                    observation_type="step",
                )
            ]
        if cold_dispatches is None and not hasattr(cold_runtime, "dispatches"):
            return [
                Violation(
                    code=ViolationCode.I6,
                    message="I6 warm/cold equivalence requires .dispatches on cold runtime",
                    facts=MappingProxyType({"missing_cold_dispatches": True}),
                    observation_type="step",
                )
            ]

        w_ds = (
            warm_dispatches if warm_dispatches is not None else getattr(warm_runtime, "dispatches")
        )
        c_ds = (
            cold_dispatches if cold_dispatches is not None else getattr(cold_runtime, "dispatches")
        )

        def _normalize(d: Dispatch) -> tuple[str, str, str | None]:
            clean_url = re.sub(r"/gen_[^/]+", "/gen_NORM", d.url)
            return (d.method, clean_url, d.body_digest)

        w_norm = [_normalize(d) for d in w_ds]
        c_norm = [_normalize(d) for d in c_ds]

        if w_norm == c_norm:
            return []

        return [
            Violation(
                code=ViolationCode.I6,
                message="I6 warm/cold equivalence violation: dispatches diverge between warm and cold runtimes",
                facts=MappingProxyType(
                    {
                        "warm_count": len(w_norm),
                        "cold_count": len(c_norm),
                        "warm_dispatches": tuple(w_norm),
                        "cold_dispatches": tuple(c_norm),
                    }
                ),
                observation_type="step",
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I7: Budget
    # -------------------------------------------------------------------------
    def evaluate_i7(
        self,
        facts: Mapping[str, Any],
    ) -> list[Violation]:
        """I7: <=2 sequences per RM generation, >=15m spacing, retry only on transient."""
        sequences_count = facts.get("sequences_count", facts.get("sequence", 0))
        spacing_seconds = facts.get("spacing_seconds", 900.0)
        is_retry = facts.get("is_retry", False)
        prior_error_transient = facts.get("prior_error_transient", True)
        rotated_after_success = facts.get("rotated_after_success", True)
        corrupt_metadata = facts.get("corrupt_metadata", False)
        failed_closed = facts.get("failed_closed", True)

        reasons = []
        if sequences_count > 2:
            reasons.append("exceeded_2_sequences")
        if spacing_seconds < 900.0:
            reasons.append("spacing_under_15_minutes")
        if is_retry and not prior_error_transient:
            reasons.append("retry_without_transient_error")
        if is_retry and not rotated_after_success:
            reasons.append("retry_after_success_without_rotation")
        if corrupt_metadata and not failed_closed:
            reasons.append("corrupt_metadata_did_not_fail_closed")

        if not reasons:
            return []

        return [
            Violation(
                code=ViolationCode.I7,
                message=f"I7 budget violation: {', '.join(reasons)}",
                facts=MappingProxyType(dict(facts)),
                observation_type="step",
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I8: Terminal durability
    # -------------------------------------------------------------------------
    def evaluate_i8(
        self,
        snapshot: Any,
        automatic_auth_attempted: bool = False,
        human_rearmed: bool = False,
    ) -> list[Violation]:
        """I8: CAPTCHA/security refusal blocks automatic auth across reload/restart."""
        admission = dict(getattr(snapshot, "renewal_admission", {}))
        terminal_reason = admission.get("terminal_reason")

        if terminal_reason and automatic_auth_attempted and not human_rearmed:
            return [
                Violation(
                    code=ViolationCode.I8,
                    message=(
                        f"I8 terminal durability violation: automatic auth attempted while terminal "
                        f"reason '{terminal_reason}' active without human rearm"
                    ),
                    facts=MappingProxyType(
                        {
                            "terminal_reason": terminal_reason,
                            "automatic_auth_attempted": automatic_auth_attempted,
                        }
                    ),
                    observation_type="step",
                )
            ]
        return []

    # -------------------------------------------------------------------------
    # Invariant I9: HA liveness / ownership
    # -------------------------------------------------------------------------
    def evaluate_i9(
        self,
        facts: Mapping[str, Any],
    ) -> list[Violation]:
        """I9: Transient gives scheduled timer retry; auth loss yields reauth flow/issue.

        Must prove timer callback actually dispatched through real scheduler.
        """
        is_transient = facts.get("transient_retry", False)
        is_auth_loss = facts.get("auth_loss", False)
        is_dead_schedule = facts.get("dead_schedule", False)

        reasons = []
        if is_dead_schedule:
            reasons.append("keepalive_schedule_dead_or_not_started")

        if is_transient:
            dispatched_via_timer = facts.get("dispatched_via_timer", False)
            direct_call = facts.get("direct_call", False)
            if direct_call and not dispatched_via_timer:
                reasons.append("direct_coordinator_call_instead_of_timer")
            elif not dispatched_via_timer:
                reasons.append("timer_callback_not_dispatched")

        if is_auth_loss:
            has_flow = facts.get("has_reauth_flow", False)
            has_issue = facts.get("has_repair_issue", False)
            if not has_flow and not has_issue:
                reasons.append("missing_reauth_flow_or_issue")

        if not reasons:
            return []

        return [
            Violation(
                code=ViolationCode.I9,
                message=f"I9 HA liveness/ownership violation: {', '.join(reasons)}",
                facts=MappingProxyType(dict(facts)),
                observation_type="step",
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I10: Typed validation
    # -------------------------------------------------------------------------
    def evaluate_i10(
        self,
        reply_or_error: Any,
        confirmed: bool = False,
    ) -> list[Violation]:
        """I10: Corpus never leaks untyped errors; malformed 200 never confirms."""
        if isinstance(reply_or_error, BaseException):
            root_exc = getattr(reply_or_error, "__cause__", None) or reply_or_error
            is_typed = isinstance(reply_or_error, PsegError) or isinstance(root_exc, PsegError)
            if not is_typed:
                return [
                    Violation(
                        code=ViolationCode.I10,
                        message=(
                            f"I10 typed validation violation: untyped exception "
                            f"'{type(root_exc).__name__}' leaked"
                        ),
                        facts=MappingProxyType({"error_type": type(root_exc).__name__}),
                        observation_type="step",
                    )
                ]

        if getattr(reply_or_error, "valid", True) is False and confirmed:
            return [
                Violation(
                    code=ViolationCode.I10,
                    message="I10 typed validation violation: unvalidated/malformed response confirmed session",
                    facts=MappingProxyType({"reply_id": getattr(reply_or_error, "reply_id", None)}),
                    observation_type="step",
                )
            ]

        return []

    # -------------------------------------------------------------------------
    # Invariant I11: Privacy
    # -------------------------------------------------------------------------
    def evaluate_i11_dispatch(self, dispatch: Dispatch) -> list[Violation]:
        """I11 send-time: check body digest SHA-256 only; never retain plaintext."""
        if hasattr(dispatch, "body") and getattr(dispatch, "body", None) is not None:
            return [
                Violation(
                    code=ViolationCode.I11,
                    message="I11 privacy violation: plaintext body retained in Dispatch record",
                    facts=MappingProxyType({"sequence": dispatch.sequence}),
                    observation_type="send",
                    sequence=dispatch.sequence,
                )
            ]
        return []

    def evaluate_i11(
        self,
        surfaces: Mapping[str, Any],
        sentinels: Sequence[str] = (),
    ) -> list[Violation]:
        """I11: Synthetic credential/cookie sentinels absent from logs/diagnostics/issues/states."""
        check_sentinels = set(sentinels) | self._sentinels
        leaks = []
        for surface_name, content in surfaces.items():
            content_str = str(content)
            for sentinel in check_sentinels:
                if sentinel and sentinel in content_str:
                    leaks.append((surface_name, sentinel))

        if not leaks:
            return []

        return [
            Violation(
                code=ViolationCode.I11,
                message=f"I11 privacy violation: sentinels leaked on surfaces: {leaks}",
                facts=MappingProxyType({"leaks": tuple(leaks)}),
                observation_type="step",
            )
        ]

    # -------------------------------------------------------------------------
    # Invariant I12: Statistics isolation
    # -------------------------------------------------------------------------
    def evaluate_i12(
        self,
        before_snapshot: Any,
        after_snapshot: Any,
    ) -> list[Violation]:
        """I12: Auth-failing poll/backfill adds no rows to either series; journal preserved.

        Compares BOTH series and journal around auth failure.
        """
        b_rows = dict(getattr(before_snapshot, "rows", ()))
        a_rows = dict(getattr(after_snapshot, "rows", ()))

        reasons = []

        # Check consumption series
        b_cons = b_rows.get("consumption", ())
        a_cons = a_rows.get("consumption", ())
        if len(a_cons) > len(b_cons) or a_cons != b_cons:
            reasons.append("consumption_series_modified")

        # Check second series (cost / production / all non-consumption series)
        other_series_keys = (set(b_rows.keys()) | set(a_rows.keys())) - {"consumption"}
        for k in sorted(other_series_keys):
            b_val = b_rows.get(k, ())
            a_val = a_rows.get(k, ())
            if len(a_val) > len(b_val) or a_val != b_val:
                reasons.append(f"second_series_{k}_modified")

        # Check journal preserved
        b_journal = dict(getattr(before_snapshot, "journal", {}))
        a_journal = dict(getattr(after_snapshot, "journal", {}))

        b_pending = b_journal.get("pending") if "pending" in b_journal else b_journal
        a_pending = a_journal.get("pending") if "pending" in a_journal else a_journal

        if b_pending and not a_pending:
            reasons.append("journal_cleared")
        elif b_journal.get("has_pending") is True and a_journal.get("has_pending") is False:
            reasons.append("journal_cleared")

        if not reasons:
            return []

        return [
            Violation(
                code=ViolationCode.I12,
                message=f"I12 statistics isolation violation: {', '.join(reasons)}",
                facts=MappingProxyType({"reasons": tuple(reasons)}),
                observation_type="step",
            )
        ]

    def assert_clean(self) -> None:
        """Assert that zero violations have been observed."""
        with self._lock:
            if self.violations:
                v_summary = [f"{v.code}: {v.message}" for v in self.violations]
                raise AssertionError(f"Oracle observed unexpected violations: {v_summary}")

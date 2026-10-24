"""Non-secret admission control for bounded Remember Me renewals.

The plan this implements is a product safety limit, not a vendor contract:

* at most two cookie-renewal sequences per verified ``MM_RememberMe`` generation:
  the initial use plus one retry that a *transient* failure must have earned,
* at least 15 minutes between any two sequences, including across generations,
* a terminal refusal (rejected cookie, CAPTCHA demand, security step) stops the
  generation until the cookie is verifiably replaced or a human signs in again.

State is deliberately value-free: no cookie value, hash or fingerprint, no
credential and no page body. The single state object for an entry lives in an
entry-scoped runtime (so every client of that entry observes the same budget,
including across an unload/reload) and is mirrored into ``entry.data`` next to the
cookie jar for the next process start.

An **absent** key is a genuine first run and starts fresh. A **present** key that
does not validate fails closed: the runtime refuses further dispatch and never
rewrites the corrupt value until a verified human sign-in rearms it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import logging
import threading
from typing import Any

from .const import (
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_REMEMBER_ME_REJECTED,
    AUTH_REASON_SECURITY_STEP,
    CONF_RENEWAL_ADMISSION,
    DOMAIN,
    LOCAL_RENEWAL_MAX_SEQUENCES,
    LOCAL_RENEWAL_MIN_INTERVAL_SECONDS,
)

_LOGGER = logging.getLogger(__name__)

#: Reasons that end one Remember Me generation: never retried automatically.
TERMINAL_REASONS = frozenset({
    AUTH_REASON_REMEMBER_ME_REJECTED,
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_SECURITY_STEP,
})

#: Admission decision reasons that never start HTTP.
DEFERRED_REASONS = frozenset({
    "retired",
    "busy",
    "cooldown",
    "exhausted",
    "terminal",
    "uncertain",
})


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a stored ISO timestamp; only an aware value is trusted."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        return None


@dataclass
class RenewalAdmission:
    """Attempt budget, retry eligibility, cooldown clock and terminal reason."""

    sequences: int = 0
    last_sequence_at: str | None = None
    terminal_reason: str | None = None
    retry_eligible: bool = False
    #: In-memory only: False from reserve() until its outcome settles. A retired
    #: owner can leave the slot spent with no known outcome; that is still a pending
    #: wait, not proof that the generation is exhausted. Never serialized.
    settled: bool = True
    #: Present-but-invalid persisted state: refuse every sequence (fail closed).
    uncertain: bool = False

    @classmethod
    def from_dict(cls, raw: Any) -> RenewalAdmission:
        """Load a *present* persisted value; anything unexpected fails closed."""
        if not isinstance(raw, dict):
            return cls(uncertain=True)
        known_clock = _parse_timestamp(raw.get("last_sequence_at"))

        def uncertain() -> RenewalAdmission:
            # Keep a trustworthy clock even when a different field is malformed.
            # Human repair must not shorten a known future/global cooldown.
            return cls(
                last_sequence_at=known_clock.isoformat() if known_clock else None,
                uncertain=True,
            )

        if raw.get("uncertain", False) is not False:
            return uncertain()
        sequences = raw.get("sequences")
        if isinstance(sequences, bool) or not isinstance(sequences, int):
            return uncertain()
        if sequences < 0 or sequences > LOCAL_RENEWAL_MAX_SEQUENCES:
            return uncertain()
        terminal = raw.get("terminal_reason")
        if terminal is not None and (
            not isinstance(terminal, str) or terminal not in TERMINAL_REASONS
        ):
            return uncertain()
        retry_eligible = raw.get("retry_eligible", False)
        if not isinstance(retry_eligible, bool):
            return uncertain()
        raw_last = raw.get("last_sequence_at")
        last_dt = None if raw_last is None else _parse_timestamp(raw_last)
        if raw_last is not None and last_dt is None:
            return uncertain()
        if sequences and last_dt is None:
            # A spent slot with no usable clock cannot enforce the global gap.
            return uncertain()
        if retry_eligible and sequences != 1:
            return uncertain()
        return cls(
            sequences=sequences,
            last_sequence_at=last_dt.isoformat() if last_dt else None,
            terminal_reason=terminal,
            retry_eligible=retry_eligible,
        )

    @classmethod
    def from_entry_data(cls, data: Mapping[str, Any]) -> RenewalAdmission:
        """Load one entry's state: absent means fresh, present must validate."""
        if CONF_RENEWAL_ADMISSION not in data:
            return cls()
        return cls.from_dict(data[CONF_RENEWAL_ADMISSION])

    def as_dict(self) -> dict[str, Any]:
        """Serialize the non-secret state for ``entry.data``."""
        return {
            "sequences": self.sequences,
            "last_sequence_at": self.last_sequence_at,
            "terminal_reason": self.terminal_reason,
            "retry_eligible": self.retry_eligible,
        }

    def blocked_reason(self, now: datetime) -> str | None:
        """Return why another sequence may not start, or None when one may."""
        if self.uncertain:
            return "uncertain"
        if self.terminal_reason:
            return "terminal"
        if self.sequences >= LOCAL_RENEWAL_MAX_SEQUENCES:
            return "exhausted"
        last = _parse_timestamp(self.last_sequence_at)
        if last is not None and now.astimezone(UTC) < last:
            # A future/rolled-back clock never bypasses the gap. It is also not yet
            # proof that the generation is spent.
            return "cooldown"
        if self.sequences and not self.retry_eligible:
            if not self.settled:
                # An in-flight or retired-owner reservation has no known outcome yet:
                # keep the wait honest instead of declaring the generation spent.
                return "cooldown"
            # A settled attempt that earned no retry can never run again, even while
            # its 15-minute window is still open. Do not promise a later attempt.
            return "exhausted"
        if last is not None:
            elapsed = (now.astimezone(UTC) - last).total_seconds()
            if elapsed < LOCAL_RENEWAL_MIN_INTERVAL_SECONDS:
                return "cooldown"
        return None

    def reserve(self, now: datetime) -> None:
        """Spend one sequence slot. Callers check :meth:`blocked_reason` first."""
        if self.blocked_reason(now) is not None:
            raise ValueError("renewal admission refuses a blocked reservation")
        self.sequences += 1
        self.last_sequence_at = now.astimezone(UTC).isoformat()
        # A slot is spent without a known outcome: no retry may follow until a
        # real transient settlement earns one.
        self.retry_eligible = False
        self.settled = False

    def record_outcome(self, reason: str | None, *, transient: bool = False) -> None:
        """Settle a spent slot: terminal, transient (one retry), or success/unknown."""
        self.settled = True
        if reason in TERMINAL_REASONS:
            self.terminal_reason = reason
            self.retry_eligible = False
            return
        if transient and self.sequences == 1:
            self.retry_eligible = True

    def record_terminal(self, reason: str) -> None:
        """Latch a terminal challenge discovered outside a renewal sequence.

        A CAPTCHA or security question can appear on the poll's permitted password
        fallback after the cookie leg was deferred. That outcome must survive a
        reload and only a completed human sign-in clears it.
        """
        if reason not in TERMINAL_REASONS:
            return
        self.terminal_reason = reason
        self.retry_eligible = False
        self.settled = True

    def rearm(self, now: datetime | None = None) -> None:
        """Start a new generation after a verified rotation or a human sign-in.

        A valid generation keeps ``last_sequence_at``: the 15-minute gap spans
        generations, so a rotated cookie cannot be renewed back-to-back. A corrupt
        state has no trustworthy clock, so the rearm starts a conservative cooldown
        from ``now`` instead of granting an immediate sequence.
        """
        if self.uncertain:
            if now is None:
                return
            known_clock = _parse_timestamp(self.last_sequence_at)
            self.uncertain = False
            self.last_sequence_at = max(
                now.astimezone(UTC), known_clock or now.astimezone(UTC)
            ).isoformat()
        self.sequences = 0
        self.terminal_reason = None
        self.retry_eligible = False
        self.settled = True


class RenewalEntryRuntime:
    """One admission object and ownership generation per config entry.

    Every coordinator/client of an entry uses this object, so a reservation, a
    terminal refusal and its cooldown survive an unload/reload without trusting a
    stale ``entry.data`` snapshot. The lock is held only for in-memory policy
    updates, never across HTTP or an event-loop await.
    """

    def __init__(self, entry_id: str) -> None:
        """Create the runtime; the first coordinator binds the persisted state."""
        self.entry_id = entry_id
        self.lock = threading.RLock()
        self._admission = RenewalAdmission()
        self._bound = False
        self._generation = 0
        self._retired = True
        self._owner_valid = None
        self._reservation_owner: int | None = None
        self._policy_epoch = 0
        self._reservation_epoch = 0
        self._persist_callback = None

    def bind_persistence(self, hass: Any, entry: Any) -> None:
        """Schedule policy-only handoffs on HA's loop, independent of jar export."""
        def schedule() -> None:
            hass.loop.call_soon_threadsafe(self.persist, hass, entry)

        self._persist_callback = schedule

    def persist(self, hass: Any, entry: Any) -> None:
        """Mirror shared policy on the event loop; uncertainty refuses dispatch.

        This copies only the shared runtime's current policy, never a retired
        client's cookies or telemetry. HA's disk write remains best effort.
        """
        with self.lock:
            state = self.admission_dict()
            if state is None or state == entry.data.get(CONF_RENEWAL_ADMISSION):
                return
            if CONF_RENEWAL_ADMISSION not in entry.data and state == RenewalAdmission().as_dict():
                return
            try:
                hass.config_entries.async_update_entry(
                    entry, data={**entry.data, CONF_RENEWAL_ADMISSION: state}
                )
            except Exception:
                self._admission.uncertain = True
                _LOGGER.warning("Renewal metadata handoff failed; further renewal is refused")

    def _changed(self) -> None:
        if self._persist_callback is not None:
            try:
                self._persist_callback()
            except Exception:
                self._admission.uncertain = True

    def bind(self, entry_data: Mapping[str, Any]) -> None:
        """Adopt ``entry.data`` once per process; later reloads share in memory."""
        with self.lock:
            if self._bound:
                return
            self._admission = RenewalAdmission.from_entry_data(entry_data)
            self._bound = True

    def activate(self, owner_valid: Any = None) -> int:
        """Return a new ownership token for a live coordinator."""
        with self.lock:
            self._generation += 1
            self._retired = False
            self._owner_valid = owner_valid
            return self._generation

    def retire(self, token: int) -> None:
        """Invalidate one ownership token; a later activate starts the next."""
        with self.lock:
            if token == self._generation:
                self._retired = True

    def is_active(self, token: int) -> bool:
        """Return True while this token may reserve or publish policy state."""
        with self.lock:
            return self._is_current(token)

    def _is_current(self, token: int) -> bool:
        return (
            not self._retired
            and token == self._generation
            and (self._owner_valid is None or self._owner_valid())
        )

    @property
    def admission(self) -> RenewalAdmission:
        """The shared admission object (callers must not mutate it directly)."""
        return self._admission

    def admission_dict(self) -> dict[str, Any] | None:
        """Current persistable state, or None when the loaded state is corrupt."""
        with self.lock:
            if self._admission.uncertain:
                return None
            return self._admission.as_dict()

    def reserve(self, token: int, now: datetime) -> str | None:
        """Atomically take the shared slot; return a refusal reason or None."""
        with self.lock:
            if not self._is_current(token):
                return "retired"
            if self._reservation_owner is not None:
                return "busy"
            blocked = self._admission.blocked_reason(now)
            if blocked is not None:
                return blocked
            self._admission.reserve(now)
            self._reservation_owner = token
            self._reservation_epoch = self._policy_epoch
            self._changed()
            return None

    def can_dispatch(self, token: int) -> bool:
        """Check ownership again immediately before a reserved sequence dispatch."""
        with self.lock:
            return (
                self._is_current(token)
                and self._reservation_owner == token
                and not self._admission.uncertain
            )

    def record_terminal(self, token: int, reason: str) -> bool:
        """Persist a terminal challenge for the current owner only.

        A retired owner's late result must never latch a replacement's fresh
        generation. Returns True when the shared state changed.
        """
        with self.lock:
            if not self._is_current(token):
                return False
            if self._admission.terminal_reason == reason:
                return False
            self._admission.record_terminal(reason)
            self._changed()
            return True

    def finish(
        self,
        token: int,
        *,
        reason: str | None,
        transient: bool,
        rotated: bool,
    ) -> None:
        """Settle this token's reservation; a retired token cannot rearm."""
        with self.lock:
            if self._reservation_owner != token:
                return
            self._reservation_owner = None
            if self._reservation_epoch != self._policy_epoch:
                return
            if rotated:
                # Only a live owner may start a new generation from a rotation.
                if self._is_current(token):
                    self._admission.rearm()
                self._changed()
                return
            self._admission.record_outcome(reason, transient=transient)
            self._changed()

    def rearm_for_human(self, now: datetime) -> dict[str, Any]:
        """Explicit human sign-in: fresh generation, conservative clock."""
        with self.lock:
            # Invalidate old clients without releasing an HTTP sequence still in
            # flight; its settlement cannot alter the human's new generation.
            self._generation += 1
            self._retired = True
            self._policy_epoch += 1
            self._admission.rearm(now=now)
            self._changed()
            return self._admission.as_dict()


def renewal_runtime_for(hass: Any, entry_id: str) -> RenewalEntryRuntime:
    """Return the one renewal runtime shared by every coordinator of an entry."""
    registry = hass.data.setdefault(f"{DOMAIN}_renewal_runtimes", {})
    runtime = registry.get(entry_id)
    if runtime is None:
        runtime = RenewalEntryRuntime(entry_id)
        registry[entry_id] = runtime
    return runtime


def rearm_entry_admission(
    hass: Any,
    entry_id: str,
    persisted: Any,
    present: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Rearm for a completed human sign-in, through the live runtime when present."""
    moment = now or datetime.now(UTC)
    runtime = hass.data.get(f"{DOMAIN}_renewal_runtimes", {}).get(entry_id)
    if runtime is not None:
        return runtime.rearm_for_human(moment)
    state = RenewalAdmission.from_dict(persisted) if present else RenewalAdmission()
    state.rearm(now=moment)
    return state.as_dict()

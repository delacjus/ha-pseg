"""Non-secret admission policy for bounded Remember Me renewals."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from custom_components.pseg.const import (
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_REMEMBER_ME_REJECTED,
    CONF_RENEWAL_ADMISSION,
    LOCAL_RENEWAL_MIN_INTERVAL_SECONDS,
)
from custom_components.pseg.renewal_admission import (
    RenewalAdmission,
    RenewalEntryRuntime,
    rearm_entry_admission,
)

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


def test_persisted_shape_is_value_free() -> None:
    state = RenewalAdmission.from_dict({
        "sequences": 1, "last_sequence_at": NOW.isoformat(),
        "terminal_reason": AUTH_REASON_CAPTCHA_REQUIRED,
    }).as_dict()
    assert set(state) == {"sequences", "last_sequence_at", "terminal_reason", "retry_eligible"}
    assert "cookie" not in str(state).lower()


def test_two_sequences_per_generation_and_fifteen_minutes_between_them() -> None:
    admission = RenewalAdmission()
    assert admission.blocked_reason(NOW) is None
    admission.reserve(NOW)
    admission.record_outcome(None, transient=True)
    assert admission.blocked_reason(NOW + timedelta(minutes=5)) == "cooldown"
    assert admission.blocked_reason(
        NOW + timedelta(seconds=LOCAL_RENEWAL_MIN_INTERVAL_SECONDS)
    ) is None
    admission.reserve(NOW + timedelta(minutes=15))
    admission.record_outcome(None, transient=True)
    assert admission.blocked_reason(NOW + timedelta(hours=4)) == "exhausted"


def test_global_gap_survives_a_rearm() -> None:
    admission = RenewalAdmission()
    admission.reserve(NOW)
    admission.record_outcome(None, transient=True)
    admission.reserve(NOW + timedelta(minutes=15))
    admission.record_outcome(AUTH_REASON_REMEMBER_ME_REJECTED)
    assert admission.terminal_reason == AUTH_REASON_REMEMBER_ME_REJECTED
    admission.rearm()
    assert admission.sequences == 0
    assert admission.terminal_reason is None
    assert admission.blocked_reason(NOW + timedelta(minutes=16)) == "cooldown"
    assert admission.blocked_reason(NOW + timedelta(minutes=31)) is None


def test_only_actual_transient_outcome_earns_retry_across_reload() -> None:
    admission = RenewalAdmission()
    admission.reserve(NOW)
    for reason in (None, "unknown"):
        admission.record_outcome(reason)
        cold = RenewalAdmission.from_dict(admission.as_dict())
        assert cold.blocked_reason(NOW + timedelta(minutes=16)) == "exhausted"
    admission.record_outcome(None, transient=True)
    cold = RenewalAdmission.from_dict(admission.as_dict())
    assert cold.blocked_reason(NOW + timedelta(minutes=16)) is None
    cold.reserve(NOW + timedelta(minutes=16))
    assert cold.retry_eligible is False
    assert cold.blocked_reason(NOW + timedelta(hours=1)) == "exhausted"


def test_terminal_reason_blocks_at_any_time() -> None:
    admission = RenewalAdmission.from_dict({
        "sequences": 1, "last_sequence_at": NOW.isoformat(),
        "terminal_reason": AUTH_REASON_REMEMBER_ME_REJECTED,
    })
    assert admission.blocked_reason(NOW + timedelta(days=30)) == "terminal"


@pytest.mark.parametrize("raw", [
    None, "garbage", {}, {"sequences": 99}, {"sequences": -4}, {"sequences": True},
    {"sequences": 1}, {"sequences": 1, "last_sequence_at": "not-a-date"},
    {"sequences": 0, "last_sequence_at": "2026-10-23T12:00:00"},
    {"sequences": 0, "last_sequence_at": "0001-01-01T00:00:00+01:00"},
    {"sequences": 0, "terminal_reason": []},
    {"sequences": 0, "terminal_reason": "unknown"},
    {"sequences": 0, "retry_eligible": True},
    {"sequences": 1, "last_sequence_at": NOW.isoformat(), "retry_eligible": 1},
])
def test_present_uncertain_metadata_refuses(raw) -> None:
    state = RenewalAdmission.from_entry_data({CONF_RENEWAL_ADMISSION: raw})
    assert state.blocked_reason(NOW + timedelta(days=365)) == "uncertain"


def test_absent_state_is_fresh_but_present_null_is_not() -> None:
    assert RenewalAdmission.from_entry_data({}).blocked_reason(NOW) is None
    assert RenewalAdmission.from_entry_data({CONF_RENEWAL_ADMISSION: None}).blocked_reason(NOW) == "uncertain"


def test_human_reauth_rearms_and_keeps_the_clock() -> None:
    previous = {
        "sequences": 2, "last_sequence_at": NOW.isoformat(),
        "terminal_reason": AUTH_REASON_REMEMBER_ME_REJECTED,
    }
    fresh = rearm_entry_admission(SimpleNamespace(data={}), "synthetic", previous, True, NOW)
    assert fresh == {
        "sequences": 0, "last_sequence_at": NOW.isoformat(),
        "terminal_reason": None, "retry_eligible": False,
    }
    assert RenewalAdmission.from_dict(fresh).blocked_reason(NOW + timedelta(minutes=5)) == "cooldown"


def test_corrupt_human_reauth_starts_conservative_cooldown() -> None:
    fresh = rearm_entry_admission(SimpleNamespace(data={}), "synthetic", None, True, NOW)
    state = RenewalAdmission.from_dict(fresh)
    assert state.blocked_reason(NOW + timedelta(minutes=5)) == "cooldown"
    assert state.blocked_reason(NOW + timedelta(minutes=15)) is None


def test_retirement_between_reserve_and_dispatch_refuses() -> None:
    runtime = RenewalEntryRuntime("synthetic")
    runtime.bind({})
    token = runtime.activate()
    assert runtime.reserve(token, NOW) is None
    runtime.retire(token)
    assert runtime.can_dispatch(token) is False
    runtime.activate()
    assert runtime.admission.sequences == 1
    assert runtime.reserve(token, NOW + timedelta(hours=1)) == "retired"


def test_human_reauth_does_not_release_inflight_or_accept_its_outcome() -> None:
    runtime = RenewalEntryRuntime("synthetic")
    runtime.bind({})
    old = runtime.activate()
    assert runtime.reserve(old, NOW) is None
    runtime.rearm_for_human(NOW)
    new = runtime.activate()
    assert runtime.reserve(new, NOW + timedelta(hours=1)) == "busy"
    runtime.finish(old, reason=AUTH_REASON_REMEMBER_ME_REJECTED, transient=False, rotated=False)
    assert runtime.admission.terminal_reason is None
    assert runtime.reserve(new, NOW + timedelta(hours=1)) is None


def test_human_repair_preserves_known_future_clock_in_otherwise_corrupt_state() -> None:
    future = NOW + timedelta(days=1)
    state = RenewalAdmission.from_dict({
        "sequences": True, "last_sequence_at": future.isoformat(),
    })
    assert state.uncertain
    state.rearm(now=NOW)
    assert state.last_sequence_at == future.isoformat()
    assert state.blocked_reason(NOW + timedelta(hours=1)) == "cooldown"
    assert state.blocked_reason(future + timedelta(minutes=14)) == "cooldown"

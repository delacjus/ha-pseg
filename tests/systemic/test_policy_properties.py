"""G4: literal policy answers, independent of the implementation under test.

No HA lifecycle ending applies to these pure decision tables. The generated
transport cases remain subject to the shared run_case ending.
"""

from datetime import UTC, datetime, timedelta

import pytest

from custom_components.pseg.const import CONF_RENEWAL_ADMISSION
from custom_components.pseg.renewal_admission import RenewalAdmission

NOW = datetime(2026, 10, 25, 12, tzinfo=UTC)
PAST = "2026-10-25T11:45:00+00:00"
FUTURE = "2026-10-25T12:15:00+00:00"

# (persisted value, uncertain, admission now). None is present-null, not absent.
LOAD_TABLE = [
    ({"sequences": 0}, False, None),
    ({"sequences": 1, "last_sequence_at": PAST}, False, "exhausted"),
    ({"sequences": 1, "last_sequence_at": PAST, "retry_eligible": True}, False, None),
    ({"sequences": 2, "last_sequence_at": PAST}, False, "exhausted"),
    ({"sequences": 3, "last_sequence_at": PAST}, True, "uncertain"),
    ({"sequences": 0, "last_sequence_at": FUTURE}, False, "cooldown"),
    ({"sequences": 1, "last_sequence_at": FUTURE, "retry_eligible": True}, False, "cooldown"),
    ({"sequences": 0, "terminal_reason": "security_step"}, False, "terminal"),
    (None, True, "uncertain"),
    ([], True, "uncertain"),
    ("broken", True, "uncertain"),
    (True, True, "uncertain"),
    ({}, True, "uncertain"),
    ({"sequences": True}, True, "uncertain"),
    ({"sequences": False}, True, "uncertain"),
    ({"sequences": -1}, True, "uncertain"),
    ({"sequences": "1"}, True, "uncertain"),
    ({"sequences": 1.0}, True, "uncertain"),
    ({"sequences": 1}, True, "uncertain"),
    ({"sequences": 0, "last_sequence_at": "broken"}, True, "uncertain"),
    ({"sequences": 0, "last_sequence_at": "2026-10-25T11:45:00"}, True, "uncertain"),
    ({"sequences": 0, "last_sequence_at": 1}, True, "uncertain"),
    ({"sequences": 0, "retry_eligible": "false"}, True, "uncertain"),
    ({"sequences": 0, "retry_eligible": True}, True, "uncertain"),
    ({"sequences": 2, "last_sequence_at": PAST, "retry_eligible": True}, True, "uncertain"),
    ({"sequences": 0, "terminal_reason": "unknown"}, True, "uncertain"),
    ({"sequences": 0, "terminal_reason": []}, True, "uncertain"),
    ({"sequences": 0, "uncertain": 0}, True, "uncertain"),
    ({"sequences": 0, "uncertain": True}, True, "uncertain"),
]


@pytest.mark.parametrize("raw,uncertain,answer", LOAD_TABLE)
def test_literal_metadata_table(raw, uncertain, answer):
    policy = RenewalAdmission.from_entry_data({CONF_RENEWAL_ADMISSION: raw})
    assert policy.uncertain is uncertain
    assert policy.blocked_reason(NOW) == answer
    if answer is not None:
        with pytest.raises(ValueError, match="refuses"):
            policy.reserve(NOW)


def test_missing_metadata_is_fresh():
    policy = RenewalAdmission.from_entry_data({})
    assert policy.as_dict() == {
        "sequences": 0,
        "last_sequence_at": None,
        "terminal_reason": None,
        "retry_eligible": False,
    }
    assert policy.blocked_reason(NOW) is None


# Attempts 0/1/2/3 and 14:59/15:00. 3 is deliberately invalid persisted state.
SPACING_TABLE = [
    (0, False, 899, "cooldown"),
    (0, False, 900, None),
    (1, False, 899, "exhausted"),
    (1, False, 900, "exhausted"),
    (1, True, 899, "cooldown"),
    (1, True, 900, None),
    (2, False, 899, "exhausted"),
    (2, False, 900, "exhausted"),
    (3, False, 899, "uncertain"),
    (3, False, 900, "uncertain"),
    (0, False, -1, "cooldown"),
    (1, True, -1, "cooldown"),
]


@pytest.mark.parametrize("attempts,retry,elapsed,answer", SPACING_TABLE)
def test_literal_spacing_and_rollback(attempts, retry, elapsed, answer):
    policy = RenewalAdmission.from_dict(
        {
            "sequences": attempts,
            "retry_eligible": retry,
            "last_sequence_at": NOW.isoformat(),
        }
    )
    assert policy.blocked_reason(NOW + timedelta(seconds=elapsed)) == answer


# Outcomes are crossed with every load shape. Settlement never repairs corruption.
OUTCOMES = [
    (None, False, "exhausted", False, None),
    ("unknown", False, "exhausted", False, None),
    ("transient", True, None, True, None),
    ("captcha_required", False, "terminal", False, "captcha_required"),
    ("security_step", False, "terminal", False, "security_step"),
    ("remember_me_rejected", False, "terminal", False, "remember_me_rejected"),
]


@pytest.mark.parametrize("reason,transient,answer,retry,terminal", OUTCOMES)
def test_literal_settlement_and_second_attempt(reason, transient, answer, retry, terminal):
    policy = RenewalAdmission()
    policy.reserve(NOW)
    assert (policy.sequences, policy.settled, policy.retry_eligible) == (1, False, False)
    assert policy.blocked_reason(NOW + timedelta(minutes=16)) == "cooldown"
    policy.record_outcome(reason, transient=transient)
    assert (policy.settled, policy.retry_eligible, policy.terminal_reason) == (
        True,
        retry,
        terminal,
    )
    assert policy.blocked_reason(NOW + timedelta(minutes=15)) == answer
    if retry:
        policy.reserve(NOW + timedelta(minutes=15))
        policy.record_outcome("transient", transient=True)
        assert policy.sequences == 2
        assert policy.retry_eligible is False
        assert policy.blocked_reason(NOW + timedelta(minutes=30)) == "exhausted"


# At +1 day, columns follow OUTCOMES order. These are literal answers,
# including settlement of already-spent or refused persisted states.
LOAD_OUTCOME_TABLE = [
    ("exhausted", "exhausted", None, "terminal", "terminal", "terminal"),
    ("exhausted", "exhausted", None, "terminal", "terminal", "terminal"),
    ("exhausted", "exhausted", "exhausted", "terminal", "terminal", "terminal"),
    ("exhausted", "exhausted", "exhausted", "terminal", "terminal", "terminal"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    (None, None, None, "terminal", "terminal", "terminal"),
    (None, None, None, "terminal", "terminal", "terminal"),
    ("terminal", "terminal", "terminal", "terminal", "terminal", "terminal"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
    ("uncertain", "uncertain", "uncertain", "uncertain", "uncertain", "uncertain"),
]


@pytest.mark.parametrize("shape,loaded", list(enumerate(LOAD_TABLE)))
@pytest.mark.parametrize("outcome,settlement", list(enumerate(OUTCOMES)))
def test_loaded_metadata_cross_outcomes(shape, loaded, outcome, settlement):
    raw, uncertain, initial = loaded
    reason, transient, _answer, _retry, _terminal = settlement
    policy = RenewalAdmission.from_dict(raw)
    clock_before = policy.last_sequence_at
    if initial is None:
        policy.reserve(NOW)
    policy.record_outcome(reason, transient=transient)
    assert policy.blocked_reason(NOW + timedelta(days=1)) == LOAD_OUTCOME_TABLE[shape][outcome]
    assert policy.uncertain is uncertain
    if uncertain:
        assert policy.blocked_reason(NOW + timedelta(days=1)) == "uncertain"
    elif reason in ("captcha_required", "security_step", "remember_me_rejected"):
        assert policy.blocked_reason(NOW + timedelta(days=1)) == "terminal"
    # All unchanged-clock states, including refused reservations, keep their clock.
    if initial is not None:
        assert policy.last_sequence_at == clock_before


@pytest.mark.parametrize(
    "raw,clock",
    [
        ({"sequences": 1, "last_sequence_at": PAST}, PAST),
        ({"sequences": 2, "last_sequence_at": FUTURE, "terminal_reason": "security_step"}, FUTURE),
        ({"sequences": True, "last_sequence_at": FUTURE}, FUTURE),
        ({"sequences": True, "last_sequence_at": PAST}, NOW.isoformat()),
        (None, NOW.isoformat()),
    ],
)
def test_generation_rotation_retains_global_clock(raw, clock):
    policy = RenewalAdmission.from_dict(raw)
    policy.rearm(NOW)
    assert policy.as_dict() == {
        "sequences": 0,
        "last_sequence_at": clock,
        "terminal_reason": None,
        "retry_eligible": False,
    }
    assert policy.uncertain is False
    assert (
        policy.blocked_reason(datetime.fromisoformat(clock) + timedelta(seconds=899)) == "cooldown"
    )
    assert policy.blocked_reason(datetime.fromisoformat(clock) + timedelta(seconds=900)) is None

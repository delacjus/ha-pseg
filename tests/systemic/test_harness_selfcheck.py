"""Systemic self-check test suite for the I1-I12 invariant harness and oracle.

Demonstrates that the systemic oracle and lifecycle harness detect bad behaviour
rather than merely accepting good traces. Covers all 12 base invariants (I1-I12),
all 14 listed extra items from the P2-05 specification, paired healthy controls,
send-time observation verification, and two unlisted adversarial seeds.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant
import pytest

from tests.systemic.selfcheck_cases import (
    BASE_I_CODES,
    LISTED_EXTRA_ITEMS,
    SEED_MATRIX,
    UNLISTED_SEEDS,
    run_selfcheck_case,
)

SEND_TIME_CASES: frozenset[str] = frozenset(
    {
        "i1_retired_send",
        "redirect_hop_retirement",
        "same_cookie_handoff",
        "i2_credential_policy",
        "i3_live_quarantine",
        "next_request_poison",
        "privacy_sentinel",
    }
)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock: Any, enable_custom_integrations: Any) -> Any:
    yield


def test_completeness_matrix() -> None:
    """Completeness test: every I1-I12 code and every listed extra item has at least one seed."""
    # Every I1-I12 code is represented in the matrix
    all_seeded_codes = set().union(*SEED_MATRIX.values())
    for code in BASE_I_CODES:
        assert code in all_seeded_codes, f"Invariant code {code} missing from SEED_MATRIX"

    # Every listed extra item is in the matrix
    for extra_item in LISTED_EXTRA_ITEMS:
        assert extra_item in SEED_MATRIX, f"Listed extra item {extra_item} missing from SEED_MATRIX"

    # Matrix size is at least 26 seeds
    assert len(SEED_MATRIX) >= 26

    # Both unlisted seeds are defined
    assert len(UNLISTED_SEEDS) == 2
    assert "unlisted_poison_second_poll" in UNLISTED_SEEDS
    assert "unlisted_retired_following_redirect" in UNLISTED_SEEDS


@pytest.mark.parametrize("case_id", sorted(SEED_MATRIX.keys()))
async def test_seeded_violations_produce_exact_codes(
    hass: HomeAssistant,
    freezer: Any,
    caplog: Any,
    case_id: str,
) -> None:
    """Verify that each seeded bad trace produces the EXACT expected I-code set."""
    result = await run_selfcheck_case(hass, freezer, caplog, case_id, active=True)
    expected = SEED_MATRIX[case_id]
    assert result.actual_codes == expected, (
        f"Case {case_id} failed: expected {expected}, got {result.actual_codes}"
    )

    if case_id in SEND_TIME_CASES:
        assert result.observed_before_response is True, (
            f"Case {case_id} expected send-time observation before response return"
        )


@pytest.mark.parametrize("case_id", sorted(SEED_MATRIX.keys()))
async def test_healthy_controls_clean(
    hass: HomeAssistant,
    freezer: Any,
    caplog: Any,
    case_id: str,
) -> None:
    """Verify that each nearby healthy control trace produces ZERO violations."""
    result = await run_selfcheck_case(hass, freezer, caplog, case_id, active=False)
    assert result.actual_codes == frozenset(), (
        f"Healthy control for {case_id} had unexpected violations: {result.actual_codes}"
    )


@pytest.mark.parametrize("case_id", sorted(UNLISTED_SEEDS.keys()))
async def test_unlisted_seeds(
    hass: HomeAssistant,
    freezer: Any,
    caplog: Any,
    case_id: str,
) -> None:
    """Verify detection and control cleanly for both unlisted adversarial seeds."""
    res_bad = await run_selfcheck_case(hass, freezer, caplog, case_id, active=True)
    expected = UNLISTED_SEEDS[case_id]
    assert res_bad.actual_codes == expected, (
        f"Unlisted seed {case_id} failed: expected {expected}, got {res_bad.actual_codes}"
    )
    assert res_bad.observed_before_response is True

    res_good = await run_selfcheck_case(hass, freezer, caplog, case_id, active=False)
    assert res_good.actual_codes == frozenset(), (
        f"Unlisted control for {case_id} had unexpected violations: {res_good.actual_codes}"
    )


def test_meta_no_generic_assertions() -> None:
    """Meta-test: inspect AST to prove no seed test uses generic 'len > 0' or truthiness assertions."""
    test_files = [
        Path(__file__),
        Path(__file__).parent / "selfcheck_cases.py",
    ]

    for path in test_files:
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                # Reject assert len(...) > 0 on violations or codes
                if isinstance(node.test, ast.Compare):
                    left = node.test.left
                    ops = node.test.ops
                    comparators = node.test.comparators
                    if (
                        isinstance(left, ast.Call)
                        and isinstance(left.func, ast.Name)
                        and left.func.id == "len"
                    ):
                        for op, comp in zip(ops, comparators, strict=False):
                            if (
                                isinstance(op, ast.Gt)
                                and isinstance(comp, ast.Constant)
                                and comp.value == 0
                            ):
                                arg_name = ""
                                if left.args and isinstance(left.args[0], ast.Name):
                                    arg_name = left.args[0].id
                                elif left.args and isinstance(left.args[0], ast.Attribute):
                                    arg_name = left.args[0].attr
                                if any(sub in arg_name.lower() for sub in ("code", "violation")):
                                    raise AssertionError(
                                        f"Forbidden generic 'len > 0' assertion found at {path}:{node.lineno}"
                                    )

                # Reject bare truthiness assert on violations or codes
                if isinstance(node.test, ast.Name) and any(
                    sub in node.test.id.lower() for sub in ("code", "violation")
                ):
                    raise AssertionError(
                        f"Forbidden generic truthiness assertion found at {path}:{node.lineno}"
                    )
                if isinstance(node.test, ast.Attribute) and any(
                    sub in node.test.attr.lower() for sub in ("code", "violation")
                ):
                    raise AssertionError(
                        f"Forbidden generic truthiness assertion found at {path}:{node.lineno}"
                    )

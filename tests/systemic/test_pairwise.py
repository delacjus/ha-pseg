"""P2-08: deterministic pairwise generator and checked-in covering proofs.

These meta-tests are the guard rail for ``tools/pairwise.py`` and
``tests/systemic/response_covering.json``:

* the CLI re-derives every valid pair from the declared domains and exclusions and
  fails on a missing pair or an invalid row;
* generation is deterministic (stable seed/order) and reproduces the checked-in
  rows exactly;
* every declared exclusion has a reason and none removes a whole core axis value;
* the mandatory findings are present, fast, and the fast tier represents every
  stage/kind/cookie/position value (or declares the member model-only);
* deleting the only row covering a pair, or adding an invalid tuple, is refused.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from tests.support.corpus import CookieKind, FlowMode, Position, ResponseKind, Stage
from tools import pairwise

REPO_ROOT = Path(__file__).resolve().parents[2]
COVERING = REPO_ROOT / "tests" / "systemic" / "response_covering.json"
CORE_AXES = ("stage", "kind", "cookie", "position")


def _model() -> dict:
    return json.loads(COVERING.read_text(encoding="utf-8"))


def test_declared_axes_match_the_p2_03_vocabulary() -> None:
    """The covering axes are the P2-03 corpus vocabulary, not a local invention."""
    axes = _model()["axes"]
    assert axes["stage"] == list(Stage.ALL)
    assert axes["kind"] == list(ResponseKind.ALL)
    assert axes["cookie"] == list(CookieKind.ALL)
    assert axes["position"] == list(Position.ALL)
    assert axes["flow"] == list(FlowMode.ALL)
    assert axes["event"] == ["setup", "poll", "keepalive", "backfill"]
    assert axes["family"] == ["client", "ha"]


def test_covering_file_passes_the_independent_checker() -> None:
    """No missing valid pair, no invalid/duplicate row, no excluded tuple."""
    problems = pairwise.check_file(COVERING)
    assert problems == []


def test_cli_check_exits_zero() -> None:
    """The acceptance CLI succeeds on the checked-in file."""
    completed = subprocess.run(
        [sys.executable, "-B", str(REPO_ROOT / "tools" / "pairwise.py"), "--check", str(COVERING)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "OK pairs=" in completed.stdout


def test_required_pairs_are_re_derived_from_domains_and_exclusions() -> None:
    """Every pair the checker requires is observable in a valid declared tuple."""
    model = _model()
    derived = pairwise.required_pairs(model)
    observed: set[tuple[str, str]] = set()
    for values in pairwise.valid_tuples(model, scope="pairwise"):
        observed |= pairwise.pair_keys(values)
    assert derived == observed
    assert len(derived) > 500
    covered: set[tuple[str, str]] = set()
    for row in model["rows"]:
        covered |= pairwise.pair_keys(pairwise.row_values(row))
    assert derived <= covered


def test_generation_is_deterministic_and_reproduces_the_checked_in_rows() -> None:
    """Stable seed and order: regenerating yields exactly the checked-in rows."""
    model = _model()
    first = pairwise.generate_rows(model)
    second = pairwise.generate_rows(model)
    assert first == second
    assert [[row["id"], row["tier"]] for row in first] == [
        [row["id"], row["tier"]] for row in model["rows"]
    ]
    assert {row["id"]: row for row in first} == {row["id"]: row for row in model["rows"]}


def test_every_exclusion_declares_a_reason_and_keeps_difficult_cases() -> None:
    """Exclusions are declared data; none may erase a whole axis value."""
    model = _model()
    assert model["exclusions"], "the covering must declare its applicability rules"
    for exclusion in model["exclusions"]:
        assert exclusion["reason"].strip()
        assert exclusion.get("scope", ["pairwise", "nightly"]) in (
            ["pairwise"],
            ["nightly"],
            ["pairwise", "nightly"],
        )
    pairwise_valid = pairwise.valid_tuples(model, scope="pairwise")
    for axis in ("stage", "kind", "cookie", "position"):
        remaining = {values[axis] for values in pairwise_valid}
        missing = set(map(str, model["axes"][axis])) - remaining
        model_only = {
            str(entry["value"]) for entry in model.get("model_only", []) if entry["axis"] == axis
        }
        assert missing <= model_only, f"exclusions removed all '{axis}' values {missing}"
    # The difficult cases stay executable.
    kinds = {values["kind"] for values in pairwise_valid}
    for kind in (
        ResponseKind.HTTP_307,
        ResponseKind.HTTP_308,
        ResponseKind.HTTP_401,
        ResponseKind.HTTP_403,
        ResponseKind.HTTP_302_LOGIN,
        ResponseKind.TIMEOUT,
        ResponseKind.CONNECTION_ERROR,
        ResponseKind.ROOT_ARRAY,
        ResponseKind.ROOT_NULL,
        ResponseKind.TRUNCATED_JSON,
        ResponseKind.CAPTCHA,
        ResponseKind.ALL_INVALID,
    ):
        assert kind in kinds, f"difficult kind {kind} was excluded everywhere"
    stages = {values["stage"] for values in pairwise_valid}
    assert stages == set(Stage.ALL)


def test_mandatory_findings_are_present_and_fast() -> None:
    """307/308, hourly rotation and the fallback controls are mandatory fast rows."""
    model = _model()
    rows = {row["id"]: row for row in model["rows"]}
    for mandatory in pairwise.MANDATORY_FAST:
        row = rows[mandatory["id"]]
        assert row["tier"] == "fast", mandatory["id"]
        for axis in pairwise.PAIRWISE_AXES:
            assert row[axis] == mandatory[axis], (mandatory["id"], axis)
    hourly = [row for row in model["rows"] if row["stage"] == Stage.HOURLY_CHART_DATA]
    assert any(row["kind"] == ResponseKind.VALID_SUCCESS for row in hourly)
    assert any(row["kind"] == ResponseKind.HTTP_401 for row in hourly)
    assert any(row["kind"] == ResponseKind.HTTP_500 for row in hourly)


def test_fast_tier_represents_every_core_value() -> None:
    """Fast covers every stage/kind/cookie/position value (or a model-only probe)."""
    model = _model()
    fast_values = {
        f"{axis}={row[axis]}"
        for row in model["rows"]
        if row["tier"] == "fast"
        for axis in CORE_AXES
    }
    model_only = {f"{entry['axis']}={entry['value']}" for entry in model.get("model_only", [])}
    required = {f"{axis}={value}" for axis in CORE_AXES for value in model["axes"][axis]}
    assert required <= fast_values | model_only


def test_missing_covering_row_is_refused(tmp_path: Path) -> None:
    """Deleting the only row covering a pair fails the checker."""
    model = _model()
    coverage: dict[tuple[str, str], list[str]] = {}
    for row in model["rows"]:
        for pair in pairwise.pair_keys(pairwise.row_values(row)):
            coverage.setdefault(pair, []).append(row["id"])
    exclusive = next(pair for pair, ids in coverage.items() if len(ids) == 1)
    victim = coverage[exclusive][0]
    model["rows"] = [row for row in model["rows"] if row["id"] != victim]
    damaged = tmp_path / "damaged.json"
    damaged.write_text(json.dumps(model), encoding="utf-8")

    problems = pairwise.check_file(damaged)
    assert any("missing pair" in problem for problem in problems), (exclusive, problems)

    completed = subprocess.run(
        [sys.executable, "-B", str(REPO_ROOT / "tools" / "pairwise.py"), "--check", str(damaged)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert completed.returncode != 0
    assert "missing pair" in completed.stdout


def test_invalid_tuple_is_refused(tmp_path: Path) -> None:
    """An out-of-domain or excluded tuple is refused by the checker."""
    model = _model()
    invalid = dict(model["rows"][0])
    invalid["id"] = "invalid:out-of-domain"
    invalid["kind"] = "not_a_declared_kind"
    model["rows"].append(invalid)
    bad_domain = tmp_path / "bad_domain.json"
    bad_domain.write_text(json.dumps(model), encoding="utf-8")
    problems = pairwise.check_file(bad_domain)
    assert any("outside axis" in problem for problem in problems), problems

    excluded = dict(model["rows"][0])
    excluded["id"] = "invalid:excluded"
    excluded.update(
        {
            "stage": Stage.DAILY_CHART_DATA,
            "kind": ResponseKind.CAPTCHA,
            "cookie": CookieKind.NONE,
            "position": Position.POST_PROOF,
            "flow": FlowMode.S,
            "event": "poll",
            "family": "client",
        }
    )
    model["rows"][-1] = excluded
    bad_excluded = tmp_path / "bad_excluded.json"
    bad_excluded.write_text(json.dumps(model), encoding="utf-8")
    problems = pairwise.check_file(bad_excluded)
    assert any("excluded but declared" in problem for problem in problems), problems


def test_negative_proof_for_the_checker_itself(tmp_path: Path) -> None:
    """The checker is not vacuous: a file with no rows has every pair missing."""
    model = _model()
    model["rows"] = []
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps(model), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "-B", str(REPO_ROOT / "tools" / "pairwise.py"), "--check", str(empty)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert completed.returncode != 0
    assert "missing pair" in completed.stdout


@pytest.mark.parametrize(
    "axis",
    ["stage", "kind", "cookie", "position", "flow", "event", "family"],
)
def test_each_axis_is_crossed(axis: str) -> None:
    """Every declared axis participates in the covering, not just the core four."""
    model = _model()
    values = {row[axis] for row in model["rows"]}
    model_only = {
        str(entry["value"]) for entry in model.get("model_only", []) if entry["axis"] == axis
    }
    assert values | model_only == set(model["axes"][axis])

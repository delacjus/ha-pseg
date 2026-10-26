"""P2-11: A/B/C/D replay declaration, classifier and refusal proofs.

Fast tests are pure or structural: the classifier matrix, the checked-in
declaration against its own table, its mapped-assertion anchors, the bound
failure evidence (the reviewer's unrelated-assertion and wrong-literal negatives
against the real detector AST), the systemic detector matrices, the
bidirectional finding links and the historical-input refusals (which happen
before any family executes).

Slow tests run the real family contrasts in a synthetic git repository through
``tools/replay_check.py``: a valid bound contrast, a surviving family, a kill at
an unmapped assertion, a kill whose message lacks the mapped literal, an
import-error invalid, a reviewed all-pass historical snapshot, and a reviewed
incompatible historical snapshot. They exercise the shared
``tools/mutation_check`` engine; no test here re-implements it.
"""


from __future__ import annotations

import ast
from contextlib import redirect_stderr, redirect_stdout
import inspect
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

from tests.support.corpus import Position
from tests.systemic.dispatch_cases import FAST_CASES as DISPATCH_FAST_CASES
from tests.systemic.exit_cases import FAST_CASES as EXIT_FAST_CASES
from tests.systemic.findings import FINDINGS
from tests.systemic.response_cases import ALL_CASES as RESPONSE_CASES
from tools import replay_check
from tools._snapshot import snapshot

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests/systemic/replay_cases.json"
TABLE = ROOT / "tests/mutations/auth_replay.py"
SYSTEMIC_TABLE = ROOT / "tests/mutations/auth_systemic.py"
SYSTEMIC_CATALOG = ROOT / "tests/systemic/test_auth_systemic_catalog.py"
_TEST_PYTHON = os.environ.get("PSEG_TEST_PYTHON") or sys.executable

_SYNTHETIC_FAMILIES = (
    ("A", "A_FENCE", "fence", "replay-A-synthetic", "tests/test_nodes.py::test_a_fence"),
    ("B", "B_POISON", "poison", "replay-B-synthetic", "tests/test_nodes.py::test_b_poison"),
    ("C", "C_ROOT", "root", "replay-C-synthetic", "tests/test_nodes.py::test_c_root"),
    ("D", "D_CHECKPOINT", "checkpoint", "replay-D-synthetic", "tests/test_nodes.py::test_d_checkpoint"),
)


# ---------------------------------------------------------------------------
# Pure classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("control", "mutant", "bound", "expected"),
    [
        ("passed", "detected", True, "proved"),
        ("passed", "detected", False, "wrong_assertion"),
        ("passed", "survived", False, "failed"),
        ("passed", "invalid", False, "invalid"),
        ("failed", "detected", True, "invalid"),
        ("not_run", "not_run", False, "invalid"),
    ],
)
def test_family_classifier_matrix(
    control: str, mutant: str, bound: bool, expected: str
) -> None:
    """A contrast needs a GREEN control and an assertion-RED mutant."""
    assert replay_check.classify_family(control, mutant, bound) == expected


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        (["proved", "proved"], "proved"),
        (["proved", "failed"], "failed"),
        (["proved", "invalid"], "invalid"),
        (["failed", "invalid"], "invalid"),
        (["proved", "wrong_assertion"], "wrong_assertion"),
        (["wrong_assertion", "failed"], "wrong_assertion"),
        ([], "invalid"),
    ],
)
def test_multi_transformation_family_needs_every_member(
    verdicts: list[str], expected: str
) -> None:
    """C is proved only when both of its transformations are proved."""
    assert replay_check.classify_family_members(verdicts) == expected


@pytest.mark.parametrize(
    ("detectors", "status", "claim"),
    [
        (
            [{"outcome": "expected_mapped_failure"}, {"outcome": "no_failure"}],
            "performed",
            "historical_input_verified",
        ),
        (
            [{"outcome": "harness_incompatibility"}] * 4,
            "incompatible",
            "mutant_fallback_only",
        ),
        (
            [{"outcome": "harness_incompatibility"}, {"outcome": "expected_mapped_failure"}],
            "incompatible",
            "mutant_fallback_only",
        ),
        (
            [{"outcome": "no_failure"}] * 4,
            "no_historical_contrast",
            "mutant_fallback_only",
        ),
        (
            [{"outcome": "wrong_assertion"}, {"outcome": "no_failure"}],
            "wrong_assertion",
            "mutant_fallback_only",
        ),
    ],
)
def test_historical_verdict_never_claims_an_unproved_replay(
    detectors: list[dict[str, str]], status: str, claim: str
) -> None:
    """Only a bound mapped RED with zero incompatibility counts as historical proof."""
    verdict = replay_check.historical_verdict(detectors)
    assert verdict["status"] == status
    assert verdict["claim"] == claim
    assert verdict["harness_incompatibility"] == sum(
        item["outcome"] == "harness_incompatibility" for item in detectors
    )
    assert verdict["wrong_assertion"] == sum(
        item["outcome"] == "wrong_assertion" for item in detectors
    )


def test_historical_classification_binds_the_assertion_it_credits() -> None:
    """A historical call-phase assertion is a RED only when its evidence binds."""
    node = (
        "tests/systemic/test_auth_systemic_catalog.py"
        "::test_focused_chart_response_contract[hourly-empty]"
    )
    run = {
        "status": "ok",
        "collect_errors": [],
        "reports": [
            {
                "nodeid": node,
                "when": "call",
                "outcome": "failed",
                "is_assertion": True,
                "exc_type": "AssertionError",
            }
        ],
    }
    assert replay_check.classify_historical_reports(run, [node])[0]["outcome"] == (
        "expected_mapped_failure"
    )

    unbound = replay_check.classify_historical_reports(
        run,
        [node],
        {node: {"bound": False, "reasons": ["mapped_literal_missing"], "failure": None}},
    )
    assert unbound[0]["outcome"] == "wrong_assertion"
    assert "mapped_literal_missing" in unbound[0]["detail"]

    absent = replay_check.classify_historical_reports(run, [node], {})
    assert absent[0]["outcome"] == "wrong_assertion"
    assert "no_evidence" in absent[0]["detail"]

    bound = replay_check.classify_historical_reports(
        run,
        [node],
        {node: {"bound": True, "reasons": [], "failure": {"file": "f.py", "line": 7}}},
    )
    assert bound[0]["outcome"] == "expected_mapped_failure"
    assert bound[0]["failure"] == {"file": "f.py", "line": 7}


# ---------------------------------------------------------------------------
# Bound failure evidence
# ---------------------------------------------------------------------------

_QUARANTINE_NODE = (
    "tests/systemic/test_auth_systemic_catalog.py"
    "::test_focused_chart_response_contract[hourly-empty]"
)


def _quarantine_anchors() -> list[dict]:
    """The checked-in C cookie mapping, anchored against the real detector AST."""
    cases = replay_check.load_cases(CASES)
    transformation = next(
        item
        for family in cases["families"]
        for item in family["transformations"]
        if item["mutation_label"] == "replay-C-invalid-200-quarantine"
    )
    return replay_check.mapped_assertion_anchors(ROOT, transformation)


def _assert_line(source: str, needle: str) -> int:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            segment = ast.get_source_segment(source, node) or ""
            if needle in segment:
                return node.lineno
    raise AssertionError(f"no assertion contains {needle!r}")


def _observation(
    anchor: dict,
    *,
    line: int | None = None,
    message: str,
    phase: str = "call",
    outcome: str = "failed",
) -> dict:
    """A junit-shaped observation as `_parse_junit_report` would return it."""
    location = anchor["locations"][0]
    reported = location["lineno"] if line is None else line
    return {
        "status": "ok",
        "returncode": 1,
        "cases": [
            {
                "nodeid": _QUARANTINE_NODE,
                "outcome": outcome,
                "phase": phase,
                "message": message,
                "text": f"{location['file']}:{reported}: AssertionError",
                "frames": [(location["file"], reported)],
            }
        ],
    }


def test_binding_rejects_the_reviewers_unrelated_assertion_kill() -> None:
    """(a) a kill at ``hourly_records == []`` is not the cookie proof it claims."""
    anchors = _quarantine_anchors()
    assert anchors[0]["assertion"] == "invalid chart changed physical cookies"
    assert anchors[0]["locations"]
    unrelated = _assert_line(SYSTEMIC_CATALOG.read_text(), 'result["hourly_records"] == []')
    assert unrelated != anchors[0]["lineno"]

    binding = replay_check.bind_mutant_failure(
        _observation(
            anchors[0],
            line=unrelated,
            message="AssertionError: \nassert [] == []",
        ),
        anchors,
    )
    assert binding["bound"] is False
    assert "failure_location_unmapped" in binding["reasons"]
    assert binding["failure"]["line"] == unrelated


def test_binding_rejects_a_kill_with_another_mappings_message() -> None:
    """(b) the mapped line firing with ``untyped parser cause`` is not proof."""
    anchors = _quarantine_anchors()
    binding = replay_check.bind_mutant_failure(
        _observation(
            anchors[0],
            message="AssertionError: untyped parser cause: AttributeError('list')",
        ),
        anchors,
    )
    assert binding["bound"] is False
    assert "mapped_literal_missing" in binding["reasons"]
    assert binding["matched_reaches"] == []


def test_binding_accepts_the_mapped_cookie_failure() -> None:
    """The real cookie assertion, at its own line and message, is the proof."""
    anchors = _quarantine_anchors()
    binding = replay_check.bind_mutant_failure(
        _observation(
            anchors[0],
            message=(
                "AssertionError: invalid chart changed physical cookies\n"
                "assert [{'name': 'MM_AuxUtil'}] == []"
            ),
        ),
        anchors,
    )
    assert binding["bound"] is True
    assert binding["reasons"] == []
    assert binding["matched_reaches"] == ["invalid_200_quarantined"]
    assert binding["failure"]["file"] == anchors[0]["locations"][0]["file"]
    assert binding["failure"]["line"] == anchors[0]["lineno"]


@pytest.mark.parametrize(
    ("observation_kwargs", "reason"),
    [
        ({"phase": "setup_or_teardown"}, "failure_not_in_call_phase"),
        ({"message": "ValueError: bad shape"}, "failure_not_an_assertion_error"),
        ({"message": "TypeError: 'list' object has no attribute 'get'"},
         "failure_not_an_assertion_error"),
    ],
)
def test_binding_requires_a_call_phase_assertion(
    observation_kwargs: dict, reason: str
) -> None:
    """Only an AssertionError in the call phase can prove a mapped reach."""
    anchors = _quarantine_anchors()
    kwargs = {
        "message": "AssertionError: invalid chart changed physical cookies",
        **observation_kwargs,
    }
    binding = replay_check.bind_mutant_failure(_observation(anchors[0], **kwargs), anchors)
    assert binding["bound"] is False
    assert reason in binding["reasons"]


def test_binding_refuses_absent_or_unusable_evidence() -> None:
    """A timeout, missing report or passing run is never a bound proof."""
    anchors = _quarantine_anchors()
    for observation, reason in (
        ({"status": "timeout", "cases": []}, "observation_timeout"),
        ({"status": "no_report", "cases": []}, "observation_no_report"),
        (None, "observation_missing"),
        (
            _observation(
                anchors[0],
                message="AssertionError: invalid chart changed physical cookies",
                outcome="passed",
            ),
            "no_failing_test_case",
        ),
    ):
        binding = replay_check.bind_mutant_failure(observation, anchors)
        assert binding["bound"] is False
        assert reason in binding["reasons"]
        assert binding["failure"] is None or binding["failure"]["bound"] is False


@pytest.mark.parametrize("raising_kind", ["helper", "later_assert"])
def test_binding_credits_only_the_actual_raising_statement(raising_kind: str) -> None:
    """A mapped caller or an earlier assertion cannot donate its location."""
    anchors = _quarantine_anchors()
    observation = _observation(
        anchors[0], message="AssertionError: invalid chart changed physical cookies"
    )
    caller = observation["cases"][0]["frames"][0]
    raised = ("tests/support/unrelated.py", 1300) if raising_kind == "helper" else (
        caller[0], caller[1] + 1
    )
    observation["cases"][0]["frames"] = [
        caller, raised, ("/venv/pluggy/_callers.py", 121),
        ("/venv/_pytest/assertion/rewrite.py", 10),
    ]
    binding = replay_check.bind_mutant_failure(observation, anchors)
    assert binding["bound"] is False
    assert binding["reasons"] == ["failure_location_unmapped"]
    assert (binding["failure"]["file"], binding["failure"]["line"]) == raised
    # Explicitly mapping the helper's own statement is valid.
    anchors[0]["locations"] = [{"file": raised[0], "lineno": raised[1], "end_lineno": raised[1]}]
    assert replay_check.bind_mutant_failure(observation, anchors)["bound"] is True


@pytest.mark.parametrize("imported", [False, True])
def test_ambiguous_literal_is_refused_before_any_trial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, imported: bool
) -> None:
    """Two matching Assert/Raise spans in the resolved modules are invalid."""
    repo = _synthetic_repo(tmp_path / "repo")
    test = repo / "tests/test_nodes.py"
    duplicate = '\ndef duplicate():\n    raise AssertionError("C root contract")\n'
    if imported:
        (repo / "tests/helpers.py").write_text(duplicate)
        test.write_text("from tests.helpers import duplicate\n" + test.read_text())
        _git(repo, "add", "tests/helpers.py")
    else:
        test.write_text(test.read_text() + duplicate)
    # An explicit span cannot rescue an ambiguous literal either.
    declaration = _write_cases(tmp_path / "cases.json")
    data = json.loads(declaration.read_text())
    data["families"][2]["transformations"][0]["reaches"][0]["statement"] = {
        "file": "tests/test_nodes.py", "lineno": 10, "end_lineno": 10,
    }
    declaration.write_text(json.dumps(data))
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("ambiguous mapping launched a family")
    monkeypatch.setattr(replay_check, "run_family", forbidden)
    code, payload = _run(repo, _write_table(tmp_path / "table.py"),
                         declaration)
    assert code == 2
    assert payload["error"] == "mapped_assertion_ambiguous"
    assert len(payload["locations"]) == 2
    assert payload["families"] == []


def test_junit_frames_are_read_from_the_traceback() -> None:
    """Frame parsing covers pytest's relative and quoted absolute forms."""
    text = (
        "tests/systemic/test_auth_systemic_catalog.py:13: in test_x\n"
        '  File "/tmp/copy/tests/support/boundaries.py", line 1044, in check\n'
        "tests/support/boundaries.py:1044: AssertionError\n"
    )
    assert replay_check._failure_frames(text) == [
        ("tests/systemic/test_auth_systemic_catalog.py", 13),
        ("/tmp/copy/tests/support/boundaries.py", 1044),
        ("tests/support/boundaries.py", 1044),
    ]
    assert replay_check._same_file("/tmp/copy/tests/support/boundaries.py",
                                   "tests/support/boundaries.py")


def test_historical_classification_separates_expected_from_harness() -> None:
    """Assertion failures are mapped evidence; import/shape errors are not."""
    nodes = ["a", "b", "c"]
    run = {
        "status": "ok",
        "collect_errors": [],
        "reports": [
            {"nodeid": "a", "when": "call", "outcome": "failed", "is_assertion": True,
             "exc_type": "AssertionError"},
            {"nodeid": "b", "when": "call", "outcome": "passed", "is_assertion": False},
            {"nodeid": "c", "when": "call", "outcome": "failed", "is_assertion": False,
             "exc_type": "AttributeError"},
        ],
    }
    rows = replay_check.classify_historical_reports(run, nodes)
    assert [row["outcome"] for row in rows] == [
        "expected_mapped_failure",
        "no_failure",
        "harness_incompatibility",
    ]

    missing = replay_check.classify_historical_reports(run, ["a", "d"])
    assert missing[-1]["outcome"] == "harness_incompatibility"
    assert "missing_node" in str(missing[-1]["detail"])

    collection = replay_check.classify_historical_reports(
        {"status": "ok", "collect_errors": [{"nodeid": "tests/test_nodes.py"}], "reports": []},
        nodes,
    )
    assert {row["outcome"] for row in collection} == {"harness_incompatibility"}

    timed_out = replay_check.classify_historical_reports({"status": "timeout"}, nodes)
    assert {row["outcome"] for row in timed_out} == {"harness_incompatibility"}


# ---------------------------------------------------------------------------
# Checked-in declaration
# ---------------------------------------------------------------------------


def test_declaration_matches_its_table() -> None:
    """The four families, five transformations, labels and detectors agree."""
    cases = replay_check.load_cases(CASES)
    rows = replay_check.load_replay_rows(TABLE)
    replay_check.cross_check(cases, rows)
    assert [family["family"] for family in cases["families"]] == ["A", "B", "C", "D"]
    assert len(rows) == 5
    by_family = {family["family"]: family for family in cases["families"]}
    for family in cases["families"]:
        assert family["transformations"]
        assert family["invariants"]
        for transformation in family["transformations"]:
            assert transformation["expect"] == "assertion_failure"
            assert transformation["reaches"]
            for reach in transformation["reaches"]:
                assert reach["reach"] and reach["assertion"]
    assert len(by_family["C"]["transformations"]) == 2
    historical = cases["historical"]
    assert historical["reviewed_manifests"] == []
    assert "3eca1d2e" in historical["freeze_label"]
    assert "2285845" in historical["substitute_commit_refused"]


def test_family_rows_reuse_the_reviewed_transformations() -> None:
    """Every replay replacement is byte-equal to its named preserved source row."""
    source = runpy.run_path(str(SYSTEMIC_TABLE), run_name="__auth_systemic_source__")
    source_rows = {
        row[0]: row for row in (*source["ORIGINAL_MUTATIONS"], *source["NEW_MUTATIONS"])
    }
    replay = runpy.run_path(str(TABLE), run_name="__auth_replay_table__")
    replay_rows = {row["label"]: row for row in replay_check.load_replay_rows(TABLE)}
    assert len(replay["FAMILIES"]) == 5
    assert {family["family"] for family in replay["FAMILIES"]} == {"A", "B", "C", "D"}
    for family in replay["FAMILIES"]:
        original = source_rows[family["source_row"]]
        row = replay_rows[family["label"]]
        assert row["filename"] == original[1]
        befores = (original[2],) if isinstance(original[2], str) else tuple(original[2])
        afters = (original[3],) if isinstance(original[3], str) else tuple(original[3])
        assert row["befores"] == befores
        assert row["afters"] == afters


def test_every_declared_reach_anchors_to_a_detector_assertion() -> None:
    """Each reach names a literal that exists in the detector's own test evidence."""
    cases = replay_check.load_cases(CASES)
    replay_check.cross_check(cases, replay_check.load_replay_rows(TABLE))
    for family in cases["families"]:
        for transformation in family["transformations"]:
            anchors = replay_check.mapped_assertion_anchors(ROOT, transformation)
            assert [item["reach"] for item in anchors] == [
                reach["reach"] for reach in transformation["reaches"]
            ]
            for item in anchors:
                assert item["anchor"], (family["family"], item)
                assert item["anchor"].split("/", 1)[0] == "tests"
                # Binding needs the exact statement span, not just the file.
                assert len(item["locations"]) == 1, (family["family"], item)
                assert item["locations"][0]["file"] == item["anchor"]
                for location in item["locations"]:
                    assert location["file"].startswith("tests/")
                    assert 1 <= location["lineno"] <= location["end_lineno"]
                assert item["lineno"] == item["locations"][0]["lineno"]
                assert item["end_lineno"] == item["locations"][0]["end_lineno"]


def test_c_proves_both_the_typed_root_and_the_cookie_half() -> None:
    """C's two transformations map to the two C contacts, with their own assertions."""
    cases = replay_check.load_cases(CASES)
    by_family = {family["family"]: family for family in cases["families"]}
    root_half, cookie_half = by_family["C"]["transformations"]
    assert root_half["mutation_label"] == "replay-C-invalid-200-root-validation"
    assert root_half["source_row"] == "37-hourly-root-dict-validation"
    assert root_half["detector_nodes"] == [
        "tests/systemic/test_auth_systemic_catalog.py"
        "::test_focused_chart_response_contract[hourly-root]"
    ]
    assert root_half["reaches"] == [
        {"reach": "root_200_typed_failure", "assertion": "untyped parser cause"}
    ]
    assert cookie_half["mutation_label"] == "replay-C-invalid-200-quarantine"
    assert cookie_half["source_row"] == "36-hourly-records-validation-before-confirm"
    assert cookie_half["detector_nodes"] == [
        "tests/systemic/test_auth_systemic_catalog.py"
        "::test_focused_chart_response_contract[hourly-empty]"
    ]
    assert cookie_half["reaches"] == [
        {
            "reach": "invalid_200_quarantined",
            "assertion": "invalid chart changed physical cookies",
        }
    ]
    catalog = ast.parse(SYSTEMIC_CATALOG.read_text())
    chart_cases = next(
        node
        for node in catalog.body
        if isinstance(node, ast.Assign)
        and any(getattr(target, "id", "") == "CHART_CASES" for target in node.targets)
    )
    declared = ast.literal_eval(chart_cases.value)
    assert ("hourly", "root") in declared
    assert ("hourly", "empty") in declared
    focused = next(
        node
        for node in catalog.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "test_focused_chart_response_contract"
    )
    focused_source = ast.get_source_segment(SYSTEMIC_CATALOG.read_text(), focused)
    # The cookie half must be a physical-jar assertion, not merely a typed error.
    assert "driver.entry.data[\"cookies\"] == prior" in focused_source
    assert "invalid chart changed physical cookies" in focused_source


def _detector_case_id(node: str) -> str:
    return node.rsplit("[", 1)[1][:-1]


def test_family_detectors_observe_the_declared_public_contract() -> None:
    """A/B/C/D detectors are the named systemic nodes with the required reach."""
    cases = replay_check.load_cases(CASES)
    by_family = {family["family"]: family for family in cases["families"]}

    def reaches(family: str) -> set[str]:
        return {
            reach["reach"]
            for transformation in by_family[family]["transformations"]
            for reach in transformation["reaches"]
        }

    a_node = by_family["A"]["transformations"][0]["detector_nodes"][0]
    assert a_node.startswith(
        "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative["
    )
    dispatch_case = next(
        case for case in DISPATCH_FAST_CASES if case.case_id == _detector_case_id(a_node)
    )
    assert dispatch_case.case_id == "fast_stage_transition_handoff"
    assert dispatch_case.flow == "R"
    assert dispatch_case.transition == "handoff"
    assert {"redirect_and_chartdata_hops", "retired_generation"} <= reaches("A")

    b_node = by_family["B"]["transformations"][0]["detector_nodes"][0]
    assert b_node.endswith(
        "tests/systemic/test_response_corpus.py"
        "::test_post_proof_poison_is_caught_only_by_the_follow_on"
    )
    b_case = next(
        case for case in RESPONSE_CASES if case.case_id == "mandatory:post-proof-poison-only-follow-on"
    )
    assert b_case.family == "ha"
    assert b_case.position == Position.POST_PROOF
    assert b_case.cookie == "aux"
    assert b_case.cookie_name == "MM_AuxUtil"
    assert {"second_poll", "cold_restart"} <= reaches("B")
    from tests.support.lifecycle import CaseResult

    ending_source = inspect.getsource(CaseResult.assert_complete)
    for step in ("ending_poll_1", "ending_poll_2", "ending_cold_restart", "ending_poll_3"):
        assert step in ending_source

    assert {reach["reach"] for reach in by_family["C"]["transformations"][1]["reaches"]} == {
        "invalid_200_quarantined"
    }

    d_node = by_family["D"]["transformations"][0]["detector_nodes"][0]
    assert d_node.startswith(
        "tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control["
    )
    exit_case = next(
        case for case in EXIT_FAST_CASES if case.case_id == _detector_case_id(d_node)
    )
    assert exit_case.case_id == (
        "after:fetch_energy_data::stop::no-renewal::MM_RememberMe"
    )
    assert exit_case.transition == "stop"
    assert exit_case.boundary.phase == "after"
    assert exit_case.boundary.name == "fetch_energy_data"
    assert {"two_eligible_checkpoints", "latest_pair_at_exit"} <= reaches("D")


def test_replay_findings_link_back_to_their_family() -> None:
    """Each family names existing findings whose registry entry links it back."""
    cases = replay_check.load_cases(CASES)
    findings = {finding["id"]: finding for finding in FINDINGS}
    for family in cases["families"]:
        assert family["findings"]
        for finding_id in family["findings"]:
            assert finding_id in findings
            assert family["family"] in findings[finding_id]["replay_families"]


def test_replay_links_are_bidirectional() -> None:
    """Every family-to-finding link has the reverse registry link, and no orphans."""
    cases = replay_check.load_cases(CASES)
    by_family = {family["family"]: family for family in cases["families"]}
    declared = {
        (family["family"], finding_id)
        for family in cases["families"]
        for finding_id in family["findings"]
    }
    registered = {
        (family, finding["id"])
        for finding in FINDINGS
        for family in finding.get("replay_families", ())
    }
    assert declared == registered
    for family, finding_id in registered:
        assert family in by_family, (family, finding_id)
        assert finding_id in by_family[family]["findings"], (family, finding_id)


# ---------------------------------------------------------------------------
# Historical input refusals (before execution)
# ---------------------------------------------------------------------------


def test_missing_historical_input_is_not_performed() -> None:
    """No --snapshot is an explicit non-claim, never an empty historical RED."""
    historical = replay_check.validate_historical(None, [])
    assert historical["status"] == "not_performed"
    assert historical["reason"] == "no_historical_input"
    assert historical["claim"] == "mutant_fallback_only"


def test_2285845_substitute_is_refused_by_code() -> None:
    """The rejected substitute commit and its tree digest are denied in code."""
    with pytest.raises(replay_check.ReplayRefusal) as digest_error:
        replay_check.refuse_substitute(
            {"sha256": replay_check.REFUSED_SUBSTITUTE_TREE_DIGEST, "head": "a" * 40}
        )
    assert digest_error.value.code == "historical_substitute_refused"
    assert digest_error.value.context["commit"] == replay_check.REFUSED_SUBSTITUTE_COMMIT

    for head in ("2285845d61c67454200e2b504231f910fdea7bef", "2285845" + "0" * 33):
        with pytest.raises(replay_check.ReplayRefusal) as head_error:
            replay_check.refuse_substitute({"sha256": "b" * 64, "head": head})
        assert head_error.value.code == "historical_substitute_refused"

    replay_check.refuse_substitute({"sha256": "b" * 64, "head": "c" * 40})


def test_2285845_tree_digest_is_current() -> None:
    """The denied digest is declared with the same tree aggregate as the code."""
    cases = replay_check.load_cases(CASES)
    historical = cases["historical"]
    assert historical["substitute_tree_digest_refused"] == (
        replay_check.REFUSED_SUBSTITUTE_TREE_DIGEST
    )
    assert historical["substitute_commit_refused"] == (
        replay_check.REFUSED_SUBSTITUTE_COMMIT
    )
    assert (
        replay_check.REFUSED_SUBSTITUTE_SHORT
        == replay_check.REFUSED_SUBSTITUTE_COMMIT[:7]
    )


def test_unreviewed_historical_digest_is_refused_before_execution(
    tmp_path: Path,
) -> None:
    """A verified manifest that no review has pinned is refused, nothing runs."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    cases = _write_cases(tmp_path / "cases.json")
    historical = tmp_path / "historical"
    snapshot(source=repo, dest=historical)
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(historical)))
    assert code == 2
    assert payload["error"] == "historical_digest_not_reviewed"
    assert payload["families"] == []
    assert payload["families_total"] == 0
    assert payload["claim"] == "no_replay_performed"


def test_2285845_digest_is_refused_even_when_reviewed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Adding the substitute digest to reviewed_manifests still refuses it."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    historical = tmp_path / "historical"
    manifest = snapshot(source=repo, dest=historical)
    monkeypatch.setattr(
        replay_check, "REFUSED_SUBSTITUTE_TREE_DIGEST", manifest["sha256"]
    )
    cases = _write_cases(
        tmp_path / "cases.json",
        reviewed=[{"label": "2285845-substitute", "digest": manifest["sha256"]}],
    )
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(historical)))
    assert code == 2
    assert payload["error"] == "historical_substitute_refused"
    assert payload["families"] == []
    assert payload["families_total"] == 0


def test_2285845_head_is_refused_even_when_reviewed(tmp_path: Path) -> None:
    """A manifest recording the rejected head is refused before execution."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    historical = tmp_path / "historical"
    manifest = snapshot(source=repo, dest=historical)
    manifest_path = historical / "snapshot-manifest.json"
    document = json.loads(manifest_path.read_text())
    document["head"] = replay_check.REFUSED_SUBSTITUTE_COMMIT
    manifest_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    cases = _write_cases(
        tmp_path / "cases.json",
        reviewed=[{"label": "2285845-head", "digest": manifest["sha256"]}],
    )
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(historical)))
    assert code == 2
    assert payload["error"] == "historical_substitute_refused"
    assert payload["families"] == []


def test_malformed_historical_input_is_refused_before_execution(tmp_path: Path) -> None:
    """A directory without a snapshot manifest cannot be authenticated."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    cases = _write_cases(tmp_path / "cases.json")
    not_a_snapshot = tmp_path / "not-a-snapshot"
    not_a_snapshot.mkdir()
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(not_a_snapshot)))
    assert code == 2
    assert payload["error"] == "historical_input_invalid"
    assert payload["families"] == []


def test_tampered_historical_bytes_are_refused_before_execution(tmp_path: Path) -> None:
    """Changing a byte after the manifest was written breaks authentication."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    cases = _write_cases(tmp_path / "cases.json")
    historical = tmp_path / "historical"
    snapshot(source=repo, dest=historical)
    (historical / "custom_components/pseg/guard.py").write_text(
        "A_FENCE = 'tampered'\n", encoding="utf-8"
    )
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(historical)))
    assert code == 2
    assert payload["error"] == "historical_manifest_mismatch"
    assert payload["families"] == []


# ---------------------------------------------------------------------------
# Real engine contrasts in a synthetic repository (slow)
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_valid_contrast_without_historical_input_is_proved(tmp_path: Path) -> None:
    """All four controls GREEN, all four mapped assertions RED, replay absent."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    cases = _write_cases(tmp_path / "cases.json")
    code, payload = _run(repo, table, cases)
    assert code == 0
    assert payload["proved"] == 4
    assert payload["failed"] == 0
    assert payload["invalid"] == 0
    assert payload["claim"] == "mutant_fallback_only"
    assert payload["historical"]["status"] == "not_performed"
    for family in payload["families"]:
        assert family["control"] == "passed"
        assert family["mutant"] == "detected"
        assert family["verdict"] == "proved"
        assert family["assertion"] == "mapped call-phase assertion failure"
        for transformation in family["transformations"]:
            assert transformation["verdict"] == "proved"
            assert transformation["assertion"] == "mapped call-phase assertion failure"
            assert transformation["mapped_assertions"]
            # Every proved member reports the failure location and message it bound.
            failure = transformation["failure"]
            assert failure["file"].startswith("tests/")
            assert failure["line"] > 0
            assert failure["message"]
            assert transformation["detail"]["binding"]["bound"] is True
    assert payload["wrong_assertion"] == 0


@pytest.mark.slow
def test_surviving_family_is_a_failure_not_a_proof(tmp_path: Path) -> None:
    """A no-op B mutation leaves the family alive; replay exits nonzero."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py", noop="B")
    cases = _write_cases(tmp_path / "cases.json")
    code, payload = _run(repo, table, cases)
    assert code == 1
    assert payload["proved"] == 3
    assert payload["failed"] == 1
    family = next(item for item in payload["families"] if item["family"] == "B")
    assert family["mutant"] != "detected"
    assert family["verdict"] == "failed"


@pytest.mark.slow
def test_kill_at_an_unmapped_assertion_is_not_proved(tmp_path: Path) -> None:
    """A kill outside the mapped assert/raise is wrong_assertion, never proof."""
    repo = _synthetic_repo(tmp_path / "repo")
    # C dies at its *tail* assertion while the declaration maps the root literal:
    # the exact shape of the reviewer's remapped-detector negative.
    table = _write_table(tmp_path / "table.py", mutate_tail="C")
    cases = _write_cases(tmp_path / "cases.json")
    code, payload = _run(repo, table, cases)
    assert code == 1
    assert payload["proved"] == 3
    assert payload["wrong_assertion"] == 1
    assert payload["failed"] == 0
    family = next(item for item in payload["families"] if item["family"] == "C")
    assert family["mutant"] == "detected"
    assert family["verdict"] == "wrong_assertion"
    transformation = family["transformations"][0]
    assert transformation["verdict"] == "wrong_assertion"
    assert transformation["assertion"] == ""
    assert "failure_location_unmapped" in transformation["detail"]["binding"]["reasons"]
    assert transformation["failure"]["file"] == "tests/test_nodes.py"
    assert transformation["failure"]["message"].startswith("AssertionError: C tail contract")


@pytest.mark.slow
def test_kill_with_another_literals_message_is_not_proved(tmp_path: Path) -> None:
    """A mapped location whose message lacks the mapped literal is not proof."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    # The literal sits in the failing assert's *expression* (the old check's
    # only requirement) but never in its failure message.
    cases = _write_cases(tmp_path / "cases.json", literal_overrides={"C": "guard.C_ROOT"})
    code, payload = _run(repo, table, cases)
    assert code == 1
    assert payload["proved"] == 3
    assert payload["wrong_assertion"] == 1
    family = next(item for item in payload["families"] if item["family"] == "C")
    assert family["mutant"] == "detected"
    assert family["verdict"] == "wrong_assertion"
    transformation = family["transformations"][0]
    assert "mapped_literal_missing" in transformation["detail"]["binding"]["reasons"]
    assert "guard.C_ROOT" not in transformation["failure"]["message"]
    assert "C root contract" in transformation["failure"]["message"]


@pytest.mark.slow
@pytest.mark.parametrize("historical_path", [False, True])
def test_helper_failure_cannot_borrow_the_mapped_callers_span(
    tmp_path: Path, historical_path: bool
) -> None:
    """R3: healthy mapped property, unrelated helper RED, on both paths."""
    repo = _synthetic_repo(tmp_path / "repo")
    test = repo / "tests/test_nodes.py"
    test.write_text(test.read_text().replace(
        'assert guard.C_ROOT == "root", "C root contract"',
        'assert unrelated_check() and guard.C_ROOT == "root", "C root contract"',
    ) + '\n\ndef unrelated_check():\n'
        '    assert guard.C_ROOT == "root"  # mapped property is healthy\n'
        '    assert guard.C_TAIL == "tail", "C root " + "contract: unrelated helper"\n'
        '    return True\n')
    extra = ()
    reviewed = None
    if historical_path:
        old = _synthetic_repo(tmp_path / "old")
        production = old / "custom_components/pseg/guard.py"
        production.write_text(production.read_text().replace('C_TAIL = "tail"', 'C_TAIL = "stale"'))
        historical = tmp_path / "historical-snapshot"
        manifest = snapshot(source=old, dest=historical)
        reviewed = [{"label": "helper-negative", "digest": manifest["sha256"]}]
        extra = ("--snapshot", str(historical))
    code, payload = _run(
        repo, _write_table(tmp_path / "table.py", mutate_tail="C"),
        _write_cases(tmp_path / "cases.json", reviewed=reviewed), extra=extra,
    )
    assert code == (2 if historical_path else 1)
    family = next(item for item in payload["families"] if item["family"] == "C")
    assert family["verdict"] == "wrong_assertion"
    failure = family["transformations"][0]["failure"]
    assert failure["line"] == _assert_line(test.read_text(), 'guard.C_TAIL == "tail", "C root "')
    assert failure["bound"] is False
    if historical_path:
        assert payload["historical"]["status"] == "wrong_assertion"
        assert payload["historical"]["expected_mapped_failures"] == 0
        assert payload["historical"]["wrong_assertion"] == 1


@pytest.mark.slow
def test_import_error_is_invalid_never_a_historic_red(tmp_path: Path) -> None:
    """An import failure is INVALID, never counted as a mapped assertion RED."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py", import_error="C")
    cases = _write_cases(tmp_path / "cases.json")
    code, payload = _run(repo, table, cases)
    assert code == 2
    family = next(item for item in payload["families"] if item["family"] == "C")
    assert family["control"] == "passed"
    assert family["verdict"] == "invalid"
    assert payload["invalid"] == 1
    assert payload["proved"] == 3


@pytest.mark.slow
def test_unverified_mapped_assertion_is_invalid(tmp_path: Path) -> None:
    """A reach whose assertion literal is absent from the evidence is never proved."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    cases = _write_cases(tmp_path / "cases.json", assertion_override="no such assertion")
    code, payload = _run(repo, table, cases)
    assert code == 2
    assert payload["invalid"] == 4
    family = next(item for item in payload["families"] if item["family"] == "C")
    transformation = family["transformations"][0]
    assert transformation["control"] == "not_run"
    assert transformation["verdict"] == "invalid"
    assert transformation["detail"]["reason"] == "mapped_assertion_unverified"


@pytest.mark.slow
def test_reviewed_historical_all_pass_is_no_contrast(tmp_path: Path) -> None:
    """A reviewed manifest whose detectors all pass proves nothing historical."""
    repo = _synthetic_repo(tmp_path / "repo")
    table = _write_table(tmp_path / "table.py")
    historical = tmp_path / "historical"
    manifest = snapshot(source=repo, dest=historical)
    cases = _write_cases(
        tmp_path / "cases.json",
        reviewed=[
            {
                "label": "synthetic-p1",
                "digest": manifest["sha256"],
                "note": "test fixture standing in for a reviewed P1 manifest",
            }
        ],
    )
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(historical)))
    assert code == 0
    assert payload["proved"] == 4
    assert payload["historical"]["status"] == "no_historical_contrast"
    assert payload["historical"]["claim"] == "mutant_fallback_only"
    assert payload["historical"]["verified_production_files"] > 0
    assert payload["historical"]["harness_incompatibility"] == 0
    assert payload["historical"]["expected_mapped_failures"] == 0
    assert payload["historical"]["unexpected_passes"] == 4
    assert payload["claim"] == "mutant_fallback_only"


@pytest.mark.slow
def test_reviewed_historical_incompatible_is_not_a_historical_claim(
    tmp_path: Path,
) -> None:
    """Historical production that cannot import is incompatible, never a claim."""
    repo = _synthetic_repo(tmp_path / "repo")
    broken = _synthetic_repo(tmp_path / "broken")
    (broken / "custom_components/pseg/guard.py").write_text(
        "A_FENCE = (\n", encoding="utf-8"
    )
    _git(broken, "add", ".")
    _git(
        broken,
        "-c", "user.name=Replay Test", "-c", "user.email=replay@example.com",
        "commit", "-m", "broken historical production",
    )
    historical = tmp_path / "historical"
    manifest = snapshot(source=broken, dest=historical)
    table = _write_table(tmp_path / "table.py")
    cases = _write_cases(
        tmp_path / "cases.json",
        reviewed=[{"label": "synthetic-broken", "digest": manifest["sha256"]}],
    )
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(historical)))
    assert code == 2
    assert payload["proved"] == 4
    assert payload["historical"]["status"] == "incompatible"
    assert payload["historical"]["claim"] == "mutant_fallback_only"
    assert payload["historical"]["harness_incompatibility"] == 4
    assert payload["historical"]["expected_mapped_failures"] == 0
    assert payload["claim"] == "mutant_fallback_only"


@pytest.mark.slow
def test_reviewed_historical_mapped_failure_is_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Historical production that fails at the mapped assertion is a real RED."""
    # Count actual subprocess entry points, including historical observation.
    runs: list[tuple[str, int]] = []
    engine_run = replay_check.engine.run_pytest_in_copy
    evidence_run = replay_check._run_pytest_junit
    def engine_spy(*args: object, **kwargs: object) -> dict:
        runs.append(("engine", int(kwargs["timeout"])))
        return engine_run(*args, **kwargs)
    def evidence_spy(python: str, root: Path, nodes: list[str], timeout: int, scratch: Path) -> dict:
        runs.append(("evidence", timeout))
        return evidence_run(python, root, nodes, timeout, scratch)
    monkeypatch.setattr(replay_check.engine, "run_pytest_in_copy", engine_spy)
    monkeypatch.setattr(replay_check, "_run_pytest_junit", evidence_spy)
    repo = _synthetic_repo(tmp_path / "repo")
    historical_repo = _synthetic_repo(tmp_path / "historical")
    (historical_repo / "custom_components/pseg/guard.py").write_text(
        'A_FENCE = "fence"\nB_POISON = "poison"\nC_ROOT = "stale"\nC_TAIL = "tail"\n'
        'D_CHECKPOINT = "checkpoint"\n',
        encoding="utf-8",
    )
    _git(historical_repo, "add", ".")
    _git(
        historical_repo,
        "-c", "user.name=Replay Test", "-c", "user.email=replay@example.com",
        "commit", "-m", "historical C_ROOT drift",
    )
    historical = tmp_path / "historical-snapshot"
    manifest = snapshot(source=historical_repo, dest=historical)
    table = _write_table(tmp_path / "table.py")
    cases = _write_cases(
        tmp_path / "cases.json",
        reviewed=[{"label": "synthetic-historical", "digest": manifest["sha256"]}],
    )
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(historical)))
    transformations = len(_SYNTHETIC_FAMILIES)
    assert len(runs) == transformations * 3 + 2
    assert sum(kind == "engine" for kind, _ in runs) == transformations * 2 + 1
    assert sum(kind == "evidence" for kind, _ in runs) == transformations + 1
    assert code == 0
    assert payload["proved"] == 4
    record = payload["historical"]
    assert record["status"] == "performed"
    assert record["expected_mapped_failures"] == 1
    assert record["unexpected_passes"] == 3
    assert record["wrong_assertion"] == 0
    assert payload["claim"] == "mutant_fallback_and_historical_input"
    detector = next(item for item in record["detectors"] if item["node"].endswith("test_c_root"))
    assert detector["outcome"] == "expected_mapped_failure"
    assert detector["failure"]["file"] == "tests/test_nodes.py"
    assert "C root contract" in detector["failure"]["message"]


@pytest.mark.slow
def test_reviewed_historical_unbound_failure_is_not_a_historical_claim(
    tmp_path: Path,
) -> None:
    """Historical production dying at another assertion proves no historical RED."""
    repo = _synthetic_repo(tmp_path / "repo")
    historical_repo = _synthetic_repo(tmp_path / "historical")
    (historical_repo / "custom_components/pseg/guard.py").write_text(
        'A_FENCE = "fence"\nB_POISON = "poison"\nC_ROOT = "root"\nC_TAIL = "stale"\n'
        'D_CHECKPOINT = "checkpoint"\n',
        encoding="utf-8",
    )
    _git(historical_repo, "add", ".")
    _git(
        historical_repo,
        "-c", "user.name=Replay Test", "-c", "user.email=replay@example.com",
        "commit", "-m", "historical C_TAIL drift",
    )
    historical = tmp_path / "historical-snapshot"
    manifest = snapshot(source=historical_repo, dest=historical)
    table = _write_table(tmp_path / "table.py")
    cases = _write_cases(
        tmp_path / "cases.json",
        reviewed=[{"label": "synthetic-historical-tail", "digest": manifest["sha256"]}],
    )
    code, payload = _run(repo, table, cases, extra=("--snapshot", str(historical)))
    assert code == 2
    assert payload["proved"] == 4
    record = payload["historical"]
    assert record["status"] == "wrong_assertion"
    assert record["expected_mapped_failures"] == 0
    assert record["wrong_assertion"] == 1
    assert record["claim"] == "mutant_fallback_only"
    assert payload["claim"] == "mutant_fallback_only"
    detector = next(item for item in record["detectors"] if item["node"].endswith("test_c_root"))
    assert detector["outcome"] == "wrong_assertion"
    assert "failure_location_unmapped" in detector["detail"]


# ---------------------------------------------------------------------------
# Synthetic repository helpers
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )


def _synthetic_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\npythonpath = [".", "tests"]\n'
        'asyncio_mode = "auto"\nasyncio_default_fixture_loop_scope = "function"\n'
        "timeout = 60\n",
        encoding="utf-8",
    )
    package = path / "custom_components" / "pseg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "guard.py").write_text(
        'A_FENCE = "fence"\nB_POISON = "poison"\nC_ROOT = "root"\nC_TAIL = "tail"\n'
        'D_CHECKPOINT = "checkpoint"\n',
        encoding="utf-8",
    )
    tests = path / "tests"
    tests.mkdir()
    (tests / "test_nodes.py").write_text(
        "from custom_components.pseg import guard\n\n"
        "def test_a_fence():\n"
        '    assert guard.A_FENCE == "fence", "A contract literal"\n\n'
        "def test_b_poison():\n"
        '    assert guard.B_POISON == "poison", "B contract literal"\n\n'
        "def test_c_root():\n"
        '    assert guard.C_ROOT == "root", "C root contract"\n'
        '    assert guard.C_TAIL == "tail", "C tail contract"\n\n'
        "def test_d_checkpoint():\n"
        '    assert guard.D_CHECKPOINT == "checkpoint", "D contract literal"\n',
        encoding="utf-8",
    )
    for args in (
        ("init", "-b", "main"),
        ("add", "."),
        ("-c", "user.name=Replay Test", "-c", "user.email=replay@example.com",
         "commit", "-m", "synthetic replay fixture"),
    ):
        _git(path, *args)
    return path


_SYNTHETIC_LITERALS = {
    "A": "A contract literal",
    "B": "B contract literal",
    "C": "C root contract",
    "D": "D contract literal",
}


def _write_table(
    path: Path,
    *,
    noop: str | None = None,
    import_error: str | None = None,
    mutate_tail: str | None = None,
) -> Path:
    rows = []
    for family, constant, value, label, node in _SYNTHETIC_FAMILIES:
        target = constant
        if mutate_tail == family:
            # Kill an assertion that is *not* the declared mapping's literal:
            # the reviewer's "remapped detector" shape.
            target, value = "C_TAIL", "tail"
        before = f'{target} = "{value}"'
        after = f'{target} = "mutated"'
        if noop == family:
            after = before
        if import_error == family:
            after = f'{before}\nimport replay_proof_missing_module'
        rows.append(
            "    {\n"
            f"        'label': {label!r},\n"
            f"        'filename': 'guard.py',\n"
            f"        'before': {before!r},\n"
            f"        'after': {after!r},\n"
            f"        'test': [{node!r}],\n"
            "    },"
        )
    path.write_text("MUTATIONS = [\n" + "\n".join(rows) + "\n]\n", encoding="utf-8")
    return path


def _write_cases(
    path: Path,
    *,
    reviewed: list[dict[str, str]] | None = None,
    assertion_override: str | None = None,
    literal_overrides: dict[str, str] | None = None,
) -> Path:
    families = [
        {
            "family": family,
            "title": f"synthetic family {family}",
            "invariants": ["I1"],
            "findings": [],
            "transformations": [
                {
                    "mutation_label": label,
                    "filename": "guard.py",
                    "source_row": f"synthetic-{family}",
                    "detector_nodes": [node],
                    "reaches": [
                        {
                            "reach": "synthetic_reach",
                            "assertion": assertion_override
                            or (literal_overrides or {}).get(family)
                            or _SYNTHETIC_LITERALS[family],
                        }
                    ],
                    "expect": "assertion_failure",
                }
            ],
        }
        for family, _constant, _value, label, node in _SYNTHETIC_FAMILIES
    ]
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "tool": "replay_check",
                "description": "synthetic replay fixture",
                "historical": {
                    "status": "synthetic",
                    "reason": "fixture",
                    "reviewed_manifests": reviewed or [],
                },
                "families": families,
            }
        ),
        encoding="utf-8",
    )
    return path


def _run(
    repo: Path,
    table: Path,
    cases: Path,
    *,
    extra: tuple[str, ...] = (),
) -> tuple[int, dict]:
    out = io.StringIO()
    err = io.StringIO()
    argv = [
        "--source", str(repo),
        "--python", _TEST_PYTHON,
        "--table", str(table),
        "--cases", str(cases),
        "--timeout", "60",
        "--json",
        *extra,
    ]
    with redirect_stdout(out), redirect_stderr(err):
        code = replay_check.main(argv)
    lines = [line for line in out.getvalue().splitlines() if line.startswith("{")]
    assert lines, f"no structured replay report; stderr={err.getvalue()}"
    return code, json.loads(lines[-1])

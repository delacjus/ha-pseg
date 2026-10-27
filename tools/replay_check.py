#!/usr/bin/env python3
"""A/B/C/D family replay proof for the reserved ``replay`` profile (P2-11).

Why this tool exists
--------------------
The reviewed R4 dirty-freeze bytes (``3eca1d2e...``) were not recovered in P1, so
an exact historical replay cannot be claimed. The required fallback is four
independently detected family faults:

* A - per-hop / ChartData dispatch fence (I1);
* B - two-poll cookie poison, observable only through the shared follow-on (I3);
* C - invalid-200 / root validation (I10), proved by two transformations: the
  typed-root half and the invalid-200-never-confirms half;
* D - latest exit checkpoint on the stop path (I5).

A run proves a *contrast*: every family's detector node must pass on the fixed
source (control GREEN) and fail with its mapped call-phase assertion on exactly
one family fault (mutant RED). A family with several transformations is proved
only when *all* of them are detected. Each declared reach names the assertion
literal that proves it, and the declaration is refused unless that literal occurs
in an ``assert``/``raise`` of the mapped detector test or of a test module it
imports. A detection alone is not proof: the mutant's own failure evidence is
re-read from a ``--junitxml`` run of the mapped node in the mutated copy, and a
member is ``proved`` only when that failure is a call-phase ``AssertionError``
whose innermost non-framework traceback frame is inside the mapped assert/raise (file and line range
from the AST) *and* whose message contains the mapped message literal. Source
selectors must be unambiguous; helper mappings name the reviewed statement span. Any other kill is
``wrong_assertion``: neither proved nor survived, so replay exits non-zero.
Exit 0 means every family contrast was both detected and bound to its mapping.

Optional ``--snapshot PATH`` accepts only a snapshot directory whose
``snapshot-manifest.json`` validates *and* whose aggregate is listed in the
reviewed declaration. The run then applies the current tests to the preserved
historical production bytes and separates expected mapped failures from harness
incompatibility. Commit ``2285845`` (the rejected dirty-freeze substitute) is
refused by digest and by recorded head before execution, even if someone adds
that digest to ``reviewed_manifests``. With no historical input the report says
``not_performed``; the mutant fallback still has to pass. A historical run that
only passes, or that only hits harness incompatibility, proves nothing
historical and says so instead of claiming a verified replay.

This is not a second mutation engine: family trials call
:mod:`tools.mutation_check` for the baseline and the mutant, and the historical
run reuses its pytest reporter. The bound-failure evidence is the only extra
pytest invocation per detected mutant (one junit report per transformation).
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import py_compile
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ElementTree

# Protect direct invocations without -B before importing local helpers.
sys.dont_write_bytecode = True

_TOOLS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TOOLS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools import mutation_check as engine  # noqa: E402
from tools._snapshot import (  # noqa: E402
    MANIFEST_NAME,
    SnapshotError,
    freeze,
    load_manifest,
    snapshot,
)

TOOL = "replay_check"
VERSION = 2
FAMILY_IDS = ("A", "B", "C", "D")
DEFAULT_TABLE = "tests/mutations/auth_replay.py"
DEFAULT_CASES = "tests/systemic/replay_cases.json"
_REQUIRED_OUTCOME = "assertion_failure"

# Commit 2285845 was explicitly ruled out as a substitute for the unrecovered
# dirty R4 freeze. Both the commit and the aggregate of its ``git archive`` tree
# (recomputed through tools/_snapshot.py freeze: 59 files) are refused in code,
# independently of the reviewed-manifest declaration.
REFUSED_SUBSTITUTE_COMMIT = "2285845d61c67454200e2b504231f910fdea7bef"
REFUSED_SUBSTITUTE_SHORT = REFUSED_SUBSTITUTE_COMMIT[:7]
REFUSED_SUBSTITUTE_TREE_DIGEST = (
    "ec22013d910c74b866cb9d0114b7145741e8aab7b4479ed0c4dc88d660cb306a"
)


class ReplayRefusal(Exception):
    """A declaration or historical-input refusal, before any family executes."""

    def __init__(self, code: str, **context: object) -> None:
        super().__init__(code)
        self.code = code
        self.context = dict(context)


# ---------------------------------------------------------------------------
# Declaration
# ---------------------------------------------------------------------------


def iter_transformations(cases: dict[str, object]) -> list[dict[str, object]]:
    """Flatten the declaration into its ordered per-transformation entries."""
    return [
        transformation
        for entry in cases["families"]
        for transformation in entry["transformations"]
    ]


def load_cases(path: str | Path) -> dict[str, object]:
    """Load and validate the family declaration (exact four family families)."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise ReplayRefusal("cases_unreadable", path=str(path), detail=str(err)) from None
    if not isinstance(document, dict):
        raise ReplayRefusal("cases_invalid", reason="root_not_object")

    families = document.get("families")
    if not isinstance(families, list) or len(families) != len(FAMILY_IDS):
        raise ReplayRefusal("cases_invalid", reason="family_count")
    seen: set[str] = set()
    seen_labels: set[str] = set()
    for entry in families:
        if not isinstance(entry, dict):
            raise ReplayRefusal("cases_invalid", reason="family_not_object")
        family = entry.get("family")
        if family not in FAMILY_IDS or family in seen:
            raise ReplayRefusal("cases_invalid", reason="family_id", family=family)
        seen.add(family)
        if not isinstance(entry.get("title"), str) or not entry["title"].strip():
            raise ReplayRefusal("cases_invalid", reason="title", family=family)
        invariants = entry.get("invariants")
        if not isinstance(invariants, list) or not invariants or any(
            invariant not in {f"I{index}" for index in range(1, 13)} for invariant in invariants
        ):
            raise ReplayRefusal("cases_invalid", reason="invariants", family=family)
        if not isinstance(entry.get("findings"), list):
            raise ReplayRefusal("cases_invalid", reason="findings", family=family)
        transformations = entry.get("transformations")
        if not isinstance(transformations, list) or not transformations:
            raise ReplayRefusal("cases_invalid", reason="transformations", family=family)
        for transformation in transformations:
            if not isinstance(transformation, dict):
                raise ReplayRefusal(
                    "cases_invalid", reason="transformation_not_object", family=family
                )
            label = transformation.get("mutation_label")
            if not isinstance(label, str) or not label or label in seen_labels:
                raise ReplayRefusal(
                    "cases_invalid", reason="mutation_label", family=family
                )
            seen_labels.add(label)
            for key in ("filename", "source_row"):
                if (
                    not isinstance(transformation.get(key), str)
                    or not transformation[key].strip()
                ):
                    raise ReplayRefusal("cases_invalid", reason=key, family=family)
            nodes = transformation.get("detector_nodes")
            if not isinstance(nodes, list) or not nodes or not all(
                isinstance(node, str) and "::" in node for node in nodes
            ):
                raise ReplayRefusal(
                    "cases_invalid", reason="detector_nodes", family=family
                )
            reaches = transformation.get("reaches")
            if not isinstance(reaches, list) or not reaches:
                raise ReplayRefusal("cases_invalid", reason="reaches", family=family)
            for reach in reaches:
                if (
                    not isinstance(reach, dict)
                    or not isinstance(reach.get("reach"), str)
                    or not reach["reach"].strip()
                    or not isinstance(reach.get("assertion"), str)
                    or not reach["assertion"].strip()
                ):
                    raise ReplayRefusal(
                        "cases_invalid", reason="reach_mapping", family=family
                    )
                if "message" in reach and (
                    not isinstance(reach["message"], str) or not reach["message"].strip()
                ):
                    raise ReplayRefusal("cases_invalid", reason="reach_message", family=family)
            if transformation.get("expect") != _REQUIRED_OUTCOME:
                raise ReplayRefusal("cases_invalid", reason="expect", family=family)
    if seen != set(FAMILY_IDS):
        raise ReplayRefusal("cases_invalid", reason="family_set", families=sorted(seen))

    historical = document.get("historical")
    if not isinstance(historical, dict):
        raise ReplayRefusal("cases_invalid", reason="historical")
    reviewed = historical.get("reviewed_manifests", [])
    if not isinstance(reviewed, list):
        raise ReplayRefusal("cases_invalid", reason="reviewed_manifests")
    for entry in reviewed:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("digest"), str)
            or not isinstance(entry.get("label"), str)
        ):
            raise ReplayRefusal("cases_invalid", reason="reviewed_manifest_entry")
    return document


def load_replay_rows(table: str | Path) -> list[dict[str, object]]:
    """Load the family table through the shared mutation engine."""
    try:
        return engine.load_table(Path(table))
    except engine.MutationSpecError as err:
        raise ReplayRefusal("table_invalid", detail=str(err)) from None


def cross_check(cases: dict[str, object], rows: list[dict[str, object]]) -> None:
    """Refuse a declaration that drifted from its own table."""
    by_label = {str(row["label"]): row for row in rows}
    declared = {str(item["mutation_label"]) for item in iter_transformations(cases)}
    if len(rows) != len(declared) or set(by_label) != declared:
        raise ReplayRefusal(
            "cases_table_mismatch",
            reason="label_set",
            declared=sorted(declared),
            table=sorted(by_label),
        )
    for entry in cases["families"]:
        for transformation in entry["transformations"]:
            row = by_label[str(transformation["mutation_label"])]
            if row["filename"] != transformation["filename"]:
                raise ReplayRefusal(
                    "cases_table_mismatch",
                    reason="filename",
                    family=entry["family"],
                    declared=transformation["filename"],
                    table=row["filename"],
                )
            if list(row["test_nodes"]) != list(transformation["detector_nodes"]):
                raise ReplayRefusal(
                    "cases_table_mismatch",
                    reason="detector_nodes",
                    family=entry["family"],
                )


def _test_module_path(root: Path, dotted: str) -> Path | None:
    """Resolve one ``tests.*`` module name inside the candidate source tree."""
    relative = Path(*dotted.split("."))
    for candidate in (root / (relative.as_posix() + ".py"), root / relative / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _direct_test_modules(root: Path, path: Path) -> list[Path]:
    """Resolved ``tests.*`` modules imported directly by one test module."""
    if path.suffix != ".py" or not path.is_file():
        return []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    found: list[Path] = []
    for item in ast.walk(tree):
        if not isinstance(item, ast.ImportFrom) or not item.module:
            continue
        bases = [item.module, *(f"{item.module}.{a.name}" for a in item.names)]
        for base in bases:
            if base.split(".")[0] != "tests":
                continue
            resolved = _test_module_path(root, base)
            if resolved is not None and resolved not in found:
                found.append(resolved)
    return found


def _detector_test_modules(root: Path, nodes: list[str]) -> list[Path]:
    """Detector modules in evidence order: own file, direct imports, then deeper."""
    order: list[Path] = []

    def add(path: Path) -> None:
        if path not in order and path.is_file() and path.suffix == ".py":
            order.append(path)

    for node in nodes:
        add(root / node.partition("::")[0])
    index = 0
    while index < len(order):
        for child in _direct_test_modules(root, order[index]):
            add(child)
        index += 1
    return order


def _test_assertion_locations(root: Path, path: Path) -> list[dict[str, object]]:
    """Every ``assert``/``raise`` in one test module, with its line span."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text)
    except (OSError, SyntaxError):
        return []
    locations: list[dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assert, ast.Raise)):
            continue
        segment = ast.get_source_segment(text, node)
        if not segment:
            continue
        locations.append(
            {
                "file": path.relative_to(root).as_posix(),
                "text": segment,
                "lineno": node.lineno,
                "end_lineno": node.end_lineno or node.lineno,
            }
        )
    return locations


def mapped_assertion_anchors(
    source: str | Path, transformation: dict[str, object]
) -> list[dict[str, object]]:
    """Anchor every declared reach to the assertion literal the detector proves.

    The literal must occur in an assertion/raise statement of the detector node's
    own test module or of a test module that module imports, so a declared reach
    cannot borrow an unrelated assertion's kill (or a docstring mention). Each
    anchor carries the file and line span of one unambiguous statement: the
    later bound-failure check requires the actual raising frame inside that
    span. Multiple matching statements are refused before execution, even when
    an explicit ``statement`` span is supplied. ``message`` optionally names the
    rendered-message literal when the source selector contains f-string syntax.
    Helper mappings also declare their reviewed file/line span via ``statement``.
    ``anchor``/``lineno``/``end_lineno`` describe the unique match and are
    ``None`` when the literal was not found there at all.
    """
    root = Path(source)
    modules = _detector_test_modules(
        root, [str(node) for node in transformation["detector_nodes"]]
    )
    locations: list[dict[str, object]] = []
    for path in modules:
        locations.extend(_test_assertion_locations(root, path))
    anchors: list[dict[str, object]] = []
    for reach in transformation["reaches"]:  # type: ignore[union-attr]
        assertion = str(reach["assertion"])
        matches = [item for item in locations if assertion in str(item["text"])]
        if len(matches) > 1:
            raise ReplayRefusal(
                "mapped_assertion_ambiguous",
                assertion=assertion,
                locations=[{key: item[key] for key in ("file", "lineno", "end_lineno")}
                           for item in matches],
            )
        first = matches[0] if matches else None
        statement = reach.get("statement")
        if statement is not None and (
            first is None or statement != {key: first[key] for key in ("file", "lineno", "end_lineno")}
        ):
            raise ReplayRefusal("mapped_statement_mismatch", assertion=assertion, statement=statement)
        anchors.append(
            {
                "reach": str(reach["reach"]),
                "assertion": assertion,
                "message": str(reach.get("message", assertion)),
                "anchor": first["file"] if first else None,
                "lineno": first["lineno"] if first else None,
                "end_lineno": first["end_lineno"] if first else None,
                "locations": [
                    {
                        "file": item["file"],
                        "lineno": item["lineno"],
                        "end_lineno": item["end_lineno"],
                    }
                    for item in matches
                ],
            }
        )
    return anchors


# ---------------------------------------------------------------------------
# Bound failure evidence
# ---------------------------------------------------------------------------

# Traceback frames as pytest's longrepr prints them: ``path.py:LINE: ...`` at
# column zero (the ``File "...", line N`` form covers non-pytest tracebacks).
_FRAME_LINE = re.compile(r"^(?P<path>[^\s].*?\.py):(?P<line>\d+):", re.MULTILINE)
_FRAME_FILE = re.compile(r'File "(?P<path>[^"]+\.py)", line (?P<line>\d+)')
_ASSERTION_MESSAGE = re.compile(r"^(?:pytest\.fail\.)?(?:Failed|AssertionError)\b|^assert\b")
_TRAILING_LOCATION = re.compile(r"^(?P<path>[^\s].*?\.py):(?P<line>\d+):\s*$", re.MULTILINE)


def _display_path(path: str) -> str:
    """Normalize a traceback path for comparison with a root-relative anchor."""
    cleaned = path.replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _same_file(path: str, anchor: str) -> bool:
    shown = _display_path(path)
    return shown == anchor or shown.endswith("/" + anchor)


def _failure_frames(text: str) -> list[tuple[str, int]]:
    """Every ``(path, line)`` frame pytest printed for one failure."""
    # Preserve textual order even when pytest and Python frame formats mix.
    matches = sorted(
        [*_FRAME_LINE.finditer(text), *_FRAME_FILE.finditer(text)],
        key=lambda match: match.start(),
    )
    return [(match.group("path"), int(match.group("line"))) for match in matches]


def _raising_frame(frames: list[tuple[str, int]]) -> tuple[str, int] | None:
    """Innermost test/helper frame, after pytest/pluggy/rewrite internals."""
    for path, line in reversed(frames):
        parts = _display_path(path).split("/")
        if any(part in {"_pytest", "pytest", "pluggy"} for part in parts):
            continue
        return path, line
    return None


def _is_assertion_failure(case: dict[str, object]) -> bool:
    """A call-phase failure of the assertion family (``pytest.fail`` included)."""
    message = str(case.get("message") or "").lstrip()
    return bool(_ASSERTION_MESSAGE.match(message))


def _parse_junit_report(path: Path) -> list[dict[str, object]]:
    """Decode one pytest ``--junitxml`` report into per-test-case records."""
    try:
        root = ElementTree.parse(path).getroot()
    except (ElementTree.ParseError, OSError):
        return []
    cases: list[dict[str, object]] = []
    for case in root.iter("testcase"):
        classname = case.get("classname") or ""
        name = case.get("name") or ""
        nodeid = (
            f"{classname.replace('.', '/')}.py::{name}" if classname else name
        )
        record: dict[str, object] = {
            "nodeid": nodeid,
            "outcome": "passed",
            "phase": "call",
            "message": "",
            "text": "",
            "frames": [],
        }
        for child in case:
            if child.tag in ("failure", "error"):
                record["outcome"] = "failed"
                # pytest writes <failure> for a call failure and <error> for a
                # setup/teardown failure.
                record["phase"] = "call" if child.tag == "failure" else "setup_or_teardown"
                record["message"] = child.get("message") or ""
                record["text"] = child.text or ""
                record["frames"] = _failure_frames(record["text"])
                break
            if child.tag == "skipped":
                record["outcome"] = "skipped"
                break
        cases.append(record)
    return cases


def _run_pytest_junit(
    python: str | Path,
    root: Path,
    test_nodes: list[str],
    timeout: int,
    scratch: Path,
) -> dict[str, object]:
    """Run the given nodes in ``root`` and return the structured junit failure."""
    report = scratch / "junit.xml"
    basetemp = scratch / "basetemp"
    basetemp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["RUFF_NO_CACHE"] = "true"
    command = [
        str(python),
        "-B",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        f"--basetemp={basetemp}",
        "-q",
        f"--junitxml={report}",
        *test_nodes,
    ]
    timed_out = False
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(
            command,
            cwd=str(root),
            env=env,
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    if timed_out:
        return {"status": "timeout", "returncode": -1, "cases": []}
    if not report.is_file():
        return {"status": "no_report", "returncode": process.returncode, "cases": []}
    return {"status": "ok", "returncode": process.returncode, "cases": _parse_junit_report(report)}


def observe_detectors(
    root: str | Path, python: str | Path, test_nodes: list[str], timeout: int
) -> dict[str, object]:
    """Run the mapped nodes as they are, keeping their junit failure evidence."""
    scratch = Path(tempfile.mkdtemp(prefix="pseg-replay-observe-", dir="/tmp"))
    try:
        return _run_pytest_junit(python, Path(root), test_nodes, timeout, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def run_mutant_observation(
    source: str | Path,
    python: str | Path,
    row: dict[str, object],
    timeout: int,
) -> dict[str, object]:
    """Mutate a disposable copy, run the mapped node and keep its own evidence."""
    scratch = Path(tempfile.mkdtemp(prefix="pseg-replay-mutant-evidence-", dir="/tmp"))
    copy_dir = scratch / "source"
    try:
        snapshot(source=Path(source), dest=copy_dir)
        target = engine.resolve_target_path(copy_dir, str(row["filename"]))
        original = target.read_text(encoding="utf-8")
        mutated = engine.apply_mutation(
            original,
            tuple(row["befores"]),  # type: ignore[arg-type]
            tuple(row["afters"]),  # type: ignore[arg-type]
            str(row["label"]),
        )
        target.write_text(mutated, encoding="utf-8")
        py_compile.compile(str(target), doraise=True)
        return _run_pytest_junit(
            python,
            copy_dir,
            [str(node) for node in row["test_nodes"]],  # type: ignore[union-attr]
            timeout,
            scratch,
        )
    except engine.MutationSpecError as err:
        return {"status": "spec_error", "detail": str(err), "cases": []}
    except SnapshotError as err:
        return {"status": "snapshot_error", "detail": err.code, "cases": []}
    except py_compile.PyCompileError as err:
        return {"status": "syntax_error", "detail": str(err), "cases": []}
    except Exception as err:  # noqa: BLE001 - evidence failure is never a proof
        return {"status": "error", "detail": str(err), "cases": []}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _unique(items: list[str]) -> list[str]:
    ordered: list[str] = []
    for item in items:
        if item not in ordered:
            ordered.append(item)
    return ordered


def bind_mutant_failure(
    observation: dict[str, object] | None,
    anchors: list[dict[str, object]],
) -> dict[str, object]:
    """Bind an observed mutant kill to the mapped assertion, or refuse it.

    All of these are required before a detection counts as mapped proof:

    (i) the failing case is a call-phase ``AssertionError`` (a setup/teardown
    error or another exception type is no proof);
    (ii) the innermost non-framework frame lies inside the ``assert``/``raise`` that
    carries the mapped literal, using the file and line range recorded from the
    detector's AST;
    (iii) the mapped message literal appears in the failure message (defaults
    to the assertion source literal). A unique source selector can distinguish
    assertions whose rendered messages share wording, without weakening (ii).

    Every failing case must satisfy all three. Returns
    ``{"bound": bool, "reasons": [...], "failure": {...}}``; a refusal names every
    unmet condition, and ``failure`` always shows the observed location and
    message so the report cannot hide where the kill really happened.
    """
    if observation is None or observation.get("status") != "ok":
        status = "missing" if observation is None else str(observation.get("status"))
        return {"bound": False, "reasons": [f"observation_{status}"], "failure": None}
    cases = [case for case in observation.get("cases") or [] if isinstance(case, dict)]
    failures = [case for case in cases if case.get("outcome") == "failed"]
    if not failures:
        return {"bound": False, "reasons": ["no_failing_test_case"], "failure": None}

    reasons: list[str] = []
    matched_reaches: list[str] = []
    observed: dict[str, object] | None = None
    for case in failures:
        frames = list(case.get("frames") or [])
        raising = _raising_frame(frames)
        message = str(case.get("message") or "")[:4096]
        case_reasons: list[str] = []
        if case.get("phase") != "call":
            case_reasons.append("failure_not_in_call_phase")
        if not _is_assertion_failure(case):
            case_reasons.append("failure_not_an_assertion_error")
        inside_frames: list[tuple[str, int]] = []
        literal_missing = False
        for anchor in anchors:
            literal = str(anchor.get("message", anchor.get("assertion")) or "")
            for location in anchor.get("locations") or []:
                inside = [
                    (path, line)
                    for path, line in ([raising] if raising else [])
                    if _same_file(path, str(location["file"]))
                    and int(location["lineno"]) <= line <= int(location["end_lineno"])
                ]
                if not inside:
                    continue
                inside_frames.extend(inside)
                if literal and literal in message:
                    if str(anchor.get("reach")) not in matched_reaches:
                        matched_reaches.append(str(anchor.get("reach")))
                else:
                    literal_missing = True
        if literal_missing:
            case_reasons.append("mapped_literal_missing")
        if not inside_frames:
            case_reasons.append("failure_location_unmapped")
        reasons.extend(case_reasons)
        if observed is None:
            location = raising
            observed = {
                "node": case.get("nodeid"),
                "file": location[0] if location else None,
                "line": location[1] if location else None,
                "message": message,
                "bound": not case_reasons,
            }
    reasons = _unique(reasons)
    return {
        "bound": not reasons,
        "reasons": reasons,
        "failure": observed,
        "matched_reaches": matched_reaches,
    }



def _node_matches(node: str, selector: str) -> bool:
    """Exact node id, or one case of a parametrized parent selector."""
    return node == selector or node.startswith(selector + "[")


def bind_node_failure(
    observation: dict[str, object] | None,
    node: str,
    anchors: list[dict[str, object]],
) -> dict[str, object]:
    """Bind one declared detector node's failure, ignoring unrelated cases."""
    if observation is None or observation.get("status") != "ok":
        return bind_mutant_failure(observation, anchors)
    cases = [case for case in observation.get("cases") or [] if isinstance(case, dict)]
    selected = [case for case in cases if _node_matches(str(case.get("nodeid")), node)]
    narrowed = dict(observation)
    narrowed["cases"] = selected or cases
    return bind_mutant_failure(narrowed, anchors)



# ---------------------------------------------------------------------------
# Family contrast
# ---------------------------------------------------------------------------


def classify_family(control: str, mutant: str, bound: bool = False) -> str:
    """Classify one transformation contrast from control, mutant and binding.

    A detected mutant is ``proved`` only when its observed failure is bound to
    the mapped assertion; otherwise it is ``wrong_assertion`` - the fault was
    detected, but not where the declaration says it must be.
    """
    if control != "passed":
        return "invalid"
    if mutant == "detected":
        return "proved" if bound else "wrong_assertion"
    if mutant == "survived":
        return "failed"
    return "invalid"


def classify_family_members(verdicts: list[str]) -> str:
    """A multi-transformation family is proved only when all members are proved."""
    if any(verdict == "invalid" for verdict in verdicts):
        return "invalid"
    if any(verdict == "wrong_assertion" for verdict in verdicts):
        return "wrong_assertion"
    if any(verdict == "failed" for verdict in verdicts):
        return "failed"
    if verdicts and all(verdict == "proved" for verdict in verdicts):
        return "proved"
    return "invalid"


def run_transformation(
    source: str | Path,
    python: str | Path,
    table: str | Path,
    family_id: str,
    transformation: dict[str, object],
    timeout: int,
) -> dict[str, object]:
    """Run one control + mutant contrast and bind the mutant's own failure."""
    started = time.monotonic()
    result: dict[str, object] = {
        "family": family_id,
        "mutation_label": transformation["mutation_label"],
        "source_row": transformation["source_row"],
        "filename": transformation["filename"],
        "detector_nodes": list(transformation["detector_nodes"]),
        "reaches": [
            {"reach": reach["reach"], "assertion": reach["assertion"]}
            for reach in transformation["reaches"]
        ],
    }
    anchors = mapped_assertion_anchors(source, transformation)
    unverified = [item for item in anchors if item["anchor"] is None]
    result["mapped_assertions"] = anchors
    if unverified:
        result.update(
            {
                "control": "not_run",
                "mutant": "not_run",
                "assertion": "",
                "verdict": "invalid",
                "detail": {
                    "reason": "mapped_assertion_unverified",
                    "missing": [item["assertion"] for item in unverified],
                },
                "failure": None,
                "engine_exit": 2,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        )
        return result

    code, report = engine.run_mutation_check(
        source=source,
        python=python,
        table=table,
        only=str(transformation["mutation_label"]),
        timeout=timeout,
    )

    control = "not_run"
    mutant = "not_run"
    detail: dict[str, object] = {}
    binding: dict[str, object] | None = None
    if report.get("outcome") == "baseline_failed":
        control = "failed"
        detail = {"reason": "baseline_failed", "error": report.get("error")}
    elif report.get("mutations"):
        control = "passed"
        trial = report["mutations"][0]
        mutant = str(trial.get("outcome", "invalid"))
        detail = dict(trial.get("details") or {})
        if mutant == "detected":
            # The engine only reports that *an* assertion failed; re-read the
            # mutant's own junit failure and bind it to the declared assertion.
            rows = {
                str(row["label"]): row for row in engine.load_table(Path(table))
            }
            observation = run_mutant_observation(
                source, python, rows[str(transformation["mutation_label"])], timeout
            )
            binding = bind_mutant_failure(observation, anchors)
            detail = {
                **detail,
                "binding": {
                    "bound": binding["bound"],
                    "reasons": binding["reasons"],
                    "failure": binding["failure"],
                },
            }
    else:
        detail = {"reason": "engine_error", "error": report.get("error")}
    verdict = classify_family(control, mutant, bool(binding and binding["bound"]))
    result.update(
        {
            "control": control,
            "mutant": mutant,
            "assertion": (
                "mapped call-phase assertion failure" if verdict == "proved" else ""
            ),
            "verdict": verdict,
            "detail": detail,
            "failure": binding["failure"] if binding else None,
            "engine_exit": code,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    )
    return result


def run_family(
    source: str | Path,
    python: str | Path,
    table: str | Path,
    family: dict[str, object],
    timeout: int,
) -> dict[str, object]:
    """Run every declared transformation of one family and aggregate the verdict."""
    started = time.monotonic()
    transformations = [
        run_transformation(source, python, table, str(family["family"]), item, timeout)
        for item in family["transformations"]
    ]
    verdict = classify_family_members([str(item["verdict"]) for item in transformations])
    reaches: list[str] = []
    for item in transformations:
        for reach in item["reaches"]:
            name = str(reach["reach"])
            if name not in reaches:
                reaches.append(name)
    detected = [item["mutant"] == "detected" for item in transformations]
    return {
        "family": family["family"],
        "title": family["title"],
        "invariants": list(family["invariants"]),
        "findings": list(family["findings"]),
        "reaches": reaches,
        "transformations": transformations,
        "control": (
            "passed"
            if all(item["control"] == "passed" for item in transformations)
            else "failed"
        ),
        "mutant": "detected" if all(detected) else "not_detected",
        "assertion": "mapped call-phase assertion failure" if verdict == "proved" else "",
        "verdict": verdict,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


# ---------------------------------------------------------------------------
# Optional historical input
# ---------------------------------------------------------------------------


def refuse_substitute(frozen: dict[str, object]) -> None:
    """Refuse commit 2285845 by tree digest or recorded head, before execution."""
    digest = str(frozen.get("sha256", "")).lower()
    head = str(frozen.get("head", "")).lower()
    if digest == REFUSED_SUBSTITUTE_TREE_DIGEST or head.startswith(
        REFUSED_SUBSTITUTE_SHORT
    ):
        raise ReplayRefusal(
            "historical_substitute_refused",
            commit=REFUSED_SUBSTITUTE_COMMIT,
            digest=digest,
            head=head,
        )


def validate_historical(
    path: str | None, reviewed: list[dict[str, object]]
) -> dict[str, object]:
    """Accept only a verified, pre-reviewed historical manifest directory.

    Refuses (before any family runs) anything that is not a snapshot directory,
    whose manifest does not describe its own bytes, whose recorded head or tree
    digest is the rejected 2285845 substitute, or whose aggregate is not in the
    reviewed declaration. Missing input is ``not_performed``, never a claim.
    """
    if path is None:
        return {
            "status": "not_performed",
            "reason": "no_historical_input",
            "claim": "mutant_fallback_only",
            "reviewed_manifests": len(reviewed),
        }
    root = Path(path)
    if not root.is_dir():
        raise ReplayRefusal("historical_input_invalid", reason="not_a_directory", path=str(root))
    if not (root / MANIFEST_NAME).is_file():
        raise ReplayRefusal(
            "historical_input_invalid", reason="no_snapshot_manifest", path=str(root)
        )
    try:
        load_manifest(root / MANIFEST_NAME)
    except SnapshotError as err:
        raise ReplayRefusal(
            "historical_input_invalid", reason=err.code, path=str(root)
        ) from None
    try:
        frozen = freeze(source=root)
    except SnapshotError as err:
        raise ReplayRefusal(
            "historical_manifest_mismatch", reason=err.code, path=str(root)
        ) from None
    refuse_substitute(frozen)
    digest = str(frozen["sha256"])
    labels = [str(entry["label"]) for entry in reviewed]
    match = next(
        (entry for entry in reviewed if str(entry["digest"]).lower() == digest),
        None,
    )
    if match is None:
        raise ReplayRefusal(
            "historical_digest_not_reviewed",
            digest=digest,
            reviewed_manifests=labels,
        )
    return {
        "status": "validated",
        "digest": digest,
        "head": frozen["head"],
        "manifest_label": match["label"],
        "claim": "historical_input_verified",
    }


def classify_historical_reports(
    run_result: dict[str, object],
    detector_nodes: list[str],
    evidence: dict[str, dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    """Classify a current-tests-over-historical-production run per detector.

    Expected mapped failure: the detector's own call-phase assertion failed *and*
    its observed failure is bound to the mapped assertion (call-phase
    AssertionError, traceback inside the mapped assert/raise, mapped literal in
    the message). A call-phase assertion that does not bind is
    ``wrong_assertion`` - never a historical RED. Harness incompatibility:
    collection/import/setup/missing-node/timeout or an unexpected exception.

    ``evidence`` maps a node to the binding produced by
    :func:`bind_mutant_failure`; without it the assertion failure is classified
    raw, which the CLI never does.
    """
    results: list[dict[str, object]] = []
    status = run_result.get("status")
    common: dict[str, object] | None = None
    if status != "ok":
        common = {"outcome": "harness_incompatibility", "detail": f"run_status:{status}"}
    elif run_result.get("collect_errors"):
        common = {"outcome": "harness_incompatibility", "detail": "collection_error"}
    if common is not None:
        return [{"node": node, **common} for node in detector_nodes]

    by_node: dict[str, list[dict[str, object]]] = {}
    for report in run_result.get("reports") or []:
        by_node.setdefault(str(report.get("nodeid", "")), []).append(report)

    for node in detector_nodes:
        reports = by_node.get(node)
        if not reports:
            results.append(
                {"node": node, "outcome": "harness_incompatibility", "detail": "missing_node"}
            )
            continue
        if any(
            report.get("when") in ("setup", "teardown") and report.get("outcome") == "failed"
            for report in reports
        ):
            results.append(
                {"node": node, "outcome": "harness_incompatibility", "detail": "setup_or_teardown"}
            )
            continue
        call = next((report for report in reports if report.get("when") == "call"), None)
        if call is None:
            results.append(
                {"node": node, "outcome": "harness_incompatibility", "detail": "no_call_report"}
            )
        elif call.get("outcome") == "passed":
            results.append({"node": node, "outcome": "no_failure", "detail": "passed"})
        elif call.get("outcome") == "failed" and call.get("is_assertion"):
            if evidence is None:
                results.append(
                    {"node": node, "outcome": "expected_mapped_failure", "detail": "assertion"}
                )
                continue
            binding = evidence.get(node) or {
                "bound": False,
                "reasons": ["no_evidence"],
                "failure": None,
            }
            if binding.get("bound"):
                results.append(
                    {
                        "node": node,
                        "outcome": "expected_mapped_failure",
                        "detail": "assertion",
                        "failure": binding.get("failure"),
                    }
                )
            else:
                results.append(
                    {
                        "node": node,
                        "outcome": "wrong_assertion",
                        "detail": ",".join(str(reason) for reason in binding.get("reasons") or []),
                        "failure": binding.get("failure"),
                    }
                )
        else:
            results.append(
                {
                    "node": node,
                    "outcome": "harness_incompatibility",
                    "detail": f"unexpected:{call.get('exc_type')}",
                }
            )
    return results


def historical_verdict(detectors: list[dict[str, object]]) -> dict[str, object]:
    """Historical input proves something only with a bound mapped RED.

    * any harness incompatibility -> ``incompatible``, never a historical claim;
    * any assertion failure that does not bind -> ``wrong_assertion``, never a
      historical claim either;
    * every detector passes -> ``no_historical_contrast`` (nothing was compared);
    * at least one bound mapped failure and nothing incompatible -> performed.
    """
    expected = sum(item.get("outcome") == "expected_mapped_failure" for item in detectors)
    passed = sum(item.get("outcome") == "no_failure" for item in detectors)
    incompatible = sum(item.get("outcome") == "harness_incompatibility" for item in detectors)
    wrong = sum(item.get("outcome") == "wrong_assertion" for item in detectors)
    if incompatible:
        status, claim = "incompatible", "mutant_fallback_only"
    elif wrong:
        status, claim = "wrong_assertion", "mutant_fallback_only"
    elif expected == 0:
        status, claim = "no_historical_contrast", "mutant_fallback_only"
    else:
        status, claim = "performed", "historical_input_verified"
    return {
        "status": status,
        "claim": claim,
        "expected_mapped_failures": expected,
        "unexpected_passes": passed,
        "harness_incompatibility": incompatible,
        "wrong_assertion": wrong,
    }



def run_historical(
    source: str | Path,
    snapshot_root: str | Path,
    python: str | Path,
    detector_nodes: list[str],
    timeout: int,
    anchors_by_node: dict[str, list[dict[str, object]]] | None = None,
) -> dict[str, object]:
    """Apply the current tests to preserved historical production bytes.

    A call-phase assertion failure is only a historical RED after its own junit
    evidence binds to the mapped assert/raise, exactly as for a mutant.
    """
    anchors_by_node = anchors_by_node or {}
    work = Path(tempfile.mkdtemp(prefix="pseg-replay-historical-", dir="/tmp"))
    composite = work / "source"
    keep = False
    try:
        snapshot(source=source, dest=composite)
        manifest = load_manifest(Path(snapshot_root) / MANIFEST_NAME)
        historical_production = Path(snapshot_root) / "custom_components"
        if not historical_production.is_dir():
            raise ReplayRefusal(
                "historical_input_invalid", reason="no_custom_components", path=str(snapshot_root)
            )
        live_production = composite / "custom_components"
        if live_production.exists():
            shutil.rmtree(live_production)
        shutil.copytree(historical_production, live_production)
        # The composite is intentionally not a snapshot: its manifest would
        # describe the current tests, not the overlaid historical production.
        (composite / MANIFEST_NAME).unlink(missing_ok=True)

        verified = 0
        for relative, expected in manifest["paths"]:
            if relative != "custom_components" and not relative.startswith("custom_components/"):
                continue
            target = composite / relative
            if not target.is_file():
                raise ReplayRefusal("historical_manifest_mismatch", path=relative)
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual != expected:
                raise ReplayRefusal("historical_manifest_mismatch", path=relative)
            verified += 1

        run_result = engine.run_pytest_in_copy(
            python_path=str(python),
            snapshot_dir=composite,
            test_nodes=detector_nodes,
            timeout=timeout,
        )
        detectors = classify_historical_reports(run_result, detector_nodes)
        candidates = [
            str(item["node"])
            for item in detectors
            if item.get("outcome") == "expected_mapped_failure"
        ]
        if candidates:
            observation = observe_detectors(composite, python, candidates, timeout)
            evidence = {
                node: bind_node_failure(observation, node, anchors_by_node.get(node, []))
                for node in candidates
            }
            detectors = classify_historical_reports(run_result, detector_nodes, evidence)
        verdict = historical_verdict(detectors)
        keep = verdict["status"] == "incompatible"
        return {
            **verdict,
            "verified_production_files": verified,
            "detectors": detectors,
            "composite": str(composite) if keep else None,
        }
    finally:
        if not keep:
            shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _emit_error(error: str, **context: object) -> int:
    payload = {
        "tool": TOOL,
        "version": VERSION,
        "ok": False,
        "error": error,
        **context,
        "families": [],
        "families_total": 0,
        "proved": 0,
        "failed": 0,
        "invalid": 0,
        "wrong_assertion": 0,
        "claim": "no_replay_performed",
        "exit_code": 2,
    }
    print(json.dumps(payload, sort_keys=True))
    print(f"replay refused: {error}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="replay_check",
        description="A/B/C/D family replay proof (P2-11)",
    )
    parser.add_argument("--source", default=".", help="Fixed candidate source or snapshot")
    parser.add_argument("--python", required=True, help="Interpreter for child detector runs")
    parser.add_argument("--table", default=DEFAULT_TABLE, help="Replay mutation table")
    parser.add_argument("--cases", default=DEFAULT_CASES, help="Family declaration")
    parser.add_argument(
        "--snapshot",
        default=None,
        help="Optional pre-reviewed snapshot-manifest directory of historical production bytes",
    )
    parser.add_argument(
        "--timeout", type=int, default=120, help="Per-detector child bound in seconds"
    )
    parser.add_argument(
        "--json", action="store_true", help="Accepted for runner symmetry; JSON is always emitted"
    )
    args = parser.parse_args(argv)

    try:
        cases = load_cases(args.cases)
        rows = load_replay_rows(args.table)
        cross_check(cases, rows)
        # Resolve every literal before controls, mutants or historical work run.
        for transformation in iter_transformations(cases):
            mapped_assertion_anchors(args.source, transformation)
        reviewed = list(cases["historical"].get("reviewed_manifests") or [])
        historical = validate_historical(args.snapshot, reviewed)
    except ReplayRefusal as err:
        return _emit_error(err.code, **err.context)

    families: list[dict[str, object]] = []
    for family in cases["families"]:
        result = run_family(args.source, args.python, args.table, family, args.timeout)
        families.append(result)
        status = str(result["verdict"]).upper()
        members = ", ".join(
            "{label}={verdict}{where}".format(
                label=item["mutation_label"],
                verdict=str(item["verdict"]).upper(),
                where=(
                    " at {file}:{line}".format(
                        file=(item.get("failure") or {}).get("file"),
                        line=(item.get("failure") or {}).get("line"),
                    )
                    if item.get("failure")
                    else ""
                ),
            )
            for item in result["transformations"]
        )
        print(
            f"{result['family']} {status} (control {result['control']}, "
            f"mutant {result['mutant']}): {members}",
            file=sys.stderr,
        )

    proved = sum(family["verdict"] == "proved" for family in families)
    failed = sum(family["verdict"] == "failed" for family in families)
    invalid = sum(family["verdict"] == "invalid" for family in families)
    wrong = sum(family["verdict"] == "wrong_assertion" for family in families)

    if historical["status"] == "validated":
        anchors_by_node: dict[str, list[dict[str, object]]] = {}
        for transformation in iter_transformations(cases):
            anchors = mapped_assertion_anchors(args.source, transformation)
            for node in transformation["detector_nodes"]:
                anchors_by_node.setdefault(str(node), []).extend(anchors)
        try:
            historical = {
                **historical,
                **run_historical(
                    args.source,
                    args.snapshot,
                    args.python,
                    [
                        node
                        for transformation in iter_transformations(cases)
                        for node in transformation["detector_nodes"]
                    ],
                    args.timeout,
                    anchors_by_node,
                ),
            }
        except ReplayRefusal as err:
            return _emit_error(err.code, historical=historical, **err.context)
        except SnapshotError as err:
            return _emit_error("historical_input_invalid", historical=historical, reason=err.code)

    historical_unproved = historical.get("status") in ("incompatible", "wrong_assertion")
    if historical_unproved or invalid:
        exit_code = 2
    elif failed or wrong:
        exit_code = 1
    else:
        exit_code = 0

    claim = (
        "mutant_fallback_and_historical_input"
        if historical.get("status") == "performed"
        else "mutant_fallback_only"
    )
    payload = {
        "tool": TOOL,
        "version": VERSION,
        "ok": exit_code == 0,
        "claim": claim,
        "families": families,
        "families_total": len(families),
        "proved": proved,
        "failed": failed,
        "invalid": invalid,
        "wrong_assertion": wrong,
        "historical": historical,
        "exit_code": exit_code,
    }
    print(json.dumps(payload, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

"""Generic copy-only mutation testing engine for ha-pseg (P1-10).

Contract:
  --source PATH --python PATH --table FILE [--only LABEL] [--timeout SECONDS] [--json]

Exit codes:
  0: All mutations validly detected (total > 0, 0 survivors, 0 invalid).
  1: One or more mutants survived (and no invalid mutants).
  2: Invalid run (spec error, baseline failed, collection/import error,
     timeout, syntax error, missing/ambiguous preimage, source integrity failed).
     Invalid takes precedence over survivor in a mixed run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import py_compile
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TOOLS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools._snapshot import (  # noqa: E402
    SnapshotError,
    freeze,
    snapshot,
)

_TEXT_LIMIT = 4096
_REPORT_LIMIT = 262144


def _clip(text: str) -> str:
    return text if len(text) <= _TEXT_LIMIT else text[:_TEXT_LIMIT] + " [truncated]"


_REPORTER_CODE = """
import os
import json
import pytest

class MutationReporter:
    def __init__(self):
        self.collect_errors = []
        self.reports = []
        self.overflow = False
        self.budget = 60000

    def record(self, records, data):
        size = len(json.dumps(data))
        if size > self.budget:
            self.overflow = True
            return
        self.budget -= size
        records.append(data)

    def pytest_collectreport(self, report):
        if report.failed:
            self.record(self.collect_errors, {
                "nodeid": report.nodeid,
                "outcome": report.outcome,
                "message": str(report.longrepr)[:4096] + " [truncated if longer]",
            })

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        result = yield
        report = result.get_result()
        exc = call.excinfo.type if call.excinfo else None
        identities = lambda cls: [cls.__qualname__, cls.__module__ + "." + cls.__qualname__]
        crash = getattr(getattr(report, "longrepr", None), "reprcrash", None)
        message = crash.message if crash else (str(report.longrepr) if report.failed else None)
        if message and len(message) > 4096:
            message = message[:4096] + " [truncated]"
        self.record(self.reports, {
            "nodeid": report.nodeid,
            "when": report.when,
            "outcome": report.outcome,
            "wasxfail": hasattr(report, "wasxfail") or bool(item.get_closest_marker("xfail")),
            "crash_message": message,
            "exc_type": exc.__module__ + "." + exc.__qualname__ if exc else None,
            "exc_names": identities(exc) if exc else [],
            "is_assertion": bool(exc and issubclass(exc, (AssertionError, pytest.fail.Exception))),
            "exc_mro": [c.__module__ + "." + c.__qualname__ for c in exc.__mro__] if exc else [],
        })

    def pytest_sessionfinish(self, session, exitstatus):
        with open(os.environ["MUTATION_REPORT_JSON"], "w", encoding="utf-8") as f:
            json.dump({"exitstatus": int(exitstatus), "overflow": self.overflow,
                       "collect_errors": self.collect_errors, "reports": self.reports}, f)

def pytest_configure(config):
    config.pluginmanager.register(MutationReporter(), "mutation_reporter_instance")
"""


class MutationSpecError(Exception):
    """Raised when table spec or target path is invalid."""


class PreimageError(MutationSpecError):
    """Raised when preimage is missing or ambiguous."""


class SourceIntegrityError(Exception):
    """Raised when source directory changes during execution."""


def resolve_target_path(snapshot_root: Path, filename: str) -> Path:
    """Resolve target path strictly within snapshot root.

    Legacy bare filenames resolve strictly under snapshot's custom_components/pseg/.
    Rejects path traversal (..) and all source-root escapes.
    """
    if not filename or not isinstance(filename, str):
        raise MutationSpecError(f"Invalid filename spec: {filename!r}")

    if os.path.isabs(filename):
        raise MutationSpecError(f"Absolute path escape rejected: {filename!r}")

    pure = Path(filename)
    if ".." in pure.parts:
        raise MutationSpecError(f"Directory traversal rejected: {filename!r}")

    snapshot_real = snapshot_root.resolve()
    custom_pseg = snapshot_real / "custom_components" / "pseg"
    if custom_pseg.resolve() != custom_pseg:
        raise MutationSpecError("Symlink integration root rejected")
    target = custom_pseg / pure if len(pure.parts) == 1 else snapshot_real / pure
    if target.is_symlink():
        raise MutationSpecError(f"Symlink target rejected: {filename!r}")
    target_real = target.resolve()
    if not target_real.is_relative_to(custom_pseg):
        raise MutationSpecError(f"Target escapes custom_components/pseg: {filename!r}")

    if not target.exists():
        raise MutationSpecError(f"Target file not found: {filename!r} at {target}")

    if not target.is_file():
        raise MutationSpecError(f"Target is not a regular file: {filename!r}")

    return target


def normalize_row(raw: Any, index: int) -> dict[str, Any]:
    """Normalize row to structured mutant dict."""
    label: str
    filename: str
    before: Any
    after: Any
    test: Any
    expected: Any = None

    if isinstance(raw, dict):
        label = raw.get("label", f"row-{index}")
        filename = raw.get("filename") or raw.get("file", "")
        before = raw.get("before", "")
        after = raw.get("after", "")
        test = raw.get("test") or raw.get("tests") or raw.get("node_ids")
        expected = raw.get("expected") or raw.get("expected_exception")
    elif isinstance(raw, (tuple, list)):
        if len(raw) < 5:
            raise MutationSpecError(f"Row {index} has fewer than 5 items: {len(raw)}")
        label = str(raw[0])
        filename = str(raw[1])
        before = raw[2]
        after = raw[3]
        test = raw[4]
        if len(raw) >= 6:
            expected = raw[5]
    else:
        raise MutationSpecError(f"Row {index} invalid type: {type(raw)}")

    if not label:
        raise MutationSpecError(f"Row {index} missing label")
    if not filename:
        raise MutationSpecError(f"Row {index} ({label}) missing filename")

    befores = (before,) if isinstance(before, str) else tuple(before)
    afters = (after,) if isinstance(after, str) else tuple(after)

    if len(befores) != len(afters):
        raise MutationSpecError(
            f"{label}: before count ({len(befores)}) != after count ({len(afters)})"
        )
    if not befores:
        raise MutationSpecError(f"{label}: empty before/after tuple")

    for b in befores:
        if not isinstance(b, str):
            raise MutationSpecError(f"{label}: before item must be string, got {type(b)}")
    for a in afters:
        if not isinstance(a, str):
            raise MutationSpecError(f"{label}: after item must be string, got {type(a)}")

    if isinstance(test, (list, tuple)):
        test_nodes = [str(t).strip() for t in test if str(t).strip()]
    elif isinstance(test, str):
        test_nodes = [test.strip()] if test.strip() else []
    else:
        raise MutationSpecError(f"{label}: invalid test node spec: {test!r}")

    if not test_nodes:
        raise MutationSpecError(f"{label}: no test nodes specified")

    expected_spec: dict[str, Any] | None = None
    if expected:
        if isinstance(expected, str):
            expected_spec = {"phase": "call", "type": expected.strip()}
        elif isinstance(expected, dict):
            expected_spec = {
                "phase": expected.get("phase", "call"),
                "type": expected.get("type", ""),
            }

    # Replacement hash is sha256 of concatenated replacements
    repl_data = b"\x00".join(a.encode("utf-8") for a in afters)
    replacement_hash = hashlib.sha256(repl_data).hexdigest()

    return {
        "label": label,
        "filename": filename,
        "befores": befores,
        "afters": afters,
        "test_nodes": test_nodes,
        "expected": expected_spec,
        "replacement_hash": replacement_hash,
    }


def load_table(table_path: Path | str) -> list[dict[str, Any]]:
    """Load mutation table from Python or JSON file."""
    path = Path(table_path).resolve()
    if not path.is_file():
        raise MutationSpecError(f"Table file not found: {table_path}")

    rows_raw: Any = None
    if path.suffix == ".json":
        try:
            with open(path, encoding="utf-8") as f:
                rows_raw = json.load(f)
        except Exception as exc:
            raise MutationSpecError(f"Failed to load JSON table: {exc}") from exc
    elif path.suffix == ".py":
        try:
            ns = runpy.run_path(str(path), run_name="__table__")
            rows_raw = ns.get("MUTATIONS") or ns.get("TABLE") or ns.get("ROWS")
        except Exception as exc:
            raise MutationSpecError(f"Failed to load Python table {path}: {exc}") from exc
    else:
        raise MutationSpecError(f"Unsupported table file format: {path.suffix}")

    if not isinstance(rows_raw, (list, tuple)):
        raise MutationSpecError(f"Table must define a list of rows, got {type(rows_raw)}")

    normalized = [normalize_row(r, i) for i, r in enumerate(rows_raw)]
    seen_labels: set[str] = set()
    for row in normalized:
        lbl = row["label"]
        if lbl in seen_labels:
            raise MutationSpecError(f"Duplicate mutation label: {lbl!r}")
        seen_labels.add(lbl)

    return normalized


def apply_mutation(content: str, befores: tuple[str, ...], afters: tuple[str, ...], label: str) -> str:
    """Apply exact unique preimage replacements to text content."""
    mutated = content
    for b, a in zip(befores, afters, strict=True):
        cnt = mutated.count(b)
        if cnt == 0:
            raise PreimageError(f"{label}: preimage not found: {b!r}")
        if cnt > 1:
            raise PreimageError(f"{label}: ambiguous preimage ({cnt} occurrences): {b!r}")
        mutated = mutated.replace(b, a)
    return mutated


def run_pytest_in_copy(
    python_path: str,
    snapshot_dir: Path,
    test_nodes: list[str],
    timeout: int = 35,
) -> dict[str, Any]:
    """Run pytest on test_nodes inside snapshot_dir using structured reporting."""
    scratch_dir = Path(tempfile.mkdtemp(prefix="pseg-py-run-"))
    try:
        plugin_dir = scratch_dir / "plugins"
        plugin_dir.mkdir(parents=True, exist_ok=True)
        (plugin_dir / "mutation_reporter.py").write_text(_REPORTER_CODE, encoding="utf-8")

        report_json = scratch_dir / "report.json"
        basetemp_dir = scratch_dir / "basetemp"
        basetemp_dir.mkdir(parents=True, exist_ok=True)

        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONHASHSEED"] = "0"
        env["RUFF_NO_CACHE"] = "true"
        env["MUTATION_REPORT_JSON"] = str(report_json)
        env["PYTHONPATH"] = f"{plugin_dir}:{env.get('PYTHONPATH', '')}"

        cmd = [
            python_path,
            "-B",
            "-m",
            "pytest",
            "-p",
            "mutation_reporter",
            "-p",
            "no:cacheprovider",
            f"--basetemp={basetemp_dir}",
            "-q",
            *test_nodes,
        ]

        # Files avoid unbounded PIPE/communicate buffering on noisy failures.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(
                cmd, cwd=str(snapshot_dir), env=env, stdout=out, stderr=err,
                start_new_session=True,
            )
            timed_out = False
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                # Also runs on KeyboardInterrupt/SIGTERM and kills grandchildren
                # even when pytest itself has already exited.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            out.seek(0)
            err.seek(0)
            stdout = _clip(out.read(_TEXT_LIMIT + 1).decode("utf-8", errors="replace"))
            stderr = _clip(err.read(_TEXT_LIMIT + 1).decode("utf-8", errors="replace"))

        if timed_out:
            return {
                "status": "timeout",
                "returncode": -1,
                "collect_errors": [],
                "reports": [],
                "stdout": stdout,
                "stderr": stderr,
            }

        if not report_json.exists():
            return {
                "status": "no_report",
                "returncode": proc.returncode,
                "collect_errors": [],
                "reports": [],
                "stdout": stdout,
                "stderr": stderr,
            }

        try:
            with open(report_json, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return {
                "status": "corrupt_report",
                "returncode": proc.returncode,
                "collect_errors": [],
                "reports": [],
                "stdout": stdout,
                "stderr": stderr,
            }

        return {
            "status": "report_overflow" if data.get("overflow") else "ok",
            "returncode": proc.returncode,
            "collect_errors": data.get("collect_errors", []),
            "reports": data.get("reports", []),
            "stdout": stdout,
            "stderr": stderr,
        }
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)


def classify_mutant_outcome(
    run_result: dict[str, Any],
    expected_nodes: list[str],
    expected_exc: dict[str, Any] | None,
) -> tuple[str, dict[str, Any]]:
    """Classify test run into (outcome, details).

    Outcomes:
      'detected': validly detected (call-phase assertion failure or declared typed exception)
      'survived': all expected tests passed
      'invalid': spec/baseline/import/collection/timeout/missing node/unexpected crash
    """
    status = run_result.get("status")
    if status not in ("ok", "no_report", "corrupt_report"):
        return "invalid", {"reason": status or "execution_failed"}

    collect_errors = run_result.get("collect_errors", [])
    if collect_errors:
        return "invalid", {"reason": "collection_error", "errors": collect_errors}

    returncode = run_result.get("returncode", 0)
    reports = run_result.get("reports", [])

    if status in ("no_report", "corrupt_report"):
        if returncode in (4, 5):
            return "invalid", {"reason": "missing_node"}
        return "invalid", {"reason": "execution_failed", "returncode": returncode}

    reports_by_node: dict[str, list[dict[str, Any]]] = {}
    for r in reports:
        node = r.get("nodeid", "")
        reports_by_node.setdefault(node, []).append(r)

    # Check for missing nodes
    for exp in expected_nodes:
        found = False
        for node in reports_by_node:
            if node == exp or node.endswith(exp) or exp.endswith(node):
                found = True
                break
        if not found:
            return "invalid", {"reason": "missing_node", "expected": exp}

    if returncode not in (0, 1):
        return "invalid", {"reason": "execution_failed", "returncode": returncode}

    has_valid_detection = False
    all_passed = True

    for node, rlist in reports_by_node.items():
        if any(r.get("outcome") == "skipped" or r.get("wasxfail") for r in rlist):
            return "invalid", {"reason": "skipped_or_xfail", "nodeid": node}
        # Check setup/teardown errors
        for r in rlist:
            when = r.get("when")
            outcome = r.get("outcome")
            if when in ("setup", "teardown") and outcome == "failed":
                return "invalid", {"reason": f"{when}_error", "nodeid": node, "crash": r.get("crash_message")}

        call_report = next((r for r in rlist if r.get("when") == "call"), None)
        if not call_report:
            return "invalid", {"reason": "no_call_report", "nodeid": node}

        call_outcome = call_report.get("outcome")
        if call_outcome == "passed":
            continue
        elif call_outcome == "failed":
            all_passed = False
            exc_type = call_report.get("exc_type", "")
            crash_msg = call_report.get("crash_message", "") or ""

            is_assertion = call_report.get("is_assertion", False)

            if is_assertion:
                has_valid_detection = True
            elif expected_exc:
                exp_type = expected_exc.get("type", "")
                exp_phase = expected_exc.get("phase", "call")
                if exp_phase == "call" and exp_type and exp_type in call_report.get("exc_names", []):
                    has_valid_detection = True
                else:
                    return "invalid", {
                        "reason": "unexpected_exception",
                        "nodeid": node,
                        "exc_type": exc_type,
                        "expected_type": exp_type,
                        "crash": crash_msg,
                    }
            else:
                return "invalid", {
                    "reason": "unexpected_exception",
                    "nodeid": node,
                    "exc_type": exc_type,
                    "crash": crash_msg,
                }
        else:
            all_passed = False

    if has_valid_detection:
        return "detected", {"reason": "assertion_failure"}

    if all_passed:
        return "survived", {"reason": "all_passed"}

    return "invalid", {"reason": "unclassified_failure"}


def check_baseline(
    python_path: str,
    source_path: Path,
    test_nodes: list[str],
    timeout: int = 35,
) -> tuple[bool, str]:
    """Verify all detector test nodes pass on unmodified baseline in a fresh copy."""
    scratch_dir = Path(tempfile.mkdtemp(prefix="pseg-baseline-"))
    copy_dir = scratch_dir / "source"
    try:
        snapshot(source=source_path, dest=copy_dir)
        res = run_pytest_in_copy(
            python_path=python_path,
            snapshot_dir=copy_dir,
            test_nodes=test_nodes,
            timeout=timeout,
        )

        collect_errors = res.get("collect_errors", [])
        if collect_errors:
            return False, f"Baseline collection error: {collect_errors}"

        reports = res.get("reports", [])
        if res.get("status") != "ok" or res.get("returncode") != 0:
            return False, f"Baseline detector failed: run returncode {res.get('returncode')}: stdout={res.get('stdout')!r} stderr={res.get('stderr')!r}"

        reports_by_node: dict[str, list[dict[str, Any]]] = {}
        for r in reports:
            reports_by_node.setdefault(r.get("nodeid", ""), []).append(r)

        for exp in test_nodes:
            found = False
            for node, rlist in reports_by_node.items():
                if node == exp or node.endswith(exp) or exp.endswith(node):
                    found = True
                    if not any(r.get("when") == "call" for r in rlist):
                        return False, f"Baseline detector failed: {node}: no call phase"
                    for r in rlist:
                        if r.get("outcome") != "passed" or r.get("wasxfail"):
                            return False, f"Baseline detector failed: {node} during {r.get('when')}: {r.get('crash_message')}"
                    break
            if not found:
                return False, f"Baseline detector not found: {exp}"

        return True, "Baseline detectors passed"
    except SnapshotError as exc:
        return False, f"Baseline snapshot error: {exc.code} {exc.context}"
    except Exception as exc:
        return False, f"Baseline exception: {exc}"
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)


def run_mutant_trial(
    python_path: str,
    source_path: Path,
    candidate_hash: str,
    row: dict[str, Any],
    timeout: int = 35,
) -> dict[str, Any]:
    """Run a single mutant trial in a fresh disposable snapshot."""
    label = row["label"]
    filename = row["filename"]
    befores = row["befores"]
    afters = row["afters"]
    test_nodes = row["test_nodes"]
    expected = row["expected"]
    replacement_hash = row["replacement_hash"]

    scratch_dir = Path(tempfile.mkdtemp(prefix="pseg-mutant-"))
    copy_dir = scratch_dir / "source"
    start_time = time.monotonic()
    outcome = "invalid"
    details: dict[str, Any] = {}

    try:
        snapshot(source=source_path, dest=copy_dir)
        target_file = resolve_target_path(copy_dir, filename)

        original_content = target_file.read_text(encoding="utf-8")
        mutated_content = apply_mutation(original_content, befores, afters, label)
        target_file.write_text(mutated_content, encoding="utf-8")

        try:
            py_compile.compile(str(target_file), doraise=True)
        except py_compile.PyCompileError as exc:
            outcome = "invalid"
            details = {"reason": "syntax_error", "message": str(exc)}
            elapsed = time.monotonic() - start_time
            return {
                "candidate_hash": candidate_hash,
                "label": label,
                "replacement_hash": replacement_hash,
                "node_ids": test_nodes,
                "elapsed_time": round(elapsed, 4),
                "outcome": outcome,
                "details": details,
            }

        run_res = run_pytest_in_copy(
            python_path=python_path,
            snapshot_dir=copy_dir,
            test_nodes=test_nodes,
            timeout=timeout,
        )

        outcome, details = classify_mutant_outcome(
            run_result=run_res,
            expected_nodes=test_nodes,
            expected_exc=expected,
        )
    except MutationSpecError as exc:
        outcome = "invalid"
        details = {"reason": "spec_error", "message": str(exc)}
    except SnapshotError as exc:
        outcome = "invalid"
        details = {"reason": "snapshot_error", "code": exc.code, "context": exc.context}
    except Exception as exc:
        outcome = "invalid"
        details = {"reason": "unexpected_error", "message": str(exc)}
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)

    elapsed = time.monotonic() - start_time
    return {
        "candidate_hash": candidate_hash,
        "label": label,
        "replacement_hash": replacement_hash,
        "node_ids": test_nodes,
        "elapsed_time": round(elapsed, 4),
        "outcome": outcome,
        "details": details,
    }


def _run_mutation_check(
    source: str | Path,
    python: str | Path,
    table: str | Path,
    only: str | None = None,
    timeout: int = 35,
) -> tuple[int, dict[str, Any]]:
    """Execute full mutation check process. Returns (exit_code, report_dict)."""
    source_path = Path(source).resolve()
    python_path = os.path.abspath(str(python))

    if not source_path.is_dir():
        return 2, {"error": f"Source directory not found: {source}"}
    if not os.path.isfile(python_path) or not os.access(python_path, os.X_OK):
        return 2, {"error": f"Python interpreter not executable: {python}"}

    try:
        initial_manifest = freeze(source=source_path)
    except SnapshotError as exc:
        return 2, {"error": f"Initial source freeze failed: {exc.code}", "context": exc.context}

    candidate_hash = initial_manifest["sha256"]
    head = initial_manifest.get("head", "unknown")

    try:
        rows = load_table(table)
    except MutationSpecError as exc:
        return 2, {"error": f"Table error: {exc}"}

    if only:
        rows = [r for r in rows if r["label"] == only]
        if not rows:
            return 2, {"error": f"Label {only!r} not found in table"}

    if not rows:
        return 2, {"error": "No mutation rows to test"}

    all_detector_nodes = sorted({node for r in rows for node in r["test_nodes"]})
    baseline_ok, baseline_msg = check_baseline(
        python_path=python_path,
        source_path=source_path,
        test_nodes=all_detector_nodes,
        timeout=max(35, timeout),
    )
    if not baseline_ok:
        return 2, {
            "candidate_hash": candidate_hash,
            "head": head,
            "error": f"Baseline failed: {baseline_msg}",
            "outcome": "baseline_failed",
        }

    mutant_results: list[dict[str, Any]] = []
    detected_count = 0
    survived_count = 0
    invalid_count = 0

    for r in rows:
        res = run_mutant_trial(
            python_path=python_path,
            source_path=source_path,
            candidate_hash=candidate_hash,
            row=r,
            timeout=timeout,
        )
        mutant_results.append(res)
        out = res["outcome"]
        if out == "detected":
            detected_count += 1
        elif out == "survived":
            survived_count += 1
        else:
            invalid_count += 1

    try:
        final_manifest = freeze(source=source_path)
        if final_manifest["sha256"] != candidate_hash:
            return 2, {
                "candidate_hash": candidate_hash,
                "error": "source_integrity_failed",
                "message": "Source directory changed during mutation run",
            }
    except Exception as exc:
        return 2, {
            "candidate_hash": candidate_hash,
            "error": "source_integrity_failed",
            "message": str(exc),
        }

    if invalid_count > 0:
        exit_code = 2
    elif survived_count > 0:
        exit_code = 1
    elif detected_count > 0:
        exit_code = 0
    else:
        exit_code = 2

    report = {
        "candidate_hash": candidate_hash,
        "head": head,
        "total": len(rows),
        "detected": detected_count,
        "survived": survived_count,
        "invalid": invalid_count,
        "exit_code": exit_code,
        "mutations": mutant_results,
    }
    return exit_code, report


def run_mutation_check(
    source: str | Path,
    python: str | Path,
    table: str | Path,
    only: str | None = None,
    timeout: int = 35,
) -> tuple[int, dict[str, Any]]:
    """Run checks with bounded diagnostics, including early invalid-spec reports."""
    code, report = _run_mutation_check(source, python, table, only, timeout)

    def clip_values(value: Any) -> Any:
        if isinstance(value, str):
            return _clip(value)
        if isinstance(value, list):
            return [clip_values(item) for item in value]
        if isinstance(value, dict):
            return {key: clip_values(item) for key, item in value.items()}
        return value

    report = clip_values(report)
    if len(json.dumps(report).encode()) > _REPORT_LIMIT:
        report = {key: report[key] for key in (
            "candidate_hash", "head", "total", "detected", "survived", "invalid", "exit_code"
        ) if key in report}
        report.update(mutations=[], diagnostics_truncated=True)
    return code, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mutation_check",
        description="Generic copy-only mutation testing engine",
    )
    parser.add_argument("--source", required=True, help="Source repository or snapshot path")
    parser.add_argument("--python", required=True, help="Python interpreter path")
    parser.add_argument("--table", required=True, help="Path to mutation table (py or json)")
    parser.add_argument("--only", default=None, help="Filter to a single mutant label")
    parser.add_argument("--timeout", type=int, default=35, help="Subprocess timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Output JSON result to stdout")

    args = parser.parse_args(argv)

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        exit_code, report = run_mutation_check(
            source=args.source,
            python=args.python,
            table=args.table,
            only=args.only,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        print(json.dumps({"error": "interrupted", "exit_code": 130}), file=sys.stderr)
        return 130
    except Exception as exc:
        print(json.dumps({"error": str(exc), "exit_code": 2}), file=sys.stderr)
        return 2

    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for m in report.get("mutations", []):
            print(f"{m['label']}: {m['outcome'].upper()} ({m['elapsed_time']}s)")
        print(
            f"Summary: {report.get('detected', 0)}/{report.get('total', 0)} detected, "
            f"{report.get('survived', 0)} survived, {report.get('invalid', 0)} invalid "
            f"(exit {exit_code})"
        )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

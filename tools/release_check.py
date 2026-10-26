#!/usr/bin/env python3
"""ha-pseg release check and snapshot tooling.

Profiles execute exact frozen inputs in fresh external copies; source is never a child cwd.
Snapshots and child logs are retained as evidence, including on failure. This has the
same local, non-hostile-process threat model as tools._snapshot.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

# Also protect direct invocations without -B before importing the local helper.
sys.dont_write_bytecode = True

_TOOLS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TOOLS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools._snapshot import (  # noqa: E402
    CleanupRefused,
    SnapshotError,
    freeze,
    snapshot,
)


def _emit_error(code: str, **context: object) -> None:
    payload = {"ok": False, "error": code, **context}
    print(json.dumps(payload, sort_keys=True), file=sys.stderr)


_NODE_FILES = (
    "tests/test_node_offline.js",
    "tests/test_captcha_helper.js",
    "tests/test_captcha_extension.js",
)

# Scoped statistics-surface baseline; the child never regenerates it.
_STATS_BASELINE_MANIFEST = "tests/fixtures/statistics_baseline_v1_6_0.json"


def _source_state(source: Path, paths_from: str | None) -> dict[str, object]:
    manifest = freeze(source=source, paths_from=paths_from)
    status = None
    if (source / ".git").exists():
        result = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(source), "status", "--porcelain", "--untracked-files=all"],
            check=True, capture_output=True, text=True,
        )
        status = result.stdout
    return {"head": manifest["head"], "sha256": manifest["sha256"], "status": status}


def _child(command: list[str], copy: Path, label: str, timeout: float) -> bool:
    # Runtime (logs, basetemp, TMPDIR, caches) lives beside the copy, never in it:
    # a test that snapshots its own copy must see exactly the frozen source.
    runtime = (copy.parent / "mutation-runtime" if label == "mutation"
               else copy.parent / "runtime" / label)
    runtime.mkdir(parents=True)
    env = os.environ.copy()
    for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "NODE_OPTIONS", "PYTHONHOME"):
        env.pop(key, None)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
        # Unbuffered output plus faulthandler: a hang that hits the timeout leaves
        # the real progress and every thread's stack in the log, not a stale buffer.
        "PYTHONUNBUFFERED": "1", "PYTHONFAULTHANDLER": "1",
        "PYTHONPATH": os.pathsep.join((str(copy), str(copy / "tests"))),
        "RUFF_NO_CACHE": "true", "TMPDIR": str(runtime), "TMP": str(runtime),
        "TEMP": str(runtime), "XDG_CACHE_HOME": str(runtime / "cache"),
    })
    if label in {"fast-pytest", "independent-pytest"}:
        command += ["--basetemp", str(runtime / "pytest")]
    log = runtime / "output.log"
    timed_out = False
    with log.open("w") as output:
        process = subprocess.Popen(
            command, cwd=copy, env=env, stdout=output, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # SIGABRT first so faulthandler dumps all thread stacks, then SIGKILL.
            try:
                process.send_signal(signal.SIGABRT)
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            returncode = process.wait()
        except BaseException:
            # Ctrl-C / SIGTERM: never leave the child's process group running.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    text = log.read_text(errors="replace")
    counts: dict[str, int] = {}
    if label.endswith("pytest"):
        # Take the final pytest summary, rather than counting progress or warning lines.
        summaries = [line for line in text.splitlines() if re.search(r"\d+ passed|\d+ failed|no tests ran|\d+ deselected", line)]
        if summaries:
            counts = {kind: int(n) for n, kind in re.findall(
                r"(\d+) (passed|failed|skipped|xfailed|xpassed|errors?)\b", summaries[-1]
            )}
        nonempty = sum(counts.values()) > 0
    elif label == "node":
        counts = {kind: int(n) for kind, n in re.findall(
            r"^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$", text, re.MULTILINE
        )}
        # Node reports an empty file as a successful test of that file. Those
        # implicit wrappers are not suite cases and must not create empty success.
        wrappers = sum(bool(re.search(
            r"^ok \d+ - (?:" + re.escape(name) + "|" + re.escape(str(copy / name)) + r")$",
            text, re.MULTILINE,
        )) for name in _NODE_FILES)
        nonempty = counts.get("tests", 0) > wrappers
    elif label == "mutation":
        try:
            report = json.loads(text)
            counts = {key: int(report[key]) for key in ("detected", "survived", "invalid")}
            nonempty = report["total"] > 0
        except (ValueError, KeyError, TypeError):
            nonempty = False
    elif label == "stats-baseline":
        # The child prints the structured report on stdout and a human summary on
        # stderr; both land in this log, so decode the last report line. A
        # malformed or empty report is a refusal, never an empty-but-green run.
        report = None
        for line in text.splitlines():
            if not line.startswith("{"):
                continue
            try:
                candidate = json.loads(line)
            except ValueError:
                continue
            if isinstance(candidate, dict) and candidate.get("tool") == "stats_baseline":
                report = candidate
        counts = {}
        if report is not None:
            try:
                counts = {
                    key: int(report[key])
                    for key in ("surfaces_total", "equal", "approved_expected_delta",
                                "unreviewed")
                }
            except (KeyError, TypeError, ValueError):
                counts = {}
        nonempty = counts.get("surfaces_total", 0) > 0 and not (report or {}).get("error")
    else:
        nonempty = True  # Ruff is a lint check, not an expected test suite.
    ok = returncode == 0 and not timed_out and nonempty
    print(json.dumps({
        "child": label, "returncode": returncode, "counts": counts, "ok": ok,
        "timeout": timed_out, "empty_suite": not nonempty, "log": str(log),
    }, sort_keys=True), flush=True)
    if not ok:
        # A timeout's faulthandler dump (Python stacks, then a long C stack) needs
        # far more than the usual tail to show which test was running.
        print(text[-(200_000 if timed_out else 6000):], file=sys.stderr)
    return ok


def _run_profiles(args: argparse.Namespace) -> int:
    if args.subcommand in {"slow", "nightly", "replay"}:
        _emit_error("profile_not_available", profile=args.subcommand)
        return 1
    if args.repeat < 1 or not math.isfinite(args.timeout) or args.timeout <= 0:
        _emit_error("invalid_repeat_or_timeout")
        return 1
    interpreter = shutil.which(args.python)
    if interpreter is None:
        _emit_error("interpreter_not_found", interpreter=args.python)
        return 1
    interpreter = str(Path(interpreter).absolute())
    source = Path(args.source).resolve()
    profiles = ("fast", "node", "independent", "mutation") if args.subcommand == "all" else (args.subcommand,)
    ok = True
    for iteration in range(1, args.repeat + 1):
        # Explicit external parent: ignore a caller TMPDIR that might point into source.
        evidence = Path(tempfile.mkdtemp(prefix="pseg-release-", dir="/tmp"))
        copy = evidence / "source"
        print(json.dumps({"repeat": iteration, "evidence": str(evidence)}), flush=True)
        before = _source_state(source, args.paths_from)
        print(json.dumps({"source_before": before}, sort_keys=True), flush=True)
        try:
            manifest = snapshot(source=source, dest=copy, paths_from=args.paths_from)
            print(json.dumps({"manifest": manifest["sha256"], "files": manifest["count"],
                              "copy": str(copy)}, sort_keys=True), flush=True)
            if manifest["sha256"] != before["sha256"] or manifest["head"] != before["head"]:
                raise SnapshotError("source_changed_before_snapshot")
            for profile in profiles:
                if profile == "fast":
                    lint_ok = _child([interpreter, "-B", "-m", "ruff", "check", "."],
                                     copy, "ruff", args.timeout)
                    ok = lint_ok and ok
                if profile in {"fast", "independent"}:
                    marker = "not slow and not nightly and not quarantine" if profile == "fast" else "independent"
                    command = [interpreter, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                               "-o", "pythonpath=. tests", "-m", marker]
                    passed = _child(command, copy, profile + "-pytest", args.timeout)
                elif profile == "mutation":
                    passed = _child([interpreter, "-B", "tools/mutation_check.py",
                                     "--source", ".", "--python", interpreter,
                                     "--table", "tests/mutations/auth_guards.py", "--json"],
                                    copy, "mutation", args.timeout)
                elif profile == "stats-baseline":
                    # Explicit manifest plus the snapshot copy: no git, no
                    # regeneration, nonzero on any unreviewed surface change.
                    passed = _child([interpreter, "-B", "tools/stats_baseline.py",
                                     "--manifest", _STATS_BASELINE_MANIFEST,
                                     "--source", "."],
                                    copy, "stats-baseline", args.timeout)
                else:
                    node = shutil.which("node")
                    if node is None:
                        raise SnapshotError("node_not_found")
                    passed = _child([str(Path(node).absolute()), "--require", "./tests/support/node_offline.cjs",
                                     "--test", "--test-reporter=tap", *_NODE_FILES], copy, "node", args.timeout)
                ok = passed and ok
        finally:
            after = _source_state(source, args.paths_from)
            unchanged = before == after
            print(json.dumps({"source_after": after, "source_unchanged": unchanged},
                             sort_keys=True), flush=True)
            if not unchanged:
                raise SnapshotError("source_changed_during_run")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="release_check",
        description="ha-pseg release and validation runner",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # freeze
    freeze_parser = subparsers.add_parser("freeze", help="Freeze candidate manifest")
    freeze_parser.add_argument(
        "--source", default=".", help="Source path (git worktree or snapshot)"
    )
    freeze_parser.add_argument("--json", action="store_true", help="Emit manifest JSON")
    freeze_parser.add_argument(
        "--paths-from",
        default=None,
        help="Explicit file containing paths to include",
    )

    # snapshot
    snapshot_parser = subparsers.add_parser(
        "snapshot", help="Create independent safe snapshot"
    )
    snapshot_parser.add_argument(
        "--source", default=".", help="Source path (git worktree or snapshot)"
    )
    snapshot_parser.add_argument(
        "--dest", required=True, help="Destination directory (must not exist)"
    )
    snapshot_parser.add_argument(
        "--paths-from",
        default=None,
        help="Explicit file containing paths to include",
    )

    for profile in ("fast", "node", "independent", "mutation", "all",
                    "slow", "nightly", "replay", "stats-baseline"):
        runner = subparsers.add_parser(profile, help=f"Run {profile} profile in a fresh copy")
        runner.add_argument("--source", default=".")
        runner.add_argument("--python", default=os.environ.get("PSEG_TEST_PYTHON", sys.executable))
        runner.add_argument("--paths-from", help="Explicit reviewed new suite paths (snapshot contract)")
        runner.add_argument("--repeat", type=int, default=1)
        runner.add_argument("--timeout", type=float, default=600, help="Seconds per child (default: 600)")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        if args.subcommand == "freeze":
            manifest = freeze(source=args.source, paths_from=args.paths_from)
            if args.json:
                print(json.dumps(manifest, indent=2, sort_keys=True))
            else:
                print(
                    f"Frozen {manifest['count']} files; "
                    f"head={manifest['head']} aggregate={manifest['sha256']}"
                )
            return 0
        elif args.subcommand == "snapshot":
            res = snapshot(
                source=args.source, dest=args.dest, paths_from=args.paths_from
            )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "files": res["count"],
                        "sha256": res["sha256"],
                        "head": res["head"],
                        "dest": res.get("dest", args.dest),
                    },
                    sort_keys=True,
                )
            )
            return 0
        else:
            return _run_profiles(args)
    except SnapshotError as err:
        _emit_error(err.code, **err.context)
        return 1
    except CleanupRefused:
        _emit_error("cleanup_refused")
        return 1
    except (OSError, subprocess.SubprocessError) as err:
        _emit_error("child_or_io_error", detail=str(err))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

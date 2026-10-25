"""Tests for generic copy-only mutation testing engine (P1-10)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools.mutation_check import (
    MutationSpecError,
    main as cli_main,
    resolve_target_path,
    run_mutation_check,
)

_TEST_PYTHON = os.environ.get("PSEG_TEST_PYTHON") or (
    "/home/tacoriffic/ha-pseg/.venv/bin/python"
    if Path("/home/tacoriffic/ha-pseg/.venv/bin/python").exists()
    else sys.executable
)


def _run_git(repo: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip()


def _create_synthetic_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _run_git(path, "init", "-b", "main")
    _run_git(path, "config", "user.name", "Test Runner")
    _run_git(path, "config", "user.email", "test@example.com")

    (path / "pyproject.toml").write_text(
        """[project]
name = "synthetic"
version = "0.1.0"

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = [".", "tests"]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
""",
        encoding="utf-8",
    )

    pkg = path / "custom_components" / "pseg"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "auth.py").write_text(
        '''"""Synthetic auth module."""

def check_permission(user_role: str) -> bool:
    if user_role == "admin":
        return True
    return False

def get_secret_token(authenticated: bool) -> str:
    if not authenticated:
        raise PermissionError("Access denied")
    return "secret-token-xyz"
''',
        encoding="utf-8",
    )

    test_dir = path / "tests"
    test_dir.mkdir(parents=True, exist_ok=True)
    (test_dir / "__init__.py").write_text("", encoding="utf-8")
    (test_dir / "test_auth.py").write_text(
        '''import pytest
from custom_components.pseg.auth import check_permission, get_secret_token

def test_admin_has_permission():
    assert check_permission("admin") is True

def test_guest_no_permission():
    assert check_permission("guest") is False

def test_token_requires_auth():
    with pytest.raises(PermissionError):
        get_secret_token(False)
''',
        encoding="utf-8",
    )

    _run_git(path, "add", ".")
    _run_git(path, "commit", "-m", "initial commit")
    return path


def test_green_to_assertion_red(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "admin-guard",
        "auth.py",
        'if user_role == "admin":',
        'if user_role != "admin":',
        "tests/test_auth.py::test_admin_has_permission",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 0
    assert report["detected"] == 1
    assert report["survived"] == 0
    assert report["invalid"] == 0
    m = report["mutations"][0]
    assert m["outcome"] == "detected"
    assert m["replacement_hash"] is not None
    assert m["candidate_hash"] == report["candidate_hash"]


def test_survivor(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "survivor-mutant",
        "auth.py",
        'return "secret-token-xyz"',
        'return "other-token-abc"',
        "tests/test_auth.py::test_token_requires_auth",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 1
    assert report["detected"] == 0
    assert report["survived"] == 1
    assert report["invalid"] == 0
    assert report["mutations"][0]["outcome"] == "survived"


def test_missing_preimage(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "missing-preimage",
        "auth.py",
        "nonexistent_line_of_code_xyz()",
        "pass",
        "tests/test_auth.py::test_admin_has_permission",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 2
    assert report["invalid"] == 1
    m = report["mutations"][0]
    assert m["outcome"] == "invalid"
    assert "preimage not found" in m["details"]["message"]


def test_ambiguous_preimage(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "ambiguous-preimage",
        "auth.py",
        "return",
        "return True",
        "tests/test_auth.py::test_admin_has_permission",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 2
    assert report["invalid"] == 1
    m = report["mutations"][0]
    assert m["outcome"] == "invalid"
    assert "ambiguous preimage" in m["details"]["message"]


def test_tuple_replacement(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "tuple-mutant",
        "auth.py",
        ('if user_role == "admin":', 'return False'),
        ('if False:', 'return True'),
        "tests/test_auth.py::test_guest_no_permission",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 0
    assert report["detected"] == 1
    assert report["mutations"][0]["outcome"] == "detected"


def test_missing_node(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "missing-node",
        "auth.py",
        'if user_role == "admin":',
        'if False:',
        "tests/test_auth.py::test_non_existent_function_name",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 2
    assert "Baseline failed" in report["error"]


def test_baseline_red(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    test_file = repo / "tests" / "test_auth.py"
    test_file.write_text(
        test_file.read_text(encoding="utf-8") + "\ndef test_broken_baseline():\n    assert 1 == 2\n",
        encoding="utf-8",
    )
    _run_git(repo, "commit", "-am", "add failing baseline test")

    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "baseline-red",
        "auth.py",
        'if user_role == "admin":',
        'if False:',
        "tests/test_auth.py::test_broken_baseline",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 2
    assert report["outcome"] == "baseline_failed"
    assert "Baseline detector failed" in report["error"]


def test_collection_error(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    bad_test = repo / "tests" / "test_bad_syntax.py"
    bad_test.write_text("def test_broken(:\n    pass\n", encoding="utf-8")
    _run_git(repo, "add", "tests/test_bad_syntax.py")
    _run_git(repo, "commit", "-m", "add syntax error test")

    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "collect-err",
        "auth.py",
        'if user_role == "admin":',
        'if False:',
        "tests/test_bad_syntax.py::test_broken",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 2
    assert "Baseline failed" in report["error"] or "collection" in report["error"].lower()


def test_timeout(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.json"
    table.write_text(
        json.dumps([
            {
                "label": "timeout-mutant",
                "filename": "auth.py",
                "before": 'if user_role == "admin":',
                "after": 'import time\n    time.sleep(10)\n    if user_role == "admin":',
                "test": "tests/test_auth.py::test_admin_has_permission",
            }
        ]),
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
        timeout=1,
    )
    assert code == 2
    assert report["invalid"] == 1
    m = report["mutations"][0]
    assert m["outcome"] == "invalid"
    assert m["details"]["reason"] == "timeout"


def test_syntax_error(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "syntax-err",
        "auth.py",
        'if user_role == "admin":',
        'def broken(:',
        "tests/test_auth.py::test_admin_has_permission",
    ),
]
""",
        encoding="utf-8",
    )

    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 2
    assert report["invalid"] == 1
    m = report["mutations"][0]
    assert m["outcome"] == "invalid"
    assert m["details"]["reason"] == "syntax_error"


def test_hostile_paths_and_escapes(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")

    with pytest.raises(MutationSpecError, match="traversal"):
        resolve_target_path(repo, "../escape.py")

    with pytest.raises(MutationSpecError, match="Absolute"):
        resolve_target_path(repo, "/etc/passwd")

    with pytest.raises(MutationSpecError, match="not found"):
        resolve_target_path(repo, "nonexistent_outside.py")


def test_symlink_target_rejected(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    sym = repo / "custom_components" / "pseg" / "link_auth.py"
    sym.symlink_to(repo / "custom_components" / "pseg" / "auth.py")

    with pytest.raises(MutationSpecError, match="Symlink"):
        resolve_target_path(repo, "link_auth.py")


def test_typed_exception_handling(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")

    # Case A: undeclared exception escape -> INVALID
    table_undeclared = tmp_path / "table_undeclared.json"
    table_undeclared.write_text(
        json.dumps([
            {
                "label": "crash-undeclared",
                "filename": "auth.py",
                "before": 'if user_role == "admin":',
                "after": 'raise RuntimeError("boom")\n    if user_role == "admin":',
                "test": "tests/test_auth.py::test_admin_has_permission",
            }
        ]),
        encoding="utf-8",
    )
    code_a, report_a = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table_undeclared,
    )
    assert code_a == 2
    assert report_a["mutations"][0]["outcome"] == "invalid"
    assert report_a["mutations"][0]["details"]["reason"] == "unexpected_exception"

    # Case B: declared exception escape -> DETECTED
    table_declared = tmp_path / "table_declared.json"
    table_declared.write_text(
        json.dumps([
            {
                "label": "crash-declared",
                "filename": "auth.py",
                "before": 'if user_role == "admin":',
                "after": 'raise RuntimeError("boom")\n    if user_role == "admin":',
                "test": "tests/test_auth.py::test_admin_has_permission",
                "expected": "RuntimeError",
            }
        ]),
        encoding="utf-8",
    )
    code_b, report_b = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table_declared,
    )
    assert code_b == 0
    assert report_b["mutations"][0]["outcome"] == "detected"


def test_multiple_detector_nodes(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "multi-nodes",
        "auth.py",
        'if user_role == "admin":',
        'if user_role != "admin":',
        [
            "tests/test_auth.py::test_admin_has_permission",
            "tests/test_auth.py::test_guest_no_permission",
        ],
    ),
]
""",
        encoding="utf-8",
    )
    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 0
    assert report["detected"] == 1
    assert len(report["mutations"][0]["node_ids"]) == 2


def test_only_filter(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "row-1",
        "auth.py",
        'if user_role == "admin":',
        'if user_role != "admin":',
        "tests/test_auth.py::test_admin_has_permission",
    ),
    (
        "row-2",
        "auth.py",
        'return "secret-token-xyz"',
        'return "other"',
        "tests/test_auth.py::test_token_requires_auth",
    ),
]
""",
        encoding="utf-8",
    )
    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
        only="row-2",
    )
    assert code == 1
    assert report["total"] == 1
    assert report["mutations"][0]["label"] == "row-2"


def test_exit_code_precedence(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "survivor",
        "auth.py",
        'return "secret-token-xyz"',
        'return "other"',
        "tests/test_auth.py::test_token_requires_auth",
    ),
    (
        "invalid-syntax",
        "auth.py",
        'if user_role == "admin":',
        'def broken(:',
        "tests/test_auth.py::test_admin_has_permission",
    ),
]
""",
        encoding="utf-8",
    )
    code, report = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 2
    assert report["survived"] == 1
    assert report["invalid"] == 1


def test_cli_execution_exits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = tmp_path / "table.json"
    table.write_text(
        json.dumps([
            {
                "label": "cli-detected",
                "filename": "auth.py",
                "before": 'if user_role == "admin":',
                "after": 'if user_role != "admin":',
                "test": "tests/test_auth.py::test_admin_has_permission",
            }
        ]),
        encoding="utf-8",
    )

    exit_code = cli_main([
        "--source", str(repo),
        "--python", _TEST_PYTHON,
        "--table", str(table),
        "--json",
    ])
    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["detected"] == 1
    assert payload["exit_code"] == 0


def test_source_remains_untouched(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    head_before = _run_git(repo, "rev-parse", "HEAD")
    status_before = _run_git(repo, "status", "--porcelain")

    table = tmp_path / "table.py"
    table.write_text(
        """MUTATIONS = [
    (
        "test-touch",
        "auth.py",
        'if user_role == "admin":',
        'if user_role != "admin":',
        "tests/test_auth.py::test_admin_has_permission",
    ),
]
""",
        encoding="utf-8",
    )

    code, _ = run_mutation_check(
        source=repo,
        python=_TEST_PYTHON,
        table=table,
    )
    assert code == 0
    head_after = _run_git(repo, "rev-parse", "HEAD")
    status_after = _run_git(repo, "status", "--porcelain")

    assert head_before == head_after
    assert status_before == status_after


def _table(tmp_path: Path, **changes: object) -> Path:
    row = dict(label="regression", filename="auth.py", before="return True",
               after="return False", test="tests/test_auth.py::test_admin_has_permission")
    row.update(changes)
    table = tmp_path / "regression.json"
    table.write_text(json.dumps([row]), encoding="utf-8")
    return table


@pytest.mark.parametrize(("statement", "expected", "code"), [
    ('raise RuntimeError("AssertionError: unrelated runtime failure")', None, 2),
    ('raise ValueError("RuntimeError in message only")', "RuntimeError", 2),
    ("assert False", None, 0),
    ('import pytest; pytest.fail("explicit failure")', None, 0),
    ('raise RuntimeError("declared")', "builtins.RuntimeError", 0),
    ('raise RuntimeError("wrong phase")', {"phase": "setup", "type": "RuntimeError"}, 2),
    ('class Child(AssertionError): pass\n        raise Child()', None, 0),
])
def test_actual_exception_types(tmp_path: Path, statement: str, expected: object, code: int) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    if statement == "assert False":
        # Reproduce the review's rewritten detector assertion (no message).
        detector = repo / "tests/test_auth.py"
        detector.write_text(detector.read_text() + (
            '\n\ndef test_bare_assertion():\n'
            '    if not check_permission("admin"):\n        assert False\n'
        ))
        _run_git(repo, "commit", "-am", "bare detector assertion")
        table = _table(tmp_path, test="tests/test_auth.py::test_bare_assertion")
    else:
        table = _table(tmp_path, after=statement, expected=expected)
    result, report = run_mutation_check(repo, _TEST_PYTHON, table)
    assert result == code, report
    assert report["mutations"][0]["outcome"] == ("detected" if code == 0 else "invalid")


@pytest.mark.parametrize("mode", ["skip", "xfail", "xpass", "setup_skip"])
def test_baseline_must_pass_call(tmp_path: Path, mode: str) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    test = repo / "tests/test_auth.py"
    prefix = "import pytest\nfrom custom_components.pseg.auth import check_permission\n"
    if mode == "setup_skip":
        prefix += '@pytest.fixture(autouse=True)\ndef skip_setup():\n    pytest.skip("setup")\n'
    elif mode in ("xfail", "xpass"):
        prefix += '@pytest.mark.xfail(reason="baseline", strict=False)\n'
    body = '    if check_permission("admin"):\n        pytest.skip("baseline never ran")\n    assert False\n'
    if mode == "xfail":
        body = '    assert not check_permission("admin")\n'
    elif mode == "xpass":
        body = '    assert check_permission("admin")\n'
    test.write_text(prefix + "def test_admin_has_permission():\n" + body)
    _run_git(repo, "commit", "-am", "baseline regression")
    code, report = run_mutation_check(repo, _TEST_PYTHON, _table(tmp_path))
    assert code == 2
    assert report["outcome"] == "baseline_failed"


@pytest.mark.parametrize("filename", ["tests/test_auth.py", "../auth.py", "/tmp/auth.py",
                                      "custom_components/pseg/link.py", "custom_components/pseg/escape/auth.py"])
def test_every_target_confined_before_write(tmp_path: Path, filename: str) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    pkg = repo / "custom_components/pseg"
    (pkg / "link.py").symlink_to(repo / "tests/test_auth.py")
    (pkg / "escape").symlink_to(repo / "tests", target_is_directory=True)
    before = (repo / "tests/test_auth.py").read_bytes()
    with pytest.raises(MutationSpecError):
        resolve_target_path(repo, filename)
    assert (repo / "tests/test_auth.py").read_bytes() == before


def test_foreign_detector_target_is_invalid(tmp_path: Path) -> None:
    repo = _create_synthetic_repo(tmp_path / "repo")
    table = _table(tmp_path, filename="tests/test_auth.py",
                   before='assert check_permission("admin") is True', after="assert False")
    code, report = run_mutation_check(repo, _TEST_PYTHON, table)
    assert code == 2
    assert report["mutations"][0]["details"]["reason"] == "spec_error"


def test_diagnostics_are_bounded(tmp_path: Path) -> None:
    from tools.mutation_check import run_pytest_in_copy

    repo = _create_synthetic_repo(tmp_path / "repo")
    (repo / "tests/test_large.py").write_text('def test_large():\n    raise RuntimeError("X" * 1048576)\n')
    result = run_pytest_in_copy(_TEST_PYTHON, repo, ["tests/test_large.py::test_large"])
    assert len(json.dumps(result)) < 65536
    call = next(r for r in result["reports"] if r["when"] == "call")
    assert "truncated" in call["crash_message"]
    assert len(result["stdout"]) < 4200


@pytest.mark.parametrize("termination", ["SIGINT", "SIGTERM", "timeout"])
def test_interruption_kills_process_group(tmp_path: Path, termination: str) -> None:
    import signal
    import time

    from tools import mutation_check

    repo = _create_synthetic_repo(tmp_path / "repo")
    marker = tmp_path / "running.json"
    test = repo / "tests/test_auth.py"
    test.write_text(test.read_text() + f'''

def test_sleeping_mutant():
    import os, subprocess, sys, time, json
    from pathlib import Path
    if not check_permission("admin"):
        child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(120)"])
        Path({str(marker)!r}).write_text(json.dumps(dict(pid=os.getpid(), pgid=os.getpgrp(), child=child.pid)))
        time.sleep(120)
''')
    _run_git(repo, "commit", "-am", "process regression")
    table = _table(tmp_path, test="tests/test_auth.py::test_sleeping_mutant")
    source_bytes = (repo / "custom_components/pseg/auth.py").read_bytes()
    proc = subprocess.Popen([
        _TEST_PYTHON, "-B", mutation_check.__file__, "--source", str(repo),
        "--python", _TEST_PYTHON, "--table", str(table), "--json", "--timeout",
        "2" if termination == "timeout" else "35",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    group = None
    try:
        deadline = time.monotonic() + 25
        while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(.03)
        assert marker.exists()
        group = json.loads(marker.read_text())["pgid"]
        if termination != "timeout":
            os.kill(proc.pid, getattr(signal, termination))
        out, err = proc.communicate(timeout=15)
        assert proc.returncode != 0
        assert b"timeout" in out if termination == "timeout" else b"interrupted" in err
        # Zombies are dead and cannot execute; PID1 controls their reaping.
        def survivors() -> list[str]:
            live = []
            for stat in Path("/proc").glob("[0-9]*/stat"):
                try:
                    fields = stat.read_text().rsplit(")", 1)[1].split()
                    if int(fields[2]) == group and fields[0] != "Z":
                        live.append(str(stat))
                except (FileNotFoundError, ProcessLookupError):
                    pass
            return live
        deadline = time.monotonic() + 3
        while survivors() and time.monotonic() < deadline:
            time.sleep(.03)
        assert not survivors()
        assert (repo / "custom_components/pseg/auth.py").read_bytes() == source_bytes
    finally:
        if group:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if proc.poll() is None:
            proc.kill()
        proc.communicate()


def test_total_report_limit_preserves_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    from tools import mutation_check

    large = {"total": 100, "invalid": 100, "exit_code": 2,
             "mutations": [{"details": "X" * 4096}] * 100}
    monkeypatch.setattr(mutation_check, "_run_mutation_check", lambda *args: (2, large))
    code, report = run_mutation_check("unused", "unused", "unused")
    assert code == 2
    assert report["invalid"] == 100
    assert report["diagnostics_truncated"] is True
    assert len(json.dumps(report)) < 262144

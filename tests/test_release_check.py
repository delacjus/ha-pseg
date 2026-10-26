"""Release profiles use real children in synthetic, disposable source repositories."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools import release_check, stats_baseline


@pytest.fixture
def source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tests" / "support").mkdir(parents=True)
    (repo / "pyproject.toml").write_text(
        '[tool.ruff.lint]\nselect=["E", "F"]\nignore=["E501"]\n[tool.pytest.ini_options]\ntestpaths=["tests"]\n'
        'markers=["independent: probe", "slow: slow", "nightly: nightly", "quarantine: quarantine"]\n'
    )
    (repo / "origin.py").write_text(
        "VALUE = 42\n\n\ndef helper(value):\n    return value + 1\n"
    )
    (repo / "tests" / "test_origin.py").write_text(
        "from pathlib import Path\nimport os\nimport origin\nimport pytest\n\n"
        "@pytest.mark.independent\ndef test_origin():\n"
        "    assert origin.VALUE == 42\n"
        "    assert Path(origin.__file__).parent == Path.cwd()\n"
        f"    assert Path.cwd() != Path({str(repo)!r})\n"
        "    tmp = Path(os.environ['TMPDIR'])\n"
        "    assert tmp.is_relative_to(Path.cwd().parent)\n"
        "    assert not tmp.is_relative_to(Path.cwd())\n"
        "    assert not Path('origin.py').is_symlink()\n\n"
        "@pytest.mark.slow\ndef test_slow():\n    assert False\n\n"
        "@pytest.mark.nightly\ndef test_nightly():\n    assert False\n\n"
        "@pytest.mark.quarantine\ndef test_quarantine():\n    assert False\n"
    )
    (repo / "tests" / "support" / "node_offline.cjs").write_text(
        "process.env.PSEG_PRELOAD_SENTINEL = 'loaded';\n"
    )
    for name in release_check._NODE_FILES:
        (repo / name).write_text(
            "const test = require('node:test');\nconst assert = require('node:assert/strict');\n"
            "test('preload', () => { assert.equal(process.env.PSEG_PRELOAD_SENTINEL, 'loaded'); });\n"
        )
    # Exercise the real copy engine, with a small catalog whose detector also
    # verifies that both release and mutation imports come from disposable copies.
    (repo / "tools").mkdir()
    for name in ("mutation_check.py", "_snapshot.py", "stats_baseline.py"):
        (repo / "tools" / name).write_bytes(
            (Path(release_check.__file__).parent / name).read_bytes()
        )
    # Scoped statistics baseline: one function and one constant of origin.py.
    fixture_dir = repo / "tests" / "fixtures"
    fixture_dir.mkdir()
    surfaces = []
    for kind, name in (("function", "helper"), ("assignment", "VALUE")):
        digest, detail = stats_baseline.extract_digest(repo, "origin.py", kind, name)
        assert detail == "ok"
        surfaces.append({
            "group": "writer_state",
            "path": "origin.py",
            "kind": kind,
            "name": name,
            "sha256": digest,
            "baseline_file_sha256": stats_baseline.file_digest(repo, "origin.py"),
            "approved_deltas": [],
        })
    (fixture_dir / "statistics_baseline_v1_6_0.json").write_text(json.dumps({
        "schema": 1,
        "baseline": {"commit": "0" * 40, "tag": "v1.6.0"},
        "normalization": {"digest": "sha256"},
        "surfaces": surfaces,
    }))
    (repo / "custom_components" / "pseg").mkdir(parents=True)
    (repo / "custom_components" / "pseg" / "auth.py").write_text("VALUE = 42\n")
    (repo / "tests" / "test_mutant.py").write_text(
        "from pathlib import Path\nfrom custom_components.pseg import auth\n\n"
        "def test_value():\n"
        "    assert Path(auth.__file__).is_relative_to(Path.cwd())\n"
        f"    assert not Path.cwd().is_relative_to(Path({str(repo)!r}))\n"
        "    assert auth.VALUE == 42\n"
    )
    (repo / "tests" / "mutations").mkdir()
    (repo / "tests" / "mutations" / "auth_guards.py").write_text(
        'MUTATIONS = [("guard", "auth.py", "VALUE = 42", "VALUE = 0", '
        '"tests/test_mutant.py::test_value")]\n'
    )
    for args in (("init", "-b", "main"), ("add", "."),
                 ("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "fixture")):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    # A hostile inherited import root/options must not leak into the child.
    monkeypatch.setenv("PYTHONPATH", str(repo))
    monkeypatch.setenv("PYTEST_ADDOPTS", "--unknown-inherited-option")
    return repo


def run(source: Path, profile: str = "fast", *options: str) -> int:
    return release_check.main([profile, "--source", str(source), "--python", sys.executable, *options])


def records(capsys: pytest.CaptureFixture[str]) -> list[dict]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]


def report_from(child: dict) -> dict:
    """Return the structured stats-baseline report from a child log."""
    for line in Path(child["log"]).read_text().splitlines():
        if line.startswith("{"):
            return json.loads(line)
    raise AssertionError("child log has no structured report")


def test_fast_isolated_imports_counts_no_source_writes(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = sorted(str(p.relative_to(source)) for p in source.rglob("*"))
    assert run(source) == 0
    result = records(capsys)
    child = next(row for row in result if row.get("child") == "fast-pytest")
    assert child["counts"] == {"passed": 2}
    assert next(row for row in result if "source_unchanged" in row)["source_unchanged"]
    assert before == sorted(str(p.relative_to(source)) for p in source.rglob("*"))
    assert not list(source.rglob("__pycache__"))
    assert not list(source.rglob(".pytest_cache"))
    assert not list(source.rglob(".ruff_cache"))


def test_independent(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, "independent") == 0
    child = next(row for row in records(capsys) if row.get("child") == "independent-pytest")
    assert child["counts"] == {"passed": 1}


def test_repeat_executes_two_fresh_copies(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, "independent", "--repeat", "2") == 0
    result = records(capsys)
    copies = [row["copy"] for row in result if "copy" in row]
    children = [row for row in result if row.get("child") == "independent-pytest"]
    assert len(set(copies)) == len(children) == 2
    assert all(Path(row["log"]).read_text().count("1 passed") == 1 for row in children)
    assert all(Path(copy).is_dir() and not Path(copy).is_relative_to(source) for copy in copies)


def test_allowlisted_new_failing_suite(source: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    extra = source / "tests" / "new_suite"
    extra.mkdir()
    (extra / "test_failure.py").write_text("def test_failure():\n    assert False\n")
    paths = tmp_path / "paths.txt"
    paths.write_text("tests/new_suite/test_failure.py\n")
    assert run(source, "fast", "--paths-from", str(paths)) == 1
    result = records(capsys)
    child = next(row for row in result if row.get("child") == "fast-pytest")
    assert child["counts"] == {"failed": 1, "passed": 2}
    assert "assert False" in Path(child["log"]).read_text()
    assert next(row for row in result if "source_unchanged" in row)["source_unchanged"]


def test_dirty_tracked_failure(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (source / "origin.py").write_text("VALUE = 0\n")
    assert run(source) == 1
    result = records(capsys)
    assert next(row["source_before"] for row in result if "source_before" in row)["status"] == " M origin.py\n"
    assert next(row for row in result if "source_unchanged" in row)["source_unchanged"]


def test_node_preload_and_all_files(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, "node") == 0
    child = next(row for row in records(capsys) if row.get("child") == "node")
    assert child["counts"]["tests"] == child["counts"]["pass"] == len(release_check._NODE_FILES)


def test_missing_node(source: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    original = release_check.shutil.which
    monkeypatch.setattr(release_check.shutil, "which", lambda name: None if name == "node" else original(name))
    assert run(source, "node") == 1
    assert "node_not_found" in capsys.readouterr().err


def test_rejected_symlink(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (source / "origin.py").unlink()
    (source / "origin.py").symlink_to("pyproject.toml")
    assert run(source) == 1
    assert "symlink" in capsys.readouterr().err


def test_timeout_keeps_evidence(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (source / "tests" / "test_origin.py").write_text(
        "import time\ndef test_hang():\n    time.sleep(30)\n"
    )
    assert run(source, "fast", "--timeout", "0.2") == 1
    children = [row for row in records(capsys) if "child" in row]
    assert any(row["timeout"] for row in children)
    assert all(Path(row["log"]).exists() for row in children)


def test_empty_suite(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (source / "tests" / "test_origin.py").write_text("# empty\n")
    (source / "tests" / "test_mutant.py").write_text("# empty\n")
    assert run(source) == 1
    assert any(row.get("empty_suite") for row in records(capsys))


def test_empty_node_suite(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for name in release_check._NODE_FILES:
        (source / name).write_text("// no tests\n")
    assert run(source, "node") == 1
    assert any(row.get("empty_suite") for row in records(capsys))


def test_lint_failure(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (source / "origin.py").write_text("VALUE = missing_name\n")
    assert run(source) == 1
    assert any(row.get("child") == "ruff" and not row["ok"] for row in records(capsys))


def test_source_change_detected(source: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def change(*args: object) -> bool:
        (source / "origin.py").write_text("VALUE = 99\n")
        return True
    monkeypatch.setattr(release_check, "_child", change)
    assert run(source, "independent") == 1
    assert "source_changed_during_run" in capsys.readouterr().err


@pytest.mark.parametrize("profile", ["slow", "nightly", "unknown"])
def test_unavailable_profiles(source: Path, profile: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, profile) != 0
    assert capsys.readouterr().err


def test_all_runs_every_profile(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, "all") == 0
    captured = capsys.readouterr()
    assert not captured.err
    children = [json.loads(line)["child"] for line in captured.out.splitlines() if '"child"' in line]
    assert children == ["ruff", "fast-pytest", "node", "independent-pytest", "mutation"]


@pytest.mark.parametrize("options", [("--repeat", "0"), ("--timeout", "0"), ("--timeout", "nan"), ("--python", "/missing/python")])
def test_bad_options(source: Path, options: tuple[str, str], capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, "fast", *options) != 0
    assert capsys.readouterr().err


def test_failed_child_executable(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, "fast", "--python", "/bin/false") == 1
    assert any(row.get("returncode") == 1 for row in records(capsys))


def test_failed_snapshot_retains_evidence_and_checks_source(source: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def fail(**kwargs: object) -> None:
        raise release_check.SnapshotError("write_failed")
    monkeypatch.setattr(release_check, "snapshot", fail)
    assert run(source) == 1
    captured = capsys.readouterr()
    assert "write_failed" in captured.err
    result = [json.loads(line) for line in captured.out.splitlines()]
    assert Path(next(row["evidence"] for row in result if "evidence" in row)).is_dir()
    assert next(row["source_unchanged"] for row in result if "source_unchanged" in row)


def test_node_failure(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (source / release_check._NODE_FILES[0]).write_text(
        "require('node:test')('failure', () => { throw new Error('deliberate failure'); });\n"
    )
    assert run(source, "node") == 1
    child = next(row for row in records(capsys) if row.get("child") == "node")
    assert child["counts"]["fail"] == 1
    assert "deliberate failure" in Path(child["log"]).read_text()


def test_mutation_real_engine(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, "mutation") == 0
    result = records(capsys)
    child = next(row for row in result if row.get("child") == "mutation")
    report = json.loads(Path(child["log"]).read_text())
    assert (report["detected"], report["survived"], report["invalid"]) == (1, 0, 0)
    assert next(row["source_unchanged"] for row in result if "source_unchanged" in row)


def test_mutation_failure_propagates(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    table = source / "tests/mutations/auth_guards.py"
    table.write_text(table.read_text().replace('"VALUE = 0"', '"VALUE = 42"'))
    assert run(source, "mutation") == 1
    child = next(row for row in records(capsys) if row.get("child") == "mutation")
    assert json.loads(Path(child["log"]).read_text())["survived"] == 1


def test_stats_baseline_profile_equal(source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(source, "stats-baseline") == 0
    result = records(capsys)
    child = next(row for row in result if row.get("child") == "stats-baseline")
    assert child["ok"] is True
    assert child["counts"] == {
        "surfaces_total": 2,
        "equal": 2,
        "approved_expected_delta": 0,
        "unreviewed": 0,
    }
    report = report_from(child)
    assert report["scope"] == "selected-surfaces-only"
    assert report["blanket_module_or_file_identity_claimed"] is False
    # The child runs against the snapshot copy, never the source worktree.
    assert report["informational_file_digests"][0]["file_digest_changed"] is False
    assert next(row for row in result if "source_unchanged" in row)["source_unchanged"]


def test_stats_baseline_profile_refuses_unreviewed_change(
    source: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (source / "origin.py").write_text(
        "VALUE = 42\n\n\ndef helper(value):\n    return value + 2\n"
    )
    assert run(source, "stats-baseline") == 1
    result = records(capsys)
    child = next(row for row in result if row.get("child") == "stats-baseline")
    assert child["ok"] is False
    assert child["counts"]["unreviewed"] == 1
    text = Path(child["log"]).read_text()
    assert "unreviewed-change" in text
    assert "origin.py" in text
    assert next(row for row in result if "source_unchanged" in row)["source_unchanged"]


def test_stats_baseline_profile_malformed_manifest_is_never_green(
    source: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (source / "tests/fixtures/statistics_baseline_v1_6_0.json").write_text("{}")
    assert run(source, "stats-baseline") == 1
    child = next(row for row in records(capsys) if row.get("child") == "stats-baseline")
    assert child["ok"] is False
    assert child["empty_suite"] is True


def test_stats_baseline_new_paths_from(
    source: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A new, not-yet-committed manifest arrives through --paths-from only."""
    manifest = "tests/fixtures/statistics_baseline_v1_6_0.json"
    subprocess.run(
        ["git", "-C", str(source), "rm", "--cached", "-q", manifest],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(source), "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "commit", "-q", "-m", "untrack fixture manifest"],
        check=True, capture_output=True,
    )
    paths = tmp_path / "paths.txt"
    paths.write_text(f"{manifest}\n", encoding="utf-8")
    assert run(source, "stats-baseline", "--paths-from", str(paths)) == 0
    child = next(row for row in records(capsys) if row.get("child") == "stats-baseline")
    assert child["counts"]["equal"] == 2


# ---------------------------------------------------------------------------
# Replay profile (P2-11)
# ---------------------------------------------------------------------------


def _replay_report(**overrides: object) -> str:
    report = {
        "tool": "replay_check",
        "ok": True,
        "families_total": 4,
        "proved": 4,
        "failed": 0,
        "invalid": 0,
        "wrong_assertion": 0,
        "claim": "mutant_fallback_only",
    }
    report.update(overrides)
    return json.dumps(report)


def test_replay_report_requires_every_family_proved() -> None:
    """A partially-proved or noisy replay report is never accepted as green."""
    counts, accepted = release_check._parse_replay_report(_replay_report())
    assert accepted is True
    assert counts == {
        "families_total": 4,
        "proved": 4,
        "failed": 0,
        "invalid": 0,
        "wrong_assertion": 0,
    }

    for garbled in (
        _replay_report(proved=3),
        _replay_report(proved=0, families_total=0),
        _replay_report(failed=1, proved=3),
        _replay_report(invalid=1, proved=3),
        _replay_report(wrong_assertion=1, proved=3),
        _replay_report(error="cases_invalid"),
        json.dumps({"tool": "replay_check", "families_total": 4}),
        "not json at all",
        "",
    ):
        _counts, accepted = release_check._parse_replay_report(garbled)
        assert accepted is False, garbled


def test_stub_replay_report_with_unproved_families_is_not_green() -> None:
    """A tool that claims rc 0 while proving fewer families is refused."""
    stub = json.dumps(
        {
            "tool": "replay_check",
            "ok": True,
            "families_total": 5,
            "proved": 4,
            "failed": 0,
            "invalid": 1,
            "wrong_assertion": 0,
            "exit_code": 0,
        }
    )
    counts, accepted = release_check._parse_replay_report(stub)
    assert accepted is False
    assert counts["proved"] < counts["families_total"]


@pytest.mark.parametrize(
    ("outer", "requested", "upper"),
    [
        (600.0, None, 600),
        (1500.0, None, 1500),
        (300.0, None, 300),
        (222.0, None, 222),
        (222.0, None, 222),
        (600.0, 30, 600),
        (600.0, 500, 600),
    ],
)
def test_replay_detector_bound_is_strictly_below_outer(
    outer: float, requested: int | None, upper: int
) -> None:
    """The inner per-detector timeout must fire before the outer child timeout."""
    inner = release_check._replay_detector_timeout(outer, requested)
    assert 0 < inner < upper
    if requested is not None:
        assert inner <= requested


@pytest.mark.parametrize("outer", [0, 1, 5, 17, 221.9])
def test_replay_bound_rejects_nonsense_outer_timeouts(outer: float) -> None:
    """An outer bound too small for the run count is a usage error, not a bound."""
    with pytest.raises(ValueError) as error:
        release_check._replay_detector_timeout(outer)
    assert "minimum" in str(error.value)


def test_replay_bound_accounts_for_every_pytest_run() -> None:
    """The inner bound is derived from the outer bound and the child's run count."""
    # Observe the real frozen engine's baseline invocation; do not mirror its literal.
    import ast
    import inspect

    from tools import mutation_check
    calls = [node for node in ast.walk(ast.parse(inspect.getsource(mutation_check._run_mutation_check)))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
             and node.func.id == "check_baseline"]
    timeout = next(keyword.value for keyword in calls[0].keywords if keyword.arg == "timeout")
    floor = eval(compile(ast.Expression(timeout), "<engine timeout>", "eval"), {"timeout": 1})
    assert release_check._REPLAY_BASELINE_FLOOR == floor
    # Cross-check the real declaration; the slow historical replay test also
    # spies on actual engine/evidence invocations (3 per member + 2 historical).
    declaration = json.loads((Path(release_check.__file__).parents[1]
                              / "tests/systemic/replay_cases.json").read_text())
    assert sum(len(family["transformations"]) for family in declaration["families"]) == 5
    # Five baseline/mutant/evidence triples plus both historical processes.
    assert release_check._REPLAY_PYTEST_RUNS == 5 * 3 + 2
    minimum = 5 * floor + 12 + floor
    assert release_check._REPLAY_MIN_OUTER_TIMEOUT == minimum
    with pytest.raises(ValueError):
        release_check._replay_detector_timeout(minimum - 0.01)
    for outer in (minimum, 300, 600, 1500):
        inner = release_check._replay_detector_timeout(outer)
        assert inner >= 1
        cost = 5 * max(floor, inner) + 12 * inner
        assert cost + max(floor, inner) <= outer


def test_replay_profile_rejects_a_tiny_outer_timeout(
    source: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's accepted 17s bound refuses before copying or spawning."""
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("tiny replay timeout launched work")
    monkeypatch.setattr(release_check, "snapshot", forbidden)
    monkeypatch.setattr(release_check, "_child", forbidden)
    assert run(source, "replay", "--timeout", "17") == 1
    payload = next(
        json.loads(line)
        for line in capsys.readouterr().err.splitlines()
        if line.startswith("{")
    )
    assert payload["error"] == "invalid_replay_timeout"
    assert payload["minimum"] == release_check._REPLAY_MIN_OUTER_TIMEOUT
    assert payload["pytest_runs"] == release_check._REPLAY_PYTEST_RUNS



def test_replay_child_uses_the_smaller_detector_bound(
    source: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The dispatched replay command carries the clamped inner bound."""
    seen: list[tuple[str, list[str], float]] = []

    def fake(command: list[str], copy: Path, label: str, timeout: float) -> bool:
        seen.append((label, command, timeout))
        return True

    monkeypatch.setattr(release_check, "_child", fake)
    assert run(source, "replay", "--timeout", "600") == 0
    label, command, outer = next(row for row in seen if row[0] == "replay")
    inner = int(command[command.index("--timeout") + 1])
    assert label == "replay"
    assert 0 < inner < int(outer)
    assert inner == release_check._replay_detector_timeout(outer, None)


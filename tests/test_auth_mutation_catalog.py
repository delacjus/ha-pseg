"""The migrated catalog preserves the frozen legacy AST values and detectors."""

import ast
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

from tools._snapshot import snapshot
from tools.mutation_check import load_table, resolve_target_path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "tests/mutations/auth_guards.py"
FROZEN = CATALOG.with_name("auth_guards_original.json")


def test_catalog_preserves_original_ast_rows() -> None:
    # Frozen at test-write time with git show 804451d:tests/auth_guard_mutations.py.
    # No git history is required at runtime, including inside release snapshots.
    frozen = json.loads(FROZEN.read_text())
    tree = ast.parse(CATALOG.read_text())
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)]
    namespace = {}
    exec(compile(ast.Module(body=assignments, type_ignores=[]), str(CATALOG), "exec"), namespace)
    rows = namespace["MUTATIONS"]
    assert len(rows) == len(frozen) == 60
    assert len({row[0] for row in rows}) == 60
    assert json.loads(json.dumps([row[:5] for row in rows])) == frozen
    assert rows == runpy.run_path(str(CATALOG))["MUTATIONS"]
    for row, original in zip(rows, frozen, strict=True):
        for index in (2, 3):
            assert isinstance(row[index], tuple) == isinstance(original[index], list)
    exceptions = {row[0]: row[5] for row in rows if len(row) == 6}
    # Exhaustive allowlist: any new typed-exception detection needs review.
    assert exceptions == {
        "37-hourly-root-dict-validation": {
            "phase": "call", "type": "homeassistant.helpers.update_coordinator.UpdateFailed",
        },
        "54-non-meter-series-skip-order": {
            "phase": "call", "type": "homeassistant.helpers.update_coordinator.UpdateFailed",
        },
    }


def test_catalog_preimages_unique() -> None:
    for row in load_table(CATALOG):
        text = resolve_target_path(ROOT, row["filename"]).read_text()
        for before in row["befores"]:
            assert text.count(before) == 1, row["label"]


def test_catalog_detectors_collect_in_copy(tmp_path: Path) -> None:
    copy = tmp_path / "source"
    snapshot(source=ROOT, dest=copy)
    nodes = sorted({node for row in load_table(CATALOG) for node in row["test_nodes"]})
    # An inner pytest must collect from its disposable cwd, including bare imports.
    env = os.environ.copy()
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONHOME"):
        env.pop(name, None)
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
                "PYTHONPATH": str(copy) + os.pathsep + str(copy / "tests")})
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *nodes],
        cwd=copy, env=env, capture_output=True, text=True, timeout=35,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    collected = set(result.stdout.splitlines())
    for node in nodes:
        assert any(item == node or item.startswith(node + "[") for item in collected), node

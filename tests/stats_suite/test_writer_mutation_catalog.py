"""Validate the S5 table's exact preimages, physical crosswalk and real nodes."""

import ast
import os
from pathlib import Path
import runpy
import subprocess
import sys

from tools._snapshot import snapshot
from tools.mutation_check import apply_mutation, load_table, resolve_target_path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tests/mutations/statistics_writer.py"


def test_writer_catalog_preimages_and_function_ownership():
    """Every independently labelled fault changes compilable real writer code."""
    rows = load_table(CATALOG)
    coverage = runpy.run_path(str(CATALOG))["COVERAGE"]
    assert len(rows) == len(coverage) == 13
    assert {row["label"] for row in rows} == set(coverage)
    assert len({(row["filename"], row["befores"], row["afters"]) for row in rows}) == len(rows)
    for row in rows:
        assert row["expected"] is None, "S5 requires assertions, no exception allowance"
        assert row["befores"] != row["afters"], row["label"]
        path = resolve_target_path(ROOT, row["filename"])
        assert path.name in {"coordinator.py", "statistics_state.py", "statistics_hourly.py"}
        source = path.read_text()
        target = coverage[row["label"]][0].split(".")[-1]
        functions = [
            node for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == target
        ]
        assert len(functions) == 1
        segment = ast.get_source_segment(source, functions[0])
        for before in row["befores"]:
            assert source.count(before) == 1, row["label"]
            assert before.strip() in segment, (row["label"], target)
        changed = apply_mutation(source, row["befores"], row["afters"], row["label"])
        assert changed != source
        compile(changed, str(path), "exec")


def test_writer_catalog_physical_coverage_and_exclusions():
    """Every row names a systemic detector plus a preserved related node."""
    namespace = runpy.run_path(str(CATALOG))
    for row in load_table(CATALOG):
        target, physical_assertion, link = namespace["COVERAGE"][row["label"]]
        assert target and len(physical_assertion) > 20
        assert all(node.startswith("tests/stats_suite/") for node in row["test_nodes"])
        assert link.startswith(("tests/test_statistics_recorder.py::", "tests/independent/",
                                "tests/stats_suite/test_fault_points.py::"))
    assert set(namespace["EXCLUDED"]) == {
        "duplicate-queue-submission", "partial-sql-error-as-success", "raw-hour-start-reparse",
    }
    assert all(len(reason) > 80 for reason in namespace["EXCLUDED"].values())


def test_writer_catalog_detectors_and_links_collect_in_copy(tmp_path):
    """Resolve actual exact pytest nodes (including named parameter cases)."""
    copy = tmp_path / "source"
    snapshot(source=ROOT, dest=copy)
    coverage = runpy.run_path(str(CATALOG))["COVERAGE"]
    nodes = sorted({
        node for row in load_table(CATALOG) for node in row["test_nodes"]
    } | {item[2] for item in coverage.values()})
    env = os.environ.copy()
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONHOME"):
        env.pop(name, None)
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
                "PYTHONPATH": str(copy) + os.pathsep + str(copy / "tests")})
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         *nodes], cwd=copy, env=env, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    collected = set(result.stdout.splitlines())
    for node in nodes:
        assert any(item == node or item.startswith(node + "[") for item in collected), node

"""Exact pytest collection closure, including cross-directory marker isolation."""

import json

from tests.support.factory import exit_boundary_ids
from tests.systemic import dispatch_cases, exit_cases, response_cases
from tests.systemic.coverage_data import (
    BASELINE_FAST,
    BASELINE_MODULE_MARKS,
    GENERATED_INVENTORY,
    MANDATORY_FAST,
    NEW_MODULES,
    ROOT,
    collected_nodes as collected_nodes,
    module_inventory,
    require_node,
)
from tools import pairwise


def test_prephase_fast_inventory_is_preserved(collected_nodes):
    inventory = module_inventory(collected_nodes, fast_only=True)
    prior = {module: value for module, value in inventory.items() if module not in NEW_MODULES}
    assert prior == BASELINE_FAST, "pre-phase exact fast node inventory changed"
    additions = {module: value for module, value in inventory.items() if module in NEW_MODULES}
    assert set(additions) == NEW_MODULES and all(count for count, _ in additions.values())
    print("P2-09 fast delta:", {module: count for module, (count, _) in additions.items()})


def test_cross_directory_module_markers_are_unchanged(collected_nodes):
    for node, facts in collected_nodes.items():
        module = node.split("::", 1)[0]
        expected = BASELINE_MODULE_MARKS.get(module, ())
        assert tuple(facts["module_marks"]) == expected, (
            "cross-directory module marker contamination",
            node,
            facts["module_marks"],
            expected,
        )


def test_mandatory_fast_nodes_are_exact_and_runnable(collected_nodes):
    assert MANDATORY_FAST
    for node in MANDATORY_FAST:
        require_node(collected_nodes, node, fast=True)


def test_generated_g1_g2_g3_exact_collection(collected_nodes):
    inventory = module_inventory(collected_nodes)
    assert {module: inventory[module] for module in GENERATED_INVENTORY} == GENERATED_INVENTORY
    matrices = (
        (
            dispatch_cases.FAST_CASES,
            "test_dispatch_fence",
            "test_fast_dispatch_fence_representative",
            True,
        ),
        (
            dispatch_cases.SLOW_CASES,
            "test_dispatch_fence",
            "test_slow_full_boundary_retirement_sweep",
            False,
        ),
        (exit_cases.FAST_CASES, "test_exit_checkpoint", "test_fast_exit_checkpoint_control", True),
        (exit_cases.SLOW_CASES, "test_exit_checkpoint", "test_slow_exit_checkpoint_sweep", False),
        (response_cases.FAST_CASES, "test_response_corpus", "test_fast_case", True),
        (response_cases.SLOW_CASES, "test_response_corpus", "test_slow_case", False),
    )
    for cases, module, function, fast in matrices:
        expected = {f"tests/systemic/{module}.py::{function}[{case.case_id}]" for case in cases}
        actual = {
            node
            for node in collected_nodes
            if node.split("[", 1)[0] == f"tests/systemic/{module}.py::{function}"
        }
        assert actual == expected, (module, function, expected - actual, actual - expected)
        for node in expected:
            require_node(collected_nodes, node, fast=fast)
            if not fast:
                assert "slow" in collected_nodes[node]["marks"], node
    assert not dispatch_cases.sweep_coverage_problems()
    assert not dispatch_cases.requirement_problems(dispatch_cases.FAST_CASES)
    assert not exit_cases.coverage_problems()
    assert set(exit_cases.boundary_coverage()) == set(exit_boundary_ids())


def test_pairwise_pairs_and_rows_reach_collected_assertions(collected_nodes):
    path = ROOT / "tests/systemic/response_covering.json"
    assert pairwise.check_file(path) == []
    model = json.loads(path.read_text())
    required = pairwise.required_pairs(model)
    covered = set()
    for row in model["rows"]:
        covered |= pairwise.pair_keys(pairwise.row_values(row))
        function = "test_fast_case" if row["tier"] == "fast" else "test_slow_case"
        node = f"tests/systemic/test_response_corpus.py::{function}[{row['id']}]"
        require_node(collected_nodes, node, fast=row["tier"] == "fast")
    assert required <= covered, required - covered
    for row in pairwise.MANDATORY_FAST:
        node = f"tests/systemic/test_response_corpus.py::test_fast_case[{row['id']}]"
        require_node(collected_nodes, node, fast=True)

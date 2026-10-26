"""Reject omissions against independently transcribed review/provenance anchors."""

import ast
import json
from pathlib import Path
from uuid import UUID

import pytest

from tests.systemic.coverage_data import (
    ROOT,
    SOURCE_ALIASES,
    SOURCE_FINDINGS,
    collected_nodes as collected_nodes,
    require_node,
    require_reviewed_evidence,
)
from tests.systemic.findings import FINDINGS, KNOWN_GAPS


def test_review_inventory_is_complete():
    ids = [finding["id"] for finding in FINDINGS]
    assert len(ids) == len(set(ids)), "duplicate finding IDs"
    assert set(ids) == set(SOURCE_FINDINGS), (
        "missing review finding",
        set(SOURCE_FINDINGS) - set(ids),
        set(ids) - set(SOURCE_FINDINGS),
    )
    by_id = {finding["id"]: finding for finding in FINDINGS}
    for alias, (fid, fix_source, node) in SOURCE_ALIASES.items():
        finding = by_id[fid]
        assert alias in finding["aliases"], f"missing source alias: {alias}"
        assert fix_source in finding["source_fixes"], (alias, "missing fix lineage")
        assert node in finding["fast_cases"], (alias, "missing hourly assertion")
    assert {f["family"] for f in FINDINGS} == {"α", "β", "γ", "δ", "ε"}
    assert {f["id"].split("-")[0] for f in FINDINGS} == {
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
        "R7B",
        "R8",
        "R9",
        "HOURLY",
    }


@pytest.mark.parametrize("finding", FINDINGS, ids=[f["id"] for f in FINDINGS])
def test_finding_has_exact_assertion_evidence(finding, collected_nodes):
    fid = finding["id"]
    source_kb, module, function = SOURCE_FINDINGS[fid]
    assert finding["source_kb"] == source_kb
    UUID(source_kb)
    assert finding["aliases"] and finding["evidence"]
    assert finding["invariant"] in {f"I{i}" for i in range(1, 13)}
    # Identity comes from promoted provenance, not counting tests. The probe
    # function is the review's concrete assertion anchor; all parameter IDs exist.
    provenance = json.loads((ROOT / module).parent.joinpath("provenance.json").read_text())
    assert provenance["status"] == "active"
    assert any(p["relative_path"] == Path(module).name for p in provenance["promoted_files"])
    assert provenance["sources"] and all(p["archived_sha256"] for p in provenance["sources"])
    tree = ast.parse((ROOT / module).read_text())
    anchor = next(
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function
    )
    if finding["provenance_cases"]:
        assert any(isinstance(n, ast.Assert) for n in ast.walk(anchor)), fid
    else:
        assert fid in {"R8-N1", "R8-N3"}, "unjustified missing promoted assertion"
    for node in finding["provenance_cases"]:
        assert node.split("::", 1)[0] == module
        assert node.split("::", 1)[1].split("[", 1)[0] == function
        require_node(collected_nodes, node, fast=True)
    assert finding["fast_cases"], f"no fast assertion evidence: {fid}"
    for node in finding["fast_cases"]:
        require_node(collected_nodes, node, fast=True)
    for node in finding["slow_cases"]:
        require_node(collected_nodes, node)
        assert "slow" in collected_nodes[node]["marks"], node
        assert node.startswith("tests/systemic/"), node
    require_reviewed_evidence(finding, collected_nodes)
    assert finding["slow_cases"] or finding["systemic_gap"].strip(), fid
    original = {
        row[0]
        for row in json.loads((ROOT / "tests/mutations/auth_guards_original.json").read_text())
    }
    assert set(finding["original_mutants"]) <= original, fid
    assert finding["original_mutants"] or finding["new_mutant_need"].strip(), fid


def test_every_original_mutant_is_accounted_for():
    original = {
        row[0]
        for row in json.loads((ROOT / "tests/mutations/auth_guards_original.json").read_text())
    }
    mapped = {label for finding in FINDINGS for label in finding["original_mutants"]}
    # This extra original row is a human account-proof control, not a ranked
    # defect; it remains an explicit P2-10 mapping obligation.
    assert original - mapped == {"setup-human-account-proof"}


def test_carried_gaps_are_explicit_and_never_claimed_covered():
    gaps = {gap["id"]: gap for gap in KNOWN_GAPS}
    assert set(gaps) == {"P2-08-SECURITY", "P2-07-POLICY-PERSIST"}
    for gap in gaps.values():
        UUID(gap["source_kb"])
        assert gap["reason"].strip() and gap["new_mutant_need"].strip()
        assert not gap.get("fast_cases") and not gap.get("slow_cases")
    assert "HTML" in gaps["P2-08-SECURITY"]["reason"]
    assert "_persist_auth_metadata" in gaps["P2-07-POLICY-PERSIST"]["reason"]

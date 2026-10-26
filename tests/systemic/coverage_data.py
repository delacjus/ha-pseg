"""Collection evidence and reviewed pre-P2-09 inventory (HEAD 58398c2).

Digests commit to sorted, complete exact node IDs per module, not counts or
substring selectors. The literal finding inventory is separately transcribed
from review references; deleting a registry row cannot redefine completeness.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXCLUDED_MARKS = frozenset({"slow", "nightly", "quarantine"})
NEW_MODULES = frozenset(
    {
        "tests/systemic/test_policy_properties.py",
        "tests/systemic/test_findings_registry.py",
        "tests/systemic/test_coverage_meta.py",
        "tests/systemic/test_auth_systemic_catalog.py",
    }
)


def node_digest(nodes):
    """Unambiguous sorted full-node inventory, including every parameter ID."""
    return hashlib.sha256(("\n".join(sorted(nodes)) + "\n").encode()).hexdigest()


def module_inventory(nodes, *, fast_only=False):
    modules = defaultdict(list)
    for node, facts in nodes.items():
        if fast_only and EXCLUDED_MARKS.intersection(facts["marks"]):
            continue
        modules[node.split("::", 1)[0]].append(node)
    return {module: (len(ids), node_digest(ids)) for module, ids in modules.items()}


@pytest.fixture(scope="session")
def collected_nodes(tmp_path_factory):
    """Collect all directories together, through pytest's item model.

    Subprocess only collects: it never runs these meta-tests recursively. Plugin,
    log and basetemp live beside the copy in the external pytest runtime.
    """
    runtime = tmp_path_factory.mktemp("p209-collection")
    output = runtime / "items.json"
    program = textwrap.dedent("""
        import ast, hashlib, inspect, json, sys, textwrap
        from pathlib import Path
        import pytest
        class Inventory:
            def pytest_collection_finish(self, session):
                rows = {}
                for item in session.items:
                    try:
                        tree = ast.parse(textwrap.dedent(inspect.getsource(item.obj)))
                        assertion = any(isinstance(n, ast.Assert) for n in ast.walk(tree))
                        fingerprint = hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()
                        bypass = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                                     and n.func.attr in {'skip', 'xfail'} for n in ast.walk(tree))
                    except (OSError, TypeError, SyntaxError):
                        assertion, bypass, fingerprint = False, True, None
                    rows[item.nodeid] = {
                        'marks': sorted({m.name for m in item.iter_markers()}),
                        'module_marks': sorted({m.name for m in item.getparent(pytest.Module).own_markers}),
                        'assertion': assertion, 'bypass': bypass,
                        'assertion_fingerprint': fingerprint,
                        'param_id': item.callspec.id if hasattr(item, 'callspec') else None,
                    }
                Path(sys.argv[1]).write_text(json.dumps(rows))
        raise SystemExit(pytest.main(['--collect-only', '-q', '-p', 'no:cacheprovider',
                                     '--basetemp', sys.argv[2], 'tests'], plugins=[Inventory()]))
    """)
    env = os.environ.copy()
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONHOME", "PYTHONPATH"):
        env.pop(name, None)
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0", RUFF_NO_CACHE="true")
    result = subprocess.run(
        [sys.executable, "-B", "-c", program, str(output), str(runtime / "pytest")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    (runtime / "collection.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    rows = json.loads(output.read_text())
    assert rows, "empty cross-directory collection"
    return rows


def require_node(nodes, node, *, fast=False):
    """No prefix/parent fallback: a parameterized parent is not a collected case."""
    assert node in nodes, f"uncollected exact node: {node}"
    facts = nodes[node]
    assert not {"skip", "skipif", "xfail"}.intersection(facts["marks"]), node
    assert facts["assertion"] and not facts["bypass"], f"no executable assertion: {node}"
    if fast:
        assert not EXCLUDED_MARKS.intersection(facts["marks"]), f"mandatory fast moved: {node}"


def require_reviewed_evidence(finding, nodes):
    """Bind each invariant to reviewed bodies, guards and exact parameter IDs.

    Pins below are literal review inputs, never derived from FINDINGS at runtime.
    A whole-function AST fingerprint includes every specific assert expression,
    its control-flow guards, setup and decorators. This rejects replacing an
    invariant assertion while leaving an unrelated assert in the same body.
    Exact per-role node digests pin the reviewed parameter allowlist separately:
    R9's informational parameter shares a body but bypasses the cookie assertion.
    Changing either the evidence or its assertions requires another review.
    """
    fid = finding["id"]
    invariant, *digests = REVIEWED_FINDING_EVIDENCE[fid]
    assert finding["invariant"] == invariant, f"reviewed invariant changed: {fid}"
    for role, expected in zip(("provenance_cases", "fast_cases", "slow_cases"), digests):
        assert node_digest(finding[role]) == expected, f"unreviewed {role} evidence: {fid}"
        for node in finding[role]:
            require_node(nodes, node, fast=role != "slow_cases")
            function = node.split("[", 1)[0]
            assert nodes[node]["assertion_fingerprint"] == REVIEWED_ASSERTION_BODIES[function], (
                "reviewed assertion body changed", fid, node
            )
            param_id = node.split("[", 1)[1][:-1] if "[" in node else None
            assert nodes[node]["param_id"] == param_id, (fid, node, "parameter identity")


# R6-N2 is a source-backed alias, not a second systemic-coverage claim. The
# assertion rejects the foreign hourly cookie while keeping the proven daily jar.
SOURCE_ALIASES = {
    "R6-N2": (
        "R6-F1",
        "a6c8e412-9034-4d7c-b811-20261023c601",
        "tests/test_auth_review_r5_regressions.py::test_daily_and_hourly_meter_swap_and_fresh_manual_flow_semantics",
    ),
}


# R7 was interrupted; R7B is its completed successor. R1–R5 provenance files
# accidentally reuse a NY-wall reviewer UUID. SOURCE_FINDINGS pins actual auth
# review IDs, with the promoted function as an independently auditable anchor.
SOURCE_FINDINGS = {
    "R1-1": (
        "c5f4a8b2-1093-4d6e-8baf-9c20261023a1",
        "tests/independent/auth_r1/test_independent_auth_r1.py",
        "test_actual_entry_reload_does_not_overlap_old_and_new_renewal",
    ),
    "R1-2": (
        "c5f4a8b2-1093-4d6e-8baf-9c20261023a1",
        "tests/independent/auth_r1/test_independent_auth_r1.py",
        "test_failed_first_refresh_persists_terminal_admission",
    ),
    "R1-3": (
        "c5f4a8b2-1093-4d6e-8baf-9c20261023a1",
        "tests/independent/auth_r1/test_independent_auth_r1.py",
        "test_poll_failure_does_not_rearm_unconfirmed_rotation",
    ),
    "R1-4": (
        "c5f4a8b2-1093-4d6e-8baf-9c20261023a1",
        "tests/independent/auth_r1/test_independent_auth_r1.py",
        "test_retired_keepalive_cannot_dismiss_replacement_auth_issue",
    ),
    "R1-5": (
        "c5f4a8b2-1093-4d6e-8baf-9c20261023a1",
        "tests/independent/auth_r1/test_independent_auth_r1.py",
        "test_uncertain_metadata_refuses",
    ),
    "R1-6": (
        "c5f4a8b2-1093-4d6e-8baf-9c20261023a1",
        "tests/independent/auth_r1/test_independent_auth_r1.py",
        "test_success_without_rotation_does_not_authorize_transient_retry",
    ),
    "R1-7": (
        "c5f4a8b2-1093-4d6e-8baf-9c20261023a1",
        "tests/independent/auth_r1/test_independent_auth_r1.py",
        "test_probe_rotation_is_rolled_back_after_transient_renewal",
    ),
    "R2-1": (
        "76fd81f4-2e7c-4575-87bd-e7052a5ef2d8",
        "tests/independent/auth_r2/test_independent_auth_r2.py",
        "test_d1_poll_keeps_verified_renewal_after_post_renewal_hiccup",
    ),
    "R2-2": (
        "76fd81f4-2e7c-4575-87bd-e7052a5ef2d8",
        "tests/independent/auth_r2/test_independent_auth_r2.py",
        "test_d2_runtime_poll_in_cooldown_is_auth_failure_and_kills_poll_schedule",
    ),
    "R2-3": (
        "76fd81f4-2e7c-4575-87bd-e7052a5ef2d8",
        "tests/independent/auth_r2/test_independent_auth_r2.py",
        "test_d3_uncertain_state_never_prompts_human",
    ),
    "R2-4": (
        "76fd81f4-2e7c-4575-87bd-e7052a5ef2d8",
        "tests/independent/auth_r2/test_independent_auth_r2.py",
        "test_d4_rotation_seen_on_plain_dashboard_rearms_next_renewal",
    ),
    "R2-5": (
        "76fd81f4-2e7c-4575-87bd-e7052a5ef2d8",
        "tests/independent/auth_r2/test_independent_auth_r2_extra.py",
        "test_e3_security_step_seen_by_poll_fallback_does_not_stop_keepalive_cookie_retry",
    ),
    "R3-N1": (
        "c2e982ad-c000-4182-ae70-7b748ad41ddc",
        "tests/independent/auth_r3/test_independent_auth_r3.py",
        "test_p1_setup_verified_renewal_then_daily_timeout_loses_jar",
    ),
    "R3-N2": (
        "c2e982ad-c000-4182-ae70-7b748ad41ddc",
        "tests/independent/auth_r3/test_independent_auth_r3.py",
        "test_p2_cooldown_without_earned_retry_is_a_fake_wait",
    ),
    "R3-N3": (
        "c2e982ad-c000-4182-ae70-7b748ad41ddc",
        "tests/independent/auth_r3/test_independent_auth_r3.py",
        "test_p5_real_security_reply_latches_then_reload_limit",
    ),
    "R4-F1": (
        "4c38eaf4-c5ce-4ea9-bf4b-a232f5a42618",
        "tests/independent/auth_r4/test_independent_auth_r4.py",
        "test_optional_hourly_failed_response_cannot_replace_proof_jar",
    ),
    "R4-F2": (
        "4c38eaf4-c5ce-4ea9-bf4b-a232f5a42618",
        "tests/independent/auth_r4/test_independent_auth_r4.py",
        "test_real_unload_retires_saved_password_fallback",
    ),
    "R5-A": (
        "8d06a670-6ddb-575f-9f24-f14e8d92d21f",
        "tests/independent/auth_r5/test_independent_auth_r5.py",
        "test_saml_redirect_cannot_dispatch_new_post_after_retirement",
    ),
    "R5-B": (
        "8d06a670-6ddb-575f-9f24-f14e8d92d21f",
        "tests/independent/auth_r5/test_independent_auth_r5.py",
        "test_postproof_failed_dashboard_cookie_cannot_be_promoted_by_next_poll",
    ),
    "R5-C": (
        "8d06a670-6ddb-575f-9f24-f14e8d92d21f",
        "tests/independent/auth_r5/test_independent_auth_r5.py",
        "test_invalid_hourly_200_does_not_replace_proven_whole_jar",
    ),
    "R5-D": (
        "8d06a670-6ddb-575f-9f24-f14e8d92d21f",
        "tests/independent/auth_r5/test_independent_auth_r5.py",
        "test_latest_valid_hourly_jar_survives_cancel_or_stop",
    ),
    "R6-F1": (
        "09006854-467a-42b9-b137-7a4eae1e2b8b",
        "tests/independent/auth_r6/test_independent_auth_r6.py",
        "test_daily_leg_must_validate_before_confirming_cookie",
    ),
    "R6-F2": (
        "09006854-467a-42b9-b137-7a4eae1e2b8b",
        "tests/independent/auth_r6/test_independent_auth_r6.py",
        "test_backfill_chunk_cookie_never_promoted",
    ),
    "R6-F3": (
        "09006854-467a-42b9-b137-7a4eae1e2b8b",
        "tests/independent/auth_r6/test_independent_auth_r6_extra.py",
        "test_owner_predicate_stays_true_during_own_cookie_write",
    ),
    "R6-N1": (
        "09006854-467a-42b9-b137-7a4eae1e2b8b",
        "tests/independent/auth_r7b/test_independent_auth_r7b.py",
        "test_checkpoint_old_ack_preserves_new_publish",
    ),
    "R7B-1": (
        "e6291b73-520d-44f0-9c86-20261024a007",
        "tests/independent/auth_r7b/test_independent_auth_r7b.py",
        "test_backfill_parser_fault_quarantines_every_cookie",
    ),
    "R7B-2": (
        "e6291b73-520d-44f0-9c86-20261024a007",
        "tests/independent/auth_r7b/test_independent_auth_r7b.py",
        "test_empty_expected_meter_does_not_prove_unrelated_records",
    ),
    "R7B-3": (
        "e6291b73-520d-44f0-9c86-20261024a007",
        "tests/independent/auth_r7b/test_independent_auth_r7b.py",
        "test_rejected_daily_identity_cannot_teach_entry_new_account",
    ),
    "R7B-4": (
        "e6291b73-520d-44f0-9c86-20261024a007",
        "tests/independent/auth_r7b/test_independent_auth_r7b.py",
        "test_own_write_failure_keeps_actual_baseline_coherent",
    ),
    "R8-1": (
        "97312f6b-90bd-4483-a80b-8fb5d29f6b6f",
        "tests/independent/auth_r8/test_independent_auth_r8.py",
        "test_p1_fresh_cookie_sign_in_with_lagging_daily_window",
    ),
    "R8-2": (
        "97312f6b-90bd-4483-a80b-8fb5d29f6b6f",
        "tests/independent/auth_r8/test_independent_auth_r8.py",
        "test_p2_rejected_daily_real_refresh_keeps_previous_reading",
    ),
    "R8-N1": (
        "97312f6b-90bd-4483-a80b-8fb5d29f6b6f",
        "tests/independent/auth_r8/test_independent_auth_r8.py",
        "test_p5_daily_proven_successor_learning_vs_hourly_overwrite",
    ),
    "R8-N2": (
        "97312f6b-90bd-4483-a80b-8fb5d29f6b6f",
        "tests/independent/auth_r8/test_independent_auth_r8.py",
        "test_p4_failed_leg_cookie_never_dispatched_or_persisted",
    ),
    "R8-N3": (
        "97312f6b-90bd-4483-a80b-8fb5d29f6b6f",
        "tests/independent/auth_r7b/test_independent_auth_r7b.py",
        "test_empty_expected_meter_does_not_prove_unrelated_records",
    ),
    "R9-1": (
        "5c9e1d27-4b3a-4f8e-9a61-20261024e9a9",
        "tests/independent/auth_r9/test_independent_auth_r9.py",
        "test_q1_renewal_proof_shape_anomaly_cookie",
    ),
    "R9-N1": (
        "5c9e1d27-4b3a-4f8e-9a61-20261024e9a9",
        "tests/independent/auth_r9/test_independent_auth_r9.py",
        "test_q3_label_identity_flow_cookie_acceptance",
    ),
    "HOURLY-AUTH": (
        "6ea61c6e-cba2-4ac5-8828-7f9555f22f3e",
        "tests/independent/hourly_r5/test_independent_hourly_r5.py",
        "test_hourly_auth_vs_transient_and_daily_authority",
    ),
    "HOURLY-REDIRECT": (
        "6ea61c6e-cba2-4ac5-8828-7f9555f22f3e",
        "tests/independent/hourly_r5/test_independent_hourly_r5.py",
        "test_hourly_login_redirect_is_typed_auth_loss",
    ),
}

BASELINE_FAST = {
    "tests/independent/auth_r1/test_independent_auth_r1.py": (
        15,
        "070412711276177206e93bd61b11d55c34d306188c04604e4a199c9cb9ae7fc1",
    ),
    "tests/independent/auth_r2/test_independent_auth_r2.py": (
        26,
        "17c69a71fb1ee93faed7a3941ca67c360f83c6a5f23f4dfbd6aa726011b104d3",
    ),
    "tests/independent/auth_r2/test_independent_auth_r2_extra.py": (
        3,
        "fec31a135865d31d6109dc1aa0cedbce8732184708a8cf37c190822dd48590e0",
    ),
    "tests/independent/auth_r3/test_independent_auth_r3.py": (
        29,
        "53b29a798321457622e978474898f218f4217b3feed09f06e9d7729db4620bbe",
    ),
    "tests/independent/auth_r4/test_independent_auth_r4.py": (
        29,
        "fef47559a6cf3a44727eee62681e5b5094da533b9da2ba968546d14803443897",
    ),
    "tests/independent/auth_r5/test_independent_auth_r5.py": (
        58,
        "f4976a98eea5a1edac4cd3511c6dce277560bb9348d1c818343b95d836c91bb4",
    ),
    "tests/independent/auth_r6/test_independent_auth_r6.py": (
        38,
        "cc934b4a7c9083791c4ef5a55ffe2740f7318fa59fcff83df18bfe70fd29aed1",
    ),
    "tests/independent/auth_r6/test_independent_auth_r6_extra.py": (
        7,
        "8594165f41b8def22dac6cc9fa0fa5e1c1c9219154cbf4ecf09d7129e7ed55a5",
    ),
    "tests/independent/auth_r6/test_independent_auth_r6_flows.py": (
        2,
        "e1de207d63daeb3e69be9fb85a9019a97bf47d04c77c69e3041a6c89950d3698",
    ),
    "tests/independent/auth_r6/test_independent_auth_r6_race.py": (
        1,
        "e58205f1b84e83d5c13e08dbb17b927e84bdd3888ad8b3333e6352b9f8a9506f",
    ),
    "tests/independent/auth_r7b/test_independent_auth_r7b.py": (
        29,
        "83d70f256f63030215fdd1f9a280da54376af589148b74eef374182b63004621",
    ),
    "tests/independent/auth_r8/test_independent_auth_r8.py": (
        22,
        "fe5f417500ac90585f126a3dc3f2eca8b0b9a4bbf8ee75b91183c030630d1fb4",
    ),
    "tests/independent/auth_r9/test_independent_auth_r9.py": (
        8,
        "adcb621c8b00eac93c9a732fd11b90375a3d8948d6cda5eb90d44bfd69d490dc",
    ),
    "tests/independent/hourly_r5/test_independent_hourly_guards.py": (
        19,
        "fb04302347738de766833a5aaa557a49f11243ee3c429509c51ee9da2713fed1",
    ),
    "tests/independent/hourly_r5/test_independent_hourly_physical_failure.py": (
        2,
        "eea0579f075d686434dca69919ce38b3c51a382acdc60ee5c45ec3586f7a4f87",
    ),
    "tests/independent/hourly_r5/test_independent_hourly_r5.py": (
        39,
        "de4148aa05d59750cedc43bb3372cacda83186b30ba90fe636749ef694fd856d",
    ),
    "tests/independent/nywall/test_independent_nywall_contract.py": (
        16,
        "f0be5644ecbae9844795f75329e5cd82b982376e2cc9659e63e3abfe054b7812",
    ),
    "tests/independent/nywall/test_independent_nywall_labels.py": (
        34,
        "fe85d2b951585e79db8f754bfeb87df2eb7f62be61a793ac315b595a447822d5",
    ),
    "tests/independent/test_provenance.py": (
        44,
        "ce8615f8735e348d772ae13a4b4196feb5fd69dd156c12d5ffd4c202a72ce755",
    ),
    # Gate C fix (KB 741a6cbf) added 9 reviewed boundary probes.
    "tests/stats_suite/test_fault_harness.py": (
        17,
        "f9ed01ca9ff43632dd89f70ea98936389e69bfa5369e3c5b0af909e2b074d331",
    ),
    "tests/stats_suite/test_fault_points.py": (
        9,
        "5c811be8589205f143a47098f9ce9924caac433e60d629c7a1c99e658aaedf2c",
    ),
    "tests/stats_suite/test_interval_table.py": (
        400,
        "729962938afdee0ed0447035fb56ac1ab1bdcdd646803432733a27261e8026a5",
    ),
    # Reviewed fast additions integrated alongside P2-09: P3-07 (KB 5096c307)
    # and P3-06 (KB d8c34961).
    "tests/stats_suite/test_parser_mutation_catalog.py": (
        15,
        "c86c81602b0be04f399d7a64bec215aba2c6b56d79690dc120734d2575e0bc43",
    ),
    "tests/stats_suite/test_reference_model.py": (
        13,
        "6e4f17709497e9952ce35c89d5b5324811995ad4a75fb55d7a02d8a4119315db",
    ),
    "tests/stats_suite/test_store_schema.py": (
        5,
        "4f9b9f66c72e518624aea50c282f094c4eea4df4b70c0f1fcd08b794c24fdb4d",
    ),
    "tests/stats_suite/test_writer_mutation_catalog.py": (
        3,
        "20014ee1a3c84640f2654a73534ee0ef52e233848de2d0c56a503975f6669e42",
    ),
    "tests/systemic/test_dispatch_fence.py": (
        27,
        "b7f82cf146604a92223c38180487eae534b969069fbbee31c81b6b60c1ae89fb",
    ),
    "tests/systemic/test_exit_checkpoint.py": (
        18,
        "d60888673b9712e180c93bbe40471d7544e7b98801fce8cd3b6714ab2634c7df",
    ),
    "tests/systemic/test_expectation_model.py": (
        27,
        "cd3e30433f6799b90e86d8812ba25d047c82f9ebe7e630739f85523bda923a61",
    ),
    "tests/systemic/test_harness_selfcheck.py": (
        56,
        "96edf73ad60901b2c9ecbb622e761bc25a4846ab66af2820311261ec74ce172e",
    ),
    "tests/systemic/test_lifecycle_driver.py": (
        22,
        "9dadfe4e25dfcca8246aa0857852cc6cabde9a349a1719e2395e4643954a7985",
    ),
    "tests/systemic/test_oracle_contract.py": (
        21,
        "8ed99a7f15ca8f143e564ce4dfb94fc32016f62f67674e1bc86b96a89c88938b",
    ),
    "tests/systemic/test_oracle_real_driver.py": (
        15,
        "a85f0b883c44598ec1a973840972705dd3929a910c5232eed3a1654857721ac1",
    ),
    "tests/systemic/test_pairwise.py": (
        18,
        "3a7f1d8e1d2942980204151eccac0e3487bfe7141d228a30bb368de7155dbfbf",
    ),
    "tests/systemic/test_portal_factory.py": (
        68,
        "b3fa1f9297647298448f3c3a280a06da166eaf73931aeebb9161886971480a39",
    ),
    "tests/systemic/test_response_corpus.py": (
        34,
        "fb82bec0ab6407484247af1c6615921a28fa8ff72cbeb13b1a50002d51073877",
    ),
    "tests/test_auth_mutation_catalog.py": (
        3,
        "903aecebecdc8cb24db5f0905d1d91f193877b12fb6721bac2c1f6ba9d652a40",
    ),
    "tests/test_auth_reason.py": (
        14,
        "d53acd5b4814eac5235cd4824fa784c66a559a482db032cef690e997c5b30469",
    ),
    "tests/test_auth_review_r2_regressions.py": (
        20,
        "c2014228fe5739005b55911de25ae03046025550e23f983254fd4109f83e9ec7",
    ),
    "tests/test_auth_review_r3_regressions.py": (
        22,
        "5e35ab927df2db0286efa6296e3ef2c934dee358d02b40c6a499312702ab3b97",
    ),
    "tests/test_auth_review_r4_regressions.py": (
        38,
        "382237fdc842bd551d54231130a5963c375c08c6d01b01236359a9b38d0d1647",
    ),
    "tests/test_auth_review_r5_regressions.py": (
        196,
        "8ab6406fdbf36ec6b39145b68f8b1acb1cdda9fb8782015f63d6a70868b6c019",
    ),
    "tests/test_auth_review_regressions.py": (
        23,
        "8917271f06293b95c5aeb9f2a14772dde27e58715598bde6b03352841aba9be0",
    ),
    "tests/test_build_extension_zip.py": (
        7,
        "ccbb8734e88166b4d48d60d0254035e80677432d40192b05aa2a4f3f78e18fe1",
    ),
    "tests/test_captcha_client.py": (
        15,
        "bf8189cce953cb04a5dc2070f8005a963041e5fea33eecdf70d1820bad017e70",
    ),
    "tests/test_captcha_flow.py": (
        33,
        "0ef3b94282beaf3565f207ec57a341984572fcf9f65fa8b3616ac26a7ba4478c",
    ),
    "tests/test_captcha_helper.py": (
        16,
        "d2ade5dad782d7b214e2fc4cb7a192fa0dd71fbd4b0f36d372b526e0d2c59b2b",
    ),
    "tests/test_concurrency.py": (
        6,
        "0bcef16881337f99861106a5d1058d0e908239e4f2e684481716e074ae659745",
    ),
    "tests/test_config_flow.py": (
        70,
        "8213663bc1429dc6b4a5eb7fa4daa327cfb611fc54a5b30095c11bbeaf8a445b",
    ),
    "tests/test_coordinator.py": (
        25,
        "e2014a98cb616e16670c6d955917a80b3dc26a2d036ae74c1b3780301d9e2c43",
    ),
    "tests/test_cost_contract.py": (
        18,
        "9ebfe57fed27279468894d3d3a24b2d654cdf4412ab058ad057ed00fa0926fbb",
    ),
    "tests/test_cost_contract_usagetype3.py": (
        15,
        "f71cecc99e3940b8855b719f5854a8ec2a976738d886252f9265fd70cdc6b248",
    ),
    "tests/test_cost_contract_usagetype3_review.py": (
        3,
        "a945592a3f9d8995e800cd3577c5357385730b8ba16b466a5f658b7f920b3483",
    ),
    "tests/test_cost_evidence.py": (
        29,
        "d06d757c1fcc77efb822ad88a6227bdb108c64ab5a732833e14e497e27216baa",
    ),
    "tests/test_cost_evidence_review_r2.py": (
        32,
        "d86d6c6740d6ecc0c22279c6fb8ec604da027ace85ee70528ad7c60451e478f5",
    ),
    "tests/test_cost_evidence_review_r3.py": (
        16,
        "e96c432ef814ec48914700f5fe7bf1d60d5bf48dca62cacc5f5a2c9dfe409a61",
    ),
    "tests/test_cost_evidence_review_r4.py": (
        11,
        "078b4853d5095ff94a3694d8b63c4e63918a8d8309340da5f278d03cf16bc345",
    ),
    "tests/test_cost_evidence_review_r5.py": (
        2,
        "55705df8a184e35101f7450db8c9068d89c492b193a3a2c60dd0cc80a1c365bc",
    ),
    "tests/test_cost_evidence_review_r6.py": (
        3,
        "675a0ab493f68dfc1314b8af18f0de95c0a0358c087f3ba41a8e9d092c55c5ad",
    ),
    "tests/test_diagnostics.py": (
        9,
        "787e84cf9c39bc05d1553bbdbe184d17c6c47fb295e462b081a6fac81754758a",
    ),
    "tests/test_harness_guards.py": (
        92,
        "e5865ae29d34d7ceefc2ab9a16537c1df676703342a8df75b5984b40adfcfb4c",
    ),
    "tests/test_init.py": (10, "9d3814bcdf596b3d307135fe0c75cd2b21a4ef02556f226455b968cacf360d09"),
    "tests/test_local_keepalive.py": (
        27,
        "6f488d265ce6a5a60c3e1826af95cb07828da3217041d05b7ddfd23ce73c976d",
    ),
    "tests/test_mutation_check.py": (
        43,
        "4e1fb3236b9ef9c40939c6f5d477ed22ead8b793ee074ddc1f8a5478c6816179",
    ),
    "tests/test_price_sanitizing.py": (
        23,
        "e3a6b0f968eee7d91efdefd2678c50be9a1dbd7885948c0146eb5a1bb4c581d7",
    ),
    "tests/test_pseg_client.py": (
        128,
        "90ee90aa08fd190d420275621fcea4c605d7c178fb2f3f89d65300023747e4af",
    ),
    "tests/test_release_check.py": (
        31,
        "c480883553e11b3d61c23963bfd84b593b6a29bbc28a512ad0963fc3fbfc9122",
    ),
    "tests/test_release_snapshot.py": (
        31,
        "c50ee7e29090264932600f65b919ff0065d9991ebebdf769b204ac0abb219ced",
    ),
    "tests/test_renewal_admission.py": (
        25,
        "524ceea2d60907d19e2b4bae7ec9f198e3ea91e82451dca46f37fcae4794bf7d",
    ),
    "tests/test_security_guards.py": (
        4,
        "1ee83a54c2d4d9bf01243041f829576d36c1bb7f923dc64b26d59f36ebbc96a9",
    ),
    "tests/test_session_lifecycle.py": (
        17,
        "450e7184e7e4f4d6eef040cec966b578f85dbe5191dac0cecf240ac69bc9d831",
    ),
    "tests/test_statistics.py": (
        6,
        "22ff641501a44de254d0c7a4874daa0542e7dfdb017d31db0a23eff0c5bde3d7",
    ),
    "tests/test_statistics_hourly.py": (
        23,
        "56335aba35163816aab2519adf3a7eeafb2536b751c80281b00f59fda4ddfd47",
    ),
    "tests/test_statistics_recorder.py": (
        60,
        "869b17dfa938db152bd818e5ad2df11c33a0d01d5e8d706d229cea91c1b70621",
    ),
    "tests/test_stats_baseline.py": (
        19,
        "f566ae40fb9b3f83dc205c49117f84af02083087d83862ac27097fe47c6fe927",
    ),
}

GENERATED_INVENTORY = {
    "tests/systemic/test_dispatch_fence.py": (
        97,
        "e65ee3c8885d332a6945acca50810327caad5b2a33eeaa09aae95405db6d3ad2",
    ),
    "tests/systemic/test_exit_checkpoint.py": (
        180,
        "41d45eafb9048b088e160715124ed75b8a40de2244ca94b6cabc240fa7a02a19",
    ),
    "tests/systemic/test_response_corpus.py": (
        854,
        "62fc87afb8395d0757baf89578d27ee3c2406089ea97d6a546624b49f64e26d0",
    ),
}

BASELINE_MODULE_MARKS = {
    "tests/independent/auth_r1/test_independent_auth_r1.py": ("independent",),
    "tests/independent/auth_r2/test_independent_auth_r2.py": ("independent",),
    "tests/independent/auth_r2/test_independent_auth_r2_extra.py": ("independent",),
    "tests/independent/auth_r3/test_independent_auth_r3.py": ("independent",),
    "tests/independent/auth_r4/test_independent_auth_r4.py": ("independent",),
    "tests/independent/auth_r5/test_independent_auth_r5.py": ("independent",),
    "tests/independent/auth_r6/test_independent_auth_r6.py": ("independent",),
    "tests/independent/auth_r6/test_independent_auth_r6_extra.py": ("independent",),
    "tests/independent/auth_r6/test_independent_auth_r6_flows.py": ("independent",),
    "tests/independent/auth_r6/test_independent_auth_r6_race.py": ("independent",),
    "tests/independent/auth_r7b/test_independent_auth_r7b.py": ("independent",),
    "tests/independent/auth_r8/test_independent_auth_r8.py": ("independent",),
    "tests/independent/auth_r9/test_independent_auth_r9.py": ("independent",),
    "tests/independent/hourly_r5/test_independent_hourly_guards.py": ("independent",),
    "tests/independent/hourly_r5/test_independent_hourly_physical_failure.py": ("independent",),
    "tests/independent/hourly_r5/test_independent_hourly_r5.py": ("independent",),
    "tests/independent/nywall/test_independent_nywall_contract.py": ("independent",),
    "tests/independent/nywall/test_independent_nywall_labels.py": ("independent",),
    "tests/independent/test_provenance.py": (),
    "tests/stats_suite/test_fault_harness.py": (),
    "tests/stats_suite/test_fault_points.py": (),
    "tests/stats_suite/test_interval_table.py": (),
    "tests/stats_suite/test_reference_model.py": (),
    "tests/stats_suite/test_store_schema.py": (),
    "tests/systemic/test_dispatch_fence.py": (),
    "tests/systemic/test_exit_checkpoint.py": (),
    "tests/systemic/test_expectation_model.py": (),
    "tests/systemic/test_harness_selfcheck.py": (),
    "tests/systemic/test_lifecycle_driver.py": (),
    "tests/systemic/test_oracle_contract.py": (),
    "tests/systemic/test_oracle_real_driver.py": (),
    "tests/systemic/test_pairwise.py": (),
    "tests/systemic/test_portal_factory.py": (),
    "tests/systemic/test_response_corpus.py": (),
    "tests/test_auth_mutation_catalog.py": (),
    "tests/test_auth_reason.py": (),
    "tests/test_auth_review_r2_regressions.py": (),
    "tests/test_auth_review_r3_regressions.py": (),
    "tests/test_auth_review_r4_regressions.py": (),
    "tests/test_auth_review_r5_regressions.py": (),
    "tests/test_auth_review_regressions.py": (),
    "tests/test_build_extension_zip.py": (),
    "tests/test_captcha_client.py": (),
    "tests/test_captcha_flow.py": (),
    "tests/test_captcha_helper.py": (),
    "tests/test_concurrency.py": (),
    "tests/test_config_flow.py": (),
    "tests/test_coordinator.py": (),
    "tests/test_cost_contract.py": (),
    "tests/test_cost_contract_usagetype3.py": (),
    "tests/test_cost_contract_usagetype3_review.py": (),
    "tests/test_cost_evidence.py": (),
    "tests/test_cost_evidence_review_r2.py": (),
    "tests/test_cost_evidence_review_r3.py": (),
    "tests/test_cost_evidence_review_r4.py": (),
    "tests/test_cost_evidence_review_r5.py": (),
    "tests/test_cost_evidence_review_r6.py": (),
    "tests/test_diagnostics.py": (),
    "tests/test_harness_guards.py": (),
    "tests/test_init.py": (),
    "tests/test_local_keepalive.py": (),
    "tests/test_mutation_check.py": (),
    "tests/test_price_sanitizing.py": (),
    "tests/test_pseg_client.py": (),
    "tests/test_release_check.py": (),
    "tests/test_release_snapshot.py": (),
    "tests/test_renewal_admission.py": (),
    "tests/test_security_guards.py": (),
    "tests/test_session_lifecycle.py": (),
    "tests/test_statistics.py": (),
    "tests/test_statistics_hourly.py": (),
    "tests/test_statistics_recorder.py": (),
    "tests/test_stats_baseline.py": (),
}

MANDATORY_FAST = (
    "tests/systemic/test_dispatch_fence.py::test_fast_representatives_cover_mandatory_classes_and_transitions",
    "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_first_poll_unload]",
    "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_mid_get_poll_cancel]",
    "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_redirect_boundary_reload]",
    "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_stage_transition_handoff]",
    "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_credential_post_stop]",
    "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_last_before_persist_cancel]",
    "tests/systemic/test_dispatch_fence.py::test_fast_retirement_before_first_request",
    "tests/systemic/test_dispatch_fence.py::test_fast_human_handoff_exemption_and_reconfigure_usable",
    "tests/systemic/test_dispatch_fence.py::test_fast_current_owner_307_control",
    "tests/systemic/test_dispatch_fence.py::test_fast_old_status_cannot_win_after_successor",
    "tests/systemic/test_dispatch_fence.py::test_fast_unattached_human_exemption_rule",
    "tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control[before:fetch_energy_data::cancel::no-renewal::MM_SID]",
    "tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control[after:fetch_energy_data::cancel::renewal::MM_SID]",
    "tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control[after:fetch_energy_data::stop::no-renewal::MM_RememberMe]",
    "tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control[after:export_cookies_and_auth_reason::cancel::renewal::MM_AuxUtil]",
    "tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control[before:confirmed_cookies::stop::renewal::MM_SID]",
    "tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control[after:pending_confirmed_snapshot::stop::no-renewal::MM_RememberMe]",
    "tests/systemic/test_response_corpus.py::test_fast_case[daily_chart_data::maintenance::none::post_proof::S::setup::ha]",
    "tests/systemic/test_response_corpus.py::test_fast_case[daily_chart_data::missing_token::aux::post_proof::R::setup::ha]",
    "tests/systemic/test_response_corpus.py::test_fast_case[daily_chart_data::root_number::remember_me::post_proof::H::poll::client]",
    "tests/systemic/test_response_corpus.py::test_fast_case[dashboard_verify_token::403::aux::post_proof::L::keepalive::ha]",
    "tests/systemic/test_response_corpus.py::test_fast_case[dashboard_verify_token::429::none::pre_proof::H::backfill::ha]",
    "tests/systemic/test_response_corpus.py::test_fast_case[dashboard_verify_token::all_invalid::remember_me::pre_proof::R::setup::ha]",
    "tests/systemic/test_response_corpus.py::test_fast_case[dashboard_verify_token::empty::aux::pre_proof::L::poll::client]",
    "tests/systemic/test_response_corpus.py::test_fast_case[history_chunk::root_null::remember_me::post_proof::L::backfill::client]",
    "tests/systemic/test_response_corpus.py::test_fast_case[history_chunk::truncated_json::sid::post_proof::R::backfill::client]",
    "tests/systemic/test_response_corpus.py::test_fast_case[history_chunk::unrelated::aux::post_proof::S::backfill::ha]",
    "tests/systemic/test_response_corpus.py::test_fast_case[hourly_chart::302_login::none::post_proof::R::setup::ha]",
    "tests/systemic/test_response_corpus.py::test_fast_case[hourly_chart::404::aux::optional::H::setup::client]",
    "tests/systemic/test_response_corpus.py::test_fast_case[hourly_chart_data::root_array::remember_me::optional::R::poll::client]",
    "tests/systemic/test_response_corpus.py::test_fast_case[hourly_chart_data::root_string::none::post_proof::S::setup::client]",
    "tests/systemic/test_response_corpus.py::test_fast_case[login_form_get::captcha::none::post_proof::L::poll::client]",
    "tests/systemic/test_response_corpus.py::test_fast_case[login_form_get::connection_error::remember_me::pre_proof::L::poll::ha]",
    "tests/systemic/test_response_corpus.py::test_fast_case[mandatory:307-credential-repost]",
    "tests/systemic/test_response_corpus.py::test_fast_case[mandatory:308-credential-repost]",
    "tests/systemic/test_response_corpus.py::test_fast_case[mandatory:auth-on-hourly-is-auth-loss]",
    "tests/systemic/test_response_corpus.py::test_fast_case[mandatory:healthy-hourly-rotation]",
    "tests/systemic/test_response_corpus.py::test_fast_case[mandatory:non-auth-hourly-daily-fallback]",
    "tests/systemic/test_response_corpus.py::test_fast_case[mandatory:post-proof-poison-only-follow-on]",
    "tests/systemic/test_response_corpus.py::test_fast_case[saml_acs::timeout::aux::pre_proof::S::poll::ha]",
    "tests/systemic/test_response_corpus.py::test_mandatory_307_and_308_repost_the_credential_body",
    "tests/systemic/test_response_corpus.py::test_mandatory_healthy_hourly_rotation_advances_the_checkpoint",
    "tests/systemic/test_response_corpus.py::test_mandatory_auth_on_hourly_is_not_a_daily_fallback",
    "tests/systemic/test_response_corpus.py::test_mandatory_non_auth_hourly_falls_back_to_daily",
    "tests/systemic/test_response_corpus.py::test_post_proof_poison_is_caught_only_by_the_follow_on",
)


# Reviewed R1 correction: invariant + exact per-role parameter allowlists.
# Order: provenance, fast, slow. These literals must not follow registry edits.
REVIEWED_FINDING_EVIDENCE = {
    'HOURLY-AUTH': (
        'I12',
        '465caa8da7b4dc6814871d4e4f5087784595e10adc039b8ca3a120d539060411',
        '440b407c3b305c85e22c0609e70840f7d1b0203a6b93108486a2a45fdb709b34',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'HOURLY-REDIRECT': (
        'I12',
        'b017ee31b98399d990a28bf904c60b0b545c2213339b4df8d1f03a08e63a5fa2',
        'e31ebbb08ab6e07b31a554203f027b972ed76a901305d29af57daf3cbec827e7',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R1-1': (
        'I1',
        '4527c763932c068090f101a3a11abcb1c8f7b01a7ab381193c5fcac6c219c492',
        'f0743dc7538e0bb5845e4c1336ff74a433fa75fc8b5aa67003b44eb4df489a89',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R1-2': (
        'I5',
        '5493378be570e23d704f479ca5ff706c1d0dc40d84597a4988d74d5b2eb6723a',
        '9899036ba57f296c35a66f7249ad3aef276a1ab734dcf39af531c6b48c3756ba',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R1-3': (
        'I7',
        '5e6dffc75cff89362f5d005e4efcd3254ac60fe663dcf902e86c266624a1dc77',
        '78f3ed6ce041331b91f76faca893e57bbcddba86b43853c80d38555c4865ebfb',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R1-4': (
        'I9',
        '10928a64ede5a6b9ab96291e392dd6828062ff9f439592a197e27ea18acb25ec',
        '0b0c1ea980d10c7c4b379df55846f1af40ecbe94d6d34eff9db6e84ebb006fba',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R1-5': (
        'I7',
        '82b5081d15dd9bc89be4e2bf297aebecfd557936f78f2ac27a57506281c95ca3',
        'cdfd6dbe182c8087fd4003dc7a824411c49b36f2be70bde162f59716b0e58088',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R1-6': (
        'I7',
        'f52440cdc12a779f809df5fc972c1708d4994826e35274dc363029f401decec2',
        '9ca5a7e6ab45ddf7f0bf87e834b2d8b5190795b7519dd4c3dc168a96b5516375',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R1-7': (
        'I3',
        'd98e79a5ba07d975a3134252abe39a0e8cf2c1cfef5d5bcf60c9571079b9690d',
        'd22232ceb8a25728b978017913023692bfa6c7bbbdabdebd4a4a946e42730e65',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R2-1': (
        'I5',
        'ba55b2e605f63a35fe96115a05fd7376d28bc097e17fed00443c75feab4ca199',
        '3f721bb0bf1d7e7a2b57121b92aee097b6c68cb6197fa67a2f70b01a164d359a',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R2-2': (
        'I9',
        'd8fab5b50f8047e8555df867c122581ef708789430fcf2dc309669e173ae065e',
        'b81741ceaa5e5a0f4b6c6b16c402c3e3f269e1d82efe27bb70cc84d610984ace',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R2-3': (
        'I7',
        '95ba96462717a8750c818b388b08d7f5246bb7984873d4d273405ef1fa232e85',
        '7bc5cd451992d6ac015aa7d805a28a78a0b3b63750438dcde6bf3c3b78030e13',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R2-4': (
        'I7',
        '5b39f56d4736131134d77c50f406e84a17486d972aed20020774f96ac5d07fbd',
        '811a6fec9c477cfd0223370d5fa7c43571625099a217b3d5241d69e80f312244',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R2-5': (
        'I8',
        '94e55e522333ee47360f99f263451caaac168a0353c2bea91cd4ee908a7915c6',
        '05297880e16f1903f877dddcefdf0563c90f11d7a650bf1466d32cad868336b1',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R3-N1': (
        'I5',
        '481117eed77c62f0d1357f66897fad1146dd3af404bf705f81be7f05b7e77aff',
        '04bee091076bbd4bc9089c2a2ba5c762b3e67e8de89a4681be3a7925c1f3a920',
        'c20e685ae9abefbcd413fe672d58d5f08958ae96349bd662aeec935adb76368c',
    ),
    'R3-N2': (
        'I7',
        'c6217334baeebc443a44bc1ecafaf0e04ae706689f9246525a8f7ec105f53300',
        'c7728fd8af898b6e210407423780be89568a368c5962a4d3538244bd433260d2',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R3-N3': (
        'I8',
        'ae83d775bbf18917c6ff33fbed91f286c282c8e715a3f12370d839c4f9bf527f',
        '4fd7d29bc8ded0ad08caa831529ecde6f9872794e28c7b92bbaae9345811dd26',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R4-F1': (
        'I3',
        '57a14dcce9656c92889548cd22a9f1d2c2444e284ca698037db6d12c079f9885',
        '0c6edce50088a59d0a90a133052262fcdc0e4b79a9ad5bd0d1144c8ce5e81f98',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R4-F2': (
        'I1',
        '67a5ad4cec8a5bb0ec4ae029ce1f91c9ee663f05b6456693d637e253f397dafa',
        '7bc6e83f33915728e2401bb48d36b4c580a2fef34c56eae2e4e1b238a69c3c58',
        '52ef77111b3347dbc21d27a0cf1c03213ce6dce8182ff0d9d9566341c3af2f77',
    ),
    'R5-A': (
        'I1',
        '4564e76e97d5b14cdeeb611f1eec971d4363c78fc73fdef8bd3077e909248d2e',
        'c115bc39eaeb6a06075040d62481c06dba7933e088b1acfbac5dbf6e116325c1',
        '52ef77111b3347dbc21d27a0cf1c03213ce6dce8182ff0d9d9566341c3af2f77',
    ),
    'R5-B': (
        'I3',
        '767087f47a566156e1a9beb9eda20ecebe5668a5e4aa8e4d1ed21d88780bc9c2',
        '90196a3a547b3a0bb62e255e2dca98e451f24be08ff2327131b241007f2bbed0',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R5-C': (
        'I10',
        '8531120bb019d857eda03867cdd173abb8bcd9eae60f88dc1fdcf630eb7d94bd',
        '7c7f27b2b864b151cbf1f7af0eac3f42452a5978848ac0cbe4ab4523325aa319',
        '8bd8e360f67ab6503c4c48689f8aa10fe63a546b7a6b68c9a416828e7cf0a1c5',
    ),
    'R5-D': (
        'I5',
        'e25b42a1fbb348b1c932126e7a03f4c715a770097cb0661512717b52a3f62e99',
        'f6d9e27a65859c7411943efd52310082e1164f9bf15c36616525648cb4047584',
        'c20e685ae9abefbcd413fe672d58d5f08958ae96349bd662aeec935adb76368c',
    ),
    'R6-F1': (
        'I4',
        'ad101b8763f0d9a21c39d6ad058d5e26c4527fd8dfed625398e721e83ecc23c6',
        '2eddd0b4c2c7dfba4939088de9637fde87884aa2cf5e8a4081774d02dfc1e1ef',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R6-F2': (
        'I5',
        'eff71972884f6800d8b35bff619d5925b64ef320e9a28e771516b3d103acbcf5',
        '48f0a69cc132afc5832ba243e325adc15d24312968171bc187606cbb3dfe611e',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R6-F3': (
        'I1',
        '5dac9db7ce70a0778a2190233d40fa3f9afa2ddf9b8bffd478925056152d2c93',
        '35bdc6d562d0e1fe983cba7500a07c86dc58f2ac7b235a5ccc9dfa20fc8b7b69',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R6-N1': (
        'I5',
        '3d232b9e49f044c8b09299a4dd2221cb8c041b8fabeecd1873449b17d6bad4e9',
        '637c267a2264cc33081acb1bcfcc48af40c09ec45548e25e4b1aee25d8d37664',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R7B-1': (
        'I3',
        '7747c0d458a3fa3ed2f19d1dd1c91b98b98112389053c09231f1b1a20328dfae',
        'e38aa0046a111d1fd183f5cbca61adf783f1b8467d60abd35d26274567445ff6',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R7B-2': (
        'I4',
        '81000f115f241360ae890704952eb6d26af4794f9a8bf9fbd8ffadaedbf6a29f',
        'e8352eea1c638ecb1dac18440267814bfddccf9f649c698fcd59690b210215bb',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R7B-3': (
        'I10',
        '7769901530fa5089a4875b02bc99eb01599602155f1782403cca21a884e3005c',
        '6a94349a84c3181d4e9bb959b7521cc231d60b863c6377c120bbc862b713904f',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R7B-4': (
        'I1',
        'cfd040b6d55ad4de6e39aeacfcc5c6ee07738aa41ebfe80e3a078c1094c8a37e',
        'edb81756ed7053419c214899db7d5a922c3e292afd8bf4034270fabfee0d0fc2',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R8-1': (
        'I10',
        '51828f43b8767ceb09a3f983aa4ff7b5ebdce742f832825e4feb8084e0c6e0ae',
        'dfb58a7ee0b5262658c15c53d9bdc76cc8af2c38809de197dee9c80c49a10ec7',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R8-2': (
        'I10',
        '25e8edbdc5b1f7f2c91036801e9844febb136cd92a916a4069887584172ff846',
        '622f5dc52c459c30d4d391021c2ba1c3e61530cf470342d80cb8a5ebf1cd2fdc',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R8-N1': (
        'I10',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
        '663c6a30fc60895d624f20925033cbaf74cb288d4dd083aac4b963e961641266',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R8-N2': (
        'I4',
        '30f90f5560736751efccdd137a15fa801b1d8ea0c4b34d39ee4a27ae978e2823',
        'f1a7a5d4667fbcf3656363ee361d316dbbcfbab2354a25211b20afee0558cdd0',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R8-N3': (
        'I4',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
        '738ad0f7bb24f3b1e55ad60e25baff97f836015004790bccf6a0025a3e5f03f4',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R9-1': (
        'I7',
        '0f5c0ab1cda08928807a5e39f51b24b701dc729d1c7bef8048c879c99bff2f54',
        '8854f40478c2c9fdd334740495ffeec0e875e10eb06a0cffa339eb93e227965f',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
    'R9-N1': (
        'I4',
        '38e1ae3a93f7ebeb0f3c107e55a22b5a91867a5379ff21f66b9ac0674ac40da7',
        'a0b1dafcc40b0ef5d7e3a85432c2154b18fb112111484fae50ebeaf99ea9787d',
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    ),
}
# Normalized full collected function AST, including invariant asserts and guards.
# Parameter IDs are pinned above; informational/bypass cases receive no credit.
REVIEWED_ASSERTION_BODIES = {
    'tests/independent/auth_r1/test_independent_auth_r1.py::test_actual_entry_reload_does_not_overlap_old_and_new_renewal':
        'f22fc1b759eea4ce2333a0215bfcffe69c387498c23276b06727d934a9343252',
    'tests/independent/auth_r1/test_independent_auth_r1.py::test_failed_first_refresh_persists_terminal_admission':
        '791fb594aa980e0ad169b42c0de5ac1773934391758fbdd0f59a4bc980ee7363',
    'tests/independent/auth_r1/test_independent_auth_r1.py::test_poll_failure_does_not_rearm_unconfirmed_rotation':
        '81aea1694d89aa1d864a9b0e445873a0fa5fd54144bc3bbd15ee6b68a49b9c2e',
    'tests/independent/auth_r1/test_independent_auth_r1.py::test_probe_rotation_is_rolled_back_after_transient_renewal':
        '10479e42c9cf259bcf4639967ffb94e8066f865ae5617f29dabbd533d106bf1d',
    'tests/independent/auth_r1/test_independent_auth_r1.py::test_retired_keepalive_cannot_dismiss_replacement_auth_issue':
        'dbca8236a646fed2ce5d29903b26ee2d9e30c82141a840e2b60cb63f6c6d4efc',
    'tests/independent/auth_r1/test_independent_auth_r1.py::test_success_without_rotation_does_not_authorize_transient_retry':
        '51ca4658dac0dfbf77161371060979197f1bee2710a1afba44f0099e23f9c147',
    'tests/independent/auth_r1/test_independent_auth_r1.py::test_uncertain_metadata_refuses':
        '4b62c8a4341eacd3bdf5cbb21161f86d965fd2f7024eb17d6dd0176875d5b416',
    'tests/independent/auth_r2/test_independent_auth_r2.py::test_d1_poll_keeps_verified_renewal_after_post_renewal_hiccup':
        'fd48be56e91dc249f4e2f37d987aa2000d54a0c9b15010469f84ef57d5fbc218',
    'tests/independent/auth_r2/test_independent_auth_r2.py::test_d2_runtime_poll_in_cooldown_is_auth_failure_and_kills_poll_schedule':
        '05487a43a18b5ec50fa85f384e33563aa0ca42f6eab44080ef2f15439f073187',
    'tests/independent/auth_r2/test_independent_auth_r2.py::test_d3_uncertain_state_never_prompts_human':
        'd2c23780740a38cf65007cd3d85965d78d723377576bb955937334a3d5cc2543',
    'tests/independent/auth_r2/test_independent_auth_r2.py::test_d4_rotation_seen_on_plain_dashboard_rearms_next_renewal':
        '6a5c243d0402e1ce9db5bcbf5f3a6c08952be24e169a61156d30850f96459a96',
    'tests/independent/auth_r2/test_independent_auth_r2_extra.py::test_e3_security_step_seen_by_poll_fallback_does_not_stop_keepalive_cookie_retry':
        '7a17a3345ee0cbad3d7d5758aa3a9e9d91e00bdf98b76f0db8876ddfe58638d2',
    'tests/independent/auth_r3/test_independent_auth_r3.py::test_p1_setup_verified_renewal_then_daily_timeout_loses_jar':
        'a19467cb733f934aa6ef0e67bb33f40748099bf2ab227dbd90cab26181c54ecb',
    'tests/independent/auth_r3/test_independent_auth_r3.py::test_p2_cooldown_without_earned_retry_is_a_fake_wait':
        '8038e19d7cadce7913f208422fdc412029377d06cdae1f4b905c78a50b8fcb77',
    'tests/independent/auth_r3/test_independent_auth_r3.py::test_p5_real_security_reply_latches_then_reload_limit':
        '1c989ffafbdf6785bb91c56459a3316a2015eb95564542f638e89c157b344107',
    'tests/independent/auth_r4/test_independent_auth_r4.py::test_optional_hourly_failed_response_cannot_replace_proof_jar':
        'dcde9f9be5829ff9e03eb6b512957a618f68cebbccc391c75cfc17f9b862273b',
    'tests/independent/auth_r4/test_independent_auth_r4.py::test_real_unload_retires_saved_password_fallback':
        '41e411fa19a8f6b6c25fa187ac1f04749677e7e4f342467fe3a219cf9425fb2a',
    'tests/independent/auth_r5/test_independent_auth_r5.py::test_invalid_hourly_200_does_not_replace_proven_whole_jar':
        'f1b3bb00c7861a73d9193e50b2a33579625a4f9c0ca7091f2d5b6c0261848c67',
    'tests/independent/auth_r5/test_independent_auth_r5.py::test_latest_valid_hourly_jar_survives_cancel_or_stop':
        '62a6514259e8c21b58a7eff2be66b794564c828dc3eccbf2b23a6c6f119232de',
    'tests/independent/auth_r5/test_independent_auth_r5.py::test_postproof_failed_dashboard_cookie_cannot_be_promoted_by_next_poll':
        'fe9f3117f5d4cd07bf829e44cb65507a57db60b775215af315c7ef67434ae7d9',
    'tests/independent/auth_r5/test_independent_auth_r5.py::test_saml_redirect_cannot_dispatch_new_post_after_retirement':
        '04d2cb9eff393ad58bb815c56f862f30fc2a9ffa89a2ebf30a1602cdc62d23dd',
    'tests/independent/auth_r6/test_independent_auth_r6.py::test_backfill_chunk_cookie_never_promoted':
        '55dd8304d38fb05b54defa4706f01fc7f2d52c90525f887fcadc511f3425792a',
    'tests/independent/auth_r6/test_independent_auth_r6.py::test_daily_leg_must_validate_before_confirming_cookie':
        '777d7bc3c7947e5556c5b1319805c50ac676dc59e300966f40528b7897f2dd2b',
    'tests/independent/auth_r6/test_independent_auth_r6_extra.py::test_owner_predicate_stays_true_during_own_cookie_write':
        '92115c6e3edfb0e240ce37e37433b6437f94a8c5c481df66fd5fbab0baad5dba',
    'tests/independent/auth_r7b/test_independent_auth_r7b.py::test_backfill_parser_fault_quarantines_every_cookie':
        '203e50123ef69f5814563e4d835c71ce326401e0c16b8d343124b1ecb146b1f8',
    'tests/independent/auth_r7b/test_independent_auth_r7b.py::test_checkpoint_old_ack_preserves_new_publish':
        '7968e1e849c255ca088ebee7cc15187a134669461d8b7d6621c3b4ca90122118',
    'tests/independent/auth_r7b/test_independent_auth_r7b.py::test_empty_expected_meter_does_not_prove_unrelated_records':
        'f46e75f9bc3b4c1b2eda11ea06ed93fef474f11345d5f18e579ad84107ecc954',
    'tests/independent/auth_r7b/test_independent_auth_r7b.py::test_own_write_failure_keeps_actual_baseline_coherent':
        '439e6be039d469f482dfc55078bfe16baed985c338fcd025cbc8731d9509cceb',
    'tests/independent/auth_r7b/test_independent_auth_r7b.py::test_rejected_daily_identity_cannot_teach_entry_new_account':
        '47ee527adad85ea9127221fb305f395307c8ac642080217a5da38562031d437e',
    'tests/independent/auth_r8/test_independent_auth_r8.py::test_p1_fresh_cookie_sign_in_with_lagging_daily_window':
        '2f7c59aa22afa067a61d5c0966fcd0182f369e17e8dc9456c75cbc2119cf9c49',
    'tests/independent/auth_r8/test_independent_auth_r8.py::test_p2_rejected_daily_real_refresh_keeps_previous_reading':
        '574e2c20a958ccf3a2dab029d739ff90e480d18fc78e5bec7c25af972ec282ca',
    'tests/independent/auth_r8/test_independent_auth_r8.py::test_p4_failed_leg_cookie_never_dispatched_or_persisted':
        '1e9a53cc1df1bf6f20beb4fb9540f7036bf06edc4878653f279a5b17f1759298',
    'tests/independent/auth_r9/test_independent_auth_r9.py::test_q1_renewal_proof_shape_anomaly_cookie':
        '6a7160bc0304ce7358a91c21797915e19868113ca89dd7fae7b8d8fb783cba12',
    'tests/independent/auth_r9/test_independent_auth_r9.py::test_q3_label_identity_flow_cookie_acceptance':
        'e2b28b7a45ad7c1d4e4b93aa88592e8b076804fc5b66fa93049179d8b716b34a',
    'tests/independent/hourly_r5/test_independent_hourly_r5.py::test_hourly_auth_vs_transient_and_daily_authority':
        'ad3c39951acd843b582a46dc565633d0d94d85112dc2206ac054bc0a3584dc92',
    'tests/independent/hourly_r5/test_independent_hourly_r5.py::test_hourly_login_redirect_is_typed_auth_loss':
        '1c4fd5c8f19c8f89e454be879ccbc220576425e032527e6b47c2eed17e89959a',
    'tests/systemic/test_auth_systemic_catalog.py::test_adapter_parser_provenance_and_empty_renewal_identity':
        'd79a4c6c0930951cef4bb4035f7c7682e6737d42d7b81611fe2a668da3166914',
    'tests/systemic/test_auth_systemic_catalog.py::test_checkpoint_ack_cannot_clear_a_newer_publication':
        'dd497ec423f506b14d7bfdf1e541c83ce4129c8ad6a6e943af190ee78630cbc4',
    'tests/systemic/test_auth_systemic_catalog.py::test_confirmed_remember_slide_is_not_a_second_renewal_generation':
        '2c7b9b307c5556414a474c9733b005c7371c9009b18542b4d473ec11db92ccfb',
    'tests/systemic/test_auth_systemic_catalog.py::test_daily_successor_is_learned_when_hourly_omits_it':
        '2bc65eb4e799681b7ab379787ed138ce432949d7b024abc8cd7bcd710de9d8e2',
    'tests/systemic/test_auth_systemic_catalog.py::test_failed_first_setup_preserves_spent_terminal_admission':
        '48ca31d7fed4f5d4ec5c865cef965f3a33f8d7574a81758459641a7655e047f2',
    'tests/systemic/test_auth_systemic_catalog.py::test_failed_renewal_preserves_preprobe_jar_and_spent_budget':
        '7d7dc184ab65b4b04410a9ddf13b577486a1839bb13d6580d10866c8c6b2949b',
    'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract':
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    'tests/systemic/test_auth_systemic_catalog.py::test_fresh_human_cookie_flow_has_its_own_account_proof':
        '1b1399fcaed78f3df5490c58d19bff2069304bd59ffaa390d5cf2bbb78e29814',
    'tests/systemic/test_auth_systemic_catalog.py::test_handoff_callback_fault_preserves_physical_owner':
        '2416f505b83327f96cbd32d5a7fabd63ed02a0487ac5a221976cbe38c71497af',
    'tests/systemic/test_auth_systemic_catalog.py::test_handoff_refuses_unvalidated_or_partial_live_jar':
        'e51368acecc22a87f301af351e6840c7c156abb31aa05a9ac775fbdc6de03200',
    'tests/systemic/test_auth_systemic_catalog.py::test_hourly_login_redirect_is_typed_auth_loss_with_statistics_isolation':
        '8db338b7eae412740b3ab90fbd64792b75f2d0ce39de8c489d8fee1c19635792',
    'tests/systemic/test_auth_systemic_catalog.py::test_hourly_stage_cookie_is_rolled_back_when_data_fails':
        'ab21d032e3ce250a5f59f140a21fae40082c49a952df85970ea6ace31e3d8e84',
    'tests/systemic/test_auth_systemic_catalog.py::test_loaded_admission_has_the_correct_public_outcome':
        '3113b6d3d4c3aaf73f116df63815a3219c2712bbfa34ab2ed9986f84909c188f',
    'tests/systemic/test_auth_systemic_catalog.py::test_login_json_security_step_is_latched_and_durable':
        '2a3f310576998506b12649151058831df4c8f4296ca8c75d59b1a3d1a8ca1569',
    'tests/systemic/test_auth_systemic_catalog.py::test_old_checkpoint_cannot_overwrite_human_successor':
        '3d94a0ea9564b02c2291fb770569ed79fcee2400f9fd5356f91bff4504ae52ee',
    'tests/systemic/test_auth_systemic_catalog.py::test_owner_stays_active_inside_own_physical_assignment':
        '63aaac2a7dd869c837e5b65c3cd88ceaf4332f8dceb7dbd503b2b9b629d61af1',
    'tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint':
        '7289bed8e0b4ac8f806f1298ed88c4a02b2e84dabc4b275cfaabb1c9544ef79f',
    'tests/systemic/test_auth_systemic_catalog.py::test_rejected_daily_result_contains_no_foreign_readings':
        '3f4c7b61e6ee18817252568c2abf006718cd421d29cd60737404273bb54b8120',
    'tests/systemic/test_auth_systemic_catalog.py::test_renewal_anomalous_proof_never_adopts_response_cookies':
        'ed116b72280641985d0afa994a0c744530ebb24407a35fe29ce6be2a31089c20',
    'tests/systemic/test_auth_systemic_catalog.py::test_renewal_requires_known_daily_proof_before_publication':
        'c7a903e3e95ea9572a0108ef1f7f7dd6ca3c345d0bf9f689cfb808375797c1ff',
    'tests/systemic/test_auth_systemic_catalog.py::test_replacement_inherits_the_inflight_entry_reservation':
        'd1597eb4e80e8428b348e0179b9cf717aa59f8a41c84a733130bb69c0e4e7553',
    'tests/systemic/test_auth_systemic_catalog.py::test_retired_keepalive_cannot_dismiss_successor_issue_after_export_await':
        '0160de1b9d9a200eb5f0fe6ec398fee9c1a7ec34bac0b66a0a262b053a0cd990',
    'tests/systemic/test_auth_systemic_catalog.py::test_uncertain_midsequence_admission_refuses_publication':
        '37a7b54f8a0f8da2febc86b8d21a0b056f62e2eb04afc8a0c52ed205de53e240',
    'tests/systemic/test_auth_systemic_catalog.py::test_valid_history_chunk_publishes_immutable_checkpoint':
        '41e59e02fc7c3043c4a7dd7dbd64648e2d1ce2c6a8bab98a030fc4da93a3a996',
    'tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative': '8e0f3604c603f8fbaf7224d4a12cadce059601df2edec5248cccf2c75b7c1c6e',
    'tests/systemic/test_dispatch_fence.py::test_slow_full_boundary_retirement_sweep': 'b4e19ec5f434d91aed7e24691eca9b8afccb05fd2621f09f526dbc66d4baf353',
    'tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control': '539dabcb17a8e9f4f7c5276db9282f67c42bdc73c88567f3512d3b1ff32a69f7',
    'tests/systemic/test_exit_checkpoint.py::test_slow_exit_checkpoint_sweep': '6de5c5e3b8ccde3e9e12ffac9158932261f68206c9270cd55f2f3a86b8db87be',
    'tests/systemic/test_policy_properties.py::test_literal_metadata_table': '5b8ea4feaac337232bb3d69e4f7db3f0a281aad02a916f74d352eb4de62e2cc0',
    'tests/systemic/test_policy_properties.py::test_literal_spacing_and_rollback': '31f2868d3744aa41a5073dcde331564e4b327e4f2b9c4968db05d00d03eba152',
    'tests/systemic/test_response_corpus.py::test_mandatory_auth_on_hourly_is_not_a_daily_fallback':
        'befc964d9a4a39e499dfeb7c017c862aab64d741d7f73d2f30e55299fa880aba',
    'tests/systemic/test_response_corpus.py::test_slow_case': '4bdce96845ba775e94863b4b0d5a8c76fcf1dc128600635130baa57f4d089bf7',
    'tests/test_auth_review_r2_regressions.py::test_confirmed_dashboard_slide_is_not_a_renewal_rotation':
        'b6adf20cf09d0e72f13eb282e42289920b8f7bcd370507f642ecc3f859d12587',
    'tests/test_auth_review_r2_regressions.py::test_confirmed_slide_with_a_domain_copy_is_not_a_renewal_rotation':
        '3518416e563140c0481911a66316affe110418d139dc9e4cd73799664aa712e0',
    'tests/test_auth_review_r2_regressions.py::test_corrupt_budget_prompts_the_normal_reauth_flow':
        'cf9c3358e522a96e2c619734550fd986125cdcd33aa27eacc0f68df89a495f19',
    'tests/test_auth_review_r2_regressions.py::test_poll_during_an_earned_retry_cooldown_keeps_the_schedule':
        '01af0cc84bf8e0ec86d2e41f9efd1e2e6e8d85129412acb1f9a0ff38a54cc09f',
    'tests/test_auth_review_r2_regressions.py::test_poll_keeps_the_verified_renewal_after_a_post_renewal_hiccup':
        '7a291b555e5d4c25a4b65a917d44e72e5b83084a79f99d8d2fb92d569f7035a5',
    'tests/test_auth_review_r3_regressions.py::test_failed_response_poison_cookie_is_never_persisted_or_replayed':
        'b5ddaab543dd313dd430b17f281063e291fd6b5d80d713e0f82d2006496801c8',
    'tests/test_auth_review_r3_regressions.py::test_failed_startup_challenge_is_durable_metadata':
        '5937f12a16ba550d92afa65f530a225eb84cf4ee02aed501762146d0fdbcc3c8',
    'tests/test_auth_review_r3_regressions.py::test_partial_confirmed_snapshot_is_never_persisted':
        '2fc7b59ea4e8b2f98412186d692aa51f2415fb11c15b98b6ffadd356a3ba665c',
    'tests/test_auth_review_r3_regressions.py::test_poll_fallback_challenge_survives_reload_and_cold_process':
        '2afdc183c8b0d31a45b524899cfb8173cec7239a6f7f6007f058107a5e6ba548',
    'tests/test_auth_review_r3_regressions.py::test_settled_unchanged_success_is_exhausted_before_its_window_closes':
        '19dd4d3836515fbbaee37c668048924f2568b48cba43f5f1bccd51030c164aeb',
    'tests/test_auth_review_r3_regressions.py::test_setup_persists_confirmed_renewal_before_a_later_chart_timeout':
        '01b435b116bfa700f0e120d2c67067f8578109c8737b9e4feeb9a280c924ec91',
    'tests/test_auth_review_r3_regressions.py::test_setup_with_spent_generation_is_an_auth_error_not_a_password_post':
        '6ec2dda018dcd8ee8b0ad4e072cb6d458d8ca858bbd27a53c0c15016f12a63d5',
    'tests/test_auth_review_r3_regressions.py::test_stale_owner_never_overwrites_a_human_replaced_jar':
        'bf25753efab2dccd2c4e291b584222aff90257fbf6b1031eb0aef1c6b17bc4c8',
    'tests/test_auth_review_r3_regressions.py::test_stop_keepalive_persists_a_confirmed_renewal_before_retiring':
        '1893798f859ac2a0a4f144012077226a43f435be849a798d1dcd60f44bb0efae',
    'tests/test_auth_review_r4_regressions.py::test_optional_hourly_failed_response_cannot_replace_proof_jar':
        '4b740e3fd809f93de32b58a5f60ced22cddf210d82f7ab2598aa3a82dab7aa37',
    'tests/test_auth_review_r4_regressions.py::test_optional_hourly_setup_200_cookie_is_rolled_back_when_chart_data_fails':
        '0ea56972e12a227c28e2732d6db9b2244afbb30b9be946a5536ee30a9b1a5177',
    'tests/test_auth_review_r4_regressions.py::test_persist_cookies_refuses_unconfirmed_live_jar_mutation_and_keeps_confirmed_snapshot':
        'c098ab3298be852a2dac7b4a2c4bf46bfea5e3e464d3b98bcacfa2ff4b8fae0c',
    'tests/test_auth_review_r4_regressions.py::test_real_unload_retires_saved_password_fallback':
        '13a702587674c91d16a9f584cdce56e92a7cf42dcadadeb1be49cf40c06f2282',
    'tests/test_auth_review_r4_regressions.py::test_real_unload_retires_sso_fallback': '1132869f6e76aabe4d0b98d5cc130aee371fd0751ab2587260f76cf803a7f7b4',
    'tests/test_auth_review_r5_regressions.py::test_backfill_invalid_or_empty_chunk_cookie_is_quarantined':
        '51729c6d73fa6f80996663dbe7367fbd5b42e6294ba100ea4d94c3151cb8e10c',
    'tests/test_auth_review_r5_regressions.py::test_checkpoint_lock_synchronizes_publish_and_clear':
        '2dbe4ed02584b445d0f19091556ca89a1c3159e99285e10ef968292708a598be',
    'tests/test_auth_review_r5_regressions.py::test_daily_and_hourly_meter_swap_and_fresh_manual_flow_semantics':
        '1b8689e0a09a3b987c24ad7c4ef656b1dad1da88af08dae16fdba586c240ec3e',
    'tests/test_auth_review_r5_regressions.py::test_daily_leg_requires_valid_meter_read_before_confirming_cookie':
        '927b06c992d2daf6e0996667717b9d87b0ffd82074aaa1f9454fcb8a539542f9',
    'tests/test_auth_review_r5_regressions.py::test_invalid_hourly_200_does_not_replace_proven_whole_jar':
        '29daee1629535da6ad3db5e73a2b6c7e88ad275dad9444d1db68b5ceb2a6f907',
    'tests/test_auth_review_r5_regressions.py::test_latest_valid_hourly_jar_survives_cancel_or_stop':
        'd51ec8e794a99f9296a53d3b24b12f81abc6b6eb0e3aa8171f62f2cecf7ccec4',
    'tests/test_auth_review_r5_regressions.py::test_owner_predicate_true_during_own_write_and_false_on_foreign_replace':
        '04692a44e4d05c8fcfda082676b08c7f84fa2f4e930bf9710e1647ecc6480b48',
    'tests/test_auth_review_r5_regressions.py::test_postproof_failed_dashboard_cookie_cannot_be_promoted_by_next_poll':
        '8640860022c193a1aa7bbcdd6378ed5493140c1e63548dc106fbd022228e9acb',
    'tests/test_auth_review_r5_regressions.py::test_r7b_known_decoy_series_with_unknown_valid_records_rejected':
        'afbcad58b5c57d7467da730abacf80a1481800f8319f38c7cca5642af4403d35',
    'tests/test_auth_review_r5_regressions.py::test_r7b_malformed_nested_chart_shapes_quarantined_across_all_legs':
        '8b4b66fdc38b1f23363cc6490a6e0a6b55c3bf48e8bcc5b0e9a9a5ca293ccee2',
    'tests/test_auth_review_r5_regressions.py::test_r7b_proven_meter_learning_and_rejected_daily_isolation':
        'a6c4ab91ef34ce48d33117e8da7a5ca522455f9f118edeb7811995ea4f886885',
    'tests/test_auth_review_r5_regressions.py::test_r7b_records_without_per_meter_provenance_never_prove_identity':
        '48f207c59e2f95a1d7d9f56860f67bdffe0b656b5e71cea6d96562784284430e',
    'tests/test_auth_review_r5_regressions.py::test_r7b_write_cookie_handoff_reconciles_baseline_across_update_faults':
        '530ef4f42c8f0b01bfc8095395c36bb8752e9f2e20ec2739217051aaa13f139b',
    'tests/test_auth_review_r5_regressions.py::test_r8_daily_successor_learned_when_hourly_omits_it':
        '0e952a0c537e4a2ccd13c3b84b41f00b43f56f8ee3b7bc6aa2e4a93d9d4c6924',
    'tests/test_auth_review_r5_regressions.py::test_r8_fresh_cookie_setup_survives_lagging_daily_window':
        '9b6c643095681c76903e2bf5bdd77bae0b67ad81c9160b94cbbe47713fd4c8e9',
    'tests/test_auth_review_r5_regressions.py::test_r8_label_identity_read_never_confirms_response_cookies':
        'd43abc7f946ba2197ab694f440f7fea389a297b830ec05019c64345f5565a417',
    'tests/test_auth_review_r5_regressions.py::test_r8_nonlist_nonmeter_telemetry_keeps_metered_leg':
        'd328e79a5c491c6b8314b35d9edbe318c364c5b53a78203ef43712d76e3663a8',
    'tests/test_auth_review_r5_regressions.py::test_r8_rejected_daily_real_refresh_keeps_previous_data':
        '0e512b13d33465db4fe02621c40b77045b63a23ad431c2410808338b37d4aa66',
    'tests/test_auth_review_r5_regressions.py::test_r9_renewal_proof_anomaly_never_adopts_cookie':
        'ef56737f25e972d22d0e1036ea4e727d8027846fd3881c444adf4fee446d9257',
    'tests/test_auth_review_r5_regressions.py::test_saml_redirect_cannot_dispatch_new_post_after_retirement':
        '12aec5d6c3536e9e3059ecd7deff5aeb49ffc7f933f41a5e145e06d2037cd87b',
    'tests/test_auth_review_r5_regressions.py::test_valid_backfill_chunk_rotation_persisted_on_unload':
        '0622fb5b8d3da8b164fff180246069b5d6c620350f74040b3a2e92c7dfe56c09',
    'tests/test_auth_review_regressions.py::test_failed_first_refresh_persists_terminal_admission':
        '791fb594aa980e0ad169b42c0de5ac1773934391758fbdd0f59a4bc980ee7363',
    'tests/test_auth_review_regressions.py::test_poll_failure_does_not_rearm_unconfirmed_rotation':
        '81aea1694d89aa1d864a9b0e445873a0fa5fd54144bc3bbd15ee6b68a49b9c2e',
    'tests/test_auth_review_regressions.py::test_probe_rotation_is_rolled_back_after_transient_renewal':
        '10479e42c9cf259bcf4639967ffb94e8066f865ae5617f29dabbd533d106bf1d',
    'tests/test_auth_review_regressions.py::test_replacement_uses_live_reservation_instead_of_stale_persisted_copy':
        '3ffa3252fd6ff6e450b82ada8fce75e6b8214af462d7509e5ea8339433f8a21e',
    'tests/test_auth_review_regressions.py::test_retired_keepalive_cannot_dismiss_replacement_auth_issue':
        'dbca8236a646fed2ce5d29903b26ee2d9e30c82141a840e2b60cb63f6c6d4efc',
    'tests/test_auth_review_regressions.py::test_retirement_between_reservation_and_immediate_dispatch_sends_nothing':
        '8d8fc6868dcd386d7f92bb0991d3284d410e2463005c07545531e2838492c2d8',
    'tests/test_auth_review_regressions.py::test_success_without_rotation_does_not_authorize_transient_retry':
        '51ca4658dac0dfbf77161371060979197f1bee2710a1afba44f0099e23f9c147',
    'tests/test_auth_review_regressions.py::test_uncertain_metadata_refuses': '4b62c8a4341eacd3bdf5cbb21161f86d965fd2f7024eb17d6dd0176875d5b416',
}

# P2-10 literal reviewed additions: exact nodes and full assertion ASTs.
#
# Fence-row truth (R2 measured, not a coverage claim): the preserved rows
# 27/28/29/31 are compound replacements (their stage guard *and* the structural
# AllowlistedSession.send guard), so their own-stage fast cases detect the compound
# row. For 28/29/31 the stage guard is redundant defence-in-depth behind the
# identical _check_active_owner predicate Session.send already enforces (same
# typed exception, zero dispatch) and both layers must be removed; 27's verify
# path also goes through can_dispatch. Row 1 is not a Session.send detector: it is
# mapped to the uncertain-admission case, where can_dispatch's reservation-owner
# and not-uncertain checks are the only refusal (its stage guard is not redundant).
SYSTEMIC_AUTH_DETECTORS = {
    '1-entry-shared-admission': (
        'tests/systemic/test_auth_systemic_catalog.py::test_replacement_inherits_the_inflight_entry_reservation',
        'd1597eb4e80e8428b348e0179b9cf717aa59f8a41c84a733130bb69c0e4e7553',
    ),
    '1-immediate-owner-check': (
        'tests/systemic/test_auth_systemic_catalog.py::test_uncertain_midsequence_admission_refuses_publication',
        '37a7b54f8a0f8da2febc86b8d21a0b056f62e2eb04afc8a0c52ed205de53e240',
    ),
    '10-cooldown-is-transient': (
        'tests/systemic/test_auth_systemic_catalog.py::test_loaded_admission_has_the_correct_public_outcome[cooldown]',
        '3113b6d3d4c3aaf73f116df63815a3219c2712bbfa34ab2ed9986f84909c188f',
    ),
    '11-uncertain-fails-closed': (
        'tests/systemic/test_auth_systemic_catalog.py::test_loaded_admission_has_the_correct_public_outcome[uncertain]',
        '3113b6d3d4c3aaf73f116df63815a3219c2712bbfa34ab2ed9986f84909c188f',
    ),
    '12-confirmed-generation': (
        'tests/systemic/test_auth_systemic_catalog.py::test_confirmed_remember_slide_is_not_a_second_renewal_generation[host]',
        '2c7b9b307c5556414a474c9733b005c7371c9009b18542b4d473ec11db92ccfb',
    ),
    '12-confirmed-generation-dedupe': (
        'tests/systemic/test_auth_systemic_catalog.py::test_confirmed_remember_slide_is_not_a_second_renewal_generation[domain-copy]',
        '2c7b9b307c5556414a474c9733b005c7371c9009b18542b4d473ec11db92ccfb',
    ),
    '14-confirmed-snapshot-capture': (
        'tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[maintenance]',
        '7289bed8e0b4ac8f806f1298ed88c4a02b2e84dabc4b275cfaabb1c9544ef79f',
    ),
    '15-confirmed-stop-handoff': (
        'tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control[after:fetch_energy_data::stop::no-renewal::MM_RememberMe]',
        '539dabcb17a8e9f4f7c5276db9282f67c42bdc73c88567f3512d3b1ff32a69f7',
    ),
    '16-confirmed-snapshot-not-live-jar': (
        'tests/systemic/test_auth_systemic_catalog.py::test_handoff_refuses_unvalidated_or_partial_live_jar[immutable]',
        'e51368acecc22a87f301af351e6840c7c156abb31aa05a9ac775fbdc6de03200',
    ),
    '17-confirmed-stale-owner-guard': (
        'tests/systemic/test_auth_systemic_catalog.py::test_old_checkpoint_cannot_overwrite_human_successor',
        '3d94a0ea9564b02c2291fb770569ed79fcee2400f9fd5356f91bff4504ae52ee',
    ),
    '18-confirmed-partial-jar-guard': (
        'tests/systemic/test_auth_systemic_catalog.py::test_handoff_refuses_unvalidated_or_partial_live_jar[partial]',
        'e51368acecc22a87f301af351e6840c7c156abb31aa05a9ac775fbdc6de03200',
    ),
    '19-settled-spent-is-exhausted': (
        'tests/systemic/test_policy_properties.py::test_literal_spacing_and_rollback[1-False-899-exhausted]',
        '31f2868d3744aa41a5073dcde331564e4b327e4f2b9c4968db05d00d03eba152',
    ),
    '2-independent-policy-handoff': (
        'tests/systemic/test_auth_systemic_catalog.py::test_failed_first_setup_preserves_spent_terminal_admission',
        '48ca31d7fed4f5d4ec5c865cef965f3a33f8d7574a81758459641a7655e047f2',
    ),
    '20-durable-challenge-admission': (
        'tests/systemic/test_auth_systemic_catalog.py::test_login_json_security_step_is_latched_and_durable',
        '2a3f310576998506b12649151058831df4c8f4296ca8c75d59b1a3d1a8ca1569',
    ),
    '21-durable-challenge-no-background-http': (
        'tests/systemic/test_auth_systemic_catalog.py::test_login_json_security_step_is_latched_and_durable',
        '2a3f310576998506b12649151058831df4c8f4296ca8c75d59b1a3d1a8ca1569',
    ),
    '22-exhausted-no-password-fallback': (
        'tests/systemic/test_auth_systemic_catalog.py::test_loaded_admission_has_the_correct_public_outcome[exhausted]',
        '3113b6d3d4c3aaf73f116df63815a3219c2712bbfa34ab2ed9986f84909c188f',
    ),
    '23-optional-hourly-jar-quarantine': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[hourly-empty]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '24-optional-hourly-stage-rollback': (
        'tests/systemic/test_auth_systemic_catalog.py::test_hourly_stage_cookie_is_rolled_back_when_data_fails',
        'ab21d032e3ce250a5f59f140a21fae40082c49a952df85970ea6ace31e3d8e84',
    ),
    '25-persist-confirmed-cookies-guard': (
        'tests/systemic/test_auth_systemic_catalog.py::test_handoff_refuses_unvalidated_or_partial_live_jar[unconfirmed]',
        'e51368acecc22a87f301af351e6840c7c156abb31aa05a9ac775fbdc6de03200',
    ),
    '26-active-owner-dispatch-guard': (
        'tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_first_poll_unload]',
        '8e0f3604c603f8fbaf7224d4a12cadce059601df2edec5248cccf2c75b7c1c6e',
    ),
    '27-remember-me-inflight-owner-guard': (
        'tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_remember_me_proof_unload]',
        '8e0f3604c603f8fbaf7224d4a12cadce059601df2edec5248cccf2c75b7c1c6e',
    ),
    '28-login-form-entry-owner-guard': (
        'tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_login_form_entry_unload]',
        '8e0f3604c603f8fbaf7224d4a12cadce059601df2edec5248cccf2c75b7c1c6e',
    ),
    '29-login-post-owner-guard': (
        'tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_login_post_unload]',
        '8e0f3604c603f8fbaf7224d4a12cadce059601df2edec5248cccf2c75b7c1c6e',
    ),
    '3-poll-identity-proof': (
        'tests/systemic/test_auth_systemic_catalog.py::test_renewal_requires_known_daily_proof_before_publication',
        'c7a903e3e95ea9572a0108ef1f7f7dd6ca3c345d0bf9f689cfb808375797c1ff',
    ),
    '30-sso-entry-owner-guard': (
        'tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_redirect_boundary_reload]',
        '8e0f3604c603f8fbaf7224d4a12cadce059601df2edec5248cccf2c75b7c1c6e',
    ),
    '31-sso-post-owner-guard': (
        'tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_sso_post_unload]',
        '8e0f3604c603f8fbaf7224d4a12cadce059601df2edec5248cccf2c75b7c1c6e',
    ),
    '32-structural-session-send-owner-guard': (
        'tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_stage_transition_handoff]',
        '8e0f3604c603f8fbaf7224d4a12cadce059601df2edec5248cccf2c75b7c1c6e',
    ),
    '33-post-renewal-failed-dashboard-leg-restore': (
        'tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[maintenance]',
        '7289bed8e0b4ac8f806f1298ed88c4a02b2e84dabc4b275cfaabb1c9544ef79f',
    ),
    '34-post-renewal-missing-token-leg-restore': (
        'tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[notoken]',
        '7289bed8e0b4ac8f806f1298ed88c4a02b2e84dabc4b275cfaabb1c9544ef79f',
    ),
    '35-post-renewal-exception-leg-restore': (
        'tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[503]',
        '7289bed8e0b4ac8f806f1298ed88c4a02b2e84dabc4b275cfaabb1c9544ef79f',
    ),
    '36-hourly-records-validation-before-confirm': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[hourly-empty]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '37-hourly-root-dict-validation': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[hourly-root]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '38-latest-confirmed-checkpoint-publish': (
        'tests/systemic/test_auth_systemic_catalog.py::test_checkpoint_ack_cannot_clear_a_newer_publication',
        'dd497ec423f506b14d7bfdf1e541c83ce4129c8ad6a6e943af190ee78630cbc4',
    ),
    '39-daily-validation-before-confirm': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-empty]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '4-post-await-retirement': (
        'tests/systemic/test_auth_systemic_catalog.py::test_retired_keepalive_cannot_dismiss_successor_issue_after_export_await',
        '0160de1b9d9a200eb5f0fe6ec398fee9c1a7ec34bac0b66a0a262b053a0cd990',
    ),
    '40-history-chunk-acceptance-checkpoint': (
        'tests/systemic/test_auth_systemic_catalog.py::test_valid_history_chunk_publishes_immutable_checkpoint',
        '41e59e02fc7c3043c4a7dd7dbd64648e2d1ce2c6a8bab98a030fc4da93a3a996',
    ),
    '41-history-gap-abort-rollback': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[backfill-null]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '42-own-save-owner-predicate': (
        'tests/systemic/test_auth_systemic_catalog.py::test_owner_stays_active_inside_own_physical_assignment',
        '63aaac2a7dd869c837e5b65c3cd88ceaf4332f8dceb7dbd503b2b9b629d61af1',
    ),
    '43-atomic-checkpoint-compare-clear': (
        'tests/systemic/test_auth_systemic_catalog.py::test_checkpoint_ack_cannot_clear_a_newer_publication',
        'dd497ec423f506b14d7bfdf1e541c83ce4129c8ad6a6e943af190ee78630cbc4',
    ),
    '44-nested-series-and-ajax-shape-guard': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[backfill-nested]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '45-per-record-contributor-provenance': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-foreign]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '46-rejected-daily-quarantines-result': (
        'tests/systemic/test_auth_systemic_catalog.py::test_rejected_daily_result_contains_no_foreign_readings',
        '3f4c7b61e6ee18817252568c2abf006718cd421d29cd60737404273bb54b8120',
    ),
    '47-handoff-finally-baseline-reconcile': (
        'tests/systemic/test_auth_systemic_catalog.py::test_handoff_callback_fault_preserves_physical_owner[after]',
        '2416f505b83327f96cbd32d5a7fabd63ed02a0487ac5a221976cbe38c71497af',
    ),
    '48-history-chart-envelope-guard': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[backfill-ajax]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '49-live-chart-envelope-guard': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-ajax]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '5-pre-probe-confirmed-jar': (
        'tests/systemic/test_auth_systemic_catalog.py::test_failed_renewal_preserves_preprobe_jar_and_spent_budget',
        '7d7dc184ab65b4b04410a9ddf13b577486a1839bb13d6580d10866c8c6b2949b',
    ),
    '51-human-label-identity-only': (
        'tests/systemic/test_auth_systemic_catalog.py::test_fresh_human_cookie_flow_has_its_own_account_proof[label-only]',
        '1b1399fcaed78f3df5490c58d19bff2069304bd59ffaa390d5cf2bbb78e29814',
    ),
    '52-rejected-daily-typed-failure': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-empty]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '53-daily-hourly-contributor-union': (
        'tests/systemic/test_auth_systemic_catalog.py::test_daily_successor_is_learned_when_hourly_omits_it',
        '2bc65eb4e799681b7ab379787ed138ce432949d7b024abc8cd7bcd710de9d8e2',
    ),
    '54-non-meter-series-skip-order': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-telemetry]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '56-anomaly-withholds-cookie-confirmation': (
        'tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-telemetry]',
        'f9c9e57e618caaf06577d25eedf370d0dc17cfab9fd9985102a2c6e27c526292',
    ),
    '57-renewal-proof-anomaly-restore': (
        'tests/systemic/test_auth_systemic_catalog.py::test_renewal_anomalous_proof_never_adopts_response_cookies',
        'ed116b72280641985d0afa994a0c744530ebb24407a35fe29ce6be2a31089c20',
    ),
    '6-present-corrupt-refusal': (
        'tests/systemic/test_policy_properties.py::test_literal_metadata_table[None-True-uncertain]',
        '5b8ea4feaac337232bb3d69e4f7db3f0a281aad02a916f74d352eb4de62e2cc0',
    ),
    '7-transient-only-retry': (
        'tests/systemic/test_policy_properties.py::test_literal_spacing_and_rollback[1-False-899-exhausted]',
        '31f2868d3744aa41a5073dcde331564e4b327e4f2b9c4968db05d00d03eba152',
    ),
    '8-post-renewal-verified-keep': (
        'tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[maintenance]',
        '7289bed8e0b4ac8f806f1298ed88c4a02b2e84dabc4b275cfaabb1c9544ef79f',
    ),
    '9-post-renewal-token-keep': (
        'tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[notoken]',
        '7289bed8e0b4ac8f806f1298ed88c4a02b2e84dabc4b275cfaabb1c9544ef79f',
    ),
    'setup-human-account-proof': (
        'tests/systemic/test_auth_systemic_catalog.py::test_fresh_human_cookie_flow_has_its_own_account_proof[valid]',
        '1b1399fcaed78f3df5490c58d19bff2069304bd59ffaa390d5cf2bbb78e29814',
    ),
}

P210_FAST_ADDITIONS = {
    'tests/systemic/test_auth_systemic_catalog.py': (52, 'b13ba3bb7313d28cf549800896cc15d23c7261ed391f6f26b351ecb993a9525f'),
}

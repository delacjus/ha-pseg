"""Check the S5 catalog and isolate parser faults before coverage/sum gates.

Expected calendar starts and fixture labels come from the independent S1/S3
model. Focused controls add explicit conservation preconditions to the existing
S3 matrix; production imports below are solely the system under test.
"""

import ast
from datetime import UTC, datetime
import os
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

from custom_components.pseg.pseg_client import PsegClient
from custom_components.pseg.statistics_hourly import validate_hourly_day
from tests.stats_suite.interval_cases import (
    CASES_BY_ID,
    EDT_REFERENCE_DAY,
    EST_REFERENCE_DAY,
    FALL_2026_DAY,
    make_case_points,
    make_valid_control_points,
)
from tests.support.stats_model import ny_day_hours_utc
from tools._snapshot import snapshot
from tools.mutation_check import apply_mutation, load_table, resolve_target_path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tests/mutations/statistics_parser.py"
NOW = datetime(2028, 1, 1, tzinfo=UTC)


def test_parser_catalog_preimages_and_function_ownership():
    rows = load_table(CATALOG)
    coverage = runpy.run_path(str(CATALOG))["COVERAGE"]
    assert len(rows) == len(coverage) == 8
    assert {row["label"] for row in rows} == set(coverage)
    assert len({(row["filename"], row["befores"], row["afters"]) for row in rows}) == len(rows)
    for row in rows:
        assert row["expected"] is None, "S5 requires assertions, no exception allowance"
        assert row["befores"] != row["afters"], row["label"]
        path = resolve_target_path(ROOT, row["filename"])
        assert path.name in {"pseg_client.py", "statistics_hourly.py"}
        source = path.read_text()
        target = coverage[row["label"]][0].split(".")[-1]
        functions = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.FunctionDef) and node.name == target
        ]
        assert len(functions) == 1
        segment = ast.get_source_segment(source, functions[0])
        for before in row["befores"]:
            assert source.count(before) == 1, row["label"]
            if row["label"] == "p02-broaden-date-only":
                assert "_DATE_ONLY_LABEL_RE.fullmatch(text)" in segment
                assignment = next(
                    node
                    for node in ast.parse(source).body
                    if isinstance(node, ast.Assign)
                    and any(
                        isinstance(t, ast.Name) and t.id == "_DATE_ONLY_LABEL_RE"
                        for t in node.targets
                    )
                )
                assert before == ast.get_source_segment(source, assignment)
            else:
                assert before.strip() in segment, (row["label"], target)
        changed = apply_mutation(source, row["befores"], row["afters"], row["label"])
        assert changed != source
        compile(changed, str(path), "exec")


def test_parser_catalog_contracts_layers_and_exclusions():
    namespace = runpy.run_path(str(CATALOG))
    for row in load_table(CATALOG):
        target, contract, layer, assertion, link = namespace["COVERAGE"][row["label"]]
        assert target and len(contract) > 20 and len(assertion) > 20
        assert layer in {"helper", "parser", "day"}
        assert all(node.startswith("tests/stats_suite/") for node in row["test_nodes"])
        assert link.startswith(("tests/stats_suite/", "tests/independent/nywall/"))
    assert set(namespace["EXCLUDED"]) == {
        "coverage-bypass",
        "iso-basic-naive-clock",
        "fall-raw-promotion",
    }
    assert all(len(reason) > 80 for reason in namespace["EXCLUDED"].values())


def test_parser_catalog_detectors_and_links_collect_in_copy(tmp_path):
    copy = tmp_path / "source"
    snapshot(source=ROOT, dest=copy)
    coverage = runpy.run_path(str(CATALOG))["COVERAGE"]
    nodes = sorted(
        {node for row in load_table(CATALOG) for node in row["test_nodes"]}
        | {item[4] for item in coverage.values()}
    )
    env = os.environ.copy()
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONHOME"):
        env.pop(name, None)
    env.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": str(copy) + os.pathsep + str(copy / "tests"),
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            *nodes,
        ],
        cwd=copy,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    collected = set(result.stdout.splitlines())
    for node in nodes:
        assert any(item == node or item.startswith(node + "[") for item in collected), node


def _parse(series):
    return object.__new__(PsegClient)._parse_hourly_chart({"Data": {"series": series}})


def _assert_conserved(parsed, count, total):
    records = parsed["hourly_records"]
    assert parsed["hourly_invalid_points"] == 0
    assert parsed["hourly_granularity"] == "hourly"
    assert len(records) == count
    assert sum(record["kwh"] for record in records) == total, "Totals precondition"
    return records


@pytest.mark.parametrize("day", [EDT_REFERENCE_DAY, EST_REFERENCE_DAY], ids=["edt", "est"])
def test_parser_wall_start_with_conserved_totals(day):
    points = make_case_points(day, CASES_BY_ID["strict_same_date"])
    assert len(points) == 24 and sum(point["y"] for point in points) == 24.0
    parsed = _parse([{"name": "Meter #1", "data": points}])
    records = _assert_conserved(parsed, 24, 24.0)
    # This precedes every day validator and cannot be killed by missing_hours.
    assert [record["start"] for record in records] == ny_day_hours_utc(day), (
        "Parser start assertion"
    )
    result = validate_hourly_day(day, records, 24.0, NOW)
    assert result.complete and result.reason is None


@pytest.mark.parametrize("order", ["forward", "reverse"])
@pytest.mark.parametrize(
    "case_id",
    [
        "missing_zero_padding",
        "both_aware_wrong_end",
        "aware_iso_basic_wrong_hour",
        "date_start_aware_noon_end",
    ],
)
def test_parser_label_proof_with_conserved_coverage(case_id, order):
    day = EDT_REFERENCE_DAY
    case = CASES_BY_ID[case_id]
    control = make_valid_control_points(day, case, kwh_per_hour=0.5)
    target = make_case_points(day, case, kwh_per_hour=0.5)
    assert len(control) == len(target) == 24
    assert sum(point["y"] for point in control + target) == 24.0
    # Nearest healthy control runs first with identical count, starts and total.
    healthy = _parse([{"name": "Meter #1", "data": control}, {"name": "Meter #2", "data": control}])
    healthy_records = _assert_conserved(healthy, 24, 24.0)
    assert [record["start"] for record in healthy_records] == ny_day_hours_utc(day)
    result = validate_hourly_day(day, healthy_records, 24.0, NOW)
    assert result.complete and result.reason is None, "Healthy label control"

    series = [{"name": "Meter #1", "data": control}, {"name": "Meter #2", "data": target}]
    parsed = _parse(series if order == "forward" else series[::-1])
    records = _assert_conserved(parsed, 24, 24.0)
    assert [record["start"] for record in records] == ny_day_hours_utc(day)
    # Exact reason/outcome comes before day validation. Totals and coverage passed.
    assert records[0]["interval_reason"] == case.expected_reason, "Parser interval reason assertion"
    assert all(record["interval_ok"] is False for record in records), (
        "Parser interval outcome assertion"
    )
    expected_meters = ("1", "2") if order == "forward" else ("2", "1")
    assert all(record.contributing_meter_ids == expected_meters for record in records)
    result = validate_hourly_day(day, records, 24.0, NOW)
    assert result.reason == case.expected_reason, "Day label reason assertion"
    assert result.complete is False, "Day label outcome assertion"


def test_parser_ambiguity_precedes_aware_proof():
    day = FALL_2026_DAY
    points = make_case_points(day, CASES_BY_ID["exact_both_aware_valid"])
    assert len(points) == 25 and sum(point["y"] for point in points) == 25.0
    parsed = _parse([{"name": "Meter #1", "data": points}])
    records = _assert_conserved(parsed, 24, 25.0)
    # Raw repeated 01:00 intentionally collapses. Inspect its proof before coverage.
    assert records[1]["kwh"] == 2.0
    assert records[1]["interval_reason"] == "dst_ambiguous", "Parser ambiguity reason assertion"
    assert records[1]["interval_ok"] is False
    result = validate_hourly_day(day, records, 25.0, NOW)
    assert result.complete is False and result.reason == "dst_ambiguous"


def test_day_conservation_with_full_coverage():
    day = EDT_REFERENCE_DAY
    points = make_case_points(day, CASES_BY_ID["strict_same_date"])
    parsed = _parse([{"name": "Meter #1", "data": points}])
    records = _assert_conserved(parsed, 24, 24.0)
    assert [record["start"] for record in records] == ny_day_hours_utc(day)
    assert all(record["interval_ok"] is True for record in records)
    healthy = validate_hourly_day(day, records, 24.0, NOW)
    assert healthy.complete and healthy.reason is None
    result = validate_hourly_day(day, records, 48.0, NOW)
    assert result.reason == "sum_mismatch", "Day conservation reason assertion"
    assert result.complete is False
    assert result.total_kwh == 24.0 and result.received_hours == 24

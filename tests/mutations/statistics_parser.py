"""S5 parser faults using the unchanged P1 copy-only mutation engine.

Five-field rows; COVERAGE names the function, affected contract, assertion layer
and preserved S3/independent link. Focused catalog controls assert counts/totals
before label outcomes. No exception allowance or missing-hour label kill.
"""

C = "tests/stats_suite/test_parser_mutation_catalog.py::"
T = "tests/stats_suite/test_interval_table.py::"
INDEPENDENT = "tests/independent/nywall/test_independent_nywall_contract.py::"

MUTATIONS = [
    (
        "p01-x-as-real-utc",
        "pseg_client.py",
        "                start, wall_status = ny_wall_ms_to_utc(timestamp)",
        "                start, wall_status = datetime.fromtimestamp(timestamp / 1000, tz=UTC), 'ok'",
        C + "test_parser_wall_start_with_conserved_totals",
    ),
    (
        "p02-broaden-date-only",
        "statistics_hourly.py",
        '_DATE_ONLY_LABEL_RE = re.compile(r"^\\s*(\\d{2})/(\\d{2})/(\\d{4})\\s*$")',
        '_DATE_ONLY_LABEL_RE = re.compile(r"^\\s*(\\d{1,2})/(\\d{1,2})/(\\d{4})\\s*$")',
        [
            C + f"test_parser_label_proof_with_conserved_coverage[missing_zero_padding-{order}]"
            for order in ("forward", "reverse")
        ],
    ),
    (
        "p03-ignore-contradictory-end",
        "pseg_client.py",
        '                    elif not end_check:\n                        point_reason = "interval_end_mismatch"',
        '                    elif False and not end_check:\n                        point_reason = "interval_end_mismatch"',
        [
            C + f"test_parser_label_proof_with_conserved_coverage[both_aware_wrong_end-{order}]"
            for order in ("forward", "reverse")
        ],
    ),
    (
        "p04-discard-iso-basic-offset",
        "statistics_hourly.py",
        "    if not text:\n        return None\n\n    parsed: datetime | None = None",
        '    if not text or ":" not in text:\n        return None\n\n    parsed: datetime | None = None',
        [
            C
            + f"test_parser_label_proof_with_conserved_coverage[aware_iso_basic_wrong_hour-{order}]"
            for order in ("forward", "reverse")
        ],
    ),
    (
        "p05-bypass-fall-precedence",
        "pseg_client.py",
        '                if wall_status == "dst_ambiguous":\n                    c0 =',
        '                if False and wall_status == "dst_ambiguous":\n                    c0 =',
        C + "test_parser_ambiguity_precedes_aware_proof",
    ),
    (
        "p06-accept-spring-gap",
        "statistics_hourly.py",
        '        return (None, "dst_nonexistent")',
        '        return (a0.astimezone(UTC), "ok")',
        T + "test_spring_nonexistent_02_gap_increments_invalid_points",
    ),
    (
        "p07-valid-meter-masks-invalid",
        "pseg_client.py",
        "                interval_ok[start] = interval_ok.get(start, True) and point_ok",
        "                interval_ok[start] = interval_ok.get(start, False) or point_ok",
        [
            C
            + f"test_parser_label_proof_with_conserved_coverage[date_start_aware_noon_end-{order}]"
            for order in ("forward", "reverse")
        ],
    ),
    (
        "p08-bypass-conservation",
        "statistics_hourly.py",
        "    if not values_close(total, daily_total, abs_tol=promotion_tolerance(float(daily_total))):",
        "    if False and not values_close(total, daily_total, abs_tol=promotion_tolerance(float(daily_total))):",
        C + "test_day_conservation_with_full_coverage",
    ),
]

# (target, affected contract, assertion layer, mapped assertion, related old node)
COVERAGE = {
    "p01-x-as-real-utc": (
        "PsegClient._parse_hourly_chart",
        "x encodes NY wall-clock hour START, not an instant",
        "parser",
        "Parser start assertion after 24 records and 24 kWh conserved",
        INDEPENDENT + "test_contract_edt_baseline",
    ),
    "p02-broaden-date-only": (
        "parse_date_only_label",
        "Both date-only endpoints require strict zero padding",
        "parser",
        "Parser interval reason is timestamp_semantics_unverified, not None",
        T + "test_interval_table_single_meter_layer_assertions[missing_zero_padding]",
    ),
    "p03-ignore-contradictory-end": (
        "PsegClient._parse_hourly_chart",
        "Aware end must equal canonical start plus one hour",
        "parser",
        "Parser interval reason is interval_end_mismatch with full coverage",
        T + "test_interval_table_single_meter_layer_assertions[both_aware_wrong_end]",
    ),
    "p04-discard-iso-basic-offset": (
        "label_matches_ny_time",
        "ISO-basic aware time/offset must be checked before clock syntax",
        "parser",
        "Parser interval reason remains label_mismatch for wrong ISO-basic hour",
        T + "test_interval_table_single_meter_layer_assertions[aware_iso_basic_wrong_hour]",
    ),
    "p05-bypass-fall-precedence": (
        "PsegClient._parse_hourly_chart",
        "Ambiguous fall wall hour precedes both-aware proof",
        "parser",
        "Parser fold-hour reason is dst_ambiguous despite aware endpoints",
        INDEPENDENT + "test_fallback_25_aware_dst_ambiguous",
    ),
    "p06-accept-spring-gap": (
        "ny_wall_ms_to_utc",
        "Nonexistent spring 02:00 has no UTC instant and is invalid",
        "helper",
        "gap_status == dst_nonexistent before parser invalid count and day reason",
        INDEPENDENT + "test_spring_nonexistent_02_gap_rejected",
    ),
    "p07-valid-meter-masks-invalid": (
        "PsegClient._parse_hourly_chart",
        "Every overlapping contributor must prove its interval",
        "parser",
        "Parser interval outcome is False in both conserved meter orders",
        T + "test_multi_meter_both_orders",
    ),
    "p08-bypass-conservation": (
        "validate_hourly_day",
        "Exact coverage cannot replace authoritative daily conservation",
        "day",
        "Day outcome is incomplete/sum_mismatch for 24 hours totalling 24 versus 48",
        T + "test_spring_nonexistent_02_gap_increments_invalid_points",
    ),
}

EXCLUDED = {
    "coverage-bypass": (
        "The requested coverage-or-conservation slot uses conservation (p08). Existing S3 "
        "missing/extra/duplicate-hour controls remain unchanged; no duplicate row is counted."
    ),
    "iso-basic-naive-clock": (
        "Naive colon-free basic clocks already carry no positive hour proof. p04 discards "
        "the aware basic time/offset, the meaningful regression, while S3 retains both forms."
    ),
    "fall-raw-promotion": (
        "Raw duplicate fall 01:00 collapses to 24 canonical starts. p05 must fail at the "
        "parser ambiguity reason, before missing_hours; no raw 25-hour promotion is claimed."
    ),
}

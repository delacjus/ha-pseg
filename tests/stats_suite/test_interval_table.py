"""Full America/New_York wall label, interval, and meter-order table tests.

Contract S3 (P3-04):
Expands the independent P1 parser controls without weakening their exact
layer-specific outcomes.

Three-layer outcomes asserted per case:
(a) Helper-level status/reason: parse_date_only_label, label_matches_ny_time, ny_wall_ms_to_utc.
(b) Parser-level: hourly_invalid_points, records length, record interval_ok/reason/label_ok.
(c) Day diagnostic: complete flag and reason from validate_hourly_day.

ORACLE INDEPENDENCE:
Expected values derive strictly from standard library, ZoneInfo, and the pure
reference model in tests.support.stats_model.
DO NOT import production helpers on the expected side.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from custom_components.pseg.pseg_client import PsegClient
from custom_components.pseg.statistics_hourly import (
    expected_hour_starts,
    label_matches_ny_time,
    ny_day_bounds,
    ny_wall_ms_to_utc,
    parse_date_only_label,
    validate_hourly_day,
)
from tests.stats_suite.interval_cases import (
    ANOMALY_VARIANTS,
    CASES_BY_ID,
    EDT_REFERENCE_DAY,
    EST_REFERENCE_DAY,
    FALL_2026_DAY,
    INTERVAL_CASES,
    SPRING_2026_DAY,
    TIMESTAMP_VARIANTS,
    IntervalCase,
    make_anomaly_points,
    make_case_points,
    make_timestamp_variant_points,
    make_valid_control_points,
)
from tests.support.stats_model import (
    FALL_DST_2026,
    SPRING_DST_2026,
    enumerate_2026_days,
    ny_day_end_utc,
    ny_day_hours_utc,
    ny_day_start_utc,
    ny_wall_hour_to_x_ms,
    resolve_raw_wall_hour,
)

NY_TZ = ZoneInfo("America/New_York")
FAR_FUTURE_NOW = datetime(2028, 1, 1, tzinfo=UTC)

DAY_INFO: dict[str, tuple[date, int]] = {
    "spring_23h": (SPRING_2026_DAY, 23),
    "edt_24h": (EDT_REFERENCE_DAY, 24),
    "est_24h": (EST_REFERENCE_DAY, 24),
    "fall_25h": (FALL_2026_DAY, 25),
}


@pytest.fixture
def uninitialized_client() -> PsegClient:
    """Provide an uninitialized PsegClient instance bypassing network init."""
    return object.__new__(PsegClient)


# ============================================================================
# 1. Full-day interval table cases: malformed cases alongside valid controls
# ============================================================================


@pytest.mark.parametrize("case", INTERVAL_CASES, ids=lambda c: c.case_id)
def test_interval_table_single_meter_layer_assertions(
    uninitialized_client: PsegClient,
    case: IntervalCase,
) -> None:
    """Assert exact outcomes across helper, parser, and day validation layers.

    Every malformed-label case runs as a FULL conserved day (24 hours, daily total = sum)
    alongside its nearest VALID control, proving that rejection is caused solely by
    the interval/label proof rather than missing hours or sum mismatches.
    """
    day = EDT_REFERENCE_DAY
    # 1. Helper-level verification for each hour of the day
    for h in range(24):
        st_utc, wall_status = resolve_raw_wall_hour(day, h)
        assert st_utc is not None
        assert wall_status == "ok"

        # Check production helper against pure expected status
        start_label = case.start_label_fn(day, h, st_utc)
        expected_date = case.get_expected_date_only(day, h)
        actual_date = parse_date_only_label(start_label)
        assert actual_date == expected_date, (
            f"Helper parse_date_only_label mismatch for case {case.case_id} hour {h}: "
            f"expected {expected_date}, got {actual_date}"
        )

        expected_match = case.get_expected_label_match(day, h)
        actual_match = label_matches_ny_time(start_label, st_utc)
        assert actual_match == expected_match, (
            f"Helper label_matches_ny_time mismatch for case {case.case_id} hour {h}: "
            f"expected {expected_match}, got {actual_match}"
        )

        end_label = case.end_label_fn(day, h, st_utc)
        expected_end_date = case.get_expected_end_date_only(day, h)
        actual_end_date = parse_date_only_label(end_label)
        assert actual_end_date == expected_end_date

        expected_end_match = case.get_expected_end_label_match(day, h)
        actual_end_match = label_matches_ny_time(end_label, st_utc + timedelta(hours=1))
        assert actual_end_match == expected_end_match

    # 2. Build full-day points with conserved varying load
    def varying_kwh(h: int) -> float:
        return round(0.4 + (h % 7) * 0.13, 4)

    case_points = make_case_points(day, case, kwh_per_hour=varying_kwh)
    daily_total = round(sum(p["y"] for p in case_points), 4)

    # Parser execution (SUT)
    payload = {"Data": {"series": [{"name": "Meter #1", "data": case_points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    # Layer (b) assertions: parser invalid count, length, granularity, and per-record metadata
    assert parsed["hourly_invalid_points"] == case.expected_invalid_points
    assert len(parsed["hourly_records"]) == 24
    assert parsed["hourly_granularity"] == "hourly"

    for h, record in enumerate(parsed["hourly_records"]):
        expected_start, _ = resolve_raw_wall_hour(day, h)
        assert record["start"] == expected_start
        assert record["label_ok"] == case.get_expected_record_label_ok(day, h)
        assert record["interval_ok"] == case.get_expected_record_interval_ok(day, h)
        assert record["interval_reason"] == case.get_expected_record_interval_reason(day, h)
        assert record.contributing_meter_ids == ("1",)

    # Layer (c) assertions: day validation
    val = validate_hourly_day(
        day,
        parsed["hourly_records"],
        daily_total,
        FAR_FUTURE_NOW,
        granularity=parsed["hourly_granularity"],
    )
    assert val.complete is case.get_expected_day_complete(day), (
        f"Case {case.case_id}: expected complete={case.get_expected_day_complete(day)}, got {val.complete} "
        f"(reason={val.reason})"
    )
    assert val.reason == case.get_expected_day_reason(day), (
        f"Case {case.case_id}: expected reason={case.get_expected_day_reason(day)}, got {val.reason}"
    )

    # 3. Conserved valid control alongside every malformed-label case
    if case.is_malformed:
        control_points = make_valid_control_points(day, case, kwh_per_hour=varying_kwh)
        control_total = round(sum(p["y"] for p in control_points), 4)
        assert control_total == daily_total, "Control daily total must equal case total"

        control_payload = {"Data": {"series": [{"name": "Meter #1", "data": control_points}]}}
        control_parsed = uninitialized_client._parse_hourly_chart(control_payload)
        assert control_parsed["hourly_invalid_points"] == 0
        assert len(control_parsed["hourly_records"]) == 24

        control_val = validate_hourly_day(
            day,
            control_parsed["hourly_records"],
            control_total,
            FAR_FUTURE_NOW,
            granularity=control_parsed["hourly_granularity"],
        )
        assert control_val.complete is True, (
            f"Valid control for {case.case_id} failed: reason={control_val.reason}"
        )
        assert control_val.reason is None
        assert control_val.total_kwh == daily_total


# ============================================================================
# 2. EST 24-hour baseline verification
# ============================================================================


@pytest.mark.parametrize(
    "case_id",
    [
        "strict_same_date",
        "surrounding_whitespace",
        "exact_both_aware_valid",
        "invalid_date_feb29_nonleap",
        "iso_date_only",
        "surrounding_text",
        "missing_zero_padding",
        "equal_bare_clocks",
        "wrong_start_date",
        "end_plus_2_days",
    ],
)
def test_est_reference_day_interval_table(
    uninitialized_client: PsegClient,
    case_id: str,
) -> None:
    """Verify standard EST 24-hour day (UTC offset -5h, midnight 05:00Z)."""
    day = EST_REFERENCE_DAY
    case = CASES_BY_ID[case_id]
    points = make_case_points(day, case, kwh_per_hour=1.0)
    daily_total = 24.0

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    assert parsed["hourly_invalid_points"] == case.expected_invalid_points
    assert len(parsed["hourly_records"]) == 24

    for h, record in enumerate(parsed["hourly_records"]):
        expected_start, _ = resolve_raw_wall_hour(day, h)
        assert record["start"] == expected_start
        assert record["label_ok"] == case.get_expected_record_label_ok(day, h)
        assert record["interval_ok"] == case.get_expected_record_interval_ok(day, h)
        assert record["interval_reason"] == case.get_expected_record_interval_reason(day, h)
        assert record.contributing_meter_ids == ("1",)

    val = validate_hourly_day(
        day,
        parsed["hourly_records"],
        daily_total,
        FAR_FUTURE_NOW,
        granularity=parsed["hourly_granularity"],
    )
    assert val.complete is case.get_expected_day_complete(day)
    assert val.reason == case.get_expected_day_reason(day)


# ============================================================================
# 3. Timestamp variants: true UTC, shifted x, end-stamped x
# ============================================================================


def test_timestamp_true_utc_rejected(uninitialized_client: PsegClient) -> None:
    """Verify true UTC epoch ms (04:00Z for midnight EDT) rejects as unexpected_start."""
    day = EDT_REFERENCE_DAY
    points = make_timestamp_variant_points(day, "true_utc")
    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    val = validate_hourly_day(day, parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "unexpected_start"


@pytest.mark.parametrize("shift_hours", [4, -4], ids=["shift_+4h", "shift_-4h"])
def test_timestamp_shifted_x_rejected(
    uninitialized_client: PsegClient,
    shift_hours: int,
) -> None:
    """Verify shifted x by +/-4h rejects as unexpected_start."""
    day = EDT_REFERENCE_DAY
    variant = "shifted_+4h" if shift_hours > 0 else "shifted_-4h"
    points = make_timestamp_variant_points(day, variant)
    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    val = validate_hourly_day(day, parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "unexpected_start"


def test_timestamp_end_stamped_x_rejected(uninitialized_client: PsegClient) -> None:
    """Verify end-stamped x (x = end of interval) rejects as unexpected_start."""
    day = EDT_REFERENCE_DAY
    points = make_timestamp_variant_points(day, "end_stamped_x")
    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    val = validate_hourly_day(day, parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "unexpected_start"


# ============================================================================
# 4. Coverage anomalies: duplicate, missing, and extra hours
# ============================================================================


def test_missing_hours_conserved_sum_rejected(uninitialized_client: PsegClient) -> None:
    """Verify 23 hours on a 24-hour day with matching daily total rejects as missing_hours."""
    day = EDT_REFERENCE_DAY
    points = make_anomaly_points(day, "missing_hours", kwh_per_hour=1.0)

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    assert len(parsed["hourly_records"]) == 23
    assert parsed["hourly_invalid_points"] == 0

    val = validate_hourly_day(day, parsed["hourly_records"], 23.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "missing_hours"


def test_extra_hours_from_next_day_rejected(uninitialized_client: PsegClient) -> None:
    """Verify extra 25th hour (belonging to next day) rejects as unexpected_start."""
    day = EDT_REFERENCE_DAY
    points = make_anomaly_points(day, "extra_hours", kwh_per_hour=1.0)

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    assert len(parsed["hourly_records"]) == 25
    val = validate_hourly_day(day, parsed["hourly_records"], 25.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "unexpected_start"


def test_duplicate_hour_single_series_conserved_sum(uninitialized_client: PsegClient) -> None:
    """Verify duplicate x in single series sums kwh cleanly when total is conserved."""
    day = EDT_REFERENCE_DAY
    points = make_anomaly_points(day, "duplicate_hour", kwh_per_hour=1.0)

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    assert len(parsed["hourly_records"]) == 24
    assert parsed["hourly_invalid_points"] == 0

    val = validate_hourly_day(day, parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val.complete is True
    assert val.reason is None


# ============================================================================
# 5. Spring DST: 23-hour promotion and nonexistent 02:00 hour handling
# ============================================================================


def test_spring_valid_23_hours_promotes(uninitialized_client: PsegClient) -> None:
    """Verify spring forward 23-hour day (2026-03-08, gap at 02:00) promotes."""
    day = SPRING_2026_DAY
    case = CASES_BY_ID["strict_same_date"]
    hours_23 = [0, 1, *range(3, 24)]
    points = make_case_points(day, case, hours=hours_23, kwh_per_hour=1.0)

    # Helper layer verification for the 23 valid hours
    for h in hours_23:
        x_ms = ny_wall_hour_to_x_ms(day, h)
        utc_dt, status = ny_wall_ms_to_utc(x_ms)
        expected_utc, expected_status = resolve_raw_wall_hour(day, h)
        assert status == expected_status
        assert utc_dt == expected_utc

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    assert parsed["hourly_invalid_points"] == 0
    assert len(parsed["hourly_records"]) == 23

    for h_idx, h in enumerate(hours_23):
        record = parsed["hourly_records"][h_idx]
        expected_start, _ = resolve_raw_wall_hour(day, h)
        assert record["start"] == expected_start
        assert record["label_ok"] is True
        assert record["interval_ok"] is True
        assert record["interval_reason"] is None
        assert record.contributing_meter_ids == ("1",)

    val = validate_hourly_day(day, parsed["hourly_records"], 23.0, FAR_FUTURE_NOW)
    assert val.complete is True
    assert val.reason is None


def test_spring_nonexistent_02_gap_increments_invalid_points(
    uninitialized_client: PsegClient,
) -> None:
    """Verify nonexistent 02:00 on spring forward increments invalid_points."""
    day = SPRING_2026_DAY
    case = CASES_BY_ID["strict_same_date"]
    # Provide all 24 raw hours including nonexistent 02:00
    points = make_case_points(day, case, hours=list(range(24)), kwh_per_hour=1.0)

    # 1. Helper layer assertion: 02:00 returns dst_nonexistent
    gap_x = ny_wall_hour_to_x_ms(day, 2)
    gap_dt, gap_status = ny_wall_ms_to_utc(gap_x)
    assert gap_status == "dst_nonexistent"
    assert gap_dt is None

    # 2. Parser layer assertion: invalid_points == 1, 23 valid records
    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)
    assert parsed["hourly_invalid_points"] == 1
    assert len(parsed["hourly_records"]) == 23

    # 3. Day validation assertion: sum_mismatch
    val = validate_hourly_day(day, parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "sum_mismatch"


# ============================================================================
# 6. Fall DST: 25-hour day, precedence of dst_ambiguous and contradictory labels
# ============================================================================


def test_fall_raw_25_hours_duplicate_01_dst_ambiguous(
    uninitialized_client: PsegClient,
) -> None:
    """Verify raw 25-hour fall-back day with duplicate 01:00 rejects as dst_ambiguous."""
    day = FALL_2026_DAY
    case = CASES_BY_ID["strict_same_date"]
    hours_25 = [0, 1, 1, *range(2, 24)]
    points = make_case_points(day, case, hours=hours_25, kwh_per_hour=1.0)

    # Helper layer assertion for 01:00: dst_ambiguous
    ambig_x = ny_wall_hour_to_x_ms(day, 1)
    ambig_dt, ambig_status = ny_wall_ms_to_utc(ambig_x)
    expected_ambig_dt, expected_ambig_status = resolve_raw_wall_hour(day, 1)
    assert ambig_status == expected_ambig_status
    assert ambig_dt == expected_ambig_dt

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    # Duplicate 01:00 collapses into one start in the parser
    assert len(parsed["hourly_records"]) == 24
    assert parsed["hourly_invalid_points"] == 0

    val = validate_hourly_day(day, parsed["hourly_records"], 25.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "dst_ambiguous"


def test_fall_distinct_24_hours_dst_ambiguous(uninitialized_client: PsegClient) -> None:
    """Verify 24 distinct hours on fall-back day rejects as dst_ambiguous."""
    day = FALL_2026_DAY
    case = CASES_BY_ID["strict_same_date"]
    points = make_case_points(day, case, hours=list(range(24)), kwh_per_hour=1.0)

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    val = validate_hourly_day(day, parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "dst_ambiguous"


def test_fall_aware_25_hours_raw_payload_cannot_promote(
    uninitialized_client: PsegClient,
) -> None:
    """Verify 25 aware points on fall-back day still reject with dst_ambiguous."""
    day = FALL_2026_DAY
    aware_hours = ny_day_hours_utc(day)
    assert len(aware_hours) == 25

    points: list[dict[str, Any]] = []
    for st in aware_hours:
        local = st.astimezone(NY_TZ)
        wall_x = int(datetime(day.year, day.month, day.day, local.hour, 0, 0, tzinfo=UTC).timestamp() * 1000)
        points.append(
            {
                "x": wall_x,
                "y": 1.0,
                "hs": {
                    "start": st.isoformat(),
                    "end": (st + timedelta(hours=1)).isoformat(),
                },
            }
        )

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    val = validate_hourly_day(day, parsed["hourly_records"], 25.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "dst_ambiguous"


def test_fall_contradictory_label_precedes_interval_reason(
    uninitialized_client: PsegClient,
) -> None:
    """Verify contradictory labels report label_mismatch before dst_ambiguous.

    Uses full 25 raw hours (with duplicate fold hour 1) and daily total 25.0.
    """
    day = FALL_2026_DAY
    case = CASES_BY_ID["strict_same_date"]
    hours_25 = [0, 1, 1, *range(2, 24)]
    points = make_case_points(day, case, hours=hours_25, kwh_per_hour=1.0)
    # Set contradictory start label on hour 1 points
    points[1]["hs"]["start"] = "2026-11-01T23:00:00-05:00"
    points[2]["hs"]["start"] = "2026-11-01T23:00:00-05:00"

    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    assert parsed["hourly_invalid_points"] == 0
    assert len(parsed["hourly_records"]) == 24
    assert parsed["hourly_records"][1]["label_ok"] is False

    val = validate_hourly_day(day, parsed["hourly_records"], 25.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "label_mismatch"

    # Nearest valid control with 25 raw hours rejects with dst_ambiguous
    control_points = make_case_points(day, case, hours=hours_25, kwh_per_hour=1.0)
    control_parsed = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": control_points}]}})
    control_val = validate_hourly_day(day, control_parsed["hourly_records"], 25.0, FAR_FUTURE_NOW)
    assert control_val.complete is False
    assert control_val.reason == "dst_ambiguous"


# ============================================================================
# 7. Multi-meter concurrent overlap and meter order invariance
# ============================================================================


@pytest.mark.parametrize("order", ["forward", "reverse"], ids=["order_M1_M2", "order_M2_M1"])
@pytest.mark.parametrize(
    "scenario,day,total_kwh,expected_complete,expected_reason,expected_invalid",
    [
        ("both_valid_concurrent_edt", EDT_REFERENCE_DAY, 24.0, True, None, 0),
        ("both_valid_concurrent_est", EST_REFERENCE_DAY, 24.0, True, None, 0),
        ("both_valid_concurrent_spring", SPRING_2026_DAY, 23.0, True, None, 0),
        ("meter_swap_sequential", EDT_REFERENCE_DAY, 24.0, True, None, 0),
        ("one_invalid_unverified", EDT_REFERENCE_DAY, 24.0, False, "timestamp_semantics_unverified", 0),
        ("one_invalid_label_mismatch", EDT_REFERENCE_DAY, 24.0, False, "label_mismatch", 0),
        ("one_invalid_end_mismatch", EDT_REFERENCE_DAY, 24.0, False, "interval_end_mismatch", 0),
        ("fall_both_valid_date_only", FALL_2026_DAY, 25.0, False, "dst_ambiguous", 0),
        ("fall_one_contradictory_label", FALL_2026_DAY, 25.0, False, "label_mismatch", 0),
    ],
)
def test_multi_meter_both_orders(
    uninitialized_client: PsegClient,
    order: str,
    scenario: str,
    day: date,
    total_kwh: float,
    expected_complete: bool,
    expected_reason: str | None,
    expected_invalid: int,
) -> None:
    """Verify multi-meter scenarios yield identical layer outcomes in BOTH series orders."""
    if day == SPRING_2026_DAY:
        hours = [0, 1, *range(3, 24)]
    elif day == FALL_2026_DAY:
        hours = [0, 1, 1, *range(2, 24)]
    else:
        hours = list(range(24))

    valid_case = CASES_BY_ID["strict_same_date"]

    if scenario in ("both_valid_concurrent_edt", "both_valid_concurrent_est", "both_valid_concurrent_spring"):
        m1_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.4)
        m2_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.6)
    elif scenario == "meter_swap_sequential":
        m1_pts = make_case_points(day, valid_case, hours=list(range(12)), kwh_per_hour=1.0)
        m2_pts = make_case_points(day, valid_case, hours=list(range(12, 24)), kwh_per_hour=1.0)
    elif scenario == "one_invalid_unverified":
        m1_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.5)
        invalid_case = CASES_BY_ID["date_start_aware_noon_end"]
        m2_pts = make_case_points(day, invalid_case, hours=hours, kwh_per_hour=0.5)
    elif scenario == "one_invalid_label_mismatch":
        m1_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.5)
        invalid_case = CASES_BY_ID["wrong_start_date"]
        m2_pts = make_case_points(day, invalid_case, hours=hours, kwh_per_hour=0.5)
    elif scenario == "one_invalid_end_mismatch":
        m1_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.5)
        invalid_case = CASES_BY_ID["end_plus_2_days"]
        m2_pts = make_case_points(day, invalid_case, hours=hours, kwh_per_hour=0.5)
    elif scenario == "fall_both_valid_date_only":
        m1_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.5)
        m2_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.5)
    elif scenario == "fall_one_contradictory_label":
        m1_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.5)
        m2_pts = make_case_points(day, valid_case, hours=hours, kwh_per_hour=0.5)
        m2_pts[1]["hs"]["start"] = "2026-11-01T23:00:00-05:00"
        m2_pts[2]["hs"]["start"] = "2026-11-01T23:00:00-05:00"
    else:
        raise ValueError(f"Unknown scenario: {scenario}")

    s1 = {"name": "Meter #1", "data": m1_pts}
    s2 = {"name": "Meter #2", "data": m2_pts}
    series = [s1, s2] if order == "forward" else [s2, s1]

    payload = {"Data": {"series": series}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    # Independent parser assertion: invalid points count MUST equal expected
    assert parsed["hourly_invalid_points"] == expected_invalid, (
        f"Multi-meter invalid points mutant detected: expected {expected_invalid}, got {parsed['hourly_invalid_points']}"
    )

    expected_len = 23 if day == SPRING_2026_DAY else 24
    assert len(parsed["hourly_records"]) == expected_len

    # Assert per-record metadata and contributing meters
    expected_meters = ("1", "2") if order == "forward" else ("2", "1")
    for r in parsed["hourly_records"]:
        if scenario == "meter_swap_sequential":
            assert len(r.contributing_meter_ids) == 1
        else:
            assert r.contributing_meter_ids == expected_meters

    val = validate_hourly_day(
        day,
        parsed["hourly_records"],
        total_kwh,
        FAR_FUTURE_NOW,
        granularity=parsed["hourly_granularity"],
    )
    assert val.complete is expected_complete, (
        f"Scenario {scenario} order {order}: expected complete={expected_complete}, got {val.complete} (reason={val.reason})"
    )
    assert val.reason == expected_reason


# ============================================================================
# 8. Full Matrix: 20 Label Families x 4 Day Lengths x 3 Meter Configurations
# ============================================================================


@pytest.mark.parametrize("order", ["single", "forward", "reverse"])
@pytest.mark.parametrize("case", INTERVAL_CASES, ids=lambda c: c.case_id)
@pytest.mark.parametrize("day_code", ["spring_23h", "edt_24h", "est_24h", "fall_25h"])
def test_interval_matrix_labels_and_orders(
    uninitialized_client: PsegClient,
    day_code: str,
    case: IntervalCase,
    order: str,
) -> None:
    """Full cross-product matrix: every label family x {23h, 24h EDT, 24h EST, 25h} x {single, forward, reverse}."""
    day, expected_hours = DAY_INFO[day_code]
    hours = [0, 1, *range(3, 24)] if day == SPRING_2026_DAY else ([0, 1, 1, *range(2, 24)] if day == FALL_2026_DAY else list(range(24)))

    def varying_kwh(h: int) -> float:
        return round(0.3 + (h % 5) * 0.11, 4)

    if order == "single":
        pts = make_case_points(day, case, hours=hours, kwh_per_hour=varying_kwh)
        series = [{"name": "Meter #1", "data": pts}]
        daily_total = round(sum(p["y"] for p in pts), 4)
        expected_meters = ("1",)
    else:
        # Two meters: M1 valid control (half load), M2 target case (half load)
        def half_kwh(h: int) -> float:
            return round(varying_kwh(h) / 2.0, 4)

        m_valid = make_valid_control_points(day, case, hours=hours, kwh_per_hour=half_kwh)
        m_target = make_case_points(day, case, hours=hours, kwh_per_hour=half_kwh)
        s1 = {"name": "Meter #1", "data": m_valid}
        s2 = {"name": "Meter #2", "data": m_target}
        series = [s1, s2] if order == "forward" else [s2, s1]
        daily_total = round(sum(p["y"] for p in m_valid) + sum(p["y"] for p in m_target), 4)
        expected_meters = ("1", "2") if order == "forward" else ("2", "1")

    payload = {"Data": {"series": series}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    # 1. Layer (b) parser assertions
    assert parsed["hourly_invalid_points"] == case.expected_invalid_points
    expected_records_len = 23 if day == SPRING_2026_DAY else 24
    assert len(parsed["hourly_records"]) == expected_records_len
    assert parsed["hourly_granularity"] == "hourly"

    # Per-record checks
    unique_hours = [0, 1, *range(3, 24)] if day == SPRING_2026_DAY else list(range(24))
    for h_idx, h in enumerate(unique_hours):
        record = parsed["hourly_records"][h_idx]
        expected_start, _ = resolve_raw_wall_hour(day, h)
        assert record["start"] == expected_start
        assert record.contributing_meter_ids == expected_meters

        if order == "single":
            assert record["label_ok"] == case.get_expected_record_label_ok(day, h)
        else:
            target_label_ok = case.get_expected_record_label_ok(day, h)
            if day == FALL_2026_DAY and h == 1:
                if target_label_ok is False:
                    assert record["label_ok"] is False
                elif target_label_ok is True:
                    assert record["label_ok"] is True
                else:
                    assert record["label_ok"] is None
            else:
                if target_label_ok is False:
                    assert record["label_ok"] is False
                else:
                    assert record["label_ok"] is True

        assert record["interval_ok"] == case.get_expected_record_interval_ok(day, h)
        assert record["interval_reason"] == case.get_expected_record_interval_reason(day, h)

    # 2. Layer (c) day validation assertions
    val = validate_hourly_day(
        day,
        parsed["hourly_records"],
        daily_total,
        FAR_FUTURE_NOW,
        granularity=parsed["hourly_granularity"],
    )
    assert val.complete is case.get_expected_day_complete(day)
    assert val.reason == case.get_expected_day_reason(day)
    if val.complete:
        assert val.total_kwh == daily_total

    # 3. Nearest valid control on this same day length
    if case.is_malformed:
        ctrl_pts = make_valid_control_points(day, case, hours=hours, kwh_per_hour=varying_kwh)
        ctrl_total = round(sum(p["y"] for p in ctrl_pts), 4)
        ctrl_parsed = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": ctrl_pts}]}})
        assert ctrl_parsed["hourly_invalid_points"] == 0
        ctrl_val = validate_hourly_day(day, ctrl_parsed["hourly_records"], ctrl_total, FAR_FUTURE_NOW)
        if day == FALL_2026_DAY:
            assert ctrl_val.complete is False
            assert ctrl_val.reason == "dst_ambiguous"
        else:
            assert ctrl_val.complete is True
            assert ctrl_val.reason is None
            assert ctrl_val.total_kwh == ctrl_total


# ============================================================================
# 9. Full Matrix: Timestamp Variants x 4 Day Lengths x 3 Meter Configurations
# ============================================================================


@pytest.mark.parametrize("order", ["single", "forward", "reverse"])
@pytest.mark.parametrize("variant", TIMESTAMP_VARIANTS)
@pytest.mark.parametrize("day_code", ["spring_23h", "edt_24h", "est_24h", "fall_25h"])
def test_interval_matrix_timestamp_variants_and_orders(
    uninitialized_client: PsegClient,
    day_code: str,
    variant: str,
    order: str,
) -> None:
    """Verify timestamp variants (true UTC, shifted x, end-stamped) across all 4 day lengths and orders."""
    day, expected_hours = DAY_INFO[day_code]
    daily_total = float(expected_hours)

    if order == "single":
        pts = make_timestamp_variant_points(day, variant, kwh_per_hour=1.0)
        series = [{"name": "Meter #1", "data": pts}]
    else:
        m_valid = make_valid_control_points(day, CASES_BY_ID["strict_same_date"], kwh_per_hour=0.5)
        m_var = make_timestamp_variant_points(day, variant, kwh_per_hour=0.5)
        s1 = {"name": "Meter #1", "data": m_valid}
        s2 = {"name": "Meter #2", "data": m_var}
        series = [s1, s2] if order == "forward" else [s2, s1]

    payload = {"Data": {"series": series}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    expected_invalid = 1 if (day == SPRING_2026_DAY and variant in ("shifted_-4h", "end_stamped_x")) else 0
    assert parsed["hourly_invalid_points"] == expected_invalid

    val = validate_hourly_day(day, parsed["hourly_records"], daily_total, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "unexpected_start"


# ============================================================================
# 10. Full Matrix: Coverage Anomalies x 4 Day Lengths x 3 Meter Configurations
# ============================================================================


@pytest.mark.parametrize("order", ["single", "forward", "reverse"])
@pytest.mark.parametrize("anomaly", ANOMALY_VARIANTS)
@pytest.mark.parametrize("day_code", ["spring_23h", "edt_24h", "est_24h", "fall_25h"])
def test_interval_matrix_coverage_anomalies_and_orders(
    uninitialized_client: PsegClient,
    day_code: str,
    anomaly: str,
    order: str,
) -> None:
    """Verify coverage anomalies across all 4 day lengths and orders."""
    day, expected_hours = DAY_INFO[day_code]

    if anomaly == "meter_swap":
        # Sequential split between Meter 1 and Meter 2
        split_hour = 12
        if day == SPRING_2026_DAY:
            h1 = [0, 1, *range(3, split_hour)]
            h2 = list(range(split_hour, 24))
        elif day == FALL_2026_DAY:
            h1 = [0, 1, 1, *range(2, split_hour)]
            h2 = list(range(split_hour, 24))
        else:
            h1 = list(range(split_hour))
            h2 = list(range(split_hour, 24))

        valid_case = CASES_BY_ID["strict_same_date"]
        pts1 = make_case_points(day, valid_case, hours=h1, kwh_per_hour=1.0)
        pts2 = make_case_points(day, valid_case, hours=h2, kwh_per_hour=1.0)
        s1 = {"name": "Meter #1", "data": pts1}
        s2 = {"name": "Meter #2", "data": pts2}
        series = [s1, s2] if order in ("single", "forward") else [s2, s1]
        daily_total = float(len(h1) + len(h2))
    elif order == "single":
        pts = make_anomaly_points(day, anomaly, kwh_per_hour=1.0)
        series = [{"name": "Meter #1", "data": pts}]
        daily_total = round(sum(p["y"] for p in pts), 4)
    else:
        # Two concurrent meters with the anomaly on both or second
        pts1 = make_anomaly_points(day, anomaly, kwh_per_hour=0.5)
        pts2 = make_anomaly_points(day, anomaly, kwh_per_hour=0.5)
        s1 = {"name": "Meter #1", "data": pts1}
        s2 = {"name": "Meter #2", "data": pts2}
        series = [s1, s2] if order == "forward" else [s2, s1]
        daily_total = round(sum(p["y"] for p in pts1) + sum(p["y"] for p in pts2), 4)

    payload = {"Data": {"series": series}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    assert parsed["hourly_invalid_points"] == 0
    val = validate_hourly_day(day, parsed["hourly_records"], daily_total, FAR_FUTURE_NOW)

    if anomaly == "extra_hours":
        assert val.complete is False
        assert val.reason == "unexpected_start"
    elif anomaly == "missing_hours":
        assert val.complete is False
        if day == FALL_2026_DAY:
            assert val.reason == "dst_ambiguous"
        else:
            assert val.reason == "missing_hours"
    elif anomaly in ("duplicate_hour", "meter_swap"):
        if day == FALL_2026_DAY:
            assert val.complete is False
            assert val.reason == "dst_ambiguous"
        else:
            assert val.complete is True
            assert val.reason is None
            assert val.total_kwh == daily_total


# ============================================================================
# 11. Dedicated Negative Proofs
# ============================================================================


def test_negative_proof_broaden_label_parser(uninitialized_client: PsegClient) -> None:
    """Dedicated negative proof: broadening the date-only regex must fail."""
    day = EDT_REFERENCE_DAY

    # Mutant probe 1: ISO date-only format
    assert parse_date_only_label("2026-10-05") is None, (
        "NEGATIVE PROOF FAILED: parse_date_only_label must reject ISO date format YYYY-MM-DD"
    )
    iso_case = CASES_BY_ID["iso_date_only"]
    iso_points = make_case_points(day, iso_case, kwh_per_hour=1.0)
    iso_parsed = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": iso_points}]}})
    iso_val = validate_hourly_day(day, iso_parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert iso_val.complete is False
    assert iso_val.reason == "timestamp_semantics_unverified"

    # Mutant probe 2: surrounding text
    assert parse_date_only_label("Date: 10/05/2026") is None, (
        "NEGATIVE PROOF FAILED: parse_date_only_label must reject surrounding text"
    )
    text_case = CASES_BY_ID["surrounding_text"]
    text_points = make_case_points(day, text_case, kwh_per_hour=1.0)
    text_parsed = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": text_points}]}})
    text_val = validate_hourly_day(day, text_parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert text_val.complete is False
    assert text_val.reason == "timestamp_semantics_unverified"

    # Healthy control stays GREEN
    assert parse_date_only_label("10/05/2026") == day
    valid_points = make_case_points(day, CASES_BY_ID["strict_same_date"], kwh_per_hour=1.0)
    valid_parsed = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": valid_points}]}})
    valid_val = validate_hourly_day(day, valid_parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert valid_val.complete is True
    assert valid_val.reason is None


def test_negative_proof_discard_iso_basic_time_offset(
    uninitialized_client: PsegClient,
) -> None:
    """Dedicated negative proof: discarding ISO-basic time/offset must fail."""
    day = EDT_REFERENCE_DAY
    st_utc, _ = resolve_raw_wall_hour(day, 0)
    assert st_utc is not None

    match_result = label_matches_ny_time("20261005T230000-0400", st_utc)
    assert match_result is False, (
        f"NEGATIVE PROOF FAILED: label_matches_ny_time must return False for wrong ISO-basic, got {match_result}"
    )

    case = CASES_BY_ID["aware_iso_basic_wrong_hour"]
    points = make_case_points(day, case, kwh_per_hour=1.0)
    parsed = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": points}]}})
    val = validate_hourly_day(day, parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val.complete is False
    assert val.reason == "label_mismatch", (
        f"NEGATIVE PROOF FAILED: expected label_mismatch, got {val.reason}"
    )

    # Healthy control stays GREEN
    valid_points = make_case_points(day, CASES_BY_ID["strict_same_date"], kwh_per_hour=1.0)
    valid_parsed = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": valid_points}]}})
    valid_val = validate_hourly_day(day, valid_parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert valid_val.complete is True
    assert valid_val.reason is None


def test_negative_proof_ignore_contradictory_end_label(
    uninitialized_client: PsegClient,
) -> None:
    """Dedicated negative proof: ignoring a contradictory end label must fail."""
    day = EDT_REFERENCE_DAY

    case1 = CASES_BY_ID["date_start_aware_noon_end"]
    points1 = make_case_points(day, case1, kwh_per_hour=1.0)
    parsed1 = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": points1}]}})
    val1 = validate_hourly_day(day, parsed1["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val1.complete is False
    assert val1.reason == "timestamp_semantics_unverified"

    case2 = CASES_BY_ID["end_plus_2_days"]
    points2 = make_case_points(day, case2, kwh_per_hour=1.0)
    parsed2 = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": points2}]}})
    val2 = validate_hourly_day(day, parsed2["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val2.complete is False
    assert val2.reason == "interval_end_mismatch"

    case3 = CASES_BY_ID["both_aware_wrong_end"]
    points3 = make_case_points(day, case3, kwh_per_hour=1.0)
    parsed3 = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": points3}]}})
    val3 = validate_hourly_day(day, parsed3["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert val3.complete is False
    assert val3.reason == "interval_end_mismatch"

    # Healthy controls stay GREEN
    valid_points = make_case_points(day, CASES_BY_ID["strict_same_date"], kwh_per_hour=1.0)
    valid_parsed = uninitialized_client._parse_hourly_chart({"Data": {"series": [{"name": "Meter #1", "data": valid_points}]}})
    valid_val = validate_hourly_day(day, valid_parsed["hourly_records"], 24.0, FAR_FUTURE_NOW)
    assert valid_val.complete is True
    assert valid_val.reason is None


# ============================================================================
# 12. 365-day midnight and hour-count calendar checks (slow tier)
# ============================================================================


@pytest.mark.slow
def test_calendar_365_days_bounds_and_conversions() -> None:
    """Verify all 365 days of 2026: midnight starts, hour counts, and DST controls.

    Asserts exact datetime equality between production ny_wall_ms_to_utc,
    expected_hour_starts, ny_day_bounds and stats_model's declared instants.
    """
    days_data = enumerate_2026_days()
    assert len(days_data) == 365

    total_calendar_hours = 0
    unique_wall_hours_ok = 0
    nonexistent_hours = 0
    ambiguous_hours = 0

    for day, expected_hour_count, hours_list in days_data:
        total_calendar_hours += expected_hour_count
        assert len(hours_list) == expected_hour_count

        # Production bounds connected to model
        prod_start, prod_end = ny_day_bounds(day)
        model_start = ny_day_start_utc(day)
        model_end = ny_day_end_utc(day)
        assert prod_start == model_start, f"Day {day} prod_start {prod_start} != model_start {model_start}"
        assert prod_end == model_end, f"Day {day} prod_end {prod_end} != model_end {model_end}"

        # Production expected_hour_starts connected to model
        prod_starts = expected_hour_starts(day)
        assert prod_starts == hours_list, f"Day {day} prod_starts mismatch against model hours_list"

        # Midnight start check
        midnight_utc = ny_day_start_utc(day)
        if day <= SPRING_DST_2026 or day > FALL_DST_2026:
            assert midnight_utc.hour == 5, f"EST day {day} midnight was {midnight_utc.hour}Z, expected 05:00Z"
        else:
            assert midnight_utc.hour == 4, f"EDT day {day} midnight was {midnight_utc.hour}Z, expected 04:00Z"

        # Unique wall hours per day (0..23) compared directly with resolve_raw_wall_hour
        for h in range(24):
            x_ms = ny_wall_hour_to_x_ms(day, h)
            utc_dt, status = ny_wall_ms_to_utc(x_ms)
            expected_utc, expected_status = resolve_raw_wall_hour(day, h)

            assert status == expected_status, (
                f"Day {day} hour {h}: production status {status} != model status {expected_status}"
            )
            assert utc_dt == expected_utc, (
                f"Day {day} hour {h}: production UTC instant {utc_dt} != model instant {expected_utc}"
            )

            if status == "ok":
                unique_wall_hours_ok += 1
            elif status == "dst_nonexistent":
                nonexistent_hours += 1
            elif status == "dst_ambiguous":
                ambiguous_hours += 1

    assert total_calendar_hours == 8760
    assert nonexistent_hours == 1  # 2026-03-08 02:00
    assert ambiguous_hours == 1    # 2026-11-01 01:00
    assert unique_wall_hours_ok == 8758

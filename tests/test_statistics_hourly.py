"""Unit tests for hourly day validation, DST enumeration and merge rules."""

from datetime import UTC, date, datetime, timedelta

from custom_components.pseg.statistics_hourly import (
    cost_tolerance,
    day_records_match,
    detect_hourly_days,
    expected_hour_starts,
    label_matches_ny_time,
    merge_series_rows,
    ny_day_bounds,
    ny_day_of,
    ny_midnight_utc,
    promotion_tolerance,
    validate_hourly_day,
    validate_hourly_days,
    values_close,
)

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def _points(
    day_str: str,
    kwh: float = 1.0,
    *,
    skip: frozenset[int] = frozenset(),
) -> list[dict]:
    day = date.fromisoformat(day_str)
    return [
        {
            "start": start,
            "kwh": kwh,
            "label_ok": True,
            "interval_ok": True,
            "interval_reason": None,
        }
        for index, start in enumerate(expected_hour_starts(day))
        if index not in skip
    ]


def test_normal_day_has_24_new_york_midnight_to_midnight_starts() -> None:
    """A normal local day is 24 UTC hourly starts, not a fixed UTC-day window."""
    starts = expected_hour_starts(date(2026, 10, 20))
    assert len(starts) == 24
    assert starts[0] == datetime(2026, 10, 20, 4, 0, tzinfo=UTC)
    assert starts[-1] == datetime(2026, 10, 21, 3, 0, tzinfo=UTC)
    assert {later - earlier for earlier, later in zip(starts, starts[1:])} == {
        timedelta(hours=1)
    }


def test_spring_dst_day_has_23_hours() -> None:
    """2026-03-08 in New York is 23 hours (05:00Z to 04:00Z next day)."""
    starts = expected_hour_starts(date(2026, 3, 8))
    assert len(starts) == 23
    assert starts[0] == datetime(2026, 3, 8, 5, 0, tzinfo=UTC)
    assert starts[-1] == datetime(2026, 3, 9, 3, 0, tzinfo=UTC)
    assert ny_day_bounds(date(2026, 3, 8))[1] == datetime(
        2026, 3, 9, 4, 0, tzinfo=UTC
    )


def test_fall_dst_day_has_25_hours() -> None:
    """2026-11-01 in New York is 25 hours (04:00Z to 05:00Z next day)."""
    starts = expected_hour_starts(date(2026, 11, 1))
    assert len(starts) == 25
    assert starts[0] == datetime(2026, 11, 1, 4, 0, tzinfo=UTC)
    assert starts[-1] == datetime(2026, 11, 2, 4, 0, tzinfo=UTC)
    assert ny_day_bounds(date(2026, 11, 1))[1] == datetime(
        2026, 11, 2, 5, 0, tzinfo=UTC
    )


def test_grouping_uses_new_york_day_not_utc_day() -> None:
    """A 02:00Z point belongs to the previous New York date in winter."""
    assert ny_day_of(datetime(2026, 1, 15, 2, 0, tzinfo=UTC)) == date(2026, 1, 14)


def test_complete_day_is_promotable() -> None:
    """Exact coverage plus an agreeing daily total promotes the day."""
    result = validate_hourly_day(
        date(2026, 10, 20), _points("2026-10-20"), 24.0, NOW
    )
    assert result.complete is True
    assert result.reason is None
    assert result.total_kwh == 24.0
    assert result.expected_hours == result.received_hours == 24


def test_zero_usage_day_is_promotable() -> None:
    """An explicit all-zero day is complete; zeroes are real data, not missing."""
    result = validate_hourly_day(
        date(2026, 10, 20), _points("2026-10-20", 0.0), 0.0, NOW
    )
    assert result.complete is True
    assert result.total_kwh == 0.0
    assert all(record["kwh"] == 0.0 for record in result.records)


def test_missing_hour_is_not_promotable() -> None:
    """A day with one missing hour keeps the stored daily row."""
    result = validate_hourly_day(
        date(2026, 10, 20),
        _points("2026-10-20", skip=frozenset({5})),
        23.0,
        NOW,
    )
    assert result.complete is False
    assert result.reason == "missing_hours"
    assert result.received_hours == 23


def test_daily_total_mismatch_is_not_promotable() -> None:
    """Point count alone is never proof: the authoritative daily total must agree."""
    result = validate_hourly_day(
        date(2026, 10, 20), _points("2026-10-20"), 30.0, NOW
    )
    assert result.complete is False
    assert result.reason == "sum_mismatch"


def test_open_day_is_not_promotable() -> None:
    """Today's still-open New York day is never promoted."""
    result = validate_hourly_day(
        date(2026, 10, 22), _points("2026-10-22"), 24.0, NOW
    )
    assert result.complete is False
    assert result.reason == "open_day"


def test_missing_daily_total_is_not_promotable() -> None:
    """Hourly data without an independent daily total is kept as provenance only."""
    result = validate_hourly_day(date(2026, 10, 20), _points("2026-10-20"), None, NOW)
    assert result.complete is False
    assert result.reason == "no_daily_total"


def test_daily_granularity_is_not_promotable() -> None:
    """A payload that is not hourly never promotes a day."""
    result = validate_hourly_day(
        date(2026, 10, 20),
        _points("2026-10-20"),
        24.0,
        NOW,
        granularity="daily",
    )
    assert result.complete is False
    assert result.reason == "granularity_not_hourly"


def test_label_mismatch_is_not_promotable() -> None:
    """A raw label that contradicts the UTC hour blocks the whole day."""
    points = _points("2026-10-20")
    points[3] = {**points[3], "label_ok": False}
    result = validate_hourly_day(date(2026, 10, 20), points, 24.0, NOW)
    assert result.complete is False
    assert result.reason == "label_mismatch"


def test_duplicate_starts_are_summed_for_meter_swap_day() -> None:
    """Two meter series can split one hour; their sum is the account total."""
    points = _points("2026-10-20")
    points.append({**points[0], "kwh": 0.5})
    result = validate_hourly_day(date(2026, 10, 20), points, 24.5, NOW)
    assert result.complete is True
    assert result.total_kwh == 24.5
    assert result.records[0]["kwh"] == 1.5


def test_validate_hourly_days_reports_each_candidate_day() -> None:
    """Bulk validation keeps complete and incomplete days distinguishable."""
    records = _points("2026-10-19") + _points("2026-10-20", skip=frozenset({0}))
    results = validate_hourly_days(
        records,
        {date(2026, 10, 19): 24.0, date(2026, 10, 20): 23.0},
        NOW,
    )
    assert results[date(2026, 10, 19)].complete is True
    assert results[date(2026, 10, 20)].reason == "missing_hours"


def test_detect_hourly_days_distinguishes_daily_and_hourly_rows() -> None:
    """The recorder rows alone reveal a promoted day if the store is lost."""
    daily = [(ny_midnight_utc(date(2026, 10, 19)), 10.0)]
    hourly = [
        (start, 1.0)
        for start in expected_hour_starts(date(2026, 10, 20))
    ]
    detected = detect_hourly_days(daily + hourly)
    assert date(2026, 10, 19) not in detected
    assert detected[date(2026, 10, 20)]["total_kwh"] == 24.0


def test_merge_replaces_the_whole_promoted_day() -> None:
    """The daily midnight row becomes the first hourly value, never both rows."""
    existing = [
        (ny_midnight_utc(date(2026, 10, 19)), 10.0),
        (ny_midnight_utc(date(2026, 10, 20)), 24.0),
        (ny_midnight_utc(date(2026, 10, 21)), 10.0),
    ]
    hourly = {
        date(2026, 10, 20): [
            {"start": start, "kwh": 1.0}
            for start in expected_hour_starts(date(2026, 10, 20))
        ]
    }
    rows, changed = merge_series_rows(
        existing,
        {
            ny_midnight_utc(date(2026, 10, 19)): 10.0,
            ny_midnight_utc(date(2026, 10, 20)): 24.0,
            ny_midnight_utc(date(2026, 10, 21)): 10.0,
        },
        hourly,
        {date(2026, 10, 20)},
        0.0,
    )
    assert changed is True
    day_rows = [row for row in rows if ny_day_of(row["start"]) == date(2026, 10, 20)]
    assert len(day_rows) == 24
    assert day_rows[0]["start"] == ny_midnight_utc(date(2026, 10, 20))
    assert day_rows[0]["state"] == 1.0
    assert rows[-1]["sum"] == 44.0


def test_merge_never_rewrites_a_protected_day_from_daily() -> None:
    """A daily fallback for a promoted day leaves the hourly contribution alone."""
    existing = [
        (ny_midnight_utc(date(2026, 10, 20)), 1.0),
        (ny_midnight_utc(date(2026, 10, 20)) + timedelta(hours=1), 1.0),
    ]
    rows, changed = merge_series_rows(
        existing,
        {ny_midnight_utc(date(2026, 10, 20)): 99.0},
        {},
        {date(2026, 10, 20)},
        0.0,
    )
    assert changed is False
    assert [row["state"] for row in rows] == [1.0, 1.0]


def test_day_records_match_uses_tolerance() -> None:
    """Stored rows and canonical rows are compared with a numeric tolerance."""
    start = ny_midnight_utc(date(2026, 10, 20))
    assert day_records_match([(start, 1.0)], [{"start": start, "kwh": 1.0 + 1e-10}])
    assert not day_records_match([(start, 1.0)], [{"start": start, "kwh": 1.1}])


def test_promotion_tolerance_has_an_absolute_floor() -> None:
    """Small days get a rounding floor; large days a relative allowance."""
    assert promotion_tolerance(1.0) >= 0.05
    assert promotion_tolerance(1000.0) > 0.05


def test_cost_tolerance_is_rounding_aware() -> None:
    """Daily cents and hourly six-decimal costs compare with a rounding allowance."""
    assert cost_tolerance(1.0) >= 0.01
    assert values_close(2.47, 2.475, abs_tol=cost_tolerance(2.47))
    assert not values_close(2.47, 2.60, abs_tol=cost_tolerance(2.47))


def test_label_consistency_helpers() -> None:
    """Only labels that carry a clock time can contradict the UTC timestamp."""
    start = datetime(2026, 10, 20, 4, 0, tzinfo=UTC)  # 00:00 New York
    assert label_matches_ny_time("10/20/2026", start) is None
    assert label_matches_ny_time("10/20/2026 12:00 AM", start) is True
    assert label_matches_ny_time("10/20/2026 02:00 AM", start) is False
    assert label_matches_ny_time("2026-10-20T04:00:00+00:00", start) is True
    assert label_matches_ny_time("garbage", start) is None

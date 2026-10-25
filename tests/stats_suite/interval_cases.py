"""Declarative test cases and fixtures for hourly interval table tests.

ORACLE INDEPENDENCE:
This module imports ONLY standard library and pure helpers from
tests.support.stats_model.
It contains NO production imports, row builders, or validators.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from tests.support.stats_model import (
    FALL_DST_2026,
    SPRING_DST_2026,
    ny_wall_hour_to_x_ms,
    resolve_raw_wall_hour,
)

NY_TZ = ZoneInfo("America/New_York")

EDT_REFERENCE_DAY = date(2026, 10, 5)  # 24 hours, UTC-4 (unpadded month/day 10/5)
EST_REFERENCE_DAY = date(2026, 12, 1)  # 24 hours, UTC-5 (unpadded day 12/1)
SPRING_2026_DAY = SPRING_DST_2026      # 2026-03-08, 23 hours (unpadded 3/8)
FALL_2026_DAY = FALL_DST_2026          # 2026-11-01, 25 hours (unpadded 11/1)


@dataclass(frozen=True)
class IntervalCase:
    """Specification of an interval and label test case."""

    case_id: str
    family: str
    description: str
    start_label_fn: Callable[[date, int, datetime], str | None]
    end_label_fn: Callable[[date, int, datetime], str | None]
    expected_helper_date_only: date | None | dict[int, date | None]
    expected_helper_label_match: bool | None | dict[int, bool | None]
    expected_invalid_points: int
    expected_complete: bool
    expected_reason: str | None
    nearest_valid_family: str
    is_malformed: bool = True

    def get_expected_date_only(self, arg1: Any = 0, arg2: Any = None) -> date | None:
        """Return expected date_only result for this day and hour."""
        day = arg1 if isinstance(arg1, date) else EDT_REFERENCE_DAY
        hour = arg2 if arg2 is not None else (arg1 if isinstance(arg1, int) else 0)

        if self.case_id in ("strict_same_date", "strict_next_date", "surrounding_whitespace"):
            return day
        if self.case_id == "wrong_start_date":
            return day + timedelta(days=1)
        if self.case_id in ("date_start_aware_noon_end", "end_plus_2_days"):
            return day
        if isinstance(self.expected_helper_date_only, dict):
            return self.expected_helper_date_only.get(hour)
        return self.expected_helper_date_only

    def get_expected_end_date_only(self, day: date = EDT_REFERENCE_DAY, hour: int = 0) -> date | None:
        """Return expected end date_only result for this day and hour."""
        if self.case_id in ("strict_same_date", "surrounding_whitespace"):
            return day
        if self.case_id == "strict_next_date":
            return day + timedelta(days=1)
        if self.case_id == "wrong_start_date":
            return day + timedelta(days=1)
        if self.case_id == "end_plus_2_days":
            return day + timedelta(days=2)
        if self.case_id in ("naive_iso_basic_datetime", "aware_iso_basic_wrong_hour"):
            return day
        return None

    def get_expected_label_match(self, arg1: Any = 0, arg2: Any = None) -> bool | None:
        """Return expected label_matches_ny_time result for this day and hour."""
        hour = arg2 if arg2 is not None else (arg1 if isinstance(arg1, int) else 0)

        if self.case_id in ("exact_both_aware_valid", "equal_bare_clocks", "one_aware_endpoint_missing_end", "both_aware_wrong_end"):
            return True
        if self.case_id == "both_aware_wrong_start":
            return False
        if self.case_id == "aware_iso_basic_wrong_hour":
            return hour == 23
        if isinstance(self.expected_helper_label_match, dict):
            return self.expected_helper_label_match.get(hour)
        return self.expected_helper_label_match

    def get_expected_end_label_match(self, day: date = EDT_REFERENCE_DAY, hour: int = 0) -> bool | None:
        """Return expected label_matches_ny_time result for the end label."""
        if self.case_id == "exact_both_aware_valid":
            return True
        if self.case_id in ("both_aware_wrong_end", "both_aware_wrong_start", "equal_bare_clocks"):
            return False
        if self.case_id == "date_start_aware_noon_end":
            return hour == 11
        return None

    def get_expected_record_label_ok(self, day: date, hour: int = 0) -> bool | None:
        """Return expected record label_ok for this day and hour."""
        if day == FALL_2026_DAY and hour == 1:
            if self.case_id in ("exact_both_aware_valid", "both_aware_wrong_end", "equal_bare_clocks", "one_aware_endpoint_missing_end"):
                return True
            if self.case_id in ("both_aware_wrong_start", "aware_iso_basic_wrong_hour"):
                return False
            return None

        if self.case_id in ("strict_same_date", "strict_next_date", "surrounding_whitespace", "exact_both_aware_valid"):
            return True
        if self.case_id in ("wrong_start_date", "both_aware_wrong_start"):
            return False
        if self.case_id == "aware_iso_basic_wrong_hour":
            return True if hour == 23 else False
        if self.case_id in ("end_plus_2_days", "both_aware_wrong_end", "equal_bare_clocks", "one_aware_endpoint_missing_end"):
            return True
        if self.case_id == "date_start_aware_noon_end":
            return None
        return None

    def get_expected_record_interval_ok(self, day: date, hour: int = 0) -> bool:
        """Return expected record interval_ok for this day and hour."""
        if self.is_malformed:
            return False
        if day == FALL_2026_DAY and hour == 1:
            return False
        return True

    def get_expected_record_interval_reason(self, day: date, hour: int = 0) -> str | None:
        """Return expected record interval_reason for this day and hour."""
        if day == FALL_2026_DAY and hour == 1:
            return "dst_ambiguous"
        if not self.is_malformed:
            return None
        if self.case_id in ("wrong_start_date", "both_aware_wrong_start"):
            return "label_mismatch"
        if self.case_id == "aware_iso_basic_wrong_hour":
            return "timestamp_semantics_unverified" if hour == 23 else "label_mismatch"
        if self.case_id in ("end_plus_2_days", "both_aware_wrong_end"):
            return "interval_end_mismatch"
        return "timestamp_semantics_unverified"

    def get_expected_day_complete(self, day: date) -> bool:
        """Return expected validate_hourly_day complete flag for this day."""
        if self.is_malformed:
            return False
        if day == FALL_2026_DAY:
            return False
        return True

    def get_expected_day_reason(self, day: date) -> str | None:
        """Return expected validate_hourly_day reason for this day."""
        if day == FALL_2026_DAY:
            if self.case_id in ("wrong_start_date", "both_aware_wrong_start", "aware_iso_basic_wrong_hour"):
                return "label_mismatch"
            if self.case_id in ("end_plus_2_days", "both_aware_wrong_end"):
                return "interval_end_mismatch"
            if self.is_malformed:
                return "timestamp_semantics_unverified"
            return "dst_ambiguous"
        return self.expected_reason


# Label generator factories
def _lbl_date_only_same(d: date, _h: int, _st: datetime) -> str:
    return d.strftime("%m/%d/%Y")


def _lbl_date_only_next(d: date, _h: int, _st: datetime) -> str:
    return (d + timedelta(days=1)).strftime("%m/%d/%Y")


def _lbl_date_only_whitespace(d: date, _h: int, _st: datetime) -> str:
    return f"  {d.strftime('%m/%d/%Y')}  "


def _lbl_aware_start(_d: date, _h: int, st: datetime) -> str:
    return st.isoformat()


def _lbl_aware_end(_d: date, _h: int, st: datetime) -> str:
    return (st + timedelta(hours=1)).isoformat()


def _lbl_bare_clock(d: date, h: int, _st: datetime) -> str:
    return f"{d.strftime('%m/%d/%Y')} {h:02d}:00"


INTERVAL_CASES: tuple[IntervalCase, ...] = (
    # --- Positive valid label families ---
    IntervalCase(
        case_id="strict_same_date",
        family="valid_label",
        description="Strict MM/DD/YYYY start and end matching NY calendar date",
        start_label_fn=_lbl_date_only_same,
        end_label_fn=_lbl_date_only_same,
        expected_helper_date_only=EDT_REFERENCE_DAY,
        expected_helper_label_match=None,  # date-only has no ":" -> returns None
        expected_invalid_points=0,
        expected_complete=True,
        expected_reason=None,
        nearest_valid_family="valid_label",
        is_malformed=False,
    ),
    IntervalCase(
        case_id="strict_next_date",
        family="valid_label",
        description="Strict MM/DD/YYYY start and next-day end",
        start_label_fn=_lbl_date_only_same,
        end_label_fn=_lbl_date_only_next,
        expected_helper_date_only=EDT_REFERENCE_DAY,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=True,
        expected_reason=None,
        nearest_valid_family="valid_label",
        is_malformed=False,
    ),
    IntervalCase(
        case_id="surrounding_whitespace",
        family="valid_label",
        description="Strict MM/DD/YYYY with leading and trailing whitespace",
        start_label_fn=_lbl_date_only_whitespace,
        end_label_fn=_lbl_date_only_whitespace,
        expected_helper_date_only=EDT_REFERENCE_DAY,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=True,
        expected_reason=None,
        nearest_valid_family="valid_label",
        is_malformed=False,
    ),
    IntervalCase(
        case_id="exact_both_aware_valid",
        family="valid_aware",
        description="Both endpoints aware ISO with exact 1-hour interval",
        start_label_fn=_lbl_aware_start,
        end_label_fn=_lbl_aware_end,
        expected_helper_date_only=None,
        expected_helper_label_match=True,
        expected_invalid_points=0,
        expected_complete=True,
        expected_reason=None,
        nearest_valid_family="valid_aware",
        is_malformed=False,
    ),

    # --- Malformed label cases ---
    IntervalCase(
        case_id="invalid_date_feb29_nonleap",
        family="invalid_calendar_date",
        description="Invalid calendar date 02/29 on non-leap year",
        start_label_fn=lambda _d, _h, _st: "02/29/2025",
        end_label_fn=lambda _d, _h, _st: "02/29/2025",
        expected_helper_date_only=None,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="invalid_date_month13",
        family="invalid_calendar_date",
        description="Invalid month 13/01/2026",
        start_label_fn=lambda _d, _h, _st: "13/01/2026",
        end_label_fn=lambda _d, _h, _st: "13/01/2026",
        expected_helper_date_only=None,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="invalid_date_day32",
        family="invalid_calendar_date",
        description="Invalid day 10/32/2026",
        start_label_fn=lambda d, _h, _st: d.strftime("%m/32/%Y"),
        end_label_fn=lambda d, _h, _st: d.strftime("%m/32/%Y"),
        expected_helper_date_only=None,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="iso_date_only",
        family="iso_date_only",
        description="ISO 8601 date-only format YYYY-MM-DD",
        start_label_fn=lambda d, _h, _st: d.strftime("%Y-%m-%d"),
        end_label_fn=lambda d, _h, _st: d.strftime("%Y-%m-%d"),
        expected_helper_date_only=None,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="surrounding_text",
        family="surrounding_text",
        description="Date label surrounded by extra text",
        start_label_fn=lambda d, _h, _st: f"Date: {d.strftime('%m/%d/%Y')}",
        end_label_fn=lambda d, _h, _st: f"Date: {d.strftime('%m/%d/%Y')}",
        expected_helper_date_only=None,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="missing_zero_padding",
        family="missing_zero_padding",
        description="Date label missing leading zeros on same calendar date",
        start_label_fn=lambda d, _h, _st: f"{d.month}/{d.day}/{d.year}",
        end_label_fn=lambda d, _h, _st: f"{d.month}/{d.day}/{d.year}",
        expected_helper_date_only=None,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="equal_bare_clocks",
        family="bare_clock",
        description="Equal bare clocks start and end (zero-length interval)",
        start_label_fn=_lbl_bare_clock,
        end_label_fn=_lbl_bare_clock,
        expected_helper_date_only=None,
        expected_helper_label_match=True,  # bare clock matches wall hour
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="one_aware_endpoint_missing_end",
        family="aware_endpoint",
        description="Aware start endpoint with missing end endpoint",
        start_label_fn=_lbl_aware_start,
        end_label_fn=lambda _d, _h, _st: None,
        expected_helper_date_only=None,
        expected_helper_label_match=True,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_aware",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="date_start_aware_noon_end",
        family="mixed_endpoints",
        description="Strict date-only start with aware noon end",
        start_label_fn=_lbl_date_only_same,
        end_label_fn=lambda d, _h, _st: f"{d.strftime('%Y-%m-%d')}T12:00:00-04:00",
        expected_helper_date_only=EDT_REFERENCE_DAY,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="naive_iso_basic_datetime",
        family="iso_basic",
        description="Naive ISO-basic datetime without colons",
        start_label_fn=lambda d, h, _st: f"{d.strftime('%Y-%m-%d')}T{h:02d}0000",
        end_label_fn=_lbl_date_only_same,
        expected_helper_date_only=None,
        expected_helper_label_match=None,  # no ":" in naive basic -> None
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="aware_iso_basic_wrong_hour",
        family="iso_basic",
        description="Aware ISO-basic datetime with wrong hour (fixed 23:00)",
        start_label_fn=lambda d, _h, _st: f"{d.strftime('%Y%m%d')}T230000{'-0400' if (SPRING_DST_2026 <= d < FALL_DST_2026) else '-0500'}",
        end_label_fn=_lbl_date_only_same,
        expected_helper_date_only=None,
        expected_helper_label_match={h: (h == 23) for h in range(24)},
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="label_mismatch",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="both_endpoints_absent",
        family="missing_endpoints",
        description="Both start and end labels absent (None)",
        start_label_fn=lambda _d, _h, _st: None,
        end_label_fn=lambda _d, _h, _st: None,
        expected_helper_date_only=None,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="timestamp_semantics_unverified",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="wrong_start_date",
        family="date_mismatch",
        description="Date-only start date belongs to next day",
        start_label_fn=lambda d, _h, _st: (d + timedelta(days=1)).strftime("%m/%d/%Y"),
        end_label_fn=lambda d, _h, _st: (d + timedelta(days=1)).strftime("%m/%d/%Y"),
        expected_helper_date_only=date(2026, 10, 6),
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="label_mismatch",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="end_plus_2_days",
        family="date_mismatch",
        description="Date-only end date is +2 days ahead",
        start_label_fn=_lbl_date_only_same,
        end_label_fn=lambda d, _h, _st: (d + timedelta(days=2)).strftime("%m/%d/%Y"),
        expected_helper_date_only=EDT_REFERENCE_DAY,
        expected_helper_label_match=None,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="interval_end_mismatch",
        nearest_valid_family="valid_label",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="both_aware_wrong_end",
        family="aware_endpoint",
        description="Both endpoints aware with 2-hour duration instead of 1-hour",
        start_label_fn=_lbl_aware_start,
        end_label_fn=lambda _d, _h, st: (st + timedelta(hours=2)).isoformat(),
        expected_helper_date_only=None,
        expected_helper_label_match=True,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="interval_end_mismatch",
        nearest_valid_family="valid_aware",
        is_malformed=True,
    ),
    IntervalCase(
        case_id="both_aware_wrong_start",
        family="aware_endpoint",
        description="Both endpoints aware with start offset by +1 hour",
        start_label_fn=lambda _d, _h, st: (st + timedelta(hours=1)).isoformat(),
        end_label_fn=lambda _d, _h, st: (st + timedelta(hours=2)).isoformat(),
        expected_helper_date_only=None,
        expected_helper_label_match=False,
        expected_invalid_points=0,
        expected_complete=False,
        expected_reason="label_mismatch",
        nearest_valid_family="valid_aware",
        is_malformed=True,
    ),
)

CASES_BY_ID: dict[str, IntervalCase] = {c.case_id: c for c in INTERVAL_CASES}

TIMESTAMP_VARIANTS: tuple[str, ...] = ("true_utc", "shifted_+4h", "shifted_-4h", "end_stamped_x")
ANOMALY_VARIANTS: tuple[str, ...] = ("duplicate_hour", "missing_hours", "extra_hours", "meter_swap")


def make_case_points(
    day: date,
    case: IntervalCase,
    hours: Sequence[int] | None = None,
    kwh_per_hour: float | Callable[[int], float] = 1.0,
    x_transform: Callable[[int], int] | None = None,
) -> list[dict[str, Any]]:
    """Build chart data points for one case on a specified day."""
    if hours is None:
        if day == SPRING_2026_DAY:
            hours = [0, 1, *range(3, 24)]
        elif day == FALL_2026_DAY:
            hours = [0, 1, 1, *range(2, 24)]
        else:
            hours = list(range(24))

    points: list[dict[str, Any]] = []
    seen_h1 = 0
    for h in hours:
        raw_x = ny_wall_hour_to_x_ms(day, h)
        x_val = raw_x if x_transform is None else x_transform(raw_x)
        if day == FALL_2026_DAY and h == 1:
            if seen_h1 == 0:
                st_utc = datetime(2026, 11, 1, 5, 0, 0, tzinfo=UTC)
                seen_h1 = 1
            else:
                st_utc = datetime(2026, 11, 1, 6, 0, 0, tzinfo=UTC)
        else:
            st_utc, _ = resolve_raw_wall_hour(day, h)
            if st_utc is None:
                st_utc = datetime(day.year, day.month, day.day, h, 0, 0, tzinfo=UTC)

        sl = case.start_label_fn(day, h, st_utc)
        el = case.end_label_fn(day, h, st_utc)
        hs: dict[str, Any] | None = None
        if sl is not None or el is not None:
            hs = {"start": sl, "end": el}

        val = kwh_per_hour(h) if callable(kwh_per_hour) else kwh_per_hour
        points.append({"x": x_val, "y": float(val), "hs": hs})
    return points


def make_valid_control_points(
    day: date,
    case: IntervalCase,
    hours: Sequence[int] | None = None,
    kwh_per_hour: float | Callable[[int], float] = 1.0,
) -> list[dict[str, Any]]:
    """Build valid control points matching the hours and values of the target case."""
    valid_case_id = (
        "exact_both_aware_valid"
        if case.nearest_valid_family == "valid_aware"
        else "strict_same_date"
    )
    valid_case = CASES_BY_ID[valid_case_id]
    return make_case_points(day, valid_case, hours=hours, kwh_per_hour=kwh_per_hour)


def make_timestamp_variant_points(
    day: date,
    variant: str,
    kwh_per_hour: float | Callable[[int], float] = 1.0,
) -> list[dict[str, Any]]:
    """Build points for timestamp encoding variants (true UTC, shifted x, end-stamped)."""
    valid_case = CASES_BY_ID["strict_same_date"]
    if variant == "true_utc":
        def to_true_utc_x(raw_x: int) -> int:
            dt_wall = datetime.fromtimestamp(raw_x / 1000.0, tz=UTC)
            st_utc, _ = resolve_raw_wall_hour(day, dt_wall.hour)
            if st_utc is None:
                st_utc = datetime(day.year, day.month, day.day, dt_wall.hour, 0, 0, tzinfo=UTC)
            return int(st_utc.timestamp() * 1000)

        return make_case_points(day, valid_case, kwh_per_hour=kwh_per_hour, x_transform=to_true_utc_x)
    if variant == "shifted_+4h":
        return make_case_points(day, valid_case, kwh_per_hour=kwh_per_hour, x_transform=lambda x: x + 4 * 3600 * 1000)
    if variant == "shifted_-4h":
        return make_case_points(day, valid_case, kwh_per_hour=kwh_per_hour, x_transform=lambda x: x - 4 * 3600 * 1000)
    if variant == "end_stamped_x":
        return make_case_points(day, valid_case, kwh_per_hour=kwh_per_hour, x_transform=lambda x: x + 3600 * 1000)
    raise ValueError(f"Unknown timestamp variant: {variant}")


def make_anomaly_points(
    day: date,
    anomaly: str,
    kwh_per_hour: float | Callable[[int], float] = 1.0,
) -> list[dict[str, Any]]:
    """Build points for coverage anomalies (missing, duplicate, extra hours)."""
    valid_case = CASES_BY_ID["strict_same_date"]
    if anomaly == "missing_hours":
        if day == SPRING_2026_DAY:
            hours = [0, 1, *range(3, 12), *range(13, 24)]  # 22 hours
        elif day == FALL_2026_DAY:
            hours = [0, 1, *range(2, 24)]  # 24 distinct hours
        else:
            hours = [h for h in range(24) if h != 12]  # 23 hours
        return make_case_points(day, valid_case, hours=hours, kwh_per_hour=kwh_per_hour)
    if anomaly == "extra_hours":
        pts = make_case_points(day, valid_case, kwh_per_hour=kwh_per_hour)
        next_day = day + timedelta(days=1)
        next_day_x = ny_wall_hour_to_x_ms(next_day, 0)
        pts.append(
            {
                "x": next_day_x,
                "y": 1.0 if not callable(kwh_per_hour) else float(kwh_per_hour(0)),
                "hs": {"start": day.strftime("%m/%d/%Y"), "end": day.strftime("%m/%d/%Y")},
            }
        )
        return pts
    if anomaly == "duplicate_hour":
        pts = make_case_points(day, valid_case, kwh_per_hour=kwh_per_hour)
        target_idx = 0 if len(pts) <= 6 else 6
        orig_y = pts[target_idx]["y"]
        pts[target_idx]["y"] = round(orig_y / 2.0, 4)
        dup = dict(pts[target_idx])
        dup["y"] = round(orig_y - pts[target_idx]["y"], 4)
        pts.append(dup)
        return pts
    if anomaly == "meter_swap":
        return make_case_points(day, valid_case, kwh_per_hour=kwh_per_hour)
    raise ValueError(f"Unknown anomaly: {anomaly}")

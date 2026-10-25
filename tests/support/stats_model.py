"""Independent reference calendar and Decimal statistics model for PSE&G.

This module provides an independent reference model for America/New_York
calendar logic and Home Assistant cumulative statistics chains using only
standard library (zoneinfo, decimal, datetime).

ORACLE INDEPENDENCE:
Do NOT import production expected_hour_starts, ny_day_bounds, ny_wall_ms_to_utc,
validate_hourly_day(s), statistics row builders, or any production helper into
this model or into expected values. Production is only the system under test.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
import math
from typing import Any
from zoneinfo import ZoneInfo

# Independent ZoneInfo instance for America/New_York
NY_TZ = ZoneInfo("America/New_York")
UTC_TZ = UTC

# Literal calendar controls
EDT_MIDNIGHT_UTC_OFFSET_HOURS = 4  # EDT is UTC-4 -> midnight is 04:00Z
EST_MIDNIGHT_UTC_OFFSET_HOURS = 5  # EST is UTC-5 -> midnight is 05:00Z

# Transition dates declared as independent literals
SPRING_DST_2026 = date(2026, 3, 8)   # 23 hours in NY (clocks skip 02:00 -> 03:00)
FALL_DST_2026 = date(2026, 11, 1)    # 25 hours in NY (clocks repeat 01:00)

SPRING_DST_2025 = date(2025, 3, 9)   # 23 hours in NY (control)
FALL_DST_2025 = date(2025, 11, 2)    # 25 hours in NY (control)

# Standard statistic identifiers for the reference meter
DEFAULT_METER_ID = "m1"
CONSUMPTION_STATISTIC_ID = f"pseg:{DEFAULT_METER_ID}_energy_consumption"
COST_STATISTIC_ID = f"pseg:{DEFAULT_METER_ID}_energy_cost"

# Decimal quantization constants
DECIMAL_HOURLY_PRECISION = Decimal("0.000001")
DECIMAL_DAILY_COST_PRECISION = Decimal("0.01")


def to_decimal(val: float | int | str | Decimal) -> Decimal:
    """Convert input scalar to Decimal safely without binary float drift."""
    if isinstance(val, Decimal):
        return val
    return Decimal(str(val))


def ny_day_start_utc(day: date) -> datetime:
    """Return local midnight for the given New York date as an aware UTC datetime."""
    return datetime(day.year, day.month, day.day, 0, 0, 0, tzinfo=NY_TZ).astimezone(UTC)


def ny_day_end_utc(day: date) -> datetime:
    """Return end of the given New York date (next day midnight) as an aware UTC datetime."""
    next_day = day + timedelta(days=1)
    return datetime(next_day.year, next_day.month, next_day.day, 0, 0, 0, tzinfo=NY_TZ).astimezone(UTC)


def ny_day_hours_utc(day: date) -> list[datetime]:
    """Return all hourly start datetimes in UTC for one America/New_York date.

    Returns:
    - 23 starts for spring forward (e.g. 2026-03-08, 2025-03-09)
    - 25 starts for fall back (e.g. 2026-11-01, 2025-11-02)
    - 24 starts for all standard days
    """
    starts: list[datetime] = []
    current = ny_day_start_utc(day)
    end = ny_day_end_utc(day)
    while current < end:
        starts.append(current)
        current += timedelta(hours=1)
    return starts


def ny_day_of_utc(dt: datetime) -> date:
    """Convert an aware UTC datetime to the corresponding America/New_York date."""
    return dt.astimezone(NY_TZ).date()


def ny_wall_hour_to_x_ms(day: date, wall_hour: int) -> int:
    """Represent an America/New_York wall-clock hour start as UTC epoch milliseconds."""
    wall_dt = datetime(day.year, day.month, day.day, wall_hour, 0, 0, tzinfo=UTC)
    return int(wall_dt.timestamp() * 1000)


def x_ms_to_ny_wall_hour(x_ms: int) -> tuple[date, int]:
    """Recover the raw wall-clock date and hour from UTC epoch milliseconds."""
    dt = datetime.fromtimestamp(x_ms / 1000.0, tz=UTC)
    return dt.date(), dt.hour


def resolve_raw_wall_hour(day: date, wall_hour: int) -> tuple[datetime | None, str]:
    """Resolve raw date and wall-clock hour to UTC start and contract status.

    Returns (utc_datetime, status):
    - status 'ok': unique resolvable wall hour
    - status 'dst_nonexistent': gap hour on spring forward (e.g. 2026-03-08 02:00)
    - status 'dst_ambiguous': ambiguous hour on fall back (e.g. 2026-11-01 01:00)
    """
    if day == SPRING_DST_2026 and wall_hour == 2:
        return None, "dst_nonexistent"
    if day == FALL_DST_2026 and wall_hour == 1:
        # First occurrence (fold 0, EDT: UTC-4 -> 01:00 EDT is 05:00Z)
        return datetime(2026, 11, 1, 5, 0, 0, tzinfo=UTC), "dst_ambiguous"
    local_dt = datetime(day.year, day.month, day.day, wall_hour, 0, 0, tzinfo=NY_TZ)
    return local_dt.astimezone(UTC), "ok"


def enumerate_2026_days() -> list[tuple[date, int, list[datetime]]]:
    """Independently enumerate all 365 days of 2026 with their hour counts and UTC starts."""
    days: list[tuple[date, int, list[datetime]]] = []
    cur = date(2026, 1, 1)
    for _ in range(365):
        starts = ny_day_hours_utc(cur)
        days.append((cur, len(starts), starts))
        cur += timedelta(days=1)
    return days


@dataclass(frozen=True)
class ReferenceRow:
    """Immutable representation of one expected statistics row."""

    start: datetime
    state: Decimal
    sum: Decimal

    def as_tuple(self, precision: int = 6) -> tuple[datetime, float, float]:
        """Convert row to (start_utc, state_float, sum_float)."""
        return (
            self.start,
            float(round(self.state, precision)),
            float(round(self.sum, precision)),
        )


@dataclass
class _DayState:
    """Internal storage for one New York calendar day."""

    day: date
    daily_kwh: Decimal
    daily_cost: Decimal
    hourly_kwh: list[tuple[datetime, Decimal]] | None = None
    is_promoted: bool = False


class ReferenceStatisticsModel:
    """Pure Decimal reference model computing expected recorder rows independently.

    Features:
    - Independent calendar / zoneinfo calculation of starts
    - Decimal arithmetic for energy consumption and cost
    - Preservation of older history on subsequent imports
    - Automatic suffix sum recomputation on older day corrections
    - Protection of promoted hourly days against daily retries (no downgrade)
    - Prevention of daily + hourly double counting
    - Explicit support for zero days (state=0, sum conserved) vs sparse/missing days
    """

    def __init__(
        self,
        price_per_kwh: Decimal | float | str = Decimal("0.25"),
        meter_id: str = DEFAULT_METER_ID,
    ) -> None:
        self.price_per_kwh = to_decimal(price_per_kwh)
        self.meter_id = meter_id
        self.clean_meter = meter_id.lower().replace(" ", "_")
        self.consumption_statistic_id = f"pseg:{self.clean_meter}_energy_consumption"
        self.cost_statistic_id = f"pseg:{self.clean_meter}_energy_cost"
        self._days: dict[date, _DayState] = {}

    def record_daily(
        self, records: Sequence[Mapping[str, Any]], price_per_kwh: Decimal | float | None = None
    ) -> None:
        """Record daily records.

        If a day was already promoted to hourly, the daily record cannot downgrade
        or overwrite the promoted day.
        """
        price = to_decimal(price_per_kwh) if price_per_kwh is not None else self.price_per_kwh
        for rec in records:
            d_raw = rec["date"]
            day = date.fromisoformat(d_raw) if isinstance(d_raw, str) else d_raw
            kwh = to_decimal(rec["kwh"])
            if "cost" in rec and rec["cost"] is not None:
                cost = to_decimal(rec["cost"])
            else:
                cost = (kwh * price).quantize(DECIMAL_DAILY_COST_PRECISION, rounding=ROUND_HALF_UP)

            if day in self._days and self._days[day].is_promoted:
                # Promoted days are protected against daily retry downgrades
                continue

            self._days[day] = _DayState(
                day=day,
                daily_kwh=kwh,
                daily_cost=cost,
                hourly_kwh=None,
                is_promoted=False,
            )

    def promote_hourly(
        self,
        day: date | str,
        hourly_records: Sequence[Mapping[str, Any]] | Sequence[tuple[datetime, Decimal | float]],
        price_per_kwh: Decimal | float | None = None,
    ) -> None:
        """Promote a day to hourly, replacing the daily row with full hourly rows."""
        d = date.fromisoformat(day) if isinstance(day, str) else day
        price = to_decimal(price_per_kwh) if price_per_kwh is not None else self.price_per_kwh

        hours: list[tuple[datetime, Decimal]] = []
        total_kwh = Decimal("0")
        for item in hourly_records:
            if isinstance(item, tuple):
                st, val = item
            else:
                st = item["start"]
                val = item["kwh"]
            dec_kwh = to_decimal(val)
            hours.append((st, dec_kwh))
            total_kwh += dec_kwh

        total_cost = total_kwh * price
        self._days[d] = _DayState(
            day=d,
            daily_kwh=total_kwh,
            daily_cost=total_cost,
            hourly_kwh=hours,
            is_promoted=True,
        )

    def correct_day(
        self,
        day: date | str,
        new_kwh: Decimal | float,
        new_cost: Decimal | float | None = None,
        price_per_kwh: Decimal | float | None = None,
    ) -> None:
        """Apply a correction to an existing day (daily mode).

        This recomputes the suffix sums for all later rows in the timeline.
        """
        d = date.fromisoformat(day) if isinstance(day, str) else day
        price = to_decimal(price_per_kwh) if price_per_kwh is not None else self.price_per_kwh
        dec_kwh = to_decimal(new_kwh)
        if new_cost is not None:
            dec_cost = to_decimal(new_cost)
        else:
            dec_cost = (dec_kwh * price).quantize(DECIMAL_DAILY_COST_PRECISION, rounding=ROUND_HALF_UP)

        self._days[d] = _DayState(
            day=d,
            daily_kwh=dec_kwh,
            daily_cost=dec_cost,
            hourly_kwh=None,
            is_promoted=False,
        )

    def expected_rows(self, statistic_id: str | None = None) -> list[ReferenceRow]:
        """Compute expected rows with strictly chained cumulative sums.

        Supports both `pseg:m1_energy_consumption` and `pseg:m1_energy_cost`.
        """
        target_id = statistic_id or self.consumption_statistic_id
        is_cost = (target_id == self.cost_statistic_id)

        # Collect all points: (start_utc, state_decimal)
        points: list[tuple[datetime, Decimal]] = []
        for d in sorted(self._days):
            st_data = self._days[d]
            if st_data.is_promoted and st_data.hourly_kwh:
                for h_start, h_kwh in sorted(st_data.hourly_kwh, key=lambda x: x[0]):
                    if is_cost:
                        state = h_kwh * self.price_per_kwh
                    else:
                        state = h_kwh
                    points.append((h_start, state))
            else:
                h_start = ny_day_start_utc(d)
                if is_cost:
                    state = st_data.daily_cost
                else:
                    state = st_data.daily_kwh
                points.append((h_start, state))

        # Sort strictly by start datetime
        points.sort(key=lambda p: p[0])

        rows: list[ReferenceRow] = []
        running_sum = Decimal("0")
        for start_dt, state in points:
            running_sum += state
            rows.append(ReferenceRow(start=start_dt, state=state, sum=running_sum))

        return rows

    def expected_rows_as_tuples(
        self, statistic_id: str | None = None, precision: int = 6
    ) -> list[tuple[datetime, float, float]]:
        """Return expected rows formatted as (start_utc, state_float, sum_float)."""
        return [r.as_tuple(precision) for r in self.expected_rows(statistic_id)]


def assert_chained_nondecreasing(rows: Sequence[tuple[datetime, float, float] | ReferenceRow]) -> None:
    """Verify that cumulative sums along the chain are monotonically nondecreasing."""
    prev_sum = -float("inf")
    for row in rows:
        val = row.sum if isinstance(row, ReferenceRow) else row[2]
        float_val = float(val)
        if float_val < prev_sum - 1e-9:
            raise AssertionError(f"Cumulative sum decreased from {prev_sum} to {float_val} in chain")
        prev_sum = float_val


def compare_series(
    actual: Sequence[tuple[datetime, float, float]],
    expected: Sequence[tuple[datetime, float, float]],
    *,
    label: str = "series",
    abs_tol: float = 1e-4,
) -> None:
    """Compare actual recorder rows against expected reference rows.

    Verifies row counts, exact UTC start timestamps, and floating-point states and sums.
    """
    if len(actual) != len(expected):
        raise AssertionError(
            f"Row count mismatch for {label}: actual={len(actual)} vs expected={len(expected)}"
        )
    for idx, (act, exp) in enumerate(zip(actual, expected)):
        act_st, act_val, act_sum = act
        exp_st, exp_val, exp_sum = exp
        if act_st != exp_st:
            raise AssertionError(
                f"Row {idx} start mismatch for {label}: actual start {act_st} != expected start {exp_st}"
            )
        if not math.isclose(act_val, exp_val, abs_tol=abs_tol):
            raise AssertionError(
                f"Row {idx} ({act_st}) state mismatch for {label}: actual {act_val} != expected {exp_val}"
            )
        if not math.isclose(act_sum, exp_sum, abs_tol=abs_tol):
            raise AssertionError(
                f"Row {idx} ({act_st}) sum mismatch for {label}: actual {act_sum} != expected {exp_sum}"
            )


def compare_both_series(
    actual_consumption: Sequence[tuple[datetime, float, float]],
    actual_cost: Sequence[tuple[datetime, float, float]],
    expected_consumption: Sequence[tuple[datetime, float, float]],
    expected_cost: Sequence[tuple[datetime, float, float]],
    *,
    abs_tol: float = 1e-4,
) -> None:
    """Explicitly verify BOTH consumption and cost series against expected rows.

    Fails if the cost series comparison is omitted or empty.
    """
    if not actual_cost or not expected_cost:
        raise AssertionError(
            "Cost series comparison was omitted or empty: both pseg:m1_energy_consumption "
            "and pseg:m1_energy_cost must be compared."
        )
    if not actual_consumption or not expected_consumption:
        raise AssertionError(
            "Consumption series comparison was omitted or empty: both pseg:m1_energy_consumption "
            "and pseg:m1_energy_cost must be compared."
        )

    compare_series(
        actual_consumption,
        expected_consumption,
        label=CONSUMPTION_STATISTIC_ID,
        abs_tol=abs_tol,
    )
    compare_series(
        actual_cost,
        expected_cost,
        label=COST_STATISTIC_ID,
        abs_tol=abs_tol,
    )

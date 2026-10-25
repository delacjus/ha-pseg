"""Pure rules for promoting hourly meter data into long-term statistics.

The vendor's hourly chart contract is not proven yet, so an hourly day is only
trusted when it is *closed* and *complete*: the exact set of UTC hourly starts
between two America/New_York midnights (23, 24 or 25 of them), every value finite
(including an explicit zero), a consistent raw label when the payload carries one,
and a total that agrees with the separately fetched authoritative daily total
within rounding tolerance. Nothing here guesses a missing hour or manufactures a
zero.

The client uses :func:`validate_hourly_days` to decide whether sensor history may
use the hourly aggregate; the coordinator uses the same result to decide whether
the recorder may be promoted. Keeping one rule set means the sensor and the
statistics can never disagree about whether a day is trustworthy.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time, timedelta
import math
import re
from typing import Any
import zoneinfo

from .const import STATISTICS_PRECISION

NY_TZ = zoneinfo.ZoneInfo("America/New_York")

# A promoted day must agree with the separately sourced daily total. Daily kWh is
# published with cents-level rounding by parts of the portal, so a small absolute
# floor is required; the relative term keeps large days from being over-trusted.
PROMOTION_ABS_TOLERANCE_KWH = 0.05
PROMOTION_REL_TOLERANCE = 0.002
# Cost is estimated from kWh. Daily records carry cents; hourly cost states carry
# six decimals. Comparisons are rounding-aware, never exact float equality.
COST_ABS_TOLERANCE = 0.01
COST_REL_TOLERANCE = 0.002
# A raw label may be rounded by the portal; five minutes still catches a shifted
# timestamp (the smallest real shift is one hour).
LABEL_TOLERANCE_SECONDS = 300
# Row states are compared for "did anything change" at database precision.
ROW_EPSILON = 1e-9

# Fixed reason vocabulary exposed in diagnostics. Anything outside this set is not
# reported, so a future string can never leak payload content by accident.
STATISTICS_INCOMPLETE_REASONS = frozenset(
    {
        "granularity_not_hourly",
        "no_daily_total",
        "open_day",
        "naive_start",
        "unaligned_start",
        "unexpected_start",
        "non_numeric",
        "non_finite",
        "negative_value",
        "label_mismatch",
        "interval_end_mismatch",
        "timestamp_semantics_unverified",
        "missing_hours",
        "unexpected_hours",
        "sum_mismatch",
        "dst_ambiguous",
    }
)

_HOURLY_LABEL_FORMATS = (
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M %p",
)


@dataclass(frozen=True, slots=True)
class HourlyDayValidation:
    """Outcome of checking one New York calendar day of hourly points."""

    day: date
    complete: bool
    reason: str | None
    total_kwh: float
    records: tuple[dict[str, Any], ...]
    expected_hours: int
    received_hours: int


def ny_midnight(day: date) -> datetime:
    """Return the America/New_York midnight that starts *day* (aware)."""
    return datetime.combine(day, time.min, tzinfo=NY_TZ)


def ny_midnight_utc(day: date) -> datetime:
    """Return the UTC instant of the New York midnight that starts *day*."""
    return ny_midnight(day).astimezone(UTC)


def ny_day_bounds(day: date) -> tuple[datetime, datetime]:
    """Return [start, end) in UTC for one New York calendar day.

    The end is the *next* local midnight, so DST days are 23 or 25 hours rather
    than a fixed 24. Home Assistant's configured time zone is never consulted.
    """
    return ny_midnight_utc(day), ny_midnight_utc(day + timedelta(days=1))


def ny_day_of(start: datetime) -> date:
    """Return the New York calendar date containing an aware timestamp."""
    return start.astimezone(NY_TZ).date()


def expected_hour_starts(day: date) -> list[datetime]:
    """Return every UTC hourly start between consecutive New York midnights.

    A normal day returns 24 starts, the spring DST day 23 and the fall DST day 25.
    """
    start, end = ny_day_bounds(day)
    starts: list[datetime] = []
    current = start
    while current < end:
        starts.append(current)
        current += timedelta(hours=1)
    return starts


def parse_day(value: Any) -> date | None:
    """Parse an ISO day string, returning None instead of raising."""
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def promotion_tolerance(daily_total: float) -> float:
    """Rounding tolerance for comparing hourly kWh with a daily kWh total."""
    return max(
        PROMOTION_ABS_TOLERANCE_KWH,
        abs(float(daily_total)) * PROMOTION_REL_TOLERANCE,
    )


def cost_tolerance(reference: float) -> float:
    """Rounding tolerance for comparing cent-rounded cost with hourly cost."""
    return max(COST_ABS_TOLERANCE, abs(float(reference)) * COST_REL_TOLERANCE)


def values_close(
    left: Any,
    right: Any,
    *,
    abs_tol: float,
    rel_tol: float = 0.0,
) -> bool:
    """Compare finite numbers with an absolute and optional relative tolerance."""
    if left is None or right is None:
        return left is right
    try:
        first = float(left)
        second = float(right)
    except (TypeError, ValueError):
        return False
    if not (math.isfinite(first) and math.isfinite(second)):
        return False
    return abs(first - second) <= max(
        abs_tol, rel_tol * max(abs(first), abs(second))
    )


def parse_aware_label(label: Any) -> datetime | None:
    """Parse a label only when it carries an explicit UTC offset or timezone.

    A date-only or naked wall-clock label cannot prove whether ``x`` is the
    interval start or end, so it is deliberately not usable as positive evidence.
    """
    if not label:
        return None
    text = str(label).strip()
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%m/%d/%Y %H:%M:%S %z", "%m/%d/%Y %H:%M %z"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None or parsed.tzinfo is None:
        return None
    return parsed


def ny_wall_ms_to_utc(ms: float | int) -> tuple[datetime | None, str]:
    """Convert a New York wall-clock timestamp encoded as UTC epoch ms to true UTC.

    ChartData encodes the America/New_York wall clock as if it were UTC epoch ms
    (e.g. 00:00 local midnight is encoded as 00:00 UTC).

    Returns:
        (utc_dt, "ok"): Unique wall time in America/New_York.
        (utc_dt, "dst_ambiguous"): Fall-back hour occurring twice (fold 0 used).
        (None, "dst_nonexistent"): Spring-forward gap hour (skipped).
    """
    wall = datetime.fromtimestamp(ms / 1000, tz=UTC).replace(tzinfo=None)
    a0 = wall.replace(tzinfo=NY_TZ, fold=0)
    a1 = wall.replace(tzinfo=NY_TZ, fold=1)
    if a0.astimezone(UTC).astimezone(NY_TZ).replace(tzinfo=None) != wall:
        return (None, "dst_nonexistent")
    if a0.utcoffset() != a1.utcoffset():
        return (a0.astimezone(UTC), "dst_ambiguous")
    return (a0.astimezone(UTC), "ok")


_DATE_ONLY_LABEL_RE = re.compile(r"^\s*(\d{2})/(\d{2})/(\d{4})\s*$")


def parse_date_only_label(label: Any) -> date | None:
    """Parse a strict MM/DD/YYYY date-only label.

    Matches only strings of the form MM/DD/YYYY (with optional leading/trailing
    whitespace). Returns a datetime.date object or None if the format does not match
    or represents an invalid calendar date.
    """
    if label is None:
        return None
    text = str(label)
    m = _DATE_ONLY_LABEL_RE.fullmatch(text)
    if not m:
        return None
    month_str, day_str, year_str = m.groups()
    try:
        return date(int(year_str), int(month_str), int(day_str))
    except ValueError:
        return None


def label_matches_ny_time(label: Any, start_utc: datetime) -> bool | None:
    """Check a raw chart label against the New York wall clock.

    Returns True/False when the label carries a time of day, and None when it is
    date-only or unparseable: those carry no hour, so they are not evidence either
    way. ISO labels with an explicit offset are compared in UTC; naked labels are
    treated as portal wall-clock time in America/New_York.
    """
    if not label or not isinstance(start_utc, datetime):
        return None
    text = str(label).strip()
    if not text:
        return None

    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in _HOURLY_LABEL_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None

    if parsed.tzinfo is not None:
        label_utc = parsed.astimezone(UTC)
        return abs((label_utc - start_utc).total_seconds()) <= LABEL_TOLERANCE_SECONDS

    # A date-only label (no clock component) says nothing about the hour.
    if ":" not in text:
        return None
    local = start_utc.astimezone(NY_TZ).replace(tzinfo=None)
    return abs((parsed - local).total_seconds()) <= LABEL_TOLERANCE_SECONDS


def validate_hourly_day(
    day: date,
    points: Sequence[Mapping[str, Any]],
    daily_total: float | None,
    now: datetime,
    *,
    granularity: str = "hourly",
) -> HourlyDayValidation:
    """Decide whether one closed New York day may replace its daily row.

    ``points`` are the client's canonical records: ``{"start": aware UTC
    datetime, "kwh": float, "label_ok": bool | None}``. Duplicate starts are summed
    (a meter swap can split one hour across two meter series); the daily-total
    check then catches any accidental double count.
    """
    expected = expected_hour_starts(day)
    expected_set = set(expected)
    empty = HourlyDayValidation(
        day=day,
        complete=False,
        reason=None,
        total_kwh=0.0,
        records=(),
        expected_hours=len(expected),
        received_hours=0,
    )

    if granularity != "hourly":
        return replace(empty, reason="granularity_not_hourly")
    if daily_total is None or not math.isfinite(float(daily_total)):
        return replace(empty, reason="no_daily_total")
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    if ny_day_bounds(day)[1] > now:
        return replace(empty, reason="open_day")

    by_start: dict[datetime, float] = {}
    label_mismatch = False
    interval_failure: str | None = None
    for point in points:
        start = point.get("start")
        if not isinstance(start, datetime) or start.tzinfo is None:
            return replace(empty, reason="naive_start")
        start = start.astimezone(UTC)
        if start.minute or start.second or start.microsecond:
            return replace(empty, reason="unaligned_start")
        if start not in expected_set:
            return replace(empty, reason="unexpected_start")
        try:
            kwh = float(point.get("kwh"))
        except (TypeError, ValueError):
            return replace(empty, reason="non_numeric")
        if not math.isfinite(kwh):
            return replace(empty, reason="non_finite")
        if kwh < 0:
            return replace(empty, reason="negative_value")
        if point.get("label_ok") is False:
            label_mismatch = True
        if point.get("interval_ok") is not True:
            reason = point.get("interval_reason")
            if reason == "interval_end_mismatch":
                interval_failure = "interval_end_mismatch"
            elif interval_failure is None:
                interval_failure = reason or "timestamp_semantics_unverified"
        by_start[start] = by_start.get(start, 0.0) + kwh

    if label_mismatch:
        return replace(empty, reason="label_mismatch")
    if interval_failure:
        return replace(empty, reason=interval_failure)
    if set(by_start) != expected_set:
        reason = (
            "missing_hours"
            if expected_set - set(by_start)
            else "unexpected_hours"
        )
        return replace(empty, reason=reason, received_hours=len(by_start))

    total = round(sum(by_start.values()), STATISTICS_PRECISION)
    if not values_close(total, daily_total, abs_tol=promotion_tolerance(float(daily_total))):
        return replace(
            empty,
            reason="sum_mismatch",
            total_kwh=total,
            received_hours=len(by_start),
        )

    records = tuple(
        {"start": start, "kwh": round(by_start[start], STATISTICS_PRECISION)}
        for start in expected
    )
    return HourlyDayValidation(
        day=day,
        complete=True,
        reason=None,
        total_kwh=total,
        records=records,
        expected_hours=len(expected),
        received_hours=len(by_start),
    )


def validate_hourly_days(
    records: Iterable[Mapping[str, Any]],
    daily_totals: Mapping[date, float],
    now: datetime,
    *,
    granularity: str = "hourly",
    days: Iterable[date] | None = None,
) -> dict[date, HourlyDayValidation]:
    """Validate every candidate New York day in one pass.

    With ``days`` omitted, every day seen in the hourly records or the daily totals
    is checked. Days without an authoritative daily total are reported as
    ``no_daily_total`` and are never promoted.
    """
    grouped: dict[date, list[Mapping[str, Any]]] = {}
    for record in records:
        start = record.get("start")
        if isinstance(start, datetime) and start.tzinfo is not None:
            grouped.setdefault(ny_day_of(start), []).append(record)

    candidates = set(grouped) | set(daily_totals)
    if days is not None:
        candidates = set(days)

    return {
        day: validate_hourly_day(
            day,
            grouped.get(day, ()),
            daily_totals.get(day),
            now,
            granularity=granularity,
        )
        for day in sorted(candidates)
    }


def detect_hourly_days(
    rows: Sequence[tuple[datetime, float | None]],
) -> dict[date, dict[str, float]]:
    """Return stored days that already carry hourly provenance.

    A day is hourly when it has more than one stored row, or its only row is not at
    New York midnight. This is a second line of defence for a lost or damaged
    provenance store: the recorder itself still shows which days must not be
    downgraded by a later daily retry.
    """
    by_day: dict[date, list[tuple[datetime, float | None]]] = {}
    for start, state in rows:
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        by_day.setdefault(ny_day_of(start), []).append((start, state))

    detected: dict[date, dict[str, float]] = {}
    for day, entries in by_day.items():
        midnight = ny_midnight_utc(day)
        if len(entries) > 1 or any(start != midnight for start, _ in entries):
            detected[day] = {
                "total_kwh": round(
                    sum((state or 0.0) for _, state in entries),
                    STATISTICS_PRECISION,
                )
            }
    return detected


def rows_by_day(
    rows: Sequence[tuple[datetime, float | None]],
) -> dict[date, list[tuple[datetime, float | None]]]:
    """Group stored (start, state) rows by New York calendar day."""
    grouped: dict[date, list[tuple[datetime, float | None]]] = {}
    for start, state in rows:
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        grouped.setdefault(ny_day_of(start), []).append((start, state))
    return {day: sorted(entries) for day, entries in grouped.items()}


def day_records_match(
    existing: Sequence[tuple[datetime, float | None]],
    records: Sequence[Mapping[str, Any]],
    *,
    abs_tol: float = ROW_EPSILON,
) -> bool:
    """Return True when stored rows already equal the canonical hourly records."""
    if len(existing) != len(records):
        return False
    by_start = {start: state for start, state in existing}
    for record in records:
        start = record.get("start")
        if start not in by_start:
            return False
        if not values_close(by_start[start], record.get("kwh"), abs_tol=abs_tol):
            return False
    return True


def chain_rows(
    by_start: Mapping[datetime, float | None],
    prior_sum: float | None,
    *,
    precision: int = STATISTICS_PRECISION,
) -> list[dict[str, Any]]:
    """Build a strictly cumulative sum chain over every row in ``by_start``."""
    running = float(prior_sum or 0.0)
    rows: list[dict[str, Any]] = []
    for start in sorted(by_start):
        state = by_start[start]
        running += state or 0.0
        rows.append(
            {"start": start, "state": state, "sum": round(running, precision)}
        )
    return rows


def merge_series_rows(
    existing: Sequence[tuple[datetime, float | None]],
    daily_by_start: Mapping[datetime, float],
    hourly_replace: Mapping[date, Sequence[Mapping[str, Any]]],
    protected_days: set[date],
    prior_sum: float | None,
    *,
    precision: int = STATISTICS_PRECISION,
) -> tuple[list[dict[str, Any]], bool]:
    """Merge a daily/hourly import with every stored row and re-chain all later sums.

    ``hourly_replace`` days have *all* their stored rows replaced by the complete
    hourly set (the daily midnight row included; the first hourly value overwrites
    it in the same statistic id). ``protected_days`` are promoted or pending days:
    a daily fallback never touches them. Days omitted from both maps keep whatever
    is stored, so gaps, older rows and newer rows stay in the chain.

    Returns the rows to import and whether anything actually changed.
    """
    by_start: dict[datetime, float | None] = {
        start: state for start, state in existing
    }

    for day, records in hourly_replace.items():
        day_start, day_end = ny_day_bounds(day)
        for start in [value for value in by_start if day_start <= value < day_end]:
            del by_start[start]
        for record in records:
            start = record["start"]
            by_start[start] = record["kwh"]

    for start, value in daily_by_start.items():
        day = ny_day_of(start)
        if day in hourly_replace or day in protected_days:
            # A promoted day is replaced only by its full hourly set; the daily
            # midnight row must never overwrite the first hourly value.
            continue
        by_start[start] = value

    changed = _rows_changed(existing, by_start)
    return chain_rows(by_start, prior_sum, precision=precision), changed


def _rows_changed(
    existing: Sequence[tuple[datetime, float | None]],
    by_start: Mapping[datetime, float | None],
) -> bool:
    old = dict(existing)
    if len(old) != len(by_start):
        return True
    for start, value in by_start.items():
        if start not in old:
            return True
        if not values_close(old[start], value, abs_tol=ROW_EPSILON):
            return True
    return False

"""Test case definitions and input fixtures for reference model validation.

ORACLE INDEPENDENCE:
This module imports ONLY standard library and the independent tests.support.stats_model.
It contains NO production imports, row builders, or validators.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any

from tests.support.stats_model import (
    FALL_DST_2026,
    SPRING_DST_2026,
    ny_day_hours_utc,
    ny_wall_hour_to_x_ms,
    to_decimal,
)


def make_daily_records(
    start_date: str | date,
    count: int,
    kwh: float | Decimal = 10.0,
    price_per_kwh: float | Decimal = 0.25,
    *,
    skips: frozenset[int] = frozenset(),
    overrides: dict[int, tuple[float | Decimal, float | Decimal]] | None = None,
) -> list[dict[str, Any]]:
    """Build a list of daily portal records with authoritative kWh and estimated cost."""
    d0 = date.fromisoformat(start_date) if isinstance(start_date, str) else start_date
    price = to_decimal(price_per_kwh)
    records: list[dict[str, Any]] = []
    override_map = overrides or {}

    for i in range(count):
        if i in skips:
            continue
        cur_date = d0 + timedelta(days=i)
        if i in override_map:
            kwh_val, cost_val = override_map[i]
            cur_kwh = float(kwh_val)
            cur_cost = float(cost_val)
        else:
            cur_kwh = float(kwh)
            cur_cost = round(cur_kwh * float(price), 2)
        records.append(
            {
                "date": cur_date.strftime("%Y-%m-%d"),
                "kwh": cur_kwh,
                "cost": cur_cost,
            }
        )
    return records


def make_canonical_hourly_records(
    day: str | date,
    kwh_per_hour: float | Decimal = 1.0,
    *,
    skip_indices: frozenset[int] = frozenset(),
) -> list[dict[str, Any]]:
    """Build canonical aware hourly records using the independent calendar model.

    Produces 23 starts on 2026-03-08, 25 starts on 2026-11-01, and 24 on normal days.
    """
    d = date.fromisoformat(day) if isinstance(day, str) else day
    kwh_val = float(kwh_per_hour)
    starts = ny_day_hours_utc(d)
    return [
        {
            "start": start,
            "kwh": kwh_val,
            "label_ok": True,
            "interval_ok": True,
            "interval_reason": None,
        }
        for idx, start in enumerate(starts)
        if idx not in skip_indices
    ]


def make_raw_chart_points(
    day: str | date,
    kwh_per_hour: float | Decimal = 1.0,
    *,
    hours: Sequence[int] | None = None,
    aware_labels: bool = False,
) -> list[dict[str, Any]]:
    """Build raw PSEG ChartData points with x milliseconds and hs labels."""
    d = date.fromisoformat(day) if isinstance(day, str) else day
    hour_list = list(hours) if hours is not None else list(range(24))
    kwh_val = float(kwh_per_hour)
    date_str = d.strftime("%m/%d/%Y")

    points: list[dict[str, Any]] = []
    for h in hour_list:
        x_ms = ny_wall_hour_to_x_ms(d, h)
        if aware_labels:
            # Aware label format
            wall_dt = datetime(d.year, d.month, d.day, h, 0, 0, tzinfo=UTC)
            start_str = wall_dt.isoformat()
            end_str = (wall_dt + timedelta(hours=1)).isoformat()
        else:
            # Strict date-only format
            start_str = date_str
            end_str = date_str

        points.append(
            {
                "x": x_ms,
                "y": kwh_val,
                "hs": {
                    "start": start_str,
                    "end": end_str,
                },
            }
        )
    return points


def make_raw_chart_payload(meter_id: str, points: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap raw chart points in PSEG ChartData API envelope."""
    clean_id = "".join(ch for ch in str(meter_id) if ch.isdigit()) or "1"
    return {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{clean_id}",
                    "data": points,
                }
            ]
        }
    }


# Reference scenario definitions
SCENARIO_CLOSED_DAYS = {
    "start": "2026-10-01",
    "days": 5,
    "kwh_per_day": 10.0,
}

SCENARIO_SPARSE_DAYS = {
    "start": "2026-10-01",
    "days": 5,
    "skips": frozenset({1, 3}),  # Days 2026-10-02 and 2026-10-04 are missing
}

SCENARIO_ZERO_DAY = {
    "start": "2026-10-01",
    "days": 4,
    "overrides": {
        1: (0.0, 0.0),  # 2026-10-02 is a zero day (0 kWh, $0.00)
    },
    "skips": frozenset({2}),  # 2026-10-03 is missing (sparse)
}

SCENARIO_OVERLAPPING_BACKFILL = {
    "initial_start": "2026-10-10",
    "initial_count": 5,  # 10-10 through 10-14
    "backfill_start": "2026-10-05",
    "backfill_count": 8,  # 10-05 through 10-12 (overlaps 10-10..10-12)
}

SCENARIO_OLDER_CORRECTION = {
    "initial_start": "2026-10-01",
    "initial_count": 5,
    "initial_kwh": 10.0,
    "corrected_day": "2026-10-02",
    "corrected_kwh": 5.0,  # Lower usage -> suffix sums decrease
}

SCENARIO_SPRING_2026 = {
    "day": SPRING_DST_2026,
    "expected_hours": 23,
    "total_kwh": 23.0,
}

SCENARIO_FALL_2026 = {
    "day": FALL_DST_2026,
    "expected_hours": 25,
    "total_kwh": 25.0,
}

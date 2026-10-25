"""Portable contract tests for America/New_York wall-clock hourly timestamps.

Ported from archived R1/R2 review probes (r1_probe.py.txt, r2_probe.py.txt).
Preserves the proven timestamp semantics: ChartData `x` represents the
America/New_York wall-clock hour start encoded as UTC epoch milliseconds.

Includes full-day finite varying-load controls, 365-day 2026 calendar conversion,
DST transitions, and synthetic isolated captcha placeholder formatting.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta
import json
from pathlib import Path
import re
from typing import Any

import pytest

from custom_components.pseg.captcha_helper import HELPER_URL_PATH
from custom_components.pseg.const import PORTAL_BASE_URL
from custom_components.pseg.pseg_client import PsegClient
from custom_components.pseg.statistics_hourly import (
    NY_TZ,
    STATISTICS_INCOMPLETE_REASONS,
    expected_hour_starts,
    ny_day_bounds,
    ny_wall_ms_to_utc,
    validate_hourly_days,
)

pytestmark = pytest.mark.independent

DECLARED_INCOMPLETE_REASONS: frozenset[str] = frozenset(
    {
        "dst_ambiguous",
        "granularity_not_hourly",
        "interval_end_mismatch",
        "label_mismatch",
        "missing_hours",
        "naive_start",
        "negative_value",
        "no_daily_total",
        "non_finite",
        "non_numeric",
        "open_day",
        "sum_mismatch",
        "timestamp_semantics_unverified",
        "unaligned_start",
        "unexpected_hours",
        "unexpected_start",
    }
)


def test_contract_edt_baseline(
    uninitialized_client: PsegClient,
    base_day: date,
    base_varying_points: list[dict[str, Any]],
    base_varying_total: float,
) -> None:
    """Verify 24-hour EDT wall-clock conversion with varying load promotes.

    Original probe case: contract_EDT.
    Wall hours 00:00..23:00 EDT on 2026-10-15 correspond to UTC intervals
    2026-10-15T04:00:00+00:00 to 2026-10-16T03:00:00+00:00.
    """
    payload = {"Data": {"series": [{"name": "Meter #1", "data": base_varying_points}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {base_day: base_varying_total},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={base_day: base_varying_total},
    )

    check = checks[base_day]
    assert check.complete is True
    assert check.reason is None
    assert len(parsed["hourly_records"]) == 24
    assert parsed["hourly_invalid_points"] == 0
    assert parsed["hourly_records"][0]["start"].isoformat() == "2026-10-15T04:00:00+00:00"
    assert parsed["hourly_records"][-1]["start"].isoformat() == "2026-10-16T03:00:00+00:00"


@pytest.mark.parametrize("shift_hours", [4, -4], ids=["shift_+4h", "shift_-4h"])
def test_contract_edt_x_shift(
    uninitialized_client: PsegClient,
    base_day: date,
    base_varying_points: list[dict[str, Any]],
    base_varying_total: float,
    shift_hours: int,
) -> None:
    """Verify shifting x by +/-4h (treating x as true UTC) fails validation.

    Original probe cases: EDT_x_shift_+4h, EDT_x_shift_-4h.
    """
    pts = deepcopy(base_varying_points)
    for p in pts:
        p["x"] += shift_hours * 3_600_000

    payload = {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {base_day: base_varying_total},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={base_day: base_varying_total},
    )

    check = checks[base_day]
    assert check.complete is False
    assert check.reason is not None


def test_contract_est_baseline(
    uninitialized_client: PsegClient,
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Verify 24-hour EST wall-clock conversion promotes correctly.

    Original probe case: contract_EST.
    Wall hours 00:00..23:00 EST on 2026-12-01 correspond to UTC intervals
    2026-12-01T05:00:00+00:00 to 2026-12-02T04:00:00+00:00.
    """
    est_day = date(2026, 12, 1)
    pts = [point_factory(est_day, h, 0.75) for h in range(24)]
    total = 18.0

    payload = {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {est_day: total},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={est_day: total},
    )

    check = checks[est_day]
    assert check.complete is True
    assert check.reason is None
    assert len(parsed["hourly_records"]) == 24
    assert parsed["hourly_records"][0]["start"].isoformat() == "2026-12-01T05:00:00+00:00"
    assert parsed["hourly_records"][-1]["start"].isoformat() == "2026-12-02T04:00:00+00:00"


def test_fallback_25_duplicate_01(
    uninitialized_client: PsegClient,
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Verify fall DST transition with duplicate wall 01:00 rejects as ambiguous.

    Original probe case: fallback_25_duplicate_01.
    """
    fall_day = date(2026, 11, 1)
    hours = [0, 1, 1, *range(2, 24)]
    pts = [point_factory(fall_day, h, 1.0) for h in hours]

    payload = {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {fall_day: 25.0},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={fall_day: 25.0},
    )

    check = checks[fall_day]
    assert check.complete is False
    assert check.reason == "dst_ambiguous"


def test_fallback_24_distinct(
    uninitialized_client: PsegClient,
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Verify fall DST transition with 24 distinct wall hours rejects as ambiguous.

    Original probe case: fallback_24_distinct.
    """
    fall_day = date(2026, 11, 1)
    pts = [point_factory(fall_day, h, 1.0) for h in range(24)]

    payload = {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {fall_day: 24.0},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={fall_day: 24.0},
    )

    check = checks[fall_day]
    assert check.complete is False
    assert check.reason == "dst_ambiguous"


def test_fallback_25_aware_dst_ambiguous(
    uninitialized_client: PsegClient,
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Verify fall DST transition with 25 aware labels rejects with dst_ambiguous.

    Original probe case: fallback_25_aware.
    Supersession note: In original R1, this expected label_mismatch. In R2 and
    production v1.6.0, the ambiguity guard takes precedence ahead of aware label
    checks, emitting dst_ambiguous (obsolete-by-design in R1, closed in R2).
    """
    fall_day = date(2026, 11, 1)
    fall_aware: list[dict[str, Any]] = []
    for start in expected_hour_starts(fall_day):
        local = start.astimezone(NY_TZ)
        p = point_factory(fall_day, local.hour, 1.0)
        p["hs"] = {
            "start": start.isoformat(),
            "end": (start + timedelta(hours=1)).isoformat(),
        }
        fall_aware.append(p)

    payload = {"Data": {"series": [{"name": "Meter #1", "data": fall_aware}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {fall_day: 25.0},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={fall_day: 25.0},
    )

    check = checks[fall_day]
    assert check.complete is False
    assert check.reason == "dst_ambiguous"


def test_spring_valid_23_hours(
    uninitialized_client: PsegClient,
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Verify spring forward 23-hour day (gap at 02:00) promotes successfully.

    Original probe case: spring_valid_23.
    """
    spring_day = date(2027, 3, 14)
    hours = [0, 1, *range(3, 24)]
    pts = [point_factory(spring_day, h, 1.0) for h in hours]

    payload = {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {spring_day: 23.0},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={spring_day: 23.0},
    )

    check = checks[spring_day]
    assert check.complete is True
    assert check.reason is None
    assert len(parsed["hourly_records"]) == 23


def test_spring_nonexistent_02_gap_rejected(
    uninitialized_client: PsegClient,
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Verify spring day containing nonexistent 02:00 hour marks point invalid.

    Original probe case: spring_nonexistent_02.
    """
    spring_day = date(2027, 3, 14)
    pts = [point_factory(spring_day, h, 1.0) for h in range(24)]

    payload = {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {spring_day: 24.0},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={spring_day: 24.0},
    )

    check = checks[spring_day]
    assert check.complete is False
    assert check.reason == "sum_mismatch"
    assert parsed["hourly_invalid_points"] == 1


def test_true_utc_three_days_rejected(
    uninitialized_client: PsegClient,
    base_day: date,
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Verify true-UTC timestamps with NY date labels fail even with flat loads.

    Original probe case: true_UTC_three_days_correct_labels.
    """
    days = [base_day + timedelta(days=i) for i in range(3)]
    utc_pts: list[dict[str, Any]] = []
    for d in days:
        for h in range(24):
            p = point_factory(d, h, 1.0)
            p["x"] += 4 * 3_600_000
            utc_pts.append(p)

    payload = {"Data": {"series": [{"name": "Meter #1", "data": utc_pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    totals = {d: 24.0 for d in days}
    checks = validate_hourly_days(
        parsed["hourly_records"],
        totals,
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days=totals,
    )

    assert not any(c.complete for c in checks.values())


# Declared 2026 America/New_York transitions (the oracle; no production helpers):
# spring forward 2026-03-08 02:00 EST -> 03:00 EDT, fall back 2026-11-01 02:00 EDT
# -> 01:00 EST. EST = UTC-5, EDT = UTC-4.
_DST_START_2026 = date(2026, 3, 8)
_DST_END_2026 = date(2026, 11, 1)


def _declared_midnight_offset(day: date) -> int:
    """Hours to add to local midnight to get UTC (midnight is EST on both transition days' boundaries)."""
    return 5 if day <= _DST_START_2026 or day > _DST_END_2026 else 4


def _declared_wall_hour(day: date, hour: int) -> tuple[datetime | None, str]:
    """Declared UTC start and status for one New York wall hour of 2026."""
    wall = datetime(day.year, day.month, day.day, hour, tzinfo=UTC)
    if day == _DST_START_2026:
        if hour == 2:
            return None, "dst_nonexistent"
        return wall + timedelta(hours=5 if hour < 2 else 4), "ok"
    if day == _DST_END_2026:
        if hour == 1:
            # Fold 0 (EDT) is the instant reported for the ambiguous hour.
            return datetime(2026, 11, 1, 5, tzinfo=UTC), "dst_ambiguous"
        return wall + timedelta(hours=4 if hour == 0 else 5), "ok"
    return wall + timedelta(hours=_declared_midnight_offset(day)), "ok"


def _declared_day_starts(day: date) -> list[datetime]:
    """Declared UTC hour starts of one New York day (23/24/25 hours)."""
    start = datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(
        hours=_declared_midnight_offset(day)
    )
    nxt = day + timedelta(days=1)
    end = datetime(nxt.year, nxt.month, nxt.day, tzinfo=UTC) + timedelta(
        hours=_declared_midnight_offset(nxt)
    )
    return [start + timedelta(hours=k) for k in range(int((end - start) / timedelta(hours=1)))]


def test_declared_calendar_oracle_sanity() -> None:
    """The declared oracle itself: day lengths and the two transition days."""
    assert len(_declared_day_starts(date(2026, 3, 8))) == 23
    assert len(_declared_day_starts(date(2026, 11, 1))) == 25
    assert len(_declared_day_starts(date(2026, 10, 15))) == 24
    assert _declared_day_starts(date(2026, 10, 15))[0] == datetime(2026, 10, 15, 4, tzinfo=UTC)
    assert _declared_day_starts(date(2026, 12, 1))[0] == datetime(2026, 12, 1, 5, tzinfo=UTC)
    assert _declared_wall_hour(date(2026, 3, 8), 3) == (datetime(2026, 3, 8, 7, tzinfo=UTC), "ok")
    assert _declared_wall_hour(date(2026, 11, 1), 2) == (datetime(2026, 11, 1, 7, tzinfo=UTC), "ok")


def test_all_2026_wall_calendar_conversions(
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Control over all 365 days of 2026: 8,758 unique resolvable wall hours.

    Original probe case: ALL_2026_CONVERSIONS. Expectations come from the
    declared transition dates above, never from production helpers, so a
    correlated one-hour error in conversion AND bounds cannot pass:
    - every wall hour converts to its declared UTC instant and status;
    - exactly 8,758 ok, 1 nonexistent (03-08 02:00), 1 ambiguous (11-01 01:00);
    - production expected_hour_starts / ny_day_bounds equal the declared day;
    - on 2026-11-01 only the fold-1 instant 06:00Z is unrepresented.
    """
    start_date = date(2026, 1, 1)
    statuses: Counter[str] = Counter()

    for i in range(365):
        cur_day = start_date + timedelta(days=i)
        declared_day = _declared_day_starts(cur_day)
        assert list(expected_hour_starts(cur_day)) == declared_day, cur_day
        assert ny_day_bounds(cur_day) == (
            declared_day[0],
            declared_day[-1] + timedelta(hours=1),
        ), cur_day

        got: set[datetime] = set()
        for h in range(24):
            p = point_factory(cur_day, h, 1.0)
            st, status = ny_wall_ms_to_utc(p["x"])
            assert (st, status) == _declared_wall_hour(cur_day, h), (cur_day, h)
            statuses[status] += 1
            if st is not None:
                got.add(st)

        if cur_day == _DST_END_2026:
            assert set(declared_day) - got == {datetime(2026, 11, 1, 6, tzinfo=UTC)}
        else:
            assert got == set(declared_day), f"Mismatch for day {cur_day}"

    assert statuses["ok"] == 8758
    assert statuses["dst_nonexistent"] == 1
    assert statuses["dst_ambiguous"] == 1


def _reason_for(
    client: PsegClient,
    day: date,
    points: list[dict[str, Any]],
    daily_total: float,
    now: datetime | None = None,
) -> str | None:
    payload = {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    parsed = client._parse_hourly_chart(payload)
    checks = validate_hourly_days(
        parsed["hourly_records"],
        {day: daily_total},
        now or datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={day: daily_total},
    )
    return checks[day].reason


def test_reason_closure_observed(
    uninitialized_client: PsegClient,
    point_factory: Callable[..., dict[str, Any]],
) -> None:
    """Emitted reasons are observed, not just listed.

    Original probe case: REASON_CLOSURE. Drives the real parser + validator
    through one scenario per rejection path and asserts each emitted reason
    equals its declared value and belongs to the declared closed set, so a
    mutant that emits an unknown or wrong reason fails here.
    """
    day = date(2026, 10, 15)

    def full(**labels: str) -> list[dict[str, Any]]:
        return [point_factory(day, h, 0.5, **labels) for h in range(24)]

    scenarios: dict[str, tuple[list[dict[str, Any]], float, datetime | None, str | None]] = {
        "healthy": (full(), 12.0, None, None),
        "missing_hour": (full()[:-1], 11.5, None, "missing_hours"),
        "label_other_day": (full(start_label="10/14/2026"), 12.0, None, "label_mismatch"),
        "end_two_days_off": (full(end_label="10/17/2026"), 12.0, None, "interval_end_mismatch"),
        "labels_unparseable": (
            full(start_label="", end_label=""),
            12.0,
            None,
            "timestamp_semantics_unverified",
        ),
        "sum_off": (full(), 17.0, None, "sum_mismatch"),
        "open_day": (full(), 12.0, datetime(2026, 10, 15, 12, tzinfo=UTC), "open_day"),
    }
    fall = date(2026, 11, 1)
    fall_points = [point_factory(fall, h, 0.5) for h in range(24)]

    emitted: dict[str, str | None] = {
        name: _reason_for(uninitialized_client, day, pts, total, now)
        for name, (pts, total, now, _) in scenarios.items()
    }
    emitted["fall_back"] = _reason_for(uninitialized_client, fall, fall_points, 12.0)

    declared = {name: expected for name, (_, _, _, expected) in scenarios.items()}
    declared["fall_back"] = "dst_ambiguous"
    assert emitted == declared
    assert {r for r in emitted.values() if r is not None} <= DECLARED_INCOMPLETE_REASONS
    assert DECLARED_INCOMPLETE_REASONS <= STATISTICS_INCOMPLETE_REASONS


@pytest.mark.parametrize("origin", ["user", "reauth_confirm", "reconfigure"])
def test_captcha_placeholder_formatting(origin: str) -> None:
    """Verify synthetic captcha step description formats without unrendered placeholders.

    Original probe case: R2 captcha description formatting.
    Isolated synthetic control checking strings.json and translations/en.json
    without invoking Home Assistant config flows or network endpoints.
    """
    pseg_dir = Path(__file__).resolve().parents[3] / "custom_components" / "pseg"
    placeholders = {
        "helper_url": HELPER_URL_PATH,
        "chrome_extensions_url": "chrome://extensions",
        "edge_extensions_url": "edge://extensions",
        "portal_url": PORTAL_BASE_URL,
    }

    for fname in ["strings.json", "translations/en.json"]:
        file_path = pseg_dir / fname
        assert file_path.is_file(), f"Translation file missing: {file_path}"
        data = json.loads(file_path.read_text(encoding="utf-8"))
        desc = data["config"]["step"]["captcha"]["description"]
        rendered = desc.format(**placeholders)

        # Must not contain any remaining {placeholder} patterns
        assert not re.search(r"\{[^{}]+\}", rendered), (
            f"Unrendered placeholder in {fname} for origin {origin}: {rendered}"
        )
        for key, val in placeholders.items():
            assert val in rendered, f"Placeholder value {key}={val} missing from {fname}"

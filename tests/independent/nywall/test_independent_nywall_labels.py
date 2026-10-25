"""Portable contract tests for hourly label gates, formats, and multi-meter overlap.

Ported from archived R1/R2 review probes (r1_probe.py.txt, r2_probe.py.txt).
Preserves label validation rules:
- Strict MM/DD/YYYY date-only format requires BOTH endpoints to pass.
- Aware UTC endpoints must verify start and end = start + 1h.
- Contradictory/unparseable endpoint labels reject.
- Multi-meter concurrent overlap rejects if either contributing series lacks proof,
  regardless of series ordering.
- Historical R1 unsafe acceptances are verified as rejected.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest

from custom_components.pseg.pseg_client import PsegClient
from custom_components.pseg.statistics_hourly import (
    ny_wall_ms_to_utc,
    validate_hourly_days,
)

pytestmark = pytest.mark.independent


def _apply_r1_transform(name: str, p: dict[str, Any]) -> None:
    """Apply the exact R1 probe mutation to a point dictionary."""
    if name == "start_wrong_date":
        p["hs"]["start"] = "10/16/2026"
    elif name == "end_wrong_date":
        p["hs"]["end"] = "10/17/2026"
    elif name == "end_next_date":
        p["hs"]["end"] = "10/16/2026"
    elif name == "end_unparseable":
        p["hs"]["end"] = "garbage"
    elif name == "date_start_aware_wrong_end":
        p["hs"]["end"] = "2026-10-15T12:00:00-04:00"
    elif name == "naive_zero_length_interval":
        label = datetime.fromtimestamp(p["x"] / 1000, UTC).strftime("%m/%d/%Y %H:%M")
        p["hs"] = {"start": label, "end": label}
    elif name == "aware_start_missing_end":
        st = ny_wall_ms_to_utc(p["x"])[0]
        assert st is not None
        p["hs"] = {"start": st.isoformat(), "end": None}
    elif name == "aware_start_naive_zero_length_end":
        st = ny_wall_ms_to_utc(p["x"])[0]
        assert st is not None
        p["hs"] = {
            "start": st.isoformat(),
            "end": datetime.fromtimestamp(p["x"] / 1000, UTC).strftime("%m/%d/%Y %H:%M"),
        }
    elif name == "ISO_basic_wrong_start_hour":
        p["hs"]["start"] = "2026-10-15T230000"
    elif name == "ISO_basic_aware_wrong_start_hour":
        p["hs"]["start"] = "20261015T230000-0400"
    else:
        raise ValueError(f"Unknown transform: {name}")


@pytest.mark.parametrize(
    "name,expected_complete,expected_reason",
    [
        ("start_wrong_date", False, "label_mismatch"),
        ("end_wrong_date", False, "interval_end_mismatch"),
        ("end_next_date", True, None),
        ("end_unparseable", False, "timestamp_semantics_unverified"),
        ("date_start_aware_wrong_end", False, "timestamp_semantics_unverified"),
        ("naive_zero_length_interval", False, "timestamp_semantics_unverified"),
        ("aware_start_missing_end", False, "timestamp_semantics_unverified"),
        ("aware_start_naive_zero_length_end", False, "timestamp_semantics_unverified"),
        ("ISO_basic_wrong_start_hour", False, "timestamp_semantics_unverified"),
        ("ISO_basic_aware_wrong_start_hour", False, "label_mismatch"),
    ],
    ids=[
        "start_wrong_date",
        "end_wrong_date",
        "end_next_date",
        "end_unparseable",
        "date_start_aware_wrong_end",
        "naive_zero_length_interval",
        "aware_start_missing_end",
        "aware_start_naive_zero_length_end",
        "ISO_basic_wrong_start_hour",
        "ISO_basic_aware_wrong_start_hour",
    ],
)
def test_r1_label_transform(
    uninitialized_client: PsegClient,
    base_day: date,
    base_varying_points: list[dict[str, Any]],
    base_varying_total: float,
    name: str,
    expected_complete: bool,
    expected_reason: str | None,
) -> None:
    """Verify the 10 original R1 label transformations on full-day varying loads."""
    pts = deepcopy(base_varying_points)
    for p in pts:
        _apply_r1_transform(name, p)

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
    assert check.complete is expected_complete
    assert check.reason == expected_reason


@pytest.mark.parametrize(
    "mode,expected_complete,expected_reason",
    [
        ("valid", True, None),
        ("wrong_aware_end", False, "timestamp_semantics_unverified"),
        ("aware_zero_length", False, "interval_end_mismatch"),
    ],
    ids=["valid", "wrong_aware_end", "aware_zero_length"],
)
def test_r1_mixed_series(
    uninitialized_client: PsegClient,
    base_day: date,
    base_varying_points: list[dict[str, Any]],
    base_varying_total: float,
    mode: str,
    expected_complete: bool,
    expected_reason: str | None,
) -> None:
    """Verify R1 mixed-mode series (alternating aware and date-only labels)."""
    pts = deepcopy(base_varying_points)
    for i, p in enumerate(pts):
        if i % 2 == 0:
            st = ny_wall_ms_to_utc(p["x"])[0]
            assert st is not None
            delta = 0 if mode == "aware_zero_length" else 1
            p["hs"] = {
                "start": st.isoformat(),
                "end": (st + timedelta(hours=delta)).isoformat(),
            }
        elif mode == "wrong_aware_end":
            p["hs"]["end"] = "2026-10-15T12:00:00-04:00"

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
    assert check.complete is expected_complete
    assert check.reason == expected_reason


@pytest.mark.parametrize(
    "kind",
    [
        "bare_same_end",
        "aware_missing_end",
        "date_start_wrong_aware_end",
        "basic_aware_wrong_start",
    ],
)
def test_r1_unsafe_acceptance_rejected(
    uninitialized_client: PsegClient,
    base_varying_points: list[dict[str, Any]],
    kind: str,
) -> None:
    """Verify historical R1 unsafe gate acceptances are rejected in v1.6.0.

    In the original R1 probe, these 4 adversarial scenarios were accepted by an
    overly broad label fallback gate. The R2 review closed these defects, ensuring
    every one of the 24 intervals is rejected (interval_ok == False).
    """
    pts = deepcopy(base_varying_points)
    for p in pts:
        st = ny_wall_ms_to_utc(p["x"])[0]
        assert st is not None
        if kind == "bare_same_end":
            label = datetime.fromtimestamp(p["x"] / 1000, UTC).strftime("%m/%d/%Y %H:%M")
            p["hs"] = {"start": label, "end": label}
        elif kind == "aware_missing_end":
            p["hs"] = {"start": st.isoformat(), "end": None}
        elif kind == "date_start_wrong_aware_end":
            p["hs"]["end"] = "2026-10-15T12:00:00-04:00"
        elif kind == "basic_aware_wrong_start":
            p["hs"]["start"] = "20261015T230000-0400"
        else:
            raise ValueError(f"Unknown kind: {kind}")

    payload = {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    # Every single hourly record must have interval_ok == False
    assert not any(r["interval_ok"] for r in parsed["hourly_records"]), (
        f"Unsafe acceptance detected for kind {kind}: some intervals were marked ok"
    )


@pytest.mark.parametrize(
    "name,changes,expected_reason",
    [
        ("iso_date_only_end", {"end": "2026-10-15"}, "timestamp_semantics_unverified"),
        (
            "end_surrounding_text",
            {"end": "from 10/15/2026 through"},
            "timestamp_semantics_unverified",
        ),
        ("end_missing_zero", {"end": "1/15/2026"}, "timestamp_semantics_unverified"),
        ("start_missing_zero", {"start": "1/15/2026"}, "timestamp_semantics_unverified"),
        ("previous_start_same_end", {"start": "10/14/2026", "end": "10/15/2026"}, "label_mismatch"),
        ("missing_both_labels", {"start": None, "end": None}, "timestamp_semantics_unverified"),
        ("end_basic_naive_datetime", {"end": "20261015T230000"}, "timestamp_semantics_unverified"),
        ("start_basic_aware_wrong", {"start": "20261015T230000-0400"}, "label_mismatch"),
    ],
    ids=[
        "iso_date_only_end",
        "end_surrounding_text",
        "end_missing_zero",
        "start_missing_zero",
        "previous_start_same_end",
        "missing_both_labels",
        "end_basic_naive_datetime",
        "start_basic_aware_wrong",
    ],
)
def test_r2_adversarial_label(
    uninitialized_client: PsegClient,
    base_day: date,
    base_varying_points: list[dict[str, Any]],
    base_varying_total: float,
    name: str,
    changes: dict[str, Any],
    expected_reason: str,
) -> None:
    """Verify the 8 R2 adversarial label mutations on full-day varying loads."""
    pts = deepcopy(base_varying_points)
    for p in pts:
        p["hs"].update(changes)

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
    assert check.reason == expected_reason


@pytest.mark.parametrize("field", ["start", "end"])
def test_r2_single_digit_month(
    uninitialized_client: PsegClient,
    point_factory: Callable[..., dict[str, Any]],
    field: str,
) -> None:
    """Verify single-digit month (1/05/2026) in start or end is rejected."""
    short_day = date(2026, 1, 5)
    pts = [point_factory(short_day, h, 1.0) for h in range(24)]
    for p in pts:
        p["hs"][field] = "1/05/2026"

    payload = {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    checks = validate_hourly_days(
        parsed["hourly_records"],
        {short_day: 24.0},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days={short_day: 24.0},
    )

    check = checks[short_day]
    assert check.complete is False
    assert check.reason == "timestamp_semantics_unverified"


@pytest.mark.parametrize(
    "mutation_name,reversed_order",
    [
        ("missing_labels", False),
        ("missing_labels", True),
        ("wrong_aware_end", False),
        ("wrong_aware_end", True),
    ],
    ids=[
        "missing_labels-normal",
        "missing_labels-reversed",
        "wrong_aware_end-normal",
        "wrong_aware_end-reversed",
    ],
)
def test_r2_mixed_meter_overlap(
    uninitialized_client: PsegClient,
    base_day: date,
    base_varying_points: list[dict[str, Any]],
    base_varying_total: float,
    mutation_name: str,
    reversed_order: bool,
) -> None:
    """Verify concurrent multi-meter overlap rejects if either series is invalid.

    Tested in both series orders (normal and reversed) with matching daily sums.
    """
    other = deepcopy(base_varying_points)
    for p in other:
        if mutation_name == "missing_labels":
            p.pop("hs", None)
        elif mutation_name == "wrong_aware_end":
            p["hs"]["end"] = "2026-10-15T12:00:00-04:00"

    series = [
        {"name": "Meter #1", "data": base_varying_points},
        {"name": "Meter #2", "data": other},
    ]
    if reversed_order:
        series.reverse()

    payload = {"Data": {"series": series}}
    parsed = uninitialized_client._parse_hourly_chart(payload)

    # Combined total for two identical meters
    combined_total = base_varying_total * 2
    checks = validate_hourly_days(
        parsed["hourly_records"],
        {base_day: combined_total},
        datetime(2028, 1, 1, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
        days=[base_day],
    )

    check = checks[base_day]
    assert check.complete is False
    assert check.reason == "timestamp_semantics_unverified"
    assert not any(p["interval_ok"] for p in parsed["hourly_records"])


@pytest.mark.parametrize(
    "control_name",
    ["matching_aware", "strict_next_date_end", "surrounding_whitespace"],
)
def test_r2_positive_controls(
    uninitialized_client: PsegClient,
    base_day: date,
    base_varying_points: list[dict[str, Any]],
    base_varying_total: float,
    control_name: str,
) -> None:
    """Verify valid positive controls promote under strict label validation."""
    pts = deepcopy(base_varying_points)
    for p in pts:
        if control_name == "matching_aware":
            st = ny_wall_ms_to_utc(p["x"])[0]
            assert st is not None
            p["hs"] = {
                "start": st.isoformat(),
                "end": (st + timedelta(hours=1)).isoformat(),
            }
        elif control_name == "strict_next_date_end":
            p["hs"]["end"] = "10/16/2026"
        elif control_name == "surrounding_whitespace":
            p["hs"] = {"start": " 10/15/2026 ", "end": "\n10/15/2026\t"}

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
    assert check.complete is True
    assert check.reason is None

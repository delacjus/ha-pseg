"""Reference statistics model tests and physical recorder comparison.

ORACLE INDEPENDENCE:
Expected rows and calendar boundaries are computed strictly from zoneinfo,
Decimal, and declared literals in tests.support.stats_model.
DO NOT import production expected_hour_starts, ny_day_bounds, ny_wall_ms_to_utc,
validate_hourly_day(s), or statistics row builders.

Production is only the system under test (PsegDataUpdateCoordinator).
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch

from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)

from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient
from tests.stats_suite.reference_cases import (
    make_canonical_hourly_records,
    make_daily_records,
    make_raw_chart_payload,
    make_raw_chart_points,
)
from tests.support.stats_model import (
    CONSUMPTION_STATISTIC_ID,
    COST_STATISTIC_ID,
    FALL_DST_2025,
    FALL_DST_2026,
    SPRING_DST_2025,
    SPRING_DST_2026,
    ReferenceStatisticsModel,
    assert_chained_nondecreasing,
    compare_both_series,
    compare_series,
    enumerate_2026_days,
    ny_day_hours_utc,
    ny_day_start_utc,
    ny_wall_hour_to_x_ms,
    resolve_raw_wall_hour,
    x_ms_to_ny_wall_hour,
)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock, enable_custom_integrations):
    """Recorder must be set up before hass for these tests."""
    yield


class _ReferenceClient(PsegClient):
    def __init__(self, price_per_kwh: float = 0.25) -> None:
        super().__init__(price_per_kwh=price_per_kwh)

    def attach_renewal_admission(self, admission, runtime=None, token=None) -> None:
        self.admission = admission

    def set_expected_meter_ids(self, meter_ids) -> None:
        self.expected_meter_ids = frozenset(meter_ids)

    def pending_confirmed_snapshot(self):
        return None

    def clear_confirmed_snapshot(self, snapshot_id) -> None:
        self.cleared_snapshot = snapshot_id


@pytest.fixture
async def coord(hass: HomeAssistant) -> PsegDataUpdateCoordinator:
    return PsegDataUpdateCoordinator(hass, _ReferenceClient(), {})


async def fetch_recorder_rows(
    hass: HomeAssistant, statistic_id: str
) -> list[tuple[datetime, float, float]]:
    """Return every stored row in the real recorder as (start UTC, state, cumulative sum)."""
    result = await hass.async_add_executor_job(
        statistics_during_period,
        hass,
        datetime(2020, 1, 1, tzinfo=UTC),
        None,
        {statistic_id},
        "hour",
        None,
        {"sum", "state"},
    )
    return sorted(
        (
            datetime.fromtimestamp(row["start"], UTC),
            float(row["state"]),
            float(row["sum"]),
        )
        for row in result.get(statistic_id, [])
    )


# -----------------------------------------------------------------------------
# Pure Model Tests (Fast)
# -----------------------------------------------------------------------------


def test_literal_controls_edt_and_est() -> None:
    """Verify declared literal controls: EDT/EST midnights, 2026 & 2025 DST counts."""
    # EDT midnight = 04:00Z
    edt_day = date(2026, 10, 15)
    assert ny_day_start_utc(edt_day) == datetime(2026, 10, 15, 4, 0, tzinfo=UTC)

    # EST midnight = 05:00Z
    est_day = date(2026, 12, 1)
    assert ny_day_start_utc(est_day) == datetime(2026, 12, 1, 5, 0, tzinfo=UTC)

    # 2026 transition counts
    assert len(ny_day_hours_utc(SPRING_DST_2026)) == 23
    assert len(ny_day_hours_utc(FALL_DST_2026)) == 25

    # 2025 DST controls
    assert len(ny_day_hours_utc(SPRING_DST_2025)) == 23
    assert len(ny_day_hours_utc(FALL_DST_2025)) == 25


def test_all_365_days_of_2026_independently_enumerated() -> None:
    """Independently enumerate all 365 days of 2026 and verify day lengths."""
    days = enumerate_2026_days()
    assert len(days) == 365

    spring_days = [d for d, count, _ in days if count == 23]
    fall_days = [d for d, count, _ in days if count == 25]
    normal_days = [d for d, count, _ in days if count == 24]

    assert spring_days == [SPRING_DST_2026]
    assert fall_days == [FALL_DST_2026]
    assert len(normal_days) == 363

    total_hours = sum(count for _, count, _ in days)
    assert total_hours == 8760

    for d, count, starts in days:
        assert len(starts) == count
        for earlier, later in zip(starts, starts[1:]):
            assert later - earlier == timedelta(hours=1)


def test_raw_wall_x_representation_separate_from_canonical_aware() -> None:
    """Verify raw wall x encoding is distinct from canonical aware timestamps."""
    day = date(2026, 10, 15)
    x_ms = ny_wall_hour_to_x_ms(day, 0)
    assert x_ms == int(datetime(2026, 10, 15, 0, 0, tzinfo=UTC).timestamp() * 1000)

    recovered_date, recovered_hour = x_ms_to_ny_wall_hour(x_ms)
    assert recovered_date == day
    assert recovered_hour == 0

    # Spring nonexistent hour (02:00)
    st_nonexistent, status_spring = resolve_raw_wall_hour(SPRING_DST_2026, 2)
    assert st_nonexistent is None
    assert status_spring == "dst_nonexistent"

    # Fall ambiguous hour (01:00)
    st_ambiguous, status_fall = resolve_raw_wall_hour(FALL_DST_2026, 1)
    assert st_ambiguous == datetime(2026, 11, 1, 5, 0, tzinfo=UTC)
    assert status_fall == "dst_ambiguous"

    # Canonical aware representation has 25 distinct starts
    aware_starts = ny_day_hours_utc(FALL_DST_2026)
    assert len(aware_starts) == 25
    assert len(set(aware_starts)) == 25


def test_pure_model_open_closed_sparse_zero_days() -> None:
    """Verify reference model handles open, closed, sparse, and zero days."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))

    # Day 1: closed standard day (10 kWh)
    # Day 2: zero day (0 kWh, zero is not missing)
    # Day 3: missing (sparse, no record)
    # Day 4: closed day (20 kWh)
    records = [
        {"date": "2026-10-01", "kwh": 10.0, "cost": 2.50},
        {"date": "2026-10-02", "kwh": 0.0, "cost": 0.00},
        # 2026-10-03 is omitted
        {"date": "2026-10-04", "kwh": 20.0, "cost": 5.00},
    ]
    model.record_daily(records)

    c_rows = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    cost_rows = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    assert len(c_rows) == 3
    assert len(cost_rows) == 3

    # Zero day row exists with state 0.0 and sum conserved
    zero_row = c_rows[1]
    assert zero_row[0] == ny_day_start_utc(date(2026, 10, 2))
    assert zero_row[1] == 0.0
    assert zero_row[2] == 10.0

    # Day 4 accumulates onto Day 2
    assert c_rows[2][1] == 20.0
    assert c_rows[2][2] == 30.0

    assert_chained_nondecreasing(c_rows)
    assert_chained_nondecreasing(cost_rows)


def test_pure_model_overlapping_backfill() -> None:
    """Verify reference model handles overlapping backfill correctly."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))

    # Initial: 10-10 through 10-14 (5 days)
    model.record_daily(make_daily_records("2026-10-10", 5, 10.0))
    initial_rows = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    assert len(initial_rows) == 5
    assert initial_rows[-1][2] == 50.0

    # Backfill: 10-05 through 10-12 (8 days, overlapping 10-10..10-12)
    model.record_daily(make_daily_records("2026-10-05", 8, 10.0))
    backfill_rows = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)

    # Total days: 10-05 through 10-14 = 10 days
    assert len(backfill_rows) == 10
    assert [r[2] for r in backfill_rows] == [10.0 * i for i in range(1, 11)]
    assert_chained_nondecreasing(backfill_rows)


def test_pure_model_older_correction_recomputes_suffix() -> None:
    """Verify reference model recomputes suffix sums on older day corrections."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))

    # 5 days of 10 kWh: sums are 10, 20, 30, 40, 50
    model.record_daily(make_daily_records("2026-10-01", 5, 10.0))
    before_sums = [r[2] for r in model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)]
    assert before_sums == [10.0, 20.0, 30.0, 40.0, 50.0]

    # Correct Day 2 to 5.0 kWh: new sums should be 10, 15, 25, 35, 45 (decreased by 5)
    model.correct_day("2026-10-02", 5.0)
    after_sums = [r[2] for r in model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)]
    assert after_sums == [10.0, 15.0, 25.0, 35.0, 45.0]
    assert_chained_nondecreasing(model.expected_rows(CONSUMPTION_STATISTIC_ID))


def test_pure_model_daily_to_hourly_promotion_no_double_count() -> None:
    """Verify reference model replaces daily row with hourly rows without double counting."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))

    # 3 days daily
    model.record_daily(make_daily_records("2026-10-01", 3, 24.0))
    assert len(model.expected_rows(CONSUMPTION_STATISTIC_ID)) == 3

    # Promote Day 2 (24 hours at 1.0 kWh)
    hourly = make_canonical_hourly_records("2026-10-02", 1.0)
    model.promote_hourly("2026-10-02", hourly)

    rows = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    # Total rows: 1 (Day 1) + 24 (Day 2) + 1 (Day 3) = 26
    assert len(rows) == 26
    # Day 1 ends at 24.0, Day 2 ends at 48.0, Day 3 ends at 72.0
    assert rows[0][2] == 24.0
    assert rows[24][2] == 48.0
    assert rows[25][2] == 72.0
    assert_chained_nondecreasing(rows)


def test_pure_model_no_downgrade() -> None:
    """Verify reference model does not downgrade a promoted day back to daily."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))
    model.record_daily(make_daily_records("2026-10-01", 3, 24.0))

    # Promote Day 2
    model.promote_hourly("2026-10-02", make_canonical_hourly_records("2026-10-02", 1.0))
    assert len(model.expected_rows(CONSUMPTION_STATISTIC_ID)) == 26

    # Attempt to re-record Day 2 daily
    model.record_daily([{"date": "2026-10-02", "kwh": 24.0, "cost": 6.00}])
    # Remains 26 rows
    assert len(model.expected_rows(CONSUMPTION_STATISTIC_ID)) == 26


# -----------------------------------------------------------------------------
# Negative Proofs (Fast)
# -----------------------------------------------------------------------------


def test_negative_proof_shifted_hours_fail_comparison() -> None:
    """Negative proof: shifting every expected hour +1 conserving totals must fail row-start assertions."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))
    model.record_daily(make_daily_records("2026-10-01", 2, 24.0))
    model.promote_hourly("2026-10-02", make_canonical_hourly_records("2026-10-02", 1.0))

    actual = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)

    # Shift expected rows by +1 hour while conserving totals and states
    shifted = [
        (st + timedelta(hours=1), val, csum)
        for st, val, csum in actual
    ]

    with pytest.raises(AssertionError, match="start mismatch"):
        compare_series(actual, shifted, label="shifted_test")


def test_negative_proof_omit_cost_comparison_fails() -> None:
    """Negative proof: omitting the cost series comparison must fail the coverage check."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))
    model.record_daily(make_daily_records("2026-10-01", 2, 10.0))

    actual_c = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_c = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)

    # Calling compare_both_series with empty cost rows must raise AssertionError
    with pytest.raises(AssertionError, match="Cost series comparison was omitted"):
        compare_both_series(
            actual_consumption=actual_c,
            actual_cost=[],
            expected_consumption=expected_c,
            expected_cost=[],
        )


def test_negative_proof_wrong_cost_series_fails_comparison() -> None:
    """Negative proof: deliberately wrong cost rows with correct consumption must fail comparator."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))
    model.record_daily(make_daily_records("2026-10-01", 2, 10.0))

    actual_c = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_c = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)

    actual_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)
    # Deliberately wrong cost: non-empty, populated rows but wrong values
    wrong_cost = [(st, val + 1.0, csum + 1.0) for st, val, csum in actual_cost]

    with pytest.raises(AssertionError, match=COST_STATISTIC_ID):
        compare_both_series(
            actual_consumption=actual_c,
            actual_cost=wrong_cost,
            expected_consumption=expected_c,
            expected_cost=actual_cost,
        )


def test_negative_proof_zero_day_not_treated_as_missing() -> None:
    """Negative proof: a zero-usage day must be present in rows and not dropped as missing."""
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"))
    # Day 1: 10 kWh, Day 2: 0 kWh, Day 3: missing, Day 4: 10 kWh
    model.record_daily([
        {"date": "2026-10-01", "kwh": 10.0, "cost": 2.50},
        {"date": "2026-10-02", "kwh": 0.0, "cost": 0.00},
        {"date": "2026-10-04", "kwh": 10.0, "cost": 2.50},
    ])

    rows = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    dates_present = [st.date() for st, _, _ in rows]

    # Day 2 is present with state == 0
    assert date(2026, 10, 2) in dates_present
    d2_row = [r for r in rows if r[0].date() == date(2026, 10, 2)][0]
    assert d2_row[1] == 0.0

    # Day 3 is truly missing
    assert date(2026, 10, 3) not in dates_present


# -----------------------------------------------------------------------------
# Physical Recorder Smoke Test (Fast)
# -----------------------------------------------------------------------------


async def test_recorder_smoke_comparison_both_series(hass: HomeAssistant, coord: PsegDataUpdateCoordinator) -> None:
    """Fast smoke test comparing both real recorder series against the independent model."""
    daily = make_daily_records("2026-10-01", 2, 24.0)
    hourly = make_canonical_hourly_records("2026-10-02", 1.0)

    # Import daily for 10-01 and promote 10-02 to hourly
    await coord.async_record_statistics(
        daily,
        meter_id="m1",
        hourly_records=hourly,
        hourly_granularity="hourly",
    )
    await async_wait_recording_done(hass)

    actual_consumption = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    # Independent reference expectations
    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.record_daily(daily)
    model.promote_hourly("2026-10-02", hourly)

    expected_consumption = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    compare_both_series(
        actual_consumption=actual_consumption,
        actual_cost=actual_cost,
        expected_consumption=expected_consumption,
        expected_cost=expected_cost,
    )


@pytest.mark.slow
async def test_recorder_negative_proof_wrong_cost_fails(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Self-test: populated recorder state with wrong cost rows must fail compare_both_series."""
    records = [{"date": "2026-10-01", "kwh": 10.0, "cost": 2.50}]
    await coord.async_record_statistics(records, meter_id="m1")
    await async_wait_recording_done(hass)

    actual_c = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.record_daily(records)

    expected_c = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    # Deliberately corrupt actual cost rows while consumption is correct
    wrong_actual_cost = [(st, val + 1.0, csum + 1.0) for st, val, csum in actual_cost]

    with pytest.raises(AssertionError, match=COST_STATISTIC_ID):
        compare_both_series(
            actual_consumption=actual_c,
            actual_cost=wrong_actual_cost,
            expected_consumption=expected_c,
            expected_cost=expected_cost,
        )


# -----------------------------------------------------------------------------
# Physical Recorder Sequences (Slow)
# -----------------------------------------------------------------------------


@pytest.mark.slow
async def test_recorder_overlapping_backfill_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify overlapping backfill produces identical rows to reference model for both series."""
    # Initial import: 10-10 through 10-14 (5 days)
    initial_daily = make_daily_records("2026-10-10", 5, 10.0)
    await coord.async_record_statistics(initial_daily, meter_id="m1")
    await async_wait_recording_done(hass)

    # Backfill import: 10-05 through 10-12 (8 days, overlapping 10-10..10-12)
    backfill_daily = make_daily_records("2026-10-05", 8, 10.0)
    await coord.async_record_statistics(backfill_daily, meter_id="m1")
    await async_wait_recording_done(hass)

    actual_consumption = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.record_daily(initial_daily)
    model.record_daily(backfill_daily)

    expected_consumption = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    compare_both_series(
        actual_consumption,
        actual_cost,
        expected_consumption,
        expected_cost,
    )
    assert_chained_nondecreasing(actual_consumption)
    assert_chained_nondecreasing(actual_cost)


@pytest.mark.slow
async def test_recorder_older_correction_recomputes_suffix_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify correcting an older day in the real recorder recomputes suffix sums for both series."""
    baseline = make_daily_records("2026-10-01", 5, 10.0)
    await coord.async_record_statistics(baseline, meter_id="m1")
    await async_wait_recording_done(hass)

    # Correct Day 2 (2026-10-02) from 10.0 to 5.0 kWh
    corrected = [dict(r) for r in baseline]
    for r in corrected:
        if r["date"] == "2026-10-02":
            r["kwh"] = 5.0
            r["cost"] = 1.25

    await coord.async_record_statistics(corrected, meter_id="m1")
    await async_wait_recording_done(hass)

    actual_consumption = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.record_daily(baseline)
    model.correct_day("2026-10-02", 5.0, 1.25)

    expected_consumption = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    compare_both_series(
        actual_consumption,
        actual_cost,
        expected_consumption,
        expected_cost,
    )


@pytest.mark.slow
async def test_recorder_repeat_idempotence_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify repeating an identical import produces unchanged recorder rows for both series."""
    records = make_daily_records("2026-10-01", 3, 24.0)
    hourly = make_canonical_hourly_records("2026-10-02", 1.0)

    # First pass: day 2 daily total (24.0 kWh) matches hourly sum (24.0 kWh), so promotion succeeds
    await coord.async_record_statistics(
        records, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
    )
    await async_wait_recording_done(hass)
    first_c = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    first_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    # Promotion succeeded: 1 daily (10-01) + 24 hourly (10-02) + 1 daily (10-03) = 26 rows
    assert len(first_c) == 26
    assert len(first_cost) == 26

    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.record_daily(records)
    model.promote_hourly("2026-10-02", hourly)

    expected_c = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    compare_both_series(first_c, first_cost, expected_c, expected_cost)

    # Second identical pass
    await coord.async_record_statistics(
        records, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
    )
    await async_wait_recording_done(hass)
    second_c = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    second_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    compare_both_series(second_c, second_cost, expected_c, expected_cost)

    assert first_c == second_c
    assert first_cost == second_cost


@pytest.mark.slow
async def test_recorder_zero_day_not_missing_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify real recorder stores zero-usage rows with state 0.0 and does not treat them as missing."""
    records = [
        {"date": "2026-10-01", "kwh": 10.0, "cost": 2.50},
        {"date": "2026-10-02", "kwh": 0.0, "cost": 0.00},  # Zero day
        {"date": "2026-10-04", "kwh": 15.0, "cost": 3.75},  # 10-03 is sparse/missing
    ]
    await coord.async_record_statistics(records, meter_id="m1")
    await async_wait_recording_done(hass)

    actual_consumption = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.record_daily(records)

    expected_consumption = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    compare_both_series(
        actual_consumption,
        actual_cost,
        expected_consumption,
        expected_cost,
    )


@pytest.mark.slow
async def test_recorder_no_downgrade_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify a promoted hourly day cannot be downgraded by a subsequent daily retry."""
    records = make_daily_records("2026-10-01", 3, 24.0)
    hourly = make_canonical_hourly_records("2026-10-02", 1.0)

    # Promote 10-02 to hourly
    await coord.async_record_statistics(
        records, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
    )
    await async_wait_recording_done(hass)

    # Attempt to overwrite with daily-only records
    await coord.async_record_statistics(records, meter_id="m1")
    await async_wait_recording_done(hass)

    actual_consumption = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.record_daily(records)
    model.promote_hourly("2026-10-02", hourly)

    expected_consumption = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    compare_both_series(
        actual_consumption,
        actual_cost,
        expected_consumption,
        expected_cost,
    )


@pytest.mark.slow
async def test_recorder_spring_23_hours_promotion_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify 2026 spring forward day promotes to 23 hourly rows for both series."""
    spring_day = "2026-03-08"
    records = [{"date": spring_day, "kwh": 23.0, "cost": 5.75}]
    hourly = make_canonical_hourly_records(spring_day, 1.0)
    assert len(hourly) == 23

    await coord.async_record_statistics(
        records, meter_id="m1", hourly_records=hourly, hourly_granularity="hourly"
    )
    await async_wait_recording_done(hass)

    actual_consumption = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    assert len(actual_consumption) == 23
    assert len(actual_cost) == 23

    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.promote_hourly(spring_day, hourly)

    expected_consumption = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    compare_both_series(
        actual_consumption,
        actual_cost,
        expected_consumption,
        expected_cost,
    )


@pytest.mark.slow
async def test_recorder_fall_dst_raw_stays_daily_vs_aware_25_promotes_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify 2026 fall day stays daily under raw date-only input, but promotes with aware 25-hour input."""
    fall_day = "2026-11-01"
    daily_record = [{"date": fall_day, "kwh": 25.0, "cost": 6.25}]

    # In production, closed day check compares against now (dt_util.utcnow()).
    # Simulate historical closed day by patching now to 2026-11-10.
    future_now = datetime(2026, 11, 10, tzinfo=UTC)
    with patch("homeassistant.util.dt.utcnow", return_value=future_now):
        # 1. Feed real Nov 1 2026 date-only points through production parser + coordinator write path
        # Variant A: 24 date-only points (x = NY wall-clock as UTC ms, labels "11/01/2026")
        points_24 = make_raw_chart_points(fall_day, 1.0, hours=list(range(24)))
        payload_24 = make_raw_chart_payload("m1", points_24)
        parsed_24 = coord.client._parse_hourly_chart(payload_24)

        await coord.async_record_statistics(
            daily_record,
            meter_id="m1",
            hourly_records=parsed_24["hourly_records"],
            hourly_granularity=parsed_24["hourly_granularity"],
        )
        await async_wait_recording_done(hass)

        actual_c_24 = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
        actual_cost_24 = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

        # Stays daily: exactly 1 row for both series because dst_ambiguous prevents promotion
        assert len(actual_c_24) == 1
        assert len(actual_cost_24) == 1

        model_daily = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
        model_daily.record_daily(daily_record)

        compare_both_series(
            actual_c_24,
            actual_cost_24,
            model_daily.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            model_daily.expected_rows_as_tuples(COST_STATISTIC_ID),
        )

        # Variant B: 25 date-only points with duplicated 01:00 wall hour as PSEG plausibly sends it
        hours_25 = [0, 1, 1] + list(range(2, 24))
        points_25 = make_raw_chart_points(fall_day, 1.0, hours=hours_25)
        payload_25 = make_raw_chart_payload("m1", points_25)
        parsed_25 = coord.client._parse_hourly_chart(payload_25)

        await coord.async_record_statistics(
            daily_record,
            meter_id="m1",
            hourly_records=parsed_25["hourly_records"],
            hourly_granularity=parsed_25["hourly_granularity"],
        )
        await async_wait_recording_done(hass)

        actual_c_25 = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
        actual_cost_25 = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

        assert len(actual_c_25) == 1
        assert len(actual_cost_25) == 1

        compare_both_series(
            actual_c_25,
            actual_cost_25,
            model_daily.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            model_daily.expected_rows_as_tuples(COST_STATISTIC_ID),
        )

        # 2. Canonical aware 25-hour writer input -> promotes to HOURLY
        canonical_25 = make_canonical_hourly_records(fall_day, 1.0)
        assert len(canonical_25) == 25

        await coord.async_record_statistics(
            daily_record,
            meter_id="m1",
            hourly_records=canonical_25,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        promoted_c = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
        promoted_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

        assert len(promoted_c) == 25
        assert len(promoted_cost) == 25

        model_promoted = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
        model_promoted.promote_hourly(fall_day, canonical_25)

        compare_both_series(
            promoted_c,
            promoted_cost,
            model_promoted.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            model_promoted.expected_rows_as_tuples(COST_STATISTIC_ID),
        )


@pytest.mark.slow
async def test_recorder_open_day_remains_daily_until_closed_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify today's open day partial/complete hourly data is not promoted until day is closed."""
    # Freeze time at NY local mid-day on 2026-10-25 (12:00 EDT = 16:00 UTC)
    frozen_now = datetime(2026, 10, 25, 16, 0, 0, tzinfo=UTC)
    with patch("homeassistant.util.dt.utcnow", return_value=frozen_now):
        daily = [{"date": "2026-10-25", "kwh": 24.0, "cost": 6.0}]
        hourly = make_canonical_hourly_records("2026-10-25", 1.0)
        assert len(hourly) == 24

        await coord.async_record_statistics(
            daily,
            meter_id="m1",
            hourly_records=hourly,
            hourly_granularity="hourly",
        )
        await async_wait_recording_done(hass)

        actual_c = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
        actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

        # Must remain daily: exactly 1 row for each series
        assert len(actual_c) == 1
        assert len(actual_cost) == 1

        model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
        model.record_daily(daily)

        compare_both_series(
            actual_c,
            actual_cost,
            model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID),
            model.expected_rows_as_tuples(COST_STATISTIC_ID),
        )


@pytest.mark.slow
async def test_recorder_fractional_half_cent_cost_both_series(
    hass: HomeAssistant, coord: PsegDataUpdateCoordinator
) -> None:
    """Verify fractional half-cent costs (e.g. 2.505) are preserved and compared within tolerance."""
    records = [{"date": "2026-10-01", "kwh": 10.0, "cost": 2.505}]
    await coord.async_record_statistics(records, meter_id="m1")
    await async_wait_recording_done(hass)

    actual_c = await fetch_recorder_rows(hass, CONSUMPTION_STATISTIC_ID)
    actual_cost = await fetch_recorder_rows(hass, COST_STATISTIC_ID)

    model = ReferenceStatisticsModel(price_per_kwh=Decimal("0.25"), meter_id="m1")
    model.record_daily(records)

    expected_c = model.expected_rows_as_tuples(CONSUMPTION_STATISTIC_ID)
    expected_cost = model.expected_rows_as_tuples(COST_STATISTIC_ID)

    assert actual_cost[0][1] == pytest.approx(2.505, abs=1e-4)
    compare_both_series(
        actual_c,
        actual_cost,
        expected_c,
        expected_cost,
    )

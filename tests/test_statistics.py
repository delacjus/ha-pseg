"""Tests for external statistics computation and idempotency."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant.components.recorder.models import StatisticMeanType
from homeassistant.const import UnitOfEnergy
from homeassistant.core import HomeAssistant

from custom_components.pseg.const import DOMAIN
from custom_components.pseg.coordinator import (
    PsegDataUpdateCoordinator,
    build_external_statistics,
)


def test_statistics_ids_and_metadata() -> None:
    """Test that external statistic IDs are lowercase and valid with proper metadata."""
    records = [{"date": "2026-10-15", "kwh": 12.5, "cost": 3.09}]
    consumption_meta, consumption_data, cost_meta, cost_data = build_external_statistics(
        records=records,
        meter_id="Electric Meter #12345678",
        price_per_kwh=0.247,
    )

    # Valid lowercase external statistic ids
    assert consumption_meta["statistic_id"] == "pseg:electric_meter_12345678_energy_consumption"
    assert cost_meta["statistic_id"] == "pseg:electric_meter_12345678_energy_cost"

    # Metadata conforms to Home Assistant external statistics standards
    assert consumption_meta["source"] == DOMAIN
    assert consumption_meta["has_mean"] is False
    assert consumption_meta["mean_type"] == StatisticMeanType.NONE
    assert consumption_meta["has_sum"] is True
    assert consumption_meta["unit_class"] == "energy"
    assert consumption_meta["unit_of_measurement"] == UnitOfEnergy.KILO_WATT_HOUR

    assert cost_meta["source"] == DOMAIN
    assert cost_meta["has_mean"] is False
    assert cost_meta["has_sum"] is True
    assert cost_meta["unit_of_measurement"] == "USD"

    assert len(consumption_data) == 1
    assert consumption_data[0]["state"] == 12.5
    assert consumption_data[0]["sum"] == 12.5

    assert len(cost_data) == 1
    assert cost_data[0]["state"] == 3.09
    assert cost_data[0]["sum"] == 3.09


def test_two_overlapping_polls_cumulative_and_identical() -> None:
    """Test two overlapping 5-day polls produce strictly cumulative and identical sums on re-import."""
    # Poll 1: 2026-10-01 to 2026-10-05 (10 kWh/day)
    poll1_records = [
        {"date": f"2026-10-0{i}", "kwh": 10.0, "cost": 2.47} for i in range(1, 6)
    ]
    _, c1_data, _, cost1_data = build_external_statistics(
        records=poll1_records,
        meter_id="meter1",
        prior_consumption_sum=None,
        prior_cost_sum=None,
    )

    assert [d["sum"] for d in c1_data] == [10.0, 20.0, 30.0, 40.0, 50.0]
    assert [d["sum"] for d in cost1_data] == [2.47, 4.94, 7.41, 9.88, 12.35]

    # Poll 2: 2026-10-03 to 2026-10-07 (overlapping 10-03..10-05, new 10-06..10-07)
    # The last statistic strictly before 2026-10-03 is 2026-10-02 (sum = 20.0 kWh, cost = 4.94)
    poll2_records = [
        {"date": f"2026-10-0{i}", "kwh": 10.0, "cost": 2.47} for i in range(3, 8)
    ]
    _, c2_data, _, cost2_data = build_external_statistics(
        records=poll2_records,
        meter_id="meter1",
        prior_consumption_sum=20.0,
        prior_cost_sum=4.94,
    )

    # Overlapping days (10-03, 10-04, 10-05) have IDENTICAL sums to poll 1
    assert c2_data[0]["sum"] == c1_data[2]["sum"] == 30.0
    assert c2_data[1]["sum"] == c1_data[3]["sum"] == 40.0
    assert c2_data[2]["sum"] == c1_data[4]["sum"] == 50.0

    # New days continue strictly cumulatively
    assert c2_data[3]["sum"] == 60.0
    assert c2_data[4]["sum"] == 70.0

    assert cost2_data[0]["sum"] == cost1_data[2]["sum"] == 7.41
    assert cost2_data[1]["sum"] == cost1_data[3]["sum"] == 9.88
    assert cost2_data[2]["sum"] == cost1_data[4]["sum"] == 12.35
    assert cost2_data[3]["sum"] == 14.82
    assert cost2_data[4]["sum"] == 17.29


def test_2year_backfill_then_poll_continuous() -> None:
    """Test backfill followed by rolling 14-day poll remains continuous without zero-sum reset."""
    # 730 days backfill at 20 kWh / day
    prior_days_count = 730
    backfill_total_kwh = prior_days_count * 20.0  # 14,600 kWh
    backfill_total_cost = round(prior_days_count * 20.0 * 0.247, 2)  # 3,606.20 USD

    # Rolling poll starts day after backfill
    poll_records = [
        {"date": "2026-10-18", "kwh": 15.0},
        {"date": "2026-10-19", "kwh": 18.0},
        {"date": "2026-10-20", "kwh": 22.0},
    ]

    _, c_data, _, cost_data = build_external_statistics(
        records=poll_records,
        meter_id="12345",
        prior_consumption_sum=backfill_total_kwh,
        prior_cost_sum=backfill_total_cost,
        price_per_kwh=0.247,
    )

    assert c_data[0]["sum"] == 14615.0
    assert c_data[1]["sum"] == 14633.0
    assert c_data[2]["sum"] == 14655.0

    assert cost_data[0]["sum"] == round(backfill_total_cost + round(15.0 * 0.247, 2), 2)
    assert cost_data[1]["sum"] == round(backfill_total_cost + round(15.0 * 0.247, 2) + round(18.0 * 0.247, 2), 2)
    assert cost_data[2]["sum"] == round(backfill_total_cost + round(15.0 * 0.247, 2) + round(18.0 * 0.247, 2) + round(22.0 * 0.247, 2), 2)


def test_dst_transition_america_new_york() -> None:
    """Test daily start timestamps across DST fall-back day (2026-11-01 in America/New_York)."""
    records = [
        {"date": "2026-10-31", "kwh": 10.0, "cost": 2.47},
        {"date": "2026-11-01", "kwh": 10.0, "cost": 2.47},  # DST fall-back day (25-hour day)
        {"date": "2026-11-02", "kwh": 10.0, "cost": 2.47},  # First standard time day
    ]

    _, c_data, _, _ = build_external_statistics(
        records=records,
        meter_id="test_dst",
    )

    # In America/New_York:
    # 2026-10-31 midnight EDT is UTC-4 -> 2026-10-31 04:00:00 UTC
    # 2026-11-01 midnight EDT is UTC-4 -> 2026-11-01 04:00:00 UTC (DST transition occurs at 2am)
    # 2026-11-02 midnight EST is UTC-5 -> 2026-11-02 05:00:00 UTC
    assert c_data[0]["start"] == datetime(2026, 10, 31, 4, 0, tzinfo=UTC)
    assert c_data[1]["start"] == datetime(2026, 11, 1, 4, 0, tzinfo=UTC)
    assert c_data[2]["start"] == datetime(2026, 11, 2, 5, 0, tzinfo=UTC)

    # Time delta between Nov 1 and Nov 2 midnight is 25 hours
    assert c_data[2]["start"] - c_data[1]["start"] == datetime(2026, 11, 2, 5, 0, tzinfo=UTC) - datetime(2026, 11, 1, 4, 0, tzinfo=UTC)


async def test_coordinator_async_record_statistics_integration(hass: HomeAssistant) -> None:
    """Test coordinator async_record_statistics integrates with external statistics."""
    mock_client = MagicMock()
    mock_client.price_per_kwh = 0.247

    coord = PsegDataUpdateCoordinator(
        hass=hass,
        client=mock_client,
        entry_data={"meter_id": "999888"},
    )

    records = [
        {"date": "2026-10-10", "kwh": 14.0, "cost": 3.46},
        {"date": "2026-10-11", "kwh": 16.0, "cost": 3.95},
    ]

    with (
        patch(
            "custom_components.pseg.coordinator._async_get_last_stat_before",
            new_callable=AsyncMock,
            return_value=100.0,
        ) as mock_get_prior,
        patch(
            "custom_components.pseg.coordinator._async_get_stats_after",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "custom_components.pseg.coordinator.async_add_external_statistics"
        ) as mock_add_ext,
    ):
        await coord.async_record_statistics(records, meter_id="999888")

        assert mock_get_prior.call_count == 2
        assert mock_add_ext.call_count == 2

        # First call was consumption
        c_meta_call, c_data_call = mock_add_ext.call_args_list[0][0][1], mock_add_ext.call_args_list[0][0][2]
        assert c_meta_call["statistic_id"] == "pseg:999888_energy_consumption"
        assert c_data_call[0]["sum"] == 114.0
        assert c_data_call[1]["sum"] == 130.0

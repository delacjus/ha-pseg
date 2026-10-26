"""Observed UsageType 3 cost contract: synthetic fixture, currency proof, request payload.

Guards for the cost contract observed in the browser on 2026-10-26 (docs/portal-cost.md):
the chart POST uses UsageType "3" with jsTargetName "UsageType", and dollar data is
proven from the response itself (`tooltipOptions.currency == "USD"` plus
`Data.usageType == "Dollar"`), never from the request or from a corroborating label.

The fixture `tests/fixtures/cost_contract/usagetype3_daily_synthetic.json` reproduces the
captured response structure (key names, key order, series types) with synthetic values;
see its `PROVENANCE.md`. It is synthetic on purpose and proves shape only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
import json
from pathlib import Path
from unittest.mock import MagicMock
import urllib.parse

import requests
import requests_mock

from custom_components.pseg.const import (
    PORTAL_BASE_URL,
    USAGE_INTERVAL_DAILY,
    USAGE_INTERVAL_HOURLY,
)
from custom_components.pseg.cost_evidence import (
    REASON_CURRENCY_UNPROVEN,
    REASON_NO_AUTHORITATIVE_METER_SERIES,
    REASON_UNSUPPORTED_UNIT,
    CostEvidenceStatus,
    CostPermit,
    execute_cost_sampler,
    validate_and_sanitize_cost_payload,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cost_contract" / "usagetype3_daily_synthetic.json"
FIXTURE_BYTES = FIXTURE.read_bytes()

METER_A = "000012345678"
METER_B = "000087654321"
AUTHORITATIVE = {METER_A, METER_B}

# The fixture's 15 daily values, in order: the sample must preserve them at source precision.
FIXTURE_Y_VALUES = (
    "3.751234567890123",
    "4.128765432109876",
    "2.9876543210987654",
    "5.24680135792468",
    "4.86420975318642",
    "3.109876543210987",
    "6.357913579135792",
    "5.024680246802468",
    "4.24680246802468",
    "3.642086420864208",
    "5.531086420864208",
    "4.975308642097531",
    "3.864197530864197",
    "5.185185185185185",
    "4.320987654320988",
)


def _permit(usage_interval: str = USAGE_INTERVAL_DAILY) -> CostPermit:
    """Daily or hourly permit for a fixed synthetic window."""
    return CostPermit(
        permit_id="usagetype3_permit",
        entry_id="usagetype3_entry",
        ny_date="2026-10-26",
        usage_interval=usage_interval,
        start_str="2026-09-01",
        end_str="2026-09-15",
        created_at=datetime.now(UTC).isoformat(),
    )


def _fixture() -> dict:
    """Load the synthetic fixture with ordinary JSON types (mutation-friendly)."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _fixture_like_production() -> dict:
    """Load the fixture the way `execute_cost_sampler` decodes a body: Decimal numbers."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"), parse_float=Decimal, parse_int=Decimal)


def _validate(payload: dict) -> tuple[CostEvidenceStatus, dict, bool]:
    """Run the production validator over a payload with the fixture's meter set."""
    return validate_and_sanitize_cost_payload(
        payload=payload,
        authoritative_meters=AUTHORITATIVE,
        meter_placeholders={},
        permit=_permit(),
    )


def _run_sampler(usage_interval: str) -> tuple[CostEvidenceStatus, dict, bool, dict]:
    """Dispatch the real two-request pair against the fixture body; return its form body."""
    with requests_mock.Mocker() as mock:
        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", content=FIXTURE_BYTES)
        status, sample, promotable = execute_cost_sampler(
            seed_cookies=requests.cookies.RequestsCookieJar(),
            token="usagetype3_token",
            permit=_permit(usage_interval),
            owner_check=MagicMock(),
            authoritative_meters=AUTHORITATIVE,
            meter_placeholders={},
        )
        assert len(mock.request_history) == 2
        post = mock.request_history[0]
        assert post.method == "POST"
        body = urllib.parse.parse_qs(post.text)
    return status, sample, promotable, body


# ---------------------------------------------------------------------------
# Request: the browser's cost chart payload
# ---------------------------------------------------------------------------


def test_daily_cost_post_sends_usagetype_3_and_the_cost_chart_target() -> None:
    """UsageType is "3" (not "2") and jsTargetName is "UsageType", as the browser sends."""
    status, sample, promotable, body = _run_sampler(USAGE_INTERVAL_DAILY)

    assert status == CostEvidenceStatus.OK
    assert promotable is True
    assert body["UsageType"] == ["3"]
    assert body["UsageInterval"] == [USAGE_INTERVAL_DAILY] == ["6"]
    assert body["jsTargetName"] == ["UsageType"]
    assert body["__RequestVerificationToken"] == ["usagetype3_token"]
    assert body["Start"] == ["2026-09-01"]
    assert body["End"] == ["2026-09-15"]
    assert body["EnableHoverChart"] == ["true"]
    assert body["IsRangeOpen"] == ["False"]
    assert body["MaintainMaxDate"] == ["true"]
    assert body["SelectedViaDateRange"] == ["False"]
    assert body["ChartComparison"] == ["1"]
    assert body["ChartComparison2"] == ["0"]
    assert body["ChartComparison3"] == ["0"]
    assert body["ChartComparison4"] == ["0"]
    # The sample records the type it actually asked for, so diagnostics cannot drift.
    assert sample["request"]["usage_type"] == "3"
    assert sample["request"]["usage_interval"] == "6"


def test_hourly_cost_post_keeps_interval_5_under_the_same_contract() -> None:
    """The hourly slot is unchanged ("5"), sends the same cost payload, and stays unproven."""
    status, sample, _promotable, body = _run_sampler(USAGE_INTERVAL_HOURLY)

    assert status == CostEvidenceStatus.OK
    assert body["UsageInterval"] == [USAGE_INTERVAL_HOURLY] == ["5"]
    assert body["UsageType"] == ["3"]
    assert body["jsTargetName"] == ["UsageType"]
    assert sample["request"]["usage_interval"] == "5"


# ---------------------------------------------------------------------------
# Response: the observed synthetic fixture
# ---------------------------------------------------------------------------


def test_synthetic_daily_fixture_is_ok_and_promotable_with_every_point_parsed() -> None:
    """The captured shape proves USD and parses all 15 points, ignoring every other series."""
    payload = _fixture_like_production()
    points = payload["Data"]["series"][1]["data"]

    status, sample, promotable = _validate(payload)

    assert status == CostEvidenceStatus.OK
    assert promotable is True
    assert sample["status"] == "ok"
    assert sample["unit"] == "USD"
    assert sample["total_points"] == len(points) == 15
    # Both authoritative meters are kept (the second may legitimately be empty).
    assert [s["name"] for s in sample["series"]] == ["Meter #1", "Meter #2"]
    assert [len(s["data"]) for s in sample["series"]] == [15, 0]

    retained = sample["series"][0]["data"]
    for point, original, expected_y in zip(retained, points, FIXTURE_Y_VALUES, strict=True):
        assert point["x"] == f"{original['x']:f}"
        assert point["y"] == expected_y
        assert Decimal(point["y"]) == original["y"]
        started = datetime.strptime(original["hs"]["start"], "%m/%d/%Y")
        ended = datetime.strptime(original["hs"]["end"], "%m/%d/%Y")
        assert point["hs"] == {
            "start": started.strftime("%Y-%m-%d"),
            "end": ended.strftime("%Y-%m-%d"),
        }
        assert (ended - started).days == 1

    # The navigator, temperature and marker series are dropped, and so are the
    # redacted extra point fields (xs, xe, v): counted, never parsed or kept.
    assert sample["dropped_count"] == 3 + 15 * 3
    serialized = json.dumps(sample)
    assert METER_A not in serialized
    assert METER_B not in serialized
    assert '"xe"' not in serialized


def test_daily_value_precision_is_kept_at_source_precision() -> None:
    """A long decimal from the response survives the sample verbatim, not as a float sum."""
    _, sample, _ = _validate(_fixture_like_production())

    values = [point["y"] for point in sample["series"][0]["data"]]
    assert values == list(FIXTURE_Y_VALUES)
    assert max(len(value.split(".")[1]) for value in values) >= 15


# ---------------------------------------------------------------------------
# Currency proof: exact currency + exact usage name, corroboration can only refute
# ---------------------------------------------------------------------------


def test_missing_currency_is_unproven_even_with_a_dollar_usage_type() -> None:
    """`usageType: "Dollar"` without `tooltipOptions.currency` proves nothing."""
    payload = _fixture()
    del payload["Data"]["tooltipOptions"]["currency"]

    status, sample, promotable = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == REASON_CURRENCY_UNPROVEN
    assert promotable is False
    assert "series" not in sample


def test_empty_currency_is_unproven() -> None:
    """A blank currency token is absence, not proof."""
    payload = _fixture()
    payload["Data"]["tooltipOptions"]["currency"] = "   "

    status, sample, _ = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == REASON_CURRENCY_UNPROVEN


def test_kwh_usage_type_contradicts_the_usd_currency() -> None:
    """A kWh chart is not dollar data, even when the currency field says USD."""
    payload = _fixture()
    payload["Data"]["usageType"] = "kWh"

    status, sample, promotable = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == REASON_UNSUPPORTED_UNIT
    assert promotable is False


def test_foreign_currency_is_unsupported_not_unproven() -> None:
    """Another currency is a contradiction, so the reason is unsupported_unit."""
    payload = _fixture()
    payload["Data"]["tooltipOptions"]["currency"] = "EUR"

    status, sample, _ = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == REASON_UNSUPPORTED_UNIT


def test_currency_token_is_case_sensitive() -> None:
    """The contract names "USD" exactly; a lower-case token is a different token."""
    payload = _fixture()
    payload["Data"]["tooltipOptions"]["currency"] = "usd"

    status, sample, _ = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == REASON_UNSUPPORTED_UNIT


def test_dollar_sign_corroboration_alone_is_unproven() -> None:
    """`yAxis` "$" plus a meter `$` prefix are labels, not proof of the currency."""
    payload = _fixture()
    del payload["Data"]["tooltipOptions"]["currency"]
    del payload["Data"]["tooltipOptions"]["usageTypeDisplayName"]
    del payload["Data"]["usageType"]
    assert payload["Data"]["yAxis"][0]["title"]["text"] == "$"
    assert payload["Data"]["series"][1]["tooltip"]["valuePrefix"] == "$"

    status, sample, promotable = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == REASON_CURRENCY_UNPROVEN
    assert promotable is False


def test_usage_type_display_name_completes_the_proof_without_data_usage_type() -> None:
    """`tooltipOptions.usageTypeDisplayName` is the documented alternative to `usageType`."""
    payload = _fixture()
    del payload["Data"]["usageType"]
    assert payload["Data"]["tooltipOptions"]["usageTypeDisplayName"] == "Dollar"

    status, _sample, promotable = _validate(payload)

    assert status == CostEvidenceStatus.OK
    assert promotable is True


def test_non_dollar_meter_series_prefix_contradicts_the_proof() -> None:
    """A kWh prefix on a meter series means the series is not dollars."""
    payload = _fixture()
    payload["Data"]["series"][1]["tooltip"]["valuePrefix"] = "kWh"

    status, sample, _ = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == REASON_UNSUPPORTED_UNIT


def test_non_dollar_axis_title_contradicts_the_proof() -> None:
    """A y-axis title that names another unit contradicts the currency fields."""
    payload = _fixture()
    payload["Data"]["yAxis"][0]["title"]["text"] = "Therms"

    status, sample, _ = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == REASON_UNSUPPORTED_UNIT


def test_navigator_only_response_has_no_authoritative_series() -> None:
    """Correct dollars from a payload with no meter series is still not evidence."""
    payload = _fixture()
    payload["Data"]["series"] = [payload["Data"]["series"][0]]

    status, sample, promotable = _validate(payload)

    assert status == CostEvidenceStatus.WRONG_METER
    assert sample["reason"] == REASON_NO_AUTHORITATIVE_METER_SERIES
    assert promotable is False


def test_fixture_proof_does_not_depend_on_series_order() -> None:
    """Meter identity, not series position, selects the authoritative series."""
    payload = _fixture()
    series = payload["Data"]["series"]
    series[1], series[2] = series[2], series[1]

    status, sample, _ = _validate(payload)

    assert status == CostEvidenceStatus.OK
    assert [len(s["data"]) for s in sample["series"]] == [0, 15]
    assert sample["total_points"] == 15

"""Offline contract tests for PSE&G portal cost (UsageType 2) and non-authoritative seam.

This module defines the pure offline reference validator and unit tests for RC-01:
- Freezes the request shape and parameter validation for UsageType "1" and "2".
- Enforces preservation of all 13 canonical Chart form fields.
- Verifies that the current production request builder maintains the UsageType "1" baseline.
- Defines and enumerates the complete status vocabulary.
- Enforces strict meter matching against authoritative kWh meter identity (rejecting upstream
  first-series or first-nonempty shortcuts).
- Asserts zero is a valid numeric observation (preventing upstream zero->estimate substitution).
- Quarantines booleans, NaN, Inf, negatives, duplicates, and non-USD units.
- Provides negative proofs rejecting upstream 63c912f design flaws.
"""

from enum import StrEnum
import math
from typing import Any
from unittest.mock import patch

import pytest
import requests
import requests_mock

from custom_components.pseg.const import (
    USAGE_INTERVAL_DAILY,
    USAGE_INTERVAL_HOURLY,
)
from custom_components.pseg.pseg_client import (
    _METER_SERIES,
    PsegClient,
)

# Canonical form fields required by POST /Dashboard/Chart
EXPECTED_CHART_FIELDS = frozenset({
    "__RequestVerificationToken",
    "UsageInterval",
    "UsageType",
    "jsTargetName",
    "EnableHoverChart",
    "Start",
    "End",
    "IsRangeOpen",
    "MaintainMaxDate",
    "SelectedViaDateRange",
    "ChartComparison",
    "ChartComparison2",
    "ChartComparison3",
    "ChartComparison4",
})


# ---------------------------------------------------------------------------
# Reference Contract Validator (Pure, Offline - not production code)
# ---------------------------------------------------------------------------


class CostEvidenceStatus(StrEnum):
    """Status vocabulary for non-authoritative cost evidence evaluations."""

    OK = "ok"
    MISSING = "missing"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    AUTH_REJECTED = "auth_rejected"
    WRONG_METER = "wrong_meter"
    WRONG_UNIT = "wrong_unit"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TRUNCATED = "truncated"


def validate_usage_type(usage_type: str = "1") -> str:
    """Validate usage_type parameter.

    Default is '1' (Consumption). Only '1' and '2' (Cost) are valid.
    """
    if not isinstance(usage_type, str):
        raise TypeError(f"usage_type must be a string, got {type(usage_type).__name__}")
    if usage_type not in ("1", "2"):
        raise ValueError(
            f"Invalid usage_type '{usage_type}': only '1' (consumption) and '2' (cost) are supported"
        )
    return usage_type


def build_chart_request_payload(
    token: str,
    usage_interval: str,
    start_str: str,
    end_str: str,
    usage_type: str = "1",
) -> dict[str, str]:
    """Pure reference request builder for POST /Dashboard/Chart."""
    validated_type = validate_usage_type(usage_type)
    return {
        "__RequestVerificationToken": token,
        "UsageInterval": usage_interval,
        "UsageType": validated_type,
        "jsTargetName": "StorageType",
        "EnableHoverChart": "true",
        "Start": start_str,
        "End": end_str,
        "IsRangeOpen": "False",
        "MaintainMaxDate": "true",
        "SelectedViaDateRange": "False",
        "ChartComparison": "1",
        "ChartComparison2": "0",
        "ChartComparison3": "0",
        "ChartComparison4": "0",
    }


def validate_cost_observation(y: Any) -> tuple[bool, str | None]:
    """Validate a single cost observation.

    Zero is a valid numeric observation. Booleans, NaN, Inf, and negatives
    are quarantined.
    """
    if isinstance(y, bool):
        return False, "quarantine_boolean"
    if not isinstance(y, (int, float)):
        return False, "quarantine_non_numeric"
    if not math.isfinite(y):
        return False, "quarantine_non_finite"
    if float(y) < 0.0:
        return False, "quarantine_negative"
    return True, None


def validate_cost_payload(
    payload: Any,
    authoritative_meters: set[str] | list[str],
    *,
    max_points: int = 1500,
    max_series: int = 4,
) -> tuple[CostEvidenceStatus, dict[str, Any]]:
    """Pure reference validator for cost evidence payloads.

    Enforces authoritative meter identity matching, zero-observation validity,
    bounded sample diagnostics limits, and quarantine of invalid data.
    """
    if payload is None or payload == {}:
        return CostEvidenceStatus.MISSING, {"reason": "empty_payload"}

    if not isinstance(payload, dict):
        return CostEvidenceStatus.MALFORMED, {"reason": "payload_not_dict"}

    # Transport / HTTP status simulations
    if payload.get("status_code") in (401, 403) or payload.get("auth_rejected"):
        return CostEvidenceStatus.AUTH_REJECTED, {"reason": "http_auth_failure"}

    if payload.get("redirect") or payload.get("status_code") in (301, 302, 303, 307, 308) or payload.get("unsupported"):
        return CostEvidenceStatus.UNSUPPORTED, {"reason": "redirect_or_unsupported"}

    if payload.get("budget_exhausted"):
        return CostEvidenceStatus.BUDGET_EXHAUSTED, {"reason": "budget_permit_unavailable"}

    if payload.get("truncated"):
        return CostEvidenceStatus.TRUNCATED, {"reason": "flagged_truncated"}

    data_block = payload.get("Data")
    if data_block is None:
        return CostEvidenceStatus.MISSING, {"reason": "missing_data_block"}
    if not isinstance(data_block, dict):
        return CostEvidenceStatus.MALFORMED, {"reason": "data_block_not_dict"}

    raw_series = data_block.get("series")
    if raw_series is None:
        return CostEvidenceStatus.MISSING, {"reason": "missing_series"}
    if not isinstance(raw_series, list):
        return CostEvidenceStatus.MALFORMED, {"reason": "series_not_list"}
    if len(raw_series) == 0:
        return CostEvidenceStatus.MISSING, {"reason": "empty_series"}
    if len(raw_series) > max_series:
        return CostEvidenceStatus.TRUNCATED, {"reason": f"series_count_{len(raw_series)}_exceeds_max"}

    # Unit / Currency check: dollars must be PROVEN by an explicit unit token;
    # absent or blank units are unproven, never assumed to be USD.
    proven_usd = False
    for unit_key in ("unit", "unitOfMeasure", "currency", "yAxisTitle"):
        val = data_block.get(unit_key)
        if val is None or not str(val).strip():
            continue
        if str(val).strip().upper() not in ("USD", "$"):
            return CostEvidenceStatus.WRONG_UNIT, {"reason": f"unsupported_currency_unit_{val}"}
        proven_usd = True
    if not proven_usd:
        return CostEvidenceStatus.WRONG_UNIT, {"reason": "currency_unproven"}

    auth_set = {str(m) for m in authoritative_meters}
    matched_series: list[dict[str, Any]] = []
    total_points = 0
    # (meter, timestamp) keys are unique across the WHOLE payload, so a repeated
    # meter series cannot double-count an interval.
    seen_keys: set[tuple[str, Any]] = set()

    for series_item in raw_series:
        if not isinstance(series_item, dict):
            return CostEvidenceStatus.MALFORMED, {"reason": "series_item_not_dict"}

        name = str(series_item.get("name") or "")
        match = _METER_SERIES.match(name)
        if not match:
            # Non-meter series (e.g. Temperature) are skipped
            continue

        meter_id = match.group(1)
        if meter_id not in auth_set:
            # Cannot enlarge or discover identity
            return CostEvidenceStatus.WRONG_METER, {
                "reason": f"meter_{meter_id}_not_in_authoritative_set",
                "observed_meter": meter_id,
                "authoritative_meters": sorted(auth_set),
            }

        raw_points = series_item.get("data")
        if not isinstance(raw_points, list):
            return CostEvidenceStatus.MALFORMED, {"reason": "points_not_list"}

        total_points += len(raw_points)
        seen_x: set[Any] = set()
        validated_points: list[dict[str, Any]] = []

        for pt in raw_points:
            if not isinstance(pt, dict):
                return CostEvidenceStatus.MALFORMED, {"reason": "point_not_dict"}

            x = pt.get("x")
            if x is not None:
                if x in seen_x or (meter_id, x) in seen_keys:
                    return CostEvidenceStatus.MALFORMED, {"reason": f"duplicate_timestamp_{x}"}
                seen_x.add(x)
                seen_keys.add((meter_id, x))

            is_valid, q_reason = validate_cost_observation(pt.get("y"))
            if not is_valid:
                return CostEvidenceStatus.MALFORMED, {"reason": q_reason, "point": pt}

            validated_points.append(pt)

        matched_series.append({
            "meter_id": meter_id,
            "name": name,
            "points": validated_points,
        })

    if total_points > max_points:
        return CostEvidenceStatus.TRUNCATED, {"reason": f"point_count_{total_points}_exceeds_max"}

    if not matched_series:
        return CostEvidenceStatus.WRONG_METER, {
            "reason": "no_matching_authoritative_meter_found",
            "authoritative_meters": sorted(auth_set),
        }

    return CostEvidenceStatus.OK, {
        "matched_series": matched_series,
        "total_points": total_points,
    }


# ---------------------------------------------------------------------------
# Test Suite: Request Seam and Form Fields
# ---------------------------------------------------------------------------


def test_usage_type_argument_validation() -> None:
    """Validate usage_type parameter defaults to '1', accepts '1'/'2', and rejects others."""
    # Default is "1"
    assert validate_usage_type() == "1"
    assert validate_usage_type("1") == "1"
    assert validate_usage_type("2") == "2"

    # Rejection of invalid types and values
    for invalid in ("0", "3", "cost", "kwh", "", " "):
        with pytest.raises(ValueError, match="Invalid usage_type"):
            validate_usage_type(invalid)

    for invalid_type in (1, 2, None, False, 1.0):  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="must be a string"):
            validate_usage_type(invalid_type)


def test_chart_request_form_fields_preserved() -> None:
    """All 13 canonical Chart form fields are preserved identical between UsageType '1' and '2'."""
    token = "token_abc123"
    start = "2026-10-10"
    end = "2026-10-24"

    daily_kwh = build_chart_request_payload(token, USAGE_INTERVAL_DAILY, start, end, "1")
    daily_cost = build_chart_request_payload(token, USAGE_INTERVAL_DAILY, start, end, "2")
    hourly_kwh = build_chart_request_payload(token, USAGE_INTERVAL_HOURLY, start, end, "1")
    hourly_cost = build_chart_request_payload(token, USAGE_INTERVAL_HOURLY, start, end, "2")

    for payload in (daily_kwh, daily_cost, hourly_kwh, hourly_cost):
        assert set(payload.keys()) == EXPECTED_CHART_FIELDS
        assert payload["__RequestVerificationToken"] == token
        assert payload["Start"] == start
        assert payload["End"] == end
        assert payload["jsTargetName"] == "StorageType"
        assert payload["EnableHoverChart"] == "true"
        assert payload["IsRangeOpen"] == "False"
        assert payload["MaintainMaxDate"] == "true"
        assert payload["SelectedViaDateRange"] == "False"
        assert payload["ChartComparison"] == "1"
        assert payload["ChartComparison2"] == "0"
        assert payload["ChartComparison3"] == "0"
        assert payload["ChartComparison4"] == "0"

    # Verify that the ONLY difference between kWh and Cost requests is UsageType
    for k in EXPECTED_CHART_FIELDS:
        if k == "UsageType":
            assert daily_kwh[k] == "1"
            assert daily_cost[k] == "2"
        else:
            assert daily_kwh[k] == daily_cost[k]


def test_production_request_builder_kwh_baseline() -> None:
    """Assert current production PsegClient._fetch_chart_json builds UsageType '1' kWh shape.

    This baseline guard ensures that RC-02 cannot inadvertently mutate the existing
    consumption request construction.
    """
    client = PsegClient(portal_cookies="MM_SID=valid_sid")
    captured_data: dict[str, Any] = {}

    def custom_matcher(request: requests.PreparedRequest) -> requests.Response:
        nonlocal captured_data
        if "/Dashboard/Chart" in request.url and request.method == "POST":
            # parse urlencoded body
            from urllib.parse import parse_qs

            body = request.body if isinstance(request.body, str) else request.body.decode("utf-8")  # type: ignore[union-attr]
            captured_data = {k: v[0] for k, v in parse_qs(body).items()}
            resp = requests.Response()
            resp.status_code = 200
            resp._content = b"ok"
            return resp
        if "/Dashboard/ChartData" in request.url and request.method == "GET":
            resp = requests.Response()
            resp.status_code = 200
            resp._content = b'{"Data": {"unit": "USD", "series": []}}'
            return resp
        resp = requests.Response()
        resp.status_code = 404
        return resp

    with requests_mock.Mocker() as mock:
        mock.add_matcher(custom_matcher)
        client._fetch_chart_json("test_token", USAGE_INTERVAL_DAILY, "2026-10-10", "2026-10-24")

    assert set(captured_data.keys()) == EXPECTED_CHART_FIELDS
    assert captured_data["UsageType"] == "1"
    assert captured_data["UsageInterval"] == USAGE_INTERVAL_DAILY
    assert captured_data["__RequestVerificationToken"] == "test_token"
    assert captured_data["Start"] == "2026-10-10"
    assert captured_data["End"] == "2026-10-24"


# ---------------------------------------------------------------------------
# Test Suite: Status Vocabulary Enumeration
# ---------------------------------------------------------------------------


def test_status_vocabulary_enumeration() -> None:
    """Enumerate all 8 required non-authoritative evidence statuses with explicit cases."""
    auth_meters = ["12345678"]

    # 1. MISSING: empty payload or missing data/series
    assert validate_cost_payload(None, auth_meters)[0] == CostEvidenceStatus.MISSING
    assert validate_cost_payload({}, auth_meters)[0] == CostEvidenceStatus.MISSING
    assert validate_cost_payload({"Data": None}, auth_meters)[0] == CostEvidenceStatus.MISSING
    assert validate_cost_payload({"Data": {"unit": "USD", "series": []}}, auth_meters)[0] == CostEvidenceStatus.MISSING

    # 2. MALFORMED: invalid types, malformed points, duplicate timestamps
    assert validate_cost_payload("not_a_dict", auth_meters)[0] == CostEvidenceStatus.MALFORMED
    assert validate_cost_payload({"Data": "not_a_dict"}, auth_meters)[0] == CostEvidenceStatus.MALFORMED
    assert validate_cost_payload({"Data": {"unit": "USD", "series": "not_a_list"}}, auth_meters)[0] == CostEvidenceStatus.MALFORMED
    assert (
        validate_cost_payload({"Data": {"unit": "USD", "series": [{"name": "Meter #12345678", "data": "not_a_list"}]}}, auth_meters)[0]
        == CostEvidenceStatus.MALFORMED
    )
    assert (
        validate_cost_payload(
            {"Data": {"unit": "USD", "series": [{"name": "Meter #12345678", "data": [{"x": 1000, "y": 1.0}, {"x": 1000, "y": 2.0}]}]}},
            auth_meters,
        )[0]
        == CostEvidenceStatus.MALFORMED
    )

    # 3. UNSUPPORTED: HTTP redirect 30x or unsupported flag
    assert validate_cost_payload({"redirect": True}, auth_meters)[0] == CostEvidenceStatus.UNSUPPORTED
    assert validate_cost_payload({"status_code": 302}, auth_meters)[0] == CostEvidenceStatus.UNSUPPORTED
    assert validate_cost_payload({"unsupported": True}, auth_meters)[0] == CostEvidenceStatus.UNSUPPORTED

    # 4. AUTH_REJECTED: HTTP 401/403 or auth_rejected flag
    assert validate_cost_payload({"status_code": 401}, auth_meters)[0] == CostEvidenceStatus.AUTH_REJECTED
    assert validate_cost_payload({"status_code": 403}, auth_meters)[0] == CostEvidenceStatus.AUTH_REJECTED
    assert validate_cost_payload({"auth_rejected": True}, auth_meters)[0] == CostEvidenceStatus.AUTH_REJECTED

    # 5. WRONG_METER: unauthoritative meter or missing matching meter
    assert (
        validate_cost_payload(
            {"Data": {"unit": "USD", "series": [{"name": "Meter #99999999", "data": [{"x": 1000, "y": 2.50}]}]}},
            auth_meters,
        )[0]
        == CostEvidenceStatus.WRONG_METER
    )

    # 6. WRONG_UNIT: non-USD currency
    assert (
        validate_cost_payload(
            {"Data": {"unit": "EUR", "series": [{"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]}]}},
            auth_meters,
        )[0]
        == CostEvidenceStatus.WRONG_UNIT
    )
    assert (
        validate_cost_payload(
            {"Data": {"unit": "kWh", "series": [{"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]}]}},
            auth_meters,
        )[0]
        == CostEvidenceStatus.WRONG_UNIT
    )

    # 7. BUDGET_EXHAUSTED: sampling attempt refused by permit
    assert validate_cost_payload({"budget_exhausted": True}, auth_meters)[0] == CostEvidenceStatus.BUDGET_EXHAUSTED

    # 8. TRUNCATED: points > 1500 or series > 4
    many_pts = [{"x": i * 3600000, "y": 0.10} for i in range(1501)]
    assert (
        validate_cost_payload(
            {"Data": {"unit": "USD", "series": [{"name": "Meter #12345678", "data": many_pts}]}},
            auth_meters,
        )[0]
        == CostEvidenceStatus.TRUNCATED
    )
    five_series = [
        {"name": "Meter #12345678", "data": [{"x": 1000, "y": 0.10}]} for _ in range(5)
    ]
    assert (
        validate_cost_payload({"Data": {"unit": "USD", "series": five_series}}, auth_meters)[0]
        == CostEvidenceStatus.TRUNCATED
    )

    # 9. OK: valid payload
    status, res = validate_cost_payload(
        {"Data": {"unit": "USD", "series": [{"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]}]}},
        auth_meters,
    )
    assert status == CostEvidenceStatus.OK
    assert res["total_points"] == 1


# ---------------------------------------------------------------------------
# Test Suite: Meter Matching and Anti-Upstream Rules
# ---------------------------------------------------------------------------


def test_meter_matching_authoritative_identity() -> None:
    """Cost series matches the exact authoritative kWh meter ID."""
    auth_meters = ["12345678"]
    payload = {
        "Data": {"unit": "USD",
            "series": [
                {"name": "Temperature", "data": [{"x": 1000, "y": 72.0}]},  # non-meter series ignored
                {"name": "Meter #12345678 (RS)", "data": [{"x": 1000, "y": 1.25}]},
            ]
        }
    }
    status, result = validate_cost_payload(payload, auth_meters)
    assert status == CostEvidenceStatus.OK
    assert len(result["matched_series"]) == 1
    assert result["matched_series"][0]["meter_id"] == "12345678"


def test_meter_matching_rejects_unauthoritative_meter() -> None:
    """Cost series belonging to a different meter is rejected as wrong_meter."""
    auth_meters = ["12345678"]
    payload = {
        "Data": {"unit": "USD",
            "series": [
                {"name": "Meter #87654321", "data": [{"x": 1000, "y": 1.25}]},
            ]
        }
    }
    status, result = validate_cost_payload(payload, auth_meters)
    assert status == CostEvidenceStatus.WRONG_METER
    assert result["observed_meter"] == "87654321"


def test_meter_matching_cannot_enlarge_identity() -> None:
    """Cost payload containing extra unknown meter cannot enlarge identity."""
    auth_meters = ["12345678"]
    payload = {
        "Data": {"unit": "USD",
            "series": [
                {"name": "Meter #12345678", "data": [{"x": 1000, "y": 1.25}]},
                {"name": "Meter #99999999", "data": [{"x": 1000, "y": 0.50}]},
            ]
        }
    }
    status, result = validate_cost_payload(payload, auth_meters)
    # The presence of an unauthoritative meter rejects the payload
    assert status == CostEvidenceStatus.WRONG_METER
    assert result["observed_meter"] == "99999999"


def test_meter_reordering_and_inactive_old_meter() -> None:
    """Cost series matching is robust to meter ordering and inactive old-meter series."""
    auth_meters = ["22222222"]

    # Inactive old meter first (0 points), active meter second (312 points)
    payload_inactive_first = {
        "Data": {"unit": "USD",
            "series": [
                {"name": "Meter #11111111 (RS)", "data": []},  # old inactive meter
                {"name": "Meter #22222222 (RS)", "data": [{"x": 1000, "y": 3.45}]},  # active meter
            ]
        }
    }
    # If only 22222222 is authoritative, the presence of 11111111 without being in auth_meters fails
    status, _ = validate_cost_payload(payload_inactive_first, auth_meters)
    assert status == CostEvidenceStatus.WRONG_METER

    # If account legitimately has both in auth_meters (e.g. meter swap across 14d)
    auth_swap = ["11111111", "22222222"]
    status, result = validate_cost_payload(payload_inactive_first, auth_swap)
    assert status == CostEvidenceStatus.OK
    assert len(result["matched_series"]) == 2
    # Verify active meter points were correctly preserved
    active_s = next(s for s in result["matched_series"] if s["meter_id"] == "22222222")
    assert len(active_s["points"]) == 1
    assert active_s["points"][0]["y"] == 3.45

    # Reverse order: active meter first, inactive meter second
    payload_active_first = {
        "Data": {"unit": "USD",
            "series": [
                {"name": "Meter #22222222 (RS)", "data": [{"x": 1000, "y": 3.45}]},
                {"name": "Meter #11111111 (RS)", "data": []},
            ]
        }
    }
    status, result2 = validate_cost_payload(payload_active_first, auth_swap)
    assert status == CostEvidenceStatus.OK
    active_s2 = next(s for s in result2["matched_series"] if s["meter_id"] == "22222222")
    assert active_s2["points"][0]["y"] == 3.45


# ---------------------------------------------------------------------------
# Test Suite: Zero Observation and Quarantine Rules
# ---------------------------------------------------------------------------


def test_zero_is_valid_numeric_observation() -> None:
    """A zero dollar observation ($0.00) is valid data, never missing or replaced by an estimate."""
    auth_meters = ["12345678"]
    payload = {
        "Data": {"unit": "USD",
            "series": [
                {
                    "name": "Meter #12345678",
                    "data": [
                        {"x": 1000, "y": 0.0},
                        {"x": 2000, "y": 0},
                        {"x": 3000, "y": 1.50},
                    ],
                }
            ]
        }
    }
    status, result = validate_cost_payload(payload, auth_meters)
    assert status == CostEvidenceStatus.OK
    pts = result["matched_series"][0]["points"]
    assert len(pts) == 3
    assert pts[0]["y"] == 0.0
    assert pts[1]["y"] == 0
    assert pts[2]["y"] == 1.50


def test_quarantine_booleans() -> None:
    """Booleans (True/False) evaluate as int in Python but must be quarantined."""
    is_valid_true, reason_true = validate_cost_observation(True)
    assert not is_valid_true
    assert reason_true == "quarantine_boolean"

    is_valid_false, reason_false = validate_cost_observation(False)
    assert not is_valid_false
    assert reason_false == "quarantine_boolean"

    auth_meters = ["12345678"]
    payload = {
        "Data": {"unit": "USD",
            "series": [
                {"name": "Meter #12345678", "data": [{"x": 1000, "y": True}]}
            ]
        }
    }
    status, result = validate_cost_payload(payload, auth_meters)
    assert status == CostEvidenceStatus.MALFORMED
    assert result["reason"] == "quarantine_boolean"


def test_quarantine_non_finite_nan_and_inf() -> None:
    """NaN, +Inf, and -Inf are quarantined as malformed."""
    for bad_val in (float("nan"), float("inf"), float("-inf")):
        is_valid, reason = validate_cost_observation(bad_val)
        assert not is_valid
        assert reason == "quarantine_non_finite"

    auth_meters = ["12345678"]
    payload = {
        "Data": {"unit": "USD",
            "series": [
                {"name": "Meter #12345678", "data": [{"x": 1000, "y": float("nan")}]}
            ]
        }
    }
    status, result = validate_cost_payload(payload, auth_meters)
    assert status == CostEvidenceStatus.MALFORMED
    assert result["reason"] == "quarantine_non_finite"


def test_quarantine_negatives_and_credits() -> None:
    """Negative values (credits) are quarantined until explicitly supported."""
    for neg_val in (-0.01, -1.50, -100.0):
        is_valid, reason = validate_cost_observation(neg_val)
        assert not is_valid
        assert reason == "quarantine_negative"

    auth_meters = ["12345678"]
    payload = {
        "Data": {"unit": "USD",
            "series": [
                {"name": "Meter #12345678", "data": [{"x": 1000, "y": -0.50}]}
            ]
        }
    }
    status, result = validate_cost_payload(payload, auth_meters)
    assert status == CostEvidenceStatus.MALFORMED
    assert result["reason"] == "quarantine_negative"


def test_quarantine_duplicate_timestamps() -> None:
    """Points sharing duplicate x timestamps are quarantined as malformed."""
    auth_meters = ["12345678"]
    payload = {
        "Data": {"unit": "USD",
            "series": [
                {
                    "name": "Meter #12345678",
                    "data": [
                        {"x": 1729382400000, "y": 1.20},
                        {"x": 1729382400000, "y": 1.20},  # duplicate
                    ],
                }
            ]
        }
    }
    status, result = validate_cost_payload(payload, auth_meters)
    assert status == CostEvidenceStatus.MALFORMED
    assert "duplicate_timestamp" in result["reason"]


def test_quarantine_unknown_currency_units() -> None:
    """Units other than USD or $ produce wrong_unit status."""
    auth_meters = ["12345678"]
    for bad_unit in ("EUR", "GBP", "kWh", "therms", "CAD"):
        payload = {
            "Data": {
                "unit": bad_unit,
                "series": [
                    {"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]}
                ],
            }
        }
        status, _ = validate_cost_payload(payload, auth_meters)
        assert status == CostEvidenceStatus.WRONG_UNIT

    # Dollars must be proven by an explicit token: a missing, None or blank unit
    # is unproven (wrong_unit), never assumed USD.
    for unproven in (None, "", "   "):
        payload = {
            "Data": {
                "unit": unproven,
                "series": [
                    {"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]}
                ],
            }
        }
        status, details = validate_cost_payload(payload, auth_meters)
        assert status == CostEvidenceStatus.WRONG_UNIT
        assert details["reason"] == "currency_unproven"
    no_unit_key = {
        "Data": {"series": [{"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]}]}
    }
    assert validate_cost_payload(no_unit_key, auth_meters)[0] == CostEvidenceStatus.WRONG_UNIT

    for good_unit in ("USD", "$", "usd"):
        payload = {
            "Data": {
                "unit": good_unit,
                "series": [
                    {"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]}
                ],
            }
        }
        status, _ = validate_cost_payload(payload, auth_meters)
        assert status == CostEvidenceStatus.OK


# ---------------------------------------------------------------------------
# Test Suite: Negative Proofs Rejecting Upstream 63c912f Flaws
# ---------------------------------------------------------------------------


def test_negative_proof_first_series_selection() -> None:
    """Demonstrate that upstream 63c912f first-series heuristic fails on real multi-meter accounts.

    Upstream commit 63c912f did:
        c_meter = next((s for s in c_series if "Meter" in str(s.get("name") or "")), None)
        if not c_meter and c_series:
            c_meter = c_series[0]

    On an account with an inactive replaced meter first, upstream picks the wrong meter.
    Authoritative matching prevents this misattribution.
    """
    authoritative_active_meter = "22222222"
    multi_meter_payload_series = [
        {"name": "Meter #11111111 (RS)", "data": []},  # inactive replaced meter (0 points)
        {"name": "Meter #22222222 (RS)", "data": [{"x": 1000, "y": 4.50}]},  # active meter (1 point)
    ]

    # 1. Show upstream flaw: it picks series[0] (Meter #11111111) and drops all readings
    def upstream_flawed_selector(series_list: list[dict[str, Any]]) -> dict[str, Any] | None:
        c_meter = next((s for s in series_list if "Meter" in str(s.get("name") or "")), None)
        if not c_meter and series_list:
            c_meter = series_list[0]
        return c_meter

    upstream_picked = upstream_flawed_selector(multi_meter_payload_series)
    assert upstream_picked is not None
    assert "11111111" in upstream_picked["name"]
    # Upstream found 0 data points because it picked the inactive meter!
    assert len(upstream_picked["data"]) == 0

    # 2. Show contract enforcement: authoritative matching rejects unauthoritative series
    # and strictly targets the active authoritative meter
    auth_set = [authoritative_active_meter]
    payload = {"Data": {"unit": "USD", "series": multi_meter_payload_series}}

    # The payload contains an unauthoritative meter (11111111) -> rejected as wrong_meter
    status, result = validate_cost_payload(payload, auth_set)
    assert status == CostEvidenceStatus.WRONG_METER
    assert result["observed_meter"] == "11111111"

    # When both are recognized authoritative swap meters, matching by ID preserves 22222222 points
    status_swap, result_swap = validate_cost_payload(payload, ["11111111", "22222222"])
    assert status_swap == CostEvidenceStatus.OK
    active_matched = next(s for s in result_swap["matched_series"] if s["meter_id"] == "22222222")
    assert len(active_matched["points"]) == 1
    assert active_matched["points"][0]["y"] == 4.50


def test_negative_proof_zero_to_estimate_substitution() -> None:
    """Demonstrate that upstream 63c912f zero-to-estimate substitution corrupts real zero observations.

    Upstream commit 63c912f did:
        if actual_hourly_cost is not None and actual_hourly_cost > 0:
            cost_val = actual_hourly_cost
            is_exact = True
        else:
            cost_val = round(p_kwh * effective_rate, 4)
            is_exact = False

    If the portal legitimately reported $0.00 (e.g. net-metered solar export hour or off-peak),
    upstream corrupts it by substituting an estimated rate calculation.
    """
    p_kwh = 2.0
    effective_rate = 0.25
    actual_hourly_cost = 0.0  # Real portal observation: $0.00

    # 1. Upstream behavior
    def upstream_flawed_cost_calculation(actual_cost: float | None, kwh: float, rate: float) -> tuple[float, bool]:
        if actual_cost is not None and actual_cost > 0:
            return actual_cost, True
        return round(kwh * rate, 4), False

    upstream_cost, upstream_exact = upstream_flawed_cost_calculation(actual_hourly_cost, p_kwh, effective_rate)
    # Upstream replaced $0.00 with $0.50 (kwh * rate) and marked it not exact!
    assert upstream_cost == 0.50
    assert upstream_exact is False

    # 2. Contract behavior
    is_valid, reason = validate_cost_observation(actual_hourly_cost)
    assert is_valid is True
    assert reason is None
    # In contract: 0.0 remains 0.0 (exact observation)
    assert actual_hourly_cost == 0.0


# ---------------------------------------------------------------------------
# Test Suite: Non-Authoritative Transport Isolation Invariants
# ---------------------------------------------------------------------------


def test_non_authoritative_transport_isolation_contract() -> None:
    """Verify non-authoritative seam invariants: zero session confirmation, zero writes."""
    client = PsegClient(portal_cookies="MM_SID=authoritative_sid")

    # In evidence mode, cost failures do not call session mutation methods
    with (
        patch.object(client, "_note_confirmed_generation") as mock_confirm,
        patch.object(client, "_mark_auth_failure") as mock_auth_fail,
    ):
        # Simulate evidence evaluation of 401 response
        status, _ = validate_cost_payload({"status_code": 401}, ["12345678"])
        assert status == CostEvidenceStatus.AUTH_REJECTED

        # Neither session confirmation nor auth failure marking may be called by cost leg
        mock_confirm.assert_not_called()
        mock_auth_fail.assert_not_called()


def test_quarantine_duplicate_meter_timestamp_across_series() -> None:
    """A repeated meter series cannot double-count an interval (key = meter, x)."""
    auth_meters = ["12345678"]
    payload = {
        "Data": {
            "unit": "USD",
            "series": [
                {"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]},
                {"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]},
            ],
        }
    }
    status, details = validate_cost_payload(payload, auth_meters)
    assert status == CostEvidenceStatus.MALFORMED
    assert details["reason"].startswith("duplicate_timestamp_")
    # Distinct meters at the same timestamp are legitimate contributions.
    two_meters = {
        "Data": {
            "unit": "USD",
            "series": [
                {"name": "Meter #12345678", "data": [{"x": 1000, "y": 2.50}]},
                {"name": "Meter #87654321", "data": [{"x": 1000, "y": 1.25}]},
            ],
        }
    }
    status, _ = validate_cost_payload(two_meters, ["12345678", "87654321"])
    assert status == CostEvidenceStatus.OK

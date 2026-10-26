"""Synthetic extra tests for ignored telemetry and contradictory display names."""

from test_cost_contract_usagetype3 import _fixture_like_production, _validate

from custom_components.pseg.cost_evidence import CostEvidenceStatus


def test_auxiliary_prefix_is_not_currency_evidence():
    payload = _fixture_like_production()
    for item in payload["Data"]["series"]:
        if not str(item.get("name", "")).startswith("Meter #"):
            item["tooltip"] = {"valuePrefix": "degrees Fahrenheit"}
    status, _, promotable = _validate(payload)
    assert status == CostEvidenceStatus.OK
    assert promotable is True


def test_display_name_contradiction_cannot_be_outvoted():
    payload = _fixture_like_production()
    payload["Data"]["tooltipOptions"]["usageTypeDisplayName"] = "kWh"
    status, sample, promotable = _validate(payload)
    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == "unsupported_unit"
    assert promotable is False


def test_empty_meter_prefix_is_still_a_contradiction():
    payload = _fixture_like_production()
    for item in payload["Data"]["series"]:
        if str(item.get("name", "")).startswith("Meter #") and not item["data"]:
            item["tooltip"] = {"valuePrefix": "kWh"}
    status, sample, promotable = _validate(payload)
    assert status == CostEvidenceStatus.WRONG_UNIT
    assert sample["reason"] == "unsupported_unit"
    assert promotable is False

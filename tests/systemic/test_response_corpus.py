"""P2-08: G3 corpus generator sweep (fast, slow and exhaustive nightly).

Fast tier
    Every stage/kind/cookie/position value is represented plus the mandatory
    findings: the 307/308 credential re-POST, the healthy hourly rotation, the
    auth-on-hourly versus non-auth daily-fallback controls, and one post-proof
    poison that only the follow-on can catch.

Slow tier
    The constrained pairwise HA/client cases from the checked-in covering.

Nightly tier
    The exhaustive applicable G3 declaration (stage x kind x cookie x position
    minus the explicit exclusions). It is collected and counted here; execution
    waits for P4 capacity.

The independent nightly count is computed from the declared product minus the
declared exclusions with a *different* arithmetic (per-stage products) from the
tuple enumeration used to build the parameters, so a silent exclusion change
cannot keep both sides in agreement.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant
import pytest

from tests.support.corpus import (
    Position,
    ResponseKind,
    Stage,
    build_kind_reply,
    get_expected_outcome,
)
from tests.systemic.response_cases import (
    ALL_CASES,
    FAST_CASES,
    SLOW_CASES,
    CaseEvidence,
    ResponseCase,
    night_case_params,
    run_case_evidence,
)

COVERING = Path(__file__).with_name("response_covering.json")
CORE_AXES = ("stage", "kind", "cookie", "position")


def _model() -> dict[str, Any]:
    return json.loads(COVERING.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Independent nightly derivation (no import of tools/pairwise.py)
# ---------------------------------------------------------------------------


def _scope_exclusions(model: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    return [
        exclusion
        for exclusion in model["exclusions"]
        if scope in exclusion.get("scope", ["pairwise", "nightly"])
    ]


def _matches(exclusion: dict[str, Any], values: dict[str, str]) -> bool:
    if exclusion["axis"] not in values:
        return False
    if values[exclusion["axis"]] not in {str(value) for value in exclusion["values"]}:
        return False
    for context_axis, context_values in exclusion.get("context", {}).items():
        if context_axis not in values:
            return False
        if values[context_axis] not in {str(value) for value in context_values}:
            return False
    return True


def _is_valid(values: dict[str, str], exclusions: list[dict[str, Any]]) -> bool:
    return not any(_matches(exclusion, values) for exclusion in exclusions)


def independent_nightly_tuples(model: dict[str, Any]) -> list[dict[str, str]]:
    """Enumerate the applicable G3 core tuples from domains and exclusions."""
    exclusions = _scope_exclusions(model, "nightly")
    axes = model["axes"]
    tuples: list[dict[str, str]] = []
    for stage, kind, cookie, position in itertools.product(
        axes["stage"], axes["kind"], axes["cookie"], axes["position"]
    ):
        values = {
            "stage": str(stage),
            "kind": str(kind),
            "cookie": str(cookie),
            "position": str(position),
        }
        if _is_valid(values, exclusions):
            tuples.append(values)
    return tuples


def _nightly_applicable_exclusions(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the exclusions that constrain the four nightly axes."""
    applicable: list[dict[str, Any]] = []
    coupled: set[frozenset[str]] = {
        frozenset({"kind"}),
        frozenset({"position"}),
        frozenset({"stage", "kind"}),
        frozenset({"stage", "position"}),
        frozenset({"kind", "cookie"}),
    }
    for exclusion in _scope_exclusions(model, "nightly"):
        axes = frozenset({exclusion["axis"], *exclusion.get("context", {})})
        if not axes <= set(CORE_AXES):
            # The rule talks about flow/event/family: not a nightly axis.
            continue
        assert axes in coupled, (
            f"nightly exclusion {axes} couples axes the per-stage product cannot "
            "express; the independent count must be extended explicitly"
        )
        assert exclusion["axis"] in axes - set(exclusion.get("context", {})), exclusion
        applicable.append(exclusion)
    return applicable


def independent_nightly_count(model: dict[str, Any]) -> int:
    """Count applicable G3 tuples as per-stage products minus the exclusions.

    The decomposition is exact because the declared nightly rules constrain only
    (kind), (position), (stage x kind), (stage x position) or (kind x cookie);
    no rule couples position with kind/cookie or stage with cookie.
    """
    exclusions = _nightly_applicable_exclusions(model)
    total = 0
    for stage in model["axes"]["stage"]:
        positions = [
            position
            for position in model["axes"]["position"]
            if _is_valid({"stage": str(stage), "position": str(position)}, exclusions)
        ]
        for kind in model["axes"]["kind"]:
            if not _is_valid({"stage": str(stage), "kind": str(kind)}, exclusions):
                continue
            cookies = [
                cookie
                for cookie in model["axes"]["cookie"]
                if _is_valid({"kind": str(kind), "cookie": str(cookie)}, exclusions)
            ]
            total += len(cookies) * len(positions)
    return total


MODEL = _model()
NIGHTLY_TUPLES = independent_nightly_tuples(MODEL)
NIGHTLY_CASES = night_case_params(NIGHTLY_TUPLES)
NIGHTLY_COUNT = independent_nightly_count(MODEL)


def _params(cases: tuple[ResponseCase, ...] | list[ResponseCase]) -> list[Any]:
    return [
        pytest.param(
            case,
            id=case.case_id,
            marks=pytest.mark.slow if case.tier == "slow" else (),
        )
        for case in cases
    ]


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock: Any, enable_custom_integrations: Any) -> Any:
    yield


# ---------------------------------------------------------------------------
# Executable tiers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", _params(FAST_CASES))
async def test_fast_case(
    case: ResponseCase,
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """A fast representative passes its family's assertions plus the follow-on."""
    evidence: CaseEvidence = await run_case_evidence(case, hass, caplog)
    assert evidence.reply_consumed
    assert evidence.follow_on_steps == (
        "ending_poll_1",
        "ending_poll_2",
        "ending_cold_restart",
        "ending_poll_3",
    )
    if case.quarantined:
        assert evidence.quarantined
    else:
        assert evidence.advanced


@pytest.mark.parametrize("case", _params(SLOW_CASES))
async def test_slow_case(
    case: ResponseCase,
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """Every constrained pairwise case passes its family's assertions."""
    evidence: CaseEvidence = await run_case_evidence(case, hass, caplog)
    assert evidence.reply_consumed
    assert evidence.follow_on_steps == (
        "ending_poll_1",
        "ending_poll_2",
        "ending_cold_restart",
        "ending_poll_3",
    )


@pytest.mark.nightly
@pytest.mark.parametrize("case", _params(NIGHTLY_CASES))
async def test_nightly_case(case: ResponseCase) -> None:
    """Exhaustive G3 declaration: collected now, executed at P4 capacity."""
    pytest.skip("nightly execution waits for P4 capacity")


# ---------------------------------------------------------------------------
# Tier and inventory meta-tests
# ---------------------------------------------------------------------------


def test_tiers_are_nonempty_and_unique() -> None:
    """Client and HA tiers are both represented, with unique case ids."""
    assert FAST_CASES and SLOW_CASES
    assert {case.family for case in ALL_CASES} == {"client", "ha"}
    assert {case.family for case in FAST_CASES} == {"client", "ha"}
    assert len({case.case_id for case in ALL_CASES}) == len(ALL_CASES)


def test_fast_tier_represents_every_kind_stage_cookie_position() -> None:
    """Fast covers the entire core G3 vocabulary at least once."""
    model = _model()
    model_only = {f"{entry['axis']}={entry['value']}" for entry in model["model_only"]}
    fast = {f"{axis}={getattr(case, axis)}" for case in FAST_CASES for axis in CORE_AXES}
    required = {f"{axis}={value}" for axis in CORE_AXES for value in model["axes"][axis]}
    assert required <= fast | model_only


def test_root_200_cases_are_executable_at_json_stages() -> None:
    """Root-200 kinds only appear where the typed parser actually runs."""
    for case in ALL_CASES:
        if case.kind in {
            ResponseKind.ROOT_ARRAY,
            ResponseKind.ROOT_STRING,
            ResponseKind.ROOT_NULL,
            ResponseKind.ROOT_NUMBER,
            ResponseKind.TRUNCATED_JSON,
        }:
            assert case.stage in {
                Stage.DAILY_CHART_DATA,
                Stage.HOURLY_CHART_DATA,
                Stage.HISTORY_CHUNK,
            }, case.case_id


def test_nightly_collection_count_equals_independent_calculation() -> None:
    """Collected nightly cases equal product minus explicit exclusions."""
    assert len(NIGHTLY_CASES) == NIGHTLY_COUNT
    assert len(NIGHTLY_CASES) == len(NIGHTLY_TUPLES)
    assert len({case.case_id for case in NIGHTLY_CASES}) == len(NIGHTLY_CASES)
    assert NIGHTLY_COUNT == 724
    # Every core value appears in the exhaustive declaration, including the
    # model-only security-step kind.
    nightly_values = {
        f"{axis}={getattr(case, axis)}" for case in NIGHTLY_CASES for axis in CORE_AXES
    }
    required = {f"{axis}={value}" for axis in CORE_AXES for value in MODEL["axes"][axis]}
    assert required <= nightly_values


def test_security_step_fixture_is_declared_model_only() -> None:
    """Document the P2-03 security-step fixture gap instead of hiding it.

    The builder is an HTML page; production classifies the terminal security step
    from the login POST's JSON Data (pseg_client.py:1141-1145). The corpus still
    declares the kind terminal, so it is probed at model level and stays in the
    exhaustive nightly declaration.
    """
    reply = build_kind_reply(ResponseKind.SECURITY_STEP, Stage.LOGIN_FORM_GET)
    outcome = get_expected_outcome("kinds", ResponseKind.SECURITY_STEP)
    assert reply.valid is False and reply.cookie_eligible is False
    assert reply.metadata.get("is_terminal") is True
    assert outcome.is_terminal is True
    model = _model()
    probes = {(entry["axis"], entry["value"]) for entry in model.get("model_only", [])}
    assert ("kind", ResponseKind.SECURITY_STEP) in probes
    assert not any(case.kind == ResponseKind.SECURITY_STEP for case in ALL_CASES)
    assert any(case.kind == ResponseKind.SECURITY_STEP for case in NIGHTLY_CASES)


def test_every_exclusion_declares_a_reason() -> None:
    """Applicability rules are declared data, each with its reason."""
    model = _model()
    for exclusion in model["exclusions"]:
        assert exclusion["reason"].strip(), exclusion
        assert exclusion["values"]
    for entry in model.get("model_only", []):
        assert entry["reason"].strip()


# ---------------------------------------------------------------------------
# Mandatory findings (named proofs)
# ---------------------------------------------------------------------------


def _mandatory(case_id: str) -> ResponseCase:
    for case in ALL_CASES:
        if case.case_id == case_id:
            return case
    raise AssertionError(f"mandatory case missing from the covering: {case_id}")


async def test_mandatory_307_and_308_repost_the_credential_body(
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """307/308 keep the POST method and the exact credential body digest."""
    for case_id in ("mandatory:307-credential-repost", "mandatory:308-credential-repost"):
        case = _mandatory(case_id)
        assert case.tier == "fast"
        evidence = await run_case_evidence(case, hass, caplog)
        assert "credential_repost" in evidence.notes, evidence.notes


async def test_mandatory_healthy_hourly_rotation_advances_the_checkpoint(
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """A validated hourly rotation is persisted as the latest checkpoint."""
    case = _mandatory("mandatory:healthy-hourly-rotation")
    evidence = await run_case_evidence(case, hass, caplog)
    assert evidence.advanced is True
    assert evidence.quarantined is False


async def test_mandatory_auth_on_hourly_is_not_a_daily_fallback(
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """A 401 on the hourly leg is typed auth loss, not a successful daily fallback."""
    case = _mandatory("mandatory:auth-on-hourly-is-auth-loss")
    evidence = await run_case_evidence(case, hass, caplog)
    assert "auth_loss" in evidence.notes, evidence.notes
    assert "daily_fallback" not in evidence.notes
    assert "i12" in evidence.notes, evidence.notes


async def test_mandatory_non_auth_hourly_falls_back_to_daily(
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """A non-auth hourly failure still delivers the defined daily fallback."""
    case = _mandatory("mandatory:non-auth-hourly-daily-fallback")
    evidence = await run_case_evidence(case, hass, caplog)
    assert "daily_fallback" in evidence.notes, evidence.notes
    assert "auth_loss" not in evidence.notes


async def test_post_proof_poison_is_caught_only_by_the_follow_on(
    hass: HomeAssistant,
    caplog: Any,
) -> None:
    """The last leg of the call leaves no next request; only the follow-on sees it.

    The declared reply is the optional post-proof hourly read, so the case body
    records no later request at all. A production mutant that keeps the failed
    reply's cookie is therefore invisible to the body and surfaces only in the
    handed-off HA runtime (warm poll or cold restart).
    """
    case = _mandatory("mandatory:post-proof-poison-only-follow-on")
    assert case.position == Position.POST_PROOF
    assert case.quarantined is True
    evidence = await run_case_evidence(case, hass, caplog)
    assert evidence.later_dispatches == 0, (
        "the post-proof poison case must not have a later request inside the case body"
    )
    assert "follow_on_only" in evidence.notes, evidence.notes

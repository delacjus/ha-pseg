"""Gate B generator regressions: F1 whole-jar derivation, F2 terminal fence, F3 fast retention.

Review ``pseg-suite-gb-generators-review-r1-20261027`` found three no-weakening
defects in the B3/B4 generator fix:

F1 (major)
    ``run_ha_case`` treated any observed jar difference as a declared renewal
    rotation and then adopted the observed jar as the expectation, so a production
    fault that clears the persisted cookies passed. The runner now derives the
    latest whole jar and settled admission from the pre-operation baseline and each
    *declared* reply through the pure expectation model, and asserts that pair.
    ``test_deletion_of_persisted_cookies_is_rejected`` is the reviewer's own
    counterexample: it must FAIL if the derivation is removed. Review-r2 closed the
    admission half: the declared admission is compared exactly (an empty ``{}``
    means empty persistence, a nullable field must be present as null), and the
    authorized successor's settlement comes from its own declared healthy replies.
    ``test_undeclared_fresh_admission_is_rejected`` and
    ``test_settled_admission_must_keep_its_nullable_fields`` are the two r2
    counterexamples; ``test_declared_settled_admission_passes_exactly`` is the
    positive control.
F2 (major)
    The terminal latch fence listed ``LOGIN_FORM_GET`` and ``SAML_ACS`` but not the
    new ``LOGIN_POST`` stage, so a terminal state accepted a credential POST, its
    reply and its cookies. ``test_terminal_fence_covers_the_credential_post`` is the
    negative regression with honest GET/ACS controls.
F3 (minor)
    Re-running tier assignment dropped 15 unrelated former fast rows and demoted one
    more. ``test_former_fast_rows_stay_fast`` pins the restored membership.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant
import pytest

from custom_components.pseg.const import CONF_RENEWAL_ADMISSION, PORTAL_BASE_URL
from tests.support.corpus import FlowMode, Position, ResponseKind, Stage, build_stage_reply
from tests.support.expectation import ExpectationState, apply_step
from tests.support.flows import FlowStep
from tests.support.portal import Dispatch
from tests.systemic import response_cases as rc
from tests.systemic.coverage_data import MANDATORY_FAST
from tests.systemic.findings import GENERATOR_FIX_CLOSURES
from tools import pairwise

COVERING = Path(__file__).with_name("response_covering.json")
PORTAL = PORTAL_BASE_URL

#: The exact former fast rows the B3 login-stage relabel must not drop (F3). The one
#: other removed row, ``login_form_get::captcha::none::post_proof::L::poll::client``,
#: is a login-stage row the B3 applicability rule now excludes with a declared reason.
FORMER_FAST_ROWS = (
    "daily_chart_data::maintenance::none::post_proof::S::setup::ha",
    "daily_chart_data::missing_token::aux::post_proof::R::setup::ha",
    "daily_chart_data::root_number::remember_me::post_proof::H::poll::client",
    "dashboard_verify_token::403::aux::post_proof::L::keepalive::ha",
    "dashboard_verify_token::429::none::pre_proof::H::backfill::ha",
    "dashboard_verify_token::all_invalid::remember_me::pre_proof::R::setup::ha",
    "dashboard_verify_token::empty::aux::pre_proof::L::poll::client",
    "history_chunk::root_null::remember_me::post_proof::L::backfill::client",
    "history_chunk::truncated_json::sid::post_proof::R::backfill::client",
    "history_chunk::unrelated::aux::post_proof::S::backfill::ha",
    "hourly_chart::302_login::none::post_proof::R::setup::ha",
    "hourly_chart::404::aux::optional::H::setup::client",
    "hourly_chart_data::root_array::remember_me::optional::R::poll::client",
    "hourly_chart_data::root_string::none::post_proof::S::setup::client",
    "login_form_get::connection_error::remember_me::pre_proof::L::poll::ha",
    "saml_acs::timeout::aux::pre_proof::S::poll::ha",
)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock: Any, enable_custom_integrations: Any) -> Any:
    yield


def _case(case_id: str) -> rc.ResponseCase:
    for case in rc.ALL_CASES:
        if case.case_id == case_id:
            return case
    raise AssertionError(f"case missing from the covering: {case_id}")


def _dispatch(sequence: int, method: str, url: str, reply_id: str | None) -> Dispatch:
    return Dispatch(
        generation_id="derived:expected",
        sequence=sequence,
        method=method,
        url=url,
        reply_id=reply_id,
    )


# ---------------------------------------------------------------------------
# F1: the latest whole jar and admission are derived, never adopted
# ---------------------------------------------------------------------------


def test_declared_rotation_advances_the_derived_jar() -> None:
    """A declared, validated, eligible proof is the only thing that may move the jar."""
    case = _case("mandatory:healthy-hourly-rotation")
    dashboard = build_stage_reply(Stage.DASHBOARD_VERIFY_TOKEN)
    daily = build_stage_reply(Stage.DAILY_CHART_DATA)
    baseline = {"MM_SID": "SYNTH_BASELINE_SID"}
    declared = {dashboard.reply_id: dashboard, daily.reply_id: daily}

    jar, admission = rc._expected_checkpoint(
        case,
        baseline,
        {},
        declared,
        daily,
        (
            _dispatch(1, "GET", f"{PORTAL}/Dashboard", dashboard.reply_id),
            _dispatch(2, "GET", f"{PORTAL}/Dashboard/ChartData", daily.reply_id),
        ),
    )

    assert jar == {**baseline, **dashboard.cookies, **daily.cookies}
    assert jar != baseline, "a declared rotation must advance the derived whole jar"
    assert admission["sequences"] == 0
    assert admission["terminal_reason"] is None


def test_no_declared_proof_keeps_the_baseline_jar() -> None:
    """Without a declared confirming reply the derivation cannot invent a rotation."""
    case = _case("mandatory:healthy-hourly-rotation")
    dashboard = build_stage_reply(Stage.DASHBOARD_VERIFY_TOKEN)
    failed_daily = dataclasses.replace(
        build_stage_reply(Stage.DAILY_CHART_DATA, valid=False),
        cookies={"MM_SID": "SYNTH_POISON_SID"},
    )
    baseline = {"MM_SID": "SYNTH_BASELINE_SID"}
    declared = {dashboard.reply_id: dashboard, failed_daily.reply_id: failed_daily}

    jar, admission = rc._expected_checkpoint(
        case,
        baseline,
        {},
        declared,
        failed_daily,
        (
            _dispatch(1, "GET", f"{PORTAL}/Dashboard", dashboard.reply_id),
            _dispatch(2, "GET", f"{PORTAL}/Dashboard/ChartData", failed_daily.reply_id),
        ),
    )

    assert jar == baseline, "an invalid reply may not move the persisted jar"
    assert admission == {
        "sequences": 0,
        "last_sequence_at": None,
        "terminal_reason": None,
        "retry_eligible": False,
    }


async def test_deletion_of_persisted_cookies_is_rejected(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F1: the reviewer's counterexample - clearing the persisted jar must fail.

    Same fault as review-r1: a real case runs, then the physical
    ``entry.data["cookies"]`` is emptied before the exit snapshot. The old runner
    read that difference as a legitimate rotation and adopted the empty jar as its
    own expectation, so it passed. The derived whole jar cannot move without a
    declared eligible reply, so this must raise.
    """
    original_operation = rc._run_ha_operation
    corrupted: list[list[dict[str, Any]]] = []

    async def corrupt(driver: rc.LifecycleDriver, event: str) -> Any:
        result = await original_operation(driver, event)
        previous = list(driver.entry.data["cookies"])
        assert previous, "the case must start with a real persisted jar"
        driver.hass.config_entries.async_update_entry(
            driver.entry, data={**driver.entry.data, "cookies": []}
        )
        corrupted.append(previous)
        return result

    monkeypatch.setattr(rc, "_run_ha_operation", corrupt)
    case = rc.ResponseCase(
        case_id="regression:deleted-persisted-jar",
        stage=Stage.DAILY_CHART_DATA,
        kind=ResponseKind.HTTP_500,
        cookie="none",
        position=Position.POST_PROOF,
        flow=FlowMode.L,
        event="poll",
        family="ha",
        tier="slow",
    )

    with pytest.raises(AssertionError, match="latest whole jar"):
        await rc.run_ha_case(case, hass)

    assert corrupted, "the deletion fault never ran; the probe would be vacuous"


async def test_declared_rotation_case_still_passes(hass: HomeAssistant) -> None:
    """F1 positive control: the checked-in declared rotation passes end to end."""
    case = _case("mandatory:healthy-hourly-rotation")
    evidence = await rc.run_case_evidence(case, hass)
    assert evidence.quarantined is False
    assert evidence.advanced is True
    assert evidence.follow_on_steps == (
        "ending_poll_1",
        "ending_poll_2",
        "ending_cold_restart",
        "ending_poll_3",
    )


def test_terminal_admission_reason_is_declared_for_the_durable_pair() -> None:
    """The declared terminal kind owns the durable reason the derived pair expects."""
    case = _case("login_post::captcha::none::post_proof::L::poll::ha")
    assert case.is_terminal
    assert rc.TERMINAL_ADMISSION_REASONS[case.kind] == "captcha_required"


async def test_undeclared_fresh_admission_is_rejected(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F1 admission half: a never-settled ``{}`` may not persist any field.

    Review-r2 counterexample: after a failed fresh setup whose declared admission is
    ``{}``, the durable admission was rewritten to ``sequences=1`` plus a timestamp
    and the runner still completed all four ending steps. The frozen oracle's I5
    loop iterates expected keys only, so ``{}`` checked nothing; the runner now
    compares the exact declared mapping.
    """
    original_setup = rc.LifecycleDriver.setup
    corrupted: list[dict[str, Any]] = []

    async def corrupt(driver: rc.LifecycleDriver) -> Any:
        result = await original_setup(driver)
        admission = dict(driver.entry.data.get(CONF_RENEWAL_ADMISSION) or {})
        assert admission == {}, f"the case must start never-settled: {admission}"
        wrong = {
            "sequences": 1,
            "last_sequence_at": 1729382400.0,
            "terminal_reason": None,
            "retry_eligible": False,
        }
        driver.hass.config_entries.async_update_entry(
            driver.entry,
            data={**driver.entry.data, CONF_RENEWAL_ADMISSION: wrong},
        )
        corrupted.append(wrong)
        return result

    monkeypatch.setattr(rc.LifecycleDriver, "setup", corrupt)
    case = _case("dashboard_verify_token::all_invalid::remember_me::pre_proof::R::setup::ha")

    with pytest.raises(AssertionError, match="durable admission"):
        await rc.run_ha_case(case, hass)

    assert corrupted, "the admission fault never ran; the probe would be vacuous"


async def test_settled_admission_must_keep_its_nullable_fields(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F1 admission half: an absent nullable field is not the same as ``None``.

    Review-r2 counterexample: dropping ``last_sequence_at`` and ``terminal_reason``
    from a settled admission still passed, because the frozen I5 used ``.get()``.
    The exact declared comparison treats presence and value as one fact.
    """
    original_operation = rc._run_ha_operation
    corrupted: list[dict[str, Any]] = []

    async def corrupt(driver: rc.LifecycleDriver, event: str) -> Any:
        result = await original_operation(driver, event)
        admission = dict(driver.entry.data[CONF_RENEWAL_ADMISSION])
        assert admission["last_sequence_at"] is None, admission
        assert admission["terminal_reason"] is None, admission
        del admission["last_sequence_at"]
        del admission["terminal_reason"]
        driver.hass.config_entries.async_update_entry(
            driver.entry,
            data={**driver.entry.data, CONF_RENEWAL_ADMISSION: admission},
        )
        corrupted.append(admission)
        return result

    monkeypatch.setattr(rc, "_run_ha_operation", corrupt)
    case = _case("daily_chart_data::root_null::sid::post_proof::L::poll::ha")

    with pytest.raises(AssertionError, match="durable admission"):
        await rc.run_ha_case(case, hass)

    assert corrupted, "the admission fault never ran; the probe would be vacuous"


async def test_declared_settled_admission_passes_exactly(hass: HomeAssistant) -> None:
    """F1 positive control: the genuinely declared settled admission passes."""
    case = _case("daily_chart_data::root_null::sid::post_proof::L::poll::ha")

    evidence = await rc.run_case_evidence(case, hass)

    assert evidence.follow_on_steps == (
        "ending_poll_1",
        "ending_poll_2",
        "ending_cold_restart",
        "ending_poll_3",
    )


# ---------------------------------------------------------------------------
# F2: the terminal latch fences the credential POST stage
# ---------------------------------------------------------------------------


def _terminal_state() -> ExpectationState:
    return ExpectationState(generation_id="fence", is_terminal=True)


@pytest.mark.parametrize(
    "stage",
    [Stage.LOGIN_POST, Stage.LOGIN_FORM_GET, Stage.SAML_ACS],
)
def test_terminal_fence_covers_the_credential_post(stage: str) -> None:
    """F2: a terminal state refuses every declared sign-in request and its cookies."""
    reply = build_stage_reply(stage)
    assert reply.cookies, "the control must declare cookies or accumulation is unprovable"

    after = apply_step(_terminal_state(), FlowStep(stage=stage, reply=reply))

    assert any("credential_post_while_terminal" in event for event in after.history_events), (
        f"{stage}: a terminal state accepted a sign-in request: {after.history_events}"
    )
    assert after.validated_reply_ids == ()
    assert dict(after.pending_session_jar) == {}
    assert after.pending_renewal_expectation == "blocked_terminal_human_rearm_required"


def test_non_terminal_credential_post_still_validates() -> None:
    """F2 control: the fence must stay specific to the terminal latch."""
    reply = build_stage_reply(Stage.LOGIN_POST)

    after = apply_step(
        ExpectationState(generation_id="fence"),
        FlowStep(stage=Stage.LOGIN_POST, reply=reply),
    )

    assert not any("credential_post_while_terminal" in event for event in after.history_events)
    assert after.validated_reply_ids == (reply.reply_id,)
    assert dict(after.pending_session_jar) == dict(reply.cookies)


# ---------------------------------------------------------------------------
# F3: former fast rows stay fast
# ---------------------------------------------------------------------------


def _model() -> dict[str, Any]:
    import json

    return json.loads(COVERING.read_text(encoding="utf-8"))


def test_former_fast_rows_stay_fast() -> None:
    """F3: reselection may not drop the reviewed fast membership."""
    model = _model()
    rows = {row["id"]: row for row in model["rows"]}
    fast = {row["id"] for row in model["rows"] if row["tier"] == "fast"}
    pinned = {entry["id"] for entry in pairwise.pinned_rows()}

    missing = [case_id for case_id in FORMER_FAST_ROWS if case_id not in rows]
    assert not missing, f"former fast rows removed from the covering: {missing}"
    demoted = [case_id for case_id in FORMER_FAST_ROWS if case_id not in fast]
    assert not demoted, f"former fast rows are no longer fast: {demoted}"
    unpinned = [case_id for case_id in FORMER_FAST_ROWS if case_id not in pinned]
    assert not unpinned, f"former fast rows are not pinned against reselection: {unpinned}"
    nodes = set(MANDATORY_FAST)
    unrequired = [
        f"tests/systemic/test_response_corpus.py::test_fast_case[{case_id}]"
        for case_id in FORMER_FAST_ROWS
        if f"tests/systemic/test_response_corpus.py::test_fast_case[{case_id}]" not in nodes
    ]
    assert not unrequired, f"former fast rows are not mandatory fast nodes: {unrequired}"
    assert pairwise.check_file(COVERING) == []


def test_fast_tier_still_represents_the_core_vocabulary() -> None:
    """F3: retaining the old rows did not become a tier-only gesture."""
    model = _model()
    fast_values = {
        f"{axis}={row[axis]}"
        for row in model["rows"]
        if row["tier"] == "fast"
        for axis in ("stage", "kind", "cookie", "position")
    }
    model_only = {f"{entry['axis']}={entry['value']}" for entry in model.get("model_only", [])}
    required = {
        f"{axis}={value}"
        for axis in ("stage", "kind", "cookie", "position")
        for value in model["axes"][axis]
    }
    assert required <= fast_values | model_only


def test_generator_fix_registry_names_these_regressions() -> None:
    """F1/F2/F3 closures resolve to callable nodes in this module."""
    closures = {closure["id"]: closure for closure in GENERATOR_FIX_CLOSURES}
    assert set(closures) == {"F1", "F2", "F3"}
    for closure in GENERATOR_FIX_CLOSURES:
        assert closure["reason"].strip() and closure["closure"].strip()
        assert closure["cases"], closure["id"]
        for node in closure["cases"]:
            module, _, function = node.partition("::")
            assert module == "tests/systemic/test_gate_b_generator_regressions.py", node
            assert "[" not in function, node
            assert callable(globals().get(function)), f"missing closure node: {node}"


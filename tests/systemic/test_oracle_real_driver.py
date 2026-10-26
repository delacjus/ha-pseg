"""Real-driver validation tests and acceptance gate for systemic Oracle (I1-I12).

Executes real LifecycleDriver + ScriptedPortal traces across all 11 production
failure scenarios, verifying that healthy controls run completely clean (0 violations)
with mandatory run_case ending, and that production mutations trigger their exact
expected invariant codes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from types import MappingProxyType
from typing import Any

from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)

from custom_components.pseg.const import (
    PORTAL_BASE_URL,
)
from custom_components.pseg.pseg_client import PsegError
from tests.support.expectation import Checkpoint, ExpectationState
from tests.support.factory import ClientFactory, ClientRegistry
from tests.support.lifecycle import LifecycleDriver, run_case, script_healthy_portal
from tests.support.oracle import Oracle
from tests.support.portal import Reply, ScriptedPortal
from tests.systemic.test_lifecycle_driver import _create_test_entry

SCENARIOS: list[str] = [
    "retired_send",
    "poison_next",
    "unvalidated_persist",
    "latest_checkpoint",
    "dead_schedule",
    "missing_reauth",
    "untyped",
    "privacy",
    "journal_clear",
    "rows_consumption",
    "rows_cost",
]

INTENDED_CODES: dict[str, str] = {
    "retired_send": "I1",
    "poison_next": "I3",
    "unvalidated_persist": "I4",
    "latest_checkpoint": "I5",
    "dead_schedule": "I9",
    "missing_reauth": "I9",
    "untyped": "I10",
    "privacy": "I11",
    "journal_clear": "I12",
    "rows_consumption": "I12",
    "rows_cost": "I12",
}


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock: Any, enable_custom_integrations: Any) -> Any:
    yield


def healthy(portal: ScriptedPortal) -> None:
    with portal._lock:
        portal._scripts.clear()
    script_healthy_portal(portal)


def replace_reply(portal: ScriptedPortal, route: tuple[str, str], reply: Reply) -> None:
    with portal._lock:
        portal._scripts.pop(portal._normalize_route_key(route), None)
    portal.script(route, reply)


async def physical_rows(hass: HomeAssistant) -> dict[str, list[tuple[Any, Any, Any]]]:
    await async_wait_recording_done(hass)
    ids = {f"pseg:12345678_energy_{suffix}" for suffix in ("consumption", "cost")}
    result = await hass.async_add_executor_job(
        statistics_during_period,
        hass,
        datetime(2020, 1, 1, tzinfo=UTC),
        None,
        ids,
        "hour",
        None,
        {"sum", "state"},
    )
    return {
        key: [(r["start"], r.get("state"), r.get("sum")) for r in result.get(key, [])]
        for key in sorted(ids)
    }


async def run_scenario_probe(
    hass: HomeAssistant,
    freezer: Any,
    caplog: Any,
    scenario: str,
    active: bool = False,
) -> dict[str, Any]:
    """Execute a single scenario probe using real LifecycleDriver + ScriptedPortal."""
    portal = ScriptedPortal()
    healthy(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory, freezer=freezer)
    state = ExpectationState(
        generation_id="gen_001",
        latest_checkpoint=Checkpoint(
            "gen_001",
            0,
            MappingProxyType({"MM_SID": "SYNTH_TEST_PORTAL"}),
            MappingProxyType({}),
            0,
        ),
    )
    oracle = Oracle(expectation_state=state)
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    driver.attach_caplog(caplog)
    oracle.attach_caplog(caplog)
    oracle.register_eligible_cookie("MM_SID", "SYNTH_TEST_PORTAL")

    facts: dict[str, Any] = {}
    extra: list[str] = []

    with factory:
        assert await driver.setup()
        driver.observe_checkpoint("setup", await driver.snapshot())
        await driver.poll()
        driver.observe_checkpoint("healthy_poll", await driver.snapshot())
        before = await driver.snapshot()
        db_before = await physical_rows(hass)

        if scenario == "retired_send":
            old_client = driver.client
            assert old_client is not None
            old_gen = old_client.generation_id
            assert await driver.reload()
            prior = len(portal.dispatches)
            try:
                await hass.async_add_executor_job(old_client.ensure_session)
            except PsegError:
                pass
            bad = any(d.generation_id == old_gen for d in portal.dispatches[prior:])
            facts = {"retired_client_sent": bad, "portal_retired": portal.is_retired(old_gen)}
        elif scenario == "dead_schedule":
            prior = len(portal.dispatches)
            await driver.advance(timedelta(minutes=3))
            bad = len(portal.dispatches) == prior
            facts = {"timer_dispatches": len(portal.dispatches) - prior}
        elif scenario == "latest_checkpoint":
            rotated = Reply.ok(
                body='<html><input name="__RequestVerificationToken" value="SYNTH_TOKEN"/>Dashboard</html>',
                cookies={"MM_SID": "SYNTH_LATEST"},
                reply_id="SYNTH_ROTATE_VALID",
            )
            replace_reply(portal, ("GET", f"{PORTAL_BASE_URL}/Dashboard"), rotated)
            oracle.register_eligible_cookie("MM_SID", "SYNTH_LATEST")
            oracle.expectation_state = ExpectationState(
                generation_id="gen_001",
                latest_checkpoint=Checkpoint(
                    "gen_001",
                    2,
                    MappingProxyType({"MM_SID": "SYNTH_LATEST"}),
                    MappingProxyType({}),
                    1,
                ),
            )
            await driver.poll()
            after = await driver.snapshot()
            driver.observe_checkpoint("rotation", after)
            jar_map = dict(
                (c["name"], c["value"])
                if isinstance(c, dict) or hasattr(c, "__getitem__")
                else (c.name, c.value)
                for c in after.persisted_jar
            )
            print("DEBUG jar_map:", jar_map)
            bad = jar_map.get("MM_SID") != "SYNTH_LATEST"
            facts = {"latest_lost": bad, "jar_map": jar_map}
            oracle.expectation_state = None
        else:
            if scenario == "journal_clear":
                assert driver.coordinator is not None
                await driver.coordinator._stats_state.async_load()
                await driver.coordinator._stats_state.async_begin(
                    {
                        "series": {
                            "pseg:12345678_energy_consumption": [
                                ["2026-01-01T00:00:00+00:00", 1, 1]
                            ],
                            "pseg:12345678_energy_cost": [
                                ["2026-01-01T00:00:00+00:00", 0.25, 0.25]
                            ],
                        },
                        "promoted": {},
                    }
                )
                before = await driver.snapshot()

            replace_reply(
                portal,
                ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
                Reply(
                    reply_id="SYNTH_AUTH_FAIL",
                    status_code=401,
                    body="refused",
                    cookies={"SYNTH_POISON": "SYNTH_POISON_VALUE"},
                    valid=False,
                    cookie_eligible=False,
                ),
            )
            await driver.poll()
            assert driver.coordinator is not None
            assert not driver.coordinator.last_update_success
            after = await driver.snapshot()
            driver.observe_checkpoint("failure", after)
            extra = [str(v.code) for v in oracle.evaluate_i12(before, after)]
            db_after = await physical_rows(hass)

            if scenario == "poison_next":
                healthy(portal)
                prior = len(portal.dispatches)
                await driver.poll()
                bad = any(
                    d.cookies.get("SYNTH_POISON") == "SYNTH_POISON_VALUE"
                    for d in portal.dispatches[prior:]
                )
                facts = {"next_request_poison": bad}
            elif scenario == "unvalidated_persist":
                bad = any(c.get("name") == "SYNTH_POISON" for c in after.persisted_jar)
                facts = {"unvalidated_persisted": bad}
            elif scenario == "journal_clear":
                bad = not driver.coordinator._stats_state.has_pending()
                facts = {
                    "pending_before": before.journal.get("pending_recovery"),
                    "pending_after": after.journal.get("pending_recovery"),
                    "journal_truthy": bool(after.journal),
                }
                driver.coordinator._stats_state._data["pending"] = {}
                driver.coordinator._stats_state._mark_dirty()
                await driver.coordinator._stats_state.async_wait_durable()
            elif scenario.startswith("rows_"):
                bad = db_before != db_after
                facts = {
                    "physical_counts_before": {k: len(v) for k, v in db_before.items()},
                    "physical_counts_after": {k: len(v) for k, v in db_after.items()},
                    "oracle_rows_equal": before.rows == after.rows,
                }
            elif scenario == "missing_reauth":
                bad = not after.flows and not after.issues
                facts = {"flows": len(after.flows), "issues": len(after.issues)}
            elif scenario == "untyped":
                bad = type(driver.coordinator.last_exception).__name__ == "ValueError"
                facts = {"last_exception": type(driver.coordinator.last_exception).__name__}
            elif scenario == "privacy":
                bad = "SYNTH_PRIVACY_SENTINEL" in caplog.text
                facts = {"caplog_sentinel": bad}
            else:
                raise AssertionError(scenario)

        codes_before_ending = [str(v.code) for v in oracle.violations]
        healthy(portal)
        result = await run_case(driver, oracle=oracle)
        result.assert_complete()
        assert result.success

        oracle_codes = sorted(
            set(codes_before_ending + [str(v.code) for v in oracle.violations] + extra)
        )
        intended = INTENDED_CODES[scenario]
        expected_steps = 6 if scenario in ("retired_send", "dead_schedule") else 7

        assert oracle.send_invocation_count == len(portal.dispatches)
        assert oracle.step_invocation_count == expected_steps
        assert (
            oracle.invocation_count == oracle.send_invocation_count + oracle.step_invocation_count
        )

        report = {
            "scenario": scenario,
            "active": active,
            "bad_behavior": bad,
            "intended_code": intended,
            "detected": intended in oracle_codes,
            "codes": oracle_codes,
            "manual_i12": extra,
            "sends": len(portal.dispatches),
            "send_observations": oracle.send_invocation_count,
            "steps": oracle.step_invocation_count,
            "ending": result.ending_steps,
            "facts": facts,
        }
        return report


@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_control_scenario_clean(
    hass: HomeAssistant,
    freezer: Any,
    caplog: Any,
    scenario: str,
) -> None:
    """Verify that each of the 11 healthy CONTROL scenarios runs clean with 0 violations."""
    report = await run_scenario_probe(hass, freezer, caplog, scenario, active=False)
    # The oracle is the primary detector: check its verdict before the
    # scenario's own ground-truth facts, so an oracle miss cannot be masked.
    assert not report["codes"], (
        f"Healthy control {scenario} had unexpected violations: {report['codes']}"
    )
    assert report["bad_behavior"] is False, (
        f"Healthy control {scenario} failed bad_behavior check: facts={report.get('facts')}"
    )


async def test_eligible_real_sso_produces_zero_i2_violations(hass: HomeAssistant) -> None:
    """Prove that real client.renew_sso() produces zero I2 violations."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)

    with factory:
        assert await driver.setup()
        await driver.poll()
        assert driver.client is not None
        assert await hass.async_add_executor_job(driver.client.renew_sso)
        assert not driver.client._in_keepalive
        assert not driver.client._renewal_admission.terminal_reason

        # Verify POST to /Acs occurred and was not a redirect hop
        posts = [d for d in portal.dispatches if d.method == "POST" and "/Acs" in d.url]
        assert len(posts) == 1
        assert not posts[0].is_redirect_hop

        # Assert ZERO I2 violations observed!
        i2_violations = [v for v in oracle.violations if v.code == "I2"]
        assert len(i2_violations) == 0, (
            f"Eligible real SSO had false I2 violations: {i2_violations}"
        )

        # Mandatory ending
        result = await run_case(driver, oracle=oracle)
        result.assert_complete()
        assert oracle.invocation_count == len(portal.dispatches) + 4
        assert oracle.step_invocation_count == 4


async def test_i6_rejects_shared_coordinator_and_requires_dispatches(hass: HomeAssistant) -> None:
    """Prove I6 enforces independent coordinator/client/session instances and requires .dispatches."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup()
        await driver.poll()

        alias = LifecycleDriver(hass, entry, portal, factory=factory)
        assert alias.coordinator is driver.coordinator

        # Shared coordinator must produce I6 violation
        v_shared = Oracle().evaluate_i6(driver, alias)
        assert any(v.code == "I6" and "shared coordinator" in v.message for v in v_shared)

        # Missing dispatches must produce I6 violation
        class StandaloneNoDispatches:
            coordinator = object()
            client = object()
            session = object()

        v_no_disp = Oracle().evaluate_i6(driver, StandaloneNoDispatches())
        assert any(v.code == "I6" and "dispatches" in v.message for v in v_no_disp)


async def test_persisted_store_divergence_caught_by_oracle(
    hass: HomeAssistant,
    hass_storage: Any,
) -> None:
    """Prove that tampering with the physical mock_storage is caught by I4 and I5."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle(
        expectation_state=ExpectationState(
            generation_id="gen_001",
            latest_checkpoint=Checkpoint(
                "gen_001",
                0,
                MappingProxyType({"MM_SID": "SYNTH_TEST_PORTAL"}),
                MappingProxyType({}),
                0,
            ),
        )
    )
    oracle.register_eligible_cookie("MM_SID", "SYNTH_TEST_PORTAL")

    with factory:
        assert await driver.setup()
        await driver.poll()

        # Tamper with physical store directly
        saved = hass_storage["core.config_entries"]["data"]["entries"]
        raw = next(x for x in saved if x["entry_id"] == entry.entry_id)
        raw["data"]["cookies"][0]["value"] = "SYNTH_BAD_STORE_VALUE"

        snap = await driver.snapshot()
        assert snap.persisted_jar[0]["value"] == "SYNTH_BAD_STORE_VALUE"

        v_i4 = oracle.evaluate_i4(snap)
        assert any(v.code == "I4" for v in v_i4)

        v_i5 = oracle.evaluate_i5(snap)
        assert any(v.code == "I5" for v in v_i5)


async def test_review_audit_probe(
    hass: HomeAssistant,
    freezer: Any,
    caplog: Any,
) -> None:
    """Replay probe entrypoint used by automated audit reproduction."""
    scenario = os.environ.get("PSEG_REVIEW_SCENARIO")
    if not scenario:
        pytest.skip("PSEG_REVIEW_SCENARIO not set; skipping audit probe invocation")
    active = os.environ.get("PSEG_REVIEW_ACTIVE") == "1"
    report = await run_scenario_probe(hass, freezer, caplog, scenario, active=active)
    print("AUDIT_RESULT " + json.dumps(report, sort_keys=True))
    assert report["bad_behavior"] == active, f"Activation/control failed for {scenario}"
    if not active:
        assert not report["codes"], f"Control {scenario} had violations: {report['codes']}"

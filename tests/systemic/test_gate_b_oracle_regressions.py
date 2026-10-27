"""Gate B B1/B6/B7 real-driver reproductions and nearby healthy controls.

B1: I7/I8 are derived from the real driver's observed renewal attempts and sends.
B6: unavailable recorder evidence is rejected, never read as an empty series.
B7: a failing case still attempts and records the mandatory ending and cleans up.
"""

import time
from typing import Any

from homeassistant.config_entries import ConfigEntryState
import pytest

from tests.support import lifecycle as lm
from tests.support.boundaries import (
    DASHBOARD_HTML,
    LOGIN_HTML,
    PORTAL_BASE_URL,
    FencePortal,
    create_flow_entry,
    install_auth_bounce,
    register_initial_jar,
    register_scripted_eligibility,
    replace_route,
    script_portal,
)
from tests.support.factory import ClientFactory, ClientRegistry
from tests.support.lifecycle import LifecycleDriver, run_case
from tests.support.oracle import Oracle
from tests.support.portal import Reply


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock, enable_custom_integrations):
    yield


def make(hass, flow="R", *, freezer=None):
    portal = FencePortal()
    script_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    driver = LifecycleDriver(
        hass, create_flow_entry(hass, flow), portal, factory=factory, freezer=freezer
    )
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    register_initial_jar(oracle, driver.entry)
    register_scripted_eligibility(oracle, portal)
    return driver, oracle, factory


def codes(oracle, code):
    return [violation for violation in oracle.violations if str(violation.code) == code]


async def test_live_i7(
    hass,
    monkeypatch,
):
    """Three real renewals in one Remember-Me generation report I7."""
    from custom_components.pseg.renewal_admission import RenewalAdmission

    driver, oracle, factory = make(hass)
    with factory:
        assert await driver.setup()
        monkeypatch.setattr(RenewalAdmission, "blocked_reason", lambda self, now: None)
        for _ in range(3):
            install_auth_bounce(driver.portal)
            await driver.poll()
            driver.observe_checkpoint("poll", await driver.snapshot())
        assert driver.client is not None
        assert driver.client._renewal_admission.sequences == 3
        assert len(driver.renewal_events) == 3
        violations = codes(oracle, "I7")
        print(
            "LIVE_I7",
            driver.client._renewal_admission.sequences,
            driver.client.sso_renewals,
            [violation.message for violation in violations],
        )
        assert violations, "three real renewals in one generation produced no I7"
        assert any("exceeded_2_sequences" in violation.message for violation in violations)
        # Every evaluated attempt came from a real recorded dispatch.
        for violation in violations:
            assert violation.facts["send_sequences"]
        await driver.unload()


async def test_live_i7_healthy_single_sequence(hass):
    """One real renewal is inside budget and repeated observation never re-counts it."""
    driver, oracle, factory = make(hass)
    with factory:
        assert await driver.setup()
        install_auth_bounce(driver.portal)
        await driver.poll()
        driver.observe_checkpoint("poll", await driver.snapshot())
        assert len(driver.renewal_events) == 1
        assert driver.renewal_events[0]["sends"]
        assert not codes(oracle, "I7")
        assert not codes(oracle, "I8")
        # A second checkpoint observes no new attempt, so no duplicate count.
        driver.observe_checkpoint("same_checkpoint", await driver.snapshot())
        assert not codes(oracle, "I7")
        await driver.unload()


@pytest.mark.parametrize(
    ("rotated", "elapsed", "expected"),
    [
        (False, 900, {"retry_without_transient_error", "retry_after_success_without_rotation"}),
        (True, 0, {"spacing_under_15_minutes"}),
        (True, 900, set()),
    ],
)
async def test_live_i7_rotation_and_spacing(hass, freezer, monkeypatch, rotated, elapsed, expected):
    """The driver clock times the 15-minute gap and rotation resets the generation."""
    from custom_components.pseg.renewal_admission import RenewalAdmission

    driver, oracle, factory = make(hass, freezer=freezer)
    with factory:
        assert await driver.setup()
        install_auth_bounce(driver.portal)
        if rotated:
            # Attach a declared rotation to the actual renewal Dashboard reply.
            route = ("GET", PORTAL_BASE_URL + "/Dashboard")
            with driver.portal._lock:
                bounce = driver.portal._scripts[driver.portal._normalize_route_key(route)][0]
            replace_route(
                driver.portal,
                route,
                [
                    bounce,
                    Reply.ok(
                        body=DASHBOARD_HTML,
                        headers={"Set-Cookie": "MM_RememberMe=SYNTH_ROTATED; Path=/; Secure"},
                        reply_id="gateb-rotation",
                    ),
                ],
            )
        await driver.poll()
        driver.observe_checkpoint("first", await driver.snapshot())
        assert not codes(oracle, "I7")
        freezer.tick(elapsed)
        monkeypatch.setattr(RenewalAdmission, "blocked_reason", lambda self, now: None)
        install_auth_bounce(driver.portal)
        await driver.poll()
        driver.observe_checkpoint("second", await driver.snapshot())
        violations = codes(oracle, "I7")
        actual = set(violations[-1].message.split(": ", 1)[1].split(", ")) if violations else set()
        assert actual == expected
        assert len(driver.renewal_events) == 2
        await driver.unload()


async def test_live_i7_transient_retry_across_cold_restart(hass, freezer):
    """A transient failure earns the one retry, and a cold restart keeps its generation."""
    driver, oracle, factory = make(hass, freezer=freezer)
    with factory:
        assert await driver.setup()
        install_auth_bounce(driver.portal)
        route = ("GET", PORTAL_BASE_URL + "/Dashboard")
        with driver.portal._lock:
            bounce = driver.portal._scripts[driver.portal._normalize_route_key(route)][0]
        replace_route(
            driver.portal,
            route,
            [
                bounce,
                Reply(
                    reply_id="gateb-transient", status_code=500, valid=False, cookie_eligible=False
                ),
            ],
        )
        await driver.poll()
        driver.observe_checkpoint("failure", await driver.snapshot())
        assert not driver.coordinator.last_update_success
        script_portal(driver.portal)
        freezer.tick(900)
        await driver.cold_restart()
        install_auth_bounce(driver.portal)
        await driver.poll()
        driver.observe_checkpoint("retry", await driver.snapshot())
        assert driver.coordinator.last_update_success
        assert len(driver.renewal_events) == 2
        assert (
            driver.renewal_events[0]["generation_id"] != driver.renewal_events[1]["generation_id"]
        )
        assert not codes(oracle, "I7")
        await driver.unload()


async def test_live_i7_success_with_intermediate_transient_earns_no_retry(hass, freezer, monkeypatch):
    """A sequence that ends successfully settles as success despite an intermediate 500.

    The whole observed sequence (401 -> ignored landing 500 -> Dashboard + identity
    chart) really succeeds, so a later forced renewal with an unchanged Remember-Me
    cookie is a retry after success without rotation and must report I7.
    """
    from custom_components.pseg.renewal_admission import RenewalAdmission

    driver, oracle, factory = make(hass, freezer=freezer)
    with factory:
        assert await driver.setup()
        replace_route(
            driver.portal,
            ("GET", PORTAL_BASE_URL + "/Dashboard"),
            [
                Reply.redirect(
                    location=PORTAL_BASE_URL + "/", status_code=302, reply_id="initial-auth-loss"
                ),
                Reply(
                    reply_id="renewal-login-page",
                    status_code=401,
                    valid=False,
                    cookie_eligible=False,
                ),
                Reply.ok(body=DASHBOARD_HTML, reply_id="renewal-final-success"),
            ],
        )
        replace_route(
            driver.portal,
            ("GET", PORTAL_BASE_URL + "/"),
            [
                Reply.ok(body=LOGIN_HTML, reply_id="initial-login-form"),
                Reply(
                    reply_id="ignored-landing-500",
                    status_code=500,
                    valid=False,
                    cookie_eligible=False,
                ),
            ],
        )
        try:
            await driver.poll()
            driver.observe_checkpoint("first", await driver.snapshot())
            assert driver.coordinator.last_update_success
            assert driver.client.sso_renewals == 1
            first = driver.renewal_events[0]
            first_sends = [
                (d.sequence, d.status_code, d.reply_id)
                for d in driver.portal.dispatches
                if d.sequence in first["sends"]
            ]
            assert any(status == 500 for _, status, _ in first_sends)
            # The whole sequence succeeded; the intermediate 500 did not settle it.
            assert first["settlement"] == "success"
            assert not codes(oracle, "I7")

            freezer.tick(900)
            monkeypatch.setattr(RenewalAdmission, "blocked_reason", lambda self, now: None)
            script_portal(driver.portal)
            install_auth_bounce(driver.portal)
            await driver.poll()
            driver.observe_checkpoint("second", await driver.snapshot())
            assert len(driver.renewal_events) == 2
            assert driver.renewal_events[1]["settlement"] == "success"
            violations = codes(oracle, "I7")
            print("SUCCESS_RETRY_I7", [violation.message for violation in violations])
            assert any(
                "retry_after_success_without_rotation" in violation.message
                for violation in violations
            ), "a successful sequence with an intermediate 500 earned a later retry"
            retry = [v for v in violations if "retry_after_success" in v.message]
            assert retry[0].facts["prior_error_transient"] is False
            await driver.unload()
        finally:
            if driver.entry.state is ConfigEntryState.LOADED:
                await driver.unload()


async def test_live_i8_terminal_sends(hass):
    """An automatic ACS send under a persisted terminal reason reports I8."""
    driver, oracle, factory = make(hass, "S")
    with factory:
        assert await driver.setup()
        before = await driver.snapshot()
        from custom_components.pseg.const import CONF_RENEWAL_ADMISSION

        admission = dict(before.renewal_admission)
        admission["terminal_reason"] = "captcha_required"
        hass.config_entries.async_update_entry(
            driver.entry, data={**driver.entry.data, CONF_RENEWAL_ADMISSION: admission}
        )
        terminal = await driver.snapshot()
        assert terminal.renewal_admission["terminal_reason"] == "captcha_required"
        assert not codes(oracle, "I8")
        start = len(driver.portal.dispatches)
        assert driver.client is not None
        await hass.async_add_executor_job(driver.client.renew_sso)
        automatic = [
            dispatch
            for dispatch in driver.portal.dispatches[start:]
            if dispatch.method == "POST" and "/Acs" in dispatch.url
        ]
        assert automatic, "the terminal probe produced no automatic ACS send"
        driver.observe_checkpoint("terminal_reload", terminal)
        violations = codes(oracle, "I8")
        print(
            "LIVE_I8",
            len(driver.portal.dispatches) - start,
            [violation.message for violation in violations],
        )
        assert violations, "an automatic ACS send under a terminal reason produced no I8"
        assert any(violation.facts["send_sequence"] for violation in violations)
        await driver.unload()


async def test_live_i8_terminal_history_survives_unhuman_disk_clear(hass):
    """Once observed, a terminal latch is oracle-owned and disk alone cannot clear it.

    The durable admission is physically cleared without any human rearm, then a real
    automatic ACS round trip runs. I8 must still fire from the oracle's independent
    per-entry terminal history, not from what is on disk at send time.
    """
    from custom_components.pseg.const import CONF_RENEWAL_ADMISSION

    driver, oracle, factory = make(hass, "S")
    with factory:
        assert await driver.setup()
        try:
            admission = dict(driver.entry.data[CONF_RENEWAL_ADMISSION])
            admission["terminal_reason"] = "captcha_required"
            hass.config_entries.async_update_entry(
                driver.entry, data={**driver.entry.data, CONF_RENEWAL_ADMISSION: admission}
            )
            terminal = await driver.snapshot()
            assert terminal.renewal_admission["terminal_reason"] == "captcha_required"
            driver.observe_checkpoint("terminal_persisted", terminal)
            assert not codes(oracle, "I8")

            # Seed the effect of an improper disk clear: no human rearm happened.
            cleared_admission = dict(driver.entry.data[CONF_RENEWAL_ADMISSION])
            cleared_admission["terminal_reason"] = None
            hass.config_entries.async_update_entry(
                driver.entry,
                data={**driver.entry.data, CONF_RENEWAL_ADMISSION: cleared_admission},
            )
            cleared = await driver.snapshot()
            assert not cleared.renewal_admission.get("terminal_reason")
            start = len(driver.portal.dispatches)
            assert driver.client is not None
            await hass.async_add_executor_job(driver.client.renew_sso)
            automatic = [
                dispatch
                for dispatch in driver.portal.dispatches[start:]
                if dispatch.method == "POST" and "/Acs" in dispatch.url
            ]
            assert automatic, "the erase probe produced no automatic ACS send"
            assert not any(send["human"] for send in driver.auth_sends)
            driver.observe_checkpoint("reload_escape", cleared)
            violations = codes(oracle, "I8")
            print("TERMINAL_ERASE_I8", [violation.message for violation in violations])
            assert violations, "previously observed terminal latch escaped without human rearm"
            assert all(
                violation.facts["terminal_from_history"] for violation in violations
            ), "I8 was derived from disk state instead of the independent terminal history"
            assert {violation.facts["terminal_reason"] for violation in violations} == {
                "captcha_required"
            }
        finally:
            if driver.entry.state is ConfigEntryState.LOADED:
                await driver.unload()


async def test_live_i8_human_rearm_sends_are_exempt(hass):
    """Human rearm sends are recorded as human and never reported as automatic I8."""
    driver, oracle, factory = make(hass, "R")
    with factory:
        assert await driver.setup()
        from custom_components.pseg.const import CONF_RENEWAL_ADMISSION

        admission = dict(driver.entry.data.get(CONF_RENEWAL_ADMISSION, {}))
        admission["terminal_reason"] = "captcha_required"
        hass.config_entries.async_update_entry(
            driver.entry, data={**driver.entry.data, CONF_RENEWAL_ADMISSION: admission}
        )
        script_portal(driver.portal)
        res = await driver.human_reauth(same_cookies=True)
        assert res.get("type") == "abort", res
        assert any(send["human"] for send in driver.auth_sends), (
            "the human rearm produced no observed sends to exempt"
        )
        driver.observe_checkpoint("human_rearm", await driver.snapshot())
        assert not codes(oracle, "I8")
        assert not codes(oracle, "I7")
        await driver.unload()


async def test_live_i8_human_rearm_stops_history_for_later_automatic_auth(hass):
    """A completed human rearm retires the latch for the automatic auth after it.

    An observed terminal latch, then a real successful human rearm, then a real
    automatic ACS round trip: the human flow's own buffered sends carry the old
    epoch and must not re-arm history, so the automatic sends of the new
    generation produce zero I8.
    """
    from custom_components.pseg.const import CONF_RENEWAL_ADMISSION

    driver, oracle, factory = make(hass, "R")
    with factory:
        assert await driver.setup()
        try:
            admission = dict(driver.entry.data[CONF_RENEWAL_ADMISSION])
            admission["terminal_reason"] = "captcha_required"
            hass.config_entries.async_update_entry(
                driver.entry, data={**driver.entry.data, CONF_RENEWAL_ADMISSION: admission}
            )
            driver.observe_checkpoint("terminal_persisted", await driver.snapshot())
            assert not codes(oracle, "I8")

            script_portal(driver.portal)
            result = await driver.human_reauth(same_cookies=True)
            assert result.get("reason") == "reauth_successful", result
            assert driver.human_epoch == 1
            driver.observe_checkpoint("human_rearmed", await driver.snapshot())
            assert not driver.entry.data[CONF_RENEWAL_ADMISSION]["terminal_reason"]

            start = len(driver.portal.dispatches)
            assert driver.client is not None
            await hass.async_add_executor_job(driver.client.renew_sso)
            automatic = [
                dispatch
                for dispatch in driver.portal.dispatches[start:]
                if dispatch.method == "POST" and "/Acs" in dispatch.url
            ]
            assert automatic, "the post-rearm control produced no automatic ACS send"
            assert not any(send["human"] for send in driver.auth_sends[start:])
            driver.observe_checkpoint("automatic_after_rearm", await driver.snapshot())
            violations = codes(oracle, "I8")
            print("POST_REARM_I8", [violation.message for violation in violations])
            assert not violations, (
                "a completed human rearm left terminal history latched for later automatic auth"
            )
        finally:
            if driver.entry.state is ConfigEntryState.LOADED:
                await driver.unload()


async def test_recorder_error_is_invalid(hass, monkeypatch):
    """A recorder read failure is explicitly unavailable evidence, and I12 refuses it."""
    driver, oracle, factory = make(hass, "L")
    with factory:
        assert await driver.setup()
        healthy = await driver.snapshot()
        assert healthy.recorder_error is None
        assert isinstance(healthy.rows, tuple)

        def broken(*a, **k):
            raise RuntimeError("Gate B recorder read failure")

        monkeypatch.setattr(lm, "statistics_during_period", broken)
        a = await driver.snapshot()
        b = await driver.snapshot()

        assert a.recorder_error == b.recorder_error == "RuntimeError"
        assert a.rows is b.rows is None
        with pytest.raises(AssertionError, match="INVALID I12: recorder observation unavailable"):
            oracle.evaluate_i12(a, b)
        with pytest.raises(AssertionError, match="INVALID I12"):
            driver.observe_checkpoint("poll", a)
        await driver.unload()


async def test_primary_error_attempts_ending_and_cleans_up(hass):
    """A failing body still runs all four ending steps, records them and unloads."""
    driver, oracle, factory = make(hass, "L")
    tags = []
    driver.add_observer(lambda d, tag, s=None: tags.append(tag))
    with factory:
        assert await driver.setup()

        async def fail(d):
            raise AssertionError("Gate B primary fault")

        prior = len(driver.portal.dispatches)
        with pytest.raises(AssertionError, match="Gate B primary fault"):
            await run_case(driver, fail, case_name="gateb-failure", oracle=oracle)
        print("FAILED_CASE", tags, len(driver.portal.dispatches) - prior, driver.entry.state)
        assert tags == [
            "ending_poll_1",
            "ending_poll_2",
            "ending_cold_restart",
            "ending_poll_3",
        ]
        assert driver.entry.state is ConfigEntryState.NOT_LOADED
        result = driver.last_case_result
        assert result is not None
        assert not result.success
        assert result.ending_steps == tags
        assert result.metadata["ending_completed"] == tags
        assert len(driver.portal.dispatches) > prior
        assert isinstance(result.primary_error, AssertionError)


async def test_primary_error_survives_ending_and_cleanup_errors(hass, monkeypatch):
    """Secondary ending/cleanup failures are noted; the primary error is preserved."""
    driver, oracle, factory = make(hass, "L")
    primary = AssertionError("primary body failure")
    with factory:
        assert await driver.setup()

        async def fail(d):
            raise primary

        async def bad_poll():
            raise RuntimeError("secondary poll failure")

        unload = driver.unload

        async def bad_cleanup():
            await unload()
            raise RuntimeError("secondary cleanup failure")

        monkeypatch.setattr(driver, "unload", bad_cleanup)
        monkeypatch.setattr(driver, "poll", bad_poll)
        with pytest.raises(AssertionError, match="primary body failure") as caught:
            await run_case(driver, fail, oracle=oracle)
        assert caught.value is primary
        result = driver.last_case_result
        assert result is not None
        assert result.primary_error is primary
        assert result.ending_steps == [
            "ending_poll_1",
            "ending_poll_2",
            "ending_cold_restart",
            "ending_poll_3",
        ]
        assert len(primary.__notes__) == 4
        assert all("secondary poll failure" in note for note in primary.__notes__[:3])
        assert "secondary cleanup failure" in primary.__notes__[3]
        assert result.metadata["secondary_errors"]
        assert driver.entry.state is ConfigEntryState.NOT_LOADED


async def test_run_case_rejects_unavailable_recorder_without_oracle(hass, monkeypatch):
    """run_case treats unavailable recorder evidence as INVALID even with no oracle."""
    driver, _, factory = make(hass, "L")
    with factory:
        assert await driver.setup()

        def broken(*args, **kwargs):
            raise RuntimeError("recorder unavailable")

        monkeypatch.setattr(lm, "statistics_during_period", broken)
        with pytest.raises(AssertionError, match="INVALID I12"):
            await run_case(driver)
        result = driver.last_case_result
        assert result is not None
        assert not result.success
        assert result.snapshots[0].recorder_error == "RuntimeError"
        assert len(result.ending_steps) == 4
        assert driver.entry.state is ConfigEntryState.NOT_LOADED


async def test_consumed_pre_fence_gate_is_drained_on_body_failure(hass, monkeypatch):
    """A body fault after gate arrival drains the gate and cleans up its setup.

    Failure cleanup alone must leave no coordinator keepalive behind, so the test
    never stops a coordinator itself.
    """
    import asyncio

    from tests.support import boundaries as boundaries_module
    from tests.support.portal import Gate, ScriptedPortal

    portal = ScriptedPortal()
    boundaries_module.script_portal(portal)
    gate = Gate("pre_first_request", default_timeout=10.0)
    gate.hold()
    factory = boundaries_module.PreFenceFactory(
        portal, boundaries_module.ClientRegistry(), gate
    )
    entry = boundaries_module.create_flow_entry(hass, "L")
    driver = LifecycleDriver(hass, entry, portal, factory=factory)
    oracle = Oracle()
    oracle.attach_portal(portal)
    oracle.attach_registry(factory.registry)
    driver.add_observer(oracle)
    boundaries_module.register_initial_jar(oracle, entry)
    boundaries_module.register_scripted_eligibility(oracle, portal)

    original_wait_arrived = Gate.wait_arrived
    setup_task: asyncio.Future[Any] | None = None

    from custom_components.pseg.coordinator import PsegDataUpdateCoordinator

    created_coordinators: list[Any] = []
    original_coordinator_init = PsegDataUpdateCoordinator.__init__

    def track_coordinator(coordinator, *args, **kwargs):
        original_coordinator_init(coordinator, *args, **kwargs)
        created_coordinators.append(coordinator)

    monkeypatch.setattr(PsegDataUpdateCoordinator, "__init__", track_coordinator)

    def fail_after_arrival(target, *args, **kwargs):
        original_wait_arrived(target, *args, **kwargs)
        raise AssertionError("primary pre-fence body fault")

    async def body(current: LifecycleDriver) -> None:
        nonlocal setup_task
        setup_task = asyncio.ensure_future(current.setup())
        await hass.async_add_executor_job(fail_after_arrival, gate)

    monkeypatch.setattr(Gate, "wait_arrived", fail_after_arrival)
    started = time.monotonic()
    try:
        with factory:
            with pytest.raises(AssertionError, match="primary pre-fence body fault"):
                await run_case(driver, body, case_name="pre_fence_body_fault", oracle=oracle)
        elapsed = time.monotonic() - started
        print("CONSUMED_PRE_FENCE_GATE", gate._proceed.is_set(), gate._hold, elapsed)
        assert gate._proceed.is_set(), "consumed pre-fence gate was never drained"
        assert not gate._hold
        # The parked worker must be released by cleanup, not by the 10s timeout.
        assert elapsed < 5.0, f"pre-fence gate drain waited for the timeout ({elapsed:.1f}s)"
        # The factory consumed and cleared its attribute; the driver still owns it.
        assert factory._pre_fence_gate is None
        assert any(kept is gate for kept in driver.owned_gates())
    finally:
        gate.drain()
        if setup_task is not None:
            await asyncio.gather(setup_task, return_exceptions=True)
        await asyncio.wait_for(hass.async_block_till_done(wait_background_tasks=True), 20)
    # Failure cleanup, not this test, must own the released setup's coordinator.
    assert created_coordinators, "the released setup never created a coordinator"
    assert driver.entry.state is ConfigEntryState.NOT_LOADED
    for coordinator in created_coordinators:
        assert coordinator._unsub_keepalive is None, (
            "failure cleanup left a coordinator keepalive timer running"
        )


def test_gate_b_closure_registry_names_live_regressions():
    from tests.systemic.findings import GATE_B_ORACLE_CLOSURES

    assert {row["id"] for row in GATE_B_ORACLE_CLOSURES} == {"B1", "B6", "B7"}
    assert all(row["cases"] and row["evidence"] for row in GATE_B_ORACLE_CLOSURES)
    assert all(
        row["source_kb"] == "8e261d0b-ae95-4f56-bbf9-905173bebf5c" for row in GATE_B_ORACLE_CLOSURES
    )
    registered = {node for row in GATE_B_ORACLE_CLOSURES for node in row["cases"]}
    assert "tests/systemic/test_gate_b_oracle_regressions.py::test_live_i7" in registered
    assert "tests/systemic/test_gate_b_oracle_regressions.py::test_live_i8_terminal_sends" in (
        registered
    )
    assert (
        "tests/systemic/test_gate_b_oracle_regressions.py::"
        "test_live_i7_success_with_intermediate_transient_earns_no_retry"
    ) in registered
    assert (
        "tests/systemic/test_gate_b_oracle_regressions.py::"
        "test_live_i8_terminal_history_survives_unhuman_disk_clear"
    ) in registered
    assert (
        "tests/systemic/test_gate_b_oracle_regressions.py::"
        "test_consumed_pre_fence_gate_is_drained_on_body_failure"
    ) in registered

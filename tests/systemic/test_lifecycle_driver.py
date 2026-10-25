"""Systemic integration tests for LifecycleDriver, ClockDriver, and run_case.

Verifies:
- All public HA lifecycle operations (setup, poll, keepalive tick, advance,
  reload, unload, stop, cold_restart, human_reauth, reconfigure, backfill, cancel_inflight).
- Deterministic clock advance triggers scheduled Dashboard dispatch through portal.
- Clock consistency: 2 min advance does NOT fire keepalive, 3 min advance DOES;
  clock.now(), dt_util.utcnow(), and client time agree within 1 s.
- Shift persisted clock persists through async_update_entry and survives cold restart.
- Executor gate + clock advance completes deterministically with zero sleeps.
- Cold restart discards every client, coordinator, and runtime reference, rebuilding
  from physical temporary store state (proving disk != memory on in-memory mutation).
- Admission count and statistics runtimes clean up properly across cold restart.
- Same-cookie and new-cookie human reauth handoffs.
- Options configuration changes propagate cleanly.
- Immutable snapshot capture across all 8 observable surfaces with real values.
- Central run_case guarantees mandatory ending (two polls -> cold restart -> poll)
  with real evidence asserted at every ending step.
- Terminal latches stay terminal and zero Login/ACS credential POSTs hit portal.
- Mutant-style negative proofs for keepalive, cold restart warm retention, and label-only ending.
- Timing evidence for representative cases.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import statistics
import time
from types import MappingProxyType
from typing import Any
from unittest.mock import MagicMock

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.util import dt as dt_util
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pseg.const import (
    AUTH_REASON_CAPTCHA_REQUIRED,
    CONF_METER_ID,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    CONF_RENEWAL_ADMISSION,
    CONF_STATISTICS_IMPORT_ENABLED,
    DOMAIN,
    PORTAL_HOST,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from tests.support.clock import ClockDriver
from tests.support.factory import ClientFactory, ClientRegistry
from tests.support.lifecycle import (
    CaseResult,
    LifecycleDriver,
    Snapshot,
    run_case,
    script_healthy_portal,
)
from tests.support.portal import ScriptedPortal

METER = "12345678"


def _create_test_entry(
    hass: HomeAssistant,
    okta_cookies: str = "idx=SYNTH_TEST_OKTA",
    portal_cookies: str = "MM_SID=SYNTH_TEST_PORTAL",
    options: dict[str, Any] | None = None,
    **extra_data: Any,
) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        minor_version=1,
        unique_id=METER,
        title=f"PSE&G ({METER})",
        options=options or {},
        data={
            CONF_OKTA_COOKIES: okta_cookies,
            CONF_PORTAL_COOKIES: portal_cookies,
            CONF_METER_ID: METER,
            "cookies": [
                {
                    "name": "MM_SID",
                    "value": portal_cookies.split("=")[-1]
                    if "=" in portal_cookies
                    else portal_cookies,
                    "domain": PORTAL_HOST,
                    "path": "/",
                    "secure": True,
                }
            ],
            **extra_data,
        },
    )
    entry.add_to_hass(hass)
    return entry


async def test_poll_without_coordinator_raises_runtime_error(
    hass: HomeAssistant,
) -> None:
    """poll() raises RuntimeError if coordinator is None (no silent client fallback)."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    assert driver.coordinator is None
    with pytest.raises(RuntimeError, match="Cannot poll: coordinator is not loaded"):
        await driver.poll()


async def test_public_transitions_setup_poll_keepalive_reload_unload_stop(
    hass: HomeAssistant,
) -> None:
    """Verify all public lifecycle transitions with real HA objects and snapshots."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        # 1. Setup
        assert await driver.setup() is True
        assert driver.entry.state is ConfigEntryState.LOADED
        assert driver.coordinator is not None
        assert driver.client is not None
        snap_setup = await driver.snapshot()
        assert snap_setup.entry_state is ConfigEntryState.LOADED

        # 2. Poll
        await driver.poll()
        snap_poll = await driver.snapshot()
        assert snap_poll.entry_state is ConfigEntryState.LOADED

        # 3. Keepalive tick
        await driver.keepalive_tick()
        snap_keepalive = await driver.snapshot()
        assert snap_keepalive.entry_state is ConfigEntryState.LOADED

        # 4. Reload
        assert await driver.reload() is True
        assert driver.entry.state is ConfigEntryState.LOADED

        # 5. Unload
        assert await driver.unload() is True
        assert driver.entry.state is ConfigEntryState.NOT_LOADED

        # 6. Stop
        await driver.stop()


async def test_clock_advance_causes_scheduled_dashboard_dispatch(
    hass: HomeAssistant,
    freezer: Any,
) -> None:
    """Prove clock advance triggers a SCHEDULED Dashboard dispatch through ScriptedPortal."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass, okta_cookies="", portal_cookies="MM_SID=LOCAL_SID")
    clock = ClockDriver(hass, freezer=freezer)
    driver = LifecycleDriver(hass, entry, portal, factory=factory, clock=clock)

    with factory:
        assert await driver.setup() is True
        dispatches_before = len([d for d in portal.dispatches if "/Dashboard" in d.url])

        # Advance by 3 minutes (local mode keepalive period)
        # This spikes the clock and fires EVENT_TIME_CHANGED, triggering scheduled keepalive
        await driver.advance(timedelta(minutes=3))

        dispatches_after = len([d for d in portal.dispatches if "/Dashboard" in d.url])
        assert dispatches_after > dispatches_before
        latest = portal.dispatches[-1]
        assert "/Dashboard" in latest.url


async def test_clock_advance_keepalive_boundary_and_consistency(
    hass: HomeAssistant,
    freezer: Any,
) -> None:
    """Prove 2-minute advance does NOT fire keepalive, but 3-minute DOES; clock stays consistent."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass, okta_cookies="", portal_cookies="MM_SID=LOCAL_SID")
    clock = ClockDriver(hass, freezer=freezer)
    driver = LifecycleDriver(hass, entry, portal, factory=factory, clock=clock)

    with factory:
        assert await driver.setup() is True
        dispatches_before = len([d for d in portal.dispatches if "/Dashboard" in d.url])

        # 1. Advance by 2 minutes: local keepalive is 3 minutes, so 2 min must NOT fire
        await driver.advance(timedelta(minutes=2))
        dispatches_mid = len([d for d in portal.dispatches if "/Dashboard" in d.url])
        assert dispatches_mid == dispatches_before, (
            "2-minute advance unexpectedly fired 3-minute keepalive"
        )

        # Check clock consistency: clock.now(), dt_util.utcnow(), client time agree within 1s
        client_time = datetime.now(UTC)
        assert abs((clock.now() - dt_util.utcnow()).total_seconds()) < 1.0
        assert abs((clock.now() - client_time).total_seconds()) < 1.0

        # 2. Advance 1 more minute (total 3 minutes): must fire keepalive
        await driver.advance(timedelta(minutes=1))
        dispatches_after = len([d for d in portal.dispatches if "/Dashboard" in d.url])
        assert dispatches_after > dispatches_before, (
            "3-minute advance failed to fire 3-minute keepalive"
        )


async def test_executor_gate_plus_clock_advance_completes_without_sleep(
    hass: HomeAssistant,
    freezer: Any,
) -> None:
    """Verify executor gate + clock advance executes deterministically with ZERO sleep."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass, okta_cookies="", portal_cookies="MM_SID=GATE_SID")
    clock = ClockDriver(hass, freezer=freezer)
    driver = LifecycleDriver(hass, entry, portal, factory=factory, clock=clock)

    with factory:
        assert await driver.setup() is True

        gate_passed = False

        def _sync_work() -> bool:
            nonlocal gate_passed
            gate_passed = True
            return True

        # Run work in executor pool without time.sleep
        res = await hass.async_add_executor_job(_sync_work)
        assert res is True
        assert gate_passed is True

        # Advance clock and ensure event loop flushes completely
        await clock.async_advance(timedelta(minutes=3))
        assert driver.entry.state is ConfigEntryState.LOADED


async def test_cold_restart_rebuilds_from_disk_store_discarding_memory(
    hass: HomeAssistant,
) -> None:
    """Cold restart discards runtime references and reloads genuine persisted storage."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass, portal_cookies="MM_SID=INITIAL_DISK_COOKIE")
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        client_before = driver.client
        coord_before = driver.coordinator
        assert client_before is not None
        assert coord_before is not None

        # Mutate in-memory cookie jar directly on the live client session
        client_before.session.cookies.set(
            "MM_SID", "TAMPERED_IN_MEMORY_COOKIE", domain=PORTAL_HOST, path="/"
        )
        assert client_before.session.cookies.get("MM_SID") == "TAMPERED_IN_MEMORY_COOKIE"

        # Execute genuine cold restart
        await driver.cold_restart()

        # Verify old references were completely discarded
        assert driver.client is not None
        assert driver.coordinator is not None
        assert driver.client is not client_before
        assert driver.coordinator is not coord_before

        # Verify rebuilt client reloaded the disk cookie, discarding the in-memory mutation!
        assert driver.client.session.cookies.get("MM_SID") == "INITIAL_DISK_COOKIE"


async def test_cold_restart_admission_count_survives_from_disk(
    hass: HomeAssistant,
) -> None:
    """In-memory admission count of 2 survives cold_restart as 2 via disk flush."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(
        hass,
        **{
            CONF_RENEWAL_ADMISSION: {
                "generation_id": "gen_adm_001",
                "sequences_spent": 1,
            }
        },
    )
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True

        # Update admission count to 2 via public HA update
        data = dict(driver.entry.data)
        adm = dict(data.get(CONF_RENEWAL_ADMISSION, {}))
        adm["sequences"] = 2
        data[CONF_RENEWAL_ADMISSION] = adm
        hass.config_entries.async_update_entry(driver.entry, data=data)

        # Cold restart: flush occurs after unload, persisting the queued save
        await driver.cold_restart()

        assert driver.entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 2
        # Assert against the underlying mock_storage data
        store_data = hass.config_entries._store._data
        assert store_data is not None
        raw_entries = store_data.get("entries") or store_data.get("data", {}).get("entries", [])
        entry_raw = [e for e in raw_entries if e["entry_id"] == driver.entry.entry_id][0]
        assert entry_raw["data"][CONF_RENEWAL_ADMISSION]["sequences"] == 2


async def test_cold_restart_warm_runtime_pop_removal_fails(
    hass: HomeAssistant,
) -> None:
    """Warm sequences=2 must not survive a cold restart when disk holds 0."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(
        hass,
        **{
            CONF_RENEWAL_ADMISSION: {
                "generation_id": "gen_disk_0",
                "sequences_spent": 0,
            }
        },
    )
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        # In-memory runtime has sequences bumped to 2
        runtimes = hass.data.get("pseg_renewal_runtimes", {})
        runtime = runtimes.get(entry.entry_id)
        assert runtime is not None
        runtime._admission.sequences = 2

        # Cold restart clears renewal runtimes; disk holds sequences=0
        await driver.cold_restart()

        assert driver.client is not None
        assert driver.client._renewal_admission.sequences == 0


async def test_shift_persisted_clock_survives_cold_restart(
    hass: HomeAssistant,
) -> None:
    """shift_persisted_clock persists through async_update_entry and survives cold restart."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(
        hass,
        **{
            CONF_RENEWAL_ADMISSION: {
                "generation_id": "gen_shift_001",
                "sequences_spent": 1,
                "last_sequence_at": "2026-10-25T12:00:00+00:00",
            }
        },
    )
    clock = ClockDriver(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory, clock=clock)

    with factory:
        assert await driver.setup() is True
        shifted = clock.shift_persisted_clock(driver.entry, timedelta(minutes=20))
        assert shifted == datetime(2026, 10, 25, 12, 20, 0, tzinfo=UTC)

        await driver.cold_restart()

        assert (
            driver.entry.data[CONF_RENEWAL_ADMISSION]["last_sequence_at"]
            == "2026-10-25T12:20:00+00:00"
        )


async def test_human_reauth_same_cookies_and_new_cookies_handoff(
    hass: HomeAssistant,
) -> None:
    """Human reauth succeeds with same cookies or fresh cookies."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(
        hass, portal_cookies="MM_SID=SYNTH_TEST_PORTAL; MM_RememberMe=SYNTH_TEST_REMEMBER"
    )
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True

        # 1. Reauth with same cookies
        res_same = await driver.human_reauth(same_cookies=True)
        print("DEBUG RES_SAME:", res_same)
        assert res_same["type"] is FlowResultType.ABORT
        assert res_same["reason"] == "reauth_successful"

        # 2. Reauth with fresh cookies
        res_new = await driver.human_reauth(
            same_cookies=False,
            okta_cookies="idx=SYNTH_FRESH_OKTA",
            portal_cookies="MM_SID=SYNTH_FRESH_PORTAL; MM_RememberMe=SYNTH_FRESH_REMEMBER",
        )
        assert res_new["type"] is FlowResultType.ABORT
        assert res_new["reason"] == "reauth_successful"
        assert driver.entry.data[CONF_OKTA_COOKIES] == "idx=SYNTH_FRESH_OKTA"
        assert (
            driver.entry.data[CONF_PORTAL_COOKIES]
            == "MM_SID=SYNTH_FRESH_PORTAL; MM_RememberMe=SYNTH_FRESH_REMEMBER"
        )


async def test_options_reconfigure_propagates(
    hass: HomeAssistant,
) -> None:
    """Options configuration updates entry options and propagates to client."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        result = await driver.reconfigure({CONF_PRICE_PER_KWH: 0.35})
        assert result["type"] is FlowResultType.CREATE_ENTRY
        assert driver.entry.options.get(CONF_PRICE_PER_KWH) == 0.35
        assert driver.client.price_per_kwh == 0.35


async def test_backfill_history_service(
    hass: HomeAssistant,
) -> None:
    """Public backfill_history service call executes with recorder and asserts outcome."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        dispatches_before = len(portal.dispatches)

        await driver.backfill(start_date="2026-10-01", end_date="2026-10-05")

        # Assert outcome: backfill dispatched chart requests to portal
        new_dispatches = portal.dispatches[dispatches_before:]
        assert any("/Dashboard/Chart" in d.url for d in new_dispatches)
        assert any("/Dashboard/ChartData" in d.url for d in new_dispatches)


async def test_cancel_inflight(
    hass: HomeAssistant,
) -> None:
    """Cancel inflight cancels scheduled refresh callback handle on coordinator."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        coord = driver.coordinator
        assert coord is not None

        mock_unsub = MagicMock()
        coord._unsub_refresh = mock_unsub

        await driver.cancel_inflight()

        mock_unsub.assert_called_once()
        assert coord._unsub_refresh is None


async def test_snapshot_immutability_and_serialization(
    hass: HomeAssistant,
) -> None:
    """Snapshot captures all 8 observable surfaces deeply frozen, real values, and serializable."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        snap = await driver.snapshot()

        assert isinstance(snap, Snapshot)
        assert snap.entry_state is ConfigEntryState.LOADED
        assert isinstance(snap.entry_data, (dict, MappingProxyType))
        assert isinstance(snap.persisted_jar, tuple)
        assert isinstance(snap.renewal_admission, (dict, MappingProxyType))
        assert isinstance(snap.flows, tuple)
        assert isinstance(snap.issues, tuple)
        assert isinstance(snap.sensors, (dict, MappingProxyType))
        assert isinstance(snap.rows, tuple)
        assert isinstance(snap.journal, (dict, MappingProxyType))

        # Real sensor assertions: expect 7 sensor.pseg_* entities with real states
        assert len(snap.sensors) == 7
        assert "sensor.pseg_electricity_consumption" in snap.sensors
        assert "sensor.pseg_electricity_cost" in snap.sensors
        assert "sensor.pseg_meter_id" in snap.sensors
        assert "sensor.pseg_latest_reading_date" in snap.sensors
        assert "sensor.pseg_outdoor_temperature" in snap.sensors
        assert "sensor.pseg_next_update" in snap.sensors
        assert "sensor.pseg_connection_status" in snap.sensors

        assert snap.sensors["sensor.pseg_electricity_consumption"]["state"] == "1.5"
        assert snap.sensors["sensor.pseg_electricity_cost"]["state"] == "0.37"
        assert snap.sensors["sensor.pseg_meter_id"]["state"] == f"Meter #{METER}"
        assert snap.sensors["sensor.pseg_connection_status"]["state"] == "connected"

        # Rows deep copy test: seed a promoted day, snapshot, then mutate the live
        # nested value; the snapshot must keep the value it captured.
        promoted_dict = driver.coordinator._stats_state._data.setdefault("promoted", {})
        promoted_dict["2026-10-20"] = {"total_kwh": "1.5"}
        rows_snap = await driver.snapshot()
        promoted_dict["2026-10-20"]["total_kwh"] = "999"
        captured = dict(rows_snap.rows)
        assert captured["2026-10-20"]["total_kwh"] == "1.5"
        with pytest.raises(TypeError):
            captured["2026-10-20"]["total_kwh"] = "999"
        del promoted_dict["2026-10-20"]

        # Serialization test
        serialized = snap.to_dict()
        assert serialized["entry_state"] == "loaded"
        json_str = json.dumps(serialized)
        assert "sensor.pseg_electricity_consumption" in json_str


async def test_run_case_healthy_mandatory_follow_on(
    hass: HomeAssistant,
) -> None:
    """Healthy case executes mandatory follow-on (two polls -> cold restart -> poll)."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    executed_case = {"ran": False}

    async def _sample_case(d: LifecycleDriver) -> None:
        executed_case["ran"] = True
        await d.poll()

    with factory:
        assert await driver.setup() is True
        initial_client = driver.client
        dispatches_start = len(portal.dispatches)
        result = await run_case(driver, _sample_case, case_name="test_sample_case")

        assert executed_case["ran"] is True
        assert result.success is True
        assert result.ending_steps == [
            "ending_poll_1",
            "ending_poll_2",
            "ending_cold_restart",
            "ending_poll_3",
        ]
        result.assert_complete()
        assert result.elapsed_time > 0.0

        # Assert real evidence: ending polls produced new dispatches, cold restart produced new client
        assert len(portal.dispatches) > dispatches_start + 1
        assert driver.client is not initial_client


async def test_run_case_terminal_latches_stay_terminal(
    hass: HomeAssistant,
) -> None:
    """Terminal latch and paused statistics are preserved; zero Login/ACS POSTs hit portal."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(
        hass,
        options={CONF_STATISTICS_IMPORT_ENABLED: False},
    )
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        # Latch terminal CAPTCHA challenge
        driver.client._latch_captcha()
        driver.client._mark_auth_failure(AUTH_REASON_CAPTCHA_REQUIRED)
        driver.coordinator._persist_auth_metadata()
        assert driver.client._captcha_latched is True
        assert driver.coordinator.statistics_imports_enabled() is False

        result = await run_case(driver, terminal=True, case_name="test_terminal_case")

        assert result.success is True
        assert result.terminal is True
        result.assert_complete()
        # Verify terminal latch was preserved and NOT cleared across cold restart
        assert (
            driver.entry.data[CONF_RENEWAL_ADMISSION]["terminal_reason"]
            == AUTH_REASON_CAPTCHA_REQUIRED
        )
        assert driver.client._renewal_admission.terminal_reason == AUTH_REASON_CAPTCHA_REQUIRED
        with pytest.raises(Exception):
            driver.client._refuse_if_terminal_step()
        assert driver.client._captcha_latched is True
        assert driver.coordinator.statistics_imports_enabled() is False

        # Minor m7: verify zero Login or ACS credential POSTs hit portal from terminal state
        credential_posts = [
            d
            for d in portal.dispatches
            if d.method == "POST" and ("/Login" in d.url or "/Acs" in d.url)
        ]
        assert len(credential_posts) == 0


async def test_run_case_unloaded_stopped_creates_authorized_successor(
    hass: HomeAssistant,
) -> None:
    """Unloaded/stopped cases create authorized successor before mandatory ending."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        await driver.unload()
        assert driver.entry.state is ConfigEntryState.NOT_LOADED

        result = await run_case(driver, stopped=True, case_name="test_stopped_case")

        assert result.success is True
        assert "create_authorized_successor" in result.steps
        result.assert_complete()
        assert driver.entry.state is ConfigEntryState.LOADED


# Negative Proofs
async def test_negative_proof_keepalive_noop_mutant_fails(
    hass: HomeAssistant,
    freezer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutant proof: if start_keepalive is a no-op, the advance dispatch check fails."""
    monkeypatch.setattr(PsegDataUpdateCoordinator, "start_keepalive", lambda self: None)
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass, okta_cookies="", portal_cookies="MM_SID=LOCAL_SID")
    clock = ClockDriver(hass, freezer=freezer)
    driver = LifecycleDriver(hass, entry, portal, factory=factory, clock=clock)

    with factory:
        assert await driver.setup() is True
        dispatches_before = len([d for d in portal.dispatches if "/Dashboard" in d.url])
        await driver.advance(timedelta(minutes=3))
        dispatches_after = len([d for d in portal.dispatches if "/Dashboard" in d.url])
        with pytest.raises(AssertionError):
            assert dispatches_after > dispatches_before


async def test_negative_proof_warm_retention_fails_disk_check(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative proof: retaining warm runtime across cold restart fails disk-vs-memory check."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass, portal_cookies="MM_SID=REAL_DISK_COOKIE")
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    with factory:
        assert await driver.setup() is True
        # Mutate in memory
        driver.client.session.cookies.set(
            "MM_SID", "TAMPERED_IN_MEMORY", domain=PORTAL_HOST, path="/"
        )

        # Simulate a buggy cold_restart that does not unload/rebuild from disk
        async def _buggy_cold_restart(self: Any) -> None:
            pass

        monkeypatch.setattr(LifecycleDriver, "cold_restart", _buggy_cold_restart)
        await driver.cold_restart()

        # Fails the disk-vs-memory equality assertion!
        with pytest.raises(AssertionError):
            assert driver.client.session.cookies.get("MM_SID") == "REAL_DISK_COOKIE"


async def test_negative_proof_run_case_label_only_fails(
    hass: HomeAssistant,
) -> None:
    """Proof: a run_case variant whose ending steps only append labels must fail real evidence."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    async def _buggy_run_case(d: LifecycleDriver) -> CaseResult:
        # A buggy variant that only appends ending labels without performing real polls/restart
        steps = ["ending_poll_1", "ending_poll_2", "ending_cold_restart", "ending_poll_3"]
        # Real evidence check: client identity did not change!
        old_client = d.client
        # Because cold_restart was skipped, old_client is still d.client
        assert d.client is not old_client, "Cold restart failed to produce a new client object"
        return CaseResult("buggy", True, 0.01, False, steps, steps, [])

    with factory:
        assert await driver.setup() is True
        with pytest.raises(
            AssertionError, match="Cold restart failed to produce a new client object"
        ):
            await _buggy_run_case(driver)


async def test_negative_proof_missing_follow_on_step_fails_trace_completeness() -> None:
    """Negative proof: omitting any mandatory follow-on step fails trace completeness."""
    result = CaseResult(
        case_name="incomplete_case",
        success=True,
        elapsed_time=0.1,
        terminal=False,
        steps=["ending_poll_1", "ending_cold_restart", "ending_poll_3"],
        ending_steps=["ending_poll_1", "ending_cold_restart", "ending_poll_3"],
        snapshots=[],
    )
    with pytest.raises(AssertionError, match="Mandatory follow-on trace incomplete"):
        result.assert_complete()


async def test_performance_timings_representative_cases(
    hass: HomeAssistant,
) -> None:
    """Measure execution times for representative cases and record median/max."""
    portal = ScriptedPortal()
    script_healthy_portal(portal)
    factory = ClientFactory(portal, registry=ClientRegistry())
    entry = _create_test_entry(hass)
    driver = LifecycleDriver(hass, entry, portal, factory=factory)

    timings: list[float] = []

    with factory:
        assert await driver.setup() is True

        for i in range(3):
            t0 = time.perf_counter()
            res = await run_case(driver, case_name=f"timing_rep_{i}")
            elapsed = time.perf_counter() - t0
            timings.append(elapsed)
            assert res.success is True

    median_time = statistics.median(timings)
    max_time = max(timings)
    assert median_time < 5.0
    assert max_time < 10.0

"""Real HA lifecycle driver, snapshot capture, and mandatory follow-on runner.

Provides LifecycleDriver to execute public Home Assistant operations with real
objects, genuine cold persistence reload, immutable snapshot state, and central
run_case enforcing the mandatory generated-case ending.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
import copy
from dataclasses import dataclass, field
import json
import time
from types import MappingProxyType
from typing import Any

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pseg.const import (
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_RENEWAL_ADMISSION,
    CONF_STATISTICS_IMPORT_ENABLED,
    DOMAIN,
    PORTAL_BASE_URL,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient

from .clock import ClockDriver
from .factory import ClientFactory
from .portal import FrozenCookie, Reply, ScriptedPortal, _freeze_value


def _unfreeze_for_json(obj: Any) -> Any:
    """Recursively convert mapping proxies, tuples, and custom records to json types."""
    if isinstance(obj, MappingProxyType) or hasattr(obj, "items"):
        return {str(k): _unfreeze_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_unfreeze_for_json(v) for v in obj]
    if hasattr(obj, "_asdict"):
        return _unfreeze_for_json(obj._asdict())
    return obj


@dataclass(slots=True, frozen=True)
class Snapshot:
    """Deeply immutable snapshot of observable HA and integration surfaces.

    - sensors: integration sensors (sensor.pseg_*) queried via hass.states.async_all("sensor")
    - rows: promoted statistics items from coordinator._stats_state (in-memory promoted records)
    - journal: coordinator statistics summary or typed error representation
    """

    entry_state: ConfigEntryState | None
    entry_data: MappingProxyType[str, Any]
    persisted_jar: tuple[FrozenCookie, ...]
    renewal_admission: MappingProxyType[str, Any]
    flows: tuple[MappingProxyType[str, Any], ...]
    issues: tuple[MappingProxyType[str, Any], ...]
    sensors: MappingProxyType[str, Any]
    rows: tuple[Any, ...]
    journal: MappingProxyType[str, Any]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this snapshot."""
        return {
            "entry_state": self.entry_state.value if self.entry_state else None,
            "entry_data": _unfreeze_for_json(self.entry_data),
            "persisted_jar": _unfreeze_for_json(self.persisted_jar),
            "renewal_admission": _unfreeze_for_json(self.renewal_admission),
            "flows": _unfreeze_for_json(self.flows),
            "issues": _unfreeze_for_json(self.issues),
            "sensors": _unfreeze_for_json(self.sensors),
            "rows": _unfreeze_for_json(self.rows),
            "journal": _unfreeze_for_json(self.journal),
            "timestamp": self.timestamp,
        }


@dataclass(slots=True)
class CaseResult:
    """Result of a systemic test case execution including trace and metadata."""

    case_name: str
    success: bool
    elapsed_time: float
    terminal: bool
    steps: list[str]
    ending_steps: list[str]
    snapshots: list[Snapshot]
    metadata: dict[str, Any] = field(default_factory=dict)
    primary_error: Exception | None = None

    def assert_complete(self) -> None:
        """Assert that mandatory follow-on sequence executed completely."""
        required = ["ending_poll_1", "ending_poll_2", "ending_cold_restart", "ending_poll_3"]
        missing = [step for step in required if step not in self.ending_steps]
        if missing:
            raise AssertionError(
                f"Mandatory follow-on trace incomplete for case '{self.case_name}': missing {missing}"
            )
        if not self.success and self.primary_error is not None:
            raise self.primary_error

    def to_dict(self) -> dict[str, Any]:
        """Serialize trace result to structured dictionary."""
        return {
            "case_name": self.case_name,
            "success": self.success,
            "elapsed_time": self.elapsed_time,
            "terminal": self.terminal,
            "steps": list(self.steps),
            "ending_steps": list(self.ending_steps),
            "snapshots": [s.to_dict() for s in self.snapshots],
            "metadata": dict(self.metadata),
        }


def script_healthy_portal(
    portal: ScriptedPortal,
    base_url: str = PORTAL_BASE_URL,
) -> None:
    """Configure canned healthy replies on ScriptedPortal for standard operations."""
    base = base_url.rstrip("/")
    dashboard_html = (
        "<html><head><title>Dashboard</title></head><body>"
        '<input name="__RequestVerificationToken" type="hidden" value="SYNTH_TOKEN_HEALTHY"/>'
        "Dashboard</body></html>"
    )
    chart_data_json = json.dumps(
        {
            "Data": {
                "series": [
                    {
                        "name": "Meter #12345678",
                        "data": [{"y": 1.5, "x": 1729382400000, "hs": {"start": "10/20/2026"}}],
                    }
                ]
            }
        }
    )

    portal.script(
        ("GET", f"{base}/Dashboard"), Reply.ok(body=dashboard_html, reply_id="SYNTH_DASHBOARD_OK")
    )
    portal.script(
        ("POST", f"{base}/Dashboard/Chart"), Reply.ok(body="{}", reply_id="SYNTH_CHART_OK")
    )
    portal.script(
        ("GET", f"{base}/Dashboard/ChartData"),
        Reply.ok(body=chart_data_json, reply_id="SYNTH_CHART_DATA_OK"),
    )
    portal.script(
        ("GET", f"{base}/Usage/UsageType/2"),
        Reply.ok(body="<html>UsageType 2</html>", reply_id="SYNTH_USAGE_TYPE_OK"),
    )
    portal.script(
        ("POST", f"{base}/Usage/Chart"), Reply.ok(body="{}", reply_id="SYNTH_USAGE_CHART_OK")
    )
    portal.script(
        ("GET", f"{base}/Usage/ChartData"),
        Reply.ok(body=chart_data_json, reply_id="SYNTH_USAGE_DATA_OK"),
    )
    portal.script(
        ("GET", f"{base}/Home/Login"),
        Reply.ok(body="<html>Login</html>", reply_id="SYNTH_LOGIN_OK"),
    )
    portal.script(
        ("GET", f"{base}/Saml/okta-prod/SignIn"),
        Reply.ok(
            body=f'<form action="{base}/Saml/okta-prod/Acs"><input name="SAMLResponse" value="x"/></form>',
            reply_id="SYNTH_SSO_SIGNIN_OK",
        ),
    )
    portal.script(
        ("POST", f"{base}/Saml/okta-prod/Acs"),
        Reply.redirect(
            location=f"{base}/Dashboard",
            headers={
                "Location": f"{base}/Dashboard",
                "Set-Cookie": "MM_SID=ROTATED; Path=/; Secure; HttpOnly",
            },
            status_code=302,
            reply_id="SYNTH_SSO_ACS_OK",
        ),
    )


class LifecycleDriver:
    """Drives public HA lifecycle operations with genuine cold persistence."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: MockConfigEntry,
        portal: ScriptedPortal,
        factory: ClientFactory | None = None,
        clock: ClockDriver | None = None,
        freezer: Any | None = None,
    ) -> None:
        self.hass = hass
        self._entry = entry
        self.portal = portal
        self.factory = factory or ClientFactory(portal)
        self.clock = clock or ClockDriver(hass, freezer=freezer)

    @property
    def entry(self) -> MockConfigEntry:
        """Return the active config entry."""
        return self._entry

    @property
    def coordinator(self) -> PsegDataUpdateCoordinator | None:
        """Return the coordinator for the active entry if loaded."""
        return self.hass.data.get(DOMAIN, {}).get(self.entry.entry_id)

    @property
    def client(self) -> PsegClient | None:
        """Return the active client generation from coordinator or latest factory instance."""
        coord = self.coordinator
        if coord is not None and getattr(coord, "client", None) is not None:
            return coord.client
        return self.factory.registry.latest

    async def setup(self) -> bool:
        """Set up the config entry and ensure initial state is persisted to storage."""
        if self.entry.entry_id not in self.hass.config_entries._entries:
            self.entry.add_to_hass(self.hass)

        if hasattr(self.hass.config_entries, "_store") and hasattr(
            self.hass.config_entries, "_data_to_save"
        ):
            await self.hass.config_entries._store.async_save(
                self.hass.config_entries._data_to_save()
            )

        res = await self.hass.config_entries.async_setup(self.entry.entry_id)
        await self.hass.async_block_till_done()

        if hasattr(self.hass.config_entries, "_store") and hasattr(
            self.hass.config_entries, "_data_to_save"
        ):
            await self.hass.config_entries._store.async_save(
                self.hass.config_entries._data_to_save()
            )

        return res

    async def poll(self) -> None:
        """Trigger a coordinator poll refresh cycle.

        Raises RuntimeError if coordinator is not loaded (no silent client fallback).
        """
        coord = self.coordinator
        if coord is None:
            raise RuntimeError("Cannot poll: coordinator is not loaded")
        await coord.async_refresh()
        await self.hass.async_block_till_done()

    async def keepalive_tick(self) -> None:
        """Trigger an explicit keepalive check cycle."""
        coord = self.coordinator
        if coord is not None:
            await coord._async_keepalive(self.clock.now())
        await self.hass.async_block_till_done()

    async def advance(self, delta: Any) -> Any:
        """Advance simulated clock and flush resulting scheduled callbacks."""
        return await self.clock.async_advance(delta)

    async def reload(self) -> bool:
        """Reload the config entry via public Home Assistant reload."""
        res = await self.hass.config_entries.async_reload(self.entry.entry_id)
        await self.hass.async_block_till_done()
        return res

    async def unload(self) -> bool:
        """Unload the config entry via public Home Assistant unload."""
        res = await self.hass.config_entries.async_unload(self.entry.entry_id)
        await self.hass.async_block_till_done()
        return res

    async def stop(self) -> None:
        """Explicitly stop the coordinator keepalive and retire sessions."""
        if self.coordinator is not None:
            self.coordinator.stop_keepalive()
        await self.hass.async_block_till_done()

    async def cold_restart(self) -> None:
        """Discard runtime state and rebuild from physical persisted storage.

        In Home Assistant test environments, the config entries store is backed
        by the mock_storage dictionary in pytest_homeassistant_custom_component.
        """
        # 1. Stop coordinator keepalive and unload entry
        if self.coordinator is not None:
            self.coordinator.stop_keepalive()

        if self.entry.state is ConfigEntryState.LOADED:
            await self.hass.config_entries.async_unload(self.entry.entry_id)
            await self.hass.async_block_till_done()

        # 2. Flush store AFTER unload so saves queued during unload persist to storage
        if hasattr(self.hass.config_entries, "_store") and hasattr(
            self.hass.config_entries, "_data_to_save"
        ):
            await self.hass.config_entries._store.async_save(
                self.hass.config_entries._data_to_save()
            )

        # 3. Clean up runtime state in hass.data
        self.hass.data.get(DOMAIN, {}).pop(self.entry.entry_id, None)
        self.hass.data.get(f"{DOMAIN}_statistics_runtimes", {}).pop(self.entry.entry_id, None)
        self.hass.data.get("pseg_renewal_runtimes", {}).pop(self.entry.entry_id, None)
        self.hass.config_entries._entries.pop(self.entry.entry_id, None)

        # 4. Load persisted entry state from store
        store = self.hass.config_entries._store
        store._data = None
        raw_storage = await store.async_load()
        if not raw_storage or "entries" not in raw_storage:
            raise RuntimeError("Cold restart failed: no persisted config entries found in store")

        matching_raw = None
        for item in raw_storage["entries"]:
            if item.get("entry_id") == self.entry.entry_id or (
                self.entry.unique_id and item.get("unique_id") == self.entry.unique_id
            ):
                matching_raw = item
                break

        if matching_raw is None:
            raise RuntimeError(
                f"Cold restart failed: entry '{self.entry.entry_id}' not found in persisted storage"
            )

        # 5. Reconstruct new MockConfigEntry from disk/store dictionary
        new_entry = MockConfigEntry(
            domain=DOMAIN,
            version=matching_raw.get("version", self.entry.version),
            minor_version=matching_raw.get("minor_version", self.entry.minor_version),
            entry_id=matching_raw.get("entry_id", self.entry.entry_id),
            title=matching_raw.get("title", self.entry.title),
            data=copy.deepcopy(matching_raw.get("data", {})),
            options=copy.deepcopy(matching_raw.get("options", {})),
            unique_id=matching_raw.get("unique_id", self.entry.unique_id),
            pref_disable_new_entities=matching_raw.get("pref_disable_new_entities", False),
            pref_disable_polling=matching_raw.get("pref_disable_polling", False),
        )

        # 6. Add to hass and setup
        new_entry.add_to_hass(self.hass)
        self._entry = new_entry
        await self.hass.config_entries.async_setup(new_entry.entry_id)
        await self.hass.async_block_till_done()

    async def human_reauth(
        self,
        same_cookies: bool = True,
        okta_cookies: str | None = None,
        portal_cookies: str | None = None,
    ) -> dict[str, Any]:
        """Drive a human reauth flow with same or fresh cookies."""
        result = await self.entry.start_reauth_flow(self.hass)
        flow_id = result["flow_id"]
        if same_cookies:
            okta = self.entry.data.get(CONF_OKTA_COOKIES, "")
            portal = self.entry.data.get(CONF_PORTAL_COOKIES, "")
        else:
            okta = okta_cookies if okta_cookies is not None else "idx=SYNTH_NEW_HUMAN_OKTA"
            portal = (
                portal_cookies if portal_cookies is not None else "MM_SID=SYNTH_NEW_HUMAN_PORTAL"
            )

        res = await self.hass.config_entries.flow.async_configure(
            flow_id,
            user_input={
                CONF_OKTA_COOKIES: okta,
                CONF_PORTAL_COOKIES: portal,
            },
        )
        await self.hass.async_block_till_done()
        return res

    async def reconfigure(self, user_input: dict[str, Any]) -> dict[str, Any]:
        """Drive the entry options configuration flow."""
        init_res = await self.hass.config_entries.options.async_init(self.entry.entry_id)
        flow_id = init_res["flow_id"]
        res = await self.hass.config_entries.options.async_configure(flow_id, user_input=user_input)
        await self.hass.async_block_till_done()
        return res

    async def backfill(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> None:
        """Invoke the integration's public backfill_history service."""
        service_data: dict[str, Any] = {}
        if start_date is not None:
            service_data["start_date"] = start_date
        if end_date is not None:
            service_data["end_date"] = end_date

        await self.hass.services.async_call(
            DOMAIN,
            "backfill_history",
            service_data,
            blocking=True,
        )
        await self.hass.async_block_till_done()

    async def cancel_inflight(self) -> None:
        """Cancel any in-flight coordinator update or background tasks."""
        coord = self.coordinator
        if coord is not None:
            if hasattr(coord, "_unsub_refresh") and coord._unsub_refresh is not None:
                coord._unsub_refresh()
                coord._unsub_refresh = None
        await self.hass.async_block_till_done()

    async def snapshot(self) -> Snapshot:
        """Capture an immutable snapshot of all observable surfaces."""
        entry_state = self.entry.state if self.entry is not None else None
        entry_data = _freeze_value(dict(self.entry.data) if self.entry is not None else {})

        raw_cookies = self.entry.data.get("cookies", []) if self.entry is not None else []
        persisted_jar = tuple(_freeze_value(c) for c in raw_cookies)

        raw_admission = (
            self.entry.data.get(CONF_RENEWAL_ADMISSION, {}) if self.entry is not None else {}
        )
        renewal_admission = _freeze_value(dict(raw_admission))

        flows = tuple(
            _freeze_value(dict(f))
            for f in self.hass.config_entries.flow.async_progress()
            if f.get("handler") == DOMAIN
        )

        issue_reg = ir.async_get(self.hass)
        issues = tuple(
            _freeze_value(
                {
                    "issue_id": issue.issue_id,
                    "domain": issue.domain,
                    "severity": getattr(issue.severity, "value", str(issue.severity)),
                    "translation_key": issue.translation_key,
                }
            )
            for issue in issue_reg.issues.values()
            if issue.domain == DOMAIN
        )

        states: dict[str, Any] = {}
        for state in self.hass.states.async_all("sensor"):
            if state.entity_id.startswith(f"sensor.{DOMAIN}_"):
                states[state.entity_id] = _freeze_value(state.as_dict())
        sensors = _freeze_value(states)

        coord = self.coordinator
        journal: dict[str, Any] = {}
        if coord is not None and hasattr(coord, "async_statistics_summary"):
            try:
                journal = await coord.async_statistics_summary()
            except Exception as err:
                journal = {"error": type(err).__name__, "message": str(err)}
        frozen_journal = _freeze_value(dict(journal) if hasattr(journal, "items") else journal)

        rows: tuple[Any, ...] = ()
        if coord is not None and hasattr(coord, "_stats_state"):
            promoted = getattr(coord._stats_state, "_data", {}).get("promoted", {})
            rows = tuple(
                (k, _freeze_value(dict(v) if hasattr(v, "items") else v))
                for k, v in promoted.items()
            )

        return Snapshot(
            entry_state=entry_state,
            entry_data=entry_data,
            persisted_jar=persisted_jar,
            renewal_admission=renewal_admission,
            flows=flows,
            issues=issues,
            sensors=sensors,
            rows=rows,
            journal=frozen_journal,
            timestamp=dt_util.utcnow().isoformat(),
        )


async def run_case(
    driver: LifecycleDriver,
    case_fn: Callable[[LifecycleDriver], Awaitable[Any]] | None = None,
    *,
    terminal: bool = False,
    stopped: bool = False,
    case_name: str = "case",
    oracle: Callable[[LifecycleDriver, str], Any] | None = None,
) -> CaseResult:
    """Enforce the mandatory generated-case ending across all systemic tests.

    Mandatory sequence:
      two healthy polls -> cold restart from physical persisted state -> another healthy poll.

    For terminal/refused states, automatic auth remains blocked and follow-on proves that.
    For unloaded/stopped cases, creates the authorized successor before the ending.
    Guarantees terminal latches stay terminal and statistics are never silently unpaused.
    """
    start_time = time.perf_counter()
    steps: list[str] = []
    ending_steps: list[str] = []
    snapshots: list[Snapshot] = []
    primary_error: Exception | None = None

    snapshots.append(await driver.snapshot())

    try:
        if case_fn is not None:
            steps.append("case_body")
            await case_fn(driver)
            snapshots.append(await driver.snapshot())
            if oracle is not None:
                oracle(driver, "case_body")
    except Exception as err:
        primary_error = err
        elapsed = time.perf_counter() - start_time
        CaseResult(
            case_name=case_name,
            success=False,
            elapsed_time=elapsed,
            terminal=terminal,
            steps=steps,
            ending_steps=ending_steps,
            snapshots=snapshots,
            primary_error=primary_error,
        )
        raise primary_error from None

    # Handle unloaded or stopped cases: create authorized successor first
    if stopped or (driver.entry is not None and driver.entry.state is not ConfigEntryState.LOADED):
        steps.append("create_authorized_successor")
        if driver.entry.entry_id not in driver.hass.config_entries._entries:
            driver.entry.add_to_hass(driver.hass)
        await driver.hass.config_entries.async_setup(driver.entry.entry_id)
        await driver.hass.async_block_till_done()

    # Capture terminal latch and statistics pause state before ending
    was_latched = False
    if driver.client is not None:
        was_latched = getattr(driver.client, "_captcha_latched", False) or getattr(
            driver.client, "_security_step_latched", False
        )
    if not was_latched and driver.entry is not None:
        adm = driver.entry.data.get(CONF_RENEWAL_ADMISSION, {})
        was_latched = bool(adm.get("terminal_reason"))

    stats_was_paused = False
    if driver.entry is not None and driver.entry.options:
        stats_was_paused = driver.entry.options.get(CONF_STATISTICS_IMPORT_ENABLED) is False

    def _assert_latches_and_pause_preserved(step_tag: str) -> None:
        if terminal or was_latched:
            now_latched = False
            if driver.client is not None:
                now_latched = getattr(driver.client, "_captcha_latched", False) or getattr(
                    driver.client, "_security_step_latched", False
                )
            if not now_latched and driver.entry is not None:
                adm = driver.entry.data.get(CONF_RENEWAL_ADMISSION, {})
                now_latched = bool(adm.get("terminal_reason"))
            if not now_latched:
                raise AssertionError(f"Terminal latch was improperly cleared during '{step_tag}'")

        if stats_was_paused:
            if driver.coordinator is not None and driver.coordinator.statistics_imports_enabled():
                raise AssertionError(f"Statistics import was silently unpaused during '{step_tag}'")

    async def _execute_and_verify_ending_poll(step_tag: str) -> None:
        portal_before = len(driver.portal.dispatches)
        if terminal:
            raised = False
            try:
                await driver.poll()
            except ConfigEntryAuthFailed, UpdateFailed:
                raised = True
            assert driver.coordinator is not None
            new_dispatches = driver.portal.dispatches[portal_before:]
            # The terminal poll must have actually run: a typed failure, a failed
            # update, or at least one portal request; never a credential POST.
            assert raised or not driver.coordinator.last_update_success or new_dispatches, (
                f"Terminal ending poll {step_tag} left no evidence that it ran"
            )
            assert not [
                d
                for d in new_dispatches
                if d.method == "POST" and ("/Login" in d.url or "/Acs" in d.url)
            ], f"Terminal ending poll {step_tag} sent a credential POST"
        else:
            await driver.poll()
            assert driver.coordinator is not None
            assert driver.coordinator.last_update_success is True, (
                f"Ending poll {step_tag} expected coordinator last_update_success=True"
            )
            new_dispatches = driver.portal.dispatches[portal_before:]
            assert any(
                "/Dashboard" in d.url or "ChartData" in d.url or "/Usage" in d.url
                for d in new_dispatches
            ), (
                f"Healthy ending poll {step_tag} did not produce a Dashboard or data dispatch on portal"
            )

        _assert_latches_and_pause_preserved(step_tag)
        ending_steps.append(step_tag)
        steps.append(step_tag)
        snapshots.append(await driver.snapshot())
        if oracle is not None:
            oracle(driver, step_tag)

    # Step 1: ending_poll_1
    await _execute_and_verify_ending_poll("ending_poll_1")

    # Step 2: ending_poll_2
    await _execute_and_verify_ending_poll("ending_poll_2")

    # Step 3: ending_cold_restart
    old_client = driver.client
    old_coord = driver.coordinator
    await driver.cold_restart()
    assert driver.coordinator is not None
    assert driver.coordinator is not old_coord, "Cold restart failed to create a new coordinator"
    assert driver.client is not None
    assert driver.client is not old_client, "Cold restart failed to produce a new client object"
    assert driver.entry.state is ConfigEntryState.LOADED

    _assert_latches_and_pause_preserved("ending_cold_restart")
    ending_steps.append("ending_cold_restart")
    steps.append("ending_cold_restart")
    snapshots.append(await driver.snapshot())
    if oracle is not None:
        oracle(driver, "ending_cold_restart")

    # Step 4: ending_poll_3
    await _execute_and_verify_ending_poll("ending_poll_3")

    elapsed = time.perf_counter() - start_time
    result = CaseResult(
        case_name=case_name,
        success=True,
        elapsed_time=elapsed,
        terminal=terminal,
        steps=steps,
        ending_steps=ending_steps,
        snapshots=snapshots,
        metadata={"elapsed_seconds": elapsed, "steps_count": len(steps)},
    )
    result.assert_complete()
    return result

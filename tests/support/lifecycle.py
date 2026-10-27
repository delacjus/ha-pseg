"""Real HA lifecycle driver, snapshot capture, and mandatory follow-on runner.

Provides LifecycleDriver to execute public Home Assistant operations with real
objects, genuine cold persistence reload, immutable snapshot state, and central
run_case enforcing the mandatory generated-case ending.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import wraps
import hashlib
import json
import re
import threading
import time
from types import MappingProxyType
from typing import Any

from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)

from custom_components.pseg.const import (
    CONF_METER_ID,
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
from .portal import Dispatch, FrozenCookie, Reply, ScriptedPortal, _freeze_value


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
    rows: tuple[Any, ...] | None
    journal: MappingProxyType[str, Any]
    timestamp: str
    recorder_error: str | None = None

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
            "recorder_error": self.recorder_error,
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
    primary_error: BaseException | None = None

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
        self._observers: list[Callable[..., Any]] = []
        self._caplog: Any | None = None
        self.last_advance_timer_dispatches: int | None = None
        self.last_case_result: CaseResult | None = None
        self.auth_sends: list[dict[str, Any]] = []
        self.renewal_events: list[dict[str, Any]] = []
        self._auth_lock = threading.Lock()
        self._renewal_scope = threading.local()
        self._human_auth = False
        self._human_generations: set[str] = set()
        self._human_epoch = 0
        # A setup parked at a harness boundary is still owned by this driver so a
        # failing case can settle it and unload the coordinator it builds.
        self._pending_setup: asyncio.Task[Any] | None = None
        # Gates a factory consumes (and clears) stay owned by the driver so a
        # failing case can still drain them in finally instead of by timeout.
        self._retained_gates: list[Any] = []
        self.portal.add_observer(self._observe_auth_send)

        # Observe invocation boundaries, never admission/confirmation predicates.
        # Original arguments, return values and exceptions remain untouched.
        create_client = self.factory.create_client

        @wraps(create_client)
        def observed_client(*args: Any, **kwargs: Any) -> Any:
            # Retain the one-shot gate before the factory consumes it.
            self.retain_gate(getattr(self.factory, "_pre_fence_gate", None))
            client = create_client(*args, **kwargs)
            if self._human_auth:
                self._human_generations.add(client.generation_id)
            sequence = client._renew_remember_me_sequence

            @wraps(sequence)
            def observed_sequence(*a: Any, **kw: Any) -> Any:
                event: dict[str, Any] = {
                    "generation_id": client.generation_id,
                    "human": self._human_auth and client.generation_id in self._human_generations,
                    "epoch": self._human_epoch,
                    "sends": [],
                }
                previous = getattr(self._renewal_scope, "event", None)
                self._renewal_scope.event = event
                try:
                    settled = sequence(*a, **kw)
                except BaseException as err:
                    event["exception_type"] = type(err).__name__
                    event["settlement"] = "failed"
                    raise
                else:
                    # Whole-sequence settlement: the real sequence either returns
                    # a confirmed renewal or raises. Intermediate transient replies
                    # never decide the settlement of a sequence that succeeded.
                    event["settlement"] = "success" if settled else "failed"
                    return settled
                finally:
                    self._renewal_scope.event = previous
                    with self._auth_lock:
                        if event["sends"]:
                            self.renewal_events.append(_freeze_value(event))

            client._renew_remember_me_sequence = observed_sequence
            return client

        self.factory.create_client = observed_client

    def _observe_auth_send(self, dispatch: Dispatch) -> None:
        """Capture send-time evidence, including the durable entry write payload.

        Records only what was actually attempted: the dispatch, the driver-clock
        time, and the entry admission that was already persisted when the send
        happened. snapshot() separately reads the physical representation. No
        client policy/confirmation flag is read and no send is fenced or repaired.
        """
        event = getattr(self._renewal_scope, "event", None)
        now = self.clock.now().timestamp()
        with self._auth_lock:
            if event is not None:
                if not event["sends"]:
                    cookie = dispatch.cookies.get("MM_RememberMe", "")
                    event["remember_me"] = hashlib.sha256(cookie.encode()).hexdigest()
                    event["timestamp"] = now
                    event["admission_present"] = CONF_RENEWAL_ADMISSION in self.entry.data
                    event["admission"] = _freeze_value(self.entry.data.get(CONF_RENEWAL_ADMISSION))
                event["sends"].append(dispatch.sequence)
            admission = self.entry.data.get(CONF_RENEWAL_ADMISSION, {})
            self.auth_sends.append(
                _freeze_value(
                    {
                        "sequence": dispatch.sequence,
                        "timestamp": now,
                        # Send-time rearm boundary: the oracle orders terminal history
                        # by it instead of by when it processes a buffered send.
                        "epoch": self._human_epoch,
                        "terminal_reason": admission.get("terminal_reason")
                        if isinstance(admission, Mapping)
                        else None,
                        "human": self._human_auth
                        and dispatch.generation_id in self._human_generations,
                        "method": dispatch.method,
                        "url": dispatch.url,
                        "renewal": event is not None,
                    }
                )
            )

    def retain_gate(self, gate: Any) -> None:
        """Keep ownership of a harness gate a factory may consume and clear."""
        if gate is None:
            return
        if not any(gate is kept for kept in self._retained_gates):
            self._retained_gates.append(gate)

    def owned_gates(self) -> tuple[Any, ...]:
        """Every harness gate this runtime owns, including consumed ones.

        Cleanup must drain gates the factory already handed to a client, not only
        the attributes still reachable after consumption.
        """
        gates: list[Any] = list(self._retained_gates)
        for gate in (
            getattr(self.portal, "fence_gate", None),
            getattr(self.factory, "_pre_fence_gate", None),
            getattr(getattr(self.factory, "probe", None), "gate", None),
        ):
            if gate is not None and not any(gate is kept for kept in gates):
                gates.append(gate)
        return tuple(gates)

    @property
    def human_epoch(self) -> int:
        """Completed human rearm generation; only this clears a terminal latch."""
        return self._human_epoch

    @property
    def pending_setup(self) -> asyncio.Task[Any] | None:
        """The setup task a faulted case left parked, if it has not settled."""
        task = self._pending_setup
        return task if task is not None and not task.done() else None

    def _retire_current_generation(self) -> None:
        """Retire the current client generation on portal and observers."""
        old_client = self.client
        old_gen = old_client.generation_id if old_client is not None else None
        if old_gen:
            self.portal.retire(old_gen)
            for obs in list(self._observers):
                if hasattr(obs, "retire_generation"):
                    obs.retire_generation(old_gen)

    def attach_caplog(self, caplog: Any) -> None:
        """Attach pytest caplog for privacy scanning across checkpoints."""
        self._caplog = caplog
        for obs in list(self._observers):
            if hasattr(obs, "attach_caplog"):
                obs.attach_caplog(caplog)

    def add_observer(self, observer: Callable[..., Any]) -> None:
        """Register a step-time observer."""
        if observer not in self._observers:
            self._observers.append(observer)
            if self._caplog is not None and hasattr(observer, "attach_caplog"):
                observer.attach_caplog(self._caplog)

    def remove_observer(self, observer: Callable[..., Any]) -> None:
        """Unregister a step-time observer."""
        if observer in self._observers:
            self._observers.remove(observer)

    def observe_checkpoint(self, tag: str, snapshot: Snapshot | None = None) -> None:
        """Invoke step-time observers for a declared lifecycle checkpoint."""
        for obs in list(self._observers):
            try:
                obs(self, tag, snapshot)
            except TypeError:
                obs(self, tag)

    @property
    def dispatches(self) -> Sequence[Dispatch]:
        """Dispatches associated with this lifecycle driver runtime."""
        gen_id = self.client.generation_id if self.client else None
        if gen_id and self.portal:
            return tuple(d for d in self.portal.dispatches if d.generation_id == gen_id)
        return tuple(self.portal.dispatches) if self.portal else ()

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

        task = asyncio.current_task()
        self._pending_setup = task
        try:
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
        finally:
            if self._pending_setup is task:
                self._pending_setup = None

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
        prior = len(self.portal.dispatches)
        res = await self.clock.async_advance(delta)
        self.last_advance_timer_dispatches = len(self.portal.dispatches) - prior
        return res

    async def reload(self) -> bool:
        """Reload the config entry via public Home Assistant reload."""
        self._retire_current_generation()
        res = await self.hass.config_entries.async_reload(self.entry.entry_id)
        await self.hass.async_block_till_done()
        return res

    async def unload(self) -> bool:
        """Unload the config entry via public Home Assistant unload."""
        self._retire_current_generation()
        res = await self.hass.config_entries.async_unload(self.entry.entry_id)
        await self.hass.async_block_till_done()
        return res

    async def stop(self) -> None:
        """Explicitly stop the coordinator keepalive and retire sessions."""
        self._retire_current_generation()
        if self.coordinator is not None:
            self.coordinator.stop_keepalive()
        await self.hass.async_block_till_done()

    async def cold_restart(self) -> None:
        """Discard runtime state and rebuild from physical persisted storage.

        In Home Assistant test environments, the config entries store is backed
        by the mock_storage dictionary in pytest_homeassistant_custom_component.
        """
        self._retire_current_generation()
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
        self._human_auth = True
        res = None
        try:
            self._retire_current_generation()
            result = await self.entry.start_reauth_flow(self.hass)
            flow_id = result["flow_id"]
            if same_cookies:
                okta = self.entry.data.get(CONF_OKTA_COOKIES, "")
                portal = self.entry.data.get(CONF_PORTAL_COOKIES, "")
            else:
                okta = okta_cookies if okta_cookies is not None else "idx=SYNTH_NEW_HUMAN_OKTA"
                portal = (
                    portal_cookies
                    if portal_cookies is not None
                    else "MM_SID=SYNTH_NEW_HUMAN_PORTAL"
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
        finally:
            self._human_auth = False
            if (
                res is not None
                and res.get("type") == "abort"
                and res.get("reason") in {"reauth_successful", "reconfigure_successful"}
            ):
                self._human_epoch += 1

    async def reconfigure(self, user_input: dict[str, Any]) -> dict[str, Any]:
        """Drive the entry options configuration flow."""
        self._human_auth = True
        res = None
        try:
            init_res = await self.hass.config_entries.options.async_init(self.entry.entry_id)
            flow_id = init_res["flow_id"]
            res = await self.hass.config_entries.options.async_configure(
                flow_id, user_input=user_input
            )
            await self.hass.async_block_till_done()
            return res
        finally:
            self._human_auth = False
            if (
                res is not None
                and res.get("type") == "abort"
                and res.get("reason") in {"reauth_successful", "reconfigure_successful"}
            ):
                self._human_epoch += 1

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

        # Read physical persisted store (core.config_entries)
        persisted_raw_entry = None
        store = getattr(self.hass.config_entries, "_store", None)
        if store is not None:
            if getattr(store, "_delay_handle", None) is not None:
                await store._async_callback_delayed_write()
            store._data = None  # Invalidate in-memory cache so load reads underlying storage
            raw_storage = await store.async_load()
            if raw_storage and "entries" in raw_storage:
                for item in raw_storage["entries"]:
                    if item.get("entry_id") == self.entry.entry_id:
                        persisted_raw_entry = item
                        break

        if persisted_raw_entry is not None:
            raw_data = persisted_raw_entry.get("data", {})
            raw_cookies = raw_data.get("cookies", [])
            raw_admission = raw_data.get(CONF_RENEWAL_ADMISSION, {})
        else:
            raw_data = self.entry.data if self.entry is not None else {}
            raw_cookies = raw_data.get("cookies", [])
            raw_admission = raw_data.get(CONF_RENEWAL_ADMISSION, {})

        entry_data = _freeze_value(dict(raw_data))
        persisted_jar = tuple(_freeze_value(c) for c in raw_cookies)
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

        # 3. Read REAL pending journal from statistics Store
        coord = self.coordinator
        journal_data: dict[str, Any] = {}
        if coord is not None and hasattr(coord, "_stats_state"):
            pending = getattr(coord._stats_state, "_data", {}).get("pending", {})
            journal_data["pending"] = copy.deepcopy(pending)
            journal_data["has_pending"] = coord._stats_state.has_pending()
            journal_data["pending_recovery"] = coord._stats_state.has_pending()
        frozen_journal = _freeze_value(journal_data)

        # 4. Read REAL recorder rows for BOTH consumption and cost series AND promoted days
        rows_dict: dict[str, Any] = {}
        if coord is not None and hasattr(coord, "_stats_state"):
            promoted = getattr(coord._stats_state, "_data", {}).get("promoted", {})
            for k, v in promoted.items():
                rows_dict[k] = _freeze_value(dict(v) if hasattr(v, "items") else v)

        meter_id = self.entry.data.get(CONF_METER_ID, "12345678") if self.entry else "12345678"
        clean_meter = re.sub(r"[^a-z0-9_]+", "_", str(meter_id).lower()).strip("_") or "meter"
        cons_id = f"{DOMAIN}:{clean_meter}_energy_consumption"
        cost_id = f"{DOMAIN}:{clean_meter}_energy_cost"
        target_ids = {cons_id, cost_id}

        recorder_error = None
        try:
            await async_wait_recording_done(self.hass)
            rec_result = await self.hass.async_add_executor_job(
                statistics_during_period,
                self.hass,
                datetime(2020, 1, 1, tzinfo=UTC),
                None,
                target_ids,
                "hour",
                None,
                {"sum", "state"},
            )
            rows_dict["consumption"] = tuple(
                (r["start"], r.get("state"), r.get("sum")) for r in rec_result.get(cons_id, [])
            )
            rows_dict["cost"] = tuple(
                (r["start"], r.get("state"), r.get("sum")) for r in rec_result.get(cost_id, [])
            )
        except Exception as err:
            # Unavailable evidence is distinct from an observed empty database.
            recorder_error = type(err).__name__

        rows = (
            tuple((k, _freeze_value(v)) for k, v in rows_dict.items())
            if recorder_error is None
            else None
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
            recorder_error=recorder_error,
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
    result = CaseResult(
        case_name=case_name,
        success=False,
        elapsed_time=0,
        terminal=terminal,
        steps=[],
        ending_steps=[],
        snapshots=[],
        metadata={"ending_completed": [], "secondary_errors": []},
    )
    driver.last_case_result = result
    if oracle is not None:
        driver.add_observer(oracle)

    def record_error(err: BaseException, tag: str) -> None:
        if result.primary_error is None:
            result.primary_error = err
        else:
            # Preserve the original exception object and traceback. Secondary
            # failures must remain visible, without ever replacing the primary.
            note = f"{tag}: {type(err).__name__}: {err}"
            result.primary_error.add_note(note)
            result.metadata["secondary_errors"].append(note)

    def release_gates() -> None:
        driver.portal.drain()
        # FencePortal, pre-fence and exit probes own additional one-shot gates.
        # Consumed factory gates are retained by the driver, so a body fault after
        # arrival still drains them here instead of by their 10s timeout.
        for gate in driver.owned_gates():
            gate.drain()

    def safely_release_gates() -> None:
        try:
            release_gates()
        except BaseException as err:
            record_error(err, "release_gates")

    async def settle_outstanding_setup() -> None:
        """Let a setup released from a harness gate finish before cleanup runs.

        Cleanup must own the coordinator that setup builds. Without this, unload
        runs before the entry exists, the released setup then installs a
        coordinator nothing unloads, and its keepalive timer outlives the case.
        """
        task = driver.pending_setup
        if task is not None:
            await asyncio.wait_for(asyncio.shield(task), timeout=20)

    async def capture(tag: str) -> None:
        snapshot = await driver.snapshot()
        result.snapshots.append(snapshot)
        if snapshot.recorder_error:
            raise AssertionError(
                f"INVALID I12: recorder observation unavailable ({snapshot.recorder_error})"
            )
        driver.observe_checkpoint(tag, snapshot)

    async def successor() -> None:
        if stopped or driver.entry.state is not ConfigEntryState.LOADED:
            result.steps.append("create_authorized_successor")
            if driver.entry.entry_id not in driver.hass.config_entries._entries:
                driver.entry.add_to_hass(driver.hass)
            await driver.hass.config_entries.async_setup(driver.entry.entry_id)
            await driver.hass.async_block_till_done()

    was_latched = False
    stats_was_paused = False

    def capture_ending_preconditions() -> None:
        nonlocal was_latched, stats_was_paused
        if driver.client is not None:
            was_latched = getattr(driver.client, "_captcha_latched", False) or getattr(
                driver.client, "_security_step_latched", False
            )
        if not was_latched:
            was_latched = bool(
                driver.entry.data.get(CONF_RENEWAL_ADMISSION, {}).get("terminal_reason")
            )
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

    async def cold_restart() -> None:
        old_client, old_coord = driver.client, driver.coordinator
        await driver.cold_restart()
        assert driver.coordinator is not None
        assert driver.coordinator is not old_coord, (
            "Cold restart failed to create a new coordinator"
        )
        assert driver.client is not None
        assert driver.client is not old_client, "Cold restart failed to produce a new client object"
        assert driver.entry.state is ConfigEntryState.LOADED
        _assert_latches_and_pause_preserved("ending_cold_restart")

    try:
        try:
            result.snapshots.append(await driver.snapshot())
            if result.snapshots[-1].recorder_error:
                raise AssertionError(
                    "INVALID I12: recorder observation unavailable "
                    f"({result.snapshots[-1].recorder_error})"
                )
            if case_fn is not None:
                result.steps.append("case_body")
                await case_fn(driver)
                await capture("case_body")
        except BaseException as err:
            record_error(err, "case_body")
            safely_release_gates()
            # A setup parked at a harness boundary is this case's own work: settle it
            # now, so the mandatory ending runs against a completed lifecycle and
            # cleanup can unload the coordinator that setup builds.
            try:
                await settle_outstanding_setup()
            except BaseException as settle_err:
                record_error(settle_err, "settle_setup")
        try:
            capture_ending_preconditions()
        except BaseException as err:
            record_error(err, "ending_preconditions")
        try:
            await successor()
        except BaseException as err:
            record_error(err, "create_authorized_successor")

        for tag in ("ending_poll_1", "ending_poll_2", "ending_cold_restart", "ending_poll_3"):
            # Record the attempt BEFORE entering a failing operation/observer.
            result.ending_steps.append(tag)
            result.steps.append(tag)
            try:
                if tag == "ending_cold_restart":
                    await cold_restart()
                else:
                    await _execute_and_verify_ending_poll(tag)
                await capture(tag)
                result.metadata["ending_completed"].append(tag)
            except BaseException as err:
                record_error(err, tag)
                safely_release_gates()
    finally:
        # Always release harness gates so no parked worker outlives the case. A
        # failed case additionally cleans up its entry, timers and tasks; each
        # cleanup is independent so one failure can never skip the others.
        safely_release_gates()
        if result.primary_error is not None:
            for tag, cleanup in (
                ("settle_setup", settle_outstanding_setup),
                ("cancel_inflight", driver.cancel_inflight),
                ("unload", driver.unload),
            ):
                try:
                    await asyncio.wait_for(cleanup(), timeout=20)
                except BaseException as err:
                    record_error(err, tag)
            try:
                await asyncio.wait_for(
                    driver.hass.async_block_till_done(wait_background_tasks=True), timeout=20
                )
            except BaseException as err:
                record_error(err, "drain_tasks")
        result.elapsed_time = time.perf_counter() - start_time
        result.metadata.update(elapsed_seconds=result.elapsed_time, steps_count=len(result.steps))

    if result.primary_error is not None:
        raise result.primary_error
    result.success = True
    result.assert_complete()
    return result

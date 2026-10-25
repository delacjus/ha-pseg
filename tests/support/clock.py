"""Clock spike and time simulation utilities for deterministic HA lifecycle testing.

Provides ClockDriver to advance Home Assistant event-loop time, trigger scheduled
timer events, spike freezer/system clocks without disturbing monotonic timers, and
isolate/document persisted clock adjustments (such as renewal admission timestamps).
"""

from __future__ import annotations

from datetime import datetime, timedelta
import threading
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from custom_components.pseg.const import CONF_RENEWAL_ADMISSION
from custom_components.pseg.renewal_admission import _parse_timestamp


class ClockDriver:
    """Spikes freezer and triggers HA time-change events deterministically."""

    def __init__(
        self,
        hass: HomeAssistant,
        freezer: Any | None = None,
    ) -> None:
        self.hass = hass
        self._freezer = freezer
        self._offset = timedelta()
        self._lock = threading.Lock()

    @property
    def freezer(self) -> Any | None:
        """Return the attached freezer fixture/factory if any."""
        return self._freezer

    def now(self) -> datetime:
        """Return the current simulated UTC datetime."""
        if self._freezer is not None:
            return dt_util.utcnow()
        return dt_util.utcnow() + self._offset

    def advance(
        self,
        delta: timedelta | float | int,
        *,
        fire_time: bool = True,
        fire_all: bool = False,
    ) -> datetime:
        """Advance simulated clock by a delta, spiking the freezer and firing EVENT_TIME_CHANGED."""
        if isinstance(delta, (int, float)):
            delta = timedelta(seconds=float(delta))

        with self._lock:
            if self._freezer is not None:
                if hasattr(self._freezer, "tick"):
                    self._freezer.tick(delta)
                elif hasattr(self._freezer, "move_to"):
                    self._freezer.move_to(dt_util.utcnow() + delta)
                target_dt = dt_util.utcnow()
                fire_target = target_dt
            else:
                self._offset += delta
                target_dt = dt_util.utcnow() + self._offset
                fire_target = target_dt

            if fire_time:
                async_fire_time_changed(self.hass, fire_target, fire_all=fire_all)

        return target_dt

    async def async_advance(
        self,
        delta: timedelta | float | int,
        *,
        fire_time: bool = True,
        fire_all: bool = False,
    ) -> datetime:
        """Advance simulated clock by delta and await completion of scheduled HA callbacks."""
        target_dt = self.advance(delta, fire_time=fire_time, fire_all=fire_all)
        await self.hass.async_block_till_done()
        return target_dt

    def fire_time_changed(
        self,
        target_dt: datetime | None = None,
        *,
        fire_all: bool = False,
    ) -> datetime:
        """Directly fire EVENT_TIME_CHANGED without advancing freezer."""
        dt = target_dt or self.now()
        async_fire_time_changed(self.hass, dt, fire_all=fire_all)
        return dt

    def shift_persisted_clock(
        self,
        entry: Any,
        delta: timedelta | float | int,
    ) -> datetime | None:
        """Isolate and shift persisted renewal admission clock.

        Documents and modifies ONLY the persisted timestamp field (e.g. last_sequence_at
        in CONF_RENEWAL_ADMISSION), leaving monotonic timeout clocks intact.
        Persists changes through Home Assistant public async_update_entry so that
        updates survive cold restart and update storage caches.
        """
        if isinstance(delta, (int, float)):
            delta = timedelta(seconds=float(delta))

        data = dict(entry.data)
        admission_data = dict(data.get(CONF_RENEWAL_ADMISSION, {}))
        raw_last = admission_data.get("last_sequence_at")
        if raw_last is None:
            return None

        last_dt = _parse_timestamp(raw_last)
        if last_dt is None:
            return None

        shifted_dt = last_dt + delta
        shifted_iso = shifted_dt.isoformat()
        admission_data["last_sequence_at"] = shifted_iso
        data[CONF_RENEWAL_ADMISSION] = admission_data

        self.hass.config_entries.async_update_entry(entry, data=data)

        runtimes = self.hass.data.get("pseg_renewal_runtimes", {})
        runtime = runtimes.get(entry.entry_id)
        if runtime is not None and hasattr(runtime, "_admission"):
            runtime._admission.last_sequence_at = shifted_iso

        return shifted_dt


async def async_advance_time(
    hass: HomeAssistant,
    delta: timedelta | float | int,
    freezer: Any | None = None,
) -> datetime:
    """Helper to advance time and flush HA event loop."""
    driver = ClockDriver(hass, freezer=freezer)
    return await driver.async_advance(delta)

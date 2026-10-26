"""R5 review regression: cancelling a save while its file write is running.

Store.async_save finishes the file write in an executor thread that a caller's
cancellation cannot stop. The cost store must wait for that write to settle
before reconciling and releasing the entry lock; otherwise the stale write can
land after a newer save and overwrite it (Codex review R5).
"""

from __future__ import annotations

import asyncio
from datetime import date
import json
from pathlib import Path
import threading
from unittest.mock import patch

from homeassistant.core import HomeAssistant

from custom_components.pseg import cost_evidence as ce


def _block_first_write(store: ce.CostEvidenceStore) -> tuple[threading.Event, threading.Event]:
    """Hold the store's first file write until released; later writes pass through."""
    started = threading.Event()
    finished = threading.Event()
    release = threading.Event()
    original = store._store._write_data

    def gated(data):
        if started.is_set():
            return original(data)
        started.set()
        release.wait(5)
        try:
            return original(data)
        finally:
            finished.set()

    store._gate = (gated, release)  # type: ignore[attr-defined]
    return started, finished


async def _cancel_while_writing(hass: HomeAssistant, store, operation) -> tuple[bool, dict]:
    started, finished = _block_first_write(store)
    gated, release = store._gate
    with patch.object(store._store, "_write_data", gated):
        task = asyncio.create_task(operation())
        while not started.is_set():
            await asyncio.sleep(0.001)
        task.cancel()
        hass.loop.call_later(0.05, release.set)
        try:
            await task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("cancelled save did not raise CancelledError")
    disk = json.loads(Path(store._store.path).read_text())["data"]
    return finished.is_set(), disk


async def test_cancelled_mode_save_settles_before_returning(hass: HomeAssistant) -> None:
    store = ce.CostEvidenceStore(hass, "r5-cancel-mode")
    await store.async_set_mode("off")

    write_done, disk = await _cancel_while_writing(
        hass, store, lambda: store.async_set_mode("evidence")
    )

    assert write_done, "cancellation returned while the file write was still running"
    assert store._data == disk
    # A newer OFF must be the last word on disk; no stale write may follow it.
    await store.async_set_mode("off")
    await asyncio.sleep(0.1)
    disk = json.loads(Path(store._store.path).read_text())["data"]
    assert disk["mode"] == "off"
    assert store._data == disk


async def test_cancelled_reservation_save_settles_before_returning(hass: HomeAssistant) -> None:
    store = ce.CostEvidenceStore(hass, "r5-cancel-reserve")
    await store.async_set_mode("evidence")
    day = date(2026, 10, 25)

    write_done, disk = await _cancel_while_writing(
        hass, store, lambda: store.async_reserve_permit(day, "2026-10-11", "2026-10-25")
    )

    assert write_done, "cancellation returned while the file write was still running"
    assert store._data == disk
    if day.isoformat() in disk.get("reservations", {}):
        # The cancelled reservation landed: the day's budget is spent durably.
        assert await store.async_reserve_permit(day, "2026-10-11", "2026-10-25") is None

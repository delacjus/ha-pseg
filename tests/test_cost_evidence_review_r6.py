"""Codex review R6 probes: cancellation at save completion and repeated cancellation."""

import asyncio
from datetime import date
from unittest.mock import patch

import pytest

from custom_components.pseg import cost_evidence as ce


@pytest.mark.parametrize("operation", ["mode", "reservation"])
async def test_cancel_at_save_completion_propagates(hass, operation):
    store = ce.CostEvidenceStore(hass, "r6-completion-" + operation)
    await store.async_set_mode("off" if operation == "mode" else "evidence")
    original = store._store.async_save
    cancels = []

    async def save(data):
        await original(data)
        # This callback runs after shield completes its outer Future, before
        # the caller resumes. cancel() is accepted while save.done() is true.
        asyncio.current_task().add_done_callback(lambda _: cancels.append(task.cancel()))

    with patch.object(store._store, "async_save", save):
        task = asyncio.create_task(
            store.async_set_mode("evidence")
            if operation == "mode"
            else store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
        )
        try:
            result = await task
        except asyncio.CancelledError:
            return
        print("CANCEL_ACCEPTED", cancels, "RESULT", result, "CANCELLING", task.cancelling())
        pytest.fail("accepted caller cancellation swallowed at save completion")


async def test_repeated_cancel_during_write_settles(hass):
    import json
    from pathlib import Path

    from .test_cost_evidence_review_r5 import _block_first_write

    store = ce.CostEvidenceStore(hass, "r6-repeated")
    await store.async_set_mode("off")
    started, finished = _block_first_write(store)
    gated, release = store._gate
    with patch.object(store._store, "_write_data", gated):
        task = asyncio.create_task(store.async_set_mode("evidence"))
        while not started.is_set():
            await asyncio.sleep(0.001)
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0.005)
            assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert finished.is_set()
    assert store._data == json.loads(Path(store._store.path).read_text())["data"]

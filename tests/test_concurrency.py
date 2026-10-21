"""Portal and coordinator serialization tests (review r1 finding 1)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import threading
import time
from unittest.mock import AsyncMock, patch
import urllib.parse

from homeassistant.core import HomeAssistant
import requests_mock

from custom_components.pseg.const import PORTAL_BASE_URL
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient

DASHBOARD = '<input name="__RequestVerificationToken" value="t"/>Dashboard'


def test_concurrent_chart_requests_do_not_interleave() -> None:
    """MyMeter keeps the chart range server-side: poll and backfill must not interleave."""
    client = PsegClient(portal_cookies="MM_SID=x")
    state: dict = {}

    def chart(req, ctx):
        q = urllib.parse.parse_qs(req.text)
        state["range"] = (q["Start"][0], q["End"][0])
        time.sleep(0.05)
        return ""

    def data(req, ctx):
        start, end = state["range"]
        d = datetime.strptime(start, "%Y-%m-%d")
        d1 = datetime.strptime(end, "%Y-%m-%d")
        pts = []
        while d <= d1:
            pts.append({"y": 1.0, "hs": {"start": d.strftime("%m/%d/%Y")}})
            d += timedelta(days=1)
        time.sleep(0.05)
        return {"Data": {"series": [{"name": "Electric Meter 1", "data": pts}]}}

    out: dict = {}
    with requests_mock.Mocker() as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD)
        m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=chart)
        m.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=data)
        t1 = threading.Thread(
            target=lambda: out.setdefault(
                "bf", client.fetch_history_range("2024-01-01", "2024-12-31", 90)
            )
        )
        t2 = threading.Thread(target=lambda: out.setdefault("poll", client.fetch_energy_data(14)))
        t1.start()
        time.sleep(0.03)
        t2.start()
        t1.join()
        t2.join()

    poll = out["poll"]["history_14d"]
    bf_dates = [r["date"] for r in out["bf"]]
    assert len(poll) == 15
    assert all(r["date"] > "2024-12-31" for r in poll)
    assert min(bf_dates) == "2024-01-01"
    assert max(bf_dates) == "2024-12-31"


async def test_coordinator_serializes_poll_and_backfill(hass: HomeAssistant) -> None:
    """Poll and backfill fetch + import run one at a time even if the client is unlocked."""
    client = PsegClient(portal_cookies="MM_SID=x")
    coord = PsegDataUpdateCoordinator(hass, client, {})
    active = 0
    max_active = 0
    guard = threading.Lock()

    def _enter() -> None:
        nonlocal active, max_active
        with guard:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.05)

    def _leave() -> None:
        nonlocal active
        with guard:
            active -= 1

    def fake_poll(_days):
        _enter()
        return {"meter": "Meter 1", "history_14d": [{"date": "2026-10-20", "kwh": 1.0, "cost": 0.25}]}

    def fake_history(_s, _e, _c):
        _enter()
        return [{"date": "2026-10-20", "kwh": 1.0, "cost": 0.25}]

    async def fake_record(records, meter_id=None):
        await asyncio.sleep(0.05)
        _leave()

    with (
        patch.object(client, "fetch_energy_data", side_effect=fake_poll),
        patch.object(client, "fetch_history_range", side_effect=fake_history),
        patch.object(coord, "async_record_statistics", AsyncMock(side_effect=fake_record)),
    ):
        await asyncio.gather(
            coord._async_update_data(),
            coord.async_backfill_history("2026-10-01", "2026-10-20"),
            coord._async_update_data(),
        )

    assert max_active == 1

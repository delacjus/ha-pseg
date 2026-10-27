"""Portal and coordinator serialization tests (review r1 finding 1)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import threading
from unittest.mock import AsyncMock, patch
import urllib.parse

from homeassistant.core import HomeAssistant
import pytest
import requests_mock

from custom_components.pseg.const import PORTAL_BASE_URL
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient, PsegTransientError
from tests.support.synchronization import (
    ObservedAsyncLock,
    ObservedLock,
    join_thread,
    wait_event,
    wait_event_async,
    wait_task,
)

DASHBOARD = '<input name="__RequestVerificationToken" value="t"/>Dashboard'


def test_concurrent_chart_requests_do_not_interleave() -> None:
    """MyMeter keeps the chart range server-side: poll and backfill must not interleave."""
    client = PsegClient(portal_cookies="MM_SID=x")
    state: dict = {}
    client._lock = ObservedLock(client._lock, "poll/backfill client lock")
    chart_arrived = threading.Event()
    chart_release = threading.Event()
    data_arrived = threading.Event()
    data_release = threading.Event()

    def chart(req, ctx):
        q = urllib.parse.parse_qs(req.text)
        state["range"] = (q["Start"][0], q["End"][0])
        return ""

    def data(req, ctx):
        start, end = state["range"]
        d = datetime.strptime(start, "%Y-%m-%d")
        d1 = datetime.strptime(end, "%Y-%m-%d")
        pts = []
        while d <= d1:
            pts.append({"y": 1.0, "hs": {"start": d.strftime("%m/%d/%Y")}})
            d += timedelta(days=1)
        return {"Data": {"series": [{"name": "Meter #1", "data": pts}]}}

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
        real_send = client.session.send

        def send(request, **kwargs):
            response = real_send(request, **kwargs)
            # Pause outside requests_mock's callback lock, at the real response
            # boundaries where the old sleeps tried to let the poll interleave.
            if threading.current_thread() is t1:
                path = urllib.parse.urlparse(request.url).path
                if path == "/Dashboard/Chart" and not chart_arrived.is_set():
                    chart_arrived.set()
                    wait_event(chart_release, "backfill Chart response release")
                elif path == "/Dashboard/ChartData" and not data_arrived.is_set():
                    data_arrived.set()
                    wait_event(data_release, "backfill ChartData response release")
            return response

        with patch.object(client.session, "send", side_effect=send):
            t1.start()
            try:
                wait_event(chart_arrived, "backfill Chart response arrival")
                t2.start()
                wait_event(client._lock.contended, "poll waiting on backfill client lock")
                chart_release.set()
                wait_event(data_arrived, "backfill ChartData response arrival")
                data_release.set()
            finally:
                chart_release.set()
                data_release.set()
                join_thread(t1, "backfill")
                join_thread(t2, "poll")

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
    entered = threading.Event()
    release = threading.Event()
    coord._update_lock = ObservedAsyncLock(coord._update_lock, "coordinator update lock")

    def _enter() -> None:
        nonlocal active, max_active
        with guard:
            active += 1
            max_active = max(max_active, active)
        if not entered.is_set():
            entered.set()
            wait_event(release, "first coordinator fetch release")

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
        # Plain functions retain the real executor boundary; HA runs Mock jobs
        # inline, where a blocking handshake would stop the event loop.
        patch.object(client, "fetch_energy_data", new=fake_poll),
        patch.object(client, "fetch_history_range", new=fake_history),
        patch.object(coord, "async_record_statistics", AsyncMock(side_effect=fake_record)),
    ):
        tasks = [asyncio.create_task(coord._async_update_data())]
        try:
            await wait_event_async(entered, "first coordinator fetch arrival")
            tasks.extend([
                asyncio.create_task(coord.async_backfill_history("2026-10-01", "2026-10-20")),
                asyncio.create_task(coord._async_update_data()),
            ])
            await wait_event_async(coord._update_lock.contended, "queued coordinator update")
            release.set()
            await wait_task(asyncio.gather(*tasks), "serialized coordinator operations")
        finally:
            release.set()
            await wait_task(asyncio.gather(*tasks, return_exceptions=True), "coordinator cleanup")

    assert max_active == 1


def _renewal_portal(state: dict[str, object], guard: threading.Lock):
    """Portal stubs: only the very first probe is a sign-in page, later ones work."""

    def dashboard(_request, context):
        with guard:
            state["probes"] = int(state["probes"]) + 1
            first_probe = state["probes"] == 1
        if first_probe:
            context.status_code = 302
            context.headers["Location"] = "/"
            return ""
        return '<input name="__RequestVerificationToken" value="af"/>Dashboard'

    def chart_setup(_request, _context):
        with guard:
            state["charts"] = int(state["charts"]) + 1
        return "ok"

    def chart_data(_request, _context):
        return {
            "Data": {
                "series": [
                    {
                        "name": "Meter #12345",
                        "data": [{"y": 2.0, "hs": {"start": "10/22/2026"}}],
                    }
                ]
            }
        }

    return dashboard, chart_setup, chart_data


def _run_pair(first, second) -> list:
    """Run two client calls on their own threads and return their outcomes."""
    outcomes: list = []
    guard = threading.Lock()

    def run(func, label):
        try:
            result = func()
            with guard:
                outcomes.append((label, result))
        except Exception as err:  # noqa: BLE001 - the outcome is the assertion
            with guard:
                outcomes.append((label, type(err).__name__))

    threads = [threading.Thread(target=run, args=(first, "a")),
               threading.Thread(target=run, args=(second, "b"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    return outcomes


@pytest.mark.parametrize("second", ["keepalive", "poll"])
def test_concurrent_keepalive_and_poll_spend_one_renewal(second: str) -> None:
    """The client lock plus the shared admission allow exactly one renewal sequence."""
    client = PsegClient(portal_cookies="MM_SID=dead; MM_RememberMe=remember-token")
    client.set_expected_meter_ids({"12345"})
    state: dict[str, object] = {"probes": 0, "charts": 0}
    guard = threading.Lock()
    dashboard, chart_setup, chart_data = _renewal_portal(state, guard)

    first_call = client.keepalive
    second_call = client.keepalive if second == "keepalive" else client.ensure_session

    with requests_mock.Mocker() as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=dashboard)
        m.get(f"{PORTAL_BASE_URL}/", text="<html>home</html>")
        m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=chart_setup)
        m.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=chart_data)
        outcomes = _run_pair(first_call, second_call)

    assert len(outcomes) == 2
    assert state["charts"] == 1  # exactly one renewal sequence
    assert client.sso_renewals == 1
    assert client.has_remember_me is True
    assert client.auth_reason is None
    assert client._renewal_admission.sequences == 1
    assert client._in_keepalive is False


def test_keepalive_holds_the_client_lock_across_a_renewal() -> None:
    """A second entry point waits for the lock instead of reading a half-renewed jar."""
    client = PsegClient(portal_cookies="MM_SID=dead; MM_RememberMe=remember-token")
    client.set_expected_meter_ids({"12345"})
    parked = threading.Event()
    release = threading.Event()
    client._lock = ObservedLock(client._lock, "renewal client lock")
    calls = {"n": 0}
    guard = threading.Lock()

    def dashboard(_request, context):
        with guard:
            calls["n"] += 1
            first = calls["n"] == 1
        if first:
            parked.set()
            assert release.wait(5)
            context.status_code = 302
            context.headers["Location"] = "/"
            return ""
        return '<input name="__RequestVerificationToken" value="af"/>Dashboard'

    def chart_data(_request, _context):
        return {
            "Data": {
                "series": [
                    {"name": "Meter #12345", "data": [{"y": 1.0, "hs": {"start": "10/22/2026"}}]}
                ]
            }
        }

    outcome: dict = {}
    with requests_mock.Mocker() as m:
        dash = m.get(f"{PORTAL_BASE_URL}/Dashboard", text=dashboard)
        m.get(f"{PORTAL_BASE_URL}/", text="<html>home</html>")
        m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        m.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=chart_data)
        first = threading.Thread(
            target=lambda: outcome.setdefault("keepalive", client.keepalive())
        )
        second = threading.Thread(target=client.renew_remember_me)
        first.start()
        try:
            wait_event(parked, "keepalive Dashboard arrival")
            assert parked.wait(5)
            second.start()
            wait_event(client._lock.contended, "renewal waiting on keepalive client lock")
            # Parked inside the renewal: the second caller must not send a request yet.
            assert dash.call_count == 1
        finally:
            release.set()
            join_thread(first, "keepalive")
            join_thread(second, "renewal")

    assert dash.call_count >= 2
    assert outcome["keepalive"] is True


def test_public_renewal_entry_point_waits_for_the_client_lock() -> None:
    """The RLock is what makes the shared admission non-racy between entry points."""
    client = PsegClient(portal_cookies="MM_SID=dead; MM_RememberMe=remember-token")
    client._lock = ObservedLock(client._lock, "renewal entry-point client lock")
    assert client._lock.acquire(timeout=1)
    done = threading.Event()
    started = threading.Event()

    def call_renewal() -> None:
        started.set()
        try:
            client.renew_remember_me()
        except Exception:  # noqa: BLE001 - the fake portal raises to stop the test
            pass
        done.set()

    with patch.object(
        client, "_get_dashboard", side_effect=PsegTransientError("synthetic stop")
    ):
        thread = threading.Thread(target=call_renewal)
        thread.start()
        try:
            assert started.wait(5)
            wait_event(client._lock.contended, "renewal waiting on held client lock")
            # While another portal operation holds the lock, no request may start.
            assert not done.wait(0.25)
        finally:
            client._lock.release()
        thread.join(5)

    assert done.is_set()

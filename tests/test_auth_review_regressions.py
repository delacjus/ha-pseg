"""Independent synthetic, no-network review probes; never print cookie values."""
import asyncio
from datetime import UTC, datetime, timedelta
from http.client import HTTPMessage
import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlparse

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
from requests.adapters import BaseAdapter

import custom_components.pseg as pkg
from custom_components.pseg.const import (
    AUTH_REASON_PORTAL_SESSION_EXPIRED,
    CONF_PORTAL_COOKIES,
    CONF_RENEWAL_ADMISSION,
    DOMAIN,
    PORTAL_BASE_URL,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient, PsegTransientError
from custom_components.pseg.renewal_admission import RenewalAdmission

METER = "12345"
TOKEN_HTML = '<input name="__RequestVerificationToken" value="synthetic-af"/>'
CHART = {"Data": {"series": [{"name": "Meter #12345", "data": [
    {"y": 4.0, "hs": {"start": "10/22/2026"}}
]}]}}
DATA = {"meter": "Meter #12345", "meter_ids": [METER], "history_14d": [],
        "last_updated": "synthetic", "latest_date": "2026-10-22", "latest_kwh": 4,
        "latest_cost": 1, "previous_date": "2026-10-21", "previous_kwh": 3,
        "previous_cost": 1, "temperature_range": "", "temperature_avg": None,
        "total_records": 0}


class Portal(BaseAdapter):
    """Independent requests adapters, no requests_mock global serialization."""
    def __init__(self, *, block_probe=False, block_renew=False, block_chart=False,
                 rotate_probe=False, rotate_renew=False, fail_chart=False,
                 fail_renew=False, reject=False):
        self.dash = 0
        self.events = []
        self.probe_entered = threading.Event()
        self.renew_entered = threading.Event()
        self.chart_entered = threading.Event()
        self.probe_release = threading.Event()
        self.renew_release = threading.Event()
        self.chart_release = threading.Event()
        for key, value in locals().copy().items():
            if key not in {"self", "__class__"}:
                setattr(self, key, value)

    def send(self, request, **kwargs):
        path = urlparse(request.url).path
        self.events.append((request.method, path, time.monotonic()))
        r = requests.Response()
        r.status_code = 200
        r.url = request.url
        r.request = request
        r._content = b"ok"
        r._content_consumed = True
        msg = HTTPMessage()
        r.raw = SimpleNamespace(_original_response=SimpleNamespace(msg=msg))
        if path == "/Dashboard":
            self.dash += 1
            if self.dash == 1:
                self.probe_entered.set()
                if self.block_probe:
                    assert self.probe_release.wait(8), "synthetic probe timeout"
                r.url = PORTAL_BASE_URL + "/"
                if self.rotate_probe:
                    msg.add_header("Set-Cookie", "MM_RememberMe=synthetic-b; Path=/")
            else:
                if self.dash == 2:
                    self.renew_entered.set()
                    if self.block_renew:
                        assert self.renew_release.wait(8), "synthetic renewal timeout"
                    if self.fail_renew:
                        raise requests.Timeout("synthetic renewal timeout")
                    if self.rotate_renew:
                        msg.add_header("Set-Cookie", "MM_RememberMe=synthetic-b; Path=/")
                r._content = TOKEN_HTML.encode()
                if self.reject:
                    r.url = PORTAL_BASE_URL + "/"
        elif path == "/Dashboard/Chart":
            self.chart_entered.set()
            if self.block_chart:
                assert self.chart_release.wait(8), "synthetic identity timeout"
            if self.fail_chart:
                raise requests.Timeout("synthetic chart timeout")
        elif path == "/Dashboard/ChartData":
            r._content = json.dumps(CHART).encode()
        elif path != "/":
            raise AssertionError("unexpected synthetic HTTP route")
        return r

    def close(self):
        pass

    def release_all(self):
        self.probe_release.set()
        self.renew_release.set()
        self.chart_release.set()


def client_with(portal):
    c = PsegClient(portal_cookies="MM_SID=synthetic; MM_RememberMe=synthetic-a")
    c.set_expected_meter_ids({METER})
    c.session.mount("https://", portal)
    return c


@pytest.mark.parametrize("raw", [
    {"sequences": 1, "last_sequence_at": "broken"},
    {"sequences": True, "last_sequence_at": None},
    {"sequences": -1},
    "broken",
])
def test_uncertain_metadata_refuses(raw):
    state = RenewalAdmission.from_dict(raw)
    assert state.blocked_reason(datetime.now(UTC)) is not None, "uncertain metadata granted admission"


def test_success_without_rotation_does_not_authorize_transient_retry():
    portal = Portal()
    c = client_with(portal)
    assert c.keepalive()
    assert c._renewal_admission.sequences == 1
    c._renewal_admission.last_sequence_at = (datetime.now(UTC) - timedelta(minutes=16)).isoformat()
    portal.dash = 0
    before = len(portal.events)
    c.keepalive()
    assert len(portal.events) == before + 1, "success granted a transient-only retry and sent renewal HTTP"


def test_poll_failure_does_not_rearm_unconfirmed_rotation():
    portal = Portal(rotate_renew=True, fail_chart=True)
    c = client_with(portal)
    with pytest.raises(PsegTransientError):
        c.fetch_energy_data()
    assert c._renewal_admission.sequences == 1, "poll rearmed before the failed DAILY identity check"
    assert c.sso_renewals == 0


def test_probe_rotation_is_rolled_back_after_transient_renewal():
    portal = Portal(rotate_probe=True, fail_renew=True)
    c = client_with(portal)
    before = c._remember_me_values()
    c._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
    first = (c.auth_reason, c.okta_session_expired_at, c.idle_gap_seconds)
    assert c.keepalive() is False
    assert (c.auth_reason, c.okta_session_expired_at, c.idle_gap_seconds) == first
    assert c._remember_me_values() == before, "unconfirmed expiry-probe cookie became rollback baseline"


def test_meter_proof_does_not_publish_success_early():
    portal = Portal(block_chart=True, rotate_renew=True)
    c = client_with(portal)
    c._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
    before = (c.auth_reason, c.okta_session_expired_at, c.idle_gap_seconds,
              c.sso_renewals, c.last_sso_renewal, c.last_portal_success_at)
    result = []
    t = threading.Thread(target=lambda: result.append(c.keepalive()))
    t.start()
    try:
        assert portal.chart_entered.wait(4)
        assert (c.auth_reason, c.okta_session_expired_at, c.idle_gap_seconds,
                c.sso_renewals, c.last_sso_renewal, c.last_portal_success_at) == before
        assert c._renewal_admission.sequences == 1
    finally:
        portal.release_all()
        t.join(5)
    assert result == [True]
    assert c.sso_renewals == 1
    assert c.auth_reason is None


def test_renewal_rotation_transient_restores_jar_first_failure_and_budget():
    portal = Portal(rotate_renew=True, fail_chart=True)
    c = client_with(portal)
    before_jar = c._remember_me_values()
    c._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
    first = (c.auth_reason, c.okta_session_expired_at, c.idle_gap_seconds)
    assert c.keepalive() is False
    assert c._remember_me_values() == before_jar
    assert (c.auth_reason, c.okta_session_expired_at, c.idle_gap_seconds) == first
    assert c.sso_renewals == 0
    assert c._renewal_admission.sequences == 1
    assert c._renewal_admission.blocked_reason(datetime.now(UTC)) == "cooldown"


def test_real_adapter_same_client_poll_waits_for_keepalive_transaction():
    portal = Portal(block_chart=True)
    c = client_with(portal)
    outcomes = []
    keep = threading.Thread(target=lambda: outcomes.append(c.keepalive()))
    poll_started = threading.Event()
    def poll():
        poll_started.set()
        outcomes.append(c.ensure_session())
    keep.start()
    poll_thread = threading.Thread(target=poll)
    try:
        assert portal.chart_entered.wait(3)
        before = len(portal.events)
        poll_thread.start()
        assert poll_started.wait(2)
        poll_thread.join(.1)
        assert poll_thread.is_alive()
        assert len(portal.events) == before
    finally:
        portal.release_all()
        keep.join(5)
        if poll_thread.ident:
            poll_thread.join(5)
    assert outcomes == [True, True]
    assert c._renewal_admission.sequences == 1


def test_future_timestamp_and_clock_rollback_refuse():
    now = datetime.now(UTC)
    state = RenewalAdmission.from_dict({
        "sequences": 1, "last_sequence_at": (now + timedelta(days=1)).isoformat(),
        "terminal_reason": None,
    })
    assert state.blocked_reason(now) == "cooldown"
    assert state.blocked_reason(now - timedelta(days=1)) == "cooldown"


async def test_actual_entry_reload_does_not_overlap_old_and_new_renewal(hass, monkeypatch):
    clients = []
    adapters = []
    real_client = PsegClient
    real_fetch = PsegClient.fetch_energy_data

    def factory(**kwargs):
        c = real_client(**kwargs)
        p = Portal(block_probe=not clients, block_renew=True)
        c.session.mount("https://", p)
        clients.append(c)
        adapters.append(p)
        return c

    def startup_fetch(c, days):
        # The first setup needs a confirmed existing session. The replacement setup
        # runs the entire real poll, including the actual admitted Remember Me leg.
        if c is not clients[0]:
            return real_fetch(c, days)
        return dict(DATA)

    monkeypatch.setattr(pkg, "PsegClient", factory)
    monkeypatch.setattr(real_client, "fetch_energy_data", startup_fetch)
    monkeypatch.setattr(PsegDataUpdateCoordinator, "async_record_statistics", AsyncMock())
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: "MM_SID=synthetic; MM_RememberMe=synthetic-a",
    })
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    old = hass.data[DOMAIN][entry.entry_id]
    old_task = asyncio.create_task(old._async_keepalive(None))
    new_task = None
    overlap = False
    try:
        assert await asyncio.to_thread(adapters[0].probe_entered.wait, 4)
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert old._stopped
        new_task = asyncio.create_task(hass.config_entries.async_setup(entry.entry_id))
        for _ in range(100):
            if len(adapters) > 1 and adapters[1].renew_entered.is_set():
                break
            await asyncio.sleep(.02)
        assert len(adapters) == 2 and adapters[1].renew_entered.is_set()
        adapters[0].probe_release.set()
        overlap = await asyncio.to_thread(adapters[0].renew_entered.wait, 3)
        print("RELOAD_PROOF", {"old_retired": old._stopped,
            "different_clients": clients[0] is not clients[1],
            "different_admissions": clients[0]._renewal_admission is not clients[1]._renewal_admission,
            "old_slots": clients[0]._renewal_admission.sequences,
            "new_slots": clients[1]._renewal_admission.sequences,
            "overlapping_renewal_http": overlap})
    finally:
        for p in adapters:
            p.release_all()
        await asyncio.wait_for(old_task, 5)
        if new_task:
            await asyncio.wait_for(new_task, 5)
        await hass.config_entries.async_unload(entry.entry_id)
    assert not overlap, "retired and replacement clients both dispatched renewal HTTP"


async def test_failed_first_refresh_persists_terminal_admission(hass, monkeypatch):
    clients = []
    real_client = PsegClient
    def factory(**kwargs):
        c = real_client(**kwargs)
        c.session.mount("https://", Portal(reject=True))
        clients.append(c)
        return c
    monkeypatch.setattr(pkg, "PsegClient", factory)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: "MM_SID=synthetic; MM_RememberMe=synthetic-a",
    })
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    first = clients[0]._renewal_admission.as_dict()
    persisted = entry.data.get(CONF_RENEWAL_ADMISSION)
    await hass.config_entries.async_reload(entry.entry_id)
    print("FIRST_REFRESH_PROOF", {"client_count": len(clients),
        "first_sequences": first["sequences"], "first_terminal": first["terminal_reason"],
        "persisted": persisted,
        "second_sequences": clients[-1]._renewal_admission.sequences})
    assert persisted == first, "failed startup discarded its spent slot and terminal refusal"


async def test_reload_after_reservation_carries_spent_slot(hass, monkeypatch):
    clients = []
    adapters = []
    real_client = PsegClient
    def factory(**kwargs):
        c = real_client(**kwargs)
        p = Portal(block_renew=not clients)
        c.session.mount("https://", p)
        clients.append(c)
        adapters.append(p)
        return c
    def startup_fetch(c, days):
        if c is not clients[0]:
            c.keepalive()
        return dict(DATA)
    monkeypatch.setattr(pkg, "PsegClient", factory)
    monkeypatch.setattr(real_client, "fetch_energy_data", startup_fetch)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: "MM_SID=synthetic; MM_RememberMe=synthetic-a",
    })
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    old = hass.data[DOMAIN][entry.entry_id]
    task = asyncio.create_task(old._async_keepalive(None))
    try:
        assert await asyncio.to_thread(adapters[0].renew_entered.wait, 4)
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 1
        assert await hass.config_entries.async_setup(entry.entry_id)
        new = hass.data[DOMAIN][entry.entry_id]
        assert new._renewal_admission.sequences == 1
        assert new._renewal_admission.blocked_reason(datetime.now(UTC)) == "cooldown"
        assert adapters[1].dash == 1
    finally:
        for p in adapters:
            p.release_all()
        await asyncio.wait_for(task, 5)
        await hass.config_entries.async_unload(entry.entry_id)


async def test_retired_keepalive_cannot_dismiss_replacement_auth_issue(hass, monkeypatch):
    from homeassistant.helpers import issue_registry as ir
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: "MM_SID=synthetic; MM_RememberMe=synthetic-a",
    })
    entry.add_to_hass(hass)
    old_client = client_with(Portal())
    old = PsegDataUpdateCoordinator(hass, old_client, dict(entry.data), config_entry=entry)
    old.auth_required = True
    old.status = "auth_required"
    entered = threading.Event()
    release = threading.Event()
    def export():
        entered.set()
        assert release.wait(6)
        return [], None
    monkeypatch.setattr(old_client, "keepalive", lambda: True)
    monkeypatch.setattr(old_client, "export_cookies_and_auth_reason", export)
    task = asyncio.create_task(old._async_keepalive(None))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        old.stop_keepalive()
        new = PsegDataUpdateCoordinator(hass, client_with(Portal()), dict(entry.data), config_entry=entry)
        new.auth_required = True
        new.status = "auth_required"
        new._raise_auth_issues("synthetic current auth refusal")
        issue_id = "reauth_required_" + entry.entry_id
        assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is not None
        release.set()
        await asyncio.wait_for(task, 4)
        assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is not None, "retired result deleted replacement's current repairs issue"
    finally:
        release.set()
        await asyncio.wait_for(task, 4)


async def test_replacement_uses_live_reservation_instead_of_stale_persisted_copy(hass):
    """Construction must never load a stale budget over the entry's shared one."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={})
    entry.add_to_hass(hass)
    old_client = client_with(Portal())
    old = PsegDataUpdateCoordinator(hass, old_client, {}, config_entry=entry)
    old_client._reserve_renewal_sequence()
    # No event-loop yield: reservation persistence is still queued and data empty.
    assert CONF_RENEWAL_ADMISSION not in entry.data
    replacement_client = client_with(Portal())
    replacement = PsegDataUpdateCoordinator(hass, replacement_client, {}, config_entry=entry)
    assert old._renewal_admission is replacement._renewal_admission
    assert replacement._renewal_admission.sequences == 1
    assert not old._renewal_runtime.is_active(old._renewal_token)
    with pytest.raises(Exception, match="busy"):
        replacement_client._reserve_renewal_sequence()
    old.stop_keepalive()
    replacement.stop_keepalive()
    await hass.async_block_till_done()
    assert entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 1


async def test_retirement_between_reservation_and_immediate_dispatch_sends_nothing(hass, monkeypatch):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={})
    entry.add_to_hass(hass)
    portal = Portal()
    c = client_with(portal)
    old = PsegDataUpdateCoordinator(hass, c, {}, config_entry=entry)
    reserve = c._reserve_renewal_sequence

    def retire_after_reservation():
        reserve()
        old.stop_keepalive()

    monkeypatch.setattr(c, "_reserve_renewal_sequence", retire_after_reservation)
    from custom_components.pseg.pseg_client import PsegRenewalDeferred
    with pytest.raises(PsegRenewalDeferred, match="retired"):
        c._renew_remember_me_admitted()
    assert portal.events == []
    assert c._renewal_admission.sequences == 1
    assert not c._renewal_admission.retry_eligible
    await hass.async_block_till_done()


async def test_metadata_handoff_failure_refuses_replacement(hass, monkeypatch):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={})
    entry.add_to_hass(hass)
    c = client_with(Portal())
    old = PsegDataUpdateCoordinator(hass, c, {}, config_entry=entry)
    from unittest.mock import patch
    with patch.object(hass.config_entries, "async_update_entry", side_effect=RuntimeError("synthetic handoff failure")):
        c._reserve_renewal_sequence()
        await hass.async_block_till_done()
    assert c._renewal_admission.uncertain
    old.stop_keepalive()
    portal = Portal()
    replacement_client = client_with(portal)
    replacement = PsegDataUpdateCoordinator(hass, replacement_client, {}, config_entry=entry)
    assert replacement_client.keepalive() is False
    assert portal.dash == 1
    assert replacement._renewal_admission.uncertain
    replacement.stop_keepalive()


@pytest.mark.parametrize("poll", [False, True])
def test_expiry_probe_rotation_rolls_back_for_poll_and_keepalive(poll):
    portal = Portal(rotate_probe=True, fail_renew=True)
    c = client_with(portal)
    before = c._remember_me_values()
    if poll:
        with pytest.raises(PsegTransientError):
            c.fetch_energy_data()
    else:
        assert c.keepalive() is False
    assert c._remember_me_values() == before
    assert c._renewal_admission.sequences == 1
    assert c._renewal_admission.retry_eligible
    assert c.sso_renewals == 0
    assert not c.cookies_confirmed


def test_poll_meter_mismatch_cannot_publish_rotation():
    c = client_with(Portal(rotate_renew=True))
    c.set_expected_meter_ids({"99999"})
    before = c._remember_me_values()
    with pytest.raises(PsegTransientError, match="did not confirm"):
        c.fetch_energy_data()
    assert c._remember_me_values() == before
    assert c._renewal_admission.sequences == 1
    assert c.sso_renewals == 0
    assert c.last_sso_renewal is None
    assert not c.cookies_confirmed


def test_unknown_failure_never_earns_transient_retry(monkeypatch):
    c = client_with(Portal())
    def unknown_failure(**kwargs):
        raise RuntimeError("synthetic unknown outcome")
    monkeypatch.setattr(c, "_renew_remember_me_sequence", unknown_failure)
    with pytest.raises(RuntimeError, match="unknown outcome"):
        c._renew_remember_me_admitted()
    assert c._renewal_admission.sequences == 1
    assert c._renewal_admission.blocked_reason(datetime.now(UTC) + timedelta(minutes=16)) == "exhausted"


async def test_fresh_human_remember_cookie_setup_uses_its_account_proof(hass, monkeypatch):
    """An expired pasted MM_SID must not require a not-yet-created entry identity."""
    from custom_components.pseg import config_flow
    from custom_components.pseg.config_flow import PsegConfigFlow
    clients = []
    adapters = []

    def factory(**kwargs):
        c = PsegClient(**kwargs)
        p = Portal()
        c.session.mount("https://", p)
        clients.append(c)
        adapters.append(p)
        return c

    monkeypatch.setattr(config_flow, "PsegClient", factory)
    flow = PsegConfigFlow()
    flow.hass = hass
    errors, c, meter, meter_ids = await asyncio.wait_for(
        flow._async_validate_and_extract_meter(
            "", "MM_SID=synthetic; MM_RememberMe=synthetic-a"
        ), 5
    )
    assert errors == {}
    assert meter == METER and METER in meter_ids
    assert c is clients[0] and c.sso_renewals == 1
    assert adapters[0].chart_entered.is_set()
    assert all(path != "/Home/Login" for _, path, _ in adapters[0].events)

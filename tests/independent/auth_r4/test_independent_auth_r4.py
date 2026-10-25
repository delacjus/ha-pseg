"""Final independent auth review. Synthetic in-process HTTP only."""
import asyncio
import copy
from datetime import UTC, datetime
from http.client import HTTPMessage
import threading
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests

import custom_components.pseg as pkg
from custom_components.pseg.const import (
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
    USAGE_INTERVAL_HOURLY,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient
from custom_components.pseg.renewal_admission import rearm_entry_admission
from tests.test_auth_review_r3_regressions import (
    METER,
    SEED,
    Portal,
    abort_flows,
    make_client,
)


@pytest.fixture(autouse=True)
def enabled(enable_custom_integrations):
    yield


class OptionalFailurePortal(Portal):
    def __init__(self, stage, status, poisoned_name):
        super().__init__([
            {"kind": "login"},
            {"kind": "dash", "set_cookie": [
                "MM_SID=final-confirmed-sid; Path=/",
                "MM_RememberMe=final-confirmed-generation; Path=/",
                "review_aux=final-confirmed-aux; Path=/",
            ]},
            {"kind": "dash"},
        ])
        self.stage = stage
        self.status = status
        self.poisoned_name = poisoned_name
        self.hourly = False
        self.failed_responses = 0

    def send(self, request, **kwargs):
        path = urlparse(request.url).path
        if request.method == "POST" and path == "/Dashboard/Chart":
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            self.hourly = parse_qs(body or "").get("UsageInterval") == [str(USAGE_INTERVAL_HOURLY)]
        response = super().send(request, **kwargs)
        if self.hourly and path == self.stage:
            self.failed_responses += 1
            response.status_code = self.status
            if self.poisoned_name is not None:
                response.raw._original_response.msg.add_header(
                    "Set-Cookie", f"{self.poisoned_name}=final-failed-response; Path=/"
                )
        return response


@pytest.mark.parametrize("stage", ["/Dashboard/Chart", "/Dashboard/ChartData"])
@pytest.mark.parametrize("status", [429, 500])
@pytest.mark.parametrize("poisoned_name", [None, "MM_SID", "MM_RememberMe", "review_aux"])
async def test_optional_hourly_failed_response_cannot_replace_proof_jar(
    hass, stage, status, poisoned_name
):
    portal = OptionalFailurePortal(stage, status, poisoned_name)
    client = make_client(portal)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    snapshots = []
    capture = client._capture_confirmed_session

    def captured():
        capture()
        snapshots.append(copy.deepcopy(client.pending_confirmed_snapshot()))

    client._capture_confirmed_session = captured
    try:
        data = await coord._async_update_data()
        assert portal.failed_responses == 1
        assert data["daily_records"]
        assert data["hourly_granularity"] == "unavailable"
        assert len(snapshots) == 1
        assert snapshots[0]["cookies_confirmed"] is True
        assert client._renewal_admission.sequences == 0
        # Compare whole jar to the exact post-proof snapshot, not a cookie subset.
        assert entry.data["cookies"] == snapshots[0]["cookies"], (
            "a failed optional hourly response replaced the exact proven jar"
        )
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


class RetiredPasswordPortal(Portal):
    def __init__(self, remember, gate="dashboard"):
        # Remember Me rejection takes: probe, renewal, landing, renewal; then the
        # optional saved-password fallback must still respect retirement.
        super().__init__([{"kind": "login"}] * (3 if remember else 1))
        self.block_at = 2 if remember else 1
        self.entered = threading.Event()
        self.release = threading.Event()
        self.dashboard_count = 0
        self.root_count = 0
        self.gate = gate
        self.form_root = 2 if remember else 1

    def send(self, request, **kwargs):
        if request.method == "GET" and urlparse(request.url).path == "/Dashboard":
            self.dashboard_count += 1
            if self.gate == "dashboard" and self.dashboard_count == self.block_at:
                self.entered.set()
                assert self.release.wait(5), "scratch HTTP gate timed out"
        if request.method == "GET" and urlparse(request.url).path == "/":
            self.root_count += 1
            if self.gate == "login_form" and self.root_count == self.form_root:
                self.entered.set()
                assert self.release.wait(5), "scratch login-form gate timed out"
        return super().send(request, **kwargs)


@pytest.mark.parametrize("remember", [False, True])
@pytest.mark.parametrize("boundary", ["real_unload", "human_same_cookies"])
@pytest.mark.parametrize("gate", ["dashboard", "login_form"])
async def test_real_unload_retires_saved_password_fallback(hass, monkeypatch, remember, boundary, gate):
    clients = []
    portals = []
    real = PsegClient
    original_fetch = real.fetch_energy_data

    def factory(**kwargs):
        client = real(**kwargs)
        portal = RetiredPasswordPortal(remember, gate)
        client.session.mount("https://", portal)
        clients.append(client)
        portals.append(portal)
        return client

    def startup_fetch(client, days):
        return {"meter": "Meter #" + METER, "meter_ids": [METER],
                "daily_records": [], "history_14d": [], "hourly_records": []}

    monkeypatch.setattr(pkg, "PsegClient", factory)
    monkeypatch.setattr(real, "fetch_energy_data", startup_fetch)
    seed = SEED if remember else "MM_SID=final-existing-session"
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: seed,
        CONF_MYMETER_EMAIL: "final@example.invalid",
        CONF_MYMETER_PASSWORD: "final-synthetic",
    })
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]
    # First refresh only was stubbed. The in-flight old poll below uses the real
    # production client fetch, coordinator failure handoff and ownership checks.
    clients[0].fetch_energy_data = lambda days: original_fetch(clients[0], days)
    task = asyncio.create_task(coord._async_update_data())
    try:
        assert await asyncio.to_thread(portals[0].entered.wait, 3)
        if boundary == "real_unload":
            assert await hass.config_entries.async_unload(entry.entry_id)
            assert coord._stopped is True
        else:
            # The completed-human handoff invalidates the token even when the
            # confirmed cookie values are unchanged; no source or live auth call.
            state = rearm_entry_admission(
                hass, entry.entry_id, entry.data.get("renewal_admission"),
                "renewal_admission" in entry.data, now=datetime.now(UTC),
            )
            hass.config_entries.async_update_entry(
                entry, data={**entry.data, "renewal_admission": state}
            )
        assert coord._renewal_runtime.is_active(coord._renewal_token) is False
        portals[0].release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        assert portals[0].password_posts() == 0, (
            "a retired owner dispatched a saved-password POST after actual HA unload"
        )
    finally:
        portals[0].release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        if boundary == "human_same_cookies":
            await hass.config_entries.async_unload(entry.entry_id)
        coord.stop_keepalive()
        abort_flows(hass)


class AfterProofGatePortal(Portal):
    def __init__(self):
        super().__init__([
            {"kind": "login"},
            {"kind": "dash", "set_cookie": [
                "MM_SID=final-confirmed-sid; Path=/",
                "MM_RememberMe=final-confirmed-generation; Path=/",
            ]},
            {"kind": "dash"},
        ])
        self.setup_count = 0
        self.entered = threading.Event()
        self.release = threading.Event()

    def send(self, request, **kwargs):
        if request.method == "POST" and urlparse(request.url).path == "/Dashboard/Chart":
            self.setup_count += 1
            if self.setup_count == 2:
                self.entered.set()
                assert self.release.wait(5), "scratch post-proof gate timed out"
                raise requests.Timeout("synthetic post-proof timeout")
        return super().send(request, **kwargs)


@pytest.mark.parametrize("boundary", ["cancel_poll", "stop_during_poll", "cancel_setup"])
async def test_confirmation_handoff_during_cancel_or_stop(hass, monkeypatch, boundary):
    portal = AfterProofGatePortal()
    client = make_client(portal)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    if boundary == "cancel_setup":
        monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)
        coord = None
        task = asyncio.create_task(hass.config_entries.async_setup(entry.entry_id))
    else:
        coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
        task = asyncio.create_task(coord._async_update_data())
    try:
        assert await asyncio.to_thread(portal.entered.wait, 3)
        proof = copy.deepcopy(client.pending_confirmed_snapshot())
        assert proof is not None and proof["cookies_confirmed"]
        if boundary.startswith("cancel"):
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        else:
            coord.stop_keepalive()
        assert entry.data["cookies"] == proof["cookies"]
        assert entry.data["renewal_admission"]["sequences"] == 0
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        await hass.async_block_till_done()
        assert entry.data["cookies"] == proof["cookies"]
    finally:
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        if coord:
            coord.stop_keepalive()
        abort_flows(hass)


class RetiredSsoPortal(RetiredPasswordPortal):
    def __init__(self, gate):
        super().__init__(remember=False, gate=gate)

    def send(self, request, **kwargs):
        path = urlparse(request.url).path
        if path in {"/Saml/okta-prod/SignIn", "/Saml/review-acs"}:
            self.events.append((request.method, path))
            if self.gate == "saml_form" and request.method == "GET":
                self.entered.set()
                assert self.release.wait(5), "scratch SAML-form gate timed out"
            response = requests.Response()
            response.status_code = 200
            response.url = request.url
            response.request = request
            response._content_consumed = True
            response._content = (
                b'<form action="/Saml/review-acs">'
                b'<input name="SAMLResponse" value="synthetic-review-assertion"></form>'
                if request.method == "GET" else b"ok"
            )
            response.raw = SimpleNamespace(
                _original_response=SimpleNamespace(msg=HTTPMessage())
            )
            return response
        return super().send(request, **kwargs)


@pytest.mark.parametrize("gate", ["dashboard", "saml_form"])
async def test_real_unload_retires_sso_fallback(hass, monkeypatch, gate):
    portal = RetiredSsoPortal(gate)
    real = PsegClient
    original_fetch = real.fetch_energy_data
    clients = []

    def factory(**kwargs):
        client = real(**kwargs)
        client.session.mount("https://", portal)
        clients.append(client)
        return client

    monkeypatch.setattr(pkg, "PsegClient", factory)
    monkeypatch.setattr(real, "fetch_energy_data", lambda client, days: {
        "meter": "Meter #" + METER, "meter_ids": [METER],
        "daily_records": [], "history_14d": [], "hourly_records": [],
    })
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: "MM_SID=final-existing-session",
        CONF_OKTA_COOKIES: "idx=final-synthetic-okta-session",
    })
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]
    clients[0].fetch_energy_data = lambda days: original_fetch(clients[0], days)
    task = asyncio.create_task(coord._async_update_data())
    try:
        assert await asyncio.to_thread(portal.entered.wait, 3)
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert coord._renewal_runtime.is_active(coord._renewal_token) is False
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        assert (portal.count("GET", "/Saml/okta-prod/SignIn"),
                portal.count("POST", "/Saml/review-acs")) == (
                    1 if gate == "saml_form" else 0, 0
                ), "a retired owner dispatched SSO requests after actual HA unload"
    finally:
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        coord.stop_keepalive()
        abort_flows(hass)


pytestmark = pytest.mark.independent

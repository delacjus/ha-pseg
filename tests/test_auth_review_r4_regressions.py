"""R4 auth review regression tests (whole-jar quarantine and retired fallback guards)."""

import asyncio
import copy
from datetime import UTC, datetime
from http.client import HTTPMessage
import json
import threading
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

from homeassistant.core import HomeAssistant
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
    PORTAL_HOST,
    USAGE_INTERVAL_HOURLY,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient, PsegTransientError
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
    """Enable custom integrations in this module."""
    yield


class OptionalFailurePortal(Portal):
    """Synthetic portal that injects a failed response + Set-Cookie on the hourly leg."""

    def __init__(self, stage: str, status: int, poisoned_name: str | None) -> None:
        super().__init__(
            [
                {"kind": "login"},
                {
                    "kind": "dash",
                    "set_cookie": [
                        "MM_SID=final-confirmed-sid; Path=/",
                        "MM_RememberMe=final-confirmed-generation; Path=/",
                        "review_aux=final-confirmed-aux; Path=/",
                    ],
                },
                {"kind": "dash"},
            ]
        )
        self.stage = stage
        self.status = status
        self.poisoned_name = poisoned_name
        self.hourly = False
        self.failed_responses = 0

    def send(self, request, **kwargs):
        path = urlparse(request.url).path
        if request.method == "POST" and path == "/Dashboard/Chart":
            body = (
                request.body.decode()
                if isinstance(request.body, bytes)
                else request.body
            )
            self.hourly = parse_qs(body or "").get("UsageInterval") == [
                str(USAGE_INTERVAL_HOURLY)
            ]
        response = super().send(request, **kwargs)
        if self.hourly and path == self.stage:
            self.failed_responses += 1
            response.status_code = self.status
            if self.poisoned_name is not None:
                response.raw._original_response.msg.add_header(
                    "Set-Cookie",
                    f"{self.poisoned_name}=final-failed-response; Path=/",
                )
        return response


@pytest.mark.parametrize("stage", ["/Dashboard/Chart", "/Dashboard/ChartData"])
@pytest.mark.parametrize("status", [429, 500])
@pytest.mark.parametrize(
    "poisoned_name", [None, "MM_SID", "MM_RememberMe", "review_aux"]
)
async def test_optional_hourly_failed_response_cannot_replace_proof_jar(
    hass: HomeAssistant,
    stage: str,
    status: int,
    poisoned_name: str | None,
) -> None:
    """Failed optional hourly responses must roll back all Set-Cookie mutations."""
    portal = OptionalFailurePortal(stage, status, poisoned_name)
    client = make_client(portal)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED},
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    snapshots = []
    capture = client._capture_confirmed_session

    def captured() -> None:
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
        assert client.export_cookies() == snapshots[0]["cookies"]
        assert client._remember_me_seen == frozenset({"final-confirmed-generation"})
        assert entry.data["cookies"] == snapshots[0]["cookies"], (
            "a failed optional hourly response replaced the exact proven jar"
        )
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


class Setup200ThenDataFailPortal(Portal):
    """Hourly Chart setup returns 200 with Set-Cookie, then ChartData fails."""

    def __init__(self, data_failure: str | int) -> None:
        super().__init__(
            [
                {"kind": "login"},
                {
                    "kind": "dash",
                    "set_cookie": [
                        "MM_SID=final-confirmed-sid; Path=/",
                        "MM_RememberMe=final-confirmed-generation; Path=/",
                        "review_aux=final-confirmed-aux; Path=/",
                    ],
                },
                {"kind": "dash"},
            ]
        )
        self.data_failure = data_failure
        self.hourly = False

    def send(self, request, **kwargs):
        path = urlparse(request.url).path
        if request.method == "POST" and path == "/Dashboard/Chart":
            body = (
                request.body.decode()
                if isinstance(request.body, bytes)
                else request.body
            )
            self.hourly = parse_qs(body or "").get("UsageInterval") == [
                str(USAGE_INTERVAL_HOURLY)
            ]
        response = super().send(request, **kwargs)
        if self.hourly and path == "/Dashboard/Chart":
            for hdr in (
                "MM_SID=unconfirmed-setup-sid; Path=/",
                "MM_RememberMe=unconfirmed-setup-gen; Path=/",
                "review_aux=unconfirmed-setup-aux; Path=/",
            ):
                response.raw._original_response.msg.add_header("Set-Cookie", hdr)
        elif self.hourly and path == "/Dashboard/ChartData":
            if isinstance(self.data_failure, int):
                response.status_code = self.data_failure
            else:
                response._content = b'{"Data": null, "AjaxResults": []}'
        return response


@pytest.mark.parametrize("data_failure", [429, 500, "empty_data"])
async def test_optional_hourly_setup_200_cookie_is_rolled_back_when_chart_data_fails(
    hass: HomeAssistant,
    data_failure: str | int,
) -> None:
    """Cookies set by a 200 OK hourly Chart setup are rolled back if ChartData fails."""
    portal = Setup200ThenDataFailPortal(data_failure)
    client = make_client(portal)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED},
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    snapshots = []
    capture = client._capture_confirmed_session

    def captured() -> None:
        capture()
        snapshots.append(copy.deepcopy(client.pending_confirmed_snapshot()))

    client._capture_confirmed_session = captured
    try:
        data = await coord._async_update_data()
        assert data["daily_records"]
        assert data["hourly_granularity"] == "unavailable"
        assert len(snapshots) == 1
        assert client.export_cookies() == snapshots[0]["cookies"]
        assert entry.data["cookies"] == snapshots[0]["cookies"]
        assert client._remember_me_seen == frozenset({"final-confirmed-generation"})
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


class ConfirmedHourlyPortal(Portal):
    """Portal where the optional hourly leg succeeds and sets legitimate cookies."""

    def __init__(self) -> None:
        super().__init__(
            [
                {"kind": "login"},
                {
                    "kind": "dash",
                    "set_cookie": [
                        "MM_SID=final-confirmed-sid; Path=/",
                        "MM_RememberMe=final-confirmed-generation; Path=/",
                        "review_aux=final-confirmed-aux; Path=/",
                    ],
                },
                {"kind": "dash"},
            ]
        )
        self.hourly = False

    def send(self, request, **kwargs):
        path = urlparse(request.url).path
        if request.method == "POST" and path == "/Dashboard/Chart":
            body = (
                request.body.decode()
                if isinstance(request.body, bytes)
                else request.body
            )
            self.hourly = parse_qs(body or "").get("UsageInterval") == [
                str(USAGE_INTERVAL_HOURLY)
            ]
        response = super().send(request, **kwargs)
        if self.hourly and path == "/Dashboard/ChartData":
            payload = {
                "Data": {
                    "series": [
                        {
                            "name": f"Meter #{METER}",
                            "data": [
                                {
                                    "x": 1792468800000,
                                    "y": 1.25,
                                    "hs": {
                                        "start": "2026-10-20T00:00:00-04:00",
                                        "end": "2026-10-20T01:00:00-04:00",
                                    },
                                }
                            ],
                        }
                    ]
                }
            }
            response._content = json.dumps(payload).encode()
            for hdr in (
                "MM_RememberMe=confirmed-hourly-gen; Path=/",
                "review_aux=confirmed-hourly-aux; Path=/",
            ):
                response.raw._original_response.msg.add_header("Set-Cookie", hdr)
        return response


async def test_successful_hourly_leg_adopts_confirmed_cookies_and_updates_generation(
    hass: HomeAssistant,
) -> None:
    """A confirmed hourly leg may legitimately slide cookies through the confirmed path."""
    portal = ConfirmedHourlyPortal()
    client = make_client(portal)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED},
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    try:
        data = await coord._async_update_data()
        assert data["hourly_records"]
        persisted = {c["name"]: c["value"] for c in entry.data["cookies"]}
        assert persisted["MM_SID"] == "final-confirmed-sid"
        assert persisted["MM_RememberMe"] == "confirmed-hourly-gen"
        assert persisted["review_aux"] == "confirmed-hourly-aux"
        assert client._remember_me_seen == frozenset({"confirmed-hourly-gen"})
        assert client.pending_confirmed_snapshot() is None
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


async def test_persist_cookies_refuses_unconfirmed_live_jar_mutation_and_keeps_confirmed_snapshot(
    hass: HomeAssistant,
) -> None:
    """_async_persist_cookies refuses unconfirmed live-jar drift and preserves the snapshot."""
    portal = Portal(
        [
            {"kind": "login"},
            {
                "kind": "dash",
                "set_cookie": [
                    "MM_SID=final-confirmed-sid; Path=/",
                    "MM_RememberMe=final-confirmed-generation; Path=/",
                    "review_aux=final-confirmed-aux; Path=/",
                ],
            },
            {"kind": "dash"},
        ]
    )
    client = make_client(portal)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED},
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    try:
        await hass.async_add_executor_job(client._get_verification_token)
        snapshot = copy.deepcopy(client.pending_confirmed_snapshot())
        assert snapshot is not None
        # Simulate an unconfirmed response mutating the live jar after confirmation.
        client.session.cookies.set(
            "review_aux", "unconfirmed-live-mutation", domain=PORTAL_HOST, path="/"
        )
        await coord._async_persist_cookies()
        # The unconfirmed live jar must not be persisted and must not clear the snapshot.
        assert client.pending_confirmed_snapshot() is not None
        coord._persist_confirmed_session()
        assert entry.data["cookies"] == snapshot["cookies"]
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


async def test_failed_history_backfill_chunk_rolls_back_set_cookie_mutations(
    hass: HomeAssistant,
) -> None:
    """A failed history backfill chunk rolls back any Set-Cookie headers it received."""
    portal = Portal(
        [
            {
                "kind": "dash",
                "set_cookie": [
                    "MM_SID=confirmed-sid; Path=/",
                    "MM_RememberMe=confirmed-gen; Path=/",
                    "review_aux=confirmed-aux; Path=/",
                ],
            }
        ]
    )
    orig_send = portal.send

    def send_with_failed_chunk(request, **kwargs):
        resp = orig_send(request, **kwargs)
        if urlparse(request.url).path == "/Dashboard/Chart":
            resp.status_code = 500
            for hdr in (
                "MM_SID=chunk-poison-sid; Path=/",
                "MM_RememberMe=chunk-poison-gen; Path=/",
                "review_aux=chunk-poison-aux; Path=/",
            ):
                resp.raw._original_response.msg.add_header("Set-Cookie", hdr)
        return resp

    portal.send = send_with_failed_chunk
    client = make_client(portal)
    with pytest.raises(PsegTransientError):
        await hass.async_add_executor_job(
            client.fetch_history_range, "2026-10-01", "2026-10-05"
        )
    exported = {c["name"]: c["value"] for c in client.export_cookies()}
    assert exported["MM_SID"] == "confirmed-sid"
    assert exported["MM_RememberMe"] == "confirmed-gen"
    assert exported["review_aux"] == "confirmed-aux"
    assert client._remember_me_seen == frozenset({"confirmed-gen"})


class RetiredPasswordPortal(Portal):
    """Synthetic portal that parks at the dashboard probe/renewal or login form GET."""

    def __init__(self, remember: bool, gate: str = "dashboard") -> None:
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
async def test_real_unload_retires_saved_password_fallback(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    remember: bool,
    boundary: str,
    gate: str,
) -> None:
    """A retired entry owner never dispatches a saved-password login form or POST."""
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
        return {
            "meter": "Meter #" + METER,
            "meter_ids": [METER],
            "daily_records": [],
            "history_14d": [],
            "hourly_records": [],
        }

    monkeypatch.setattr(pkg, "PsegClient", factory)
    monkeypatch.setattr(real, "fetch_energy_data", startup_fetch)
    seed = SEED if remember else "MM_SID=final-existing-session"
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={
            CONF_PORTAL_COOKIES: seed,
            CONF_MYMETER_EMAIL: "final@example.invalid",
            CONF_MYMETER_PASSWORD: "final-synthetic",
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]
    clients[0].fetch_energy_data = lambda days: original_fetch(clients[0], days)
    task = asyncio.create_task(coord._async_update_data())
    try:
        assert await asyncio.to_thread(portals[0].entered.wait, 3)
        if boundary == "real_unload":
            assert await hass.config_entries.async_unload(entry.entry_id)
            assert coord._stopped is True
        else:
            state = rearm_entry_admission(
                hass,
                entry.entry_id,
                entry.data.get("renewal_admission"),
                "renewal_admission" in entry.data,
                now=datetime.now(UTC),
            )
            hass.config_entries.async_update_entry(
                entry, data={**entry.data, "renewal_admission": state}
            )
        assert coord._renewal_runtime.is_active(coord._renewal_token) is False
        portals[0].release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        if gate == "dashboard":
            assert portals[0].root_count == 0
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
    """Portal that gates on the post-proof daily chart setup and then times out."""

    def __init__(self) -> None:
        super().__init__(
            [
                {"kind": "login"},
                {
                    "kind": "dash",
                    "set_cookie": [
                        "MM_SID=final-confirmed-sid; Path=/",
                        "MM_RememberMe=final-confirmed-generation; Path=/",
                    ],
                },
                {"kind": "dash"},
            ]
        )
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


@pytest.mark.parametrize(
    "boundary", ["cancel_poll", "stop_during_poll", "cancel_setup"]
)
async def test_confirmation_handoff_during_cancel_or_stop(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    """Confirmed renewal snapshots persist across cancel and stop boundaries."""
    portal = AfterProofGatePortal()
    client = make_client(portal)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED},
    )
    entry.add_to_hass(hass)
    if boundary == "cancel_setup":
        monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)
        coord = None
        task = asyncio.create_task(hass.config_entries.async_setup(entry.entry_id))
    else:
        coord = PsegDataUpdateCoordinator(
            hass, client, dict(entry.data), config_entry=entry
        )
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
    """Synthetic portal that gates on the dashboard probe or SAML form GET."""

    def __init__(self, gate: str) -> None:
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
                if request.method == "GET"
                else b"ok"
            )
            response.raw = SimpleNamespace(
                _original_response=SimpleNamespace(msg=HTTPMessage())
            )
            return response
        return super().send(request, **kwargs)


@pytest.mark.parametrize("boundary", ["real_unload", "human_same_cookies"])
@pytest.mark.parametrize("gate", ["dashboard", "saml_form"])
async def test_real_unload_retires_sso_fallback(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    gate: str,
) -> None:
    """A retired entry owner never dispatches SAML SignIn GET or ACS POST."""
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
    monkeypatch.setattr(
        real,
        "fetch_energy_data",
        lambda client, days: {
            "meter": "Meter #" + METER,
            "meter_ids": [METER],
            "daily_records": [],
            "history_14d": [],
            "hourly_records": [],
        },
    )
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={
            CONF_PORTAL_COOKIES: "MM_SID=final-existing-session",
            CONF_OKTA_COOKIES: "idx=final-synthetic-okta-session",
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]
    clients[0].fetch_energy_data = lambda days: original_fetch(clients[0], days)
    task = asyncio.create_task(coord._async_update_data())
    try:
        assert await asyncio.to_thread(portal.entered.wait, 3)
        if boundary == "real_unload":
            assert await hass.config_entries.async_unload(entry.entry_id)
        else:
            state = rearm_entry_admission(
                hass,
                entry.entry_id,
                entry.data.get("renewal_admission"),
                "renewal_admission" in entry.data,
                now=datetime.now(UTC),
            )
            hass.config_entries.async_update_entry(
                entry, data={**entry.data, "renewal_admission": state}
            )
        assert coord._renewal_runtime.is_active(coord._renewal_token) is False
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        assert (
            portal.count("GET", "/Saml/okta-prod/SignIn"),
            portal.count("POST", "/Saml/review-acs"),
        ) == (
            1 if gate == "saml_form" else 0,
            0,
        ), "a retired owner dispatched SSO requests after retirement"
    finally:
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        if boundary == "human_same_cookies":
            await hass.config_entries.async_unload(entry.entry_id)
        coord.stop_keepalive()
        abort_flows(hass)


async def test_direct_entrypoints_refuse_retired_owner_and_allow_fresh_human_client(
    hass: HomeAssistant,
) -> None:
    """Retired coordinator clients refuse automatic entrypoints; fresh manual clients work."""
    portal = Portal([{"kind": "dash"}])
    client = PsegClient(
        portal_cookies=SEED,
        okta_cookies="idx=final-okta",
        email="final@example.invalid",
        password="final-password",
    )
    client.session.mount("https://", portal)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED},
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    coord.stop_keepalive()

    for call in (
        client.ensure_session,
        client.login_local,
        client.renew_sso,
        client.fetch_energy_data,
    ):
        with pytest.raises(PsegTransientError, match="retired"):
            await hass.async_add_executor_job(call)
    assert await hass.async_add_executor_job(client.keepalive) is False
    assert portal.events == []

    # Fresh unattached human client (as in config_flow) is never blocked by retirement.
    manual_portal = Portal([{"kind": "dash"}, {"kind": "dash"}])
    manual_client = PsegClient(
        portal_cookies=SEED,
        email="final@example.invalid",
        password="final-password",
    )
    manual_client.session.mount("https://", manual_portal)
    assert await hass.async_add_executor_job(manual_client.ensure_session) is True
    assert await hass.async_add_executor_job(manual_client.login_local) is True

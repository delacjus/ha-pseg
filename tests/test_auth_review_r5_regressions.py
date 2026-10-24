"""Authentication review R5 regression tests for systemic request/cookie boundaries."""

from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime
from http.client import HTTPMessage
import json
import threading
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse

from homeassistant.config_entries import SOURCE_USER, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.update_coordinator import UpdateFailed
from homeassistant.util import dt as dt_util
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
from requests.adapters import BaseAdapter
from test_auth_review_r3_regressions import (
    METER,
    SEED,
    Portal,
    abort_flows,
    make_client,
)

import custom_components.pseg as pkg
import custom_components.pseg.config_flow as flow_mod
from custom_components.pseg.const import (
    CONF_KNOWN_METER_IDS,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
    PORTAL_BASE_URL,
    PORTAL_HOST,
    USAGE_INTERVAL_HOURLY,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import (
    PsegClient,
    PsegTransientError,
    _MeterRecord,
)
from custom_components.pseg.renewal_admission import rearm_entry_admission


@pytest.fixture(autouse=True)
def _enable_custom_integrations(enable_custom_integrations: Any) -> Any:
    """Enable custom integrations for real Home Assistant entry setup/unload tests."""
    yield


PAYLOADS: dict[str, Any] = {
    "empty_json": {},
    "empty_series": {"Data": {"series": []}},
    "no_matching_meter": {"Data": {"series": [{"name": "Temperature", "data": []}]}},
    "empty_meter": {"Data": {"series": [{"name": "Meter #" + METER, "data": []}]}},
    "invalid_points": {
        "Data": {
            "series": [
                {"name": "Meter #" + METER, "data": [{"x": None, "y": -1}]}
            ]
        }
    },
    "root_list": [],
    "healthy": {
        "Data": {
            "series": [
                {
                    "name": "Meter #" + METER,
                    "data": [
                        {
                            "x": 1792540800000,
                            "y": 3.0,
                            "hs": {
                                "start": "2026-10-21T00:00:00+00:00",
                                "end": "2026-10-21T01:00:00+00:00",
                            },
                        }
                    ],
                }
            ]
        }
    },
}


class PayloadPortal(Portal):
    """Synthetic portal that injects custom hourly payloads and Set-Cookie headers."""

    def __init__(self, payload: str, name: str, renewal: bool = True) -> None:
        super().__init__(
            [
                *(
                    [
                        {"kind": "login"},
                        {
                            "kind": "dash",
                            "set_cookie": [
                                "MM_SID=r5-proven; Path=/",
                                "MM_RememberMe=r5-proven-generation; Path=/",
                                "review_aux=r5-proven-aux; Path=/",
                            ],
                        },
                    ]
                    if renewal
                    else []
                ),
                {"kind": "dash"},
            ]
        )
        self.payload = payload
        self.name = name
        self.hourly = False
        self.injected = 0

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
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
            self.injected += 1
            response._content = json.dumps(PAYLOADS[self.payload]).encode()
            response.raw._original_response.msg.add_header(
                "Set-Cookie", f"{self.name}=r5-new-response; Path=/"
            )
        return response


@pytest.mark.parametrize(
    "payload",
    [
        "empty_json",
        "empty_series",
        "no_matching_meter",
        "empty_meter",
        "invalid_points",
        "root_list",
    ],
)
@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
async def test_invalid_hourly_200_does_not_replace_proven_whole_jar(
    hass: HomeAssistant, payload: str, cookie: str
) -> None:
    """R5-C: Invalid or empty hourly 200 payloads roll back cookies and use daily fallback."""
    portal = PayloadPortal(payload, cookie)
    client = make_client(portal)
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id=METER, data={CONF_PORTAL_COOKIES: SEED}
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    proof: list[dict[str, Any]] = []
    capture = client._capture_confirmed_session

    def captured() -> None:
        capture()
        proof.append(copy.deepcopy(client.pending_confirmed_snapshot()))

    client._capture_confirmed_session = captured  # type: ignore[method-assign]
    try:
        data = await coord._async_update_data()
        assert portal.injected == 1
        assert data["daily_records"] and data["statistics_granularity"] == "daily"
        assert proof and proof[0]["cookies_confirmed"]
        assert entry.data["cookies"] == proof[0]["cookies"], (
            "invalid optional 200 response overwrote the proven whole jar"
        )
        assert client.export_cookies() == proof[0]["cookies"], (
            "invalid optional 200 response stayed in the live whole jar"
        )
        assert client._remember_me_seen == frozenset(
            c["value"] for c in proof[0]["cookies"] if c["name"] == "MM_RememberMe"
        )
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


async def test_malformed_daily_and_history_root_list_rolls_back_jar(
    hass: HomeAssistant,
) -> None:
    """R5-C: Root JSON list on daily chart or history backfill raises PsegTransientError and rolls back cookies."""
    portal = Portal(
        [
            {
                "kind": "dash",
                "set_cookie": [
                    "MM_SID=r5-daily-good; Path=/",
                    "MM_RememberMe=r5-daily-gen; Path=/",
                    "review_aux=r5-daily-aux; Path=/",
                ],
            },
            {"kind": "dash"},
        ]
    )
    orig_send = portal.send

    def send_root_list(request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        resp = orig_send(request, **kwargs)
        if urlparse(request.url).path == "/Dashboard/ChartData":
            resp._content = b"[]"
            resp.raw._original_response.msg.add_header(
                "Set-Cookie", "review_aux=r5-root-list-poison; Path=/"
            )
        return resp

    portal.send = send_root_list  # type: ignore[method-assign]
    client = make_client(portal)
    with pytest.raises(PsegTransientError):
        await hass.async_add_executor_job(client.fetch_energy_data, 14)
    assert any(
        c["name"] == "review_aux" and c["value"] == "r5-daily-aux"
        for c in client.export_cookies()
    )

    with pytest.raises(PsegTransientError):
        await hass.async_add_executor_job(
            client.fetch_history_range, "2026-10-01", "2026-10-03"
        )
    assert any(
        c["name"] == "review_aux" and c["value"] == "r5-daily-aux"
        for c in client.export_cookies()
    )


class RedirectSsoPortal(Portal):
    """Synthetic SSO portal that responds with HTTP 307 on SAML ACS POST."""

    def __init__(self) -> None:
        super().__init__([{"kind": "login"}])
        self.entered = threading.Event()
        self.release = threading.Event()

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        path = urlparse(request.url).path
        if path not in {"/Saml/okta-prod/SignIn", "/Saml/r5-acs", "/Saml/r5-next"}:
            return super().send(request, **kwargs)
        self.events.append((request.method, path))
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response._content_consumed = True
        response._content = b"ok"
        response.raw = SimpleNamespace(
            _original_response=SimpleNamespace(msg=HTTPMessage())
        )
        if path == "/Saml/okta-prod/SignIn":
            response._content = (
                b'<form action="/Saml/r5-acs">'
                b'<input name="SAMLResponse" value="r5-synthetic"></form>'
            )
        elif path == "/Saml/r5-acs":
            self.entered.set()
            assert self.release.wait(5), "scratch in-flight SAML POST gate timed out"
            response.status_code = 307
            response.headers["Location"] = "/Saml/r5-next"
        return response


@pytest.mark.parametrize(
    "boundary", ["current_owner", "real_unload", "human_same_cookies"]
)
async def test_saml_redirect_cannot_dispatch_new_post_after_retirement(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    """R5-A: Automatic redirect hops check active entry ownership before sending."""
    portal = RedirectSsoPortal()
    client = PsegClient(
        portal_cookies="MM_SID=r5-sso", okta_cookies="idx=r5-synthetic-okta"
    )
    client.set_expected_meter_ids({METER})
    client.session.mount("https://", portal)
    original_fetch = PsegClient.fetch_energy_data
    monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)
    monkeypatch.setattr(
        client,
        "fetch_energy_data",
        lambda days: {
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
            CONF_PORTAL_COOKIES: "MM_SID=r5-sso",
            CONF_OKTA_COOKIES: "idx=r5-synthetic-okta",
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]
    client.fetch_energy_data = lambda days: original_fetch(client, days)  # type: ignore[method-assign]
    task = asyncio.create_task(coord._async_update_data())
    try:
        assert await asyncio.to_thread(portal.entered.wait, 3)
        assert portal.count("POST", "/Saml/r5-acs") == 1
        if boundary == "real_unload":
            assert await hass.config_entries.async_unload(entry.entry_id)
        elif boundary == "human_same_cookies":
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
        if boundary != "current_owner":
            assert not coord._renewal_runtime.is_active(coord._renewal_token)
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        expected = 1 if boundary == "current_owner" else 0
        assert portal.count("POST", "/Saml/r5-next") == expected, (
            "requests replayed a new SAML assertion POST after actual retirement"
        )
    finally:
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        if boundary != "real_unload":
            await hass.config_entries.async_unload(entry.entry_id)
        coord.stop_keepalive()
        abort_flows(hass)


@pytest.mark.parametrize("renewal", [False, True])
@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
async def test_healthy_hourly_rotation_is_persisted(
    hass: HomeAssistant, renewal: bool, cookie: str
) -> None:
    """R5-D control: Healthy hourly rotation is confirmed and persisted on completion."""
    portal = PayloadPortal("healthy", cookie, renewal)
    client = make_client(portal)
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id=METER, data={CONF_PORTAL_COOKIES: SEED}
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    try:
        data = await coord._async_update_data()
        assert data["daily_records"] and data["hourly_records"]
        assert entry.data["cookies"] == client.export_cookies()
        assert any(
            c["name"] == cookie and c["value"] == "r5-new-response"
            for c in entry.data["cookies"]
        )
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


@pytest.mark.parametrize("failure", ["maint", "notoken", "404", "429", "500"])
@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
async def test_postproof_failed_dashboard_cookie_cannot_be_promoted_by_next_poll(
    hass: HomeAssistant, failure: str, cookie: str
) -> None:
    """R5-B: Post-renewal failed Dashboard response restores the proven checkpoint."""

    class LaterDashboardPortal(Portal):
        def __init__(self) -> None:
            super().__init__(
                [
                    {"kind": "login"},
                    {
                        "kind": "dash",
                        "set_cookie": [
                            "MM_SID=r5-proven; Path=/",
                            "MM_RememberMe=r5-proven-generation; Path=/",
                            "review_aux=r5-proven-aux; Path=/",
                        ],
                    },
                    {
                        "kind": failure if failure in {"maint", "notoken"} else "dash",
                        "set_cookie": [f"{cookie}=r5-failed-dashboard; Path=/"],
                    },
                ]
            )
            self.dash_count = 0

        def send(
            self, request: requests.PreparedRequest, **kwargs: Any
        ) -> requests.Response:
            response = super().send(request, **kwargs)
            if urlparse(request.url).path == "/Dashboard":
                self.dash_count += 1
                if self.dash_count == 3 and failure.isnumeric():
                    response.status_code = int(failure)
            return response

    portal = LaterDashboardPortal()
    client = make_client(portal)
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id=METER, data={CONF_PORTAL_COOKIES: SEED}
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    proof: list[dict[str, Any]] = []
    capture = client._capture_confirmed_session

    def captured() -> None:
        capture()
        proof.append(copy.deepcopy(client.pending_confirmed_snapshot()))

    client._capture_confirmed_session = captured  # type: ignore[method-assign]
    try:
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()
        assert proof and entry.data["cookies"] == proof[0]["cookies"], (
            "existing immutable failure-exit handoff must remain intact"
        )
        data = await coord._async_update_data()
        assert data["daily_records"]
        assert entry.data["cookies"] == proof[0]["cookies"], (
            "a failed post-proof Dashboard cookie was promoted and persisted by the next ordinary successful poll"
        )
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


@pytest.mark.parametrize("renewal", [False, True])
@pytest.mark.parametrize("boundary", ["cancel_poll", "real_unload"])
@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
async def test_latest_valid_hourly_jar_survives_cancel_or_stop(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    renewal: bool,
    boundary: str,
    cookie: str,
) -> None:
    """R5-D: Validated hourly cookie rotations publish an immutable exit checkpoint."""
    portal = PayloadPortal("healthy", cookie, renewal)
    client = make_client(portal)
    original_fetch = PsegClient.fetch_energy_data
    monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)
    monkeypatch.setattr(
        client,
        "fetch_energy_data",
        lambda days: {
            "meter": "Meter #" + METER,
            "meter_ids": [METER],
            "daily_records": [],
            "history_14d": [],
            "hourly_records": [],
        },
    )
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id=METER, data={CONF_PORTAL_COOKIES: SEED}
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]
    client.fetch_energy_data = lambda days: original_fetch(client, days)  # type: ignore[method-assign]
    entered = threading.Event()
    release = threading.Event()
    original_export = client.export_cookies_and_auth_reason

    def gated_export() -> tuple[list[dict[str, Any]], str | None]:
        entered.set()
        assert release.wait(5), "scratch valid-jar export gate timed out"
        return original_export()

    client.export_cookies_and_auth_reason = gated_export  # type: ignore[method-assign]
    task = asyncio.create_task(coord._async_update_data())
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        confirmed = copy.deepcopy(client.confirmed_cookies())
        assert confirmed and any(
            c["name"] == cookie and c["value"] == "r5-new-response"
            for c in confirmed
        )
        if boundary == "cancel_poll":
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        else:
            assert await hass.config_entries.async_unload(entry.entry_id)
        assert entry.data.get("cookies") == confirmed, (
            "ordinary cancellation/stop lost the latest successfully validated whole jar"
        )
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        if boundary == "cancel_poll":
            await hass.config_entries.async_unload(entry.entry_id)
        coord.stop_keepalive()
        abort_flows(hass)


class ChartGatePortal(Portal):
    """Synthetic portal that gates on the first /Dashboard/Chart POST."""

    def __init__(self, renewal: bool) -> None:
        super().__init__(
            [{"kind": "login"}, {"kind": "dash"}] if renewal else [{"kind": "dash"}]
        )
        self.entered = threading.Event()
        self.release = threading.Event()
        self.gated = False

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        if (
            request.method == "POST"
            and urlparse(request.url).path == "/Dashboard/Chart"
            and not self.gated
        ):
            self.gated = True
            self.entered.set()
            assert self.release.wait(5), "scratch chart gate timed out"
        return super().send(request, **kwargs)


@pytest.mark.parametrize("renewal", [False, True])
@pytest.mark.parametrize("boundary", ["real_unload", "human_same_cookies"])
async def test_no_new_chart_dispatch_after_retirement(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    renewal: bool,
    boundary: str,
) -> None:
    """R5-A: Chart-to-ChartData transition does not dispatch ChartData after retirement."""
    portal = ChartGatePortal(renewal)
    client = make_client(portal)
    original_fetch = PsegClient.fetch_energy_data
    monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)
    monkeypatch.setattr(
        client,
        "fetch_energy_data",
        lambda days: {
            "meter": "Meter #" + METER,
            "meter_ids": [METER],
            "daily_records": [],
            "history_14d": [],
            "hourly_records": [],
        },
    )
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id=METER, data={CONF_PORTAL_COOKIES: SEED}
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]
    client.fetch_energy_data = lambda days: original_fetch(client, days)  # type: ignore[method-assign]
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
        assert not coord._renewal_runtime.is_active(coord._renewal_token)
        before = portal.count("GET", "/Dashboard/ChartData")
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        assert portal.count("GET", "/Dashboard/ChartData") == before, (
            "retired owner dispatched ChartData after its in-flight Chart POST returned"
        )
    finally:
        portal.release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        if boundary == "human_same_cookies":
            await hass.config_entries.async_unload(entry.entry_id)
        coord.stop_keepalive()
        abort_flows(hass)



# ---------------------------------------------------------------------------
# R6 table-driven regressions (F1, F2, F3, N1, N2)
# ---------------------------------------------------------------------------

R6_POISON = "r6-poison"
R6_TOKEN_PAGE = (
    b'<html><input name="__RequestVerificationToken" value="r6-af"/>Dashboard</html>'
)
R6_LOGIN_FORM = (
    b'<html><form action="/Home/Login"><input name="LoginEmail"/><input id="LoginPassword"/>'
    b'<input name="__RequestVerificationToken" value="r6-form"/></form></html>'
)


def _r6_daily_payload(day: str = "10/21/2026", meter: str = METER) -> dict[str, Any]:
    return {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{meter}",
                    "data": [
                        {"x": 1792540800000, "y": 3.0, "hs": {"start": day}}
                    ],
                }
            ]
        }
    }


def _r6_hourly_payload(meter: str = METER) -> dict[str, Any]:
    return {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{meter}",
                    "data": [
                        {
                            "x": 1792540800000,
                            "y": 1.0,
                            "hs": {
                                "start": "2026-10-21T00:00:00+00:00",
                                "end": "2026-10-21T01:00:00+00:00",
                            },
                        }
                    ],
                }
            ]
        }
    }


R6_DAILY_BAD: dict[str, Any] = {
    "no_matching_meter": {
        "Data": {
            "series": [
                {
                    "name": "Temperature",
                    "data": [{"y": 51.0, "hs": {"start": "10/21/2026"}}],
                }
            ]
        }
    },
    "other_meter": _r6_daily_payload(meter="99999"),
    "empty_meter": {"Data": {"series": [{"name": f"Meter #{METER}", "data": []}]}},
    "invalid_points": {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{METER}",
                    "data": [{"x": None, "y": "bad", "hs": {"start": "not-a-date"}}],
                }
            ]
        }
    },
}


class R6StagePortal(BaseAdapter):
    """Scripted portal adapter with per-stage queues and optional request gates."""

    def __init__(self) -> None:
        super().__init__()
        self.dash: list[dict[str, Any]] = []
        self.daily: list[tuple[Any, Any]] = []
        self.hourly: list[tuple[Any, Any]] = []
        self.events: list[tuple[str, str]] = []
        self.mode = "daily"
        self.start = "10/21/2026"
        self.gate_path: str | None = None
        self.gate_mode: str | None = None
        self.entered = threading.Event()
        self.release = threading.Event()
        # A quarantined cookie must never travel on a later request.
        self.poison_dispatches: list[tuple[str, str]] = []

    def send(
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        u = urlparse(request.url)
        self.events.append((request.method or "", u.path))
        if R6_POISON in (request.headers.get("Cookie") or ""):
            self.poison_dispatches.append((request.method or "", u.path))
        if u.hostname != PORTAL_HOST:
            raise AssertionError("non-portal host contacted")
        resp = requests.Response()
        resp.status_code = 200
        resp.url = request.url
        resp.request = request
        resp._content = b"ok"
        resp._content_consumed = True
        msg = HTTPMessage()
        resp.raw = SimpleNamespace(_original_response=SimpleNamespace(msg=msg))

        def add_cookies(cookies: Any) -> None:
            for header in cookies or ():
                msg.add_header("Set-Cookie", header)

        if request.method == "GET" and u.path in ("/Dashboard", "/Dashboard/Next"):
            spec = self.dash.pop(0) if self.dash else {"kind": "dash"}
            add_cookies(spec.get("set_cookie"))
            if spec.get("gate") and self.gate_path == u.path:
                self.entered.set()
                assert self.release.wait(5), "scratch gate timed out"
            kind = spec["kind"]
            if kind == "dash":
                resp._content = R6_TOKEN_PAGE
            elif kind == "redirect":
                resp.status_code = 302
                resp.headers["Location"] = "/Dashboard/Next"
            elif kind == "login":
                resp.url = PORTAL_BASE_URL + "/"
                resp._content = R6_LOGIN_FORM
            else:
                raise AssertionError(f"bad dashboard spec {kind}")
        elif request.method == "GET" and u.path == "/":
            resp._content = R6_LOGIN_FORM
        elif request.method == "POST" and u.path == "/Dashboard/Chart":
            body = (
                request.body.decode()
                if isinstance(request.body, bytes)
                else (request.body or "")
            )
            form = parse_qs(body)
            self.mode = (
                "hourly"
                if form.get("UsageInterval") == [USAGE_INTERVAL_HOURLY]
                else "daily"
            )
            start = (form.get("Start") or ["2026-10-21"])[0]
            try:
                self.start = datetime.strptime(start, "%Y-%m-%d").strftime("%m/%d/%Y")
            except ValueError:
                self.start = "10/21/2026"
        elif request.method == "GET" and u.path == "/Dashboard/ChartData":
            if self.gate_path == u.path and self.gate_mode == self.mode:
                self.entered.set()
                assert self.release.wait(5), "scratch gate timed out"
            queue = self.hourly if self.mode == "hourly" else self.daily
            if queue:
                payload, cookies = queue.pop(0)
            else:
                payload = (
                    _r6_hourly_payload()
                    if self.mode == "hourly"
                    else _r6_daily_payload(self.start)
                )
                cookies = ()
            add_cookies(cookies)
            if isinstance(payload, dict) and "__status__" in payload:
                resp.status_code = int(payload["__status__"])
                resp._content = b"<html>server error</html>"
            elif payload == "__default__":
                resp._content = json.dumps(_r6_daily_payload(self.start)).encode()
            else:
                resp._content = json.dumps(payload).encode()
        elif request.method == "POST" and u.path == "/Home/Login":
            resp._content = json.dumps({"AjaxResults": [], "Data": {}}).encode()
        else:
            raise AssertionError(f"unexpected route {request.method} {u.path}")
        return resp

    def close(self) -> None:
        pass


def _r6_poisoned(
    cookies: list[dict[str, Any]] | None, name: str, value: str = R6_POISON
) -> bool:
    return any(
        c.get("name") == name and c.get("value") == value for c in (cookies or [])
    )


def _r6_build(
    hass: HomeAssistant, portal: R6StagePortal
) -> tuple[PsegClient, MockConfigEntry, PsegDataUpdateCoordinator]:
    client = PsegClient(portal_cookies=SEED)
    client.session.mount("https://", portal)
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id=METER, data={CONF_PORTAL_COOKIES: SEED}
    )
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(
        hass, client, dict(entry.data), config_entry=entry
    )
    return client, entry, coord


async def _r6_follow_on(
    hass: HomeAssistant,
    entry: MockConfigEntry,
    coord: PsegDataUpdateCoordinator,
    name: str,
) -> list[bool]:
    await coord._async_keepalive(dt_util.utcnow())
    flags = [_r6_poisoned(entry.data.get("cookies"), name)]
    for _ in range(2):
        try:
            await coord._async_update_data()
        except Exception:  # noqa: BLE001
            pass
        flags.append(_r6_poisoned(entry.data.get("cookies"), name))
    cold = PsegClient(cookie_list=entry.data.get("cookies"))
    flags.append(_r6_poisoned(cold.export_cookies(), name))
    return flags


@pytest.mark.parametrize("renewal", [False, True])
@pytest.mark.parametrize("payload", sorted(R6_DAILY_BAD))
@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
async def test_daily_leg_requires_valid_meter_read_before_confirming_cookie(
    hass: HomeAssistant, renewal: bool, payload: str, cookie: str
) -> None:
    """F1: Daily 200 without >=1 valid record for a known meter rolls back cookies."""
    portal = R6StagePortal()
    if renewal:
        portal.dash.extend(
            [
                {"kind": "login"},
                {
                    "kind": "dash",
                    "set_cookie": [
                        "MM_SID=r6-proven-sid; Path=/",
                        "MM_RememberMe=r6-proven-gen; Path=/",
                        "review_aux=r6-proven-aux; Path=/",
                    ],
                },
                {"kind": "dash"},
            ]
        )
        portal.daily.append(("__default__", ()))
    portal.daily.append((R6_DAILY_BAD[payload], [f"{cookie}={R6_POISON}; Path=/"]))
    client, entry, coord = _r6_build(hass, portal)
    try:
        try:
            await coord._async_update_data()
        except Exception:  # noqa: BLE001
            pass
        snap = client.pending_confirmed_snapshot()
        assert not _r6_poisoned(entry.data.get("cookies"), cookie)
        assert not (snap and _r6_poisoned(snap["cookies"], cookie))
        assert not _r6_poisoned(client.export_cookies(), cookie)
        flags = await _r6_follow_on(hass, entry, coord, cookie)
        assert not any(flags), flags
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


async def test_daily_and_hourly_meter_swap_and_fresh_manual_flow_semantics(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F1/N2: Known meter swap is accepted, foreign hourly meter is rejected, fresh setup works."""
    portal = R6StagePortal()
    swap_daily = {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{METER}",
                    "data": [
                        {"x": 1792454400000, "y": 3.5, "hs": {"start": "10/20/2026"}}
                    ],
                },
                {
                    "name": "Meter #99999",
                    "data": [
                        {"x": 1792540800000, "y": 4.5, "hs": {"start": "10/21/2026"}}
                    ],
                },
            ]
        }
    }
    portal.daily.append((swap_daily, ["MM_SID=r6-swap-daily; Path=/"]))
    portal.hourly.append(
        (_r6_hourly_payload(meter="88888"), ["MM_SID=r6-foreign-hourly; Path=/"])
    )
    client, entry, coord = _r6_build(hass, portal)
    try:
        data = await coord._async_update_data()
        assert data["daily_records"] and data["hourly_records"] == []
        assert _r6_poisoned(entry.data.get("cookies"), "MM_SID", "r6-swap-daily")
        assert not _r6_poisoned(
            entry.data.get("cookies"), "MM_SID", "r6-foreign-hourly"
        )
        assert set(entry.data.get(CONF_KNOWN_METER_IDS) or []) >= {METER, "99999"}
    finally:
        coord.stop_keepalive()
        await hass.config_entries.async_remove(entry.entry_id)
        abort_flows(hass)

    # Fresh unattached manual flow (no pre-existing entry identity) accepts any valid Meter #N.
    fresh_portal = R6StagePortal()
    fresh_portal.daily.append((_r6_daily_payload(meter="77777"), ()))

    def make_fresh(**kwargs: Any) -> PsegClient:
        c = PsegClient(**kwargs)
        c.session.mount("https://", fresh_portal)
        return c

    async def async_true(*_a: Any, **_k: Any) -> bool:
        return True

    monkeypatch.setattr(flow_mod, "PsegClient", make_fresh)
    monkeypatch.setattr(pkg, "async_setup_entry", async_true)
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
        data={
            CONF_OKTA_COOKIES: "",
            CONF_PORTAL_COOKIES: "MM_SID=r6-a; MM_RememberMe=r6-b",
        },
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "77777"


R6_GOOD = ("__default__", ())
R6_CHUNK_VARIANTS: dict[str, list[tuple[Any, str]]] = {
    "abort_null_data": [R6_GOOD, ({"Data": None}, "P"), R6_GOOD, R6_GOOD],
    "abort_unrelated_series": [
        R6_GOOD,
        (R6_DAILY_BAD["no_matching_meter"], "P"),
        R6_GOOD,
        R6_GOOD,
    ],
    "abort_empty_meter": [
        R6_GOOD,
        (R6_DAILY_BAD["empty_meter"], "P"),
        R6_GOOD,
        R6_GOOD,
    ],
    "edge_null_data": [({"Data": None}, "P"), R6_GOOD, R6_GOOD, R6_GOOD],
    "edge_empty_object": [({}, "P"), R6_GOOD, R6_GOOD, R6_GOOD],
}


@pytest.mark.parametrize("variant", sorted(R6_CHUNK_VARIANTS))
@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
async def test_backfill_invalid_or_empty_chunk_cookie_is_quarantined(
    hass: HomeAssistant, variant: str, cookie: str
) -> None:
    """F2-A: Invalid/empty history chunks roll back cookies and hole-abort restores last valid checkpoint."""
    portal = R6StagePortal()
    for idx, (payload, mark) in enumerate(R6_CHUNK_VARIANTS[variant]):
        if mark == "P":
            cookies = [f"{cookie}={R6_POISON}; Path=/"]
        elif idx == 0 and variant.startswith("abort_"):
            cookies = [f"{cookie}=r6-chunk0-good; Path=/"]
        else:
            cookies = []
        portal.daily.append((payload, cookies))
    client, entry, coord = _r6_build(hass, portal)

    async def no_stats(*_a: Any, **_kw: Any) -> None:
        return None

    coord.async_record_statistics = no_stats  # type: ignore[method-assign]
    try:
        try:
            await coord.async_backfill_history("2026-01-01", "2026-10-20")
        except Exception:  # noqa: BLE001
            pass
        assert not _r6_poisoned(entry.data.get("cookies"), cookie)
        assert not _r6_poisoned(client.export_cookies(), cookie)
        if variant.startswith("abort_"):
            assert _r6_poisoned(
                entry.data.get("cookies"), cookie, "r6-chunk0-good"
            ), "earlier validated chunk rotation must survive later hole abort"
        flags = await _r6_follow_on(hass, entry, coord, cookie)
        assert not any(flags), flags
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
async def test_valid_backfill_chunk_rotation_persisted_on_unload(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, cookie: str
) -> None:
    """F2-B: Validated backfill chunk cookie rotations publish an immutable checkpoint."""
    portal = R6StagePortal()
    client = PsegClient(portal_cookies=SEED)
    client.session.mount("https://", portal)
    monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id=METER, data={CONF_PORTAL_COOKIES: SEED}
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]

    async def no_stats(*_a: Any, **_kw: Any) -> None:
        return None

    coord.async_record_statistics = no_stats
    portal.daily.extend(
        [
            R6_GOOD,
            ("__default__", [f"{cookie}={R6_POISON}; Path=/"]),
            R6_GOOD,
            R6_GOOD,
        ]
    )
    count = await coord.async_backfill_history("2026-01-01", "2026-10-20")
    assert count > 0
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert _r6_poisoned(entry.data.get("cookies"), cookie)


async def test_owner_predicate_true_during_own_write_and_false_on_foreign_replace(
    hass: HomeAssistant,
) -> None:
    """F3: Own cookie write does not retire the coordinator; foreign human write still retires."""
    portal = R6StagePortal()
    client, entry, coord = _r6_build(hass, portal)
    try:
        await coord._async_update_data()
        portal.dash.extend(
            [
                {"kind": "login"},
                {
                    "kind": "dash",
                    "gate": True,
                    "set_cookie": ["MM_RememberMe=r6-rotated-gen; Path=/"],
                },
            ]
        )
        portal.gate_path = "/Dashboard"
        task = hass.async_add_executor_job(client.keepalive)
        assert await hass.async_add_executor_job(portal.entered.wait, 3)
        seen: list[bool] = []
        original = hass.config_entries.async_update_entry

        def spy(target: Any, **kwargs: Any) -> Any:
            res = original(target, **kwargs)
            if "cookies" in (kwargs.get("data") or {}):
                seen.append(coord._renewal_runtime.is_active(coord._renewal_token))
                portal.release.set()
                time.sleep(0.15)
            return res

        hass.config_entries.async_update_entry = spy  # type: ignore[method-assign]
        try:
            changed = [dict(c) for c in entry.data["cookies"]] + [
                {
                    "name": "review_aux",
                    "value": "r6-own-write",
                    "domain": PORTAL_HOST,
                    "path": "/",
                    "secure": True,
                }
            ]
            coord._write_cookie_handoff(changed, frozenset({"MM_SID"}))
        finally:
            hass.config_entries.async_update_entry = original  # type: ignore[method-assign]
        outcome = await task
        assert seen and all(seen), seen
        assert outcome is True
        assert client._renewal_admission.blocked_reason(datetime.now(UTC)) != "exhausted"

        # Foreign human replacement of entry.data["cookies"] must still retire the old owner.
        foreign = [
            {
                "name": "MM_SID",
                "value": "r6-foreign-human",
                "domain": PORTAL_HOST,
                "path": "/",
                "secure": True,
            }
        ]
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, "cookies": foreign}
        )
        assert coord._jar_replaced() is True
        assert not coord._renewal_runtime.is_active(coord._renewal_token)
    finally:
        portal.release.set()
        coord.stop_keepalive()
        abort_flows(hass)


def test_checkpoint_lock_synchronizes_publish_and_clear() -> None:
    """N1: Dedicated checkpoint lock protects concurrent publication and compare-and-clear."""
    client = PsegClient(portal_cookies=SEED)
    client._mark_session_ok()
    client._capture_confirmed_session()
    first = client.pending_confirmed_snapshot()
    assert first is not None
    first_id = first["id"]

    # Simulate executor publishing a newer checkpoint before the event-loop ack of first_id.
    client.session.cookies.set(
        "MM_SID", "r6-newer-sid", domain=PORTAL_HOST, path="/", secure=True
    )
    client._note_confirmed_generation()
    second = client.pending_confirmed_snapshot()
    assert second is not None and second["id"] > first_id

    # Clearing the older id must never drop the newer checkpoint.
    client.clear_confirmed_snapshot(first_id)
    assert client.pending_confirmed_snapshot() == second
    client.clear_confirmed_snapshot(second["id"])
    assert client.pending_confirmed_snapshot() is None


# ---------------------------------------------------------------------------
# R7B Regressions: Malformed nested shapes, per-record contributor provenance,
# rejected daily identity isolation, and _write_cookie_handoff baseline reconciliation.
# ---------------------------------------------------------------------------

R7B_NESTED_SHAPE_VARIANTS: dict[str, dict[str, Any]] = {
    "meter_data_integer": {"Data": {"series": [{"name": f"Meter #{METER}", "data": 123}]}},
    "meter_data_bool": {"Data": {"series": [{"name": f"Meter #{METER}", "data": True}]}},
    "ajax_results_integer": {"AjaxResults": 123},
    "ajax_results_bool": {"AjaxResults": True},
    # Envelope defect next to otherwise usable readings: the shared leg guard must
    # reject the payload rather than trust the meters of a contract-violating reply.
    "ajax_results_integer_with_valid_data": {
        "AjaxResults": 123,
        "Data": {
            "series": [
                {
                    "name": f"Meter #{METER}",
                    "data": [{"x": 1792540800000, "y": 3.0, "hs": {"start": "10/21/2026"}}],
                }
            ]
        },
    },
}


@pytest.mark.parametrize("leg", ["daily", "hourly", "backfill", "renewal"])
@pytest.mark.parametrize("variant", sorted(R7B_NESTED_SHAPE_VARIANTS))
@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
async def test_r7b_malformed_nested_chart_shapes_quarantined_across_all_legs(
    hass: HomeAssistant, leg: str, variant: str, cookie: str
) -> None:
    """R7B-1: Malformed nested series.data or AjaxResults shapes roll back cookies and sanitize errors."""
    portal = R6StagePortal()
    bad = R7B_NESTED_SHAPE_VARIANTS[variant]
    bad_cookies = [f"{cookie}={R6_POISON}; Path=/"]

    if leg == "daily":
        portal.daily.append((bad, bad_cookies))
        portal.hourly.append(({"Data": None}, ()))
    elif leg == "hourly":
        portal.daily.append(("__default__", ()))
        portal.hourly.append((bad, bad_cookies))
    elif leg == "backfill":
        portal.daily.extend(
            [
                ("__default__", [f"{cookie}=r7b-chunk0-good; Path=/"]),
                (bad, bad_cookies),
                R6_GOOD,
                R6_GOOD,
            ]
        )
    elif leg == "renewal":
        portal.dash.extend(
            [
                {"kind": "login"},
                {
                    "kind": "dash",
                    "set_cookie": [
                        "MM_SID=r7b-proven-sid; Path=/",
                        "MM_RememberMe=r7b-proven-gen; Path=/",
                        "review_aux=r7b-proven-aux; Path=/",
                    ],
                },
                {"kind": "dash"},
            ]
        )
        portal.daily.append(("__default__", ()))
        portal.daily.append((bad, bad_cookies))
        portal.hourly.append(({"Data": None}, ()))

    client, entry, coord = _r6_build(hass, portal)

    async def no_stats(*_a: Any, **_kw: Any) -> None:
        return None

    coord.async_record_statistics = no_stats  # type: ignore[method-assign]
    try:
        if leg in {"daily", "hourly", "renewal"}:
            try:
                await coord._async_update_data()
            except Exception as err:  # noqa: BLE001
                assert not isinstance(err, TypeError)
        elif leg == "backfill":
            with pytest.raises(Exception) as exc_info:
                await coord.async_backfill_history("2026-01-01", "2026-10-20")
            assert not isinstance(exc_info.value, TypeError)

        snap = client.pending_confirmed_snapshot()
        assert not _r6_poisoned(entry.data.get("cookies"), cookie)
        assert not (snap and _r6_poisoned(snap["cookies"], cookie))
        assert not _r6_poisoned(client.export_cookies(), cookie)
        if leg == "backfill":
            assert _r6_poisoned(entry.data.get("cookies"), cookie, "r7b-chunk0-good")
        flags = await _r6_follow_on(hass, entry, coord, cookie)
        assert not any(flags), flags
        assert not portal.poison_dispatches, portal.poison_dispatches
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


R7B_KNOWN_DECOY_DAILY: dict[str, dict[str, Any]] = {
    "known_empty_unknown_valid": {
        "Data": {
            "series": [
                {"name": f"Meter #{METER}", "data": []},
                {
                    "name": "Meter #99999",
                    "data": [{"x": 1792540800000, "y": 6.25, "hs": {"start": "10/21/2026"}}],
                },
            ]
        }
    },
    "known_invalid_unknown_valid": {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{METER}",
                    "data": [{"x": 1792540800000, "y": "nan", "hs": {"start": "bad-date"}}],
                },
                {
                    "name": "Meter #99999",
                    "data": [{"x": 1792540800000, "y": 6.25, "hs": {"start": "10/21/2026"}}],
                },
            ]
        }
    },
}

R7B_KNOWN_DECOY_HOURLY: dict[str, dict[str, Any]] = {
    "known_empty_unknown_valid": {
        "Data": {
            "series": [
                {"name": f"Meter #{METER}", "data": []},
                {
                    "name": "Meter #99999",
                    "data": [
                        {
                            "x": 1792555200000,
                            "y": 0.75,
                            "hs": {"start": "2026-10-21T00:00:00+00:00", "end": "2026-10-21T01:00:00+00:00"},
                        }
                    ],
                },
            ]
        }
    },
    "known_invalid_unknown_valid": {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{METER}",
                    "data": [{"x": 1792555200000, "y": "nan", "hs": {"start": "bad"}}],
                },
                {
                    "name": "Meter #99999",
                    "data": [
                        {
                            "x": 1792555200000,
                            "y": 0.75,
                            "hs": {"start": "2026-10-21T00:00:00+00:00", "end": "2026-10-21T01:00:00+00:00"},
                        }
                    ],
                },
            ]
        }
    },
}


@pytest.mark.parametrize("leg", ["daily", "hourly", "backfill", "renewal"])
@pytest.mark.parametrize("variant", sorted(R7B_KNOWN_DECOY_DAILY))
async def test_r7b_known_decoy_series_with_unknown_valid_records_rejected(
    hass: HomeAssistant, leg: str, variant: str
) -> None:
    """R7B-2: Known series with 0 valid records next to unknown valid records is rejected."""
    portal = R6StagePortal()
    cookie = "MM_SID"
    bad_cookies = [f"{cookie}={R6_POISON}; Path=/"]
    bad_daily = R7B_KNOWN_DECOY_DAILY[variant]
    bad_hourly = R7B_KNOWN_DECOY_HOURLY[variant]

    if leg == "daily":
        portal.daily.append((bad_daily, bad_cookies))
        portal.hourly.append(({"Data": None}, ()))
    elif leg == "hourly":
        portal.daily.append(("__default__", ()))
        portal.hourly.append((bad_hourly, bad_cookies))
    elif leg == "backfill":
        portal.daily.extend(
            [
                ("__default__", [f"{cookie}=r7b-chunk0-good; Path=/"]),
                (bad_daily, bad_cookies),
                R6_GOOD,
                R6_GOOD,
            ]
        )
    elif leg == "renewal":
        portal.dash.extend(
            [
                {"kind": "login"},
                {"kind": "dash", "set_cookie": ["MM_SID=r7b-renewed-sid; Path=/"]},
                {"kind": "dash"},
            ]
        )
        portal.daily.append((bad_daily, bad_cookies))
        portal.hourly.append(({"Data": None}, ()))

    client, entry, coord = _r6_build(hass, portal)

    async def no_stats(*_a: Any, **_kw: Any) -> None:
        return None

    coord.async_record_statistics = no_stats  # type: ignore[method-assign]
    try:
        if leg == "daily":
            # R8-2: a rejected DAILY identity is a typed failure, never a published
            # placeholder, so no reading, id or statistics can be observed.
            with pytest.raises(UpdateFailed):
                await coord._async_update_data()
            assert coord.data is None
            assert coord._last_valid_data is None
            assert coord.status == "error"
            assert "99999" not in set(entry.data.get(CONF_KNOWN_METER_IDS) or [])
        elif leg == "hourly":
            data = await coord._async_update_data()
            assert data["hourly_records"] == []
            assert "99999" not in set(entry.data.get(CONF_KNOWN_METER_IDS) or [])
        elif leg == "backfill":
            with pytest.raises(Exception):
                await coord.async_backfill_history("2026-01-01", "2026-10-20")
            assert _r6_poisoned(entry.data.get("cookies"), cookie, "r7b-chunk0-good")
        elif leg == "renewal":
            with pytest.raises(Exception):
                await coord._async_update_data()
            assert client.sso_renewals == 0
            assert client._renewal_admission.as_dict()["sequences"] == 1
            assert "99999" not in set(entry.data.get(CONF_KNOWN_METER_IDS) or [])

        snap = client.pending_confirmed_snapshot()
        assert not _r6_poisoned(entry.data.get("cookies"), cookie)
        assert not (snap and _r6_poisoned(snap["cookies"], cookie))
        assert not _r6_poisoned(client.export_cookies(), cookie)
        flags = await _r6_follow_on(hass, entry, coord, cookie)
        assert not any(flags), flags
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


async def test_r7b_proven_meter_learning_and_rejected_daily_isolation(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R7B-2 & R7B-3: Only contributing meters are learned; rejected daily leg publishes nothing."""
    portal = R6StagePortal()
    # First let setup succeed with a valid poll, then inject the foreign daily poll.
    portal.daily.append(("__default__", ()))
    portal.hourly.append(("__default__", ()))
    portal.daily.append((_r6_daily_payload(meter="99999"), ["MM_SID=r7b-foreign-daily; Path=/"]))
    portal.hourly.append(({"Data": None}, ()))

    client = PsegClient(portal_cookies=SEED)
    client.set_expected_meter_ids({METER})
    client.session.mount("https://", portal)
    monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)

    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={
            CONF_PORTAL_COOKIES: SEED,
            "meter_id": METER,
            CONF_KNOWN_METER_IDS: [METER],
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    coord: PsegDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    try:
        assert hass.states.get("sensor.pseg_electricity_consumption").state == "3.0"
        prior_valid = dict(coord._last_valid_data)
        prior_success_ts = coord.last_successful_update

        rejected = None
        with pytest.raises(UpdateFailed):
            rejected = await coord._async_update_data()
        assert rejected is None
        # Nothing from the rejected leg reached the published surface or the clock.
        assert coord.data == prior_valid
        assert coord._last_valid_data == prior_valid
        assert coord.last_successful_update == prior_success_ts
        assert coord.status == "error"
        assert hass.states.get("sensor.pseg_electricity_consumption").state == "3.0"
        assert "99999" not in set(entry.data.get(CONF_KNOWN_METER_IDS) or [])
        assert not _r6_poisoned(entry.data.get("cookies"), "MM_SID", "r7b-foreign-daily")

        # 2. Valid known series + invalid unknown series must NOT learn the invalid unknown meter ID.
        invalid_unknown_daily = {
            "Data": {
                "series": [
                    {
                        "name": f"Meter #{METER}",
                        "data": [
                            {"x": 1792454400000, "y": 3.5, "hs": {"start": "10/20/2026"}}
                        ],
                    },
                    {
                        "name": "Meter #55555",
                        "data": [
                            {"x": 1792540800000, "y": "nan", "hs": {"start": "bad-date"}}
                        ],
                    },
                ]
            }
        }
        portal.daily.append((invalid_unknown_daily, ()))
        portal.hourly.append(({"Data": None}, ()))
        data = await coord._async_update_data()
        assert data["meter"] == f"Meter #{METER}"
        assert "55555" not in set(entry.data.get(CONF_KNOWN_METER_IDS) or [])

        # 3. Once a successor meter is legitimately learned via co-occurring valid reads,
        # a subsequent poll where predecessor is empty and known successor has valid data succeeds.
        overlap_daily = {
            "Data": {
                "series": [
                    {
                        "name": f"Meter #{METER}",
                        "data": [
                            {"x": 1792454400000, "y": 3.5, "hs": {"start": "10/20/2026"}}
                        ],
                    },
                    {
                        "name": "Meter #88888",
                        "data": [
                            {"x": 1792540800000, "y": 5.25, "hs": {"start": "10/21/2026"}}
                        ],
                    },
                ]
            }
        }
        post_swap_daily = {
            "Data": {
                "series": [
                    {"name": f"Meter #{METER}", "data": []},
                    {
                        "name": "Meter #88888",
                        "data": [
                            {"x": 1792627200000, "y": 6.0, "hs": {"start": "10/22/2026"}}
                        ],
                    },
                ]
            }
        }
        portal.daily.append((overlap_daily, ()))
        portal.hourly.append(({"Data": None}, ()))
        await coord._async_update_data()
        assert "88888" in set(entry.data.get(CONF_KNOWN_METER_IDS) or [])

        portal.daily.append((post_swap_daily, ()))
        portal.hourly.append(({"Data": None}, ()))
        data2 = await coord._async_update_data()
        assert data2["meter"] == "Meter #88888"
        assert data2["latest_kwh"] == 6.0
    finally:
        await hass.config_entries.async_unload(entry.entry_id)
        abort_flows(hass)


@pytest.mark.parametrize("after_assignment", [False, True])
async def test_r7b_write_cookie_handoff_reconciles_baseline_across_update_faults(
    hass: HomeAssistant, after_assignment: bool
) -> None:
    """R7B-4: Post-assignment callback exception in async_update_entry still updates _jar_baseline."""
    portal = R6StagePortal()
    client, entry, coord = _r6_build(hass, portal)
    try:
        await coord._async_update_data()
        prior_baseline = coord._jar_baseline
        target = [dict(c) for c in entry.data["cookies"]] + [
            {
                "name": "review_aux",
                "value": f"r7b-fault-{after_assignment}",
                "domain": PORTAL_HOST,
                "path": "/",
                "secure": True,
            }
        ]
        original = hass.config_entries.async_update_entry

        def faulty_update(cfg_entry: Any, **kwargs: Any) -> Any:
            if not after_assignment:
                raise RuntimeError("pre-assignment fault")
            original(cfg_entry, **kwargs)
            raise RuntimeError("post-assignment listener fault")

        hass.config_entries.async_update_entry = faulty_update  # type: ignore[method-assign]
        try:
            with pytest.raises(RuntimeError):
                coord._write_cookie_handoff(target, frozenset({"MM_SID"}))
        finally:
            hass.config_entries.async_update_entry = original  # type: ignore[method-assign]

        assert coord._jar_writing_target is None
        if after_assignment:
            assert coord._jar_baseline == target
            assert coord._jar_replaced() is False
            assert coord._renewal_runtime.is_active(coord._renewal_token)
        else:
            assert coord._jar_baseline == prior_baseline
            assert coord._jar_replaced() is False

        # Control 1: If a callback replaces entry.data["cookies"] with a foreign jar during handoff,
        # _jar_baseline must NOT adopt the foreign jar and _jar_replaced() must be True.
        foreign = [
            {
                "name": "MM_SID",
                "value": "r7b-foreign-callback",
                "domain": PORTAL_HOST,
                "path": "/",
                "secure": True,
            }
        ]

        def foreign_callback_update(cfg_entry: Any, **kwargs: Any) -> Any:
            res = original(cfg_entry, **kwargs)
            original(cfg_entry, data={**cfg_entry.data, "cookies": foreign})
            return res

        hass.config_entries.async_update_entry = foreign_callback_update  # type: ignore[method-assign]
        target2 = [dict(c) for c in target] + [
            {
                "name": "review_aux_2",
                "value": "r7b-ctrl1",
                "domain": PORTAL_HOST,
                "path": "/",
                "secure": True,
            }
        ]
        try:
            coord._write_cookie_handoff(target2, frozenset({"MM_SID"}))
        finally:
            hass.config_entries.async_update_entry = original  # type: ignore[method-assign]

        assert coord._jar_replaced() is True
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe"])
async def test_r7b_quarantined_chunk_fault_never_survives_cold_restart(
    hass: HomeAssistant, cookie: str
) -> None:
    """R7B-1: a quarantined chunk keeps only the last valid checkpoint, even cold."""
    portal = R6StagePortal()
    portal.daily.extend(
        [
            ("__default__", [f"{cookie}=r7b-cold-chunk0; Path=/"]),
            (
                {"Data": {"series": [{"name": f"Meter #{METER}", "data": True}]}},
                [f"{cookie}={R6_POISON}; Path=/"],
            ),
        ]
    )
    client, entry, coord = _r6_build(hass, portal)

    async def no_stats(*_a: Any, **_kw: Any) -> None:
        return None

    coord.async_record_statistics = no_stats  # type: ignore[method-assign]
    try:
        with pytest.raises(PsegTransientError) as excinfo:
            await coord.async_backfill_history("2026-01-01", "2026-10-20")
        # Typed and sanitized: the parser's own exception type is never surfaced.
        assert "Malformed" in str(excinfo.value)
        assert "TypeError" not in str(excinfo.value)
        assert _r6_poisoned(entry.data.get("cookies"), cookie, "r7b-cold-chunk0")

        flags = await _r6_follow_on(hass, entry, coord, cookie)
        assert not any(flags), flags

        # Cold restart: a brand-new client/coordinator from the persisted entry data
        # must not dispatch or keep the failed response's cookie either.
        cold = PsegClient(cookie_list=copy.deepcopy(entry.data.get("cookies")))
        cold.session.mount("https://", portal)
        cold_coord = PsegDataUpdateCoordinator(
            hass, cold, dict(entry.data), config_entry=entry
        )
        try:
            await cold_coord._async_update_data()
        finally:
            cold_coord.stop_keepalive()
        assert not _r6_poisoned(entry.data.get("cookies"), cookie)
        assert not _r6_poisoned(cold.export_cookies(), cookie)
        assert not portal.poison_dispatches, portal.poison_dispatches
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


def test_r7b_records_without_per_meter_provenance_never_prove_identity() -> None:
    """R7B-2: only per-record contributing meters can prove an account, never a label."""
    client = PsegClient(portal_cookies=SEED)
    plain = [{"date": "2026-10-21", "kwh": 3.0, "cost": 0.1}]
    client.set_expected_meter_ids({METER})
    # An aggregated record with no per-meter provenance is not identity evidence,
    # even when its label matches a known meter exactly.
    assert client._has_valid_meter_read(plain, [METER]) is False
    assert client._has_valid_meter_read(plain, []) is False
    # N3: a plain dict's own meter_id/meter_ids claim is data, never parser proof.
    claimed = {"date": "2026-10-21", "kwh": 3.0, "meter_id": METER}
    claimed_many = {"date": "2026-10-21", "kwh": 3.0, "meter_ids": [METER]}
    assert client._has_valid_meter_read([claimed], [METER]) is False
    assert client._has_valid_meter_read([claimed_many], [METER]) is False

    known = _MeterRecord(
        {"date": "2026-10-21", "kwh": 3.0}, contributing_meter_ids=(METER,)
    )
    unknown = _MeterRecord(
        {"date": "2026-10-21", "kwh": 4.0}, contributing_meter_ids=("99999",)
    )
    client.set_expected_meter_ids(set())
    # A fresh, manually configured entry has no prior identity: real contributing
    # meters are accepted, but the renewal proof stays fail-closed.
    assert client._has_valid_meter_read([known], [METER]) is True
    assert client._has_valid_meter_read([known], [METER], require_expected=True) is False

    client.set_expected_meter_ids({METER})
    assert client._has_valid_meter_read([unknown], ["99999"], require_expected=True) is False
    assert (
        client._has_valid_meter_read([known, unknown], [METER, "99999"], require_expected=True)
        is True
    )


async def test_r7b_renewal_without_known_identity_is_refused(hass: HomeAssistant) -> None:
    """R7B-2: a renewal can never be confirmed without a known account identity."""
    portal = R6StagePortal()
    portal.dash.extend(
        [
            {"kind": "login"},
            {
                "kind": "dash",
                "set_cookie": [
                    "MM_SID=r7b-unproven-sid; Path=/",
                    "MM_RememberMe=r7b-unproven-gen; Path=/",
                ],
            },
        ]
    )
    client, entry, coord = _r6_build(hass, portal)
    client.set_expected_meter_ids(set())
    try:
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()
        assert client.sso_renewals == 0
        assert client._renewal_admission.as_dict()["sequences"] == 1
        assert not _r6_poisoned(entry.data.get("cookies"), "MM_SID", "r7b-unproven-sid")
        assert not _r6_poisoned(entry.data.get("cookies"), "MM_RememberMe", "r7b-unproven-gen")
        assert not _r6_poisoned(client.export_cookies(), "MM_SID", "r7b-unproven-sid")
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


# ---------------------------------------------------------------------------
# R8 regressions: human identity on a lagging DAILY window, authoritative DAILY
# rejection, hourly/daily contributor union, and non-meter telemetry shapes.
# ---------------------------------------------------------------------------

R8_LAG_WINDOWS: dict[str, Any] = {
    "label_no_points": {"Data": {"series": [{"name": f"Meter #{METER}", "data": []}]}},
    "null_usage_points": {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{METER}",
                    "data": [{"x": 1792540800000, "y": None, "hs": {"start": "10/21/2026"}}],
                }
            ]
        }
    },
    "control_valid_point": {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{METER}",
                    "data": [{"x": 1792540800000, "y": 2.5, "hs": {"start": "10/21/2026"}}],
                }
            ]
        }
    },
}


def _r8_factory(portal: R6StagePortal) -> Any:
    """Build real PsegClients bound to the scripted portal for config-flow tests."""

    def make(**kwargs: Any) -> PsegClient:
        client = PsegClient(**kwargs)
        client.session.mount("https://", portal)
        return client

    return make


async def _r8_async_true(*_a: Any, **_k: Any) -> bool:
    return True


@pytest.mark.parametrize("window", sorted(R8_LAG_WINDOWS))
async def test_r8_fresh_cookie_setup_survives_lagging_daily_window(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, window: str
) -> None:
    """R8-1: a lagging 1-day window must not break a fresh human cookie sign-in."""
    portal = R6StagePortal()
    portal.dash.extend(
        [
            {"kind": "login"},
            {"kind": "dash", "set_cookie": ["MM_SID=r8-fresh-sid; Path=/"]},
            {"kind": "dash"},
        ]
    )
    portal.daily.append((R8_LAG_WINDOWS[window], ()))
    monkeypatch.setattr(flow_mod, "PsegClient", _r8_factory(portal))
    monkeypatch.setattr(pkg, "PsegClient", _r8_factory(portal))
    monkeypatch.setattr(pkg, "async_setup_entry", _r8_async_true)
    try:
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_OKTA_COOKIES: "", CONF_PORTAL_COOKIES: SEED},
        )
        assert result["type"] == FlowResultType.CREATE_ENTRY, result.get("errors")
        assert result["result"].unique_id == METER
        assert result["result"].data[CONF_KNOWN_METER_IDS] == [METER]
    finally:
        abort_flows(hass)


async def test_r8_label_identity_read_never_confirms_response_cookies(
    hass: HomeAssistant,
) -> None:
    """R8-1: label-only identity never confirms cookies or publishes readings."""
    portal = R6StagePortal()
    portal.dash.extend(
        [
            {"kind": "login"},
            {"kind": "dash", "set_cookie": ["MM_SID=r8-human-sid; Path=/"]},
            {"kind": "dash"},
        ]
    )
    portal.daily.append(
        (
            {"Data": {"series": [{"name": f"Meter #{METER}", "data": []}]}},
            [f"MM_SID={R6_POISON}; Path=/"],
        )
    )
    portal.hourly.append(({"Data": None}, ()))
    client = PsegClient(portal_cookies=SEED)
    client.session.mount("https://", portal)
    client.enable_label_identity_discovery()
    try:
        assert await hass.async_add_executor_job(client.renew_remember_me)
        data = await hass.async_add_executor_job(client.fetch_energy_data, 1)
        assert data["identity_source"] == "meter_label"
        assert data["identity_confirmed"] is False
        assert data["meter"] == f"Meter #{METER}"
        assert data["meter_ids"] == [METER]
        assert data["history_14d"] == [] and data["daily_records"] == []
        assert data["latest_kwh"] == 0.0 and data["latest_date"] == "None"
        assert not _r6_poisoned(client.export_cookies(), "MM_SID")
        snapshot = client.pending_confirmed_snapshot()
        assert not (snapshot and _r6_poisoned(snapshot["cookies"], "MM_SID"))
    finally:
        client.keepalive  # noqa: B018 - keep the client referenced for clarity


@pytest.mark.parametrize("window", ["label_no_points", "null_usage_points"])
async def test_r8_reauth_survives_lagging_daily_window(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, window: str
) -> None:
    """R8-1: an existing entry's human reauth must work while usage lags."""
    portal = R6StagePortal()
    factory = _r8_factory(portal)
    monkeypatch.setattr(pkg, "PsegClient", factory)
    monkeypatch.setattr(flow_mod, "PsegClient", factory)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED, CONF_KNOWN_METER_IDS: [METER]},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    try:
        result = await entry.start_reauth_flow(hass)
        portal.daily.append((R8_LAG_WINDOWS[window], ()))
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_OKTA_COOKIES: "", CONF_PORTAL_COOKIES: "MM_SID=r8-h; MM_RememberMe=r8-h-gen"},
        )
        assert result.get("reason") == "reauth_successful", result.get("errors")
        assert set(entry.data[CONF_KNOWN_METER_IDS]) == {METER}
    finally:
        await hass.async_block_till_done()
        abort_flows(hass)
        if entry.state is not ConfigEntryState.NOT_LOADED:
            await hass.config_entries.async_unload(entry.entry_id)


async def test_r8_reconfigure_survives_lagging_daily_window(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R8-1: manual reconfigure must work while usage lags."""
    portal = R6StagePortal()
    factory = _r8_factory(portal)
    monkeypatch.setattr(pkg, "PsegClient", factory)
    monkeypatch.setattr(flow_mod, "PsegClient", factory)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED, CONF_KNOWN_METER_IDS: [METER]},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    try:
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "reconfigure", "entry_id": entry.entry_id},
        )
        portal.daily.append((R8_LAG_WINDOWS["null_usage_points"], ()))
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_OKTA_COOKIES: "", CONF_PORTAL_COOKIES: "MM_SID=r8-r; MM_RememberMe=r8-r-gen"},
        )
        assert result.get("reason") == "reconfigure_successful", result.get("errors")
    finally:
        await hass.async_block_till_done()
        abort_flows(hass)
        if entry.state is not ConfigEntryState.NOT_LOADED:
            await hass.config_entries.async_unload(entry.entry_id)


async def test_r8_reauth_label_identity_still_guards_account_mismatch(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R8-1: label-derived identity must still abort a foreign account's reauth."""
    portal = R6StagePortal()
    factory = _r8_factory(portal)
    monkeypatch.setattr(pkg, "PsegClient", factory)
    monkeypatch.setattr(flow_mod, "PsegClient", factory)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED, CONF_KNOWN_METER_IDS: [METER]},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    original_cookies = copy.deepcopy(entry.data.get("cookies"))
    try:
        result = await entry.start_reauth_flow(hass)
        portal.daily.append(
            ({"Data": {"series": [{"name": "Meter #77777", "data": []}]}}, ())
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_OKTA_COOKIES: "", CONF_PORTAL_COOKIES: "MM_SID=r8-x; MM_RememberMe=r8-x-gen"},
        )
        assert result.get("reason") == "reauth_account_mismatch", result
        assert entry.data.get("cookies") == original_cookies
        assert set(entry.data[CONF_KNOWN_METER_IDS]) == {METER}
    finally:
        await hass.async_block_till_done()
        abort_flows(hass)
        if entry.state is not ConfigEntryState.NOT_LOADED:
            await hass.config_entries.async_unload(entry.entry_id)


async def test_r8_rejected_daily_real_refresh_keeps_previous_data(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R8-2: a rejected DAILY identity keeps the last good data through async_refresh."""
    from homeassistant.helpers.update_coordinator import UpdateFailed

    portal = R6StagePortal()
    client = PsegClient(portal_cookies=SEED)
    client.session.mount("https://", portal)
    client.set_expected_meter_ids({METER})
    monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        data={CONF_PORTAL_COOKIES: SEED, "meter_id": METER, CONF_KNOWN_METER_IDS: [METER]},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    coord: PsegDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    stats_calls: list[int] = []

    async def counting_stats(records: Any, **_kwargs: Any) -> None:
        stats_calls.append(len(records))

    coord.async_record_statistics = counting_stats  # type: ignore[method-assign]
    try:
        await coord.async_refresh()
        prior = copy.deepcopy(coord.data)
        assert prior["latest_kwh"] == 3.0
        prior_success = coord.last_successful_update
        prior_interval = coord.update_interval
        prior_known = sorted(entry.data.get(CONF_KNOWN_METER_IDS) or [])
        prior_states = {
            entity: hass.states.get(entity).state
            for entity in (
                "sensor.pseg_electricity_consumption",
                "sensor.pseg_latest_reading_date",
                "sensor.pseg_electricity_cost",
            )
        }
        calls_before = len(stats_calls)
        # Rejected DAILY next to a VALID known hourly leg: hourly must not carry the
        # poll to success, and nothing from the rejected leg may be published.
        portal.daily.append((_r6_daily_payload(meter="99999"), ()))
        portal.hourly.append((_r6_hourly_payload(), ()))
        await coord.async_refresh()
        assert coord.data == prior
        assert coord._last_valid_data == prior
        assert coord.last_successful_update == prior_success
        assert coord.status == "error"
        assert coord.last_update_success is False
        assert isinstance(coord.last_exception, UpdateFailed)
        assert coord.update_interval == prior_interval and prior_interval is not None
        assert len(stats_calls) == calls_before
        assert sorted(entry.data.get(CONF_KNOWN_METER_IDS) or []) == prior_known
        assert "99999" not in (entry.data.get(CONF_KNOWN_METER_IDS) or [])
        for entity, state in prior_states.items():
            assert hass.states.get(entity).state == state, entity
        assert hass.states.get("sensor.pseg_connection_status").state == "error"
        assert entry.state is ConfigEntryState.LOADED

        # The next fully confirmed poll recovers without a reauth/config-entry change.
        portal.daily.append(("__default__", ()))
        portal.hourly.append(("__default__", ()))
        await coord.async_refresh()
        assert coord.last_update_success is True
        assert coord.status == "connected"
        assert coord.data["latest_kwh"] == 3.0
        assert coord.last_successful_update != prior_success
    finally:
        coord.stop_keepalive()
        abort_flows(hass)
        await hass.async_block_till_done()
        if entry.state is not ConfigEntryState.NOT_LOADED:
            await hass.config_entries.async_unload(entry.entry_id)


async def test_r8_daily_successor_learned_when_hourly_omits_it(
    hass: HomeAssistant,
) -> None:
    """N1: the valid DAILY successor must be learned even when hourly names only the known meter."""
    portal = R6StagePortal()
    client, entry, coord = _r6_build(hass, portal)
    try:
        await coord.async_refresh()
        swap = {
            "Data": {
                "series": [
                    {
                        "name": f"Meter #{METER}",
                        "data": [{"x": 1792454400000, "y": 3.5, "hs": {"start": "10/20/2026"}}],
                    },
                    {
                        "name": "Meter #88888",
                        "data": [{"x": 1792540800000, "y": 4.5, "hs": {"start": "10/21/2026"}}],
                    },
                ]
            }
        }
        portal.daily.append((swap, ()))
        portal.hourly.append((_r6_hourly_payload(), ()))
        data = await coord.async_refresh() or coord.data
        assert data["latest_kwh"] == 4.5
        assert data["meter"] == "Meter #88888"
        assert set(entry.data.get(CONF_KNOWN_METER_IDS) or []) == {METER, "88888"}

        # Negative control: an unknown meter with only invalid points is never learned.
        invalid_unknown = {
            "Data": {
                "series": [
                    {
                        "name": f"Meter #{METER}",
                        "data": [{"x": 1792454400000, "y": 3.5, "hs": {"start": "10/20/2026"}}],
                    },
                    {
                        "name": "Meter #55555",
                        "data": [{"x": 1792540800000, "y": "nan", "hs": {"start": "bad-date"}}],
                    },
                ]
            }
        }
        portal.daily.append((invalid_unknown, ()))
        portal.hourly.append((_r6_hourly_payload(), ()))
        await coord.async_refresh()
        assert "55555" not in (entry.data.get(CONF_KNOWN_METER_IDS) or [])
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


async def test_r8_nonlist_nonmeter_telemetry_keeps_metered_leg(
    hass: HomeAssistant,
) -> None:
    """N2: a non-meter series with non-list data is skipped, never fatal to the leg."""
    portal = R6StagePortal()
    payload = {
        "Data": {
            "series": [
                {"name": "Temperature", "data": {"y": 1}},
                {
                    "name": f"Meter #{METER}",
                    "data": [{"x": 1792540800000, "y": 3.0, "hs": {"start": "10/21/2026"}}],
                },
            ]
        }
    }
    client, entry, coord = _r6_build(hass, portal)
    try:
        portal.daily.append((payload, ()))
        portal.hourly.append(({"Data": None}, ()))
        data = await coord._async_update_data()
        assert data["identity_confirmed"] is True
        assert data["latest_kwh"] == 3.0
        assert data["meter"] == f"Meter #{METER}"

        # The same broken envelope must still never confirm/rotate the cookie jar.
        portal.daily.append((payload, [f"MM_SID={R6_POISON}; Path=/"]))
        portal.hourly.append(({"Data": None}, ()))
        await coord._async_update_data()
        assert not _r6_poisoned(entry.data.get("cookies"), "MM_SID")
        snapshot = client.pending_confirmed_snapshot()
        assert not (snapshot and _r6_poisoned(snapshot["cookies"], "MM_SID"))
        assert not _r6_poisoned(client.export_cookies(), "MM_SID")

        # A malformed METER series is still a typed failure with whole-leg rollback.
        bad_meter = {
            "Data": {
                "series": [
                    {"name": f"Meter #{METER}", "data": {"x": 1}},
                ]
            }
        }
        portal.daily.append((bad_meter, [f"MM_SID={R6_POISON}; Path=/"]))
        portal.hourly.append(({"Data": None}, ()))
        with pytest.raises(UpdateFailed) as excinfo:
            await coord._async_update_data()
        assert isinstance(excinfo.value.__cause__, PsegTransientError)
        assert not _r6_poisoned(entry.data.get("cookies"), "MM_SID")
        assert not _r6_poisoned(client.export_cookies(), "MM_SID")
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


# ---------------------------------------------------------------------------
# R9: the renewal identity-proof leg is the one chart reader that proves identity
# but must never adopt an anomalous response's cookie jar.
# ---------------------------------------------------------------------------

R9_ANOMALY_SERIES = {"name": "Temperature", "data": {"unexpected": "shape"}}


@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "review_aux"])
@pytest.mark.parametrize("anomalous", [True, False], ids=["anomaly", "clean_control"])
async def test_r9_renewal_proof_anomaly_never_adopts_cookie(
    hass: HomeAssistant, cookie: str, anomalous: bool
) -> None:
    """R9-1: identity may be proven by an anomalous proof read, but never its jar."""
    portal = R6StagePortal()
    portal.dash.extend(
        [
            {"kind": "login"},
            {"kind": "dash", "set_cookie": ["MM_SID=r9-renewed-sid; Path=/"]},
            {"kind": "dash"},
        ]
    )
    payload = copy.deepcopy(_r6_daily_payload())
    if anomalous:
        payload["Data"]["series"].append(copy.deepcopy(R9_ANOMALY_SERIES))
    portal.daily.append((payload, [f"{cookie}={R6_POISON}; Path=/"]))
    portal.hourly.append(({"Data": None}, ()))
    client, entry, coord = _r6_build(hass, portal)
    try:
        await coord._async_update_data()
        assert client.sso_renewals == 1
        sequences = client._renewal_admission.as_dict()["sequences"]
        snapshot = client.pending_confirmed_snapshot()
        if anomalous:
            # Identity proven, response jar discarded: nothing marked anywhere.
            assert sequences == 1, "anomalous proof rearmed the renewal budget"
            assert not _r6_poisoned(entry.data.get("cookies"), cookie)
            assert not _r6_poisoned(client.export_cookies(), cookie)
            assert not (snapshot and _r6_poisoned(snapshot["cookies"], cookie))
            flags = await _r6_follow_on(hass, entry, coord, cookie)
            assert not any(flags), flags
            assert not portal.poison_dispatches, portal.poison_dispatches
        else:
            # Control: a clean proof read still adopts its cookie and, for a genuine
            # Remember Me rotation, rearms the generation.
            assert _r6_poisoned(entry.data.get("cookies"), cookie)
            assert _r6_poisoned(client.export_cookies(), cookie)
            if cookie == "MM_RememberMe":
                assert sequences == 0
            else:
                assert sequences == 1
    finally:
        coord.stop_keepalive()
        abort_flows(hass)

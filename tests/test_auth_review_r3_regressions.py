"""R3 regressions for the durable confirmed-jar and terminal-latch fixes.

Synthetic only: every request goes to an in-process scripted adapter, and no
cookie value, header or credential is printed. These cover the three independent
R3 findings through the real client, coordinator, entry setup/reload and backfill
paths:

* a renewal-verified jar is durable on every failure/stop/backfill exit, but a
  later failed response's Set-Cookie is never persisted and a stale owner cannot
  overwrite a human/new jar;
* a settled attempt that earned no retry is exhausted immediately, while an
  in-flight reservation, a rearmed generation and an earned retry stay transient;
* a CAPTCHA or security step seen by the poll fallback is a durable terminal
  admission that a cold process respects until a completed human sign-in.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http.client import HTTPMessage
import json
from types import SimpleNamespace
from urllib.parse import urlparse

from homeassistant.config_entries import ConfigEntryState
from homeassistant.helpers import issue_registry as ir
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
from requests.adapters import BaseAdapter

import custom_components.pseg as pkg
from custom_components.pseg.const import (
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_SECURITY_STEP,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_PORTAL_COOKIES,
    CONF_RENEWAL_ADMISSION,
    DOMAIN,
    PORTAL_BASE_URL,
    PORTAL_HOST,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import (
    PsegClient,
    PsegTransientError,
)
from custom_components.pseg.renewal_admission import (
    RenewalAdmission,
    RenewalEntryRuntime,
    rearm_entry_admission,
    renewal_runtime_for,
)

METER = "24680"
SEED = "MM_SID=r3-dead-sid; MM_RememberMe=r3-gen-a"
TOKEN_PAGE = '<html><input name="__RequestVerificationToken" value="r3-af"/>Dashboard</html>'
LOGIN_FORM = (
    '<html><form action="/Home/Login"><input name="LoginEmail"/>'
    '<input id="LoginPassword"/>'
    '<input name="__RequestVerificationToken" value="r3-form"/></form></html>'
)
LOGIN_REPLIES = {
    "ok": {"AjaxResults": [], "Data": {}},
    "security": {"Data": {"SecretQuestionError": True}},
    "captcha": {"Data": {"RecaptchaOnLogin": True}},
}


def chart_payload(meter: str = METER) -> dict:
    return {"Data": {"series": [{"name": f"Meter #{meter}", "data": [
        {"y": 3.0, "hs": {"start": "10/21/2026"}}]}]}}


class Portal(BaseAdapter):
    """One scripted dashboard spec and chart/login mode per request."""

    def __init__(self, dashboard=(), *, charts=(), logins=(), meter=METER):
        super().__init__()
        self.dashboard = list(dashboard)
        self.charts = list(charts)
        self.logins = list(logins)
        self.meter = meter
        self.events: list[tuple[str, str]] = []
        self.dash_cookies: list[str] = []

    def send(self, request, **kwargs):
        u = urlparse(request.url)
        self.events.append((request.method, u.path))
        if u.hostname != PORTAL_HOST:
            raise AssertionError("non-portal host contacted")
        r = requests.Response()
        r.status_code = 200
        r.url = request.url
        r.request = request
        r._content = b"ok"
        r._content_consumed = True
        msg = HTTPMessage()
        r.raw = SimpleNamespace(_original_response=SimpleNamespace(msg=msg))
        if request.method == "GET" and u.path == "/Dashboard":
            self.dash_cookies.append(request.headers.get("Cookie", ""))
            spec = self.dashboard.pop(0) if self.dashboard else {"kind": "dash"}
            for header in spec.get("set_cookie", ()):
                msg.add_header("Set-Cookie", header)
            kind = spec["kind"]
            if kind == "login":
                r.url = PORTAL_BASE_URL + "/"
                r._content = LOGIN_FORM.encode()
            elif kind == "dash":
                r._content = TOKEN_PAGE.encode()
            elif kind == "maint":
                r.url = PORTAL_BASE_URL + "/Maintenance"
                r._content = b"<html>maintenance</html>"
            elif kind == "notoken":
                r._content = b"<html><body>layout change</body></html>"
            elif kind == "timeout":
                raise requests.Timeout("synthetic dashboard timeout")
            else:
                raise AssertionError("bad dashboard spec")
        elif request.method == "GET" and u.path == "/":
            r._content = LOGIN_FORM.encode()
        elif request.method == "POST" and u.path == "/Home/Login":
            mode = self.logins.pop(0) if self.logins else "ok"
            r._content = json.dumps(LOGIN_REPLIES[mode]).encode()
        elif request.method == "POST" and u.path == "/Dashboard/Chart":
            mode = self.charts.pop(0) if self.charts else "ok"
            if mode == "timeout":
                raise requests.Timeout("synthetic chart timeout")
        elif request.method == "GET" and u.path == "/Dashboard/ChartData":
            r._content = json.dumps(chart_payload(self.meter)).encode()
        else:
            raise AssertionError(f"unexpected route {request.method} {u.path}")
        return r

    def close(self):
        pass

    def count(self, method: str, path: str) -> int:
        return sum(1 for e in self.events if e == (method, path))

    def password_posts(self) -> int:
        return self.count("POST", "/Home/Login")

    def renewal_http(self) -> int:
        return self.count("GET", "/") + self.count("POST", "/Home/Login")


def make_client(portal: Portal, *, login: bool = False, cookie_list=None) -> PsegClient:
    kwargs = {"portal_cookies": SEED, "cookie_list": cookie_list}
    if login:
        kwargs.update(email="r3@example.invalid", password="r3-synthetic")
    client = PsegClient(**kwargs)
    client.set_expected_meter_ids({METER})
    client.session.mount("https://", portal)
    return client


def persisted_values(entry, name: str) -> set[str]:
    return {c["value"] for c in (entry.data.get("cookies") or []) if c["name"] == name}


def shift_clock(admission, minutes: int) -> None:
    admission.last_sequence_at = (datetime.now(UTC) - timedelta(minutes=minutes)).isoformat()


def abort_flows(hass) -> None:
    for flow in hass.config_entries.flow.async_progress_by_handler(DOMAIN):
        hass.config_entries.flow.async_abort(flow["flow_id"])


def cold_runtime(hass, entry) -> None:
    """Forget the process-local admission runtime, keeping only entry.data."""
    registry = hass.data.get(f"{DOMAIN}_renewal_runtimes", {})
    registry.pop(entry.entry_id, None)


def admission(**overrides) -> dict:
    state = {
        "sequences": 0,
        "last_sequence_at": None,
        "terminal_reason": None,
        "retry_eligible": False,
    }
    state.update(overrides)
    return state


# ======================================================================================
# R3 N1: the renewal-verified jar is durable on every exit
# ======================================================================================
@pytest.mark.parametrize("rotate", [False, True])
async def test_setup_persists_confirmed_renewal_before_a_later_chart_timeout(
    hass, monkeypatch, rotate
):
    """A failed setup hands off the renewed jar next to its settled budget."""
    renewed = ["MM_SID=r3-renewed-sid; Path=/"]
    if rotate:
        renewed.append("MM_RememberMe=r3-gen-b; Path=/")
    portals: list[Portal] = []
    scripts = [
        dict(dashboard=[{"kind": "login"},
                        {"kind": "dash", "set_cookie": renewed},
                        {"kind": "dash"}], charts=["ok", "timeout"]),
        dict(dashboard=[{"kind": "login"}]),
    ]
    real = PsegClient

    def factory(**kwargs):
        client = real(**kwargs)
        portal = Portal(**scripts[len(portals)])
        client.session.mount("https://", portal)
        portals.append(portal)
        return client

    monkeypatch.setattr(pkg, "PsegClient", factory)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    try:
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.SETUP_RETRY
        assert "r3-renewed-sid" in persisted_values(entry, "MM_SID")
        assert "r3-dead-sid" not in persisted_values(entry, "MM_SID")
        state = entry.data[CONF_RENEWAL_ADMISSION]
        if rotate:
            assert state["sequences"] == 0
            assert state["last_sequence_at"] is not None
            assert "r3-gen-b" in persisted_values(entry, "MM_RememberMe")
        else:
            assert state["sequences"] == 1
            assert state["retry_eligible"] is False

        await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
        probe = portals[1].dash_cookies[0]
        assert "r3-renewed-sid" in probe
        assert "r3-dead-sid" not in probe
    finally:
        abort_flows(hass)
        if entry.state is ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
            await hass.async_block_till_done()


async def test_runtime_poll_persists_confirmed_renewal_before_a_later_timeout(hass):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "login"},
                     {"kind": "dash", "set_cookie": ["MM_SID=r3-renewed-sid; Path=/"]},
                     {"kind": "dash"}], charts=["ok", "timeout"])
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    unsub = coord.async_add_listener(lambda: None)
    try:
        await coord.async_refresh()
        await hass.async_block_till_done()
        assert coord.status == "error"
        assert coord._is_stale() is False
        assert "r3-renewed-sid" in persisted_values(entry, "MM_SID")
        assert entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 1
    finally:
        unsub()
        coord.stop_keepalive()
        abort_flows(hass)


async def test_stop_keepalive_persists_a_confirmed_renewal_before_retiring(hass):
    """No poll/keepalive persist runs: only the stop handoff can save this jar."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "login"},
                     {"kind": "dash", "set_cookie": [
                         "MM_SID=r3-renewed-sid; Path=/",
                         "MM_RememberMe=r3-gen-b; Path=/"]}])
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    try:
        await hass.async_add_executor_job(client._get_verification_token)
        assert "cookies" not in entry.data or "r3-renewed-sid" not in persisted_values(
            entry, "MM_SID"
        )
        coord.stop_keepalive()
        await hass.async_block_till_done()
        assert "r3-renewed-sid" in persisted_values(entry, "MM_SID")
        assert "r3-gen-b" in persisted_values(entry, "MM_RememberMe")
        assert entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 0
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


async def test_backfill_persists_a_confirmed_renewal_when_its_chart_times_out(hass):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "login"},
                     {"kind": "dash", "set_cookie": [
                         "MM_SID=r3-renewed-sid; Path=/",
                         "MM_RememberMe=r3-gen-b; Path=/"]}], charts=["ok", "timeout"])
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    try:
        with pytest.raises(PsegTransientError):
            await coord.async_backfill_history("2026-09-01", "2026-09-30")
        await hass.async_block_till_done()
        assert "r3-renewed-sid" in persisted_values(entry, "MM_SID")
        assert entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 0
        # The statistics journal/provenance path never ran for this failed fetch.
        assert coord.last_statistics_import is None
    finally:
        coord.stop_keepalive()


async def test_failed_response_poison_cookie_is_never_persisted_or_replayed(hass):
    """Post-renewal maintenance Set-Cookie is rolled back and Coordinator persists only the immutable snapshot."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    portal = Portal([
        {"kind": "login"},
        {"kind": "dash", "set_cookie": ["MM_SID=r3-renewed-sid; Path=/"]},
        {"kind": "maint", "set_cookie": [
            "MM_SID=r3-poison-sid; Path=/",
            "MM_RememberMe=r3-poison-gen; Path=/"]},
    ])
    client = make_client(portal)
    orig_fetch = client.fetch_energy_data

    def _fetch_then_contaminate_live_jar(*args, **kwargs):
        try:
            return orig_fetch(*args, **kwargs)
        finally:
            assert {c.value for c in client.session.cookies if c.name == "MM_SID"} == {
                "r3-renewed-sid"
            }
            client.session.cookies.set("MM_SID", "r3-poison-sid", domain=PORTAL_HOST, path="/")

    client.fetch_energy_data = _fetch_then_contaminate_live_jar
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    unsub = coord.async_add_listener(lambda: None)
    try:
        await coord.async_refresh()
        await hass.async_block_till_done()
        assert coord.status == "error"
        assert {c.value for c in client.session.cookies if c.name == "MM_SID"} == {
            "r3-poison-sid"
        }
        assert "r3-renewed-sid" in persisted_values(entry, "MM_SID")
        assert "r3-poison-sid" not in persisted_values(entry, "MM_SID")
        assert "r3-poison-gen" not in persisted_values(entry, "MM_RememberMe")

        cold_runtime(hass, entry)
        coord.stop_keepalive()
        portal2 = Portal([{"kind": "login"}])
        client2 = make_client(portal2, cookie_list=entry.data["cookies"])
        coord2 = PsegDataUpdateCoordinator(hass, client2, dict(entry.data), config_entry=entry)
        try:
            await coord2._async_keepalive(None)
            assert "r3-poison" not in portal2.dash_cookies[0]
            assert "r3-renewed-sid" in portal2.dash_cookies[0]
        finally:
            coord2.stop_keepalive()
    finally:
        unsub()
        coord.stop_keepalive()
        abort_flows(hass)


async def test_stale_owner_never_overwrites_a_human_replaced_jar(hass):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "login"},
                     {"kind": "dash", "set_cookie": [
                         "MM_SID=r3-renewed-sid; Path=/",
                         "MM_RememberMe=r3-gen-b; Path=/"]},
                     {"kind": "dash"}])
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    try:
        await hass.async_add_executor_job(client._get_verification_token)
        human = [
            {"name": "MM_SID", "value": "r3-human-sid", "domain": PORTAL_HOST,
             "path": "/", "secure": True},
            {"name": "MM_RememberMe", "value": "r3-human-gen", "domain": PORTAL_HOST,
             "path": "/", "secure": True},
        ]
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, "cookies": human}
        )
        assert coord._jar_replaced()
        coord._persist_confirmed_session()
        assert persisted_values(entry, "MM_SID") == {"r3-human-sid"}
        assert persisted_values(entry, "MM_RememberMe") == {"r3-human-gen"}
        coord.stop_keepalive()
        assert persisted_values(entry, "MM_SID") == {"r3-human-sid"}
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


# ======================================================================================
# R3 N2: exhausted is auth now; cooldown is only a real pending attempt
# ======================================================================================
def test_settled_unchanged_success_is_exhausted_before_its_window_closes() -> None:
    now = datetime.now(UTC)
    state = RenewalAdmission()
    state.reserve(now)
    state.record_outcome(None, transient=False)
    assert state.blocked_reason(now + timedelta(minutes=5)) == "exhausted"
    assert state.blocked_reason(now + timedelta(days=1)) == "exhausted"


def test_inflight_reservation_rearmed_generation_and_earned_retry_stay_transient() -> None:
    now = datetime.now(UTC)
    in_flight = RenewalAdmission()
    in_flight.reserve(now)
    assert in_flight.blocked_reason(now + timedelta(minutes=5)) == "cooldown"

    rearmed = RenewalAdmission()
    rearmed.reserve(now)
    rearmed.record_outcome(None, transient=False)
    rearmed.rearm()
    assert rearmed.sequences == 0
    assert rearmed.blocked_reason(now + timedelta(minutes=5)) == "cooldown"

    earned = RenewalAdmission()
    earned.reserve(now)
    earned.record_outcome(None, transient=True)
    assert earned.blocked_reason(now + timedelta(minutes=5)) == "cooldown"
    assert earned.blocked_reason(now + timedelta(minutes=16)) is None


def test_retired_and_busy_reservations_are_transient() -> None:
    runtime = RenewalEntryRuntime("r3-synthetic")
    runtime.bind({})
    token = runtime.activate()
    assert runtime.reserve(token, datetime.now(UTC)) is None
    assert runtime.reserve(token, datetime.now(UTC)) == "busy"
    runtime.retire(token)
    assert runtime.reserve(token, datetime.now(UTC)) == "retired"


async def test_poll_with_spent_generation_asks_for_auth_immediately(hass):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_RENEWAL_ADMISSION: admission(
            sequences=1, last_sequence_at=(datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        ),
    })
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "login"}] * 3)
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    unsub = coord.async_add_listener(lambda: None)
    try:
        await coord.async_refresh()
        await hass.async_block_till_done()
        assert coord.auth_required is True
        assert coord.status == "auth_required"
        assert len(hass.config_entries.flow.async_progress_by_handler(DOMAIN)) == 1
        issue = ir.async_get(hass).async_get_issue(
            DOMAIN, f"reauth_required_{entry.entry_id}"
        )
        assert issue is not None
        assert portal.renewal_http() == 0
    finally:
        unsub()
        coord.stop_keepalive()
        abort_flows(hass)


async def test_keepalive_with_spent_generation_asks_for_auth_immediately(hass):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_RENEWAL_ADMISSION: admission(
            sequences=1, last_sequence_at=(datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        ),
    })
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "login"}] * 3)
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    unsub = coord.async_add_listener(lambda: None)
    try:
        await coord._async_keepalive(None)
        await hass.async_block_till_done()
        assert coord.auth_required is True
        assert len(hass.config_entries.flow.async_progress_by_handler(DOMAIN)) == 1
        assert portal.renewal_http() == 0
    finally:
        unsub()
        coord.stop_keepalive()
        abort_flows(hass)


async def test_setup_with_spent_generation_is_an_auth_error_not_a_password_post(
    hass, monkeypatch
):
    portals: list[Portal] = []
    real = PsegClient

    def factory(**kwargs):
        client = real(**kwargs)
        portal = Portal([{"kind": "login"}] * 3)
        client.session.mount("https://", portal)
        portals.append(portal)
        return client

    monkeypatch.setattr(pkg, "PsegClient", factory)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_MYMETER_EMAIL: "r3@example.invalid",
        CONF_MYMETER_PASSWORD: "r3-synthetic",
        CONF_RENEWAL_ADMISSION: admission(
            sequences=1, last_sequence_at=(datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        ),
    })
    entry.add_to_hass(hass)
    try:
        assert not await hass.config_entries.async_setup(entry.entry_id)
        assert entry.state is ConfigEntryState.SETUP_ERROR
        assert portals[0].password_posts() == 0
        assert portals[0].renewal_http() == 0
        assert len(hass.config_entries.flow.async_progress_by_handler(DOMAIN)) == 1
    finally:
        abort_flows(hass)


async def test_setup_with_an_earned_retry_in_cooldown_stays_setup_retry(hass, monkeypatch):
    portals: list[Portal] = []
    real = PsegClient

    def factory(**kwargs):
        client = real(**kwargs)
        portal = Portal([{"kind": "login"}] * 3)
        client.session.mount("https://", portal)
        portals.append(portal)
        return client

    monkeypatch.setattr(pkg, "PsegClient", factory)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_RENEWAL_ADMISSION: admission(
            sequences=1,
            last_sequence_at=(datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
            retry_eligible=True,
        ),
    })
    entry.add_to_hass(hass)
    try:
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.SETUP_RETRY
        assert portals[0].password_posts() == 0
        assert portals[0].renewal_http() == 0
        assert hass.config_entries.flow.async_progress_by_handler(DOMAIN) == []
    finally:
        abort_flows(hass)


# ======================================================================================
# R3 N3: CAPTCHA/security are durable terminal admissions
# ======================================================================================
@pytest.mark.parametrize("reply,reason,error", [
    ("captcha", AUTH_REASON_CAPTCHA_REQUIRED, "PsegCaptchaRequired"),
    ("security", AUTH_REASON_SECURITY_STEP, "PsegSecurityStepRequired"),
])
async def test_poll_fallback_challenge_survives_reload_and_cold_process(
    hass, reply, reason, error
):
    data = {CONF_PORTAL_COOKIES: SEED,
            CONF_MYMETER_EMAIL: "r3@example.invalid",
            CONF_MYMETER_PASSWORD: "r3-synthetic",
            CONF_RENEWAL_ADMISSION: admission(
                sequences=1,
                last_sequence_at=(datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
                retry_eligible=True,
            )}
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data=data)
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "login"}] * 4, logins=[reply])
    client = make_client(portal, login=True)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    unsub = coord.async_add_listener(lambda: None)
    try:
        await coord.async_refresh()
        await hass.async_block_till_done()
        assert coord.auth_required is True
        assert portal.password_posts() == 1
        assert client.auth_reason == reason
        assert client._security_step_latched is (reply == "security")
        assert client._captcha_latched is (reply == "captcha")
        assert entry.data[CONF_RENEWAL_ADMISSION]["terminal_reason"] == reason

        unsub()
        coord.stop_keepalive()
        cold_runtime(hass, entry)

        # Cold process: a fresh client with the saved login must send nothing.
        portal2 = Portal([{"kind": "login"}] * 6, logins=[reply])
        client2 = make_client(portal2, login=True, cookie_list=entry.data.get("cookies"))
        coord2 = PsegDataUpdateCoordinator(hass, client2, dict(entry.data), config_entry=entry)
        unsub2 = coord2.async_add_listener(lambda: None)
        try:
            assert coord2._renewal_admission.terminal_reason == reason
            await coord2._async_keepalive(None)
            await hass.async_block_till_done()
            assert portal2.events == []
            assert coord2.auth_required is True
            await coord2.async_refresh()
            await hass.async_block_till_done()
            assert portal2.password_posts() == 0
            assert portal2.renewal_http() == 0
        finally:
            unsub2()
            coord2.stop_keepalive()
            abort_flows(hass)
    finally:
        if not coord._stopped:
            unsub()
            coord.stop_keepalive()
        abort_flows(hass)


@pytest.mark.parametrize("reply", ["captcha", "security"])
async def test_failed_startup_challenge_is_durable_metadata(hass, monkeypatch, reply):
    portals: list[Portal] = []
    real = PsegClient

    def factory(**kwargs):
        client = real(**kwargs)
        portal = Portal([{"kind": "login"}] * 4, logins=[reply])
        client.session.mount("https://", portal)
        portals.append(portal)
        return client

    monkeypatch.setattr(pkg, "PsegClient", factory)
    reason = (
        AUTH_REASON_CAPTCHA_REQUIRED if reply == "captcha" else AUTH_REASON_SECURITY_STEP
    )
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_MYMETER_EMAIL: "r3@example.invalid",
        CONF_MYMETER_PASSWORD: "r3-synthetic",
        CONF_RENEWAL_ADMISSION: admission(
            sequences=1,
            last_sequence_at=(datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
            retry_eligible=True,
        ),
    })
    entry.add_to_hass(hass)
    try:
        assert not await hass.config_entries.async_setup(entry.entry_id)
        assert portals[0].password_posts() == 1
        assert entry.data[CONF_RENEWAL_ADMISSION]["terminal_reason"] == reason
        cold_runtime(hass, entry)
        await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
        assert portals[1].password_posts() == 0
        assert portals[1].renewal_http() == 0
        assert entry.data[CONF_RENEWAL_ADMISSION]["terminal_reason"] == reason
    finally:
        abort_flows(hass)


async def test_ordinary_success_does_not_clear_the_terminal_latch(hass):
    reason = AUTH_REASON_CAPTCHA_REQUIRED
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_RENEWAL_ADMISSION: admission(sequences=1, terminal_reason=reason,
                                          last_sequence_at=datetime.now(UTC).isoformat()),
    })
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "dash"}])
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    try:
        # A plain Dashboard success is not a human rearm.
        await hass.async_add_executor_job(client.ensure_session)
        assert coord._renewal_admission.terminal_reason == reason
        assert entry.data[CONF_RENEWAL_ADMISSION]["terminal_reason"] == reason
        # A cold process reading the same bytes still sees the latch.
        cold_runtime(hass, entry)
        runtime = renewal_runtime_for(hass, entry.entry_id)
        runtime.bind(entry.data)
        assert runtime.admission.terminal_reason == reason
    finally:
        coord.stop_keepalive()
        abort_flows(hass)


async def test_partial_confirmed_snapshot_is_never_persisted(hass):
    """A captured jar that lost a session cookie is refused by the handoff guard."""
    seed_list = [
        {"name": "MM_SID", "value": "r3-dead-sid", "domain": PORTAL_HOST,
         "path": "/", "secure": True},
        {"name": "MM_RememberMe", "value": "r3-gen-a", "domain": PORTAL_HOST,
         "path": "/", "secure": True},
    ]
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED, "cookies": seed_list,
    })
    entry.add_to_hass(hass)
    portal = Portal([{"kind": "dash"}])
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    try:
        client._confirmed_snapshot = {
            "id": 99,
            "cookies": [seed_list[1]],  # the half-empty jar after MM_SID was dropped
            "auth_reason": None,
            "cookies_confirmed": True,
        }
        coord._persist_confirmed_session()
        assert entry.data["cookies"] == seed_list
    finally:
        client._confirmed_snapshot = None
        coord.stop_keepalive()


@pytest.mark.parametrize("reason", [AUTH_REASON_CAPTCHA_REQUIRED, AUTH_REASON_SECURITY_STEP])
async def test_completed_human_rearm_clears_terminal_and_keeps_the_global_clock(
    hass, reason
):
    reserved = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_RENEWAL_ADMISSION: admission(
            sequences=1, last_sequence_at=reserved, terminal_reason=reason
        ),
    })
    entry.add_to_hass(hass)
    runtime = renewal_runtime_for(hass, entry.entry_id)
    runtime.bind(entry.data)
    fresh = rearm_entry_admission(
        hass, entry.entry_id, entry.data.get(CONF_RENEWAL_ADMISSION), True
    )
    assert fresh["sequences"] == 0
    assert fresh["terminal_reason"] is None
    assert fresh["last_sequence_at"] == reserved  # the 15-minute clock survives
    assert runtime.admission.blocked_reason(datetime.now(UTC)) == "cooldown"

    # After the gap a fresh client may renew again; no password is posted.
    shift_clock(runtime.admission, 16)
    portal = Portal([{"kind": "login"},
                     {"kind": "dash", "set_cookie": ["MM_SID=r3-human-renewed; Path=/"]}])
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    try:
        assert client.keepalive() is True
        assert portal.password_posts() == 0
        assert client.auth_reason is None
    finally:
        coord.stop_keepalive()

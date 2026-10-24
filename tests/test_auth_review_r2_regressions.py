"""R2 regressions for the bounded local renewal fixes (synthetic only).

Complements ``test_auth_review_regressions.py`` (R1): these prove the five
independent R2 findings stay closed through the real client and coordinator
paths. Every request goes to an in-process scripted adapter; no network, vendor,
credential or live Home Assistant is touched, and no cookie value is printed.
"""
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
    AUTH_REASON_REMEMBER_ME_REJECTED,
    AUTH_REASON_SECURITY_STEP,
    CONF_PORTAL_COOKIES,
    CONF_RENEWAL_ADMISSION,
    DOMAIN,
    PORTAL_BASE_URL,
    PORTAL_HOST,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import (
    PsegClient,
    PsegSecurityStepRequired,
    PsegTransientError,
)

METER = "12345"
TOKEN_HTML = '<html><input name="__RequestVerificationToken" value="synthetic-af"/>Dashboard</html>'
SEED = "MM_SID=synthetic-dead; MM_RememberMe=synthetic-gen-a"
LOGIN_FORM = (
    '<html><form action="/Home/Login"><input name="LoginEmail"/>'
    '<input id="LoginPassword"/>'
    '<input name="__RequestVerificationToken" value="synthetic-form"/></form></html>'
)
LOGIN_OK = {"AjaxResults": [], "Data": {}}
SAML_AUTOPOST = (
    f'<form method="POST" action="{PORTAL_BASE_URL}/Saml/okta-prod/Acs">'
    '<input type="hidden" name="SAMLResponse" value="assertion"/></form>'
)
REAUTH_ISSUE = "reauth_required_{entry_id}"


def chart(meter: str = METER) -> dict:
    return {"Data": {"series": [{"name": f"Meter #{meter}", "data": [
        {"y": 4.0, "hs": {"start": "10/22/2026"}}]}]}}


class ScriptedPortal(BaseAdapter):
    """One scripted specification per /Dashboard request, consumed in order."""

    def __init__(self, dashboard, *, chart_mode="ok", meter=METER):
        super().__init__()
        self.dashboard = list(dashboard)
        self.chart_mode = chart_mode
        self.meter = meter
        self.events = []

    def send(self, request, **kwargs):
        u = urlparse(request.url)
        self.events.append((request.method, u.path))
        r = requests.Response()
        r.status_code = 200
        r.url = request.url
        r.request = request
        r._content = b"ok"
        r._content_consumed = True
        msg = HTTPMessage()
        r.raw = SimpleNamespace(_original_response=SimpleNamespace(msg=msg))
        if u.hostname != PORTAL_HOST:
            raise AssertionError("non-portal host contacted")
        if request.method == "GET" and u.path == "/Dashboard":
            spec = self.dashboard.pop(0) if self.dashboard else {"kind": "dash"}
            for header in spec.get("set_cookie", ()):
                msg.add_header("Set-Cookie", header)
            kind = spec["kind"]
            if kind == "login":
                r.url = PORTAL_BASE_URL + "/"
            elif kind == "dash":
                r._content = TOKEN_HTML.encode()
            elif kind == "notoken":
                r._content = b"<html><body>layout change</body></html>"
            elif kind == "maint":
                r.url = PORTAL_BASE_URL + "/Maintenance"
                r._content = b"<html>maintenance</html>"
            elif kind == "status":
                r.status_code = spec["status"]
            elif kind == "timeout":
                raise requests.Timeout("synthetic dashboard timeout")
            else:
                raise AssertionError("bad scripted dashboard spec")
        elif request.method == "GET" and u.path == "/":
            r._content = LOGIN_FORM.encode()
        elif request.method == "POST" and u.path == "/Home/Login":
            r._content = json.dumps(LOGIN_OK).encode()
        elif request.method == "GET" and u.path == "/Saml/okta-prod/SignIn":
            r._content = SAML_AUTOPOST.encode()
        elif request.method == "POST" and u.path == "/Saml/okta-prod/Acs":
            pass
        elif request.method == "POST" and u.path == "/Dashboard/Chart":
            if self.chart_mode == "timeout":
                raise requests.Timeout("synthetic chart timeout")
        elif request.method == "GET" and u.path == "/Dashboard/ChartData":
            r._content = json.dumps(chart(self.meter)).encode()
        else:
            raise AssertionError(f"unexpected synthetic route {request.method} {u.path}")
        return r

    def close(self):
        pass

    def password_posts(self) -> int:
        return sum(1 for method, path in self.events if method == "POST" and path == "/Home/Login")

    def home_gets(self) -> int:
        return sum(1 for method, path in self.events if method == "GET" and path == "/")


def make_client(portal, *, login=False) -> PsegClient:
    kwargs = {"portal_cookies": SEED}
    if login:
        kwargs.update(email="fixture@example.invalid", password="synthetic-secret")
    client = PsegClient(**kwargs)
    client.set_expected_meter_ids({METER})
    client.session.mount("https://", portal)
    return client


def sid_values(client) -> set[str]:
    return {c.value for c in client.session.cookies if c.name == "MM_SID"}


# --------------------------------------------------------------------------------------
# R2 finding 1: a verified renewal survives a later maintenance/4xx/missing-token page
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("second", [
    {"kind": "maint"},
    {"kind": "status", "status": 404},
    {"kind": "status", "status": 429},
    {"kind": "notoken"},
])
@pytest.mark.parametrize("rotate", [False, True])
def test_poll_keeps_the_verified_renewal_after_a_post_renewal_hiccup(second, rotate):
    """The poll's own probe expires, the renewal verifies, then the token GET fails."""
    renew = ["MM_SID=synthetic-renewed; Path=/"]
    if rotate:
        renew.append("MM_RememberMe=synthetic-gen-b; Path=/")
    portal = ScriptedPortal([
        {"kind": "login"},
        {"kind": "dash", "set_cookie": renew},
        dict(second),
    ])
    client = make_client(portal)

    with pytest.raises(PsegTransientError):
        client._get_verification_token()

    assert "synthetic-renewed" in sid_values(client), "verified renewal was rolled back"
    assert "synthetic-dead" not in sid_values(client)
    assert client.cookies_confirmed is True
    assert client.sso_renewals == 1
    assert client._renewal_admission.retry_eligible is False
    if rotate:
        assert client._remember_me_values() == frozenset({"synthetic-gen-b"})
        assert client._remember_me_seen == frozenset({"synthetic-gen-b"})
        # Verified replacement: a new generation, but never an immediate retry.
        assert client._renewal_admission.sequences == 0
        assert client._renewal_admission.blocked_reason(datetime.now(UTC)) == "cooldown"
    else:
        assert client._remember_me_values() == frozenset({"synthetic-gen-a"})
        assert client._renewal_admission.sequences == 1


def test_poll_keeps_a_verified_saved_login_after_a_post_renewal_hiccup():
    """The same rule applies when the saved-login fallback, not the cookie, succeeds."""
    portal = ScriptedPortal([
        {"kind": "login"},   # poll probe
        {"kind": "login"},   # cookie renewal: rejected
        {"kind": "login"},   # cookie renewal retry: rejected
        {"kind": "dash", "set_cookie": ["MM_SID=synthetic-login; Path=/"]},
        {"kind": "maint"},   # token GET after the sign-in
    ])
    client = make_client(portal, login=True)

    with pytest.raises(PsegTransientError):
        client._get_verification_token()

    assert portal.password_posts() == 1
    assert sid_values(client) == {"synthetic-login"}
    assert client.cookies_confirmed is True
    assert client.auth_reason is None
    assert client.sso_renewals == 1
    # The rejected cookie generation stays refused: the fallback never rearms it.
    assert client._renewal_admission.terminal_reason == AUTH_REASON_REMEMBER_ME_REJECTED


def test_poll_keeps_a_verified_sso_session_after_a_post_renewal_hiccup():
    """The SSO fallback is covered by the same post-renewal transaction rule."""
    portal = ScriptedPortal([{"kind": "login"}, {"kind": "dash"}, {"kind": "maint"}])
    client = PsegClient(okta_cookies="idx=synthetic-okta-session")
    client.session.mount("https://", portal)

    with pytest.raises(PsegTransientError):
        client._get_verification_token()

    assert client.sso_renewals == 1
    assert client.cookies_confirmed is True
    assert client.auth_reason is None


# --------------------------------------------------------------------------------------
# R2 finding 2: a pending earned retry is a scheduled wait, not an auth failure
# --------------------------------------------------------------------------------------
async def test_poll_during_an_earned_retry_cooldown_keeps_the_schedule(hass):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER,
                            data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    portal = ScriptedPortal([
        {"kind": "login"}, {"kind": "dash"},   # keepalive: renewal, chart times out
        {"kind": "login"},                     # poll probe inside the cooldown
        {"kind": "login"}, {"kind": "dash"},   # keepalive retry after the gap
    ], chart_mode="timeout")
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    unsub = coord.async_add_listener(lambda: None)
    try:
        await coord._async_keepalive(None)
        admission = coord._renewal_admission
        assert (admission.sequences, admission.retry_eligible) == (1, True)
        assert not coord.auth_required

        await coord.async_refresh()
        await hass.async_block_till_done()
        assert not coord.auth_required, "a pending retry was reported as an auth failure"
        assert coord._unsub_refresh is not None, "the poll schedule was killed"
        assert hass.config_entries.flow.async_progress_by_handler(DOMAIN) == []
        assert admission.retry_eligible is True
        assert portal.home_gets() == 0

        portal.chart_mode = "ok"
        admission.last_sequence_at = (
            datetime.now(UTC) - timedelta(minutes=16)
        ).isoformat()
        await coord._async_keepalive(None)
        await hass.async_block_till_done()
        assert client.sso_renewals == 1
        assert not coord.auth_required
        assert coord._unsub_refresh is not None
    finally:
        unsub()
        coord.stop_keepalive()


async def test_setup_during_an_earned_retry_cooldown_retries_instead_of_auth(hass, monkeypatch):
    clients = []
    real_client = PsegClient

    def factory(**kwargs):
        client = real_client(**kwargs)
        client.session.mount("https://", ScriptedPortal([{"kind": "login"}]))
        clients.append(client)
        return client

    monkeypatch.setattr(pkg, "PsegClient", factory)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_RENEWAL_ADMISSION: {
            "sequences": 1,
            "last_sequence_at": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
            "terminal_reason": None,
            "retry_eligible": True,
        },
    })
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    try:
        assert entry.state is ConfigEntryState.SETUP_RETRY, (
            "a pending earned retry made startup a terminal auth error"
        )
        assert hass.config_entries.flow.async_progress_by_handler(DOMAIN) == []
        assert entry.data[CONF_RENEWAL_ADMISSION]["retry_eligible"] is True
        assert clients[0].sso_renewals == 0
    finally:
        for flow in hass.config_entries.flow.async_progress_by_handler(DOMAIN):
            hass.config_entries.flow.async_abort(flow["flow_id"])


# --------------------------------------------------------------------------------------
# R2 finding 3: unreadable renewal metadata fails closed behind the normal reauth prompt
# --------------------------------------------------------------------------------------
async def test_corrupt_budget_prompts_the_normal_reauth_flow(hass):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_RENEWAL_ADMISSION: "corrupt",
    })
    entry.add_to_hass(hass)
    portal = ScriptedPortal([{"kind": "login"}] * 6)
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    unsub = coord.async_add_listener(lambda: None)
    try:
        for _ in range(2):
            await coord._async_keepalive(None)
            await hass.async_block_till_done()
        await coord.async_refresh()
        await hass.async_block_till_done()

        assert coord.auth_required is True
        assert coord.status == "auth_required"
        flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        assert len(flows) == 1
        issue = ir.async_get(hass).async_get_issue(
            DOMAIN, REAUTH_ISSUE.format(entry_id=entry.entry_id)
        )
        assert issue is not None
        # Fail closed: no automatic cookie renewal, and the corrupt value is untouched.
        assert portal.home_gets() == 0
        assert coord._renewal_admission.uncertain is True
        assert entry.data[CONF_RENEWAL_ADMISSION] == "corrupt"
    finally:
        unsub()
        coord.stop_keepalive()
        for flow in hass.config_entries.flow.async_progress_by_handler(DOMAIN):
            hass.config_entries.flow.async_abort(flow["flow_id"])


# --------------------------------------------------------------------------------------
# R2 finding 4: only a renewal's own rotation counts as a new generation
# --------------------------------------------------------------------------------------
def test_confirmed_dashboard_slide_is_not_a_renewal_rotation():
    portal = ScriptedPortal([
        {"kind": "dash", "set_cookie": ["MM_RememberMe=synthetic-gen-b; Path=/"]},
        {"kind": "login"},
        {"kind": "dash", "set_cookie": ["MM_SID=synthetic-renewed; Path=/"]},
    ])
    client = make_client(portal)

    assert client.keepalive() is True
    assert client._renewal_admission.sequences == 0
    assert client._renewal_admission.last_sequence_at is None
    assert client._remember_me_seen == frozenset({"synthetic-gen-b"})

    assert client.keepalive() is True
    # The renewal did not rotate anything: the slide is not an extra generation.
    # R3 N2: a settled attempt that earned no retry is exhausted immediately, even
    # while its 15-minute window is open; no later attempt can follow.
    assert client._renewal_admission.sequences == 1
    assert client._renewal_admission.blocked_reason(datetime.now(UTC)) == "exhausted"
    assert client._remember_me_values() == frozenset({"synthetic-gen-b"})


def test_confirmed_slide_with_a_domain_copy_is_not_a_renewal_rotation():
    """The vendor can set the same cookie as a '.host' copy; one generation, not two."""
    portal = ScriptedPortal([
        {"kind": "dash", "set_cookie": [
            "MM_RememberMe=synthetic-gen-b; Domain=.mysmartenergy.nj.pseg.com; Path=/"]},
        {"kind": "login"},
        {"kind": "dash", "set_cookie": ["MM_SID=synthetic-renewed; Path=/"]},
    ])
    client = make_client(portal)
    assert len(client._remember_me_values()) == 1  # seeded host-only copy

    assert client.keepalive() is True
    assert client._remember_me_seen == frozenset({"synthetic-gen-b"})
    assert client.keepalive() is True
    assert client._renewal_admission.sequences == 1


def test_verified_renewal_rotation_still_rearms_after_a_confirmed_slide():
    portal = ScriptedPortal([
        {"kind": "dash", "set_cookie": ["MM_RememberMe=synthetic-gen-b; Path=/"]},
        {"kind": "login"},
        {"kind": "dash", "set_cookie": ["MM_SID=synthetic-renewed; Path=/",
                                        "MM_RememberMe=synthetic-gen-c; Path=/"]},
        {"kind": "login"},
        {"kind": "dash", "set_cookie": ["MM_SID=synthetic-renewed-2; Path=/"]},
    ])
    client = make_client(portal)

    assert client.keepalive() is True
    assert client.keepalive() is True
    # A real replacement rearms the generation count but keeps the global clock.
    assert client._renewal_admission.sequences == 0
    assert client._renewal_admission.blocked_reason(datetime.now(UTC)) == "cooldown"
    assert client._remember_me_values() == frozenset({"synthetic-gen-c"})
    assert client._remember_me_seen == frozenset({"synthetic-gen-c"})

    client._renewal_admission.last_sequence_at = (
        datetime.now(UTC) - timedelta(minutes=16)
    ).isoformat()
    assert client.keepalive() is True
    # The new generation gets its initial attempt, not a third one.
    assert client._renewal_admission.sequences == 1
    assert client._renewal_admission.retry_eligible is False


# --------------------------------------------------------------------------------------
# R2 finding 5: a pending security step latches every automatic attempt
# --------------------------------------------------------------------------------------
def test_security_step_latch_stops_automatic_sign_in_and_renewal():
    portal = ScriptedPortal([{"kind": "login"}, {"kind": "login"}])
    client = make_client(portal, login=True)
    client._mark_auth_failure(AUTH_REASON_SECURITY_STEP)

    with pytest.raises(PsegSecurityStepRequired):
        client.keepalive()
    with pytest.raises(PsegSecurityStepRequired):
        client._renew()
    with pytest.raises(PsegSecurityStepRequired):
        client.login_local()

    assert portal.events == [], "an automatic request was sent while a security step is pending"
    assert client.auth_reason == AUTH_REASON_SECURITY_STEP
    assert client._renewal_admission.sequences == 0


def test_confirmed_sign_in_clears_the_security_step_latch():
    portal = ScriptedPortal([{"kind": "dash"}])
    client = make_client(portal, login=True)
    client._mark_auth_failure(AUTH_REASON_SECURITY_STEP)

    assert client.submit_login_captcha("synthetic-human-proof") is True

    assert client._security_step_latched is False
    assert client.auth_reason is None


# --------------------------------------------------------------------------------------
# Retained fallback: a saved login still renews a session whose cookie is in cooldown
# --------------------------------------------------------------------------------------
def test_poll_cooldown_still_uses_the_permitted_saved_login_fallback():
    portal = ScriptedPortal([{"kind": "dash"}])
    client = make_client(portal, login=True)
    admission = client._renewal_admission
    admission.sequences, admission.retry_eligible = 1, True
    admission.last_sequence_at = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    reserved_at = admission.last_sequence_at

    assert client._renew() is True

    assert portal.password_posts() == 1
    # Only the login form fetch: the cookie renewal itself sent no landing request.
    assert portal.home_gets() == 1
    assert client.sso_renewals == 1
    # The permitted fallback spends no cookie sequence.
    assert admission.sequences == 1
    assert admission.last_sequence_at == reserved_at


# --------------------------------------------------------------------------------------
# Coordinator wiring: a real poll sees the repair prompt, never a silent loop
# --------------------------------------------------------------------------------------
async def test_uncertain_budget_fails_closed_through_the_real_poll(hass):
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={
        CONF_PORTAL_COOKIES: SEED,
        CONF_RENEWAL_ADMISSION: {"sequences": -1},
    })
    entry.add_to_hass(hass)
    portal = ScriptedPortal([{"kind": "login"}] * 4)
    client = make_client(portal)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    unsub = coord.async_add_listener(lambda: None)
    try:
        await coord.async_refresh()
        await hass.async_block_till_done()
        assert coord.auth_required is True
        assert len(hass.config_entries.flow.async_progress_by_handler(DOMAIN)) == 1
        assert portal.home_gets() == 0
        assert entry.data[CONF_RENEWAL_ADMISSION] == {"sequences": -1}
    finally:
        unsub()
        coord.stop_keepalive()
        for flow in hass.config_entries.flow.async_progress_by_handler(DOMAIN):
            hass.config_entries.flow.async_abort(flow["flow_id"])

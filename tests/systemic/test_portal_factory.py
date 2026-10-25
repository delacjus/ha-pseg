"""Systemic integration tests for ScriptedPortal and ClientFactory.

Verifies:
- requests.Session follows 302 and 307/308 redirects with full cookie propagation.
- 307 credential re-POST is tracked as a separate hop with body digest preserved.
- Set-Cookie in responses reaches the next real Cookie header.
- setup -> unload -> setup lifecycle creates distinct client generations.
- Chart and ChartData are observed and logged separately.
- Negative proofs: unscripted routes fail closed, real transport is blocked with
  zero outbound requests, post-retire sends are recorded as I1 evidence, and
  plaintext body data is absent from dispatch records.
- Frozen records are immutable (nested mappings cannot be mutated).
- Causal chains: unfollowed redirects do not mislabel subsequent requests.
- Factory fidelity: client session uses real AllowlistedSession and respects production fences.
- Default portal/okta URLs match production constants.
"""

from __future__ import annotations

import hashlib
import threading
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
from requests.cookies import RequestsCookieJar, create_cookie
from requests.structures import CaseInsensitiveDict

from custom_components.pseg.const import (
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
    OKTA_HOST,
    PORTAL_BASE_URL,
)
from custom_components.pseg.pseg_client import (
    AllowlistedSession,
    PsegSecurityError,
    PsegTransientError,
)
from tests.conftest import BlockedOfflineTransportError
from tests.support.factory import ClientFactory, ClientRegistry
from tests.support.portal import (
    Dispatch,
    Gate,
    PortalViewAdapter,
    Reply,
    ScriptedPortal,
    UnscriptedRouteError,
)


def test_real_session_follows_302_redirect() -> None:
    """Real Session follows 302 redirect and logs each hop separately."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_test")

    login_reply = Reply.redirect(
        location=f"{PORTAL_BASE_URL}/Dashboard",
        status_code=302,
        headers={"Location": f"{PORTAL_BASE_URL}/Dashboard"},
        reply_id="SYNTH_LOGIN_REDIR",
    )
    dashboard_reply = Reply.ok(
        body="<html>Dashboard</html>",
        reply_id="SYNTH_DASHBOARD_OK",
    )

    portal.script(("GET", f"{PORTAL_BASE_URL}/Home/Login"), login_reply)
    portal.script(("GET", f"{PORTAL_BASE_URL}/Dashboard"), dashboard_reply)

    resp = session.get(f"{PORTAL_BASE_URL}/Home/Login", allow_redirects=True)

    assert resp.status_code == 200
    assert resp.url == f"{PORTAL_BASE_URL}/Dashboard"
    assert resp.text == "<html>Dashboard</html>"

    dispatches = portal.dispatches
    assert len(dispatches) == 2

    # Hop 1: Initial GET
    assert dispatches[0].url == f"{PORTAL_BASE_URL}/Home/Login"
    assert dispatches[0].method == "GET"
    assert dispatches[0].status_code == 302
    assert dispatches[0].is_redirect_hop is False
    assert dispatches[0].reply_id == "SYNTH_LOGIN_REDIR"

    # Hop 2: Redirected GET
    assert dispatches[1].url == f"{PORTAL_BASE_URL}/Dashboard"
    assert dispatches[1].method == "GET"
    assert dispatches[1].status_code == 200
    assert dispatches[1].is_redirect_hop is True
    assert dispatches[1].reply_id == "SYNTH_DASHBOARD_OK"


def test_real_session_follows_307_credential_repost() -> None:
    """307 temporary redirect preserves POST method and body as a separate hop."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_307")

    target_url = f"{PORTAL_BASE_URL}/Home/Login_v2"
    repost_reply = Reply.redirect(
        location=target_url,
        status_code=307,
        headers={"Location": target_url},
        reply_id="SYNTH_307_REDIR",
    )
    ok_reply = Reply.json({"status": "ok"}, reply_id="SYNTH_LOGIN_SUCCESS")

    portal.script(("POST", f"{PORTAL_BASE_URL}/Home/Login"), repost_reply)
    portal.script(("POST", target_url), ok_reply)

    creds = {"user": "SYNTH_USER@example.com", "pass": "SYNTH_PASSWORD_123"}
    resp = session.post(f"{PORTAL_BASE_URL}/Home/Login", data=creds, allow_redirects=True)

    assert resp.status_code == 200
    assert resp.url == target_url

    dispatches = portal.dispatches
    assert len(dispatches) == 2

    # Both hops must be POST
    assert dispatches[0].method == "POST"
    assert dispatches[0].url == f"{PORTAL_BASE_URL}/Home/Login"
    assert dispatches[0].is_redirect_hop is False
    assert dispatches[0].status_code == 307

    assert dispatches[1].method == "POST"
    assert dispatches[1].url == target_url
    assert dispatches[1].is_redirect_hop is True
    assert dispatches[1].status_code == 200

    # Body digest must match on both hops
    assert dispatches[0].body_digest is not None
    assert dispatches[0].body_digest == dispatches[1].body_digest

    # Verify body plaintext is NEVER stored in Dispatch
    assert not hasattr(dispatches[0], "body")
    assert not hasattr(dispatches[1], "body")


def test_set_cookie_reaches_next_real_cookie_header() -> None:
    """Set-Cookie in response reaches real Cookie header on subsequent requests."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_cookie")

    reply1 = Reply.ok(
        body="Session established",
        cookies={"SYNTH_SID": "SYNTH_COOKIE_VAL_ABC123"},
        reply_id="SYNTH_COOKIE_REPLY",
    )
    reply2 = Reply.ok(
        body="Dashboard ok",
        reply_id="SYNTH_DASHBOARD_COOKIE_REPLY",
    )

    portal.script(("GET", f"{PORTAL_BASE_URL}/"), reply1)
    portal.script(("GET", f"{PORTAL_BASE_URL}/Dashboard"), reply2)

    resp1 = session.get(f"{PORTAL_BASE_URL}/")
    assert resp1.status_code == 200
    assert session.cookies.get("SYNTH_SID") == "SYNTH_COOKIE_VAL_ABC123"

    resp2 = session.get(f"{PORTAL_BASE_URL}/Dashboard")
    assert resp2.status_code == 200

    dispatches = portal.dispatches
    assert len(dispatches) == 2
    # Second dispatch received the real cookie header
    assert dispatches[1].cookies.get("SYNTH_SID") == "SYNTH_COOKIE_VAL_ABC123"


def test_chart_and_chartdata_logged_separately() -> None:
    """Chart POST and ChartData GET are observed and logged as distinct dispatches."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_chart")

    chart_url = f"{PORTAL_BASE_URL}/Dashboard/Chart"
    chart_data_url = f"{PORTAL_BASE_URL}/Dashboard/ChartData"

    portal.script(("POST", chart_url), Reply.ok(body="", reply_id="SYNTH_CHART_OK"))
    chart_json = {"Data": {"series": [{"name": "Meter #1", "data": []}]}}
    portal.script(("GET", chart_data_url), Reply.json(chart_json, reply_id="SYNTH_CHART_DATA"))

    session.post(chart_url, data={"window": 14})
    session.get(chart_data_url)

    dispatches = portal.dispatches
    assert len(dispatches) == 2

    assert dispatches[0].url == chart_url
    assert dispatches[0].method == "POST"
    assert dispatches[0].reply_id == "SYNTH_CHART_OK"

    assert dispatches[1].url == chart_data_url
    assert dispatches[1].method == "GET"
    assert dispatches[1].reply_id == "SYNTH_CHART_DATA"


async def test_setup_unload_setup_clients_have_distinct_generations(
    hass: HomeAssistant,
) -> None:
    """setup -> unload -> setup creates clients with distinct generation IDs."""
    portal = ScriptedPortal()
    registry = ClientRegistry()
    factory = ClientFactory(portal, registry=registry)

    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345678",
        data={
            CONF_OKTA_COOKIES: "idx=SYNTH_TEST_TOKEN",
            CONF_PORTAL_COOKIES: "MM_SID=SYNTH_TEST_PORTAL",
        },
    )
    entry.add_to_hass(hass)

    with factory:
        with (
            patch(
                "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.async_config_entry_first_refresh",
                new_callable=AsyncMock,
            ),
            patch(
                "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.start_keepalive"
            ),
            patch(
                "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.stop_keepalive"
            ),
        ):
            # First setup
            assert await hass.config_entries.async_setup(entry.entry_id) is True
            await hass.async_block_till_done()

            assert len(registry.generations) == 1
            gen1 = registry.generations[0]
            assert gen1 == "gen_001"
            client1 = registry.get(gen1)
            assert client1 is not None
            assert getattr(client1, "generation_id", None) == "gen_001"

            # Unload
            assert await hass.config_entries.async_unload(entry.entry_id) is True
            await hass.async_block_till_done()

            # Second setup
            assert await hass.config_entries.async_setup(entry.entry_id) is True
            await hass.async_block_till_done()

            assert len(registry.generations) == 2
            gen2 = registry.generations[1]
            assert gen2 == "gen_002"
            client2 = registry.get(gen2)
            assert client2 is not None
            assert getattr(client2, "generation_id", None) == "gen_002"

            assert gen1 != gen2
            assert client1 is not client2

            # Final cleanup
            await hass.config_entries.async_unload(entry.entry_id)
            await hass.async_block_till_done()


def test_unscripted_route_fails_closed_locally() -> None:
    """Negative proof: unscripted route raises UnscriptedRouteError locally with zero outbound."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_unscripted")

    with pytest.raises(UnscriptedRouteError) as exc_info:
        session.get(f"{PORTAL_BASE_URL}/Unscripted/Unknown/Route")

    assert "Unscripted request fails closed" in str(exc_info.value)
    # Attempt is recorded before reply matching fails closed
    assert len(portal.dispatches) == 1
    assert portal.dispatches[0].url == f"{PORTAL_BASE_URL}/Unscripted/Unknown/Route"
    assert portal.dispatches[0].outcome == "unscripted"
    assert portal.dispatches[0].reply_id is None


def test_real_httpadapter_blocked_by_offline_guards() -> None:
    """Negative proof: real HTTP transport without custom adapter is blocked by P1 guards."""
    session = requests.Session()
    # Unscripted session uses default requests.adapters.HTTPAdapter
    with pytest.raises(BlockedOfflineTransportError) as exc_info:
        session.get(f"{PORTAL_BASE_URL}/Dashboard")

    assert "Real HTTP transport blocked" in str(exc_info.value)


def test_unauthorized_host_blocked_by_security_error() -> None:
    """Negative proof: request to unauthorized host is blocked by AllowlistedSession."""
    from custom_components.pseg.pseg_client import PsegClient

    client = PsegClient(email="SYNTH_USER", password="SYNTH_PASS")
    portal = ScriptedPortal()
    portal.mount_on(client.session, generation_id="gen_sec")

    with pytest.raises(PsegSecurityError) as exc_info:
        client.session.get("https://malicious.example.com/steal")

    assert "unauthorized host blocked" in str(exc_info.value)


def test_manually_retire_then_send_recorded_as_i1_evidence() -> None:
    """Negative proof: post-retirement sends are answered and recorded as I1 evidence."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_retired")

    dash_url = f"{PORTAL_BASE_URL}/Dashboard"
    portal.script(("GET", dash_url), Reply.ok(body="dashboard content", reply_id="SYNTH_DASH_RETIRED"))

    # Manually retire generation before sending
    portal.retire("gen_retired")
    assert portal.is_retired("gen_retired") is True

    # Send after retire: adapter must NOT suppress or block the send
    resp = session.get(dash_url)
    assert resp.status_code == 200

    dispatches = portal.dispatches
    assert len(dispatches) == 1
    assert dispatches[0].is_after_retire is True
    assert dispatches[0].generation_id == "gen_retired"

    # Recorded I1 evidence must capture this dispatch
    evidence = portal.recorded_i1_evidence
    assert len(evidence) == 1
    assert evidence[0] == dispatches[0]


def test_redirect_recording_integrity_self_test() -> None:
    """Negative proof: self-test verifies that redirect hop flag distinguishes hops."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_redir_check")

    target = f"{PORTAL_BASE_URL}/Landing"
    portal.script(("GET", f"{PORTAL_BASE_URL}/Start"), Reply.redirect(target))
    portal.script(("GET", target), Reply.ok(body="Landed"))

    session.get(f"{PORTAL_BASE_URL}/Start")

    dispatches = portal.dispatches
    assert len(dispatches) == 2
    # If redirect recording were removed or flawed, this assertion fails
    assert dispatches[0].is_redirect_hop is False
    assert dispatches[1].is_redirect_hop is True


def test_privacy_body_plaintext_and_real_environment_data_absent() -> None:
    """Negative proof: dispatch records store body digests only, never plaintext credentials."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_privacy")

    login_url = f"{PORTAL_BASE_URL}/Home/Login"
    portal.script(("POST", login_url), Reply.ok(body="OK"))

    secret_payload = "username=test_synthetic&password=SYNTH_SECRET_PASSWORD_987"
    session.post(login_url, data=secret_payload)

    dispatches = portal.dispatches
    assert len(dispatches) == 1
    d = dispatches[0]

    # Verify no body attribute exists
    assert not hasattr(d, "body")

    # Verify digest matches SHA-256 of payload
    expected_digest = hashlib.sha256(secret_payload.encode("utf-8")).hexdigest()
    assert d.body_digest == expected_digest

    # Verify plaintext is absent from str/repr of Dispatch
    assert "SYNTH_SECRET_PASSWORD_987" not in str(d)
    assert "SYNTH_SECRET_PASSWORD_987" not in repr(d)


def test_gate_bounded_wait_and_hold_proceed() -> None:
    """Gate holds arriving worker until proceed() is called, within bounded wait."""
    portal = ScriptedPortal()
    gate = portal.gate("before_send:/Dashboard", timeout=5.0)
    gate.hold()

    session = requests.Session()
    portal.mount_on(session, generation_id="gen_gate")
    portal.script(("GET", f"{PORTAL_BASE_URL}/Dashboard"), Reply.ok("gate ok"))

    worker_result: dict[str, Any] = {}

    def _worker():
        try:
            resp = session.get(f"{PORTAL_BASE_URL}/Dashboard")
            worker_result["status"] = resp.status_code
        except Exception as e:
            worker_result["error"] = e

    thread = threading.Thread(target=_worker)
    thread.start()

    try:
        # Wait for worker to arrive at gate (bounded 5s)
        gate.wait_arrived(timeout=5.0)
        assert gate.is_arrived is True
        assert "status" not in worker_result

        # Proceed releases the worker
        gate.proceed()
        thread.join(timeout=5.0)
        assert not thread.is_alive()
        assert worker_result.get("status") == 200
    finally:
        portal.drain()
        if thread.is_alive():
            thread.join(timeout=1.0)


def test_gate_timeout_raises_informative_error() -> None:
    """Gate wait_arrived raises TimeoutError with clear name and duration upon expiry."""
    gate = Gate("bounded_test_gate", default_timeout=0.1)
    with pytest.raises(TimeoutError) as exc_info:
        gate.wait_arrived(timeout=0.05)

    err_msg = str(exc_info.value)
    assert "bounded_test_gate" in err_msg
    assert "timed out after 0.05s" in err_msg


def test_gate_drain_releases_waiting_workers() -> None:
    """portal.drain() releases held gates during teardown without hanging."""
    portal = ScriptedPortal()
    gate = portal.gate("before_send:/DrainRoute", timeout=5.0)
    gate.hold()

    session = requests.Session()
    portal.mount_on(session, generation_id="gen_drain")
    portal.script(("GET", f"{PORTAL_BASE_URL}/DrainRoute"), Reply.ok("drain ok"))

    thread = threading.Thread(target=lambda: session.get(f"{PORTAL_BASE_URL}/DrainRoute"))
    thread.start()

    try:
        gate.wait_arrived(timeout=5.0)
        assert thread.is_alive()
        # Drain releases gate hold immediately
        portal.drain()
        thread.join(timeout=5.0)
        assert not thread.is_alive()
    finally:
        portal.drain()
        if thread.is_alive():
            thread.join(timeout=1.0)


def test_attempt_visible_before_canned_response() -> None:
    """Oracle observes attempted send before canned response reply matching."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_attempt")
    portal.script(f"{PORTAL_BASE_URL}/Dashboard", Reply.ok("dashboard response", reply_id="REP_DASH"))
    gate = portal.gate("before_send:/Dashboard", timeout=5.0)
    gate.hold()

    errors: list[BaseException] = []

    def work():
        try:
            session.get(f"{PORTAL_BASE_URL}/Dashboard")
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=work)
    worker.start()

    try:
        gate.wait_arrived(timeout=5.0)
        # Attempt is recorded and observable while held
        assert len(portal.dispatches) == 1
        d = portal.dispatches[0]
        assert d.url == f"{PORTAL_BASE_URL}/Dashboard"
        assert d.outcome == "pending"
        assert d.reply_id is None
        assert d.status_code is None
    finally:
        portal.drain()
        worker.join(timeout=5.0)
        assert not worker.is_alive()

    assert errors == []
    # After proceeding, dispatch outcome is updated
    assert len(portal.dispatches) == 1
    assert portal.dispatches[0].outcome == "REP_DASH"
    assert portal.dispatches[0].reply_id == "REP_DASH"
    assert portal.dispatches[0].status_code == 200


def test_unknown_after_retire_still_observable() -> None:
    """Unscripted request on retired generation leaves Dispatch and I1 evidence before failing closed."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_retired_unscripted")
    portal.retire("gen_retired_unscripted")

    with pytest.raises(UnscriptedRouteError):
        session.get(f"{PORTAL_BASE_URL}/NOT_SCRIPTED")

    assert len(portal.dispatches) == 1
    assert len(portal.recorded_i1_evidence) == 1
    d = portal.dispatches[0]
    assert d.is_after_retire is True
    assert d.outcome == "unscripted"
    assert d.reply_id is None
    assert portal.recorded_i1_evidence[0] == d


def test_reply_payloads_are_frozen_after_declaration() -> None:
    """Reply nested mappings are frozen; in-place mutations raise TypeError."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_frozen_rep")

    declared_cookies = {"SYNTH_SID": "DECLARED"}
    reply = Reply.ok(
        cookies=declared_cookies,
        headers={"X-Test": "Value"},
        metadata={"key": "meta"},
    )
    portal.script(f"{PORTAL_BASE_URL}/Dashboard", reply)

    assert isinstance(reply.cookies, MappingProxyType)
    assert isinstance(reply.headers, MappingProxyType)
    assert isinstance(reply.metadata, MappingProxyType)

    # Attempting in-place mutation on MappingProxyType raises TypeError
    with pytest.raises(TypeError):
        reply.cookies["SYNTH_SID"] = "MUTATED"

    with pytest.raises(TypeError):
        reply.headers["X-Test"] = "MUTATED"

    with pytest.raises(TypeError):
        reply.metadata["key"] = "MUTATED"

    # Mutating original dictionary passed into constructor does not affect Reply
    declared_cookies["SYNTH_SID"] = "EXTERNAL_MUTATION"
    assert reply.cookies["SYNTH_SID"] == "DECLARED"

    session.get(f"{PORTAL_BASE_URL}/Dashboard")
    assert session.cookies["SYNTH_SID"] == "DECLARED"


def test_dispatch_observation_is_immutable() -> None:
    """Dispatch observation records are frozen; in-place mutations raise TypeError."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_frozen_disp")
    portal.script(f"{PORTAL_BASE_URL}/Dashboard", Reply.ok())

    session.get(f"{PORTAL_BASE_URL}/Dashboard", cookies={"SYNTH_SID": "SENT"})
    dispatch = portal.dispatches[0]

    assert isinstance(dispatch.cookies, MappingProxyType)
    assert isinstance(dispatch.headers, MappingProxyType)
    assert isinstance(dispatch.metadata, MappingProxyType)

    with pytest.raises(TypeError):
        dispatch.cookies["SYNTH_SID"] = "FORGED"

    with pytest.raises(TypeError):
        dispatch.headers["User-Agent"] = "FORGED"

    with pytest.raises(TypeError):
        dispatch.metadata["key"] = "FORGED"

    assert portal.dispatches[0].cookies["SYNTH_SID"] == "SENT"


def test_factory_uses_real_session_and_foreign_host_owner_fences() -> None:
    """Factory client uses real AllowlistedSession, adapter identity, and production fences."""
    from importlib import import_module

    import custom_components.pseg as package
    import custom_components.pseg.config_flow as flow
    import custom_components.pseg.pseg_client as module

    extra = import_module("custom_components.pseg.__init__")
    originals = [(mod, mod.PsegClient) for mod in [package, flow, module, extra]]

    portal = ScriptedPortal()
    with ClientFactory(portal):
        client = package.PsegClient()
        assert isinstance(client.session, AllowlistedSession)

        adapter = client.session.get_adapter(PORTAL_BASE_URL)
        assert isinstance(adapter, PortalViewAdapter)
        assert adapter.portal is portal
        assert adapter.generation_id == client.generation_id

        portal.script(("GET", f"{PORTAL_BASE_URL}/Dashboard"), Reply.ok("factory mounted"))
        resp = client.session.get(f"{PORTAL_BASE_URL}/Dashboard")
        assert resp.status_code == 200
        assert resp.text == "factory mounted"
        assert len(portal.dispatches) == 1
        assert portal.dispatches[0].generation_id == client.generation_id

        # Foreign host check raises PsegSecurityError before reaching portal
        portal.script(("GET", "/steal"), Reply.ok("would hide allowlist bypass"))
        with pytest.raises(PsegSecurityError, match="unauthorized host"):
            client.session.get("https://foreign.example.test/steal")
        assert len(portal.dispatches) == 1

        # Inactive owner check raises PsegTransientError before reaching portal
        client._renewal_runtime = SimpleNamespace(is_active=lambda token: False)
        client._renewal_token = 1
        with pytest.raises(PsegTransientError, match="retired"):
            client.session.get(f"{PORTAL_BASE_URL}/Dashboard")
        assert len(portal.dispatches) == 1

    for mod, original in originals:
        assert mod.PsegClient is original


def test_unfollowed_redirect_is_not_later_request_chain() -> None:
    """Unfollowed 302 does not cause subsequent independent request to be marked as redirect hop."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_causal")
    portal.script(f"{PORTAL_BASE_URL}/Start", Reply.redirect(f"{PORTAL_BASE_URL}/Landing"))
    portal.script(f"{PORTAL_BASE_URL}/Landing", Reply.ok("landed"))

    session.get(f"{PORTAL_BASE_URL}/Start", allow_redirects=False)
    session.get(f"{PORTAL_BASE_URL}/Landing")

    dispatches = portal.dispatches
    assert len(dispatches) == 2
    assert dispatches[0].url == f"{PORTAL_BASE_URL}/Start"
    assert dispatches[0].is_redirect_hop is False
    assert dispatches[1].url == f"{PORTAL_BASE_URL}/Landing"
    assert dispatches[1].is_redirect_hop is False


def test_portal_default_targets_real_client() -> None:
    """ScriptedPortal portal default URL matches production PORTAL_BASE_URL."""
    portal = ScriptedPortal()
    assert portal.portal_base_url == PORTAL_BASE_URL


def test_okta_default_targets_real_client() -> None:
    """ScriptedPortal okta default URL matches production OKTA_HOST."""
    portal = ScriptedPortal()
    assert portal.okta_base_url == f"https://{OKTA_HOST}"


def test_default_portal_url_accepted_by_client_session() -> None:
    """Client session accepts requests to default portal_base_url without PsegSecurityError."""
    portal = ScriptedPortal()
    with ClientFactory(portal) as factory:
        client = factory.create_client()
        portal.script(f"{portal.portal_base_url}/Dashboard", Reply.ok("ok"))
        resp = client.session.get(f"{portal.portal_base_url}/Dashboard")
        assert resp.status_code == 200
        assert resp.text == "ok"



@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("consume_hook", [False, True])
def test_redirect_matrix(status: int, consume_hook: bool) -> None:
    """Followed redirects across 301/302/303/307/308, consuming hooks, and subsequent independent requests."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_redir_matrix")

    portal.script(
        ("POST", f"{PORTAL_BASE_URL}/Start"),
        Reply.redirect(
            f"{PORTAL_BASE_URL}/Landing",
            status_code=status,
            headers={"Set-Cookie": "SID=declared; Path=/"},
        ),
    )
    method = "POST" if status in (307, 308) else "GET"
    portal.script((method, f"{PORTAL_BASE_URL}/Landing"), Reply.ok("landed"))
    portal.script(("GET", f"{PORTAL_BASE_URL}/Landing"), Reply.ok("independent"))

    seen = []

    def hook(resp: Any, *args: Any, **kwargs: Any) -> None:
        seen.append(resp.content)

    if consume_hook:
        session.hooks["response"] = [hook]

    response = session.post(f"{PORTAL_BASE_URL}/Start", data="SYNTHETIC")
    assert response.text == "landed"
    assert len(response.history) == 1

    # Subsequent independent request to the same target is NOT a hop
    session.get(f"{PORTAL_BASE_URL}/Landing")

    ds = portal.dispatches
    assert [d.is_redirect_hop for d in ds] == [False, True, False]
    assert ds[1].cookies["SID"] == "declared"
    assert ds[1].body_digest == (ds[0].body_digest if method == "POST" else None)
    if consume_hook:
        assert len(seen) == 3


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_hook_independent_same_target(status: int) -> None:
    """Independent request from a response hook (same target) is NOT a redirect hop."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_hook_indep")

    portal.script(
        f"{PORTAL_BASE_URL}/Start",
        Reply.redirect(f"{PORTAL_BASE_URL}/Mid", status_code=status),
    )
    portal.script(
        f"{PORTAL_BASE_URL}/Mid",
        Reply.redirect(f"{PORTAL_BASE_URL}/Landing", status_code=status),
    )
    portal.script(
        f"{PORTAL_BASE_URL}/Landing",
        [Reply.ok("independent"), Reply.ok("landed")],
    )

    def hook(resp: Any, *args: Any, **kwargs: Any) -> Any:
        _ = resp.content
        if resp.url.endswith("/Mid"):
            session.get(f"{PORTAL_BASE_URL}/Landing", hooks={"response": []})
        return resp

    session.hooks["response"] = [hook]
    assert session.get(f"{PORTAL_BASE_URL}/Start").text == "landed"

    ds = portal.dispatches
    assert [d.url.rsplit("/", 1)[-1] for d in ds] == ["Start", "Mid", "Landing", "Landing"]
    assert [d.is_redirect_hop for d in ds] == [False, True, False, True]


def test_reentrant_hook_redirect_causality() -> None:
    """Reentrant hooks initiating further requests preserve exact redirect causality."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_reentrant")

    portal.script(f"{PORTAL_BASE_URL}/Start", Reply.redirect(f"{PORTAL_BASE_URL}/Mid"))
    portal.script(f"{PORTAL_BASE_URL}/Mid", Reply.redirect(f"{PORTAL_BASE_URL}/Landing"))
    portal.script(f"{PORTAL_BASE_URL}/HookStart", Reply.redirect(f"{PORTAL_BASE_URL}/HookMid"))
    portal.script(f"{PORTAL_BASE_URL}/HookMid", Reply.ok("hook_mid_done"))
    portal.script(f"{PORTAL_BASE_URL}/Landing", Reply.ok("landing_done"))

    def outer_hook(resp: Any, *args: Any, **kwargs: Any) -> Any:
        if resp.url.endswith("/Mid"):
            session.get(f"{PORTAL_BASE_URL}/HookStart", hooks={"response": []})
        return resp

    session.hooks["response"] = [outer_hook]
    resp = session.get(f"{PORTAL_BASE_URL}/Start")
    assert resp.text == "landing_done"

    ds = portal.dispatches
    urls = [d.url.rsplit("/", 1)[-1] for d in ds]
    assert urls == ["Start", "Mid", "HookStart", "HookMid", "Landing"]
    assert [d.is_redirect_hop for d in ds] == [False, True, False, True, True]


@pytest.mark.parametrize("attr", ["headers", "cookies", "metadata"])
@pytest.mark.parametrize("record", ["reply", "dispatch"])
def test_top_mapping_guards(attr: str, record: str) -> None:
    """Top level mappings and mapping views reject in-place mutation with TypeError."""
    data = {"a": "b"}
    obj = (
        Reply.ok(**{attr: data})
        if record == "reply"
        else Dispatch("g", 1, "GET", PORTAL_BASE_URL, **{attr: data})
    )
    data["a"] = "external"
    m = getattr(obj, attr)
    assert m["a"] == "b"
    with pytest.raises(TypeError):
        m["a"] = "bad"
    with pytest.raises(TypeError):
        m.items().mapping["a"] = "bad"
    with pytest.raises(TypeError):
        m.values().mapping["a"] = "bad"
    with pytest.raises(TypeError):
        m.keys().mapping["a"] = "bad"


@pytest.mark.parametrize("path", ["caller", "values_view", "items_view", "direct"])
@pytest.mark.parametrize("record", ["reply", "dispatch"])
def test_nested_metadata_frozen(path: str, record: str) -> None:
    """Nested metadata mappings and lists are recursively frozen and isolated."""
    nested = {"layers": [{"value": "declared"}]}
    obj = (
        Reply.ok(metadata=nested)
        if record == "reply"
        else Dispatch("g", 1, "GET", PORTAL_BASE_URL, metadata=nested)
    )
    routes = {
        "caller": nested["layers"],
        "values_view": next(iter(obj.metadata.values())),
        "items_view": next(iter(obj.metadata.items()))[1],
        "direct": obj.metadata["layers"],
    }
    try:
        routes[path][0]["value"] = "mutated"
    except (TypeError, AttributeError):
        pass
    assert obj.metadata["layers"][0]["value"] == "declared"


@pytest.mark.parametrize("path", ["caller", "reply", "response"])
def test_multivalue_header_frozen(path: str) -> None:
    """Multi-value headers are frozen into immutable tuples preserving values and order."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_multivalue")

    headers = {"Set-Cookie": ["SID=declared; Path=/", "OTHER=value; Path=/"]}
    reply = Reply.ok(headers=headers)
    portal.script("/A", reply)

    if path == "caller":
        target = headers["Set-Cookie"]
    elif path == "reply":
        target = reply.headers["Set-Cookie"]
    else:
        target = session.get(f"{PORTAL_BASE_URL}/A").headers["sEt-CoOkIe"]

    try:
        target[0] = "SID=mutated; Path=/"
    except (TypeError, AttributeError):
        pass

    assert reply.headers["Set-Cookie"][0] == "SID=declared; Path=/"
    session.get(f"{PORTAL_BASE_URL}/A")
    assert session.cookies["SID"] == "declared"


def test_case_insensitive_input_private_copy() -> None:
    """Headers input as CaseInsensitiveDict is privately copied and unaffected by caller mutation."""
    headers = CaseInsensitiveDict({"X-Test": "declared"})
    reply = Reply.ok(headers=headers)
    headers["x-test"] = "changed"
    assert reply.headers["X-Test"] == "declared"


def test_cookiejar_private_copy() -> None:
    """Cookies input as RequestsCookieJar is privately copied and unaffected by caller mutation."""
    jar = RequestsCookieJar()
    jar.set("SID", "declared")
    reply = Reply.ok(cookies=jar)
    jar.set("SID", "changed")
    assert reply.cookies["SID"] == "declared"


def test_nested_cookie_object_frozen() -> None:
    """Cookie object in metadata is frozen into immutable FrozenCookie primitive."""
    cookie = create_cookie("SID", "declared")
    reply = Reply.ok(metadata={"cookie": cookie})
    try:
        cookie.value = "changed"
    except (TypeError, AttributeError):
        pass
    assert reply.metadata["cookie"].value == "declared"


@pytest.mark.parametrize("path", ["dict", "setattr"])
@pytest.mark.parametrize("getter", ["dispatches", "recorded_i1_evidence", "dispatches_for"])
def test_retained_dispatch_not_rewritable(path: str, getter: str) -> None:
    """Retained dispatch objects returned by getters are fresh copies isolated from mutation."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_disp_not_rewritable")

    portal.script("/A", Reply.ok())
    portal.retire("gen_disp_not_rewritable")
    session.get(f"{PORTAL_BASE_URL}/A", cookies={"SID": "sent"})

    d = (
        portal.dispatches_for("gen_disp_not_rewritable")
        if getter == "dispatches_for"
        else getattr(portal, getter)
    )[0]
    try:
        if path == "dict":
            d.__dict__["cookies"] = {"SID": "forged"}
        else:
            object.__setattr__(d, "cookies", {"SID": "forged"})
    except (TypeError, AttributeError):
        pass

    assert portal.dispatches[0].cookies["SID"] == "sent"
    assert portal.recorded_i1_evidence[0].cookies["SID"] == "sent"


@pytest.mark.parametrize("path", ["dict", "setattr"])
def test_reply_object_rewrite_cannot_change_script(path: str) -> None:
    """Reply objects stored in script registry are isolated from caller object mutation."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_reply_rewrite")

    reply = Reply.ok(cookies={"SID": "declared"})
    portal.script("/A", reply)
    try:
        if path == "dict":
            reply.__dict__["cookies"] = {"SID": "forged"}
        else:
            object.__setattr__(reply, "cookies", {"SID": "forged"})
    except (TypeError, AttributeError):
        pass

    session.get(f"{PORTAL_BASE_URL}/A")
    assert session.cookies["SID"] == "declared"


def test_response_cookie_and_header_edits_do_not_rewrite_records() -> None:
    """Editing response headers or cookies after receive does not mutate recorded evidence."""
    portal = ScriptedPortal()
    session = requests.Session()
    portal.mount_on(session, generation_id="gen_resp_edits")

    reply = Reply.ok(cookies={"SID": "declared"}, headers={"X-Test": "original"})
    portal.script("/A", reply)
    resp = session.get(f"{PORTAL_BASE_URL}/A", cookies={"SENT": "value"})

    list(resp.cookies)[0].value = "changed"
    resp.headers["x-test"] = "changed"
    resp.request.headers["Cookie"] = "SENT=forged"

    assert reply.cookies["SID"] == "declared"
    assert reply.headers["X-Test"] == "original"
    assert portal.dispatches[0].cookies["SENT"] == "value"
    assert portal.dispatches[0].headers["Cookie"] == "SENT=value"

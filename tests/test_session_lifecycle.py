"""Entry lifecycle tests: reloads, cookie persistence, entity ids (review r1 H2/H3/M7/L11/L12)."""

from __future__ import annotations

import asyncio
from collections.abc import Generator
import logging
import threading
from unittest.mock import patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr, entity_registry as er
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests_mock

import custom_components.pseg as pkg
from custom_components.pseg.const import (
    AUTH_REASON_REMEMBER_ME_REJECTED,
    CONF_METER_ID,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    CONF_RENEWAL_ADMISSION,
    DOMAIN,
    OKTA_HOST,
    PORTAL_BASE_URL,
    PORTAL_HOST,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient, PsegOktaSessionExpired
from tests.support.synchronization import (
    ObservedLock,
    join_thread,
    wait_event_async,
    wait_task,
)

METER = "12345678"
DATA = {
    "meter": f"Electric Meter {METER}",
    "last_updated": "x",
    "latest_date": "2026-10-20",
    "latest_kwh": 5.0,
    "latest_cost": 1.0,
    "previous_date": "2026-10-19",
    "previous_kwh": 4.0,
    "previous_cost": 1.0,
    "history_14d": [{"date": "2026-10-20", "kwh": 5.0, "cost": 1.0}],
    "temperature_range": "",
    "temperature_avg": 50.0,
    "total_records": 1,
}


def _successful_session(client: PsegClient) -> bool:
    """Model a session whose Okta cookies can renew a fresh portal client."""
    client.sso_renewals = 1
    return True


def _entry(hass: HomeAssistant, **data) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id=METER,
        title=f"PSE&G ({METER})",
        data={
            CONF_OKTA_COOKIES: "idx=a",
            CONF_PORTAL_COOKIES: "",
            CONF_METER_ID: METER,
            **data,
        },
    )
    entry.add_to_hass(hass)
    return entry


@pytest.fixture
def setup_calls() -> Generator[dict[str, int]]:
    """Count async_setup_entry calls (each reload is one more)."""
    calls = {"n": 0}
    orig = pkg.async_setup_entry

    async def counting(hass, entry):
        calls["n"] += 1
        return await orig(hass, entry)

    with patch.object(pkg, "async_setup_entry", counting):
        yield calls


@pytest.fixture
def portal() -> Generator[None]:
    """Stub portal calls and statistics import."""
    with (
        patch.object(PsegClient, "fetch_energy_data", return_value=dict(DATA)),
        patch.object(PsegClient, "ensure_session", _successful_session),
        patch.object(PsegClient, "keepalive", return_value=True),
        patch(
            "custom_components.pseg.coordinator.PsegDataUpdateCoordinator.async_record_statistics"
        ),
    ):
        yield


async def test_cookie_rotation_does_not_reload_entry(
    hass: HomeAssistant, setup_calls, portal
) -> None:
    """Persisting rotated cookies must update entry.data without reloading the entry."""
    entry = _entry(hass)
    rotation = {"n": 0}

    def export(self):
        rotation["n"] += 1
        return (
            [
                {
                    "name": "MM_SID",
                    "value": f"v{rotation['n']}",
                    "domain": PORTAL_HOST,
                    "path": "/",
                    "secure": True,
                }
            ],
            None,
        )

    with patch.object(PsegClient, "export_cookies_and_auth_reason", export):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        coord = hass.data[DOMAIN][entry.entry_id]
        await coord._async_keepalive(None)
        await hass.async_block_till_done()
        await coord._async_keepalive(None)
        await hass.async_block_till_done()

    assert setup_calls["n"] == 1
    assert entry.state is ConfigEntryState.LOADED
    assert entry.data["cookies"][0]["value"] == "v3"


async def test_options_change_reloads_once(hass: HomeAssistant, setup_calls, portal) -> None:
    """Changing the price option reloads the entry exactly once."""
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={CONF_PRICE_PER_KWH: 0.3}
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()

    assert setup_calls["n"] == 2
    assert hass.data[DOMAIN][entry.entry_id].client.price_per_kwh == 0.3


async def test_reauth_reloads_once_without_update_listener_warning(
    hass: HomeAssistant, setup_calls, portal, caplog
) -> None:
    """Reauth must reload once and not trip the 2026.12 update-listener deprecation."""
    caplog.set_level(logging.WARNING)
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={CONF_OKTA_COOKIES: "idx=fresh", CONF_PORTAL_COOKIES: ""},
    )
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()

    assert setup_calls["n"] == 2
    assert "update listener" not in caplog.text
    assert entry.data[CONF_OKTA_COOKIES] == "idx=fresh"


def _jar(client: PsegClient, name: str) -> list[str]:
    return [c.value for c in client.session.cookies if c.name == name]


def test_persisted_jar_wins_over_pasted_cookies() -> None:
    """Restart: the rotated persisted jar must not be overwritten by the stale paste."""
    client = PsegClient(
        okta_cookies="idx=PASTED_OLD",
        portal_cookies="MM_SID=PASTED_PORTAL",
        cookie_list=[
            {"name": "idx", "value": "ROTATED_NEW", "domain": OKTA_HOST, "path": "/"},
        ],
    )
    assert _jar(client, "idx") == ["ROTATED_NEW"]
    assert _jar(client, "MM_SID") == []


def test_pasted_cookies_seed_fresh_jar() -> None:
    """With nothing persisted yet, the pasted header strings seed the jar."""
    client = PsegClient(okta_cookies="idx=PASTED", portal_cookies="MM_SID=P", cookie_list=[])
    assert _jar(client, "idx") == ["PASTED"]
    assert _jar(client, "MM_SID") == ["P"]


async def test_set_cookie_rotation_persisted_and_restored(hass: HomeAssistant) -> None:
    """A server Set-Cookie rotation is kept in the jar, persisted, and survives restart."""
    entry = _entry(hass, **{CONF_PORTAL_COOKIES: "MM_SID=PASTED_OLD"})
    client = PsegClient(
        okta_cookies=entry.data[CONF_OKTA_COOKIES],
        portal_cookies=entry.data[CONF_PORTAL_COOKIES],
    )
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    # requests_mock builds responses without original_response, so requests never runs
    # extract_cookies_to_jar; this hook performs that merge exactly like a live response.
    client.session.hooks["response"].append(
        lambda resp, *a, **k: client.session.cookies.update(resp.cookies)
    )
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            text="<html>Dashboard</html>",
            # Host-only cookie (no Domain attribute), as the ASP.NET portal issues it.
            headers={"Set-Cookie": "MM_SID=ROTATED; Path=/; Secure; HttpOnly"},
        )
        _mock_sso_ok(m)
        assert client.keepalive() is True
    assert _jar(client, "MM_SID") == ["ROTATED"]

    await coord._async_persist_cookies()
    persisted = {c["name"]: c["value"] for c in entry.data["cookies"]}
    assert persisted["MM_SID"] == "ROTATED"

    restarted = PsegClient(
        okta_cookies=entry.data[CONF_OKTA_COOKIES],
        portal_cookies=entry.data[CONF_PORTAL_COOKIES],
        cookie_list=entry.data["cookies"],
    )
    assert _jar(restarted, "MM_SID") == ["ROTATED"]


async def test_failed_remember_renewal_jar_is_never_persisted(hass: HomeAssistant) -> None:
    """A jar a failed renewal left half-empty must not replace the entry's good jar."""
    remembered = [
        {"name": "MM_SID", "value": "OLD_SID", "domain": PORTAL_HOST, "path": "/", "secure": True},
        {
            "name": "MM_RememberMe",
            "value": "REMEMBER",
            "domain": PORTAL_HOST,
            "path": "/",
            "secure": True,
        },
    ]
    entry = _entry(hass, cookies=[dict(c) for c in remembered])
    client = PsegClient(cookie_list=[dict(c) for c in remembered])
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", status_code=302, headers={"Location": "/"})
        m.get(f"{PORTAL_BASE_URL}/", text="<html><body>Welcome</body></html>")
        with pytest.raises(PsegOktaSessionExpired):
            client._renew()

    # The failed transaction restores the confirmed jar in memory, but remains
    # unconfirmed and cannot overwrite entry cookies.
    exported = {c["name"] for c in client.export_cookies()}
    assert "MM_RememberMe" in exported
    assert "MM_SID" in exported
    assert client.cookies_confirmed is False

    await coord._async_persist_cookies()

    assert entry.data["cookies"] == remembered


async def test_overlapping_failed_renewal_cannot_persist_a_partial_jar(
    hass: HomeAssistant,
) -> None:
    """Jar and auth_reason are one snapshot: a racing renewal cannot half-write it.

    The export waits on the client lock while a renewal drops MM_SID and then
    records its rejection. Reading auth_reason before awaiting the export (the
    pre-fix order) queued this write anyway and replaced the good jar.
    """
    remembered = [
        {"name": "MM_SID", "value": "OLD_SID", "domain": PORTAL_HOST, "path": "/", "secure": True},
        {
            "name": "MM_RememberMe",
            "value": "REMEMBER",
            "domain": PORTAL_HOST,
            "path": "/",
            "secure": True,
        },
    ]
    entry = _entry(hass, cookies=[dict(c) for c in remembered])
    client = PsegClient(cookie_list=[dict(c) for c in remembered])
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    client._lock = ObservedLock(client._lock, "renewal/cookie export client lock")
    renewal_started = threading.Event()
    release_renewal = threading.Event()
    renewed: dict[str, object] = {}

    def bounce(_request, context):
        renewal_started.set()
        assert release_renewal.wait(5)
        context.status_code = 302
        context.headers["Location"] = "/"
        return ""

    def renew() -> None:
        with requests_mock.Mocker(session=client.session) as m:
            m.get(f"{PORTAL_BASE_URL}/Dashboard", text=bounce)
            m.get(f"{PORTAL_BASE_URL}/", text="<html><body>Welcome</body></html>")
            try:
                client.renew_remember_me()
            except PsegOktaSessionExpired as err:
                renewed["error"] = err

    thread = threading.Thread(target=renew)
    persist = None
    thread.start()
    try:
        assert renewal_started.wait(5)
        # The failed renewal already dropped MM_SID and still holds the client lock;
        # this snapshot must wait for it and then see its auth_reason.
        persist = asyncio.create_task(coord._async_persist_cookies())
        await wait_event_async(client._lock.contended, "cookie export waiting on renewal")
        release_renewal.set()
        await asyncio.wait_for(persist, 10)
    finally:
        release_renewal.set()
        join_thread(thread, "failed renewal")
        if persist is not None:
            await wait_task(persist, "cookie persistence cleanup")

    assert "error" in renewed
    assert client.auth_reason == AUTH_REASON_REMEMBER_ME_REJECTED
    exported = {c["name"] for c in client.export_cookies()}
    assert "MM_RememberMe" in exported
    assert "MM_SID" not in exported

    assert entry.data["cookies"] == remembered
    assert "MM_SID" in coord._persisted_session_cookies


async def test_partial_jar_is_not_persisted_even_when_the_reason_cleared(
    hass: HomeAssistant,
) -> None:
    """A jar missing the session cookie of the last good persist is never written."""
    remembered = [
        {"name": "MM_SID", "value": "OLD_SID", "domain": PORTAL_HOST, "path": "/", "secure": True},
        {
            "name": "MM_RememberMe",
            "value": "REMEMBER",
            "domain": PORTAL_HOST,
            "path": "/",
            "secure": True,
        },
    ]
    entry = _entry(hass, cookies=[dict(c) for c in remembered])
    client = PsegClient(cookie_list=[dict(c) for c in remembered])
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)

    # A parallel GET after the failed renewal can clear auth_reason while the jar
    # still lacks the session cookie that renewal removed.
    for cookie in [c for c in client.session.cookies if c.name == "MM_SID"]:
        client.session.cookies.clear(cookie.domain, cookie.path, cookie.name)
    assert client.auth_reason is None

    await coord._async_persist_cookies()

    assert entry.data["cookies"] == remembered


async def test_reauth_replaces_persisted_jar(hass: HomeAssistant, portal) -> None:
    """Reauth pastes fresh cookies; the old persisted jar must not survive the reload."""
    entry = _entry(
        hass,
        cookies=[
            {"name": "idx", "value": "OLD_ROTATED", "domain": OKTA_HOST, "path": "/"},
            {"name": "MM_SID", "value": "OLD_PORTAL", "domain": PORTAL_HOST, "path": "/"},
        ],
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert _jar(hass.data[DOMAIN][entry.entry_id].client, "idx") == ["OLD_ROTATED"]

    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={CONF_OKTA_COOKIES: "idx=FRESH", CONF_PORTAL_COOKIES: ""},
    )
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()

    client = hass.data[DOMAIN][entry.entry_id].client
    assert _jar(client, "idx") == ["FRESH"]
    assert _jar(client, "MM_SID") == []


async def test_entity_ids_match_card_and_readme(hass: HomeAssistant, portal) -> None:
    """The first entry's entity ids are the stable ones the card and README use."""
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    ids = sorted(
        e.entity_id
        for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
    )
    assert ids == [
        "button.pseg_refresh_data",
        "sensor.pseg_connection_status",
        "sensor.pseg_electricity_consumption",
        "sensor.pseg_electricity_cost",
        "sensor.pseg_latest_reading_date",
        "sensor.pseg_meter_id",
        "sensor.pseg_next_update",
        "sensor.pseg_outdoor_temperature",
    ]
    assert hass.states.get("sensor.pseg_connection_status").state == "connected"
    assert hass.states.get("sensor.pseg_electricity_consumption").state == "5.0"


async def test_second_account_gets_suffixed_entity_ids(hass: HomeAssistant, portal) -> None:
    """A second account added after the first is registered gets `_2` entity_ids."""
    first = _entry(hass)
    assert await hass.config_entries.async_setup(first.entry_id)
    await hass.async_block_till_done()

    second = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="87654321",
        title="PSE&G (87654321)",
        data={CONF_OKTA_COOKIES: "idx=b", CONF_PORTAL_COOKIES: "", CONF_METER_ID: "87654321"},
    )
    second.add_to_hass(hass)
    assert await hass.config_entries.async_setup(second.entry_id)
    await hass.async_block_till_done()

    registry = er.async_get(hass)
    second_ids = {e.entity_id for e in er.async_entries_for_config_entry(registry, second.entry_id)}
    assert "sensor.pseg_connection_status_2" in second_ids
    assert "sensor.pseg_electricity_consumption_2" in second_ids
    assert registry.async_get("sensor.pseg_connection_status").config_entry_id == first.entry_id


async def test_concurrent_multi_entry_domain_setup_preserves_distinct_ownership(
    hass: HomeAssistant, portal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent initial domain setup registers both accounts distinctly even if second finishes first."""
    first = _entry(hass)
    second = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="87654321",
        title="PSE&G (87654321)",
        data={CONF_OKTA_COOKIES: "idx=b", CONF_PORTAL_COOKIES: "", CONF_METER_ID: "87654321"},
    )
    second.add_to_hass(hass)

    second_fetch_done = threading.Event()
    first_entered = threading.Event()

    def ordered_fetch(self, days: int = 14):
        if "87654321" in (self._expected_meter_ids or set()):
            second_fetch_done.set()
            return dict(DATA, meter="Electric Meter 87654321")
        first_entered.set()
        assert second_fetch_done.wait(timeout=5.0)
        return dict(DATA)

    monkeypatch.setattr(PsegClient, "fetch_energy_data", ordered_fetch)

    assert await hass.config_entries.async_setup(first.entry_id)
    await hass.async_block_till_done()

    assert first_entered.is_set()
    assert second_fetch_done.is_set()
    assert first.state is ConfigEntryState.LOADED
    assert second.state is ConfigEntryState.LOADED

    registry = er.async_get(hass)
    dev_registry = dr.async_get(hass)
    first_entries = er.async_entries_for_config_entry(registry, first.entry_id)
    second_entries = er.async_entries_for_config_entry(registry, second.entry_id)
    assert len(first_entries) == 8
    assert len(second_entries) == 8
    assert len(first_entries) + len(second_entries) == 16

    first_unique_ids = {e.unique_id for e in first_entries}
    second_unique_ids = {e.unique_id for e in second_entries}
    assert all(uid.startswith(f"{first.entry_id}_") for uid in first_unique_ids)
    assert all(uid.startswith(f"{second.entry_id}_") for uid in second_unique_ids)
    assert first_unique_ids.isdisjoint(second_unique_ids)

    first_entity_ids = {e.entity_id for e in first_entries}
    second_entity_ids = {e.entity_id for e in second_entries}
    assert first_entity_ids.isdisjoint(second_entity_ids)

    base_ids = {
        "button.pseg_refresh_data",
        "sensor.pseg_connection_status",
        "sensor.pseg_electricity_consumption",
        "sensor.pseg_electricity_cost",
        "sensor.pseg_latest_reading_date",
        "sensor.pseg_meter_id",
        "sensor.pseg_next_update",
        "sensor.pseg_outdoor_temperature",
    }
    suffixed_ids = {f"{eid}_2" for eid in base_ids}
    # Whichever entry finishes first takes base_ids and the other takes suffixed_ids
    assert {frozenset(first_entity_ids), frozenset(second_entity_ids)} == {
        frozenset(base_ids),
        frozenset(suffixed_ids),
    }

    first_devices = dr.async_entries_for_config_entry(dev_registry, first.entry_id)
    second_devices = dr.async_entries_for_config_entry(dev_registry, second.entry_id)
    assert len(first_devices) == 1
    assert len(second_devices) == 1
    assert first_devices[0].id != second_devices[0].id
    assert {e.device_id for e in first_entries} == {first_devices[0].id}
    assert {e.device_id for e in second_entries} == {second_devices[0].id}


OLD_JAR = [{"name": "idx", "value": "OLD", "domain": OKTA_HOST, "path": "/", "secure": True}]
REAUTH_JAR = [
    {"name": "idx", "value": "NEW_FROM_REAUTH", "domain": OKTA_HOST, "path": "/", "secure": True}
]


async def _start_blocked_keepalive(hass: HomeAssistant, coord, gate: threading.Event):
    """Run the coordinator keepalive with the portal call parked on `gate`."""
    entered = threading.Event()

    def parked_keepalive(self):
        entered.set()
        gate.wait(10)
        raise PsegOktaSessionExpired("expired")

    patcher = patch.object(PsegClient, "keepalive", parked_keepalive)
    patcher.start()
    task = hass.async_create_task(coord._async_keepalive(None))
    await hass.async_add_executor_job(entered.wait, 5)
    return task, patcher


def _reauth_flows(hass: HomeAssistant) -> list:
    return [
        f
        for f in hass.config_entries.flow.async_progress()
        if f["context"].get("source") == "reauth"
    ]


async def test_inflight_keepalive_does_not_overwrite_reauth_jar(
    hass: HomeAssistant, portal
) -> None:
    """A keepalive started before reauth must not persist its stale jar or start reauth."""
    entry = _entry(hass, cookies=OLD_JAR)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    coord = hass.data[DOMAIN][entry.entry_id]

    gate = threading.Event()
    task, patcher = await _start_blocked_keepalive(hass, coord, gate)
    try:
        hass.config_entries.async_update_entry(entry, data={**entry.data, "cookies": REAUTH_JAR})
        gate.set()
        await asyncio.wait_for(task, 5)
    finally:
        patcher.stop()
    await hass.async_block_till_done()

    assert [c["value"] for c in entry.data["cookies"]] == ["NEW_FROM_REAUTH"]
    assert _reauth_flows(hass) == []


async def test_keepalive_finishing_after_unload_is_ignored(hass: HomeAssistant, portal) -> None:
    """An unloaded coordinator's late keepalive must not touch the entry or start reauth."""
    entry = _entry(hass, cookies=OLD_JAR)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    coord = hass.data[DOMAIN][entry.entry_id]
    coord.client.session.cookies.set("idx", "STALE_ROTATION", domain=OKTA_HOST, path="/")

    gate = threading.Event()
    task, patcher = await _start_blocked_keepalive(hass, coord, gate)
    try:
        assert await hass.config_entries.async_unload(entry.entry_id)
        gate.set()
        await asyncio.wait_for(task, 5)
    finally:
        patcher.stop()
    await hass.async_block_till_done()

    assert [c["value"] for c in entry.data["cookies"]] == ["OLD"]
    assert _reauth_flows(hass) == []

def _mock_sso_ok(m) -> None:
    """Okta session alive: SignIn returns the SAML auto-post form, ACS accepts it."""
    m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=_AUTOPOST_FORM)
    m.post(f"{PORTAL_BASE_URL}/Saml/okta-prod/Acs", status_code=200, text="ok")


_AUTOPOST_FORM = (
    f'<form method="POST" action="{PORTAL_BASE_URL}/Saml/okta-prod/Acs">'
    '<input type="hidden" name="SAMLResponse" value="assertion"/></form>'
)


REAUTH_METADATA = {
    "sequences": 2,
    "last_sequence_at": "2026-10-23T12:00:00+00:00",
    "terminal_reason": AUTH_REASON_REMEMBER_ME_REJECTED,
    "retry_eligible": False,
}


async def test_reauth_rearms_the_renewal_budget_and_keeps_the_global_clock(
    hass: HomeAssistant, portal
) -> None:
    """A completed human sign-in starts a fresh generation, not a fresh cooldown clock."""
    entry = _entry(hass, **{CONF_RENEWAL_ADMISSION: dict(REAUTH_METADATA)})
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={CONF_OKTA_COOKIES: "idx=fresh", CONF_PORTAL_COOKIES: ""},
    )
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()

    assert entry.data[CONF_RENEWAL_ADMISSION] == {
        "sequences": 0,
        "last_sequence_at": "2026-10-23T12:00:00+00:00",
        "terminal_reason": None,
        "retry_eligible": False,
    }


async def test_options_reload_keeps_the_renewal_budget(hass: HomeAssistant, portal) -> None:
    """An options reload must not reset the persisted renewal admission."""
    entry = _entry(hass, **{CONF_RENEWAL_ADMISSION: dict(REAUTH_METADATA)})
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={CONF_PRICE_PER_KWH: 0.31}
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()

    assert entry.data[CONF_RENEWAL_ADMISSION] == REAUTH_METADATA
    coord = hass.data[DOMAIN][entry.entry_id]
    assert coord._renewal_admission.terminal_reason == AUTH_REASON_REMEMBER_ME_REJECTED
    assert coord.client._renewal_admission is coord._renewal_admission
    assert METER in coord.client._expected_meter_ids

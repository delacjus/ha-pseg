"""R6 extra probes: backfill latest-checkpoint exit, renewal-proven jar vs daily leg,
and the entry-owner predicate during the coordinator's own cookie write."""

from __future__ import annotations

import copy

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.pseg as pkg
from custom_components.pseg.const import CONF_PORTAL_COOKIES, DOMAIN
from custom_components.pseg.pseg_client import PsegClient
from tests.independent.auth_r6.test_independent_auth_r6 import (
    DAILY_BAD,
    GOOD,
    METER,
    POISON,
    SEED,
    R6Portal,
    build,
    poisoned,
)

pytestmark = pytest.mark.independent


@pytest.fixture(autouse=True)
def _enabled(enable_custom_integrations):
    yield


@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "r6_aux"])
async def test_valid_backfill_chunk_rotation_survives_unload(hass, monkeypatch, cookie):
    """gamma: a chunk with valid target data rotates a cookie; unload right after."""
    portal = R6Portal()
    client = PsegClient(portal_cookies=SEED)
    client.session.mount("https://", portal)
    monkeypatch.setattr(pkg, "PsegClient", lambda **kwargs: client)
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id=METER, data={CONF_PORTAL_COOKIES: SEED})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    coord = hass.data[DOMAIN][entry.entry_id]

    async def no_stats(records, meter_id=None, **_kw):
        return None

    coord.async_record_statistics = no_stats
    portal.daily.extend([GOOD, ("__default__", [f"{cookie}={POISON}; Path=/"]), GOOD, GOOD])
    count = await coord.async_backfill_history("2026-01-01", "2026-10-20")
    assert count > 0
    assert poisoned(client.export_cookies(), cookie), "harness: rotation not live"
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert poisoned(entry.data.get("cookies"), cookie), (
        "validated backfill-chunk rotation was not persisted by the stop/unload exit"
    )


@pytest.mark.parametrize("cookie", ["MM_SID", "MM_RememberMe", "r6_aux"])
async def test_renewal_proven_jar_not_replaced_by_unvalidated_daily(hass, cookie):
    """epsilon after renewal: Dashboard+DAILY proof jar vs a later daily 200 with no target data."""
    portal = R6Portal()
    portal.dash.extend([
        {"kind": "login"},
        {"kind": "dash", "set_cookie": [
            "MM_SID=r6-proven-sid; Path=/", "MM_RememberMe=r6-proven-gen; Path=/",
            "r6_aux=r6-proven-aux; Path=/"]},
        {"kind": "dash"},
    ])
    portal.daily.extend([GOOD, (DAILY_BAD["no_matching_meter"], [f"{cookie}={POISON}; Path=/"])])
    client, entry, coord = build(hass, portal)
    proofs = []
    capture = client._capture_confirmed_session

    def captured():
        capture()
        proofs.append(copy.deepcopy(client.pending_confirmed_snapshot()))

    client._capture_confirmed_session = captured
    try:
        try:
            await coord._async_update_data()
        except Exception:  # noqa: BLE001
            pass
        assert proofs, "harness: renewal proof did not run"
        assert not poisoned(entry.data.get("cookies"), cookie), (
            "daily 200 without target data replaced the Dashboard+DAILY renewal-proven jar"
        )
    finally:
        coord.stop_keepalive()


async def test_owner_predicate_stays_true_during_own_cookie_write(hass):
    """The entry owner predicate is evaluated from executor threads (send hook,
    can_dispatch, record_terminal). Sample it at the instant HA swaps entry.data
    inside the coordinator's own cookie write, before _jar_baseline is updated."""
    portal = R6Portal()
    portal.daily.append(("__default__", [f"MM_SID={POISON}; Path=/"]))
    client, entry, coord = build(hass, portal)
    seen = []
    original = hass.config_entries.async_update_entry

    def spy(target, **kwargs):
        result = original(target, **kwargs)
        if "cookies" in (kwargs.get("data") or {}):
            seen.append(coord._renewal_runtime.is_active(coord._renewal_token))
        return result

    hass.config_entries.async_update_entry = spy
    try:
        await coord._async_update_data()
        assert seen, "harness: no cookie write observed"
        assert all(seen), f"owner predicate false inside the coordinator's own cookie write: {seen}"
    finally:
        hass.config_entries.async_update_entry = original
        coord.stop_keepalive()

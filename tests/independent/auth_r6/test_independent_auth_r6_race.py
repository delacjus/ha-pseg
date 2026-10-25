"""R6 forced-interleaving probe (timing-dependent in production): the coordinator's own
cookie write makes the entry-owner predicate false for an instant; an executor-side
renewal owner check landing in that instant sees a false retirement."""

from __future__ import annotations

from datetime import UTC, datetime
import time

import pytest

from custom_components.pseg.const import PORTAL_HOST
from tests.independent.auth_r6.test_independent_auth_r6 import R6Portal, build

pytestmark = pytest.mark.independent


@pytest.fixture(autouse=True)
def _enabled(enable_custom_integrations):
    yield


async def test_own_write_during_inflight_renewal_owner_check(hass):
    portal = R6Portal()
    client, entry, coord = build(hass, portal)
    try:
        await coord._async_update_data()  # persist a baseline jar
        assert entry.data.get("cookies")
        portal.dash.extend([
            {"kind": "login"},
            {"kind": "dash", "gate": True, "set_cookie": ["MM_RememberMe=r6-rotated-gen; Path=/"]},
        ])
        portal.gate_path = "/Dashboard"
        task = hass.async_add_executor_job(client.keepalive)
        assert await hass.async_add_executor_job(portal.entered.wait, 3)
        original = hass.config_entries.async_update_entry

        def spy(target, **kwargs):
            result = original(target, **kwargs)
            portal.release.set()
            time.sleep(0.5)  # forced interleaving: executor runs inside the write window
            return result

        hass.config_entries.async_update_entry = spy
        try:
            changed = [dict(c) for c in entry.data["cookies"]] + [{
                "name": "r6_aux", "value": "r6-other-write", "domain": PORTAL_HOST, "path": "/", "secure": True}]
            coord._write_cookie_handoff(changed, frozenset({"MM_SID"}))
        finally:
            hass.config_entries.async_update_entry = original
        outcome = await task
        adm = client._renewal_admission
        blocked = adm.blocked_reason(datetime.now(UTC))
        proof_sent = portal.count("POST", "/Dashboard/Chart")
        assert blocked != "exhausted", (
            f"false retirement during own write burned the generation: keepalive={outcome} "
            f"sequences={adm.sequences} retry={adm.retry_eligible} settled={adm.settled} "
            f"blocked={blocked} proof_posts={proof_sent} auth_reason={client.auth_reason}"
        )
    finally:
        portal.release.set()
        coord.stop_keepalive()

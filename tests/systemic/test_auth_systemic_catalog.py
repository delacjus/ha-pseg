"""P2-10 exact systemic mappings and focused real-lifecycle assertions."""

import asyncio
import copy
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import threading

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
import pytest

from custom_components.pseg.config_flow import PsegConfigFlow
from custom_components.pseg.const import (
    CONF_KNOWN_METER_IDS,
    CONF_RENEWAL_ADMISSION,
    DOMAIN,
    PORTAL_BASE_URL,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegError, PsegTransientError, _MeterRecord
from tests.mutations import auth_systemic_adapter
from tests.mutations.auth_systemic import (
    ADAPTER_LEVEL_DETECTORS,
    ADAPTER_LEVEL_LABELS,
    ADAPTER_LEVEL_MUTATIONS,
    ADAPTER_LEVEL_REASONS,
    MUTATIONS,
    NEW_MUTATIONS,
    ORIGINAL_MUTATIONS,
    SYSTEMIC_MUTATIONS,
)
from tests.support.boundaries import (
    BACKFILL_END,
    BACKFILL_START,
    DASHBOARD_HTML,
    LOGIN_HTML,
    METER_ID,
    PORTAL_HOST,
    install_auth_bounce,
    model_partial_live_jar,
    model_unvalidated_live_jar,
    replace_route,
    reserve_inflight_renewal,
)
from tests.support.factory import exit_boundary
from tests.support.portal import Gate, Reply
from tests.support.synthetic import build_synthetic_daily_chart, build_synthetic_hourly_chart
from tests.systemic.coverage_data import (
    P210_FAST_ADDITIONS,
    SYSTEMIC_AUTH_DETECTORS,
    collected_nodes as collected_nodes,
    module_inventory,
    require_node,
)
from tests.systemic.exit_cases import ExitProbe
from tests.systemic.findings import FINDINGS, KNOWN_GAPS
from tests.systemic.response_cases import run_focused_auth_case
from tools.mutation_check import load_table, resolve_target_path

ROOT = Path(__file__).resolve().parents[2]


def test_preserved_transformations_match_the_immutable_sixty():
    frozen = json.loads((ROOT / "tests/mutations/auth_guards_original.json").read_text())
    assert len(ORIGINAL_MUTATIONS) == len(frozen) == 60
    assert json.loads(json.dumps([r[:4] for r in ORIGINAL_MUTATIONS])) == [r[:4] for r in frozen], (
        "preserved transformation bytes changed"
    )
    assert len({r[0] for r in MUTATIONS}) == len(MUTATIONS)
    assert all(len(r) == 5 for r in MUTATIONS), "systemic typed-exception allowances are forbidden"
    for row in load_table(ROOT / "tests/mutations/auth_systemic.py"):
        assert row["expected"] is None
        text = resolve_target_path(ROOT, row["filename"]).read_text()
        assert all(text.count(before) == 1 for before in row["befores"]), row["label"]


def test_every_preserved_row_is_either_systemic_or_the_reviewed_adapter_level_set():
    assert ADAPTER_LEVEL_LABELS == {
        "13-security-step-latch",
        "50-renewal-empty-expected-fail-closed",
        "55-parser-only-provenance",
        "new-persist-auth-metadata-noop",
    }, "adapter-level reclassification changed"
    assert {r[0] for r in ADAPTER_LEVEL_MUTATIONS} == ADAPTER_LEVEL_LABELS
    assert set(ADAPTER_LEVEL_REASONS) == ADAPTER_LEVEL_LABELS
    assert set(ADAPTER_LEVEL_DETECTORS) == ADAPTER_LEVEL_LABELS
    for label, reason in ADAPTER_LEVEL_REASONS.items():
        assert "Masked by" in reason and reason.count(".") >= 2, label
        assert "masked by" in reason.lower(), label
    assert tuple(row for row in (*ORIGINAL_MUTATIONS, *NEW_MUTATIONS) if row[0] in ADAPTER_LEVEL_LABELS) == (
        ADAPTER_LEVEL_MUTATIONS
    )
    assert {r[0] for r in MUTATIONS} == {r[0] for r in (*ORIGINAL_MUTATIONS, *NEW_MUTATIONS)} - (
        ADAPTER_LEVEL_LABELS
    )
    assert [r[0] for r in SYSTEMIC_MUTATIONS] == [
        r[0] for r in ORIGINAL_MUTATIONS if r[0] not in ADAPTER_LEVEL_LABELS
    ]
    assert len(MUTATIONS) == 57 and len(ADAPTER_LEVEL_MUTATIONS) == 4


def test_adapter_table_is_runnable_and_complete():
    """The adapter-level rows are a real table, and the two tables partition 61.

    ``tools/mutation_check.py --table tests/mutations/auth_systemic_adapter.py``
    runs the four reviewed adapter rows directly. Exactly one table owns each row:
    57 systemic + 4 adapter-level = the 60 preserved transformations plus the one
    new fault.
    """
    systemic_rows = load_table(ROOT / "tests/mutations/auth_systemic.py")
    adapter_rows = load_table(ROOT / "tests/mutations/auth_systemic_adapter.py")
    systemic_labels = {row["label"] for row in systemic_rows}
    adapter_labels = {row["label"] for row in adapter_rows}
    assert adapter_labels == ADAPTER_LEVEL_LABELS == auth_systemic_adapter.LABELS
    assert auth_systemic_adapter.REASONS == ADAPTER_LEVEL_REASONS
    assert len(adapter_rows) == 4 and len(systemic_rows) == 57
    assert not systemic_labels & adapter_labels, "a row is owned by both tables"
    preserved = {row[0] for row in ORIGINAL_MUTATIONS}
    owned = systemic_labels | adapter_labels
    assert len(preserved) == 60
    assert preserved <= owned, sorted(preserved - owned)
    assert owned == {row[0] for row in (*ORIGINAL_MUTATIONS, *NEW_MUTATIONS)}
    assert len(owned) == 61
    assert len(preserved & systemic_labels) + len(preserved & adapter_labels) == 60
    for row in adapter_rows:
        assert row["expected"] is None, "typed-exception allowances are forbidden"


def test_adapter_level_rows_keep_their_exact_private_seam_assertion():
    for label, node in ADAPTER_LEVEL_DETECTORS.items():
        assert node.startswith("tests/systemic/test_auth_systemic_catalog.py::"), label
        assert node.split("::", 1)[1].startswith("test_adapter_"), (
            label,
            "adapter-level detectors must be clearly separated",
        )
        assert label not in SYSTEMIC_AUTH_DETECTORS


def test_every_detector_is_the_reviewed_exact_systemic_assertion(collected_nodes):
    assert set(SYSTEMIC_AUTH_DETECTORS) == {r[0] for r in MUTATIONS}
    for row in MUTATIONS:
        label, _, _, _, node = row
        expected_node, fingerprint = SYSTEMIC_AUTH_DETECTORS[label]
        assert node.startswith("tests/systemic/"), f"legacy/independent detector forbidden: {label}"
        assert node == expected_node, f"unreviewed detector substitution: {label}"
        require_node(collected_nodes, node, fast=True)
        assert collected_nodes[node]["assertion_fingerprint"] == fingerprint, (
            label,
            "reviewed systemic assertion body changed",
        )
        param_id = node.split("[", 1)[1][:-1] if "[" in node else None
        assert collected_nodes[node]["param_id"] == param_id, (
            label,
            "non-exact parameter selector",
        )


def test_p210_fast_additions_match_the_reviewed_exact_inventory(collected_nodes):
    assert set(P210_FAST_ADDITIONS) == {"tests/systemic/test_auth_systemic_catalog.py"}
    actual = module_inventory(collected_nodes, fast_only=True)
    assert {module: actual[module] for module in P210_FAST_ADDITIONS} == P210_FAST_ADDITIONS


def test_findings_have_reviewed_scenario_specific_systemic_links(collected_nodes):
    for finding in FINDINGS:
        links = finding.get("systemic_cases", ())
        assert links or finding["systemic_gap"].strip(), finding["id"]
        for node in links:
            assert node.startswith("tests/systemic/"), finding["id"]
            assert node in finding["fast_cases"] or node in finding["slow_cases"], finding["id"]
            require_node(collected_nodes, node)
        if links:
            assert finding["systemic_status"] == "covered", finding["id"]
            assert "P2-10 must map" not in finding["systemic_gap"], finding["id"]
    for gap in KNOWN_GAPS:
        assert gap.get("resolution"), gap["id"]
        assert gap.get("systemic_cases"), gap["id"]
        for node in gap["systemic_cases"]:
            require_node(collected_nodes, node, fast=True)
            assert any(node == expected for expected, _ in SYSTEMIC_AUTH_DETECTORS.values())


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock, enable_custom_integrations):
    """Use HA's offline recorder and the real integration lifecycle."""
    yield


async def test_checkpoint_ack_cannot_clear_a_newer_publication(hass):
    async def case(driver, oracle):
        client = driver.client
        # Two real, validated DAILY reads confirm two distinct jars. Each read
        # publishes its immutable checkpoint through the client's public accessor.
        first = await hass.async_add_executor_job(client.fetch_energy_data, 14)
        assert first["identity_confirmed"] is True
        first_snapshot = client.pending_confirmed_snapshot()
        assert first_snapshot is not None, "a validated read published no checkpoint"
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(
                body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)),
                cookies={"MM_AuxUtil": "SYNTH_P210_NEXT"},
            ),
        )
        oracle.register_eligible_cookie("MM_AuxUtil", "SYNTH_P210_NEXT")
        second_result = await hass.async_add_executor_job(client.fetch_energy_data, 14)
        assert second_result["identity_confirmed"] is True
        second = client.pending_confirmed_snapshot()
        assert second is not None and second["id"] > first_snapshot["id"], (
            "a newer confirmed read did not publish a newer checkpoint"
        )
        assert any(c["value"] == "SYNTH_P210_NEXT" for c in second["cookies"])
        # A stale acknowledgement of the superseded checkpoint must not drop the
        # newer publication.
        client.clear_confirmed_snapshot(first_snapshot["id"])
        assert client.pending_confirmed_snapshot() == second, (
            "stale ack discarded latest checkpoint"
        )
        # The real exit handoff persists only what is still the latest checkpoint.
        assert await driver.unload()
        assert any(
            c["value"] == "SYNTH_P210_NEXT" for c in driver.entry.data["cookies"]
        ), "latest confirmed publication was not durable at exit"

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_retired_keepalive_cannot_dismiss_successor_issue_after_export_await(hass):
    async def case(driver, oracle):
        old = driver.coordinator
        old.auth_required = True
        old.status = "auth_required"
        gate = Gate("P210_after_cookie_export")
        gate.hold()
        export = old.client.export_cookies_and_auth_reason

        def held_export():
            result = export()
            gate.arrive_and_wait()
            return result

        old.client.export_cookies_and_auth_reason = held_export
        task = asyncio.create_task(driver.keepalive_tick())
        try:
            await hass.async_add_executor_job(gate.wait_arrived)
            successor = copy.deepcopy(driver.entry.data["cookies"])
            successor.append(
                {
                    "name": "MM_AuxUtil",
                    "value": "SYNTH_P210_SUCCESSOR",
                    "domain": PORTAL_HOST,
                    "path": "/",
                    "secure": True,
                }
            )
            oracle.register_eligible_cookie("MM_AuxUtil", "SYNTH_P210_SUCCESSOR")
            hass.config_entries.async_update_entry(
                driver.entry, data={**driver.entry.data, "cookies": successor}
            )
            old._raise_auth_issues("SYNTH_P210_SUCCESSOR_AUTH_REQUIRED")
            issue_id = f"reauth_required_{driver.entry.entry_id}"
            assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is not None
            gate.proceed()
            await asyncio.wait_for(task, timeout=10)
            assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is not None, (
                "retired keepalive dismissed successor's issue after export await"
            )
            assert old.auth_required is True
        finally:
            gate.drain()
            old.client.export_cookies_and_auth_reason = export
            if not task.done():
                await asyncio.wait_for(task, timeout=10)
        assert await driver.reload()

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_rejected_daily_result_contains_no_foreign_readings(hass):
    async def case(driver, oracle):
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            [
                Reply.ok(body=json.dumps(build_synthetic_daily_chart(meter_id="87654321"))),
                Reply.ok(body=json.dumps(build_synthetic_hourly_chart(meter_id=METER_ID))),
            ],
        )
        result = await hass.async_add_executor_job(driver.client.fetch_energy_data, 14)
        assert result.get("identity_confirmed") is False, (
            "rejected daily result lost its explicit untrusted identity"
        )
        assert result["history_14d"] == [], "rejected daily identity retained foreign readings"
        assert result["daily_records"] == []
        assert result["latest_kwh"] == 0.0
        assert "87654321" not in result["meter_ids"]

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_renewal_requires_known_daily_proof_before_publication(hass):
    async def case(driver, oracle):
        prior = copy.deepcopy(driver.entry.data["cookies"])
        install_auth_bounce(driver.portal)
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(body=json.dumps(build_synthetic_daily_chart(meter_id="87654321"))),
        )
        error = None
        try:
            await driver.coordinator._async_update_data()
        except Exception as err:
            error = err
        assert isinstance(error, UpdateFailed) and isinstance(error.__cause__, PsegTransientError)
        assert driver.client.sso_renewals == 0, "unproven renewal published success telemetry"
        assert driver.entry.data["cookies"] == prior
        assert driver.client._renewal_admission.sequences == 1

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_renewal_anomalous_proof_never_adopts_response_cookies(hass):
    async def case(driver, oracle):
        install_auth_bounce(driver.portal)
        bad = Reply(
            reply_id="SYNTH_P210_ANOMALOUS_PROOF",
            status_code=200,
            body=json.dumps(_chart_payload("telemetry")),
            cookies={"MM_RememberMe": "SYNTH_P210_ANOMALY_POISON"},
            valid=False,
            cookie_eligible=False,
        )
        healthy = Reply.ok(body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)))
        oracle.register_quarantined_cookie("MM_RememberMe", "SYNTH_P210_ANOMALY_POISON")
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            [bad, healthy, healthy],
        )
        result = await driver.coordinator._async_update_data()
        assert result["identity_confirmed"] is True
        assert not any(
            c["value"] == "SYNTH_P210_ANOMALY_POISON" for c in driver.client.export_cookies()
        ), "anomalous renewal proof adopted a cookie generation"
        assert not any(
            c["value"] == "SYNTH_P210_ANOMALY_POISON" for c in driver.entry.data["cookies"]
        )
        assert driver.entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 1

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_hourly_stage_cookie_is_rolled_back_when_data_fails(hass):
    async def case(driver, oracle):
        prior = copy.deepcopy(driver.entry.data["cookies"])
        replace_route(
            driver.portal,
            ("POST", f"{PORTAL_BASE_URL}/Dashboard/Chart"),
            [
                Reply.ok(body="{}"),
                Reply.ok(body="{}", cookies={"MM_AuxUtil": "SYNTH_P210_STAGE_POISON"}),
            ],
        )
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            [
                Reply.ok(body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID))),
                Reply(
                    reply_id="SYNTH_P210_EMPTY_HOURLY",
                    body=json.dumps({"Data": None}),
                    valid=False,
                    cookie_eligible=False,
                ),
            ],
        )
        result = await driver.coordinator._async_update_data()
        assert result["hourly_records"] == []
        assert driver.entry.data["cookies"] == prior
        assert not any(
            c["value"] == "SYNTH_P210_STAGE_POISON" for c in driver.client.export_cookies()
        ), "failed hourly leg retained its setup-stage rotation"
        oracle.register_quarantined_cookie("MM_AuxUtil", "SYNTH_P210_STAGE_POISON")

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


@pytest.mark.parametrize("window", ["valid", "label-only"])
async def test_fresh_human_cookie_flow_has_its_own_account_proof(hass, window):
    async def case(driver, oracle):
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
            [
                Reply.redirect(location=f"{PORTAL_BASE_URL}/", status_code=302),
                Reply.ok(body=DASHBOARD_HTML, cookies={"MM_SID": "SYNTH_P210_HUMAN_PROVED"}),
                Reply.ok(body=DASHBOARD_HTML),
            ],
        )
        oracle.register_eligible_cookie("MM_SID", "SYNTH_P210_HUMAN_PROVED")
        if window == "label-only":
            replace_route(
                driver.portal,
                ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
                Reply(
                    reply_id="SYNTH_P210_LABEL_ONLY",
                    body=json.dumps(_chart_payload("empty")),
                    cookies={"MM_AuxUtil": "SYNTH_P210_LABEL_POISON"},
                    valid=False,
                    cookie_eligible=False,
                ),
            )
        flow = PsegConfigFlow()
        flow.hass = hass
        errors, client, meter, meters = await flow._async_validate_and_extract_meter(
            "", "MM_SID=SYNTH_P210_HUMAN_OLD; MM_RememberMe=SYNTH_P210_HUMAN_REMEMBER"
        )
        assert errors == {}, (
            f"fresh human proof was incorrectly sent through attached renewal policy: {errors}"
        )
        assert client is not None and meter == METER_ID and METER_ID in meters
        assert client.sso_renewals == 1
        if window == "label-only":
            assert not any(
                c["value"] == "SYNTH_P210_LABEL_POISON" for c in client.export_cookies()
            ), "label-only identity confirmed response cookies"
            pending = client.pending_confirmed_snapshot()
            assert not pending or not any(
                c["value"] == "SYNTH_P210_LABEL_POISON" for c in pending["cookies"]
            )

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_failed_renewal_preserves_preprobe_jar_and_spent_budget(hass):
    """A real failed cookie sequence spends budget without confirming a jar."""

    async def case(driver, oracle):
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply(
                reply_id="SYNTH_P210_AUTH_LOSS", status_code=401, valid=False, cookie_eligible=False
            ),
        )
        await driver.poll()
        assert driver.client.auth_reason is not None
        prior = copy.deepcopy(driver.entry.data["cookies"])
        pending = driver.client.pending_confirmed_snapshot()
        if pending is not None:
            # The unchanged physical checkpoint has already been acknowledged.
            assert pending["cookies"] == prior
            driver.client.clear_confirmed_snapshot(pending["id"])
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/"),
            Reply(
                reply_id="SYNTH_P210_EXPIRY_PROBE",
                body=LOGIN_HTML,
                cookies={"MM_RememberMe": "SYNTH_P210_UNPROVEN_PROBE"},
                valid=False,
                cookie_eligible=False,
            ),
        )
        oracle.register_quarantined_cookie("MM_RememberMe", "SYNTH_P210_UNPROVEN_PROBE")
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
            [
                Reply.redirect(location=f"{PORTAL_BASE_URL}/", status_code=302),
                Reply(
                    reply_id="SYNTH_P210_RENEWAL_503",
                    status_code=503,
                    valid=False,
                    cookie_eligible=False,
                ),
            ],
        )
        await driver.keepalive_tick()
        assert driver.entry.data["cookies"] == prior
        assert not any(
            c["value"] == "SYNTH_P210_UNPROVEN_PROBE" for c in driver.client.export_cookies()
        ), "expiry probe became the rollback baseline"
        policy = driver.entry.data.get(CONF_RENEWAL_ADMISSION)
        assert policy and policy["sequences"] == 1, (
            "failed renewal lost the spent budget without a cookie handoff"
        )
        assert policy["retry_eligible"] is True, "transient outcome was not persisted"
        # The real cold restart consumes only physical entry/Store bytes.
        from tests.support.boundaries import script_portal

        script_portal(driver.portal)
        await driver.cold_restart()
        assert driver.client._renewal_admission.sequences == 1, (
            "cold restart forgot failed renewal budget"
        )

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_failed_first_setup_preserves_spent_terminal_admission(hass):
    async def case(driver, oracle):
        # Every Dashboard probe is signed out, including both cookie-only
        # attempts. This is a real failed first refresh, without a jar handoff.
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
            Reply.redirect(location=f"{PORTAL_BASE_URL}/", status_code=302),
        )
        assert await driver.setup() is False
        saved = driver.entry.data.get(CONF_RENEWAL_ADMISSION)
        assert saved is not None, "failed startup lost policy-only handoff"
        assert saved["sequences"] == 1
        assert saved["terminal_reason"] == "remember_me_rejected"

    ending = await run_focused_auth_case(hass, case, setup=False, terminal=True)
    assert ending.success


async def test_replacement_inherits_the_inflight_entry_reservation(hass):
    async def case(driver, oracle):
        old = driver.coordinator
        prior = copy.deepcopy(driver.entry.data["cookies"])
        # Adapter precondition: one renewal already spent the shared entry slot and
        # has not yielded, so durable metadata still describes the pre-reservation
        # state. The client and coordinator under test are production objects.
        reserve_inflight_renewal(old.client)
        client = driver.factory.create_client(
            cookie_list=copy.deepcopy(driver.entry.data["cookies"])
        )
        replacement = PsegDataUpdateCoordinator(
            hass, client, dict(driver.entry.data), config_entry=driver.entry
        )
        install_auth_bounce(driver.portal)
        error = None
        try:
            await hass.async_add_executor_job(replacement.client.ensure_session)
        except PsegError as err:
            error = err
        finally:
            replacement.stop_keepalive()
        assert error is not None, "replacement dispatched a second renewal"
        assert replacement.client.sso_renewals == 0, (
            "replacement dispatched a second renewal from a stale persisted copy"
        )
        assert driver.entry.data["cookies"] == prior
        assert await driver.reload()

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


@pytest.mark.parametrize("variant", ["maintenance", "notoken", "503"])
async def test_postrenewal_dashboard_failure_keeps_verified_checkpoint(hass, variant):
    async def case(driver, oracle):
        bad = Reply(
            reply_id="SYNTH_P210_BAD_DASH",
            status_code=503 if variant == "503" else 200,
            body="<html>no token</html>",
            cookies={"MM_AuxUtil": "SYNTH_P210_POSTPROOF_POISON"},
            valid=False,
            cookie_eligible=False,
        )
        if variant == "maintenance":
            bad = Reply.redirect(location=f"{PORTAL_BASE_URL}/Maintenance", status_code=302)
            replace_route(
                driver.portal,
                ("GET", f"{PORTAL_BASE_URL}/Maintenance"),
                Reply(
                    reply_id="SYNTH_P210_MAINT",
                    body="maintenance",
                    cookies={"MM_AuxUtil": "SYNTH_P210_POSTPROOF_POISON"},
                    valid=False,
                    cookie_eligible=False,
                ),
            )
        oracle.register_eligible_cookie("MM_SID", "SYNTH_P210_VERIFIED")
        oracle.register_quarantined_cookie("MM_AuxUtil", "SYNTH_P210_POSTPROOF_POISON")
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
            [
                Reply.redirect(location=f"{PORTAL_BASE_URL}/", status_code=302),
                Reply.ok(body=DASHBOARD_HTML, cookies={"MM_SID": "SYNTH_P210_VERIFIED"}),
                bad,
            ],
        )
        error = None
        try:
            await driver.coordinator._async_update_data()
        except Exception as err:
            error = err
        assert isinstance(error, UpdateFailed) and isinstance(
            error.__cause__, PsegTransientError
        ), f"expected typed post-renewal transient: {error!r}"
        assert driver.client.cookies_confirmed is True, (
            "postproof hiccup rolled back verified confirmation"
        )
        assert driver.client.sso_renewals == 1, (
            "postproof hiccup rolled back verified renewal telemetry"
        )
        assert any(c["value"] == "SYNTH_P210_VERIFIED" for c in driver.entry.data["cookies"]), (
            "verified renewal was not durable at failure exit"
        )
        assert not any(
            c["value"] == "SYNTH_P210_POSTPROOF_POISON" for c in driver.client.export_cookies()
        ), "postproof failed response poisoned the live jar"

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


@pytest.mark.parametrize("domain_copy", [False, True], ids=["host", "domain-copy"])
async def test_confirmed_remember_slide_is_not_a_second_renewal_generation(hass, domain_copy):
    async def case(driver, oracle):
        header = "MM_RememberMe=SYNTH_P210_SLIDE; Path=/"
        if domain_copy:
            header += f"; Domain=.{PORTAL_HOST}"
        oracle.register_eligible_cookie("MM_RememberMe", "SYNTH_P210_SLIDE")
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard"),
            Reply.ok(body=DASHBOARD_HTML, headers={"Set-Cookie": header}),
        )
        await driver.keepalive_tick()
        install_auth_bounce(driver.portal)
        await driver.keepalive_tick()
        assert driver.entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 1, (
            "unchanged renewal invented a new generation"
        )

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


@pytest.mark.parametrize("reason", ["cooldown", "uncertain", "exhausted"])
async def test_loaded_admission_has_the_correct_public_outcome(hass, reason):
    data = (
        {"sequences": True}
        if reason == "uncertain"
        else {
            "sequences": 1,
            "last_sequence_at": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
            "retry_eligible": reason == "cooldown",
            "terminal_reason": None,
        }
    )
    entry_data = {CONF_RENEWAL_ADMISSION: data}
    if reason == "exhausted":
        entry_data.update(mymeter_email="SYNTH_P210_EMAIL", mymeter_password="SYNTH_P210_PASSWORD")

    async def case(driver, oracle):
        install_auth_bounce(driver.portal)
        before = len(driver.dispatches)
        if reason == "uncertain":
            await driver.keepalive_tick()
            assert driver.coordinator.auth_required, (
                "corrupt admission keepalive did not ask for human sign-in"
            )
            assert (await driver.snapshot()).flows or (await driver.snapshot()).issues
            return
        await driver.poll()
        posts = [
            d for d in driver.dispatches[before:] if d.method == "POST" and "/Home/Login" in d.url
        ]
        assert posts == [], "spent generation fell through to saved-password auth"
        if reason == "cooldown":
            assert isinstance(driver.coordinator.last_exception, UpdateFailed)
            assert not driver.coordinator.auth_required, (
                "earned retry cooldown became terminal auth loss"
            )
            assert driver.coordinator._unsub_keepalive is not None
        else:
            assert driver.coordinator.auth_required, (
                "uncertain/spent poll did not ask for human sign-in"
            )
            install_auth_bounce(driver.portal)
            await driver.keepalive_tick()
            assert driver.coordinator.auth_required, (
                "uncertain/spent budget did not ask for human sign-in"
            )
            assert (await driver.snapshot()).flows or (await driver.snapshot()).issues

    ending = await run_focused_auth_case(hass, case, entry_data=entry_data)
    assert ending.success


async def test_login_json_security_step_is_latched_and_durable(hass):
    async def case(driver, oracle):
        install_auth_bounce(driver.portal)
        replace_route(
            driver.portal,
            ("POST", f"{PORTAL_BASE_URL}/Home/Login"),
            Reply(
                reply_id="SYNTH_P210_SECURITY_JSON",
                status_code=200,
                body=json.dumps({"Data": {"SecretQuestionError": True}}),
                valid=False,
                cookie_eligible=False,
            ),
        )
        await driver.poll()
        assert any(d.reply_id == "SYNTH_P210_SECURITY_JSON" for d in driver.dispatches)
        assert driver.entry.data[CONF_RENEWAL_ADMISSION]["terminal_reason"] == "security_step", (
            "terminal login outcome was not durable"
        )
        assert driver.coordinator.auth_required
        # A warm timer and a reconstructed client must refuse before any HTTP,
        # even though the adapter offers healthy replies.
        before = len(driver.dispatches)
        await driver.keepalive_tick()
        assert len(driver.dispatches) == before, "warm terminal keepalive sent HTTP"
        await driver.cold_restart()
        assert driver.client._renewal_admission.terminal_reason == "security_step"
        before = len(driver.dispatches)
        await driver.keepalive_tick()
        assert len(driver.dispatches) == before, "cold terminal keepalive sent HTTP"

    ending = await run_focused_auth_case(hass, case, flow="L", terminal=True)
    assert ending.success


@pytest.mark.parametrize("mode", ["immutable", "unconfirmed", "partial"])
async def test_handoff_refuses_unvalidated_or_partial_live_jar(hass, mode):
    async def case(driver, oracle):
        client = driver.client
        # One real validated DAILY read confirms and publishes the whole jar.
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(
                body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)),
                cookies={"MM_SID": "SYNTH_P210_CONFIRMED"},
            ),
        )
        oracle.register_eligible_cookie("MM_SID", "SYNTH_P210_CONFIRMED")
        result = await hass.async_add_executor_job(client.fetch_energy_data, 14)
        assert result["identity_confirmed"] is True
        confirmed = client.confirmed_cookies()
        assert confirmed and any(c["value"] == "SYNTH_P210_CONFIRMED" for c in confirmed)
        if mode == "partial":
            model_partial_live_jar(driver)
            # Keep a nonempty auxiliary-only jar so the session-name guard, not the
            # unrelated empty-export guard, must refuse it.
            model_unvalidated_live_jar(driver, "MM_AuxUtil", "SYNTH_P210_PARTIAL")
        else:
            model_unvalidated_live_jar(driver, "MM_AuxUtil", "SYNTH_P210_UNPROVEN")
        if mode == "immutable":
            # Exit handoff: never the live jar, only the confirmed immutable snapshot.
            assert await driver.unload()
            assert any(
                c["value"] == "SYNTH_P210_CONFIRMED" for c in driver.entry.data["cookies"]
            ), "confirmed jar was not durable at exit"
            assert not any(
                c["value"] == "SYNTH_P210_UNPROVEN" for c in driver.entry.data["cookies"]
            ), "exit handoff persisted unvalidated live cookies"
            return
        if mode == "partial":
            # A healthy keepalive confirms the live (partial) jar; persistence must
            # still refuse to trade the saved session jar for a partial one.
            await driver.keepalive_tick()
            assert any(c["name"] == "MM_SID" for c in driver.entry.data["cookies"]), (
                "partial live jar replaced the persisted session jar"
            )
            return
        # unconfirmed: the poll's export snapshot is taken, a parallel request then
        # rotates the live jar and its own keepalive makes that newer jar durable.
        # The older queued export must not overwrite the newer parallel confirmation.
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(
                body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)),
                cookies={"MM_AuxUtil": "SYNTH_P210_OLD"},
            ),
        )
        oracle.register_eligible_cookie("MM_AuxUtil", "SYNTH_P210_OLD")
        probe = ExitProbe(exit_boundary("export_cookies_and_auth_reason", "after"))
        probe.install(client)
        task = asyncio.create_task(driver.poll())
        try:
            await hass.async_add_executor_job(probe.gate.wait_arrived)
            model_unvalidated_live_jar(driver, "MM_AuxUtil", "SYNTH_P210_PARALLEL")
            oracle.register_eligible_cookie("MM_AuxUtil", "SYNTH_P210_PARALLEL")
            await driver.keepalive_tick()
            assert any(
                c["value"] == "SYNTH_P210_PARALLEL" for c in driver.entry.data["cookies"]
            ), "the parallel confirmed jar never became durable"
        finally:
            probe.gate.proceed()
        await asyncio.wait_for(task, timeout=10)
        assert any(
            c["value"] == "SYNTH_P210_PARALLEL" for c in driver.entry.data["cookies"]
        ), "an older unconfirmed export replaced the newer parallel confirmation"

    ending = await run_focused_auth_case(hass, case, flow="L")
    assert ending.success


async def test_old_checkpoint_cannot_overwrite_human_successor(hass):
    async def case(driver, oracle):
        old = driver.coordinator
        # A real validated read leaves an immutable checkpoint pending for the exit
        # handoff (nothing has persisted it yet).
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(
                body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)),
                cookies={"MM_SID": "SYNTH_P210_OLD_CHECKPOINT"},
            ),
        )
        oracle.register_eligible_cookie("MM_SID", "SYNTH_P210_OLD_CHECKPOINT")
        await hass.async_add_executor_job(old.client.fetch_energy_data, 14)
        pending = old.client.pending_confirmed_snapshot()
        assert pending is not None
        successor = copy.deepcopy(driver.entry.data["cookies"])
        successor.append(
            {
                "name": "MM_AuxUtil",
                "value": "SYNTH_P210_HUMAN",
                "domain": PORTAL_HOST,
                "path": "/",
                "secure": True,
            }
        )
        oracle.register_eligible_cookie("MM_AuxUtil", "SYNTH_P210_HUMAN")
        hass.config_entries.async_update_entry(
            driver.entry, data={**driver.entry.data, "cookies": successor}
        )
        # The successor's own poll must not re-learn the retired checkpoint's jar.
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID))),
        )
        # The real unload exit of the retired owner must not overwrite the successor.
        assert await driver.reload()
        assert driver.entry.data["cookies"] == successor, (
            "retired checkpoint overwrote the human successor"
        )

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


def _chart_payload(variant):
    good = build_synthetic_daily_chart(meter_id=METER_ID)
    if variant == "root":
        return []
    if variant == "null":
        return {"Data": None}
    if variant == "empty":
        return {"Data": {"series": [{"name": f"Meter #{METER_ID}", "data": []}]}}
    if variant == "nested":
        return {"Data": {"series": [{"name": f"Meter #{METER_ID}", "data": 123}]}}
    if variant == "ajax":
        return {**good, "AjaxResults": 123}
    if variant == "foreign":
        foreign = build_synthetic_daily_chart(meter_id="87654321")
        foreign["Data"]["series"].append({"name": f"Meter #{METER_ID}", "data": []})
        return foreign
    if variant == "telemetry":
        good["Data"]["series"].insert(0, {"name": "Temperature", "data": {"y": 1}})
        return good
    raise AssertionError(variant)


CHART_CASES = [
    ("daily", "empty"),
    ("hourly", "empty"),
    ("hourly", "root"),
    ("backfill", "null"),
    ("daily", "nested"),
    ("backfill", "nested"),
    ("daily", "ajax"),
    ("backfill", "ajax"),
    ("daily", "foreign"),
    ("daily", "telemetry"),
    ("hourly", "foreign"),
]


@pytest.mark.parametrize("leg,variant", CHART_CASES, ids=[f"{a}-{b}" for a, b in CHART_CASES])
async def test_focused_chart_response_contract(hass, leg, variant):
    """A typed failure/fallback quarantines its whole jar before the ending."""

    async def case(driver, oracle):
        prior = copy.deepcopy(driver.entry.data["cookies"])
        healthy = Reply.ok(body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)))
        bad = Reply(
            reply_id="SYNTH_P210_INVALID",
            status_code=200,
            body=json.dumps(_chart_payload(variant)),
            cookies={"MM_AuxUtil": "SYNTH_P210_INVALID"},
            valid=False,
            cookie_eligible=False,
        )
        oracle.register_quarantined_cookie("MM_AuxUtil", "SYNTH_P210_INVALID")
        replies = [healthy, bad] if leg == "hourly" else [bad, healthy]
        replace_route(driver.portal, ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"), replies)
        error = None
        result = None
        try:
            if leg == "backfill":
                result = await driver.coordinator.async_backfill_history(
                    BACKFILL_START, BACKFILL_END
                )
            else:
                result = await driver.coordinator._async_update_data()
        except Exception as err:
            error = err
        assert error is None or isinstance(
            error, (PsegError, UpdateFailed, ConfigEntryAuthFailed)
        ), f"untyped chart error: {error!r}"
        if isinstance(error, UpdateFailed) and error.__cause__ is not None:
            assert isinstance(error.__cause__, PsegTransientError), (
                f"untyped parser cause: {error.__cause__!r}"
            )
        if leg == "backfill" and variant == "null":
            assert error is None, f"an empty edge chunk must remain an allowed gap: {error!r}"
        elif leg == "hourly" or variant == "telemetry":
            assert error is None, f"usable daily fallback was lost: {error!r}"
            assert result["identity_confirmed"] is True
            if leg == "hourly":
                assert result["hourly_records"] == []
        else:
            assert error is not None, "unproven/malformed chart returned successful readings"
        assert driver.entry.data["cookies"] == prior, "invalid chart changed physical cookies"
        assert not any(
            c["value"] == "SYNTH_P210_INVALID" for c in driver.client.export_cookies()
        ), "invalid chart survived in live jar"
        pending = driver.client.pending_confirmed_snapshot()
        assert not pending or not any(
            c["value"] == "SYNTH_P210_INVALID" for c in pending["cookies"]
        )

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_hourly_login_redirect_is_typed_auth_loss_with_statistics_isolation(hass):
    async def case(driver, oracle):
        before = await driver.snapshot()
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            [
                Reply.ok(body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID))),
                Reply.redirect(location=f"{PORTAL_BASE_URL}/", status_code=302),
            ],
        )
        error = None
        try:
            await driver.coordinator._async_update_data()
        except Exception as err:
            error = err
        assert isinstance(error, ConfigEntryAuthFailed), (
            f"hourly auth redirect became daily fallback: {error!r}"
        )
        after = await driver.snapshot()
        assert before.rows == after.rows, "hourly auth failure modified statistics"
        assert not oracle.evaluate_i12(before, after)
        assert driver.coordinator.auth_required

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_daily_successor_is_learned_when_hourly_omits_it(hass):
    async def case(driver, oracle):
        payload = build_synthetic_daily_chart(meter_id=METER_ID)
        successor = build_synthetic_daily_chart(meter_id="87654321")
        payload["Data"]["series"].extend(successor["Data"]["series"])
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            [
                Reply.ok(body=json.dumps(payload)),
                Reply.ok(body=json.dumps(build_synthetic_hourly_chart(meter_id=METER_ID))),
            ],
        )
        result = await driver.coordinator._async_update_data()
        assert set(result["contributing_meter_ids"]) == {METER_ID, "87654321"}
        assert "87654321" in driver.entry.data[CONF_KNOWN_METER_IDS], (
            "valid daily successor lost behind hourly identity"
        )

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_valid_history_chunk_publishes_immutable_checkpoint(hass):
    async def case(driver, oracle):
        reply = Reply.ok(
            body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)),
            cookies={"MM_AuxUtil": "SYNTH_P210_CHUNK"},
        )
        oracle.register_eligible_cookie("MM_AuxUtil", "SYNTH_P210_CHUNK")
        replace_route(driver.portal, ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"), reply)
        result = await hass.async_add_executor_job(
            driver.client.fetch_history_range, BACKFILL_START, BACKFILL_END
        )
        assert result
        pending = driver.client.pending_confirmed_snapshot()
        assert pending and any(c["value"] == "SYNTH_P210_CHUNK" for c in pending["cookies"]), (
            "accepted history chunk never published its checkpoint"
        )
        driver.coordinator._persist_confirmed_session()
        assert any(c["value"] == "SYNTH_P210_CHUNK" for c in driver.entry.data["cookies"])

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


@pytest.mark.parametrize("after_assignment", [False, True], ids=["before", "after"])
async def test_handoff_callback_fault_preserves_physical_owner(hass, after_assignment):
    async def case(driver, oracle):
        original = hass.config_entries.async_update_entry
        baseline = copy.deepcopy(driver.entry.data["cookies"])
        target = baseline + [
            {
                "name": "MM_AuxUtil",
                "value": "SYNTH_P210_HANDOFF",
                "domain": PORTAL_HOST,
                "path": "/",
                "secure": True,
            }
        ]
        oracle.register_eligible_cookie("MM_AuxUtil", "SYNTH_P210_HANDOFF")
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(
                body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)),
                cookies={"MM_AuxUtil": "SYNTH_P210_HANDOFF"},
            ),
        )

        def update(entry, **kwargs):
            if after_assignment:
                original(entry, **kwargs)
            raise PsegTransientError("SYNTH_P210_CALLBACK_FAULT")

        hass.config_entries.async_update_entry = update
        try:
            await driver.poll()
        finally:
            hass.config_entries.async_update_entry = original
        def pairs(cookies):
            return {(c["name"], c["value"]) for c in cookies}

        assert pairs(driver.entry.data["cookies"]) == pairs(
            target if after_assignment else baseline
        )
        assert isinstance(driver.coordinator.last_exception, UpdateFailed), (
            "the failing handoff callback was silently ignored"
        )
        assert isinstance(
            driver.coordinator.last_exception.__cause__, PsegTransientError
        ), "the handoff fault lost its typed outcome"
        # The coordinator that wrote its own jar is still the physical owner: the
        # mandatory following poll must not treat it as a foreign replacement.
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID))),
        )
        await driver.poll()
        assert driver.coordinator.last_update_success is True, (
            "own durable assignment was mistaken for a foreign owner"
        )

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_owner_stays_active_inside_own_physical_assignment(hass):
    async def case(driver, oracle):
        replace_route(
            driver.portal,
            ("GET", f"{PORTAL_BASE_URL}/Dashboard/ChartData"),
            Reply.ok(
                body=json.dumps(build_synthetic_daily_chart(meter_id=METER_ID)),
                cookies={"MM_AuxUtil": "SYNTH_P210_OWN_WRITE"},
            ),
        )
        oracle.register_eligible_cookie("MM_AuxUtil", "SYNTH_P210_OWN_WRITE")
        original = hass.config_entries.async_update_entry
        observed = []

        def update(entry, **kwargs):
            result = original(entry, **kwargs)
            # The coordinator's own atomic assignment is in flight. A real request
            # from the same owner must still be allowed to dispatch.
            before = len(driver.dispatches)
            outcome = {}

            def concurrent_request():
                try:
                    outcome["ok"] = driver.client.ensure_session()
                except Exception as err:  # noqa: BLE001 - the assertion is the verdict
                    outcome["error"] = err

            worker = threading.Thread(target=concurrent_request, daemon=True)
            worker.start()
            worker.join(timeout=10)
            outcome["dispatched"] = len(driver.dispatches) > before
            observed.append(outcome)
            return result

        hass.config_entries.async_update_entry = update
        try:
            await driver.poll()
        finally:
            hass.config_entries.async_update_entry = original
        assert observed, "the coordinator never performed its own physical cookie assignment"
        assert observed[0]["dispatched"] and "error" not in observed[0], (
            "owner retired during its own atomic cookie assignment"
        )
        assert any(
            c["value"] == "SYNTH_P210_OWN_WRITE" for c in driver.entry.data["cookies"]
        ), "own confirmed jar was not durably assigned"

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_uncertain_midsequence_admission_refuses_publication(hass):
    """Row 1: a mid-renewal admission fault must fail the poll closed.

    The renewal's HA metadata handoff fails while its proof read is parked, so
    the shared admission becomes uncertain while the owner is still active. The
    stage guard's ``can_dispatch`` (reservation owner plus not-uncertain) is then
    the only refusal that can stop the rest of the sequence: it must fail the
    poll closed, dispatch no further Chart POST, keep the renewal unconfirmed and
    persist no unvalidated cookie jar.
    """

    async def case(driver, oracle):
        original = hass.config_entries.async_update_entry
        persisted = threading.Event()
        prior_cookies = copy.deepcopy(driver.entry.data["cookies"])

        def chart_posts():
            return [
                dispatch
                for dispatch in driver.portal.dispatches
                if dispatch.method == "POST"
                and dispatch.url == f"{PORTAL_BASE_URL}/Dashboard/Chart"
            ]

        def update(entry, **kwargs):
            data = kwargs.get("data")
            if (
                data is not None
                and data.get("cookies") == entry.data.get("cookies")
                and data.get(CONF_RENEWAL_ADMISSION)
                != entry.data.get(CONF_RENEWAL_ADMISSION)
            ):
                persisted.set()
                raise RuntimeError("SYNTH_P210_ADMISSION_HANDOFF_FAULT")
            return original(entry, **kwargs)

        # The bounce routes make the pending renewal a real proof-read sequence;
        # the gate parks it before the first Chart POST so the admission handoff
        # failure lands mid-sequence.
        install_auth_bounce(driver.portal)
        gate = driver.portal.gate("before_send:POST:/Dashboard/Chart")
        gate.hold()
        hass.config_entries.async_update_entry = update
        task = hass.async_create_task(driver.poll())
        try:
            fault_seen = await hass.async_add_executor_job(persisted.wait, 10)
            parked_posts = len(chart_posts())
        finally:
            gate.proceed()
            hass.config_entries.async_update_entry = original
            await task

        assert fault_seen, "the renewal never attempted its admission handoff"
        assert isinstance(driver.coordinator.last_exception, UpdateFailed), (
            "the uncertain admission did not fail the poll closed"
        )
        assert driver.coordinator.last_update_success is False, (
            "an uncertain mid-renewal admission was reported as a healthy poll"
        )
        assert len(chart_posts()) == parked_posts, (
            "the uncertain admission dispatched further Chart POSTs: "
            f"{len(chart_posts())} after {parked_posts}"
        )
        assert driver.client.sso_renewals == 0, "an unconfirmed renewal was counted"
        assert driver.entry.data["cookies"] == prior_cookies, (
            "an unconfirmed renewal persisted its cookie jar"
        )

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


# ---------------------------------------------------------------------------
# ADAPTER_LEVEL: rows whose only faithful detector is a private seam.
#
# These are NOT systemic detections. Each test asserts a production seam that has
# no observable dispatch/persistence/HA difference; the written reason for every
# row lives in tests/mutations/auth_systemic.ADAPTER_LEVEL_REASONS and the catalog
# meta-test asserts this exact set.
# ---------------------------------------------------------------------------


async def test_adapter_in_memory_security_step_latch(hass):
    """ADAPTER_LEVEL (13-security-step-latch): the in-process latch flag itself."""

    async def case(driver, oracle):
        install_auth_bounce(driver.portal)
        replace_route(
            driver.portal,
            ("POST", f"{PORTAL_BASE_URL}/Home/Login"),
            Reply(
                reply_id="SYNTH_P210_SECURITY_JSON",
                status_code=200,
                body=json.dumps({"Data": {"SecretQuestionError": True}}),
                valid=False,
                cookie_eligible=False,
            ),
        )
        await driver.poll()
        assert driver.client._security_step_latched is True, (
            "Login POST JSON did not latch the security step"
        )

    ending = await run_focused_auth_case(hass, case, flow="L", terminal=True)
    assert ending.success


async def test_adapter_parser_provenance_and_empty_renewal_identity(hass):
    """ADAPTER_LEVEL (50, 55): parser provenance and the empty-expected guard."""

    async def case(driver, oracle):
        client = driver.client
        client.set_expected_meter_ids({METER_ID})
        for claim in ({"meter_id": METER_ID}, {"meter_ids": [METER_ID]}):
            record = {"date": "2026-10-21", "kwh": 3.0, **claim}
            assert not client._has_valid_meter_read([record], [METER_ID]), (
                "plain dictionary forged parser provenance"
            )
        known = _MeterRecord(
            {"date": "2026-10-21", "kwh": 3.0}, contributing_meter_ids=(METER_ID,)
        )
        client.set_expected_meter_ids(set())
        assert not client._has_valid_meter_read([known], [METER_ID], require_expected=True), (
            "renewal with no prior identity was accepted"
        )
        client.set_expected_meter_ids({METER_ID})
        assert client._has_valid_meter_read([known], [METER_ID], require_expected=True)

    ending = await run_focused_auth_case(hass, case)
    assert ending.success


async def test_adapter_exit_persists_policy_state(hass):
    """ADAPTER_LEVEL (new-persist-auth-metadata-noop): the loop-independent write.

    The runtime's own scheduled callback is what normally persists policy, so the
    synchronous exit call is only observable when the loop cannot deliver it. This
    test changes in-memory policy and calls the exit write directly; it must reach
    entry.data.
    """

    async def case(driver, oracle):
        coord = driver.coordinator
        before = dict(driver.entry.data.get(CONF_RENEWAL_ADMISSION) or {})
        coord._renewal_runtime.admission.sequences = 3
        coord._persist_auth_metadata()
        assert driver.entry.data[CONF_RENEWAL_ADMISSION]["sequences"] == 3, (
            "exit write did not persist the budget without loop delivery"
        )
        assert before.get("sequences") != 3

    ending = await run_focused_auth_case(hass, case)
    assert ending.success

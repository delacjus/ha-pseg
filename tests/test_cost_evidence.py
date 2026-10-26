"""Unit and contract tests for RC-02 bounded, isolated cost evidence sampler."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
import json
import time
from unittest.mock import MagicMock, patch
import urllib.parse

from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
import requests_mock

from custom_components.pseg.const import (
    COST_MODE_EVIDENCE,
    COST_MODE_OFF,
    DOMAIN,
    PORTAL_BASE_URL,
    PORTAL_HOST,
    USAGE_INTERVAL_DAILY,
    USAGE_INTERVAL_HOURLY,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.cost_evidence import (
    MAX_COST_BYTES,
    NY_TZ,
    CostEvidenceStatus,
    CostEvidenceStore,
    CostPermit,
    RejectingCookieJar,
    execute_cost_sampler,
    validate_and_sanitize_cost_payload,
)
from custom_components.pseg.diagnostics import async_get_config_entry_diagnostics
from custom_components.pseg.pseg_client import (
    PsegClient,
    PsegTransientError,
)

RAW_VALID_COST_PAYLOAD = {
    "Data": {
        # Dollars are proven by the response, not assumed from the request
        # (observed contract, docs/portal-cost.md §2.4).
        "usageType": "Dollar",
        "tooltipOptions": {"currency": "USD", "usageTypeDisplayName": "Dollar"},
        "series": [
            {
                "name": "Meter #12345678",
                "tooltip": {"valuePrefix": "$", "valueDecimals": 2},
                "data": [
                    {
                        "x": 1729828800000,
                        "y": 0.0,
                        "hs": {"start": "2026-10-25 00:00:00", "end": "2026-10-25 01:00:00"},
                    },
                    {
                        "x": 1729832400000,
                        "y": 1.25,
                        "hs": {"start": "2026-10-25 01:00:00", "end": "2026-10-25 02:00:00"},
                    },
                ],
            }
        ],
    }
}


def _make_dummy_permit(
    usage_interval: str = USAGE_INTERVAL_DAILY,
    ny_date_str: str = "2026-10-25",
) -> CostPermit:
    return CostPermit(
        permit_id="test_permit_123",
        entry_id="test_entry_001",
        ny_date=ny_date_str,
        usage_interval=usage_interval,
        start_str="2026-10-11",
        end_str="2026-10-25",
        created_at=datetime.now(UTC).isoformat(),
    )


# ---------------------------------------------------------------------------
# Non-Negotiable 1: Isolated Execution Conditions
# ---------------------------------------------------------------------------


def test_cost_leg_runs_only_with_proven_daily_identity_and_permit() -> None:
    """NN1: Cost leg requires proven daily identity and does not run on failed identity."""
    client = PsegClient(portal_cookies="MM_SID=valid_sid")
    client.set_expected_meter_ids(["12345678"])
    permit = _make_dummy_permit()

    # Daily chart has readings for a DIFFERENT meter (99999999), so identity is rejected
    mismatched_daily = {
        "Data": {
            "series": [
                {
                    "name": "Meter #99999999",
                    "data": [
                        {
                            "x": 1000,
                            "y": 10.0,
                            "hs": {"start": "10/24/2026", "end": "10/24/2026"},
                        }
                    ],
                }
            ]
        }
    }

    with patch.object(client, "_get_verification_token", return_value="tok"):
        with patch.object(client, "_fetch_chart_json", return_value=mismatched_daily):
            with patch("custom_components.pseg.cost_evidence.execute_cost_sampler") as mock_sampler:
                res = client.fetch_energy_data(days_back=14, cost_permit=permit)
                assert res.get("identity_confirmed") is not True
                mock_sampler.assert_not_called()


def test_cost_leg_never_runs_from_keepalive_or_backfill() -> None:
    """NN1: Keepalive, backfill, and test_connection never dispatch cost requests."""
    client = PsegClient(portal_cookies="MM_SID=valid_sid")

    with patch.object(client, "_get_dashboard") as mock_dash:
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = b"<html><div id='storageType'></div></html>"
        mock_resp.url = f"{PORTAL_BASE_URL}/Dashboard"
        mock_dash.return_value = mock_resp

        # Keepalive does not call cost sampler
        with patch("custom_components.pseg.cost_evidence.execute_cost_sampler") as mock_sampler:
            client._keepalive_local()
            mock_sampler.assert_not_called()

    # Backfill history range does not call cost sampler
    with patch.object(client, "_get_verification_token", return_value="tok"):
        with requests_mock.Mocker(session=client.session) as mock:
            mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
            mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json={"Data": {"series": []}})
            with patch("custom_components.pseg.cost_evidence.execute_cost_sampler") as mock_sampler:
                client.fetch_history_range("2026-10-01", "2026-10-05")
                mock_sampler.assert_not_called()


# ---------------------------------------------------------------------------
# Non-Negotiable 2 & Negative Proofs: RejectingCookieJar and Transport Isolation
# ---------------------------------------------------------------------------


def test_rejecting_cookie_jar_rejects_updates_when_locked() -> None:
    """NN2 & NegProof: RejectingCookieJar accepts seed cookies but rejects all subsequent updates."""
    jar = RejectingCookieJar()
    cookie1 = requests.cookies.create_cookie(
        name="MM_SID", value="original_seed", domain=PORTAL_HOST
    )
    jar.set_cookie(cookie1)
    assert jar.get("MM_SID") == "original_seed"

    jar.lock()

    # Try setting poisoned cookie directly
    cookie_poison = requests.cookies.create_cookie(
        name="MM_SID", value="poisoned_value", domain=PORTAL_HOST
    )
    jar.set_cookie(cookie_poison)
    assert jar.get("MM_SID") == "original_seed"  # Unchanged!

    # Try extracting cookies from response
    resp = requests.Response()
    resp.headers = requests.structures.CaseInsensitiveDict(
        {"Set-Cookie": "MM_SID=extracted_poison; Path=/, MM_RememberMe=stolen; Path=/"}
    )
    req = requests.Request(method="GET", url=f"{PORTAL_BASE_URL}/Dashboard/ChartData").prepare()
    jar.extract_cookies(resp, req)
    assert jar.get("MM_SID") == "original_seed"
    assert jar.get("MM_RememberMe") is None


def test_negative_proof_removing_rejecting_cookie_policy_fails() -> None:
    """NegProof: Standard RequestsCookieJar without reject policy WOULD adopt poisoned cookie."""
    standard_jar = requests.cookies.RequestsCookieJar()
    seed = requests.cookies.create_cookie(name="MM_SID", value="seed", domain=PORTAL_HOST)
    standard_jar.set_cookie(seed)

    poison = requests.cookies.create_cookie(name="MM_SID", value="poisoned", domain=PORTAL_HOST)
    # Without the RejectingCookieJar lock/policy, setting the cookie mutates the jar:
    standard_jar.set_cookie(poison)
    assert standard_jar.get("MM_SID") == "poisoned"

    # With RejectingCookieJar locked, the poisoned cookie is refused:
    rejecting_jar = RejectingCookieJar()
    rejecting_jar.set_cookie(seed)
    rejecting_jar.lock()
    rejecting_jar.set_cookie(poison)
    assert rejecting_jar.get("MM_SID") == "seed"


def test_poisoned_set_cookie_on_both_cost_responses_rejected() -> None:
    """NN2 & NegProof: Poisoned Set-Cookie on POST and GET never affects temporary jar or main jar."""
    main_session = requests.Session()
    seed = requests.cookies.create_cookie(
        name="MM_SID", value="authoritative_seed", domain=PORTAL_HOST
    )
    main_session.cookies.set_cookie(seed)

    permit = _make_dummy_permit()

    def owner_check() -> None:
        import inspect

        frame = inspect.currentframe().f_back
        while frame and "cost_session" not in frame.f_locals:
            frame = frame.f_back
        if frame and "cost_session" in frame.f_locals:
            sess = frame.f_locals["cost_session"]
            assert getattr(sess.cookies, "_locked", False) is True

    owner_mock = MagicMock(side_effect=owner_check)

    with requests_mock.Mocker() as mock:
        # POST returns poisoned cookie 1
        mock.post(
            f"{PORTAL_BASE_URL}/Dashboard/Chart",
            text="ok",
            headers={"Set-Cookie": "MM_SID=poison_from_post; Path=/"},
        )
        # GET returns poisoned cookie 2
        mock.get(
            f"{PORTAL_BASE_URL}/Dashboard/ChartData",
            json=RAW_VALID_COST_PAYLOAD,
            headers={"Set-Cookie": "MM_SID=poison_from_get; Path=/"},
        )

        status, sample, promotable = execute_cost_sampler(
            seed_cookies=main_session.cookies,
            token="test_tok",
            permit=permit,
            owner_check=owner_mock,
            authoritative_meters={"12345678"},
            meter_placeholders={},
        )

        assert status == CostEvidenceStatus.OK
        assert promotable is True

        # Assert GET request did NOT send the poison_from_post cookie
        get_req = mock.request_history[1]
        cookie_header = get_req.headers.get("Cookie", "")
        assert "poison_from_post" not in cookie_header
        assert "authoritative_seed" in cookie_header

    # Assert main jar was never mutated
    assert main_session.cookies.get("MM_SID") == "authoritative_seed"


def test_allow_redirects_false_any_30x_is_unsupported() -> None:
    """NN2: Any HTTP 30x on POST or GET is rejected immediately as UNSUPPORTED with no redirect hop."""
    main_cookies = requests.cookies.RequestsCookieJar()
    permit = _make_dummy_permit()

    with requests_mock.Mocker() as mock:
        mock.post(
            f"{PORTAL_BASE_URL}/Dashboard/Chart",
            status_code=302,
            headers={"Location": "/Home/Login"},
        )
        status, sample, promotable = execute_cost_sampler(
            seed_cookies=main_cookies,
            token="test_tok",
            permit=permit,
            owner_check=MagicMock(),
            authoritative_meters={"12345678"},
            meter_placeholders={},
        )
        assert status == CostEvidenceStatus.UNSUPPORTED
        assert promotable is False
        # Only 1 request dispatched: no redirect followed!
        assert len(mock.request_history) == 1


# ---------------------------------------------------------------------------
# Non-Negotiable 3: Two-Dispatch Sequence, 10s Deadline, 1 MiB Cap
# ---------------------------------------------------------------------------


def test_two_dispatch_sequence_post_then_get() -> None:
    """NN3: Exactly one POST /Dashboard/Chart (UsageType 3) then one GET /Dashboard/ChartData."""
    main_cookies = requests.cookies.RequestsCookieJar()
    permit = _make_dummy_permit(usage_interval=USAGE_INTERVAL_HOURLY)

    with requests_mock.Mocker() as mock:
        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=RAW_VALID_COST_PAYLOAD)

        status, sample, promotable = execute_cost_sampler(
            seed_cookies=main_cookies,
            token="token_xyz",
            permit=permit,
            owner_check=MagicMock(),
            authoritative_meters={"12345678"},
            meter_placeholders={"12345678": "1"},
        )
        assert status == CostEvidenceStatus.OK
        assert len(mock.request_history) == 2

        post_req = mock.request_history[0]
        assert post_req.method == "POST"
        parsed_body = urllib.parse.parse_qs(post_req.text)
        assert parsed_body["UsageType"] == ["3"]
        assert parsed_body["UsageInterval"] == [USAGE_INTERVAL_HOURLY]
        assert parsed_body["__RequestVerificationToken"] == ["token_xyz"]

        get_req = mock.request_history[1]
        assert get_req.method == "GET"
        assert "/Dashboard/ChartData" in get_req.url


def test_slow_trickle_deadline_bounds_completion() -> None:
    """NN3: Whole-pair 10s deadline aborts a slow trickle body without stalling."""
    from custom_components.pseg.cost_evidence import _stream_response_body

    class SlowTrickleResponse:
        def iter_content(self, chunk_size: int = 8192):
            yield b"part1"
            # Simulate monotonic time passing deadline
            time.sleep(0.05)
            yield b"part2"

    resp = SlowTrickleResponse()
    # Set deadline already expired
    deadline = time.monotonic() - 0.01
    content, err = _stream_response_body(resp, deadline)
    assert content is None
    assert err == "timeout"


def test_streamed_body_cap_enforces_1_mib_limit() -> None:
    """NN3: A response body exceeding 1 MiB is capped immediately as TRUNCATED."""
    from custom_components.pseg.cost_evidence import _stream_response_body

    class LargeBodyResponse:
        def iter_content(self, chunk_size: int = 8192):
            # Emit chunks summing over 1 MiB
            chunk = b"X" * (512 * 1024)
            yield chunk
            yield chunk
            yield chunk

    resp = LargeBodyResponse()
    deadline = time.monotonic() + 10.0
    content, err = _stream_response_body(resp, deadline, max_bytes=MAX_COST_BYTES)
    assert content is None
    assert err == "byte_cap_exceeded"


# ---------------------------------------------------------------------------
# Non-Negotiable 4 & Negative Proofs: Fixed Evidence Statuses, Failures Never Break kWh
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error_stage,status_code,body,expected_status",
    [
        ("post", 500, "Server Error", CostEvidenceStatus.MALFORMED),
        ("post", 401, "Unauthorized", CostEvidenceStatus.AUTH_REJECTED),
        ("post", 429, "Too Many Requests", CostEvidenceStatus.MALFORMED),
        ("get", 500, "Server Error", CostEvidenceStatus.MALFORMED),
        ("get", 401, "Unauthorized", CostEvidenceStatus.AUTH_REJECTED),
        (
            "get",
            200,
            "<html>Please sign in to continue with password</html>",
            CostEvidenceStatus.AUTH_REJECTED,
        ),
        ("get", 200, "not json", CostEvidenceStatus.MALFORMED),
    ],
)
def test_cost_failures_map_to_fixed_evidence_status_without_failing_kwh(
    error_stage: str,
    status_code: int,
    body: str,
    expected_status: CostEvidenceStatus,
) -> None:
    """NN4 & NegProof: Failures on POST or GET become fixed evidence status and GET is not called if POST fails."""
    main_cookies = requests.cookies.RequestsCookieJar()
    permit = _make_dummy_permit()

    with requests_mock.Mocker() as mock:
        if error_stage == "post":
            mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", status_code=status_code, text=body)
            mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=RAW_VALID_COST_PAYLOAD)
        else:
            mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
            if "not json" in body:
                mock.get(
                    f"{PORTAL_BASE_URL}/Dashboard/ChartData", status_code=status_code, text=body
                )
            else:
                mock.get(
                    f"{PORTAL_BASE_URL}/Dashboard/ChartData", status_code=status_code, text=body
                )

        status, sample, promotable = execute_cost_sampler(
            seed_cookies=main_cookies,
            token="test_tok",
            permit=permit,
            owner_check=MagicMock(),
            authoritative_meters={"12345678"},
            meter_placeholders={},
        )
        assert status == expected_status
        assert promotable is False

        if error_stage == "post":
            # If POST failed, GET was NEVER dispatched!
            assert len(mock.request_history) == 1


def test_lifecycle_owner_retirement_is_not_suppressed() -> None:
    """NN4 & NegProof: Owner retirement between POST and GET prevents GET and raises lifecycle exit."""
    main_cookies = requests.cookies.RequestsCookieJar()
    permit = _make_dummy_permit()

    post_completed = False

    def owner_check() -> None:
        if post_completed:
            # Owner retired after POST
            raise PsegTransientError("PSE&G entry owner is retired")

    with requests_mock.Mocker() as mock:
        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=RAW_VALID_COST_PAYLOAD)

        def on_post(request, context):
            nonlocal post_completed
            post_completed = True
            return "ok"

        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=on_post)

        with pytest.raises(PsegTransientError, match="retired"):
            execute_cost_sampler(
                seed_cookies=main_cookies,
                token="test_tok",
                permit=permit,
                owner_check=owner_check,
                authoritative_meters={"12345678"},
                meter_placeholders={},
            )

        # GET was NEVER dispatched after owner retired!
        assert len(mock.request_history) == 1


# ---------------------------------------------------------------------------
# Non-Negotiable 5: Durable Budget Store and Alternating Schedule
# ---------------------------------------------------------------------------


async def test_budget_store_durably_reserves_one_pair_per_ny_day(hass: HomeAssistant) -> None:
    """NN5: Store allows only 1 attempt permit per NY day and alternates daily/hourly/daily."""
    store = CostEvidenceStore(hass, "test_entry_budget")
    await store.async_load()
    await store.async_set_mode(COST_MODE_EVIDENCE)

    day1 = date(2026, 10, 25)
    permit1 = await store.async_reserve_permit(day1, "2026-10-11", "2026-10-25")
    assert permit1 is not None
    assert permit1.usage_interval == USAGE_INTERVAL_DAILY  # First is daily

    # Second attempt on same day is rejected
    permit1_repeat = await store.async_reserve_permit(day1, "2026-10-11", "2026-10-25")
    assert permit1_repeat is None

    # Next day alternates to hourly
    day2 = date(2026, 10, 26)
    permit2 = await store.async_reserve_permit(day2, "2026-10-12", "2026-10-26")
    assert permit2 is not None
    assert permit2.usage_interval == USAGE_INTERVAL_HOURLY

    # Next day repeats daily (alternating daily/hourly/daily)
    day3 = date(2026, 10, 27)
    permit3 = await store.async_reserve_permit(day3, "2026-10-13", "2026-10-27")
    assert permit3 is not None
    assert permit3.usage_interval == USAGE_INTERVAL_DAILY


async def test_budget_survives_reload_and_cold_restart(hass: HomeAssistant) -> None:
    """NN5: Reservations survive reload/restart; cold instance cannot issue another permit."""
    store1 = CostEvidenceStore(hass, "test_entry_restart")
    await store1.async_load()
    await store1.async_set_mode(COST_MODE_EVIDENCE)

    today = date(2026, 10, 25)
    permit1 = await store1.async_reserve_permit(today, "2026-10-11", "2026-10-25")
    assert permit1 is not None

    # Simulate reload / cold restart by creating a new store instance for the same entry
    store2 = CostEvidenceStore(hass, "test_entry_restart")
    await store2.async_load()
    assert store2.mode == COST_MODE_EVIDENCE

    # Attempt to reserve again on same day after restart fails
    permit_reloaded = await store2.async_reserve_permit(today, "2026-10-11", "2026-10-25")
    assert permit_reloaded is None
    assert store2.get_readiness_reason(today) == "budget_exhausted_for_today"


async def test_corrupt_budget_store_skips_sampling_without_flooding(hass: HomeAssistant) -> None:
    """NN5 & NegProof: Corrupt store fails closed and does not allow sampling."""
    store = CostEvidenceStore(hass, "test_entry_corrupt")
    # Simulate corrupt load returning non-dict
    with patch.object(store._store, "async_load", return_value="corrupt_string_not_json_dict"):
        await store.async_load()
        assert store.mode == COST_MODE_OFF
        permit = await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
        assert permit is None
        assert store.get_readiness_reason(date(2026, 10, 25)) == "corrupt_store"


# ---------------------------------------------------------------------------
# Non-Negotiable 6: Admin Service pseg.set_cost_mode
# ---------------------------------------------------------------------------


async def test_service_set_cost_mode_off_and_evidence(hass: HomeAssistant) -> None:
    """NN6: Service accepts off and evidence, updates store without resetting budget or refresh."""
    entry = MockConfigEntry(domain=DOMAIN, entry_id="entry_cost_mode", data={"cookies": []})
    entry.add_to_hass(hass)

    client = PsegClient(portal_cookies="MM_SID=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord

    from custom_components.pseg import async_setup

    assert await async_setup(hass, {}) is True
    assert hass.services.has_service(DOMAIN, "set_cost_mode")

    # Default is off
    assert coord.cost_mode == COST_MODE_OFF

    # Call service to set mode to evidence
    await hass.services.async_call(
        DOMAIN,
        "set_cost_mode",
        {"cost_mode": "evidence", "entry_id": entry.entry_id},
        blocking=True,
    )
    assert coord.cost_mode == COST_MODE_EVIDENCE

    # Call service to set mode back to off
    await hass.services.async_call(
        DOMAIN,
        "set_cost_mode",
        {"cost_mode": "off", "entry_id": entry.entry_id},
        blocking=True,
    )
    assert coord.cost_mode == COST_MODE_OFF


async def test_service_set_cost_mode_refuses_import_in_v1_7_0(hass: HomeAssistant) -> None:
    """NN6: Setting cost mode to 'import' is reserved and refused in v1.7.0."""
    entry = MockConfigEntry(domain=DOMAIN, entry_id="entry_cost_import", data={"cookies": []})
    entry.add_to_hass(hass)

    client = PsegClient(portal_cookies="MM_SID=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord

    from custom_components.pseg import async_setup

    assert await async_setup(hass, {}) is True

    with pytest.raises(ValueError, match="reserved and refused in v1.7.0"):
        await hass.services.async_call(
            DOMAIN,
            "set_cost_mode",
            {"cost_mode": "import", "entry_id": entry.entry_id},
            blocking=True,
        )


# ---------------------------------------------------------------------------
# Non-Negotiable 7: Bounded Diagnostics and Zero-Request Download
# ---------------------------------------------------------------------------


async def test_diagnostics_cost_contract_sample_bounds_and_zero_requests(
    hass: HomeAssistant,
) -> None:
    """NN7: Diagnostics exposes bounded cost_contract_sample and downloading sends ZERO requests."""
    entry = MockConfigEntry(domain=DOMAIN, entry_id="entry_diag_cost", data={"cookies": []})
    entry.add_to_hass(hass)

    client = PsegClient(portal_cookies="MM_SID=test")
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    coord.status = "connected"
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord

    # Set mock sample
    client._cost_contract_samples["daily"] = {
        "sample_version": 1,
        "captured_at": "2026-10-25T12:00:00Z",
        "status": "ok",
        "series": [{"name": "Meter #1", "data": [{"x": "1729828800000", "y": "0.0000"}]}],
    }

    # Intercept all network sends to prove downloading diagnostics makes ZERO requests
    with patch.object(client.session, "send") as mock_send:
        diag = await async_get_config_entry_diagnostics(hass, entry)
        mock_send.assert_not_called()

    assert diag["cost_mode"] == "off"
    assert diag["cost_contract_sample"] is not None
    assert "daily" in diag["cost_contract_sample"]
    assert diag["cost_contract_sample"]["daily"]["series"][0]["name"] == "Meter #1"


def test_diagnostics_quarantines_synthetic_secret_sentinels() -> None:
    """NN7: Secret sentinels in labels, unexpected keys, and extra fields never leak into sample."""
    payload_with_sentinels = {
        "password": "LEAKED_PASSWORD_SENTINEL",
        "token": "LEAKED_TOKEN_SENTINEL",
        "Data": {
            "usageType": "Dollar",
            "tooltipOptions": {"currency": "USD", "usageTypeDisplayName": "Dollar"},
            "secret_note": "LEAKED_SECRET_NOTE",
            "series": [
                {
                    "name": "Meter #12345678 - Password: LEAKED_LABEL_PASSWORD",
                    "unexpected_meta": "LEAKED_SERIES_META",
                    "data": [
                        {
                            "x": 1000,
                            "y": 5.25,
                            "leaked_point_key": "LEAKED_POINT_VALUE",
                        }
                    ],
                }
            ],
        },
    }

    permit = _make_dummy_permit()
    status, sample, promotable = validate_and_sanitize_cost_payload(
        payload=payload_with_sentinels,
        authoritative_meters={"12345678"},
        meter_placeholders={"12345678": "1"},
        permit=permit,
    )

    assert status == CostEvidenceStatus.OK
    serialized = json.dumps(sample)

    for sentinel in (
        "LEAKED_PASSWORD_SENTINEL",
        "LEAKED_TOKEN_SENTINEL",
        "LEAKED_SECRET_NOTE",
        "LEAKED_LABEL_PASSWORD",
        "LEAKED_SERIES_META",
        "LEAKED_POINT_VALUE",
        "leaked_point_key",
        "password",
        "token",
    ):
        assert sentinel not in serialized

    # Meter name is sanitized to placeholder
    assert sample["series"][0]["name"] == "Meter #1"


def test_diagnostics_oversized_payload_flags_truncated_and_non_promotable() -> None:
    """NN7: Exceeding series (>4) or points (>1500) sets TRUNCATED and non-promotable."""
    permit = _make_dummy_permit()
    oversized_series = {
        "Data": {
            "usageType": "Dollar",
            "tooltipOptions": {"currency": "USD", "usageTypeDisplayName": "Dollar"},
            "series": [
                {"name": f"Meter #1234567{i}", "data": [{"x": 1000, "y": 1.0}]}
                for i in range(5)  # 5 series > MAX_COST_SERIES (4)
            ],
        }
    }
    status, sample, promotable = validate_and_sanitize_cost_payload(
        payload=oversized_series,
        authoritative_meters={f"1234567{i}" for i in range(5)},
        meter_placeholders={},
        permit=permit,
    )
    assert status == CostEvidenceStatus.TRUNCATED
    assert promotable is False


# ---------------------------------------------------------------------------
# Non-Negotiable 8: Healthy kWh-Only Baseline Traces Stay Identical
# ---------------------------------------------------------------------------


def test_healthy_kwh_only_poll_identical_to_baseline() -> None:
    """NN8: When cost mode is off / no permit, fetch_energy_data trace is identical to baseline."""
    client = PsegClient(portal_cookies="MM_SID=test")

    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    mock_daily = {
        "Data": {
            "series": [
                {
                    "name": "Meter #12345678 (RS)",
                    "data": [
                        {
                            "x": int(
                                datetime.combine(day, datetime.min.time(), tzinfo=NY_TZ).timestamp()
                                * 1000
                            ),
                            "y": 10.0,
                            "hs": {
                                "start": day.strftime("%m/%d/%Y"),
                                "end": day.strftime("%m/%d/%Y"),
                            },
                        }
                    ],
                }
            ]
        }
    }
    mock_hourly = {
        "Data": {
            "series": [
                {
                    "name": "Meter #12345678 (RS)",
                    "data": [
                        {
                            "x": int(
                                (
                                    datetime.combine(day, datetime.min.time(), tzinfo=NY_TZ)
                                    + timedelta(hours=i)
                                ).timestamp()
                                * 1000
                            ),
                            "y": 1.0,
                        }
                        for i in range(24)
                    ],
                }
            ]
        }
    }

    with patch.object(client, "_get_verification_token", return_value="tok"):
        with patch.object(
            client, "_fetch_chart_json", side_effect=[mock_daily, mock_hourly]
        ) as mock_fetch:
            with patch("custom_components.pseg.cost_evidence.execute_cost_sampler") as mock_sampler:
                # Regular poll without cost_permit
                res = client.fetch_energy_data(days_back=14)

                assert mock_fetch.call_count == 2
                assert res.get("identity_confirmed") is True
                assert len(res.get("daily_records") or []) == 1
                # Cost sampler never touched
                mock_sampler.assert_not_called()
                assert "cost_evidence" not in res


def test_cost_session_cookies_never_copied_to_seed_cookies() -> None:
    """NN2 & NegProof: Cost session cookies are isolated and never copied back to seed jar."""
    seed_cookies = requests.cookies.RequestsCookieJar()
    seed = requests.cookies.create_cookie(
        name="MM_SID", value="authoritative_seed", domain=PORTAL_HOST
    )
    seed_cookies.set_cookie(seed)
    permit = _make_dummy_permit()

    def owner_check() -> None:
        # Simulate main session rotating or clearing its jar during cost sampling
        seed_cookies.clear()

    with patch("custom_components.pseg.cost_evidence.AllowlistedSession") as mock_session_cls:
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess
        # cost_session has cookies
        mock_sess.cookies = requests.cookies.RequestsCookieJar()
        mock_sess.cookies.set_cookie(
            requests.cookies.create_cookie(name="cost_cookie", value="val", domain=PORTAL_HOST)
        )
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b"{}"
        mock_sess.post.return_value = resp
        mock_sess.get.return_value = resp

        execute_cost_sampler(
            seed_cookies=seed_cookies,
            token="tok",
            permit=permit,
            owner_check=owner_check,
            authoritative_meters={"12345678"},
            meter_placeholders={},
        )

    # In production, seed_cookies was cleared and never updated in finally
    assert len(seed_cookies) == 0


def test_session_owner_callback_enforces_final_send_protection() -> None:
    """NN2: AllowlistedSession is initialized with owner_check, invoked during each send()."""
    seed_cookies = requests.cookies.RequestsCookieJar()
    permit = _make_dummy_permit()
    calls = []

    def owner_check() -> None:
        calls.append("check")

    post_resp = requests.Response()
    post_resp.status_code = 200
    post_resp._content = b"ok"
    get_resp = requests.Response()
    get_resp.status_code = 200
    get_resp._content = json.dumps(RAW_VALID_COST_PAYLOAD).encode()

    with patch.object(requests.Session, "send", side_effect=[post_resp, get_resp]):
        status, sample, promotable = execute_cost_sampler(
            seed_cookies=seed_cookies,
            token="tok",
            permit=permit,
            owner_check=owner_check,
            authoritative_meters={"12345678"},
            meter_placeholders={},
        )
        assert status == CostEvidenceStatus.OK

    # In production: 2 explicit owner_check calls + 2 inside AllowlistedSession.send = 4
    # With drop_session_owner_callback mutant: AllowlistedSession() has no owner_check, so only 2 calls occur
    assert len(calls) == 4


def test_watchdog_timer_is_started_and_cancelled() -> None:
    """Design 1: Watchdog timer is started at pair start and cancelled in finally."""
    seed_cookies = requests.cookies.RequestsCookieJar()
    permit = _make_dummy_permit()

    post_resp = requests.Response()
    post_resp.status_code = 200
    post_resp._content = b"ok"
    get_resp = requests.Response()
    get_resp.status_code = 200
    get_resp._content = json.dumps(RAW_VALID_COST_PAYLOAD).encode()

    with (
        patch.object(requests.Session, "send", side_effect=[post_resp, get_resp]),
        patch("custom_components.pseg.cost_evidence.threading.Timer") as mock_timer,
    ):
        mock_instance = mock_timer.return_value
        status, sample, promotable = execute_cost_sampler(
            seed_cookies=seed_cookies,
            token="tok",
            permit=permit,
            owner_check=lambda: None,
            authoritative_meters={"12345678"},
            meter_placeholders={},
        )
        assert status == CostEvidenceStatus.OK
        mock_instance.start.assert_called_once()
        mock_instance.cancel.assert_called_once()

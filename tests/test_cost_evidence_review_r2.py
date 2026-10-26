"""Independent offline R2 review probes; fake transports only."""

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
import gzip
import http.client
import io
import json
import socket
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from homeassistant.core import Context
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
import urllib3

from custom_components.pseg import async_setup, cost_evidence as ce
from custom_components.pseg.const import DOMAIN
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient
from custom_components.pseg.renewal_admission import RenewalEntryRuntime


def permit():
    p = ce.CostPermit(
        "r2",
        "review-entry",
        datetime.now(ce.NY_TZ).date().isoformat(),
        "6",
        "2026-10-11",
        "2026-10-25",
        datetime.now(UTC).isoformat(),
    )
    ce.register_issued_permit(p)
    return p


def payload(points=None):
    return {
        "Data": {
            "unit": "USD",
            "series": [
                {
                    "name": "Meter #12345678",
                    "data": points if points is not None else [{"x": 1000, "y": "1.25"}],
                }
            ],
        }
    }


class Clock:
    now = 0.0


class MemorySocket:
    """Actual SocketIO/BufferedReader/HTTPResponse stack, no OS socket."""

    def __init__(self, clock):
        self.clock = clock
        self.data = io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\n" + b"x" * 128)
        self.timeout = 5.0
        self.timeouts = []
        self.delay = 0
        self._closed = False

    def makefile(self, mode):
        return io.BufferedReader(socket.SocketIO(self, mode))

    def recv_into(self, buffer):
        if self.delay > self.timeout:
            self.clock.now += self.timeout
            raise TimeoutError()
        b = self.data.read(1)
        if b:
            self.clock.now += self.delay
            buffer[: len(b)] = b
        return len(b)

    def settimeout(self, value):
        self.timeouts.append(value)
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def _decref_socketios(self):
        pass


def real_response(clock):
    sock = MemorySocket(clock)
    http_resp = http.client.HTTPResponse(sock)
    http_resp.begin()
    sock.delay = 0.002
    resp = requests.Response()
    resp.status_code = 200
    resp.raw = urllib3.response.HTTPResponse(
        body=http_resp, preload_content=False, headers={"Content-Length": "128"}
    )
    return resp, sock


def test_real_socket_traversal_and_deadline(monkeypatch):
    clock = Clock()
    resp, sock = real_response(clock)
    assert resp.raw._fp.fp.raw._sock is sock
    monkeypatch.setattr(ce.time, "monotonic", lambda: clock.now)
    _, err = ce._stream_response_body(resp, 0.02)
    print("SOCKET", err, "elapsed", clock.now, "settimeout", sock.timeouts)
    assert sock.timeouts and clock.now <= 0.04


def test_even_correct_socket_timeout_cannot_bound_read(monkeypatch):
    clock = Clock()
    resp, sock = real_response(clock)
    monkeypatch.setattr(ce.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(ce, "_set_socket_timeout", lambda _resp, timeout: sock.settimeout(timeout))
    _, err = ce._stream_response_body(resp, 0.02)
    print("CORRECT_SOCKET", err, "elapsed", clock.now, "settimeout", sock.timeouts)
    assert clock.now <= 0.04


def test_wall_clock_deadline_on_real_buffered_stack():
    resp, sock = real_response(Clock())
    original = sock.recv_into

    def delayed(buffer):
        time.sleep(0.002)
        return original(buffer)

    sock.recv_into = delayed
    started = time.monotonic()
    _, err = ce._stream_response_body(resp, started + 0.02)
    elapsed = time.monotonic() - started
    print("WALL_CLOCK", err, "elapsed", elapsed, "settimeout", sock.timeouts)
    assert elapsed < 0.08


@pytest.mark.parametrize("method", ["post", "get"])
def test_sampler_pair_deadline_with_real_http_stack(monkeypatch, method):
    clock = Clock()
    resp, sock = real_response(clock)
    normal = requests.Response()
    normal.status_code = 200
    normal._content = b"ok"
    monkeypatch.setattr(ce.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", 0.02)
    with patch.object(ce, "AllowlistedSession") as cls:
        cls.return_value.post.return_value = resp if method == "post" else normal
        cls.return_value.get.return_value = resp
        status, _, _ = ce.execute_cost_sampler(
            requests.cookies.RequestsCookieJar(), "tok", permit(), lambda: None, {"12345678"}, {}
        )
    print("PAIR", method, str(status), clock.now, sock.timeouts)
    assert clock.now <= 0.04


def test_decoded_body_respects_memory_cap():
    resp = requests.Response()
    resp.status_code = 200
    resp._content = gzip.compress(b" " * (2 * ce.MAX_COST_BYTES))
    resp.headers["Content-Encoding"] = "gzip"
    data, err = ce._stream_response_body(resp, ce.time.monotonic() + 10)
    print("EXPANSION", len(resp._content), len(data or b""), err)
    assert data is None or len(data) <= ce.MAX_COST_BYTES


async def test_simultaneous_first_load_and_reserve(hass):
    a = ce.CostEvidenceStore(hass, "load-race")
    b = ce.CostEvidenceStore(hass, "load-race")
    entered = 0
    gate = asyncio.Event()

    async def load():
        nonlocal entered
        entered += 1
        if entered == 2:
            gate.set()
        await gate.wait()
        return {"version": 1, "mode": "evidence", "last_interval": None, "reservations": {}}

    with (
        patch.object(a._store, "async_load", side_effect=load),
        patch.object(b._store, "async_load", side_effect=load),
    ):
        await asyncio.gather(a.async_load(), b.async_load())
    # R2 stubbed async_save here; since R4 a permit requires a physically verified
    # write, so the reservations go through the real (tmp_path-routed) Store.
    issued = await asyncio.gather(
        a.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25"),
        b.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25"),
    )
    print("LOAD_RACE_PERMITS", sum(p is not None for p in issued), "same_data", a._data is b._data)
    assert sum(p is not None for p in issued) == 1


@pytest.mark.parametrize("key", ["20261025", "2026-W43-7"])
async def test_noncanonical_reservation_date_fails_closed(hass, key):
    store = ce.CostEvidenceStore(hass, "bad-date-" + key)
    data = {
        "version": 1,
        "mode": "evidence",
        "last_interval": "6",
        "reservations": {key: {"permit_id": "spent", "usage_interval": "6"}},
    }
    with patch.object(store._store, "async_load", return_value=data):
        await store.async_load()
    with patch.object(store._store, "async_save", new=AsyncMock()):
        p = await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
    print("NONCANONICAL", key, "mode", store.mode, "issued", p is not None)
    assert p is None


def attached_client():
    client = PsegClient(portal_cookies="MM_SID=synthetic")
    client.set_expected_meter_ids(["12345678"])
    runtime = RenewalEntryRuntime("review-entry")
    token = runtime.activate(lambda: True)
    client.attach_renewal_admission(runtime.admission, runtime, token)
    day = (datetime.now() - timedelta(days=1)).strftime("%m/%d/%Y")
    daily = {
        "Data": {
            "series": [
                {
                    "name": "Meter #12345678",
                    "data": [{"x": 1000, "y": 10.0, "hs": {"start": day, "end": day}}],
                }
            ]
        }
    }
    return client, daily


def fetch(client, daily, p):
    with (
        patch.object(client, "_get_verification_token", return_value="tok"),
        patch.object(
            client, "_fetch_chart_json", side_effect=[deepcopy(daily), {"Data": {"series": []}}]
        ),
    ):
        return client.fetch_energy_data(cost_permit=p)


def test_close_failure_never_logs_exception_text(caplog):
    client, daily = attached_client()
    normal = requests.Response()
    normal.status_code = 200
    normal._content = b"ok"
    with patch.object(ce, "AllowlistedSession") as cls:
        cls.return_value.post.return_value = normal
        cls.return_value.get.return_value = normal
        cls.return_value.close.side_effect = RuntimeError("SYNTHETIC_PRIVATE_MARKER")
        result = fetch(client, daily, permit())
    assert result["identity_confirmed"] is True
    assert "SYNTHETIC_PRIVATE_MARKER" not in caplog.text


def test_json_numeric_precision_is_preserved():
    raw = b'{"Data":{"unit":"USD","series":[{"name":"Meter #12345678","data":[{"x":1000,"y":0.12345678901234567890123456789}]}]}}'
    post = requests.Response()
    post.status_code = 200
    post._content = b"ok"
    get = requests.Response()
    get.status_code = 200
    get._content = raw
    with patch.object(ce, "AllowlistedSession") as cls:
        cls.return_value.post.return_value = post
        cls.return_value.get.return_value = get
        status, sample, _ = ce.execute_cost_sampler(
            requests.cookies.RequestsCookieJar(), "tok", permit(), lambda: None, {"12345678"}, {}
        )
    actual = sample["series"][0]["data"][0]["y"]
    print("PRECISION", actual, status)
    assert actual == "0.12345678901234567890123456789"


def test_aggregate_point_cap_across_slots():
    _, sample, _ = ce.validate_and_sanitize_cost_payload(
        payload([{"x": i, "y": "0"} for i in range(1500)]), {"12345678"}, {}, permit()
    )
    client = PsegClient()
    client._cost_contract_samples = {"daily": sample, "hourly": deepcopy(sample)}
    output = client.cost_contract_sample
    total = sum(len(s["data"]) for slot in output.values() for s in slot.get("series", []))
    print("AGGREGATE_POINTS", total, "bytes", len(json.dumps(output)))
    assert total <= 1500


async def test_actual_cold_store_persists_mode_and_budget(hass):
    store = ce.CostEvidenceStore(hass, "real-cold")
    await store.async_load()
    await store.async_set_mode("evidence")
    await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
    # The production test never clears shared memory; this forces an actual Store read.
    hass.data.pop(ce._SHARED_STORE_DATA_KEY)
    cold = ce.CostEvidenceStore(hass, "real-cold")
    await cold.async_load()
    assert cold.mode == "evidence"
    assert await cold.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25") is None


async def test_swallowed_store_write_failure_cannot_issue_permit(hass):
    from homeassistant.util.file import WriteError

    store = ce.CostEvidenceStore(hass, "write-failure")
    await store.async_load()
    await store.async_set_mode("evidence")
    with patch.object(
        store._store, "_async_write_data", side_effect=WriteError("synthetic disk failure")
    ):
        first = await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
    hass.data.pop(ce._SHARED_STORE_DATA_KEY)
    cold = ce.CostEvidenceStore(hass, "write-failure")
    await cold.async_load()
    second = await cold.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
    print("WRITE_FAILURE_PERMITS", first is not None, second is not None)
    assert first is None


def test_timezone_offset_evidence_is_preserved():
    points = [
        {
            "x": 1,
            "y": 1,
            "hs": {"start": "2026-11-01T01:00:00-04:00", "end": "2026-11-01T01:00:00-05:00"},
        }
    ]
    _, sample, _ = ce.validate_and_sanitize_cost_payload(
        payload(points), {"12345678"}, {}, permit()
    )
    hs = sample["series"][0]["data"][0]["hs"]
    print("TIMEZONE_EVIDENCE", hs)
    assert hs["start"] != hs["end"]


def test_direct_decimal_text_precision():
    _, sample, _ = ce.validate_and_sanitize_cost_payload(
        payload([{"x": 1, "y": "0.123456789"}]), {"12345678"}, {}, permit()
    )
    assert sample["series"][0]["data"][0]["y"] == "0.123456789"


async def test_invalid_store_version_and_date_are_rejected(hass):
    for suffix, data in [
        ("version", {"version": 99, "mode": "evidence", "last_interval": None, "reservations": {}}),
        (
            "date",
            {
                "version": 1,
                "mode": "evidence",
                "last_interval": None,
                "reservations": {"invalid": {"permit_id": "spent", "usage_interval": "6"}},
            },
        ),
    ]:
        store = ce.CostEvidenceStore(hass, "bad-schema-" + suffix)
        with patch.object(store._store, "async_load", return_value=data):
            await store.async_load()
        assert store.mode == "off"
        assert (
            await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25") is None
        )


def test_valid_large_slots_obey_total_byte_cap():
    _, sample, _ = ce.validate_and_sanitize_cost_payload(
        payload(
            [
                {
                    "x": i,
                    "y": "1.25",
                    "hs": {"start": "2026-10-25 00:00:00", "end": "2026-10-25 01:00:00"},
                }
                for i in range(1500)
            ]
        ),
        {"12345678"},
        {},
        permit(),
    )
    client = PsegClient()
    client._cost_contract_samples = {"daily": sample, "hourly": deepcopy(sample)}
    assert len(json.dumps(client.cost_contract_sample).encode()) <= ce.MAX_SERIALIZED_SAMPLE_BYTES


def test_accessible_raw_timeout_callback_is_used():
    class Raw:
        def __init__(self):
            self.parts = iter([b"ok", b""])
            self.timeouts = []

        def read(self, *args, **kwargs):
            return next(self.parts)

        def settimeout(self, value):
            self.timeouts.append(value)

    raw = Raw()
    data, err = ce._stream_response_body(SimpleNamespace(raw=raw, headers={}), time.monotonic() + 1)
    assert data == b"ok" and err is None
    assert len(raw.timeouts) == 2
    assert all(0 < t <= 0.5 for t in raw.timeouts)


async def test_no_user_context_uses_home_assistant_admin_convention(hass):
    entry = MockConfigEntry(domain=DOMAIN, entry_id="no-user", data={})
    entry.add_to_hass(hass)
    coord = PsegDataUpdateCoordinator(hass, PsegClient(), {}, config_entry=entry)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord
    await async_setup(hass, {})
    await hass.services.async_call(
        DOMAIN,
        "set_cost_mode",
        {"cost_mode": "evidence", "entry_id": entry.entry_id},
        blocking=True,
        context=Context(),
    )
    assert coord.cost_mode == "evidence"


def test_permit_not_reusable_after_failed_cost_attempt():
    client, daily = attached_client()
    p = permit()
    with patch.object(
        ce,
        "execute_cost_sampler",
        return_value=(ce.CostEvidenceStatus.MALFORMED, {"status": "malformed"}, False),
    ) as sampler:
        fetch(client, daily, p)
        fetch(client, daily, p)
    assert sampler.call_count == 1


@pytest.mark.parametrize(
    "field,value", [("entry_id", "foreign"), ("ny_date", "2026-10-24"), ("usage_interval", "2")]
)
def test_foreign_stale_and_invalid_interval_permits_denied(field, value):
    client, daily = attached_client()
    with patch.object(ce, "execute_cost_sampler") as sampler:
        fetch(client, daily, replace(permit(), **{field: value}))
    sampler.assert_not_called()


def test_unvalidated_permit_range_denied():
    client, daily = attached_client()
    with patch.object(
        ce, "execute_cost_sampler", return_value=(ce.CostEvidenceStatus.MISSING, {}, False)
    ) as sampler:
        fetch(
            client,
            daily,
            replace(permit(), start_str="SYNTHETIC_PRIVATE_MARKER", end_str="1900-01-01"),
        )
    sampler.assert_not_called()


@pytest.mark.parametrize(
    "failure", ["ok", "401", "redirect", "timeout", "malformed", "read_error", "sanitizer"]
)
def test_full_client_cost_transport_keeps_authoritative_state(monkeypatch, failure):
    client, daily = attached_client()
    original_sampler = ce.execute_cost_sampler
    captured = {}
    records = []

    def measured_sampler(*args, **kwargs):
        captured["state"] = client._snapshot_session_state()
        captured["budget"] = deepcopy(client._renewal_runtime.admission_dict())
        captured["checkpoint"] = deepcopy(client._confirmed_cookies)
        captured["meters"] = deepcopy(client._expected_meter_ids)
        return original_sampler(*args, **kwargs)

    def send(adapter, request, **kwargs):
        records.append((request.method, request.headers.get("Cookie", "")))
        if failure == "timeout":
            raise requests.Timeout("synthetic timeout")
        status = 200
        body = b"ok" if request.method == "POST" else json.dumps(payload()).encode()
        if request.method == "GET":
            if failure == "401":
                status = 401
            elif failure == "redirect":
                status = 302
            elif failure == "malformed":
                body = b"invalid json"
        msg = http.client.HTTPMessage()
        msg.add_header("Set-Cookie", "MM_SID=cost_poison; Path=/")
        msg.add_header("Set-Cookie", "MM_RememberMe=cost_poison_remember; Path=/")
        raw = urllib3.response.HTTPResponse(
            body=io.BytesIO(body),
            status=status,
            preload_content=False,
            headers={"Set-Cookie": "MM_SID=cost_poison; Path=/"},
            original_response=SimpleNamespace(msg=msg, isclosed=lambda: True, close=lambda: None),
        )
        resp = adapter.build_response(request, raw)
        if failure == "read_error" and request.method == "POST":
            raw.read = lambda *a, **k: (_ for _ in ()).throw(
                requests.ConnectionError("synthetic read failure")
            )
        return resp

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    monkeypatch.setattr(ce, "execute_cost_sampler", measured_sampler)
    if failure == "sanitizer":
        monkeypatch.setattr(
            ce,
            "validate_and_sanitize_cost_payload",
            lambda **kwargs: (_ for _ in ()).throw(ValueError("synthetic sanitizer error")),
        )
    result = fetch(client, daily, permit())
    expected = {
        "ok": "ok",
        "401": "auth_rejected",
        "redirect": "unsupported",
        "timeout": "malformed",
        "malformed": "malformed",
        "read_error": "malformed",
        "sanitizer": "malformed",
    }
    assert result["cost_evidence"]["status"] == expected[failure]
    assert len(records) == (1 if failure in ("timeout", "read_error") else 2)
    assert result["identity_confirmed"] is True
    assert client._snapshot_session_state() == captured["state"]
    assert client._renewal_runtime.admission_dict() == captured["budget"]
    assert client._confirmed_cookies == captured["checkpoint"]
    assert client._expected_meter_ids == captured["meters"]
    assert not any("cost_poison" in cookie for _, cookie in records)
    print(
        "AUTH_MATRIX", failure, "status", result["cost_evidence"]["status"], "sends", len(records)
    )

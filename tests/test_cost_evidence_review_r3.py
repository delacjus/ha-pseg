"""Review R3 probes and verification tests for RC-02 v1.7.0 fixes."""

from dataclasses import replace
from datetime import date, datetime
import http.client
import io
import json
import socket
import threading
import time
import tracemalloc
from unittest.mock import patch

import pytest
import requests
import urllib3

from custom_components.pseg import cost_evidence as ce

from .test_cost_evidence_review_r2 import attached_client, fetch, payload, permit


class HeaderSocket:
    """Emulate a peer trickling HTTP headers below the socket idle timeout."""

    def __init__(self, delay=0.002, size=0):
        self.data = io.BytesIO(
            b"HTTP/1.1 200 OK\r\nContent-Length: " + str(size).encode() + b"\r\n\r\n" + b"x" * size
        )
        self.delay = delay
        self.timeout = 5.0
        self._closed = False
        self.closed_calls = 0
        self.sent = []

    def makefile(self, mode, *args, **kwargs):
        return io.BufferedReader(socket.SocketIO(self, mode))

    def recv_into(self, buffer):
        if self.delay:
            time.sleep(min(self.delay, self.timeout))
        if self.delay > self.timeout:
            raise TimeoutError()
        data = self.data.read(1 if self.delay or getattr(self, "one_byte", False) else len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def _decref_socketios(self):
        pass

    def shutdown(self, how):
        self.closed_calls += 1
        self._closed = True

    def close(self):
        self.closed_calls += 1
        self._closed = True


# ---------------------------------------------------------------------------
# Failing probes copied from /tmp/rc02-r3-review.bbUAbp/snapshot/tests/test_review_r3.py
# ---------------------------------------------------------------------------


def test_header_watchdog_deadline(monkeypatch):
    # Keep the real Session, HTTPAdapter, urllib3 pool and HTTP header parser.
    from .conftest import _ORIG_HTTPADAPTER_SEND

    sock = HeaderSocket()

    def connect(conn):
        conn.sock = sock
        conn.is_verified = True
        conn.proxy_is_verified = True
        if hasattr(conn, "pair_context") and conn.pair_context is not None:
            conn.pair_context.record_socket(sock)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _ORIG_HTTPADAPTER_SEND)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection, "connect", connect)
    monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", 0.020)
    monkeypatch.setenv("NO_PROXY", "*")
    start = time.monotonic()
    result = ce.execute_cost_sampler(
        requests.cookies.RequestsCookieJar(),
        "synthetic",
        permit(),
        lambda: None,
        {"12345678"},
        {},
    )
    elapsed = time.monotonic() - start
    print("HEADER_WATCHDOG", elapsed, result[0], result[1], "socket_close_calls", sock.closed_calls)
    assert elapsed < 0.055
    assert result[0] == ce.CostEvidenceStatus.MALFORMED
    assert result[1].get("reason") == ce.REASON_DEADLINE_EXCEEDED


def test_chunk_header_close_race(monkeypatch):
    sock = HeaderSocket(delay=0)
    sock.one_byte = True
    sock.data = io.BytesIO(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + b"0" * 40
        + b"1\r\nx\r\n0\r\n\r\n"
    )
    h = http.client.HTTPResponse(sock)
    h.begin()
    sock.delay = 0.002
    resp = requests.Response()
    resp.status_code = 200
    resp.raw = urllib3.response.HTTPResponse(
        body=h, preload_content=False, headers={"Transfer-Encoding": "chunked"}
    )
    monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", 0.020)
    start = time.monotonic()
    with patch.object(ce, "AllowlistedSession") as cls:
        cls.return_value.post.return_value = resp
        result = ce.execute_cost_sampler(
            requests.cookies.RequestsCookieJar(),
            "synthetic",
            permit(),
            lambda: None,
            {"12345678"},
            {},
        )
    elapsed = time.monotonic() - start
    print("CHUNK_HEADER_CLOSE_RACE", elapsed, result[0], result[1])
    assert elapsed < 0.055
    assert result[0] == ce.CostEvidenceStatus.MALFORMED
    assert result[1].get("reason") == ce.REASON_DEADLINE_EXCEEDED


def test_forged_and_retargeted_permits_denied():
    client, daily = attached_client()
    original = permit()
    # In R3 dataclasses.replace auto-registered the forged ID through __post_init__;
    # R4 registers permits only in the store's reserve path, so the forgery is not
    # issued and must never reach the sampler.
    forged = replace(original, permit_id="never-durably-reserved-r3", start_str="2026-10-01")
    assert not ce.is_issued_permit(forged.permit_id)
    with patch.object(
        ce, "execute_cost_sampler", return_value=(ce.CostEvidenceStatus.MISSING, {}, False)
    ) as sampler:
        result = fetch(client, daily, forged)
    print("FORGED_PERMIT", sampler.call_count, result.get("cost_evidence"))
    sampler.assert_not_called()


async def test_shutdown_missing_file_readback_is_not_durable(hass):
    from pathlib import Path

    from homeassistant.core import CoreState

    store = ce.CostEvidenceStore(hass, "r3-stopping-no-file")
    await store.async_load()
    path = Path(store._store.path)
    assert not path.exists()
    old_state = hass.state
    try:
        hass.set_state(CoreState.stopping)
        await store.async_set_mode("evidence")
        result = await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
        print("SHUTDOWN_READBACK", "permit", result is not None, "file_exists", path.exists())
        assert result is None
    finally:
        hass.set_state(old_state)


async def test_mode_rollback_matches_disk_after_readback_error(hass, tmp_path):
    from pathlib import Path

    store = ce.CostEvidenceStore(hass, "r3-mode-readback-error")
    store._store.__dict__["path"] = str(tmp_path / "cost-store.json")

    async def physical_write(data):
        await hass.async_add_executor_job(store._store._write_data, data)

    store._store._async_write_data = physical_write
    await store.async_load()
    await store.async_set_mode("off")
    assert Path(store._store.path).exists()
    with patch.object(ce.json, "load", side_effect=OSError("synthetic readback failure")):
        with pytest.raises(OSError):
            await store.async_set_mode("evidence")
    memory_mode = store.mode
    disk_mode = json.loads(Path(store._store.path).read_text())["data"]["mode"]
    print("MODE_ROLLBACK", "memory", memory_mode, "disk", disk_mode)
    assert memory_mode == disk_mode


def test_truncated_gzip_not_accepted():
    import gzip

    raw = json.dumps(payload()).encode()
    resp = requests.Response()
    resp.status_code = 200
    resp.headers["Content-Encoding"] = "gzip"
    resp._content = gzip.compress(raw)[:-8]
    data, err = ce._stream_response_body(resp, time.monotonic() + 10)
    print("TRUNCATED_GZIP", "err", err, "complete_json", data == raw)
    assert err is not None
    assert err == "truncated_body"


# ---------------------------------------------------------------------------
# Additional reviewer baseline probes
# ---------------------------------------------------------------------------


def test_tiny_decimal_expansion_is_bounded():
    tracemalloc.start()
    start = time.monotonic()
    result = ce.validate_and_sanitize_cost_payload(
        payload([{"x": 1000, "y": "1e-2000000"}]), {"12345678"}, {}, permit()
    )
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(
        "TINY_DECIMAL",
        "peak_bytes",
        peak,
        "seconds",
        time.monotonic() - start,
        "status",
        result[0],
    )
    assert peak < 4 * 1024 * 1024


def test_one_mib_read_cpu_cost():
    sock = HeaderSocket(delay=0, size=ce.MAX_COST_BYTES)
    h = http.client.HTTPResponse(sock)
    h.begin()
    resp = requests.Response()
    resp.status_code = 200
    resp.raw = urllib3.response.HTTPResponse(
        body=h,
        preload_content=False,
        headers={"Content-Length": str(ce.MAX_COST_BYTES)},
    )
    start = time.monotonic()
    cpu = time.process_time()
    body, err = ce._stream_response_body(resp, start + 10)
    print(
        "ONE_MIB",
        "wall",
        time.monotonic() - start,
        "cpu",
        time.process_time() - cpu,
        "len",
        len(body or b""),
        "err",
        err,
    )
    assert err is None and len(body) == ce.MAX_COST_BYTES


def test_normal_timer_cleanup():
    before = {id(t) for t in threading.enumerate()}
    for _ in range(20):
        post = requests.Response()
        post.status_code = 200
        post._content = b"ok"
        get = requests.Response()
        get.status_code = 200
        get._content = json.dumps(payload()).encode()
        with patch.object(ce, "AllowlistedSession") as cls:
            cls.return_value.post.return_value = post
            cls.return_value.get.return_value = get
            status, _, _ = ce.execute_cost_sampler(
                requests.cookies.RequestsCookieJar(),
                "synthetic",
                permit(),
                lambda: None,
                {"12345678"},
                {},
            )
        assert status == ce.CostEvidenceStatus.OK
    extra = [
        t for t in threading.enumerate() if id(t) not in before and isinstance(t, threading.Timer)
    ]
    print("NORMAL_TIMER_CLEANUP", "extra_timers", len(extra))
    assert not extra


async def test_cross_entry_store_isolation(hass):
    a = ce.CostEvidenceStore(hass, "r3-isolation-a")
    b = ce.CostEvidenceStore(hass, "r3-isolation-b")
    await a.async_load()
    await b.async_load()
    await a.async_set_mode("evidence")
    assert b.mode == "off"
    await b.async_set_mode("evidence")
    first = await a.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
    second = await b.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
    assert first is not None and second is not None
    assert first.permit_id != second.permit_id
    assert a._data is not b._data
    print("CROSS_ENTRY_ISOLATION", first.entry_id, second.entry_id)


# ---------------------------------------------------------------------------
# Required R4 Designs: Stalled TLS, Stalled Body, Provenance, HA Stop
# ---------------------------------------------------------------------------


def test_stalled_tls_handshake_socketpair(monkeypatch):
    """Prove stalled TLS handshake returns within deadline + 250ms with deadline_exceeded."""
    from .conftest import _ORIG_HTTPADAPTER_SEND

    client_sock, server_sock = socket.socketpair()
    try:

        def connect(conn):
            conn.sock = client_sock
            if hasattr(conn, "pair_context") and conn.pair_context is not None:
                conn.pair_context.record_socket(client_sock)
            # Stalled TLS handshake: blocks in recv on client_sock until watchdog shutdown/close
            client_sock.recv(4096)

        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _ORIG_HTTPADAPTER_SEND)
        monkeypatch.setattr(urllib3.connection.HTTPSConnection, "connect", connect)
        deadline_sec = 0.050
        monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", deadline_sec)
        monkeypatch.setenv("NO_PROXY", "*")

        start = time.monotonic()
        result = ce.execute_cost_sampler(
            requests.cookies.RequestsCookieJar(),
            "tok",
            permit(),
            lambda: None,
            {"12345678"},
            {},
        )
        elapsed = time.monotonic() - start
        print("STALLED_TLS_TIMING", "deadline", deadline_sec, "actual", elapsed)
        assert elapsed < deadline_sec + 0.250
        assert result[0] == ce.CostEvidenceStatus.MALFORMED
        assert result[1].get("reason") == ce.REASON_DEADLINE_EXCEEDED
        assert result[2] is False
    finally:
        client_sock.close()
        server_sock.close()


def test_stalled_body_socketpair(monkeypatch):
    """Prove stalled body read returns within deadline + 250ms with no GET dispatched."""
    from .conftest import _ORIG_HTTPADAPTER_SEND

    client_sock, server_sock = socket.socketpair()
    server_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nPartial")

    try:

        def connect(conn):
            conn.sock = client_sock
            conn.is_verified = True
            conn.proxy_is_verified = True
            if hasattr(conn, "pair_context") and conn.pair_context is not None:
                conn.pair_context.record_socket(client_sock)

        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _ORIG_HTTPADAPTER_SEND)
        monkeypatch.setattr(urllib3.connection.HTTPSConnection, "connect", connect)
        deadline_sec = 0.050
        monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", deadline_sec)
        monkeypatch.setenv("NO_PROXY", "*")

        start = time.monotonic()
        result = ce.execute_cost_sampler(
            requests.cookies.RequestsCookieJar(),
            "tok",
            permit(),
            lambda: None,
            {"12345678"},
            {},
        )
        elapsed = time.monotonic() - start
        print("STALLED_BODY_TIMING", "deadline", deadline_sec, "actual", elapsed)
        assert elapsed < deadline_sec + 0.250
        assert result[0] == ce.CostEvidenceStatus.MALFORMED
        assert result[1].get("reason") == ce.REASON_DEADLINE_EXCEEDED
        assert result[2] is False
    finally:
        client_sock.close()
        server_sock.close()


def test_provenance_constructed_unreserved_permit_refused():
    """Test: a constructed but never-reserved permit is refused."""
    client, daily = attached_client()
    unreserved = ce.CostPermit(
        permit_id="unreserved-construct-1",
        entry_id="entry-1",
        ny_date=datetime.now(ce.NY_TZ).date().isoformat(),
        usage_interval="15-min",
        start_str="2026-10-11",
        end_str="2026-10-25",
        created_at=datetime.now(ce.UTC).isoformat(),
        generation=1,
    )
    assert not ce.is_issued_permit(unreserved.permit_id)
    with patch.object(
        ce, "execute_cost_sampler", return_value=(ce.CostEvidenceStatus.OK, {}, True)
    ) as sampler:
        result = fetch(client, daily, unreserved)
    sampler.assert_not_called()
    assert result.get("cost_evidence") is None


def test_provenance_altered_range_permit_refused():
    """Test: a reserved permit with an altered range is refused."""
    client, daily = attached_client()
    p = permit()
    altered = replace(p, start_str="2026-10-01")
    with patch.object(
        ce, "execute_cost_sampler", return_value=(ce.CostEvidenceStatus.OK, {}, True)
    ) as sampler:
        result = fetch(client, daily, altered)
    sampler.assert_not_called()
    assert result.get("cost_evidence") is None


def test_provenance_permit_is_single_use():
    """Test: a reserved permit is consumed on first use and refused on second use."""
    client, daily = attached_client()
    p = permit()
    with patch.object(
        ce, "execute_cost_sampler", return_value=(ce.CostEvidenceStatus.OK, {"status": "ok"}, True)
    ) as sampler:
        res1 = fetch(client, daily, p)
        assert sampler.call_count == 1
        assert res1.get("cost_evidence") is not None
        # Second fetch with same permit must be refused
        res2 = fetch(client, daily, p)
        assert sampler.call_count == 1
        assert res2.get("cost_evidence") is None


def test_ha_stop_cancels_and_fires_active_watchdogs():
    """Test: EVENT_HOMEASSISTANT_STOP cancels and fires active watchdogs."""
    fired = []

    def on_fire():
        fired.append(True)

    unreg = ce.register_active_watchdog(on_fire)
    assert on_fire in ce._ACTIVE_WATCHDOGS
    try:
        ce.fire_all_active_watchdogs()
        assert fired == [True]
        assert on_fire not in ce._ACTIVE_WATCHDOGS
    finally:
        unreg()

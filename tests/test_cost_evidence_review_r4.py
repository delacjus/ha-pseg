"""Review R4 probes for RC-02: proxies, real TLS handshakes, save exceptions.

The first block is the reviewer's failing R4 probe set copied unchanged in logic
(/tmp/rc02-r4-review.47noP6/snapshot/tests/test_review_r4_scratch.py) so the
same scenarios stay pinned as regressions. The second block adds the stricter
checks requested by the review: a real ssl handshake through the actual cost
adapter, proxy-environment isolation, and cancellation-time reconciliation.
"""

import asyncio
from datetime import date
import json
from pathlib import Path
import socket
import ssl
import threading
import time
from unittest.mock import patch

import pytest
import requests
import urllib3

from custom_components.pseg import cost_evidence as ce

from .conftest import _ORIG_HTTPADAPTER_SEND
from .test_cost_evidence_review_r2 import permit
from .test_cost_evidence_review_r3 import HeaderSocket

# ---------------------------------------------------------------------------
# Reviewer R4 probes, unchanged in logic
# ---------------------------------------------------------------------------


def test_proxy_header_deadline(monkeypatch):
    sock = HeaderSocket()
    seen = []

    def connect(conn):
        seen.append((type(conn).__name__, getattr(conn, "pair_context", None)))
        conn.sock = sock
        conn.is_verified = conn.proxy_is_verified = True

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _ORIG_HTTPADAPTER_SEND)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection, "connect", connect)
    monkeypatch.setenv("HTTPS_PROXY", "http://synthetic.invalid:3128")
    monkeypatch.setenv("https_proxy", "http://synthetic.invalid:3128")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", 0.020)
    start = time.monotonic()
    result = ce.execute_cost_sampler(
        requests.cookies.RequestsCookieJar(), "synthetic", permit(), lambda: None, {"12345678"}, {}
    )
    elapsed = time.monotonic() - start
    print("PROXY_HEADERS", elapsed, seen, result)
    assert elapsed < 0.055
    assert result[0] == ce.CostEvidenceStatus.MALFORMED
    assert result[1].get("reason") == ce.REASON_DEADLINE_EXCEEDED
    assert seen
    assert all(ctx is not None for _, ctx in seen)


async def test_mode_save_raises_reconciles(hass):
    store = ce.CostEvidenceStore(hass, "r4-write-raise")
    await store.async_set_mode("off")
    path = Path(store._store.path)
    assert path.exists()
    with patch.object(store._store, "async_save", side_effect=OSError("synthetic disk failure")):
        with pytest.raises(OSError):
            await store.async_set_mode("evidence")
    disk = json.loads(path.read_text())["data"]
    print("SAVE_EXCEPTION", store._data, disk)
    assert store._data == disk
    assert store.mode == ce.COST_MODE_OFF


async def test_reserve_save_raises_reconciles(hass):
    store = ce.CostEvidenceStore(hass, "r4-reserve-raise")
    await store.async_set_mode("evidence")
    path = Path(store._store.path)
    with patch.object(store._store, "async_save", side_effect=OSError("synthetic disk failure")):
        with pytest.raises(OSError):
            await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
    disk = json.loads(path.read_text())["data"]
    print("RESERVE_EXCEPTION", store._data, disk)
    assert store._data == disk
    assert store._data["reservations"] == {}


def test_real_tls_socket_capture():
    a, b = socket.socketpair()
    ctx = ce.PairContext(time.monotonic() + 1)
    ctx.record_socket(a)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls = context.wrap_socket(a, server_hostname="synthetic.invalid", do_handshake_on_connect=False)
    tls.settimeout(0.2)
    errors = []

    def handshake():
        try:
            tls.do_handshake()
        except Exception as e:  # noqa: BLE001 - probe records the wake reason
            errors.append(type(e).__name__)

    t = threading.Thread(target=handshake)
    start = time.monotonic()
    t.start()
    b.recv(4096)  # confirms ClientHello: wrap has detached a's fd
    ctx.close_all()
    t.join(0.04)
    interrupted = not t.is_alive()
    print(
        "REAL_TLS_CAPTURE",
        "raw_fd",
        a.fileno(),
        "tls_fd",
        tls.fileno(),
        "interrupted",
        interrupted,
        "errors",
        errors,
        "elapsed",
        time.monotonic() - start,
    )
    b.close()
    t.join(0.5)
    tls.close()
    a.close()
    ctx.release()
    assert interrupted
    assert errors


async def test_physical_store_readback(hass):
    store = ce.CostEvidenceStore(hass, "r4-physical-proof")
    await store.async_set_mode("evidence")
    path = Path(store._store.path)
    p = await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25")
    assert p is not None and path.is_file()
    assert json.loads(path.read_bytes())["data"] == store._data
    # Deleting the physical file cannot be satisfied by cached pending Store data.
    path.unlink()
    assert not await store._async_verify_persisted(store._data)
    print("PHYSICAL_READBACK", "physical before delete, failed closed afterward")


def test_proxy_tls_settings():
    ctx = ce.PairContext(time.monotonic() + 1)
    adapter = ce.CostHTTPAdapter(ctx)
    pool = adapter.poolmanager.connection_from_url("https://synthetic.invalid")
    adapter.cert_verify(pool, "https://synthetic.invalid", True, None)
    proxy = adapter.proxy_manager_for("http://synthetic.invalid:3128")
    print(
        "ADAPTER_TLS",
        "cert_reqs",
        pool.cert_reqs,
        "assert_hostname",
        pool.assert_hostname,
        "direct",
        pool.ConnectionCls,
        "proxy",
        proxy.pool_classes_by_scheme["https"].ConnectionCls,
    )
    assert pool.cert_reqs == "CERT_REQUIRED"
    assert pool.assert_hostname is not False
    assert issubclass(pool.ConnectionCls, ce.CostHTTPSConnection)
    assert issubclass(proxy.pool_classes_by_scheme["https"].ConnectionCls, ce.CostHTTPSConnection)


@pytest.mark.timeout(10)
def test_real_tls_handshake_pair_deadline(monkeypatch):
    a, b = socket.socketpair()

    def new_conn(conn):
        time.sleep(0.040)  # TCP establishment consumes 40/50ms; no real network
        a.settimeout(conn.timeout)
        return a

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _ORIG_HTTPADAPTER_SEND)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection, "_new_conn", new_conn)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", 0.050)
    try:
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
        print("REAL_TLS_PAIR", elapsed, result)
        assert elapsed < 0.095
        assert result[0] == ce.CostEvidenceStatus.MALFORMED
        assert result[1].get("reason") == ce.REASON_DEADLINE_EXCEEDED
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# Added R5 checks
# ---------------------------------------------------------------------------


def test_proxy_environment_ignored(monkeypatch):
    """HTTPS_PROXY/HTTP_PROXY env vars are ignored and every connection is tracked."""
    sock = HeaderSocket()
    captured = {}
    connects = []
    proxy_calls = []
    real_session_cls = ce.AllowlistedSession

    def session_factory(owner_check=None):
        session = real_session_cls(owner_check=owner_check)
        captured["session"] = session
        return session

    def connect(conn):
        connects.append((conn, type(conn).__name__, getattr(conn, "pair_context", None)))
        conn.sock = sock
        conn.is_verified = conn.proxy_is_verified = True

    def proxy_manager_for(self, proxy, **kwargs):
        proxy_calls.append(proxy)
        raise AssertionError("cost sampler must never build a proxy manager")

    monkeypatch.setattr(ce, "AllowlistedSession", session_factory)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _ORIG_HTTPADAPTER_SEND)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection, "connect", connect)
    monkeypatch.setattr(ce.CostHTTPAdapter, "proxy_manager_for", proxy_manager_for)
    monkeypatch.setenv("HTTPS_PROXY", "http://synthetic.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://synthetic.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://synthetic.invalid:3128")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", 0.020)
    start = time.monotonic()
    result = ce.execute_cost_sampler(
        requests.cookies.RequestsCookieJar(), "synthetic", permit(), lambda: None, {"12345678"}, {}
    )
    elapsed = time.monotonic() - start
    session = captured["session"]
    print(
        "PROXY_ENV",
        elapsed,
        "trust_env",
        session.trust_env,
        "proxies",
        session.proxies,
        "proxy_calls",
        proxy_calls,
        "connects",
        [name for _, name, _ in connects],
        result,
    )
    assert session.trust_env is False
    assert session.proxies == {}
    assert proxy_calls == []
    assert connects
    assert all(ctx is not None for _, _, ctx in connects)
    assert all(isinstance(conn, ce.CostHTTPSConnection) for conn, _, _ in connects)
    assert elapsed < 0.055
    assert result[1].get("reason") == ce.REASON_DEADLINE_EXCEEDED


@pytest.mark.timeout(10)
def test_real_tls_handshake_through_adapter(monkeypatch):
    """Real ssl over a socketpair: the deadline must abort the live handshake.

    The peer end dribbles a plausible TLS record header plus body one byte at a
    time, faster than the bounded socket timeout, so only the duplicated
    descriptor's shutdown can end the handshake before the pair deadline.
    """
    a, b = socket.socketpair()
    stop = threading.Event()

    def new_conn(conn):
        return a

    def dribble():
        try:
            b.sendall(b"\x16\x03\x03\x07\xd0")  # handshake record, 2000-byte body
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and not stop.is_set():
                b.sendall(b"\x00")
                time.sleep(0.020)
        except OSError:
            pass

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _ORIG_HTTPADAPTER_SEND)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection, "_new_conn", new_conn)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setattr(ce, "COST_PAIR_DEADLINE_SECONDS", 0.050)
    server = threading.Thread(target=dribble, daemon=True)
    start = time.monotonic()
    server.start()
    try:
        result = ce.execute_cost_sampler(
            requests.cookies.RequestsCookieJar(),
            "synthetic",
            permit(),
            lambda: None,
            {"12345678"},
            {},
        )
        elapsed = time.monotonic() - start
        print("REAL_TLS_ADAPTER", elapsed, result)
        assert elapsed < 0.120
        assert result[0] == ce.CostEvidenceStatus.MALFORMED
        assert result[1].get("reason") == ce.REASON_DEADLINE_EXCEEDED
    finally:
        stop.set()
        server.join(0.5)
        a.close()
        b.close()


async def test_mode_save_cancellation_reconciles(hass):
    store = ce.CostEvidenceStore(hass, "r4-write-cancel")
    await store.async_set_mode("off")
    path = Path(store._store.path)
    with patch.object(store._store, "async_save", side_effect=asyncio.CancelledError):
        with pytest.raises(asyncio.CancelledError):
            await store.async_set_mode("evidence")
    disk = json.loads(path.read_text())["data"]
    print("SAVE_CANCELLED", store._data, disk)
    assert store._data == disk
    assert store.mode == ce.COST_MODE_OFF


async def test_save_failure_without_readable_disk_fails_closed(hass):
    store = ce.CostEvidenceStore(hass, "r4-fail-closed")
    await store.async_set_mode("off")
    Path(store._store.path).unlink()
    with patch.object(store._store, "async_save", side_effect=OSError("disk gone")):
        with pytest.raises(OSError):
            await store.async_set_mode("evidence")
    print("FAIL_CLOSED", store._data)
    assert store.mode == ce.COST_MODE_OFF
    assert await store.async_reserve_permit(date(2026, 10, 25), "2026-10-11", "2026-10-25") is None

"""Tests verifying test harness offline guards, security boundaries, and hygiene."""

import asyncio
from pathlib import Path
import re
import socket
import subprocess
import sys
from typing import Any

import pytest
import pytest_homeassistant_custom_component.plugins as phcc_plugins
import pytest_socket
import requests
import requests.adapters
import requests_mock

from custom_components.pseg.const import PORTAL_BASE_URL
from custom_components.pseg.pseg_client import AllowlistedSession
from tests.test_pseg_client import _CannedAdapter


def _loaded_conftest():
    """Return the conftest module pytest actually loaded.

    With tests/ a package it is ``tests.conftest``; ``import conftest`` would
    create a second copy whose classes and globals the active guards never use.
    """
    for name in ("tests.conftest", "conftest"):
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "BlockedOfflineTransportError"):
            return module
    import tests.conftest as module

    return module


BlockedOfflineTransportError = _loaded_conftest().BlockedOfflineTransportError


class SentinelReachedError(RuntimeError):
    """Raised when lower-layer transport is unexpectedly reached."""


def _install_lower_sentinel(
    monkeypatch: pytest.MonkeyPatch,
    methods: tuple[str, ...] = ("connect", "connect_ex", "bind", "sendto", "sendmsg"),
) -> dict[str, list[Any]]:
    """Install lower in-test sentinels on both pytest_socket._true_* and class methods."""
    calls: dict[str, list[Any]] = {m: [] for m in methods}
    target_cls = getattr(pytest_socket, "_true_socket", socket.socket)

    conftest_module = _loaded_conftest()

    for method in methods:
        true_attr = f"_true_{method}"
        guarded_name = f"_guarded_{method}"
        orig_attr = f"_ORIG_SOCKET_{method.upper()}"

        def _make_sentinel(m: str):
            def _sentinel(self: Any, *args: Any, **kwargs: Any) -> Any:
                calls[m].append((args, kwargs))
                raise SentinelReachedError(f"Lower OS {m} reached unexpectedly!")

            return _sentinel

        sentinel_fn = _make_sentinel(method)
        monkeypatch.setattr(pytest_socket, true_attr, sentinel_fn, raising=False)
        if hasattr(conftest_module, orig_attr):
            monkeypatch.setattr(conftest_module, orig_attr, sentinel_fn)

        current_fn = getattr(target_cls, method, None)
        if current_fn is not None:

            def _make_lower_wrapper(cur_fn: Any, s_fn: Any, g_name: str):
                def _lower_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
                    if getattr(cur_fn, "__name__", "") == g_name:
                        return cur_fn(self, *args, **kwargs)
                    return s_fn(self, *args, **kwargs)

                return _lower_wrapper

            wrapper = _make_lower_wrapper(current_fn, sentinel_fn, guarded_name)
            monkeypatch.setattr(target_cls, method, wrapper)
            if socket.socket is not target_cls and hasattr(socket.socket, method):
                monkeypatch.setattr(socket.socket, method, wrapper)

    return calls


def test_guard_unscripted_requests_fail_locally_and_sanitize_url() -> None:
    """Unscripted requests hit HTTPAdapter.send guard and redact credentials/query tokens."""
    session = AllowlistedSession()
    with pytest.raises(BlockedOfflineTransportError) as exc_info:
        session.get(f"{PORTAL_BASE_URL}/unscripted-path")
    assert type(exc_info.value).__name__ == "BlockedOfflineTransportError"

    # Verify URL sanitization removes sensitive query parameters and user credentials
    sensitive_url = (
        "https://synthetic_user:SYNTH_PASSWORD@192.0.2.1/secret-endpoint?token=SYNTH_QUERY"
    )
    try:
        requests.get(sensitive_url)
    except Exception as exc:
        msg = str(exc)
        assert "SYNTH_PASSWORD" not in msg
        assert "SYNTH_QUERY" not in msg
        assert "synthetic_user" not in msg
        assert "192.0.2.1/secret-endpoint" in msg


def test_guard_canned_adapter_and_hop_chains_dispatch_and_record() -> None:
    """_CannedAdapter overrides HTTPAdapter.send and handles 302 and 307 hop chains."""
    session = AllowlistedSession()

    # 302 redirect chain
    u1 = f"{PORTAL_BASE_URL}/chain302_step1"
    u2 = f"{PORTAL_BASE_URL}/chain302_step2"
    u3 = f"{PORTAL_BASE_URL}/chain302_step3"
    responses_302 = {
        u1: (302, {"Location": u2}, ""),
        u2: (302, {"Location": u3}, ""),
        u3: (200, {}, "final 302 reached"),
    }
    adapter_302 = _CannedAdapter(responses_302)
    session.mount("https://", adapter_302)

    resp_302 = session.get(u1)
    assert resp_302.status_code == 200
    assert resp_302.text == "final 302 reached"
    assert resp_302.url == u3
    assert adapter_302.sent == [
        ("GET", u1),
        ("GET", u2),
        ("GET", u3),
    ]

    # 307 redirect chain (preserves POST method)
    p1 = f"{PORTAL_BASE_URL}/chain307_step1"
    p2 = f"{PORTAL_BASE_URL}/chain307_step2"
    responses_307 = {
        p1: (307, {"Location": p2}, ""),
        p2: (200, {}, "final 307 reached"),
    }
    adapter_307 = _CannedAdapter(responses_307)
    session_post = AllowlistedSession()
    session_post.mount("https://", adapter_307)

    resp_307 = session_post.post(p1, data={"field": "value"})
    assert resp_307.status_code == 200
    assert resp_307.text == "final 307 reached"
    assert resp_307.url == p2
    assert adapter_307.sent == [
        ("POST", p1),
        ("POST", p2),
    ]

    # requests_mock operates at BaseAdapter level without hitting HTTPAdapter.send
    with requests_mock.Mocker(session=session) as m:
        m.get(f"{PORTAL_BASE_URL}/mock-endpoint", text="mocked response")
        resp_mock = session.get(f"{PORTAL_BASE_URL}/mock-endpoint")
        assert resp_mock.text == "mocked response"


def test_guard_raw_socket_to_testnet_blocked_locally(monkeypatch) -> None:
    """Raw socket creation and connect to 192.0.2.1 are denied locally without network calls."""
    sentinel_called = False

    def _sentinel_connect(self, *args, **kwargs):
        nonlocal sentinel_called
        sentinel_called = True
        raise SentinelReachedError("Lower-layer socket connect was called!")

    monkeypatch.setattr(socket.socket, "connect", _sentinel_connect)

    try:
        with pytest.raises(pytest_socket.SocketBlockedError):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    finally:
        phcc_plugins.HASocketBlockedError.instances.clear()

    assert not sentinel_called, "Lower-layer socket connect must not be reached"


def test_guard_external_dns_fails_locally(monkeypatch) -> None:
    """External DNS resolution fails locally before attempting any OS resolution."""
    sentinel_called = False

    def _sentinel_getaddrinfo(*args, **kwargs):
        nonlocal sentinel_called
        sentinel_called = True
        raise SentinelReachedError("OS getaddrinfo was called!")

    monkeypatch.setattr(phcc_plugins, "_real_getaddrinfo", _sentinel_getaddrinfo)

    with pytest.raises(RuntimeError, match="DNS resolution disabled in tests"):
        socket.getaddrinfo("unresolved.example.test", 80)

    with pytest.raises(RuntimeError, match="DNS resolution disabled in tests"):
        socket.gethostbyname("unresolved.example.test")

    assert not sentinel_called, "OS getaddrinfo must not be called"


def test_guard_loopback_denied_by_default_and_unix_socketpair_allowed(monkeypatch) -> None:
    """Loopback network traffic is denied by default, while Unix domain sockets and socketpair succeed."""
    sentinel_hit = False

    def _sentinel(self, *args: Any, **kwargs: Any) -> None:
        nonlocal sentinel_hit
        sentinel_hit = True
        raise SentinelReachedError("Lower OS connect reached!")

    monkeypatch.setattr(pytest_socket, "_true_connect", _sentinel)

    try:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 80))
    finally:
        phcc_plugins.HASocketBlockedError.instances.clear()

    assert not sentinel_hit

    # Unix domain sockets succeed (required for asyncio mechanics)
    s_unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s_unix.close()

    # socketpair succeeds and can transfer bytes
    p1, p2 = socket.socketpair()
    try:
        p1.sendall(b"ping")
        received = p2.recv(4)
        assert received == b"ping"
    finally:
        p1.close()
        p2.close()


def test_guard_socket_enabled_does_not_reenable_loopback_without_optin(
    socket_enabled, monkeypatch
) -> None:
    """socket_enabled does not re-enable loopback connect without explicit opt-in."""
    sentinel_hit = False

    def _sentinel(self, *args: Any, **kwargs: Any) -> None:
        nonlocal sentinel_hit
        sentinel_hit = True
        raise SentinelReachedError("Lower OS connect reached!")

    monkeypatch.setattr(pytest_socket, "_true_connect", _sentinel)

    current_connect = socket.socket.connect

    def _lower_sentinel_connect(self, address: Any, *args: Any, **kwargs: Any) -> Any:
        if getattr(current_connect, "__name__", "") == "_guarded_connect":
            return current_connect(self, address, *args, **kwargs)
        _sentinel(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _lower_sentinel_connect)
    if hasattr(pytest_socket, "_true_socket") and pytest_socket._true_socket is not socket.socket:
        monkeypatch.setattr(pytest_socket._true_socket, "connect", _lower_sentinel_connect)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.connect(("127.0.0.1", 80))

    if hasattr(socket, "AF_INET6"):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s6:
            with pytest.raises(
                (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
            ):
                s6.connect(("::1", 80))

    assert not sentinel_hit


def test_guard_socket_enabled_does_not_reenable_non_loopback(socket_enabled, monkeypatch) -> None:
    """socket_enabled does not permit non-loopback outbound connections."""
    sentinel_hit = False

    def _sentinel(self, *args: Any, **kwargs: Any) -> None:
        nonlocal sentinel_hit
        sentinel_hit = True
        raise SentinelReachedError("Lower OS connect reached!")

    monkeypatch.setattr(pytest_socket, "_true_connect", _sentinel)

    current_connect = socket.socket.connect

    def _lower_sentinel_connect(self, address: Any, *args: Any, **kwargs: Any) -> Any:
        if getattr(current_connect, "__name__", "") == "_guarded_connect":
            return current_connect(self, address, *args, **kwargs)
        _sentinel(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _lower_sentinel_connect)
    if hasattr(pytest_socket, "_true_socket") and pytest_socket._true_socket is not socket.socket:
        monkeypatch.setattr(pytest_socket._true_socket, "connect", _lower_sentinel_connect)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.connect(("192.0.2.1", 80))

    if hasattr(socket, "AF_INET6"):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s6:
            with pytest.raises(
                (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
            ):
                s6.connect(("2001:db8::1", 80))

    assert not sentinel_hit


def test_guard_local_enable_socket_does_not_bypass_loopback_guard(monkeypatch) -> None:
    """Calling pytest_socket.enable_socket() locally does not bypass the loopback guard."""
    sentinel_hit = False

    def _sentinel(self, *args: Any, **kwargs: Any) -> None:
        nonlocal sentinel_hit
        sentinel_hit = True
        raise SentinelReachedError("Lower OS connect reached!")

    monkeypatch.setattr(pytest_socket, "_true_connect", _sentinel)

    current_connect = socket.socket.connect

    def _lower_sentinel_connect(self, address: Any, *args: Any, **kwargs: Any) -> Any:
        if getattr(current_connect, "__name__", "") == "_guarded_connect":
            return current_connect(self, address, *args, **kwargs)
        _sentinel(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _lower_sentinel_connect)
    if hasattr(pytest_socket, "_true_socket") and pytest_socket._true_socket is not socket.socket:
        monkeypatch.setattr(pytest_socket._true_socket, "connect", _lower_sentinel_connect)

    pytest_socket.enable_socket()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.connect(("127.0.0.1", 80))

    assert not sentinel_hit


def test_guard_connect_ex_blocked_for_non_loopback(socket_enabled, monkeypatch) -> None:
    """connect_ex cannot bypass offline guards for non-loopback addresses."""
    sentinel_hit = False

    def _sentinel_connect_ex(self, *args: Any, **kwargs: Any) -> int:
        nonlocal sentinel_hit
        sentinel_hit = True
        raise SentinelReachedError("Lower OS connect_ex reached!")

    monkeypatch.setattr(pytest_socket, "_true_connect_ex", _sentinel_connect_ex)

    current_connect_ex = socket.socket.connect_ex

    def _lower_sentinel_connect_ex(self, address: Any, *args: Any, **kwargs: Any) -> int:
        if getattr(current_connect_ex, "__name__", "") == "_guarded_connect_ex":
            return current_connect_ex(self, address, *args, **kwargs)
        return _sentinel_connect_ex(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect_ex", _lower_sentinel_connect_ex)
    if hasattr(pytest_socket, "_true_socket") and pytest_socket._true_socket is not socket.socket:
        monkeypatch.setattr(pytest_socket._true_socket, "connect_ex", _lower_sentinel_connect_ex)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.connect_ex(("192.0.2.1", 80))

    if hasattr(socket, "AF_INET6"):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s6:
            with pytest.raises(
                (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
            ):
                s6.connect_ex(("2001:db8::1", 80))

    assert not sentinel_hit


def test_guard_connect_ex_blocked_for_loopback_without_optin(socket_enabled, monkeypatch) -> None:
    """connect_ex cannot bypass offline guards for loopback addresses without opt-in."""
    sentinel_hit = False

    def _sentinel_connect_ex(self, *args: Any, **kwargs: Any) -> int:
        nonlocal sentinel_hit
        sentinel_hit = True
        raise SentinelReachedError("Lower OS connect_ex reached!")

    monkeypatch.setattr(pytest_socket, "_true_connect_ex", _sentinel_connect_ex)

    current_connect_ex = socket.socket.connect_ex

    def _lower_sentinel_connect_ex(self, address: Any, *args: Any, **kwargs: Any) -> int:
        if getattr(current_connect_ex, "__name__", "") == "_guarded_connect_ex":
            return current_connect_ex(self, address, *args, **kwargs)
        return _sentinel_connect_ex(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect_ex", _lower_sentinel_connect_ex)
    if hasattr(pytest_socket, "_true_socket") and pytest_socket._true_socket is not socket.socket:
        monkeypatch.setattr(pytest_socket._true_socket, "connect_ex", _lower_sentinel_connect_ex)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.connect_ex(("127.0.0.1", 80))

    if hasattr(socket, "AF_INET6"):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s6:
            with pytest.raises(
                (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
            ):
                s6.connect_ex(("::1", 80))

    assert not sentinel_hit


@pytest.mark.allow_loopback
def test_guard_allow_loopback_marker_permits_loopback_connect(socket_enabled, monkeypatch) -> None:
    """A test with @pytest.mark.allow_loopback is permitted loopback connect."""
    called_v4 = False
    called_v6 = False

    def _fake_connect(self, address: Any, *args: Any, **kwargs: Any) -> None:
        nonlocal called_v4, called_v6
        if address[0] == "127.0.0.1":
            called_v4 = True
        elif address[0] == "::1":
            called_v6 = True

    monkeypatch.setattr(pytest_socket, "_true_connect", _fake_connect)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 80))
    assert called_v4

    if hasattr(socket, "AF_INET6"):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s6:
            s6.connect(("::1", 80))
        assert called_v6


@pytest.mark.allow_loopback
def test_guard_allow_loopback_marker_still_denies_non_loopback(socket_enabled, monkeypatch) -> None:
    """A test with @pytest.mark.allow_loopback is still strictly forbidden non-loopback."""
    sentinel_hit = False

    def _sentinel(self, *args: Any, **kwargs: Any) -> None:
        nonlocal sentinel_hit
        sentinel_hit = True
        raise SentinelReachedError("Lower OS connect reached!")

    def _sentinel_ex(self, *args: Any, **kwargs: Any) -> int:
        nonlocal sentinel_hit
        sentinel_hit = True
        raise SentinelReachedError("Lower OS connect_ex reached!")

    monkeypatch.setattr(pytest_socket, "_true_connect", _sentinel)
    monkeypatch.setattr(pytest_socket, "_true_connect_ex", _sentinel_ex)

    current_connect = socket.socket.connect

    def _lower_sentinel_connect(self, address: Any, *args: Any, **kwargs: Any) -> None:
        if getattr(current_connect, "__name__", "") == "_guarded_connect":
            return current_connect(self, address, *args, **kwargs)
        _sentinel(self, address, *args, **kwargs)

    current_connect_ex = socket.socket.connect_ex

    def _lower_sentinel_connect_ex(self, address: Any, *args: Any, **kwargs: Any) -> int:
        if getattr(current_connect_ex, "__name__", "") == "_guarded_connect_ex":
            return current_connect_ex(self, address, *args, **kwargs)
        return _sentinel_ex(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _lower_sentinel_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _lower_sentinel_connect_ex)
    if hasattr(pytest_socket, "_true_socket") and pytest_socket._true_socket is not socket.socket:
        monkeypatch.setattr(pytest_socket._true_socket, "connect", _lower_sentinel_connect)
        monkeypatch.setattr(pytest_socket._true_socket, "connect_ex", _lower_sentinel_connect_ex)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.connect(("192.0.2.1", 80))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.connect_ex(("192.0.2.1", 80))

    assert not sentinel_hit


@pytest.mark.allow_loopback
@pytest.mark.parametrize(
    "family,addr",
    [
        (socket.AF_INET, ("localhost", 80)),
        (socket.AF_INET, ("LocalHost", 80)),
        (socket.AF_INET6, ("::ffff:127.0.0.1", 80)),
        (socket.AF_INET6, ("::ffff:192.0.2.1", 80)),
        (socket.AF_INET, ("0.0.0.0", 80)),
        (socket.AF_INET6, ("::", 80)),
        (socket.AF_INET6, ("::1%lo", 80)),
        (socket.AF_INET6, ("::1%1", 80)),
        (socket.AF_INET6, ("::1", 80, 0, 1)),
        (socket.AF_INET6, ("::1", 80, 0, -1)),
        (socket.AF_INET6, ("::1", 80, "invalid", 0)),
        (socket.AF_INET6, ("::1", 80, 1048576, 0)),
        (socket.AF_INET6, ("::1", 80, -1, 0)),
        (socket.AF_INET6, ("::1", 80, 42, 0)),
        (socket.AF_INET, ("127.0.0.1",)),
        (socket.AF_INET, ("127.0.0.1", 80, "extra")),
        (socket.AF_INET, "127.0.0.1"),
        (socket.AF_INET, 127001),
        (socket.AF_INET, None),
        (socket.AF_INET, ("192.0.2.1", 80)),
        (socket.AF_INET6, ("2001:db8::1", 80)),
    ],
)
@pytest.mark.parametrize("method", ["connect", "connect_ex", "bind"])
def test_guard_loopback_optin_rejects_non_numeric_and_invalid_forms(
    socket_enabled, monkeypatch, family, addr, method
) -> None:
    """Opted-in loopback must reject hostnames, mapped, wildcard, scoped, and malformed addresses."""
    calls = _install_lower_sentinel(monkeypatch, (method,))

    with socket.socket(family, socket.SOCK_STREAM) as sock:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            getattr(sock, method)(addr)

    assert not calls[method]


def test_guard_bind_enforces_numeric_loopback_optin(socket_enabled, monkeypatch) -> None:
    """bind enforces strict numeric-loopback rules both with and without opt-in."""
    calls = _install_lower_sentinel(monkeypatch, ("bind",))

    # Without opt-in: loopback bind is denied
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.bind(("127.0.0.1", 0))

    assert not calls["bind"]


@pytest.mark.allow_loopback
def test_guard_bind_permits_numeric_loopback_when_opted_in(socket_enabled, monkeypatch) -> None:
    """bind permits numeric loopback addresses (127.0.0.1, ::1) when opted in."""
    bound_v4 = False
    bound_v6 = False

    def _fake_bind(self, addr: Any, *args: Any, **kwargs: Any) -> None:
        nonlocal bound_v4, bound_v6
        if addr[0] == "127.0.0.1":
            bound_v4 = True
        elif addr[0] == "::1":
            bound_v6 = True

    monkeypatch.setattr(pytest_socket, "_true_bind", _fake_bind)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s4:
        s4.bind(("127.0.0.1", 0))
    assert bound_v4

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s6:
        s6.bind(("::1", 0))
    assert bound_v6


def test_guard_sendto_enforces_numeric_loopback_optin(socket_enabled, monkeypatch) -> None:
    """sendto enforces strict numeric-loopback rules both with and without opt-in."""
    calls = _install_lower_sentinel(monkeypatch, ("sendto",))

    # Without opt-in: loopback sendto is denied
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.sendto(b"SYNTH", ("127.0.0.1", 9))

    assert not calls["sendto"]


@pytest.mark.allow_loopback
def test_guard_sendto_permits_numeric_loopback_when_opted_in(socket_enabled, monkeypatch) -> None:
    """sendto permits numeric loopback addresses (127.0.0.1, ::1) when opted in."""
    sent_v4 = False
    sent_v6 = False

    def _fake_sendto(self, *args: Any, **kwargs: Any) -> int:
        nonlocal sent_v4, sent_v6
        from tests.conftest import _extract_sendto_address

        addr = _extract_sendto_address(*args, **kwargs)
        if addr[0] == "127.0.0.1":
            sent_v4 = True
        elif addr[0] == "::1":
            sent_v6 = True
        return len(args[0]) if args else 0

    monkeypatch.setattr(pytest_socket, "_true_sendto", _fake_sendto)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s4:
        s4.sendto(b"SYNTH", ("127.0.0.1", 9))
    assert sent_v4

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s6:
        s6.sendto(b"SYNTH", ("::1", 9))
    assert sent_v6


@pytest.mark.allow_loopback
def test_guard_sendto_denies_external(socket_enabled, monkeypatch) -> None:
    """sendto denies external addresses even when opted in."""
    calls = _install_lower_sentinel(monkeypatch, ("sendto",))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.sendto(b"SYNTH", ("192.0.2.1", 9))

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s6:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s6.sendto(b"SYNTH", ("2001:db8::1", 9))

    assert not calls["sendto"]


def test_guard_sendmsg_enforces_numeric_loopback_optin(socket_enabled, monkeypatch) -> None:
    """sendmsg enforces strict numeric-loopback rules both with and without opt-in."""
    calls = _install_lower_sentinel(monkeypatch, ("sendmsg",))

    # Without opt-in: loopback sendmsg is denied
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.sendmsg([b"SYNTH"], [], 0, ("127.0.0.1", 9))

    assert not calls["sendmsg"]


@pytest.mark.allow_loopback
def test_guard_sendmsg_permits_numeric_loopback_when_opted_in(socket_enabled, monkeypatch) -> None:
    """sendmsg permits numeric loopback addresses (127.0.0.1, ::1) when opted in."""
    sent_v4 = False
    sent_v6 = False

    def _fake_sendmsg(self, *args: Any, **kwargs: Any) -> int:
        nonlocal sent_v4, sent_v6
        from tests.conftest import _extract_sendmsg_address

        addr = _extract_sendmsg_address(self, *args, **kwargs)
        if addr[0] == "127.0.0.1":
            sent_v4 = True
        elif addr[0] == "::1":
            sent_v6 = True
        return 5

    monkeypatch.setattr(pytest_socket, "_true_sendmsg", _fake_sendmsg)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s4:
        s4.sendmsg([b"SYNTH"], [], 0, ("127.0.0.1", 9))
    assert sent_v4

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s6:
        s6.sendmsg([b"SYNTH"], [], 0, ("::1", 9))
    assert sent_v6


@pytest.mark.allow_loopback
def test_guard_sendmsg_denies_external(socket_enabled, monkeypatch) -> None:
    """sendmsg denies external addresses even when opted in."""
    calls = _install_lower_sentinel(monkeypatch, ("sendmsg",))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s.sendmsg([b"SYNTH"], [], 0, ("192.0.2.1", 9))

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s6:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s6.sendmsg([b"SYNTH"], [], 0, ("2001:db8::1", 9))

    assert not calls["sendmsg"]


@pytest.mark.allow_loopback
def test_guard_sendto_sendmsg_argument_positions_and_unparseable(
    socket_enabled, monkeypatch
) -> None:
    """Test sendto/sendmsg argument positions and unparseable shapes fail closed."""
    calls = _install_lower_sentinel(monkeypatch, ("sendto", "sendmsg"))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # 2-arg sendto(data, addr)
        with pytest.raises(pytest_socket.SocketConnectBlockedError):
            s.sendto(b"SYNTH", ("192.0.2.1", 9))

        # 3-arg sendto(data, flags, addr)
        with pytest.raises(pytest_socket.SocketConnectBlockedError):
            s.sendto(b"SYNTH", 0, ("192.0.2.1", 9))

        # Unparseable shapes fail closed
        with pytest.raises(pytest_socket.SocketConnectBlockedError):
            s.sendto(b"SYNTH", 0, ("192.0.2.1", 9), "extra")  # type: ignore[call-arg]

        # sendmsg(buffers, ancdata, flags, address)
        with pytest.raises(pytest_socket.SocketConnectBlockedError):
            s.sendmsg([b"SYNTH"], [], 0, ("192.0.2.1", 9))

        # sendmsg unconnected without address fails closed
        with pytest.raises(pytest_socket.SocketConnectBlockedError):
            s.sendmsg([b"SYNTH"])

    assert not calls["sendto"]
    assert not calls["sendmsg"]


async def test_guard_asyncio_sock_sendto_denies_external(socket_enabled, monkeypatch) -> None:
    """asyncio loop.sock_sendto denies external addresses."""
    calls = _install_lower_sentinel(monkeypatch, ("sendto",))

    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setblocking(False)
        with pytest.raises(pytest_socket.SocketConnectBlockedError):
            await loop.sock_sendto(s, b"SYNTH", ("192.0.2.1", 9))

    assert not calls["sendto"]


async def test_guard_asyncio_datagram_endpoint_remote_addr_denied(
    socket_enabled, monkeypatch
) -> None:
    """asyncio loop.create_datagram_endpoint with external remote_addr is denied."""
    calls = _install_lower_sentinel(monkeypatch, ("connect",))

    loop = asyncio.get_running_loop()
    with pytest.raises(pytest_socket.SocketConnectBlockedError):
        await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=("192.0.2.1", 9),
        )

    assert not calls["connect"]


async def test_guard_asyncio_datagram_transport_sendto_denies_external(
    socket_enabled, monkeypatch
) -> None:
    """asyncio DatagramTransport.sendto denies external addresses."""
    calls = _install_lower_sentinel(monkeypatch, ("sendto",))

    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setblocking(False)
        errors: list[dict[str, Any]] = []
        loop.set_exception_handler(lambda _loop, ctx: errors.append(ctx))
        transport, proto = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            sock=s,
        )
        try:
            transport.sendto(b"SYNTH", ("192.0.2.1", 9))
            assert any(
                isinstance(c.get("exception"), pytest_socket.SocketConnectBlockedError)
                for c in errors
            )
        finally:
            transport.close()

    assert not calls["sendto"]

async def test_guard_localhost_resolution_blocked_before_lookup(socket_enabled, monkeypatch) -> None:
    """Resolving localhost is blocked with SocketConnectBlockedError before any resolver is invoked."""
    resolver_reached = False

    def _fail_resolver(*args: Any, **kwargs: Any) -> Any:
        nonlocal resolver_reached
        resolver_reached = True
        raise SentinelReachedError("Lower getaddrinfo resolver reached!")

    monkeypatch.setattr(phcc_plugins, "_real_getaddrinfo", _fail_resolver)

    with pytest.raises(pytest_socket.SocketConnectBlockedError):
        socket.getaddrinfo("localhost", 80)

    with pytest.raises(pytest_socket.SocketConnectBlockedError):
        socket.getaddrinfo("LocalHost", 80)

    with pytest.raises(pytest_socket.SocketConnectBlockedError):
        await asyncio.get_running_loop().create_connection(
            asyncio.Protocol, host="localhost", port=80
        )

    assert not resolver_reached


def test_teardown_restores_monkeypatches_and_no_loopback_leak(monkeypatch) -> None:
    """Teardown restores monkeypatched attributes, and loopback remains disallowed."""
    test_obj = requests.adapters.HTTPAdapter
    monkeypatch.setattr(test_obj, "_guard_canary", 42, raising=False)
    assert getattr(test_obj, "_guard_canary", None) == 42
    monkeypatch.undo()
    assert not hasattr(test_obj, "_guard_canary")

    calls = _install_lower_sentinel(monkeypatch, ("connect",))

    try:
        with pytest.raises(
            (pytest_socket.SocketBlockedError, pytest_socket.SocketConnectBlockedError)
        ):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 8080))
    finally:
        phcc_plugins.HASocketBlockedError.instances.clear()

    assert not calls["connect"]


def test_session_teardown_restores_all_socket_and_adapter_originals() -> None:
    """Ensure after an in-process pytest session, socket methods and HTTPAdapter.send are restored to originals."""
    script = (
        "import socket, requests.adapters, pytest\n"
        "before = (requests.adapters.HTTPAdapter.send, socket.socket, socket.socket.connect, socket.socket.connect_ex, socket.socket.bind, socket.socket.sendto)\n"
        "if hasattr(socket.socket, 'sendmsg'):\n"
        "    before = before + (socket.socket.sendmsg,)\n"
        "ret = pytest.main(['-q', '-p', 'no:cacheprovider', 'tests/test_security_guards.py'])\n"
        "assert ret == 0 or ret == pytest.ExitCode.OK\n"
        "after = (requests.adapters.HTTPAdapter.send, socket.socket, socket.socket.connect, socket.socket.connect_ex, socket.socket.bind, socket.socket.sendto)\n"
        "if hasattr(socket.socket, 'sendmsg'):\n"
        "    after = after + (socket.socket.sendmsg,)\n"
        "for b, a in zip(before, after):\n"
        "    assert a is b, f'Restoration failure: {a} is not {b}'\n"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=Path(__file__).parent.parent,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.returncode == 0


FORBIDDEN_EXTENSIONS = {".har", ".pcap", ".pcapng"}
FORBIDDEN_NAME_PATTERNS = [
    re.compile(r".*raw.*capture.*", re.IGNORECASE),
    re.compile(r".*\.capture\.json$", re.IGNORECASE),
]
LIVE_SECRET_PATTERNS = [
    re.compile(r"idx=[a-zA-Z0-9_\-]{30,}"),
    re.compile(r"sid=[a-zA-Z0-9_\-]{30,}"),
    re.compile(r"MM_SID=[a-zA-Z0-9_\-]{30,}"),
]


def scan_test_tree_hygiene(test_dir: Path) -> list[str]:
    """Scan only the specified test directory tree for forbidden captures or token leaks."""
    violations: list[str] = []
    for file_path in test_dir.rglob("*"):
        if not file_path.is_file():
            continue
        if any(
            part in file_path.parts for part in (".git", ".venv", "__pycache__", ".pytest_cache")
        ):
            continue
        rel = file_path.relative_to(test_dir)
        if file_path.suffix.lower() in FORBIDDEN_EXTENSIONS:
            violations.append(f"Forbidden capture extension: {rel}")
            continue
        for pat in FORBIDDEN_NAME_PATTERNS:
            if pat.match(file_path.name):
                violations.append(f"Forbidden capture filename: {rel}")
                break
        if file_path.suffix in (".py", ".json", ".js", ".cjs", ".yaml", ".yml", ".txt"):
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pat in LIVE_SECRET_PATTERNS:
                if pat.search(content):
                    if (
                        "FIXTURE" not in content
                        and "SYNTH" not in content
                        and "secret_" not in content
                    ):
                        violations.append(f"Potential unredacted live secret in: {rel}")
    return violations


def test_hygiene_rejects_synthetic_forbidden_capture(tmp_path: Path) -> None:
    """Hygiene check detects and rejects synthetic forbidden capture files."""
    har_file = tmp_path / "login_session.har"
    har_file.write_text('{"log": {"entries": []}}', encoding="utf-8")

    pcap_file = tmp_path / "traffic.pcap"
    pcap_file.write_bytes(bytes.fromhex("d4c3b2a102000400"))

    dump_file = tmp_path / "raw_capture_session.json"
    dump_file.write_text('{"portal_cookies": "live"}', encoding="utf-8")

    violations = scan_test_tree_hygiene(tmp_path)
    assert any("login_session.har" in v for v in violations)
    assert any("traffic.pcap" in v for v in violations)
    assert any("raw_capture_session.json" in v for v in violations)


def test_hygiene_test_tree_is_clean() -> None:
    """Real tests directory tree contains no forbidden capture files or unredacted secrets."""
    tests_root = Path(__file__).parent
    violations = scan_test_tree_hygiene(tests_root)
    assert violations == [], f"Hygiene violations found in tests directory: {violations}"

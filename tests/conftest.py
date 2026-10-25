"""Pytest fixtures for PSE&G integration tests."""

import ipaddress
import socket
from typing import Any
import urllib.parse

import pytest
import pytest_socket
import requests.adapters

# Capture pre-session originals before any test or fixture patches them
_ORIG_SOCKET_CONNECT = getattr(pytest_socket, "_true_connect", socket.socket.connect)
_ORIG_SOCKET_CONNECT_EX = socket.socket.connect_ex
_ORIG_SOCKET_BIND = socket.socket.bind
_ORIG_SOCKET_SENDTO = socket.socket.sendto
_ORIG_SOCKET_SENDMSG = getattr(socket.socket, "sendmsg", None)
_ORIG_SOCKET_GETADDRINFO = getattr(pytest_socket, "_true_getaddrinfo", socket.getaddrinfo)
_ORIG_HTTPADAPTER_SEND = requests.adapters.HTTPAdapter.send

if not hasattr(pytest_socket, "_true_connect_ex"):
    pytest_socket._true_connect_ex = _ORIG_SOCKET_CONNECT_EX
if not hasattr(pytest_socket, "_true_bind"):
    pytest_socket._true_bind = _ORIG_SOCKET_BIND
if not hasattr(pytest_socket, "_true_sendto"):
    pytest_socket._true_sendto = _ORIG_SOCKET_SENDTO
if _ORIG_SOCKET_SENDMSG is not None and not hasattr(pytest_socket, "_true_sendmsg"):
    pytest_socket._true_sendmsg = _ORIG_SOCKET_SENDMSG

# Fix Python 3.14 inspect.signature annotation issue in HA 2026.10.2 recorder migration
try:
    import homeassistant.components.recorder.core
    import homeassistant.components.recorder.migration

    homeassistant.components.recorder.migration.Recorder = (
        homeassistant.components.recorder.core.Recorder
    )
except Exception:
    pass

# Python 3.14 evaluates annotations lazily; helpers.recorder only imports Session under
# TYPE_CHECKING, so recorder-backed tests (recorder_mock) fail resolving it. Bind it.
try:
    import homeassistant.helpers.recorder as _helpers_recorder
    from sqlalchemy.orm import Session as _SqlaSession

    _helpers_recorder.Session = _SqlaSession
except Exception:
    pass


def pytest_configure(config: pytest.Config) -> None:
    """Register custom test markers."""
    config.addinivalue_line(
        "markers",
        "allow_loopback: Allow in-process loopback network connections for this test",
    )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Ensure socket methods are fully restored to baseline originals at session exit."""
    target_cls = getattr(pytest_socket, "_true_socket", socket.socket)
    target_cls.connect = _ORIG_SOCKET_CONNECT
    target_cls.connect_ex = _ORIG_SOCKET_CONNECT_EX
    target_cls.bind = _ORIG_SOCKET_BIND
    target_cls.sendto = _ORIG_SOCKET_SENDTO
    if _ORIG_SOCKET_SENDMSG is not None:
        target_cls.sendmsg = _ORIG_SOCKET_SENDMSG
    if socket.socket is not target_cls:
        socket.socket.connect = _ORIG_SOCKET_CONNECT
        socket.socket.connect_ex = _ORIG_SOCKET_CONNECT_EX
        socket.socket.bind = _ORIG_SOCKET_BIND
        socket.socket.sendto = _ORIG_SOCKET_SENDTO
        if _ORIG_SOCKET_SENDMSG is not None:
            socket.socket.sendmsg = _ORIG_SOCKET_SENDMSG
    socket.getaddrinfo = _ORIG_SOCKET_GETADDRINFO
    requests.adapters.HTTPAdapter.send = _ORIG_HTTPADAPTER_SEND


@pytest.fixture
def allow_loopback() -> None:
    """Fixture allowing in-process loopback network connections."""
    return None


class BlockedOfflineTransportError(RuntimeError):
    """Raised when unscripted real network transport is attempted during tests."""


def _sanitize_url(url: str) -> str:
    """Sanitize URL to report only scheme, host (with port if explicit), and path.

    Never exposes query parameters, userinfo (usernames/passwords), or fragments.
    """
    if not isinstance(url, str):
        return "UNKNOWN"
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
        host = f"{hostname}{port}" if hostname else parts.netloc.split("@")[-1].split(":")[0]
        path = parts.path or ""
        scheme = parts.scheme or ""
        if scheme and host:
            return f"{scheme}://{host}{path}"
        if host:
            return f"{host}{path}"
        return path or "UNKNOWN"
    except Exception:
        return "<sanitized-url>"


_IPV4_LOOPBACK_NET = ipaddress.IPv4Network("127.0.0.0/8")
_IPV6_LOOPBACK_ADDR = ipaddress.IPv6Address("::1")


_UNPARSEABLE = object()


def _extract_sendto_address(*args: Any, **kwargs: Any) -> Any:
    """Extract destination address from sendto arguments.

    sendto signatures in Python:
    - sendto(data, address) -> 2 args
    - sendto(data, flags, address) -> 3 args
    Also handle potential keyword arguments.
    """
    if "address" in kwargs and kwargs["address"] is not None:
        return kwargs["address"]
    if "addr" in kwargs and kwargs["addr"] is not None:
        return kwargs["addr"]
    if len(args) == 2:
        return args[1]
    if len(args) == 3:
        return args[2]
    return _UNPARSEABLE


def _extract_sendmsg_address(inst: socket.socket, *args: Any, **kwargs: Any) -> Any:
    """Extract destination address from sendmsg arguments.

    sendmsg signatures in Python:
    - sendmsg(buffers[, ancdata[, flags[, address]]])
    If address is not passed or None, check if socket is connected via getpeername().
    """
    if "address" in kwargs and kwargs["address"] is not None:
        return kwargs["address"]
    if "addr" in kwargs and kwargs["addr"] is not None:
        return kwargs["addr"]
    if len(args) >= 4 and args[3] is not None:
        return args[3]

    try:
        return inst.getpeername()
    except Exception:
        return _UNPARSEABLE


def _is_loopback_target(address: Any, family: int | None = None) -> bool:
    """Determine whether the target address points to a valid numeric loopback address.

    Accepts ONLY numeric literals:
    - IPv4 in 127.0.0.0/8 (parsed via ipaddress.ip_address)
    - IPv6 exactly ::1

    Accepts only:
    - ("::1", port) or ("::1", port, 0, 0) for IPv6.

    Rejects:
    - Hostnames (e.g. 'localhost', denied without any resolution)
    - IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1, ::ffff:x.x.x.x)
    - 0.0.0.0 and ::
    - Scoped/zoned forms (e.g. ::1%lo, ::1%1)
    - Non-tuple or odd address shapes (fail closed)
    - AF_INET6 tuples with flowinfo != 0 or non-zero / negative scope ID
    """
    if not isinstance(address, tuple):
        return False

    if family == socket.AF_INET:
        if len(address) != 2:
            return False
    elif hasattr(socket, "AF_INET6") and family == socket.AF_INET6:
        if len(address) not in (2, 4):
            return False
    else:
        if len(address) not in (2, 4):
            return False

    host, port = address[0], address[1]
    if not isinstance(host, str) or type(port) is not int:
        return False
    if not (0 <= port <= 65535):
        return False

    if len(address) == 4:
        flowinfo, scopeid = address[2], address[3]
        if type(flowinfo) is not int or type(scopeid) is not int:
            return False
        if flowinfo != 0 or scopeid != 0:
            return False

    if "%" in host:
        return False

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    if getattr(ip, "ipv4_mapped", None) is not None:
        return False

    if ip.version == 4:
        if family is not None and family != socket.AF_INET:
            return False
        return ip in _IPV4_LOOPBACK_NET

    if ip.version == 6:
        if family is not None and hasattr(socket, "AF_INET6") and family != socket.AF_INET6:
            return False
        return ip == _IPV6_LOOPBACK_ADDR

    return False


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable custom integrations for all tests."""
    yield


@pytest.fixture(autouse=True)
def deny_unscripted_network(request, monkeypatch):
    """Autouse fixture to enforce explicit offline guards in all tests.

    1. Deny real HTTP transport at requests.adapters.HTTPAdapter.send.
       Custom adapters (_CannedAdapter, BaseAdapter portals, requests-mock)
       override send or BaseAdapter and continue functioning. Real
       AllowlistedSession.send is preserved so host and ownership checks
       are not masked. Reported URLs are strictly sanitized to never expose
       userinfo, query parameters, or request bodies.
    2. Enforce strict socket and DNS isolation, denying non-loopback outbound
       transport across connect and connect_ex unconditionally (even under
       socket_enabled). Deny loopback transport by default unless the test
       explicitly opts in via @pytest.mark.allow_loopback or allow_loopback fixture.
       Unix domain sockets and socketpair mechanics required by asyncio remain permitted.
    """

    def _blocked_httpadapter_send(self, req, *args, **kwargs):
        method = getattr(req, "method", "UNKNOWN")
        raw_url = getattr(req, "url", "UNKNOWN")
        sanitized_url = _sanitize_url(raw_url)
        raise BlockedOfflineTransportError(
            f"Real HTTP transport blocked: unscripted requests.adapters.HTTPAdapter.send "
            f"called for {method} {sanitized_url}"
        )

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _blocked_httpadapter_send)

    orig_getaddrinfo = socket.getaddrinfo

    def _guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(host, str):
            clean = host.strip()
            if clean.lower() == "localhost" or "%" in clean:
                raise pytest_socket.SocketConnectBlockedError([], host)
            try:
                ip = ipaddress.ip_address(clean)
                if getattr(ip, "ipv4_mapped", None) is not None:
                    raise pytest_socket.SocketConnectBlockedError([], host)
            except ValueError:
                pass
        return orig_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = _guarded_getaddrinfo

    # Check for explicit loopback opt-in
    has_marker = request.node.get_closest_marker("allow_loopback") is not None
    has_fixture = "allow_loopback" in getattr(request, "fixturenames", ())
    loopback_allowed = has_marker or has_fixture

    target_cls = pytest_socket._true_socket

    def _guarded_connect(inst: socket.socket, address: Any, *args: Any, **kwargs: Any) -> Any:
        if inst.family == getattr(socket, "AF_UNIX", -1):
            true_connect = getattr(pytest_socket, "_true_connect", _ORIG_SOCKET_CONNECT)
            return true_connect(inst, address, *args, **kwargs)

        is_loop = _is_loopback_target(address, family=inst.family)
        if is_loop and loopback_allowed:
            true_connect = getattr(pytest_socket, "_true_connect", _ORIG_SOCKET_CONNECT)
            return true_connect(inst, address, *args, **kwargs)

        try:
            inst.close()
        except Exception:
            pass
        host = address[0] if isinstance(address, tuple) and len(address) >= 1 else str(address)
        raise pytest_socket.SocketConnectBlockedError([], host)

    def _guarded_connect_ex(inst: socket.socket, address: Any, *args: Any, **kwargs: Any) -> int:
        if inst.family == getattr(socket, "AF_UNIX", -1):
            true_connect_ex = getattr(pytest_socket, "_true_connect_ex", _ORIG_SOCKET_CONNECT_EX)
            return true_connect_ex(inst, address, *args, **kwargs)

        is_loop = _is_loopback_target(address, family=inst.family)
        if is_loop and loopback_allowed:
            true_connect_ex = getattr(pytest_socket, "_true_connect_ex", _ORIG_SOCKET_CONNECT_EX)
            return true_connect_ex(inst, address, *args, **kwargs)

        try:
            inst.close()
        except Exception:
            pass
        host = address[0] if isinstance(address, tuple) and len(address) >= 1 else str(address)
        raise pytest_socket.SocketConnectBlockedError([], host)

    def _guarded_bind(inst: socket.socket, address: Any, *args: Any, **kwargs: Any) -> Any:
        if inst.family == getattr(socket, "AF_UNIX", -1):
            true_bind = getattr(pytest_socket, "_true_bind", _ORIG_SOCKET_BIND)
            return true_bind(inst, address, *args, **kwargs)

        is_loop = _is_loopback_target(address, family=inst.family)
        if is_loop and loopback_allowed:
            true_bind = getattr(pytest_socket, "_true_bind", _ORIG_SOCKET_BIND)
            return true_bind(inst, address, *args, **kwargs)

        try:
            inst.close()
        except Exception:
            pass
        host = address[0] if isinstance(address, tuple) and len(address) >= 1 else str(address)
        raise pytest_socket.SocketConnectBlockedError([], host)

    def _guarded_sendto(inst: socket.socket, *args: Any, **kwargs: Any) -> Any:
        if inst.family == getattr(socket, "AF_UNIX", -1):
            true_sendto = getattr(pytest_socket, "_true_sendto", _ORIG_SOCKET_SENDTO)
            return true_sendto(inst, *args, **kwargs)

        address = _extract_sendto_address(*args, **kwargs)
        is_loop = address is not _UNPARSEABLE and _is_loopback_target(address, family=inst.family)
        if is_loop and loopback_allowed:
            true_sendto = getattr(pytest_socket, "_true_sendto", _ORIG_SOCKET_SENDTO)
            return true_sendto(inst, *args, **kwargs)

        try:
            inst.close()
        except Exception:
            pass
        host = address[0] if isinstance(address, tuple) and len(address) >= 1 else str(address)
        raise pytest_socket.SocketConnectBlockedError([], host)

    def _guarded_sendmsg(inst: socket.socket, *args: Any, **kwargs: Any) -> Any:
        if inst.family == getattr(socket, "AF_UNIX", -1):
            true_sendmsg = getattr(pytest_socket, "_true_sendmsg", _ORIG_SOCKET_SENDMSG)
            return true_sendmsg(inst, *args, **kwargs)

        address = _extract_sendmsg_address(inst, *args, **kwargs)
        is_loop = address is not _UNPARSEABLE and _is_loopback_target(address, family=inst.family)
        if is_loop and loopback_allowed:
            true_sendmsg = getattr(pytest_socket, "_true_sendmsg", _ORIG_SOCKET_SENDMSG)
            return true_sendmsg(inst, *args, **kwargs)

        try:
            inst.close()
        except Exception:
            pass
        host = address[0] if isinstance(address, tuple) and len(address) >= 1 else str(address)
        raise pytest_socket.SocketConnectBlockedError([], host)

    # Reset attributes to clean baseline originals before monkeypatching so that
    # monkeypatch.undo() restores clean baseline methods.
    target_cls.connect = _ORIG_SOCKET_CONNECT
    target_cls.connect_ex = _ORIG_SOCKET_CONNECT_EX
    target_cls.bind = _ORIG_SOCKET_BIND
    target_cls.sendto = _ORIG_SOCKET_SENDTO
    if _ORIG_SOCKET_SENDMSG is not None:
        target_cls.sendmsg = _ORIG_SOCKET_SENDMSG
    if socket.socket is not target_cls:
        socket.socket.connect = _ORIG_SOCKET_CONNECT
        socket.socket.connect_ex = _ORIG_SOCKET_CONNECT_EX
        socket.socket.bind = _ORIG_SOCKET_BIND
        socket.socket.sendto = _ORIG_SOCKET_SENDTO
        if _ORIG_SOCKET_SENDMSG is not None:
            socket.socket.sendmsg = _ORIG_SOCKET_SENDMSG

    monkeypatch.setattr(target_cls, "connect", _guarded_connect)
    monkeypatch.setattr(target_cls, "connect_ex", _guarded_connect_ex)
    monkeypatch.setattr(target_cls, "bind", _guarded_bind)
    monkeypatch.setattr(target_cls, "sendto", _guarded_sendto)
    monkeypatch.setattr(target_cls, "sendmsg", _guarded_sendmsg)
    if socket.socket is not target_cls:
        monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
        monkeypatch.setattr(socket.socket, "bind", _guarded_bind)
        monkeypatch.setattr(socket.socket, "sendto", _guarded_sendto)
        monkeypatch.setattr(socket.socket, "sendmsg", _guarded_sendmsg)

    try:
        yield
    finally:
        target_cls.connect = _ORIG_SOCKET_CONNECT
        target_cls.connect_ex = _ORIG_SOCKET_CONNECT_EX
        target_cls.bind = _ORIG_SOCKET_BIND
        target_cls.sendto = _ORIG_SOCKET_SENDTO
        if _ORIG_SOCKET_SENDMSG is not None:
            target_cls.sendmsg = _ORIG_SOCKET_SENDMSG
        if socket.socket is not target_cls:
            socket.socket.connect = _ORIG_SOCKET_CONNECT
            socket.socket.connect_ex = _ORIG_SOCKET_CONNECT_EX
            socket.socket.bind = _ORIG_SOCKET_BIND
            socket.socket.sendto = _ORIG_SOCKET_SENDTO
            if _ORIG_SOCKET_SENDMSG is not None:
                socket.socket.sendmsg = _ORIG_SOCKET_SENDMSG
        socket.getaddrinfo = orig_getaddrinfo


@pytest.fixture(autouse=True)
def _real_pseg_statistics_writes(tmp_path, hass_storage, monkeypatch):
    """Give every PSE&G statistics Store an isolated real per-test path and writer.

    The HA harness mocks Store._async_write_data globally; route only our key
    through Store._write_data so Store.async_save\x27s real swallow handler is
    exercised. Direct assignment (not monkeypatch) keeps the harness mock\x27s
    autospec teardown intact.
    """
    from pathlib import Path as _Path

    from homeassistant.helpers import storage

    from custom_components.pseg.statistics_state import StatisticsStateStore

    original_init = StatisticsStateStore.__init__

    def _init(self, hass, entry_id):
        original_init(self, hass, entry_id)
        safe_entry = str(entry_id).replace("/", "_")
        self._store.__dict__["path"] = str(
            _Path(tmp_path) / f"pseg-statistics-{safe_entry}.json"
        )

    monkeypatch.setattr(StatisticsStateStore, "__init__", _init)
    original_write = storage.Store._async_write_data

    async def routed(store_obj, data):
        if store_obj.key.startswith("pseg.statistics."):
            await store_obj.hass.async_add_executor_job(
                store_obj._write_data, data
            )
            return
        await original_write(store_obj, data)

    storage.Store._async_write_data = routed
    try:
        yield
    finally:
        storage.Store._async_write_data = original_write

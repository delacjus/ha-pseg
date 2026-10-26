"""Scripted portal transport for deterministic PSE&G and Okta simulation.

Provides in-memory canned response playback, boundary gates, retirement tracking,
and immutable observation records without taking over production client
decision-making or leaking sensitive data.
"""

from __future__ import annotations

from collections import namedtuple
from collections.abc import Callable, Mapping, Sequence
import copy
import dataclasses
from dataclasses import dataclass, field
import hashlib
import http.client
import http.cookiejar
import io
import json
import threading
import time
from types import MappingProxyType
from typing import Any
import urllib.parse

import requests
from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar
from requests.structures import CaseInsensitiveDict

from custom_components.pseg.const import OKTA_HOST, PORTAL_BASE_URL

DEFAULT_PORTAL_BASE_URL = PORTAL_BASE_URL
DEFAULT_OKTA_BASE_URL = f"https://{OKTA_HOST}"


class FrozenCookie(
    namedtuple("FrozenCookie", ["name", "value", "domain", "path", "secure", "expires"])
):
    """Immutable representation of an HTTP cookie."""

    __slots__ = ()

    @property
    def version(self) -> int:
        return 0

    @property
    def port(self) -> str | None:
        return None

    @property
    def discard(self) -> bool:
        return False

    @property
    def comment(self) -> str | None:
        return None

    @property
    def comment_url(self) -> str | None:
        return None

    def is_expired(self, now: float | None = None) -> bool:
        return False


def _freeze_value(val: Any) -> Any:
    """Recursively freeze nested data structures into immutable primitives."""
    if val is None or isinstance(val, (str, bytes, int, float, bool)):
        return val
    if isinstance(val, (http.cookiejar.Cookie, FrozenCookie)) or (
        hasattr(val, "name")
        and hasattr(val, "value")
        and hasattr(val, "domain")
        and hasattr(val, "path")
    ):
        return FrozenCookie(
            name=str(val.name),
            value=str(val.value),
            domain=str(getattr(val, "domain", "") or ""),
            path=str(getattr(val, "path", "/") or "/"),
            secure=bool(getattr(val, "secure", False)),
            expires=getattr(val, "expires", None),
        )
    if isinstance(val, Mapping):
        return MappingProxyType({k: _freeze_value(v) for k, v in val.items()})
    if isinstance(val, (list, tuple)):
        return tuple(_freeze_value(v) for v in val)
    if isinstance(val, (set, frozenset)):
        return frozenset(_freeze_value(v) for v in val)
    try:
        return copy.deepcopy(val)
    except Exception:
        return val


def _freeze_headers(
    headers: Mapping[str, Any] | Sequence[tuple[str, Any]] | None,
) -> MappingProxyType[str, Any]:
    """Freeze headers preserving multi-values and order."""
    if headers is None:
        return MappingProxyType({})
    headers_map: dict[str, Any] = {}
    if isinstance(headers, Mapping):
        for k, v in headers.items():
            if isinstance(v, (list, tuple)):
                headers_map[str(k)] = tuple(_freeze_value(item) for item in v)
            else:
                headers_map[str(k)] = _freeze_value(v)
    elif isinstance(headers, (list, tuple)):
        for pair in headers:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                k, v = str(pair[0]), _freeze_value(pair[1])
                if k in headers_map:
                    existing = headers_map[k]
                    if isinstance(existing, tuple):
                        headers_map[k] = existing + (v,)
                    else:
                        headers_map[k] = (existing, v)
                else:
                    headers_map[k] = v
    else:
        for k, v in dict(headers).items():
            headers_map[str(k)] = _freeze_value(v)
    return MappingProxyType(headers_map)


def _freeze_cookies(cookies: Any) -> MappingProxyType[str, str]:
    """Freeze cookies into an immutable MappingProxyType mapping."""
    if cookies is None:
        return MappingProxyType({})
    if isinstance(cookies, requests.cookies.RequestsCookieJar) or hasattr(cookies, "items"):
        return MappingProxyType({str(k): str(v) for k, v in cookies.items()})
    if hasattr(cookies, "__iter__") and not isinstance(cookies, (str, bytes)):
        c_dict: dict[str, str] = {}
        for item in cookies:
            if isinstance(item, (http.cookiejar.Cookie, FrozenCookie)) or hasattr(item, "name"):
                c_dict[str(item.name)] = str(item.value)
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                c_dict[str(item[0])] = str(item[1])
        return MappingProxyType(c_dict)
    return MappingProxyType({str(k): str(v) for k, v in dict(cookies).items()})


def _freeze_metadata(metadata: Any) -> MappingProxyType[str, Any]:
    """Freeze metadata mapping and nested descendants recursively."""
    if metadata is None:
        return MappingProxyType({})
    if isinstance(metadata, Mapping):
        return MappingProxyType({k: _freeze_value(v) for k, v in metadata.items()})
    return MappingProxyType({k: _freeze_value(v) for k, v in dict(metadata).items()})


class _FakeRaw(io.BytesIO):
    """Raw stream adapter mimicking urllib3.response.HTTPResponse for requests."""

    def __init__(
        self,
        body: bytes,
        headers: Mapping[str, Any],
        status: int = 200,
        reason: str = "OK",
    ) -> None:
        super().__init__(body)
        self._body = body
        self.status = status
        self.reason = reason
        self._closed = False
        msg = http.client.HTTPMessage()
        for k, v in headers.items():
            if isinstance(v, (list, tuple)):
                for item in v:
                    msg.add_header(k, str(item))
            else:
                msg.add_header(k, str(v))
        self.headers = msg
        self._original_response = self

    @property
    def msg(self) -> http.client.HTTPMessage:
        return self.headers

    def isclosed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True
        super().close()

    def release_conn(self) -> None:
        pass

    def stream(self, chunk_size: int | None = None, decode_content: bool = False):
        while True:
            chunk = self.read(chunk_size or 8192)
            if not chunk:
                break
            yield chunk


@dataclass(frozen=True, slots=True)
class Reply:
    """Immutable canned HTTP response specification.

    Validity and cookie eligibility are declared independently of production
    parsing to allow oracle evaluation without relying on production policy.
    Nested mappings (headers, cookies, metadata) are deeply frozen via MappingProxyType.
    """

    reply_id: str
    status_code: int = 200
    headers: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    body: str | bytes = ""
    cookies: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    valid: bool = True
    cookie_eligible: bool = True
    metadata: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", _freeze_headers(self.headers))
        object.__setattr__(self, "cookies", _freeze_cookies(self.cookies))
        object.__setattr__(self, "metadata", _freeze_metadata(getattr(self, "metadata", None)))

    @classmethod
    def ok(
        cls,
        body: str | bytes = "",
        *,
        headers: Mapping[str, Any] | None = None,
        cookies: Mapping[str, str] | None = None,
        reply_id: str | None = None,
        valid: bool = True,
        cookie_eligible: bool = True,
        metadata: Mapping[str, Any] | None = None,
    ) -> Reply:
        """Convenience constructor for a 200 OK canned response."""
        rid = (
            reply_id or f"SYNTH_REP_{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:12]}"
        )
        return cls(
            reply_id=rid,
            status_code=200,
            headers=headers,
            body=body,
            cookies=cookies,
            valid=valid,
            cookie_eligible=cookie_eligible,
            metadata=metadata,
        )

    @classmethod
    def json(
        cls,
        data: Any,
        status_code: int = 200,
        *,
        headers: Mapping[str, Any] | None = None,
        cookies: Mapping[str, str] | None = None,
        reply_id: str | None = None,
        valid: bool = True,
        cookie_eligible: bool = True,
        metadata: Mapping[str, Any] | None = None,
    ) -> Reply:
        """Convenience constructor for a JSON canned response."""
        body = json.dumps(data)
        hdrs = dict(headers or {})
        hdrs.setdefault("Content-Type", "application/json")
        rid = (
            reply_id or f"SYNTH_REP_{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:12]}"
        )
        return cls(
            reply_id=rid,
            status_code=status_code,
            headers=hdrs,
            body=body,
            cookies=cookies,
            valid=valid,
            cookie_eligible=cookie_eligible,
            metadata=metadata,
        )

    @classmethod
    def redirect(
        cls,
        location: str,
        status_code: int = 302,
        *,
        headers: Mapping[str, Any] | None = None,
        cookies: Mapping[str, str] | None = None,
        body: str | bytes = "Redirecting",
        reply_id: str | None = None,
        valid: bool = True,
        cookie_eligible: bool = True,
        metadata: Mapping[str, Any] | None = None,
    ) -> Reply:
        """Convenience constructor for a redirect canned response."""
        hdrs = dict(headers or {})
        hdrs["Location"] = location
        rid = (
            reply_id or f"SYNTH_REP_{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:12]}"
        )
        return cls(
            reply_id=rid,
            status_code=status_code,
            headers=hdrs,
            body=body,
            cookies=cookies,
            valid=valid,
            cookie_eligible=cookie_eligible,
            metadata=metadata,
        )


@dataclass(frozen=True, slots=True)
class Dispatch:
    """Immutable observed request record.

    Note: Request body plaintext is NEVER stored; only its SHA-256 digest
    is retained to guarantee privacy and prevent credential leaks.
    Nested mappings (headers, cookies, metadata) are deeply frozen via MappingProxyType.
    """

    generation_id: str
    sequence: int
    method: str
    url: str
    headers: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    body_digest: str | None = None
    cookies: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    timestamp: float = 0.0
    is_after_retire: bool = False
    is_redirect_hop: bool = False
    reply_id: str | None = None
    status_code: int | None = None
    elapsed: float = 0.0
    error: str | None = None
    outcome: str | None = None
    hop_cause: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", _freeze_headers(self.headers))
        object.__setattr__(self, "cookies", _freeze_cookies(self.cookies))
        object.__setattr__(self, "metadata", _freeze_metadata(getattr(self, "metadata", None)))


class Gate:
    """Bounded synchronization gate for deterministic boundary testing.

    Enforces bounded waits (default 10s) with clear failure messages,
    clean worker drainage during teardown, and no ordering sleeps.
    """

    def __init__(self, name: str, default_timeout: float = 10.0) -> None:
        self.name = name
        self.default_timeout = default_timeout
        self._arrived = threading.Event()
        self._proceed = threading.Event()
        self._proceed.set()  # Default open unless hold() is invoked
        self._hold = False
        self._hit_count = 0
        self._lock = threading.Lock()

    def hold(self) -> None:
        """Pause any worker arriving at this gate until proceed() is called."""
        with self._lock:
            self._hold = True
            self._proceed.clear()

    def proceed(self) -> None:
        """Release any workers paused at this gate."""
        with self._lock:
            self._hold = False
            self._proceed.set()

    def arrive_and_wait(self, timeout: float | None = None) -> None:
        """Called by worker/adapter upon reaching the boundary."""
        wait_time = self.default_timeout if timeout is None else timeout
        with self._lock:
            self._hit_count += 1
            self._arrived.set()
        if not self._proceed.wait(timeout=wait_time):
            raise TimeoutError(
                f"Gate '{self.name}' worker hold timed out after {wait_time}s waiting for proceed()"
            )

    def wait_arrived(self, timeout: float | None = None) -> None:
        """Called by test to wait until boundary is reached."""
        wait_time = self.default_timeout if timeout is None else timeout
        if not self._arrived.wait(timeout=wait_time):
            raise TimeoutError(f"Gate '{self.name}' arrival timed out after {wait_time}s")

    def drain(self) -> None:
        """Release all waiters and unhold, for clean teardown."""
        with self._lock:
            self._hold = False
            self._proceed.set()
            self._arrived.set()

    def reset(self) -> None:
        """Reset gate state."""
        with self._lock:
            self._arrived.clear()
            self._proceed.set()
            self._hold = False
            self._hit_count = 0

    @property
    def hit_count(self) -> int:
        with self._lock:
            return self._hit_count

    @property
    def is_arrived(self) -> bool:
        return self._arrived.is_set()


class UnscriptedRouteError(RuntimeError):
    """Raised when an unscripted HTTP route is requested, failing closed locally."""


class ScriptedPortal:
    """Deterministic scripted transport portal for PSE&G and Okta simulation."""

    def __init__(
        self,
        portal_base_url: str = DEFAULT_PORTAL_BASE_URL,
        okta_base_url: str = DEFAULT_OKTA_BASE_URL,
    ) -> None:
        self.portal_base_url = portal_base_url.rstrip("/")
        self.okta_base_url = okta_base_url.rstrip("/")
        self._scripts: dict[Any, list[Reply]] = {}
        self._dispatches: list[Dispatch] = []
        self._recorded_i1_evidence: list[Dispatch] = []
        self._gates: dict[str, Gate] = {}
        self._retired: dict[str, tuple[float, int]] = {}
        self._quarantined_cookies: set[tuple[str, str]] = set()
        self._eligible_cookies: set[tuple[str, str]] = set()
        self._sequence_counter = 0
        self._observers: list[Callable[[Dispatch], Any]] = []
        self._lock = threading.Lock()

    @staticmethod
    def _wrap_session_redirects(session: requests.Session) -> None:
        """Wrap Session.rebuild_method to mark actual redirected PreparedRequest."""
        orig_rebuild = getattr(session, "rebuild_method", None)
        if callable(orig_rebuild) and not getattr(session, "_portal_redirect_wrapped", False):

            def mark_redirect(
                prepared_request: requests.PreparedRequest,
                response: requests.Response,
            ) -> None:
                orig_rebuild(prepared_request, response)
                prepared_request._is_redirect_hop = True
                dispatch_seq = getattr(response, "_portal_dispatch_seq", None)
                if dispatch_seq is not None:
                    prepared_request._redirect_origin_dispatch_id = dispatch_seq

            session.rebuild_method = mark_redirect
            session._portal_redirect_wrapped = True

    def add_observer(self, observer: Callable[[Dispatch], Any]) -> None:
        """Register an observer callback invoked on every attempted send before response."""
        with self._lock:
            if observer not in self._observers:
                self._observers.append(observer)
                target = getattr(observer, "__self__", observer)
                if hasattr(target, "register_quarantined_cookie"):
                    for k, v in self._quarantined_cookies:
                        target.register_quarantined_cookie(k, v)
                if hasattr(target, "register_eligible_cookie"):
                    for k, v in self._eligible_cookies:
                        target.register_eligible_cookie(k, v)
                if hasattr(target, "retire_generation"):
                    for t in self._retired:
                        if t != "*":
                            target.retire_generation(t)

    def remove_observer(self, observer: Callable[[Dispatch], Any]) -> None:
        """Unregister an observer callback."""
        with self._lock:
            if observer in self._observers:
                self._observers.remove(observer)

    def mount_on(
        self,
        session: requests.Session,
        generation_id: str = "gen_default",
    ) -> None:
        """Mount this portal's adapter view onto a requests.Session."""
        self._wrap_session_redirects(session)
        adapter = PortalViewAdapter(self, generation_id=generation_id)
        session.mount(self.portal_base_url, adapter)
        session.mount(self.okta_base_url, adapter)

    @staticmethod
    def _copy_dispatch(d: Dispatch) -> Dispatch:
        return dataclasses.replace(d)

    @staticmethod
    def _copy_reply(r: Reply) -> Reply:
        return dataclasses.replace(r)

    def script(
        self,
        route: str | tuple[str, str],
        reply_or_replies: Reply | Sequence[Reply],
    ) -> None:
        """Script ordered canned responses for a route.

        Route can be:
        - URL path (e.g. "/Dashboard" or "/Home/Login")
        - Full URL (e.g. "https://myaccount.pseg.com/Dashboard")
        - Method and route tuple (e.g. ("POST", "/Home/Login"))
        """
        replies = (
            list(reply_or_replies)
            if isinstance(reply_or_replies, (list, tuple))
            else [reply_or_replies]
        )
        copied_replies = [self._copy_reply(r) for r in replies]
        norm_key = self._normalize_route_key(route)
        with self._lock:
            self._scripts.setdefault(norm_key, []).extend(copied_replies)

    def _normalize_route_key(self, route: Any) -> Any:
        if isinstance(route, tuple):
            method, target = route
            return (method.upper(), self._normalize_target(target))
        return self._normalize_target(route)

    def _normalize_target(self, target: str) -> str:
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urllib.parse.urlparse(target)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if not target.startswith("/"):
            return f"/{target}"
        return target

    def _match_reply(self, method: str, url: str) -> Reply:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        canonical_url = f"{parsed.scheme}://{parsed.netloc}{path}"

        candidates = [
            (method.upper(), canonical_url),
            (method.upper(), path),
            canonical_url,
            path,
        ]

        with self._lock:
            for c in candidates:
                if c in self._scripts and self._scripts[c]:
                    if len(self._scripts[c]) > 1:
                        return self._copy_reply(self._scripts[c].pop(0))
                    return self._copy_reply(self._scripts[c][0])

        raise UnscriptedRouteError(
            f"Unscripted request fails closed locally: method={method} url={url} "
            f"(canonical={canonical_url}, path={path})"
        )

    def gate(self, name: str, timeout: float = 10.0) -> Gate:
        """Get or create a named boundary gate."""
        with self._lock:
            if name not in self._gates:
                self._gates[name] = Gate(name, default_timeout=timeout)
            return self._gates[name]

    def retire(self, generation_id: str | None = None) -> None:
        """Mark a client generation as retired."""
        target = generation_id or "*"
        with self._lock:
            self._retired[target] = (time.time(), self._sequence_counter)
            observers = list(self._observers)
        for obs in observers:
            target = getattr(obs, "__self__", obs)
            if hasattr(target, "retire_generation") and generation_id:
                target.retire_generation(generation_id)

    def is_retired(self, generation_id: str) -> bool:
        with self._lock:
            return generation_id in self._retired or "*" in self._retired

    def get_retirement(self, generation_id: str) -> tuple[float, int] | None:
        with self._lock:
            return self._retired.get(generation_id) or self._retired.get("*")

    @property
    def dispatches(self) -> list[Dispatch]:
        with self._lock:
            return [self._copy_dispatch(d) for d in self._dispatches]

    @property
    def recorded_i1_evidence(self) -> list[Dispatch]:
        with self._lock:
            return [self._copy_dispatch(d) for d in self._recorded_i1_evidence]

    def dispatches_for(self, generation_id: str) -> list[Dispatch]:
        with self._lock:
            return [
                self._copy_dispatch(d) for d in self._dispatches if d.generation_id == generation_id
            ]

    def drain(self) -> None:
        """Drain and release all boundary gates for clean teardown."""
        with self._lock:
            for g in self._gates.values():
                g.drain()

    def reset(self) -> None:
        """Reset scripts, dispatches, gates and retirements."""
        with self._lock:
            self._scripts.clear()
            self._dispatches.clear()
            self._recorded_i1_evidence.clear()
            self._retired.clear()
            self._sequence_counter = 0
            for g in self._gates.values():
                g.reset()

    def _determine_redirect_hop(
        self,
        request: requests.PreparedRequest,
        generation_id: str,
        url: str,
    ) -> tuple[bool, str | None]:
        explicit_hop = bool(getattr(request, "_is_redirect_hop", False))
        origin_seq = getattr(request, "_redirect_origin_dispatch_id", None)
        if explicit_hop:
            cause = f"redirect:{origin_seq}" if origin_seq is not None else "redirect"
            return True, cause
        return False, None

    def _update_dispatch(self, old: Dispatch, new: Dispatch) -> None:
        with self._lock:
            for idx, d in enumerate(self._dispatches):
                if d.sequence == old.sequence:
                    self._dispatches[idx] = new
                    break
            for idx, d in enumerate(self._recorded_i1_evidence):
                if d.sequence == old.sequence:
                    self._recorded_i1_evidence[idx] = new
                    break

    def handle_send(
        self,
        generation_id: str,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
    ) -> requests.Response:
        start_time = time.time()
        url = request.url or ""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"

        with self._lock:
            self._sequence_counter += 1
            seq = self._sequence_counter
            is_after_retire = generation_id in self._retired or "*" in self._retired

        is_redirect_hop, hop_cause = self._determine_redirect_hop(request, generation_id, url)

        # Body digest: SHA-256 only; never retain plaintext body
        body_digest: str | None = None
        if request.body is not None:
            if isinstance(request.body, str):
                body_digest = hashlib.sha256(request.body.encode("utf-8")).hexdigest()
            elif isinstance(request.body, bytes):
                body_digest = hashlib.sha256(request.body).hexdigest()
            else:
                body_digest = hashlib.sha256(bytes(request.body)).hexdigest()

        # Extract request cookies
        req_cookies: dict[str, str] = {}
        cookie_header = request.headers.get("Cookie")
        if cookie_header:
            for part in cookie_header.split(";"):
                if "=" in part:
                    cname, cval = part.strip().split("=", 1)
                    req_cookies[cname.strip()] = cval.strip()

        # Immutable initial record of the attempted send registered BEFORE gates and matching
        dispatch = Dispatch(
            generation_id=generation_id,
            sequence=seq,
            method=(request.method or "GET").upper(),
            url=url,
            headers=dict(request.headers),
            body_digest=body_digest,
            cookies=req_cookies,
            timestamp=start_time,
            is_after_retire=is_after_retire,
            is_redirect_hop=is_redirect_hop,
            hop_cause=hop_cause,
            reply_id=None,
            status_code=None,
            elapsed=0.0,
            error=None,
            outcome="pending",
        )

        with self._lock:
            self._dispatches.append(dispatch)
            if is_after_retire:
                self._recorded_i1_evidence.append(dispatch)
            observers = list(self._observers)

        for obs in observers:
            try:
                obs(dispatch)
            except TypeError:
                obs(self, dispatch)

        try:
            # Check before_send boundary gates
            self._trigger_gates("before_send", request.method, url, path)

            # Match scripted reply (fails closed locally if unscripted)
            reply = self._match_reply(request.method or "GET", url)

            # Metadata propagation to observers (quarantined vs eligible cookies)
            if reply.valid is False or reply.cookie_eligible is False:
                extracted_quarantined: list[tuple[str, str]] = []
                for k, v in (reply.cookies or {}).items():
                    extracted_quarantined.append((k, str(v)))
                set_cookie = (reply.headers or {}).get("Set-Cookie")
                if set_cookie:
                    for part in set_cookie.split(";"):
                        if "=" in part:
                            ck, cv = part.strip().split("=", 1)
                            extracted_quarantined.append((ck.strip(), cv.strip()))
                with self._lock:
                    self._quarantined_cookies.update(extracted_quarantined)
                    obs_list = list(self._observers)
                for obs in obs_list:
                    target = getattr(obs, "__self__", obs)
                    if hasattr(target, "register_quarantined_cookie"):
                        for ck, cv in extracted_quarantined:
                            target.register_quarantined_cookie(ck, cv)
            elif reply.valid is True and reply.cookie_eligible is True:
                extracted_eligible: list[tuple[str, str]] = []
                for k, v in (reply.cookies or {}).items():
                    extracted_eligible.append((k, str(v)))
                with self._lock:
                    self._eligible_cookies.update(extracted_eligible)
                    obs_list = list(self._observers)
                for obs in obs_list:
                    target = getattr(obs, "__self__", obs)
                    if hasattr(target, "register_eligible_cookie"):
                        for ck, cv in extracted_eligible:
                            target.register_eligible_cookie(ck, cv)

            # Convert Reply to real requests.Response
            resp = self._build_response(request, reply)
            resp._portal_dispatch_seq = dispatch.sequence

            elapsed = time.time() - start_time
            completed_dispatch = dataclasses.replace(
                dispatch,
                reply_id=reply.reply_id,
                status_code=reply.status_code,
                elapsed=elapsed,
                error=None,
                outcome=reply.reply_id,
            )
            self._update_dispatch(dispatch, completed_dispatch)

            # Check after_send boundary gates
            self._trigger_gates("after_send", request.method, url, path)

            return resp

        except UnscriptedRouteError as exc:
            elapsed = time.time() - start_time
            failed_dispatch = dataclasses.replace(
                dispatch,
                elapsed=elapsed,
                error=str(exc),
                outcome="unscripted",
            )
            self._update_dispatch(dispatch, failed_dispatch)
            raise

        except TimeoutError as exc:
            elapsed = time.time() - start_time
            failed_dispatch = dataclasses.replace(
                dispatch,
                elapsed=elapsed,
                error=str(exc),
                outcome="gated",
            )
            self._update_dispatch(dispatch, failed_dispatch)
            raise

        except BaseException as exc:
            elapsed = time.time() - start_time
            failed_dispatch = dataclasses.replace(
                dispatch,
                elapsed=elapsed,
                error=str(exc),
                outcome=f"error: {type(exc).__name__}",
            )
            self._update_dispatch(dispatch, failed_dispatch)
            raise

    def _build_response(
        self,
        request: requests.PreparedRequest,
        reply: Reply,
    ) -> requests.Response:
        resp = requests.Response()
        resp.status_code = reply.status_code
        resp.reason = http.client.responses.get(reply.status_code, "OK")
        resp.url = request.url

        headers_dict: dict[str, Any] = dict(reply.headers)
        if reply.cookies:
            existing_set_cookies = []
            for k, v in reply.headers.items():
                if k.lower() == "set-cookie":
                    if isinstance(v, (list, tuple)):
                        existing_set_cookies.extend(v)
                    else:
                        existing_set_cookies.append(v)
            new_set_cookies = list(existing_set_cookies)
            for cname, cval in reply.cookies.items():
                cookie_str = f"{cname}={cval}; Path=/"
                new_set_cookies.append(cookie_str)
            headers_dict["Set-Cookie"] = tuple(new_set_cookies)

        resp.headers = CaseInsensitiveDict(
            {
                k: (
                    tuple(v)
                    if isinstance(v, (list, tuple)) and (len(v) > 1 or k.lower() == "set-cookie")
                    else (
                        v[0]
                        if isinstance(v, (list, tuple)) and len(v) == 1
                        else (tuple(v) if isinstance(v, (list, tuple)) else str(v))
                    )
                )
                for k, v in headers_dict.items()
            }
        )

        body_bytes = reply.body.encode("utf-8") if isinstance(reply.body, str) else reply.body

        raw = _FakeRaw(body_bytes, headers_dict, status=reply.status_code, reason=resp.reason)
        resp.raw = raw
        resp.request = request

        # Extract cookies into resp.cookies using requests cookiejar logic
        extract_cookies_to_jar(resp.cookies, request, raw)

        return resp

    def _trigger_gates(
        self,
        phase: str,
        method: str | None,
        url: str,
        path: str,
    ) -> None:
        m = (method or "GET").upper()
        candidates = [
            phase,
            f"{phase}:{m}",
            f"{phase}:{url}",
            f"{phase}:{path}",
            f"{phase}:{m}:{path}",
        ]
        with self._lock:
            matched_gates = [self._gates[c] for c in candidates if c in self._gates]

        for g in matched_gates:
            g.arrive_and_wait()


class PortalViewAdapter(BaseAdapter):
    """requests.adapters.BaseAdapter view bound to a specific client generation."""

    def __init__(self, portal: ScriptedPortal, generation_id: str) -> None:
        super().__init__()
        self.portal = portal
        self.generation_id = generation_id

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: Any = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> requests.Response:
        return self.portal.handle_send(
            self.generation_id,
            request,
            stream=stream,
            timeout=timeout,
        )

    def close(self) -> None:
        pass

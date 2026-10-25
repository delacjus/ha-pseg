"""PSE&G API Client for Home Assistant (New Jersey).

Uses domain-scoped session cookies to communicate directly with PSE&G MySmartEnergy portal
and Okta SAML SSO endpoints.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
import copy
from datetime import UTC, date, datetime, timedelta
import functools
import hashlib
import json
import logging
import math
import re
import threading
import time
from typing import Any
import urllib.parse

from bs4 import BeautifulSoup
import requests

from .const import (
    ALLOWED_HOSTS,
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_OKTA_SESSION_EXPIRED,
    AUTH_REASON_PORTAL_SESSION_EXPIRED,
    AUTH_REASON_REMEMBER_ME_REJECTED,
    AUTH_REASON_SECURITY_STEP,
    DEFAULT_METER_NAME,
    DEFAULT_PRICE_PER_KWH,
    OKTA_HOST,
    PORTAL_BASE_URL,
    PORTAL_HOST,
    REMEMBER_ME_COOKIE,
    STATISTICS_PRECISION,
    USAGE_INTERVAL_DAILY,
    USAGE_INTERVAL_HOURLY,
)
from .renewal_admission import RenewalAdmission
from .statistics_hourly import (
    LABEL_TOLERANCE_SECONDS,
    label_matches_ny_time,
    ny_day_bounds,
    ny_day_of,
    ny_wall_ms_to_utc,
    parse_aware_label,
    parse_date_only_label,
    validate_hourly_days,
)

_LOGGER = logging.getLogger(__name__)
_METER_SERIES = re.compile(r"^\s*Meter #(\d+)")

# Hourly ChartData timestamp contract: x is the America/New_York wall-clock
# time of the hour start, encoded as UTC epoch milliseconds (e.g. midnight local
# encoded as midnight UTC). Validated live across 312 points (Oct 10-22, 2026):
# against 15-minute portal CSV data, 0/288 mismatched hours; daily sums matched
# PSEG app daily totals exactly across 9/9 days (Oct 10-18, 2026).
# Date-only proof requires both start and end labels to be strict MM/DD/YYYY.
HOURLY_X_CONTRACT = "ny_wall_clock_hour_start"


def _parse_iso_day(value: Any) -> date | None:
    """Parse a chart day label, returning None instead of raising."""
    try:
        return date.fromisoformat(str(value))
    except TypeError, ValueError:
        return None


class _MeterRecord(dict):
    """Parsed usage record carrying per-record contributing meter provenance."""

    __slots__ = ("contributing_meter_ids",)

    def __init__(
        self,
        *args: Any,
        contributing_meter_ids: Iterable[str] = (),
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.contributing_meter_ids: tuple[str, ...] = tuple(
            str(m) for m in contributing_meter_ids if m
        )

    def __copy__(self) -> _MeterRecord:
        return _MeterRecord(self, contributing_meter_ids=self.contributing_meter_ids)

    def __deepcopy__(self, memo: Any) -> _MeterRecord:
        return _MeterRecord(
            {copy.deepcopy(k, memo): copy.deepcopy(v, memo) for k, v in self.items()},
            contributing_meter_ids=self.contributing_meter_ids,
        )


def _record_contributing_meters(record: Any) -> tuple[str, ...]:
    """Extract parser-built contributing meter ids from one validated record.

    Only the parser's own :class:`_MeterRecord` carries provenance. A plain dict,
    a serialized copy, or a server-supplied ``meter_id``/``meter_ids`` field is
    data, not proof, and must never stand in for a validated contributing meter.
    """
    if not isinstance(record, _MeterRecord):
        return ()
    return tuple(str(m) for m in record.contributing_meter_ids if m)


def _series_shape_anomalies(series_list: Iterable[Any]) -> int:
    """Count non-meter series whose ``data`` is present but not a list.

    Such telemetry is skipped and never feeds readings, but it still marks the
    response as contract-violating, so no caller may use that response to confirm
    or rotate the cookie jar (readings prove the meter; the envelope is broken).
    """
    count = 0
    for series in series_list or ():
        if not isinstance(series, dict):
            continue
        if _METER_SERIES.match(str(series.get("name") or "")):
            continue
        data = series.get("data")
        if data is not None and not isinstance(data, list):
            count += 1
    return count


def _contributing_meter_ids(records: Iterable[Any]) -> list[str]:
    """Return ordered unique meter ids that contributed >=1 valid parsed record."""
    seen: list[str] = []
    for record in records or ():
        for meter_id in _record_contributing_meters(record):
            if meter_id not in seen:
                seen.append(meter_id)
    return seen


# Path fragments that mean "you were sent to sign in" (portal or Okta).
_SIGNIN_PATH_MARKERS = ("/signin", "/sign-in", "/login")
# Portal paths that mean the request was bounced into the SSO handshake.
_LOGIN_PATH_MARKERS = (*_SIGNIN_PATH_MARKERS, "/saml/")
# Okta Identity Engine sign-in widget markers (case-sensitive JS identifiers).
_OKTA_WIDGET_MARKERS = ("OktaSignIn", "stateToken")
# MyMeter's anonymous home page renders its local login form (live 2026-10-21).
_PORTAL_LOGIN_FORM_MARKERS = ('name="LoginEmail"', 'id="LoginPassword"')
# The portal names the CAPTCHA in its login error (live 2026-10-22, real account):
# "Please provide a valid login captcha."
_CAPTCHA_ERROR_MARKER = "captcha"
_CAPTCHA_ERROR_PHRASE = "please provide a valid login captcha"


class PsegError(Exception):
    """Base exception for PSE&G errors."""


class PsegSecurityError(PsegError):
    """Exception raised when an unauthorized host or security restriction is violated."""


class PsegAuthError(PsegError):
    """Base exception for authentication failures."""


class PsegOktaSessionExpired(PsegAuthError):
    """Exception raised when Okta session is expired and requires user re-authentication."""


class PsegLoginRejected(PsegOktaSessionExpired):
    """MyMeter email/password login refused (bad password or another refused sign-in)."""


class PsegLoginRedirected(PsegLoginRejected):
    """MyMeter answered the local login with a redirect instead of accepting it.

    The saved MyMeter email/password belongs to the portal's own form, so a redirect
    (in particular to the Okta host) is refused rather than followed: following it
    would forward the password body to another origin. The message never includes
    the raw Location header.
    """


class PsegCaptchaRequired(PsegLoginRejected):
    """MyMeter refused the sign-in because it wants a human-solved CAPTCHA.

    Raised only when the server itself names the CAPTCHA (the ``RecaptchaOnLogin``
    flag or a "captcha" error message), so a wrong password is never mislabelled.
    The proof is single-use and only the config flow's human step can supply one.
    """


class PsegSecurityStepRequired(PsegLoginRejected):
    """MyMeter asked for a security question or a password change.

    Home Assistant cannot answer those, so the user has to finish the sign-in in a
    browser; this is never treated as a solvable CAPTCHA.
    """


class PsegTransientError(PsegError):
    """Exception raised for transient network/server errors (timeouts, 5xx, connection)."""


class PsegRenewalDeferred(PsegError):
    """The shared admission refused another cookie-renewal sequence.

    Not a ``PsegAuthError``: no new authentication failure happened. ``reason`` is
    one of ``cooldown``, ``exhausted``, ``terminal`` or ``no_cookie`` and
    ``terminal`` carries the recorded fixed reason (never a cookie or body).
    """

    def __init__(self, reason: str, terminal: str | None = None) -> None:
        """Keep the machine-readable reason for the caller's policy decision."""
        super().__init__(reason)
        self.reason = reason
        self.terminal = terminal


class AllowlistedSession(requests.Session):
    """Requests session that enforces a host allowlist on every request and redirect."""

    def __init__(self, owner_check: Callable[[], None] | None = None) -> None:
        """Start with both PSE&G hosts; the client narrows this for local logins."""
        super().__init__()
        self.allowed_hosts: frozenset[str] = frozenset(ALLOWED_HOSTS)
        self.trace: list[str] = []
        self._owner_check = owner_check

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        # Runs for the first request and every redirect hop (resolve_redirects calls
        # send), before the cookie-bearing request leaves the process.
        if self._owner_check is not None:
            self._owner_check()
        parsed = urllib.parse.urlparse(request.url)
        if parsed.hostname not in self.allowed_hosts:
            raise PsegSecurityError(
                f"Request to unauthorized host blocked: {parsed.hostname or request.url}"
            )
        if parsed.scheme != "https":
            raise PsegSecurityError(
                f"Request to {parsed.hostname} blocked: scheme {parsed.scheme!r} is not https"
            )
        # Parse the port outside any handler: raising from inside `except ValueError`
        # would chain the raw URL text as __context__, even with `from None`.
        invalid_port = False
        try:
            port = parsed.port
        except ValueError:
            invalid_port = True
        if invalid_port:
            raise PsegSecurityError(f"Request to {parsed.hostname} blocked: bad port")
        if port not in (None, 443):
            raise PsegSecurityError(f"Request to {parsed.hostname} blocked: port {port}")
        resp = super().send(request, **kwargs)
        # Diagnostics only: host/path/status of each hop, never queries or cookies.
        # First path segment only: deeper segments could carry ids or tokens.
        route = "/" + parsed.path.strip("/").split("/", 1)[0]
        set_names = (
            sorted({h.split("=", 1)[0].strip() for h in resp.raw.headers.getlist("Set-Cookie")})
            if hasattr(getattr(resp, "raw", None), "headers")
            and hasattr(resp.raw.headers, "getlist")
            else []
        )
        self.trace.append(
            f"{request.method} {parsed.hostname}{route} -> {resp.status_code}"
            + (f" sets={set_names}" if set_names else "")
        )
        del self.trace[:-20]
        return resp


def _locked[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    """Serialize a PsegClient method on the client's re-entrant portal lock.

    MyMeter keeps the selected chart range in the server-side session (POST
    /Dashboard/Chart, then GET /Dashboard/ChartData), and every request shares one
    cookie jar. Poll, keepalive, backfill and the refresh button run in different
    executor threads, so each portal operation must run to completion before
    another starts or one caller reads the other's chart range.
    """

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        self = args[0]
        with self._lock:  # type: ignore[attr-defined]
            return func(*args, **kwargs)

    return wrapper


class PsegClient:
    """Client for PSE&G MySmartEnergy portal."""

    def __init__(
        self,
        okta_cookies: str = "",
        portal_cookies: str = "",
        cookie_list: list[dict[str, Any]] | None = None,
        price_per_kwh: float = DEFAULT_PRICE_PER_KWH,
        email: str = "",
        password: str = "",
    ) -> None:
        """Initialize the client with domain-scoped cookies."""
        self._lock = threading.RLock()
        self.session = AllowlistedSession(owner_check=self._check_active_owner)
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{PORTAL_BASE_URL}/Dashboard",
            }
        )
        self.price_per_kwh = price_per_kwh
        # MyMeter local login. Never logged; only sent to PORTAL_HOST/Home/Login.
        self._email = email.strip()
        self._password = password
        # Local sign-in mode stays on the portal: a saved MyMeter email/password is
        # never sent to PSE&G's Okta host, and no local request may follow a redirect
        # there (no silent SSO fallback, no Okta 2FA). Legacy cookie/SAML clients
        # keep both hosts for the explicit Okta path.
        if self.has_login:
            self.session.allowed_hosts = frozenset({PORTAL_HOST})
        # Antiforgery token for a human CAPTCHA proof, held in memory only.
        self._pending_login_token = ""
        # Set when MyMeter demands a CAPTCHA. No automatic /Home/Login POST may run
        # again until a human sign-in succeeds (config flow) or a reauth/reconfigure
        # builds a new client, so a background timer can never hammer the form.
        self._captcha_latched = False
        # Set when MyMeter asks for a security question or a password change. Like the
        # CAPTCHA latch it stops every automatic sign-in and cookie renewal (the poll's
        # fallback included) until a confirmed sign-in clears it, so a background
        # timer can never retry a form Home Assistant cannot answer.
        self._security_step_latched = False
        # True only while keepalive() runs: the timer may validate/renew with GETs
        # but must never POST the saved email/password.
        self._in_keepalive = False
        # Shared, non-secret admission for cookie renewals. The coordinator replaces
        # this with the state persisted in the entry so the poll, the keepalive and an
        # options reload all spend the same budget. A standalone client still gets a
        # local budget: an uncertain admission must never allow duplicate sequences.
        self._renewal_admission = RenewalAdmission()
        self._renewal_runtime: Any | None = None
        self._renewal_token: int | None = None
        # Meter ids this entry already owns (the account-identity guard for a
        # keepalive renewal). Set by the coordinator from entry data; not a secret.
        self._expected_meter_ids: frozenset[str] = frozenset()
        # True only on a human config-flow client: an unattached sign-in may name its
        # meter from the authenticated payload's `Meter #N` labels when the window's
        # usage is not published yet (vendor lag), but that read never confirms
        # cookies and never publishes readings or statistics.
        self._allow_label_identity = False
        # MM_RememberMe values confirmed in this client, held in memory only, to
        # detect a server rotation. Never exported, persisted, logged or compared by
        # hash anywhere outside this process. Filled after the jar is seeded below.
        self._remember_me_seen: frozenset[str] = frozenset()
        # False after a failed renewal rolled the jar back: the coordinator must not
        # persist an unconfirmed transaction.
        self.cookies_confirmed = True
        # Passive in-memory hourly contract sample for diagnostic inspection and
        # offline contract verification.
        self._hourly_contract_sample: dict[str, Any] | None = None
        self._cost_contract_samples: dict[str, Any] = {}
        self._consumed_permits: set[str] = set()
        self._meter_placeholders: dict[str, str] = {}
        # Immutable jar captured at the exact moment a renewal or sign-in was
        # confirmed (Dashboard plus meter proof where required). The coordinator
        # persists THIS snapshot on every failure/unload exit, so a later failed
        # response's Set-Cookie can never replace the jar the portal verified.
        # In-memory only, value-free outside the client, never logged.
        self._checkpoint_lock = threading.Lock()
        self._confirmed_snapshot: dict[str, Any] | None = None
        self._confirmed_snapshot_seq = 0
        self._confirmed_cookies: list[dict[str, Any]] | None = None

        # Session telemetry
        self.session_established_at: str | None = None
        self.last_sso_renewal: str | None = None
        self.sso_renewals: int = 0
        self.last_keepalive: str | None = None
        self.okta_session_expired_at: str | None = None
        # Typed auth failure reason (see AUTH_REASON_* in const); None while healthy.
        self.auth_reason: str | None = None
        # Seconds between the last confirmed portal request and the first failure of an
        # episode; a diagnostic, not a measurement of any vendor timeout.
        self.idle_gap_seconds: float | None = None
        self.last_portal_success_at: str | None = None
        self._last_success_monotonic: float | None = None

        # The persisted jar (server-rotated cookies) is authoritative. The pasted header
        # strings stay in entry.data unchanged, so applying them on top would restore
        # stale idx/MM_SID values on every restart. They only seed a jar that has never
        # been persisted; reauth/reconfigure replace the persisted jar outright.
        if cookie_list:
            self.import_cookies(cookie_list)
        else:
            if okta_cookies:
                self.set_cookies_from_header(okta_cookies, OKTA_HOST)
            if portal_cookies:
                self.set_cookies_from_header(portal_cookies, PORTAL_HOST)
        # Values present at construction (pasted or restored). Only a host-only
        # copy still holding its seeded value can be stale; see _dedupe_domain_variants.
        self._seeded = {(c.name, c.domain, c.path): c.value for c in self.session.cookies}
        # The generation this client starts with: a verified renewal that rotates the
        # cookie (value changes, in memory only) rearms the admission budget.
        self._remember_me_seen = self._remember_me_values()

    @_locked
    def set_cookies_from_header(self, cookie_header: str, domain: str) -> None:
        """Parse a Cookie header string (name=val; name2=val2) into the domain-scoped jar."""
        if not cookie_header:
            return
        parts = cookie_header.split(";")
        for part in parts:
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, val = part.split("=", 1)
            name = name.strip()
            val = val.strip()
            if name:
                self.session.cookies.set(name, val, domain=domain, path="/", secure=True)

    def _dedupe_domain_variants(self) -> None:
        """Keep one copy when a cookie exists both host-only and as '.host'.

        Pasted cookies are stored host-only; the portal or Okta may later set the
        same name with Domain=.host (e.g. a rotated MM_RememberMe or idx). Both
        would be sent and persisted, old value first. "Newer" = changed since
        construction (_seeded): the copy that changed wins and the other is
        dropped. If both changed, the dotted (server-set) copy wins. If neither
        changed, both are left as they were seeded.
        """
        jar = self.session.cookies
        seeded = getattr(self, "_seeded", {})
        by_key: dict[tuple[str, str, str], dict[bool, Any]] = {}
        for c in jar:
            dotted = (c.domain or "").startswith(".")
            by_key.setdefault((c.name, (c.domain or "").lstrip("."), c.path), {})[dotted] = c
        for pair in by_key.values():
            if len(pair) < 2:
                continue
            host, dot = pair[False], pair[True]
            host_changed = seeded.get((host.name, host.domain, host.path)) != host.value
            dot_changed = seeded.get((dot.name, dot.domain, dot.path)) != dot.value
            if host_changed and not dot_changed:
                jar.clear(dot.domain, dot.path, dot.name)
            elif dot_changed:
                jar.clear(host.domain, host.path, host.name)

    def _export_cookies_unlocked(self) -> list[dict[str, Any]]:
        """Build the persistence snapshot; caller must hold the client lock."""
        self._dedupe_domain_variants()
        cookie_data = []
        for c in self.session.cookies:
            cookie_data.append(
                {
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                    "secure": c.secure,
                }
            )
        return cookie_data

    @_locked
    def export_cookies(self) -> list[dict[str, Any]]:
        """Export cookies as a list of dicts for persistence."""
        return self._export_cookies_unlocked()

    @_locked
    def export_cookies_and_auth_reason(
        self,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Export the jar and the auth reason from one consistent snapshot.

        The coordinator must never judge a jar with an auth_reason read taken
        before awaiting the export: an overlapping renewal can drop MM_SID and
        set the reason while the export is still queued, and the half-empty jar
        then overwrites the last known-good one. Reading both inside this one
        locked call makes the reason describe exactly the jar returned.
        """
        return self._export_cookies_unlocked(), self.auth_reason

    def _capture_confirmed_session(self) -> None:
        """Freeze the just-verified jar for a later failure exit; caller holds lock.

        The snapshot is immutable and independent of the live cookiejar: a later
        maintenance/4xx/429 response may set its own cookies, and those must never
        be persisted as if the renewal had issued them.
        """
        exported = self._export_cookies_unlocked()
        with self._checkpoint_lock:
            self._confirmed_snapshot_seq += 1
            self._confirmed_cookies = copy.deepcopy(exported)
            self._confirmed_snapshot = {
                "id": self._confirmed_snapshot_seq,
                "cookies": copy.deepcopy(exported),
                "auth_reason": self.auth_reason,
                "cookies_confirmed": self.cookies_confirmed,
            }

    def confirmed_cookies(self) -> list[dict[str, Any]] | None:
        """Return the last confirmed cookie export (or None before any confirmation)."""
        with self._checkpoint_lock:
            return (
                copy.deepcopy(self._confirmed_cookies)
                if self._confirmed_cookies is not None
                else None
            )

    def pending_confirmed_snapshot(self) -> dict[str, Any] | None:
        """Return the last confirmed jar awaiting persistence (reference, read-only).

        Uses only the dedicated metadata lock, never the client network lock:
        callers may be on the event loop while a long backfill holds the portal
        lock. The dict and its list are never mutated after capture.
        """
        with self._checkpoint_lock:
            return self._confirmed_snapshot

    def clear_confirmed_snapshot(self, snapshot_id: int) -> None:
        """Drop the snapshot once its jar is durable; ignore a newer confirmation."""
        with self._checkpoint_lock:
            snapshot = self._confirmed_snapshot
            if snapshot is not None and snapshot["id"] == snapshot_id:
                self._confirmed_snapshot = None

    @_locked
    def import_cookies(self, cookie_list: list[dict[str, Any]]) -> None:
        """Restore cookies from persistence."""
        for c in cookie_list:
            name = c.get("name")
            val = c.get("value")
            domain = c.get("domain", PORTAL_HOST)
            path = c.get("path", "/")
            if name and val:
                self.session.cookies.set(
                    name, val, domain=domain, path=path, secure=bool(c.get("secure", True))
                )

    def _is_login_page(self, resp: requests.Response) -> bool:
        """Return True only on a real logged-out signal.

        Signals: the request ended on Okta, on the portal home page (where MyMeter
        bounces anonymous users), on a sign-in/login/SAML path, got 401/403, or
        rendered the Okta sign-in widget. Page wording such as "login" or "sign in"
        is NOT a signal; the logged-in dashboard contains both (Log out link, scripts).
        """
        parsed = urllib.parse.urlparse(resp.url)
        path = parsed.path.lower()
        if parsed.hostname == OKTA_HOST:
            return True
        # MyMeter's anonymous landing pages (a bounce here means signed out); other
        # off-dashboard pages such as /Maintenance stay transient.
        if path.strip("/") in ("", "home", "home/index"):
            return True
        if any(marker in path for marker in _LOGIN_PATH_MARKERS):
            return True
        if resp.status_code in (401, 403):
            return True
        # Not applied on /Dashboard itself: its logged-in markup is unverified and a
        # false hit there would read every live session as signed out.
        if not path.rstrip("/").endswith("/dashboard") and any(
            marker in resp.text for marker in _PORTAL_LOGIN_FORM_MARKERS
        ):
            return True
        return self._is_okta_widget(resp)

    @staticmethod
    def _is_okta_widget(resp: requests.Response) -> bool:
        """Return True if the response renders the Okta sign-in widget."""
        return any(marker in resp.text for marker in _OKTA_WIDGET_MARKERS)

    def _mark_session_ok(self) -> None:
        """Record a confirmed logged-in portal session."""
        now = datetime.now(UTC)
        if not self.session_established_at:
            self.session_established_at = now.isoformat()
        self.okta_session_expired_at = None
        self.auth_reason = None
        self.idle_gap_seconds = None
        self.last_portal_success_at = now.isoformat()
        self._last_success_monotonic = time.monotonic()
        self.cookies_confirmed = True

    def _seconds_since_last_success(self) -> float | None:
        """Seconds since the last confirmed portal request, or None if unknown."""
        if self._last_success_monotonic is None:
            return None
        return round(time.monotonic() - self._last_success_monotonic, 1)

    def _mark_auth_failure(self, reason: str) -> None:
        """Record the FIRST typed authentication failure of an episode.

        A repeated failure with the same reason is ignored: the timestamp and the
        idle gap then describe the request that first failed, instead of being
        overwritten on every keepalive retry. A different reason starts a new
        episode and replaces both. Only a verified recovery (``_mark_session_ok``)
        or a reason transition clears them.

        Logs the reason and the idle gap only: never a credential, cookie value or
        page body. ``okta_session_expired_at`` is still stamped for compatibility
        with existing automations/attributes, even when the reason is not Okta.
        """
        if reason == AUTH_REASON_SECURITY_STEP:
            # A security question/password change can only be answered by a human:
            # latch it so no later tick retries the form or the cookie renewal.
            self._security_step_latched = True
        if reason in {AUTH_REASON_CAPTCHA_REQUIRED, AUTH_REASON_SECURITY_STEP}:
            self._record_terminal_admission(reason)
        if reason == self.auth_reason:
            return
        self.auth_reason = reason
        self.okta_session_expired_at = datetime.now(UTC).isoformat()
        self.idle_gap_seconds = self._seconds_since_last_success()
        if self.idle_gap_seconds is None:
            _LOGGER.info(
                "PSE&G authentication failed (%s); no successful portal request yet",
                reason,
            )
        else:
            _LOGGER.info(
                "PSE&G authentication failed (%s); last successful portal request %.0f s ago",
                reason,
                self.idle_gap_seconds,
            )

    def _session_expired_reason(self) -> str:
        """Name a lapsed session truthfully: local portal sessions are not Okta."""
        if self.is_local_mode:
            return AUTH_REASON_PORTAL_SESSION_EXPIRED
        return AUTH_REASON_OKTA_SESSION_EXPIRED

    def _latch_captcha(self) -> None:
        """Stop automatic credential POSTs after MyMeter demands a CAPTCHA."""
        self._captcha_latched = True

    def _refuse_if_captcha_latched(self) -> None:
        """Fail fast on a latched CAPTCHA instead of posting the password again."""
        if self._captcha_latched:
            self._mark_auth_failure(AUTH_REASON_CAPTCHA_REQUIRED)
            raise PsegCaptchaRequired(
                "MyMeter is waiting for a solved CAPTCHA; no sign-in was sent"
            )

    def _refuse_if_security_step_latched(self) -> None:
        """Fail closed while MyMeter waits for a human security step.

        The portal asked for a security question or a password change, which Home
        Assistant cannot answer. Raising here stops the poll's automatic fallback,
        the keepalive probe and every cookie renewal until a confirmed sign-in
        (normally the reauth/config flow) clears the latch.
        """
        if self._security_step_latched:
            self._mark_auth_failure(AUTH_REASON_SECURITY_STEP)
            raise PsegSecurityStepRequired(
                "MyMeter is waiting for a security question or password change; "
                "no sign-in or renewal was sent"
            )

    def _record_terminal_admission(self, reason: str) -> None:
        """Mirror a CAPTCHA/security step into the entry's durable admission.

        The in-process latch alone forgot the challenge on reload, so a fresh
        client would post the saved password or spend an earned cookie retry.
        Only a completed human sign-in rearms this terminal state.
        """
        runtime = self._renewal_runtime
        if runtime is not None and self._renewal_token is not None:
            runtime.record_terminal(self._renewal_token, reason)
            return
        self._renewal_admission.record_terminal(reason)

    def _refuse_if_terminal_step(self) -> None:
        """Refuse every automatic attempt while a durable CAPTCHA/security step waits.

        The admission can have been restored from ``entry.data`` by a fresh client
        after an ordinary reload or a process start, so this check must not rely on
        the in-memory latches alone. No HTTP is sent from a background timer.
        """
        terminal = self._renewal_admission.terminal_reason
        if terminal == AUTH_REASON_CAPTCHA_REQUIRED:
            self._captcha_latched = True
            self._mark_auth_failure(terminal)
            raise PsegCaptchaRequired(
                "MyMeter is waiting for a solved CAPTCHA; no automatic sign-in "
                "or renewal was sent until a human signs in"
            )
        if terminal == AUTH_REASON_SECURITY_STEP:
            self._security_step_latched = True
            self._mark_auth_failure(terminal)
            raise PsegSecurityStepRequired(
                "MyMeter is waiting for a security question or password change; "
                "no automatic sign-in or renewal was sent until a human signs in"
            )

    def _raise_post_renewal_logged_out(self, resp: requests.Response) -> None:
        """Classify a still-logged-out /Dashboard right after Okta issued an assertion.

        Okta just proved the session is valid, so only Okta itself (its host or the
        sign-in widget) means "expired". A plain bounce to the portal home page is the
        portal refusing sessions (e.g. maintenance) and is transient.
        """
        if urllib.parse.urlparse(resp.url).hostname == OKTA_HOST or self._is_okta_widget(resp):
            self._mark_auth_failure(AUTH_REASON_OKTA_SESSION_EXPIRED)
            raise PsegOktaSessionExpired("Failed to establish portal session after SAML post")
        raise PsegTransientError("Portal still logged out after SAML post (maintenance?)")

    def _get_dashboard(self, timeout: int = 20) -> requests.Response:
        """GET /Dashboard; network errors, malformed redirects and 5xx are transient."""
        malformed_redirect = False
        try:
            resp = self.session.get(
                f"{PORTAL_BASE_URL}/Dashboard", allow_redirects=True, timeout=timeout
            )
        except PsegSecurityError:
            if self.has_login:
                # A local sign-in may only bounce within the portal; the blocked
                # host is a redirect away from it, so report it as such (host only).
                raise PsegLoginRedirected(
                    "PSE&G redirected the local sign-in away from the portal"
                ) from None
            raise
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error connecting to PSE&G: {err}") from err
        except ValueError:
            # requests parses the server's Location even while following redirects.
            # A malformed target raises ValueError whose text can carry the raw
            # Location; raise a generic transient error outside the handler so it is
            # never chained as __context__/__cause__. This GET carries no proof or
            # credentials, and no retry is attempted here.
            malformed_redirect = True
        if malformed_redirect:
            raise PsegTransientError("PSE&G portal returned an invalid redirect")
        if resp.status_code >= 500:
            raise PsegTransientError(f"PSE&G portal returned HTTP {resp.status_code}")
        return resp

    def auth_diagnostics(self) -> str:
        """Hop trace and cookie NAMES per host (no values) for setup failure logs."""
        names: dict[str, list[str]] = {}
        for c in self.session.cookies:
            names.setdefault(c.domain, []).append(c.name)
        return f"hops={self.session.trace} cookie_names={names}"

    @staticmethod
    def _on_dashboard(resp: requests.Response) -> bool:
        return urllib.parse.urlparse(resp.url).path.lower().rstrip("/").endswith("/dashboard")

    def _has_cookie(self, name: str, host: str) -> bool:
        return any(
            c.name == name and (c.domain or "").lstrip(".") == host for c in self.session.cookies
        )

    @property
    def has_remember_me(self) -> bool:
        """MyMeter local-login 'Remember Me' cookie present (presence only).

        How long the portal honours it is not documented; the integration never
        asserts a lifetime, only whether the cookie is in the jar right now.

        Diagnostics reads this from the event loop, so it never waits for the client
        lock: when a portal operation owns it, one unlocked pass over the jar is made,
        retried only if a concurrent mutation resized the cookiejar mid-iteration.
        """
        if self._lock.acquire(blocking=False):
            try:
                return self._has_cookie(REMEMBER_ME_COOKIE, PORTAL_HOST)
            finally:
                self._lock.release()
        try:
            return self._has_cookie(REMEMBER_ME_COOKIE, PORTAL_HOST)
        except RuntimeError:
            return False

    @property
    def has_okta_session(self) -> bool:
        """An Okta session cookie is present (SAML SSO renewal is possible)."""
        return any(self._has_cookie(name, OKTA_HOST) for name in ("idx", "sid"))

    @property
    def hourly_contract_sample(self) -> dict[str, Any] | None:
        """Return a copy of the latest hourly contract sample, if captured."""
        sample = self._hourly_contract_sample
        if sample is None:
            return None
        return copy.deepcopy(sample)

    @property
    def cost_contract_sample(self) -> dict[str, Any] | None:
        """Return a copy of the latest cost contract sample slots, if captured."""
        if not self._cost_contract_samples:
            return None
        from .cost_evidence import bound_cost_contract_sample

        return bound_cost_contract_sample(self._cost_contract_samples)

    def _remember_me_values(self) -> frozenset[str]:
        """Current MM_RememberMe values, for the in-memory rotation check only."""
        return frozenset(
            c.value
            for c in self.session.cookies
            if c.name == REMEMBER_ME_COOKIE
            and (c.domain or "").lstrip(".") == PORTAL_HOST
            and c.value
        )

    def attach_renewal_admission(
        self,
        admission: RenewalAdmission,
        runtime: Any | None = None,
        token: int | None = None,
    ) -> None:
        """Use the entry's shared (non-secret) renewal budget.

        Construct-time wiring only (the coordinator calls it before its first
        refresh), so it is a plain reference swap and never takes the client lock:
        nothing may block the event loop here. ``runtime`` is the entry-scoped
        ownership gate; without it the client keeps a local, process-only budget.
        """
        self._renewal_admission = admission
        self._renewal_runtime = runtime
        self._renewal_token = token

    def set_expected_meter_ids(self, meter_ids: Any) -> None:
        """Remember the entry's meter ids: the account-identity guard for renewals.

        An atomic reference swap of an immutable set: the renewal path reads it while
        holding the client lock, and callers on the event loop must never block there.
        """
        self._expected_meter_ids = frozenset(str(value) for value in meter_ids if value)

    def enable_label_identity_discovery(self) -> None:
        """Allow a human config-flow client to name its meter from labels alone.

        Only the unattached interactive flow calls this. With no expected meter ids,
        an authenticated DAILY window whose usage is not published yet (vendor lag)
        may still name the account's `Meter #N` series; that read never confirms
        cookies and never publishes readings, and an attached automatic client keeps
        the strict valid-known-contributor gate.
        """
        self._allow_label_identity = True

    def _reserve_renewal_sequence(self) -> None:
        """Spend one admission slot BEFORE any renewal HTTP request.

        The caller holds the client lock, so a poll and the keepalive of one client
        cannot both pass. The entry runtime adds the cross-client/cross-reload gate:
        it refuses a retired owner and a second in-flight reservation. Any unknown
        or unavailable admission refuses the sequence instead of risking a duplicate.
        """
        admission = self._renewal_admission
        if not self.has_remember_me:
            raise PsegRenewalDeferred("no_cookie", admission.terminal_reason)
        now = datetime.now(UTC)
        runtime = self._renewal_runtime
        blocked = (
            runtime.reserve(self._renewal_token, now)
            if runtime is not None and self._renewal_token is not None
            else admission.blocked_reason(now)
        )
        if blocked is not None:
            raise PsegRenewalDeferred(blocked, admission.terminal_reason)
        if runtime is None or self._renewal_token is None:
            admission.reserve(now)

    def _policy_finish(self, *, reason: str | None, transient: bool, rotated: bool) -> None:
        """Settle the reservation through the runtime, or the local budget.

        ``transient`` is the only outcome that may earn the second (retry) sequence.
        ``rotated`` rearms a new generation only after the caller verified both the
        dashboard and this entry's DAILY meter identity.
        """
        runtime = self._renewal_runtime
        if runtime is not None and self._renewal_token is not None:
            runtime.finish(
                self._renewal_token,
                reason=reason,
                transient=transient,
                rotated=rotated,
            )
            return
        if rotated:
            self._renewal_admission.rearm()
        self._renewal_admission.record_outcome(reason, transient=transient)

    def _detect_remember_me_rotation(self) -> bool:
        """Return True when a verified renewal changed MM_RememberMe's value.

        Values stay in memory. The caller must only use this after the DAILY meter
        identity proof succeeded; this method itself applies no policy. Only the
        value observed across an admitted renewal is evidence of a replacement: an
        ordinary confirmed Dashboard GET may slide the cookie too (see
        ``_note_confirmed_generation``), and that slide must never be credited to a
        later renewal as a rotation.
        """
        current = self._remember_me_values()
        rotated = bool(current) and current != self._remember_me_seen
        self._remember_me_seen = current
        if rotated:
            _LOGGER.info("MyMeter rotated the Remember Me cookie; renewal budget rearmed")
        return rotated

    def _note_confirmed_generation(self) -> None:
        """Remember the Remember Me value seen on a CONFIRMED session.

        A normal Dashboard response can carry a Set-Cookie that slides
        ``MM_RememberMe`` without any generation change. Tracking that value on every
        confirmed success keeps the next *unrotated* renewal from being miscounted as
        a rotation (which would rearm the budget and grant an extra attempt). When the
        session is confirmed and error-free, this also publishes the latest validated
        whole-jar checkpoint so an exit/cancellation/stop before async export saves
        the newest confirmed cookies. It never rearms a generation or spends a slot.
        """
        # Collapse a host-only and a '.host' copy first, exactly as persistence does:
        # otherwise the stale duplicate would make the observed set differ from the
        # value the next renewal compares against.
        self._dedupe_domain_variants()
        self._remember_me_seen = self._remember_me_values()
        if self.cookies_confirmed and self.auth_reason is None:
            exported = self._export_cookies_unlocked()
            with self._checkpoint_lock:
                self._confirmed_cookies = copy.deepcopy(exported)
                snapshot = self._confirmed_snapshot
                if (
                    snapshot is None
                    or snapshot["cookies"] != exported
                    or snapshot["auth_reason"] != self.auth_reason
                    or snapshot["cookies_confirmed"] != self.cookies_confirmed
                ):
                    self._confirmed_snapshot_seq += 1
                    self._confirmed_snapshot = {
                        "id": self._confirmed_snapshot_seq,
                        "cookies": copy.deepcopy(exported),
                        "auth_reason": self.auth_reason,
                        "cookies_confirmed": self.cookies_confirmed,
                    }

    def _has_valid_meter_read(
        self,
        records: list[dict[str, Any]],
        meter_ids: list[str] | set[str] | None = None,
        *,
        require_expected: bool = False,
    ) -> bool:
        """Return True when a chart read carries >=1 valid record from a relevant meter.

        Every valid parsed record carries its own contributing meter provenance. When
        ``self._expected_meter_ids`` is configured (or ``require_expected`` is True, as
        in renewal identity proof), at least one valid record must be contributed by a
        meter in ``self._expected_meter_ids``; an empty or all-invalid known series
        label never validates records from an unknown meter.
        """
        if not records:
            return False
        contributors = set(_contributing_meter_ids(records))
        if meter_ids is not None:
            seen = {str(value) for value in (meter_ids or []) if value}
            contributors &= seen
        if not contributors:
            return False
        expected = self._expected_meter_ids
        if require_expected and not expected:
            return False
        if expected and contributors.isdisjoint(expected):
            return False
        return True

    @staticmethod
    def _empty_chart_result(last_updated: str | None = None) -> dict[str, Any]:
        """Return an empty untrusted chart result that publishes no readings or identity."""
        return {
            "meter": DEFAULT_METER_NAME,
            "meter_ids": [],
            "contributing_meter_ids": [],
            "identity_confirmed": False,
            "last_updated": last_updated or datetime.now(UTC).isoformat(),
            "latest_date": "None",
            "latest_kwh": 0.0,
            "latest_cost": 0.0,
            "previous_date": "None",
            "previous_kwh": 0.0,
            "previous_cost": 0.0,
            "history_14d": [],
            "temperature_range": "",
            "temperature_avg": None,
            "total_records": 0,
        }

    def _snapshot_session_state(self) -> dict[str, Any]:
        """Snapshot the confirmed jar and auth telemetry for a renewal transaction."""
        return {
            "cookies": copy.deepcopy(self.session.cookies),
            "session_established_at": self.session_established_at,
            "last_sso_renewal": self.last_sso_renewal,
            "sso_renewals": self.sso_renewals,
            "okta_session_expired_at": self.okta_session_expired_at,
            "auth_reason": self.auth_reason,
            "idle_gap_seconds": self.idle_gap_seconds,
            "last_portal_success_at": self.last_portal_success_at,
            "last_success_monotonic": self._last_success_monotonic,
            "cookies_confirmed": self.cookies_confirmed,
        }

    def _restore_session_jar(self, snapshot: dict[str, Any]) -> None:
        """Put the last confirmed jar back; a failed renewal must not replace it."""
        self.session.cookies = copy.deepcopy(snapshot["cookies"])
        self.cookies_confirmed = False
        with self._checkpoint_lock:
            self._confirmed_cookies = None

    def _restore_session_state(self, snapshot: dict[str, Any]) -> None:
        """Roll back jar AND telemetry after a transient renewal failure."""
        self._restore_session_jar(snapshot)
        self.session_established_at = snapshot["session_established_at"]
        self.last_sso_renewal = snapshot["last_sso_renewal"]
        self.sso_renewals = snapshot["sso_renewals"]
        self.okta_session_expired_at = snapshot["okta_session_expired_at"]
        self.auth_reason = snapshot["auth_reason"]
        self.idle_gap_seconds = snapshot["idle_gap_seconds"]
        self.last_portal_success_at = snapshot["last_portal_success_at"]
        self._last_success_monotonic = snapshot["last_success_monotonic"]

    def _snapshot_cookie_leg(self) -> tuple[Any, frozenset[str]]:
        """Snapshot the live jar and observed generation before a chart/read stage."""
        return copy.deepcopy(self.session.cookies), self._remember_me_seen

    def _restore_cookie_leg(self, leg_snapshot: tuple[Any, frozenset[str]]) -> None:
        """Quarantine and roll back unconfirmed Set-Cookie mutations from a failed stage."""
        cookies, seen = leg_snapshot
        self.session.cookies = copy.deepcopy(cookies)
        self._remember_me_seen = seen

    def _check_active_owner(self) -> None:
        """Refuse automatic HTTP dispatch once this entry owner is retired."""
        runtime = self._renewal_runtime
        if (
            runtime is not None
            and self._renewal_token is not None
            and hasattr(runtime, "is_active")
            and not runtime.is_active(self._renewal_token)
        ):
            raise PsegTransientError("PSE&G entry owner is retired")

    @property
    def is_local_mode(self) -> bool:
        """True when this entry renews on the portal only, with no Okta session.

        The USABLE renewal path decides, not the presence of Okta cookies: a saved
        MyMeter email/password or a Remember Me cookie means the portal is the
        authority, and such a client is narrowed to the portal host, so only a
        credential-free portal GET can keep it alive. A jar holding both an Okta
        session cookie and a saved local login (or MM_RememberMe) is therefore
        local: it needs the 3-minute GET, not a 10-minute SSO round trip it cannot
        perform. Okta mode is only for a jar with no local renewal credential,
        including a pasted portal-only jar (no Okta session at all).
        """
        return self.has_login or self.has_remember_me or not self.has_okta_session

    @_locked
    def ensure_session(self) -> bool:
        """Validate the portal session; renew via Remember Me or Okta SSO if expired."""
        self._check_active_owner()
        baseline = self._snapshot_session_state()
        try:
            resp = self._get_dashboard()
            self._check_active_owner()
        except Exception:
            self._restore_session_state(baseline)
            raise
        if self._is_login_page(resp):
            self._restore_session_jar(baseline)
            return self._renew(baseline=baseline)
        if resp.status_code != 200:
            self._restore_session_state(baseline)
            raise PsegTransientError(f"Unexpected HTTP {resp.status_code} from /Dashboard")
        if not self._on_dashboard(resp):
            # e.g. a /Maintenance page: neither signed in nor signed out.
            self._restore_session_state(baseline)
            raise PsegTransientError("PSE&G portal did not serve /Dashboard (maintenance?)")
        self._mark_session_ok()
        self._note_confirmed_generation()
        return True

    @property
    def has_login(self) -> bool:
        return bool(self._email and self._password)

    @_locked
    def _login_form_token(self) -> str:
        """GET the login page and return its antiforgery token ('' if absent)."""
        self._check_active_owner()
        try:
            home = self.session.get(f"{PORTAL_BASE_URL}/", allow_redirects=True, timeout=20)
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error loading MyMeter login page: {err}") from err
        if home.status_code >= 500:
            raise PsegTransientError(f"MyMeter login page returned HTTP {home.status_code}")
        tag = BeautifulSoup(home.text, "html.parser").find(
            "input", attrs={"name": "__RequestVerificationToken"}
        )
        return str(tag["value"]) if tag and tag.get("value") else ""

    def _login_headers(self, token: str) -> dict[str, str]:
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{PORTAL_BASE_URL}/",
            "Origin": PORTAL_BASE_URL,
        }
        if token:
            headers["RequestVerificationToken"] = token
        return headers

    def _login_payload(self, token: str, captcha_response: str) -> dict[str, str]:
        data = {
            "RedirectUrl": "",
            "LoginErrorMessage": "",
            "LoginEmail": self._email,
            "LoginPassword": self._password,
            "ExternalLogin": "False",
            "TwoFactorRendered": "False",
            "SecretQuestionRendered": "False",
            "RememberMe": "true",
        }
        if token:
            data["__RequestVerificationToken"] = token
        if captcha_response:
            # One human-supplied proof, sent once. Never stored, exported or logged.
            data["g-recaptcha-response"] = captcha_response
        return data

    def _classify_login_response(self, resp: requests.Response) -> dict[str, Any]:
        """Raise the precise rejection for a /Home/Login reply, else return its Data."""
        if resp.status_code >= 500:
            raise PsegTransientError(f"MyMeter login returned HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError:
            body = {}
        result = body.get("Data") if isinstance(body, dict) else None
        result = result if isinstance(result, dict) else {}
        message = str(result.get("LoginErrorMessage") or "")
        # The exact server phrase may arrive outside Data (observed live); the full
        # phrase plus an unstructured reply keeps a successful login and a wrong
        # password out of the CAPTCHA path.
        body_is_captcha = not result and _CAPTCHA_ERROR_PHRASE in (resp.text or "").lower()
        if (
            result.get("RecaptchaOnLogin")
            or _CAPTCHA_ERROR_MARKER in message.lower()
            or body_is_captcha
        ):
            self._latch_captcha()
            self._mark_auth_failure(AUTH_REASON_CAPTCHA_REQUIRED)
            raise PsegCaptchaRequired("MyMeter requires a solved CAPTCHA")
        if result.get("SecretQuestionError") or result.get("PasswordExpiredModalData"):
            self._mark_auth_failure(AUTH_REASON_SECURITY_STEP)
            raise PsegSecurityStepRequired("MyMeter wants a security question or password change")
        if message:
            self._mark_auth_failure(AUTH_REASON_REMEMBER_ME_REJECTED)
            raise PsegLoginRejected("MyMeter rejected the email/password")
        return result

    def _confirm_login_dashboard(self) -> None:
        """Verify the sign-in reached /Dashboard and record the renewal."""
        self._check_active_owner()
        dash = self._get_dashboard()
        self._check_active_owner()
        if self._is_login_page(dash) or not self._on_dashboard(dash):
            self._mark_auth_failure(AUTH_REASON_REMEMBER_ME_REJECTED)
            raise PsegLoginRejected("MyMeter login did not reach the dashboard")
        # A confirmed human/automatic sign-in clears the challenge latches: the fresh
        # session replaced whatever the portal was asking for.
        self._captcha_latched = False
        self._security_step_latched = False
        self.last_sso_renewal = datetime.now(UTC).isoformat()
        self.sso_renewals += 1
        self._mark_session_ok()
        self._note_confirmed_generation()
        self._capture_confirmed_session()

    @_locked
    def login_local(self) -> bool:
        """Sign in with the MyMeter email/password (the page's local login form).

        No CAPTCHA proof is sent: Home Assistant cannot solve one. When MyMeter asks
        for a CAPTCHA this raises PsegCaptchaRequired and never retries, so a wrong
        password or an unwanted challenge cannot trigger lockouts. The config flow
        then lets the user supply one proof for this same jar and antiforgery state.
        """
        if not self.has_login:
            raise PsegLoginRejected("No MyMeter email/password stored")
        self._refuse_if_captcha_latched()
        self._refuse_if_security_step_latched()
        token = self._login_form_token()
        self._post_login(token, "")
        self._confirm_login_dashboard()
        _LOGGER.info("MyMeter email/password sign-in successful")
        return True

    @_locked
    def prepare_login_captcha(self) -> None:
        """Load a fresh login form and keep its antiforgery token in memory.

        The jar and token stay on this client so a human proof submitted later posts
        against the same session the challenge belongs to.
        """
        if not self.has_login:
            raise PsegLoginRejected("No MyMeter email/password stored")
        self._pending_login_token = self._login_form_token()

    @_locked
    def submit_login_captcha(self, captcha_response: str) -> bool:
        """POST one human-solved CAPTCHA proof and verify the dashboard.

        The proof is single-use: this method never retries, and the caller must never
        reuse a proof whose reply was lost (the server may already have spent it).
        """
        proof = (captcha_response or "").strip()
        if not proof:
            raise ValueError("A CAPTCHA proof is required")
        if not self.has_login:
            raise PsegLoginRejected("No MyMeter email/password stored")
        token = self._pending_login_token or self._login_form_token()
        self._pending_login_token = ""
        self._post_login(token, proof)
        self._confirm_login_dashboard()
        _LOGGER.info("MyMeter CAPTCHA-assisted sign-in successful")
        return True

    def _refuse_unexpected_login_redirect(self, resp: requests.Response) -> None:
        """Refuse a credential-POST redirect without echoing it or resending the body.

        The POST is sent with allow_redirects=False, so neither a 307/308 re-POST nor
        a method-rewritten replay can carry the MyMeter password or CAPTCHA proof to
        another origin. A same-origin portal redirect is accepted here and then
        verified by the caller's plain /Dashboard GET; anything else is a sanitized
        refusal whose message never contains the raw Location header.
        """
        location = resp.headers.get("Location") or ""
        if not location:
            raise PsegLoginRedirected("MyMeter login returned a redirect without a target")
        # Parse the target outside any handler: raising from inside `except ValueError`
        # would keep the raw URL (which can carry the one-use proof) as __context__,
        # even with `from None`. Nothing parsed is ever echoed in the message.
        parsed: urllib.parse.ParseResult | None = None
        try:
            parsed = urllib.parse.urlparse(urllib.parse.urljoin(resp.url, location))
            port = parsed.port
        except ValueError:
            parsed = None
            port = None
        if parsed is None:
            raise PsegLoginRedirected("MyMeter login redirect target is invalid")
        if parsed.scheme != "https" or parsed.hostname != PORTAL_HOST or port not in (None, 443):
            raise PsegLoginRedirected(
                "MyMeter redirected the email/password sign-in away from the portal"
            )

    def _post_login(self, token: str, captcha_response: str) -> None:
        """POST /Home/Login and classify the reply (raises on any refusal)."""
        self._check_active_owner()
        failure: str | None = None
        malformed_redirect = False
        try:
            resp = self.session.post(
                f"{PORTAL_BASE_URL}/Home/Login",
                data=self._login_payload(token, captcha_response),
                headers=self._login_headers(token),
                timeout=25,
                # Never let requests replay this credential/proof body on a redirect.
                allow_redirects=False,
            )
        except requests.RequestException as err:
            # Keep only the exception class. requests puts request state (URL,
            # headers, and for some failures a partial status line or the body) in
            # its message and __context__ chain, and this body carries the one-use
            # CAPTCHA proof. The raise below happens OUTSIDE this handler, so no raw
            # exception is chained as __context__/__cause__ or printed in a traceback.
            failure = type(err).__name__
        except ValueError:
            # requests 2.34 parses the Location header eagerly even with
            # allow_redirects=False. A malformed target raises ValueError whose text
            # carries the raw Location (which can hold the one-use proof); refuse it
            # as a redirect outside the handler so nothing is chained.
            malformed_redirect = True
        if malformed_redirect:
            raise PsegLoginRedirected("MyMeter login redirect target is invalid")
        if failure is not None:
            raise PsegTransientError(f"MyMeter login request failed ({failure})") from None
        if 300 <= resp.status_code < 400:
            self._refuse_unexpected_login_redirect(resp)
            return
        self._classify_login_response(resp)

    def _renew(self, *, baseline: dict[str, Any] | None = None) -> bool:
        """Renew a lapsed portal session: Remember Me, saved login, then Okta SSO.

        A Remember Me cookie the portal just rotated is the freshest credential, so
        it is tried first; that use is also what re-issues the cookie for the next
        cycle. Only a rejected/expired cookie falls through to the saved email and
        password (once), and only transports/transients keep their own errors.

        Every admitted Remember Me sequence proves this entry's DAILY meter before
        it publishes success, counters or a new generation.

        A portal-only entry with no renewal credential must not fall through to the
        Okta SSO probe: there is no Okta session to renew, and live 2026-10-22 that
        probe reported a misleading "Okta session expired" for a local entry.
        """
        baseline = baseline or self._snapshot_session_state()
        if self.is_local_mode and not (self.has_login or self.has_remember_me):
            self._check_active_owner()
            self._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
            raise PsegOktaSessionExpired(
                "PSE&G portal session expired and no local sign-in is stored"
            )
        self._refuse_if_captcha_latched()
        self._refuse_if_security_step_latched()
        self._refuse_if_terminal_step()
        if self.has_remember_me:
            try:
                # The poll spends the same admission budget as the keepalive: the
                # cookie cap cannot be bypassed by polling more often.
                return self._renew_remember_me_admitted(baseline=baseline)
            except PsegRenewalDeferred as deferred:
                if deferred.reason in {"retired", "busy"}:
                    # Another owner holds the sequence (or this client was retired).
                    raise PsegTransientError(
                        "Remember Me ownership or admission is unavailable"
                    ) from None
                self._check_active_owner()
                if deferred.terminal in {
                    AUTH_REASON_CAPTCHA_REQUIRED,
                    AUTH_REASON_SECURITY_STEP,
                }:
                    # Defensive: the durable check above normally caught this before
                    # any HTTP. Never fall through to the password/SSO fallback.
                    self._refuse_if_terminal_step()
                if deferred.reason == "exhausted":
                    # The generation is spent and earned no retry: no automatic
                    # attempt can follow, so a saved login must not paper over a
                    # human sign-in demand (R3 N2).
                    if self.auth_reason is None:
                        self._mark_auth_failure(
                            deferred.terminal or AUTH_REASON_PORTAL_SESSION_EXPIRED
                        )
                    raise PsegOktaSessionExpired(
                        "PSE&G portal session expired; the bounded Remember Me "
                        "generation has no retry left"
                    ) from None
                if not self.has_login and not self.has_okta_session:
                    if deferred.reason == "cooldown":
                        # An earned retry is still inside its 15-minute window and no
                        # fallback exists. This is a transient wait, not an auth
                        # failure: HA must keep scheduling polls for the future
                        # attempt instead of stopping them and demanding a sign-in.
                        raise PsegTransientError(
                            "Remember Me renewal deferred; a later attempt is still available"
                        ) from None
                    # Spent/terminal/absent cookie, or unreadable admission metadata:
                    # no automatic sequence can repair this generation, so ask the
                    # human to sign in.
                    if self.auth_reason is None:
                        self._mark_auth_failure(
                            deferred.terminal or AUTH_REASON_PORTAL_SESSION_EXPIRED
                        )
                    if deferred.reason == "uncertain":
                        _LOGGER.warning(
                            "Stored renewal metadata is unusable; automatic cookie "
                            "renewal is refused until a sign-in repairs it"
                        )
                    raise PsegOktaSessionExpired(
                        "PSE&G portal session expired; the bounded Remember Me "
                        "renewal is not available"
                    ) from None
                _LOGGER.info(
                    "Remember Me renewal deferred by its shared budget; "
                    "using the permitted fallback"
                )
            except PsegOktaSessionExpired:
                self._check_active_owner()
                if not self.has_login and not self.has_okta_session:
                    raise
                _LOGGER.info("MyMeter Remember Me cookie expired; trying the saved login")
        if self.has_login:
            if self._in_keepalive:
                self._check_active_owner()
                # Hard rule: the background timer never posts the saved password.
                # A poll may still sign in; a lapsed keepalive asks the user instead.
                self._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
                raise PsegOktaSessionExpired(
                    "PSE&G portal session expired; the keepalive never posts the saved sign-in"
                )
            try:
                return self.login_local()
            except PsegAuthError:
                self._restore_session_jar(baseline)
                raise
            except Exception:
                self._restore_session_state(baseline)
                raise
        try:
            return self.renew_sso()
        except PsegAuthError:
            self._restore_session_jar(baseline)
            raise
        except Exception:
            self._restore_session_state(baseline)
            raise

    def _renew_remember_me_admitted(self, *, baseline: dict[str, Any] | None = None) -> bool:
        """Poll-side Remember Me leg under the shared, bounded admission.

        The caller holds the client lock (``_renew`` runs from the locked
        ``ensure_session``/``_get_verification_token``), so the reservation and the
        sequence cannot interleave with the keepalive. The confirmed jar and telemetry
        are snapshotted before the request; a failed or unproven renewal rolls them
        back, so an unconfirmed rotation is never kept or persisted.
        """
        baseline = baseline or self._snapshot_session_state()
        self._reserve_renewal_sequence()
        try:
            self._check_renewal_owner()
            self._renew_remember_me_sequence(verify_identity=True)
        except PsegOktaSessionExpired:
            self._restore_session_jar(baseline)
            self._policy_finish(reason=self.auth_reason, transient=False, rotated=False)
            raise
        except Exception as err:
            self._restore_session_state(baseline)
            self._policy_finish(
                reason=None,
                transient=isinstance(err, (PsegTransientError, requests.RequestException)),
                rotated=False,
            )
            raise
        rotated = self._detect_remember_me_rotation()
        self._policy_finish(reason=None, transient=False, rotated=rotated)
        return True

    def _check_renewal_owner(self) -> None:
        """Refuse dispatch/publication after retirement or uncertain handoff."""
        if self._renewal_runtime is not None and not self._renewal_runtime.can_dispatch(
            self._renewal_token
        ):
            raise PsegRenewalDeferred("retired")

    @_locked
    def renew_remember_me(self) -> bool:
        """Let MyMeter re-issue MM_SID from its 'Remember Me' cookie.

        Accounts that use MyMeter's own email/password login with Remember Me get
        MM_RememberMe next to the session-only MM_SID (observed live 2026-10-21;
        its lifetime and the portal's rule are not documented). The dead MM_SID is
        dropped first so the portal falls back to the remember cookie.

        A refused renewal KEEPS MM_RememberMe: one unverified GET bounce is not
        proof the cookie is dead (the only live bounce was a browser-pasted copy,
        and the portal may honour the same cookie later). Dropping it here destroyed
        the only long-lived renewal credential in the live jar (2026-10-22).

        This is the raw sequence, without the shared admission: the config flow
        proves a *fresh* client once with it, and tests use it directly. The poll and
        the keepalive go through their admitted wrappers instead.
        """
        return self._renew_remember_me_sequence(verify_identity=False)

    def _renew_remember_me_sequence(self, *, verify_identity: bool) -> bool:
        """Run the GET-only Remember Me sequence; caller holds the client lock.

        ``verify_identity`` defers the session-ok stamp, the renewal counters and
        the API confirmation until a short read-only DAILY chart proves the renewed
        session still belongs to this entry's meter. A failure there raises before
        anything is published, so the caller can roll the jar back.
        """
        if not verify_identity:
            self._check_active_owner()
        for cookie in [c for c in self.session.cookies if c.name == "MM_SID"]:
            self.session.cookies.clear(cookie.domain, cookie.path, cookie.name)
        resp = self._get_dashboard()
        if verify_identity:
            self._check_renewal_owner()
        else:
            self._check_active_owner()
        if self._is_login_page(resp):
            # Some sites only honour the remember cookie on the landing page.
            try:
                self.session.get(f"{PORTAL_BASE_URL}/", allow_redirects=True, timeout=20)
            except requests.RequestException as err:
                raise PsegTransientError(
                    f"Network error during Remember Me sign-in: {err}"
                ) from err
            if verify_identity:
                self._check_renewal_owner()
            else:
                self._check_active_owner()
            resp = self._get_dashboard()
            if verify_identity:
                self._check_renewal_owner()
            else:
                self._check_active_owner()
        if self._is_login_page(resp):
            # Keep the cookie (see docstring): record the rejection and let a later
            # poll retry it instead of destroying the live jar's renewal credential.
            self._mark_auth_failure(AUTH_REASON_REMEMBER_ME_REJECTED)
            raise PsegOktaSessionExpired("MyMeter Remember Me sign-in expired or was rejected")
        if resp.status_code == 200 and not self._on_dashboard(resp):
            # Neither signed in nor signed out (e.g. a maintenance page): retry later.
            raise PsegTransientError("Remember Me sign-in did not reach /Dashboard")
        if resp.status_code != 200:
            raise PsegTransientError(
                f"Unexpected HTTP {resp.status_code} after Remember Me sign-in"
            )
        if verify_identity:
            self._confirm_meter_identity(resp)
            self._check_renewal_owner()
        self._dedupe_domain_variants()
        self.last_sso_renewal = datetime.now(UTC).isoformat()
        self.sso_renewals += 1
        self._mark_session_ok()
        self._capture_confirmed_session()
        _LOGGER.info("MyMeter Remember Me renewal successful")
        return True

    def _confirm_meter_identity(self, resp: requests.Response) -> None:
        """Prove a renewed session is this entry's account with one DAILY chart read.

        Uses the antiforgery token of the /Dashboard page that already proved the
        sign-in. It never renews recursively, never fetches the hourly chart and
        never imports or writes account data. Any failure raises, so an unconfirmed
        session is never published as connected or persisted.
        """
        expected = self._expected_meter_ids
        if not expected:
            raise PsegTransientError("No known meter identity to confirm the renewed PSE&G session")
        tag = BeautifulSoup(resp.text, "html.parser").find(
            "input", attrs={"name": "__RequestVerificationToken"}
        )
        token = str(tag["value"]) if tag and tag.get("value") else ""
        if not token:
            raise PsegTransientError("No antiforgery token to confirm the renewed PSE&G session")
        end_dt = datetime.now()
        start_str = (end_dt - timedelta(days=14)).strftime("%Y-%m-%d")
        end_str = end_dt.strftime("%Y-%m-%d")
        proof_leg = self._snapshot_cookie_leg()
        try:
            payload = self._fetch_chart_json(token, USAGE_INTERVAL_DAILY, start_str, end_str)
            parsed = self._parse_chart_data(payload)
            if not self._has_valid_meter_read(
                parsed.get("history_14d") or [],
                parsed.get("meter_ids") or [],
                require_expected=True,
            ):
                raise PsegTransientError(
                    "The renewed PSE&G session did not confirm this entry's meter"
                )
            if parsed.get("payload_anomalies"):
                # The meter identity IS proven, but an unrelated series broke the
                # response's shape contract: never adopt, confirm or rotate the
                # cookie jar from it. Restore the whole proof leg so the prior
                # Dashboard-proven jar and its observed generation stay in place.
                self._restore_cookie_leg(proof_leg)
        except Exception:
            self._restore_cookie_leg(proof_leg)
            raise

    @_locked
    def renew_sso(self) -> bool:
        """Perform SSO renewal using Okta session and SAML auto-post form.

        Only the Okta sign-in widget (or landing on an Okta sign-in path) means the Okta
        session is gone. Server errors, timeouts and unexpected pages are transient so a
        PSE&G outage never forces the user to re-paste cookies.
        """
        self._check_active_owner()
        baseline = self._snapshot_session_state()
        try:
            return self._renew_sso_locked()
        except PsegAuthError:
            self._restore_session_jar(baseline)
            raise
        except Exception:
            self._restore_session_state(baseline)
            raise

    def _renew_sso_locked(self) -> bool:
        """Run the Okta SAML renewal sequence; caller holds lock and baseline."""
        _LOGGER.debug("Attempting SSO renewal via Okta...")
        try:
            resp = self.session.get(
                f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
                allow_redirects=True,
                timeout=25,
            )
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error during SSO sign-in: {err}") from err

        # A SAML auto-post form is a successful Okta response; check it FIRST so that
        # marker text elsewhere on that page (e.g. "stateToken" in a script) is not
        # mistaken for the sign-in widget. Post the form that carries the assertion,
        # not the first form on the page (Okta pages can include e.g. sign-out).
        form = None
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            saml_input = soup.find("input", attrs={"name": "SAMLResponse"})
            form = saml_input.find_parent("form") if saml_input else None

        if not form:
            self._check_active_owner()
            parsed_final = urllib.parse.urlparse(resp.url)
            on_okta_signin = parsed_final.hostname == OKTA_HOST and any(
                marker in parsed_final.path.lower() for marker in _SIGNIN_PATH_MARKERS
            )
            if self._is_okta_widget(resp) or on_okta_signin:
                self._mark_auth_failure(AUTH_REASON_OKTA_SESSION_EXPIRED)
                raise PsegOktaSessionExpired("Okta session expired: sign-in widget returned")
            if resp.status_code != 200:
                raise PsegTransientError(f"SSO sign-in returned HTTP {resp.status_code}")
            raise PsegTransientError("SAML response form not found in SSO response")

        action = form.get("action")
        if not action:
            raise PsegTransientError("SAML form missing action attribute")

        action_url = urllib.parse.urljoin(resp.url, action)
        parsed_action = urllib.parse.urlparse(action_url)
        # The assertion is for the portal's ACS endpoint; posting it anywhere else
        # (even the allowlisted Okta host) would hand the SAML assertion to the wrong party.
        if parsed_action.hostname != PORTAL_HOST:
            raise PsegSecurityError(
                f"SAML form action points to untrusted host: {parsed_action.hostname}"
            )

        data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            val = inp.get("value", "")
            if name:
                data[name] = val

        self._check_active_owner()
        try:
            post_resp = self.session.post(action_url, data=data, allow_redirects=True, timeout=25)
            post_resp.raise_for_status()
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error posting SAML response: {err}") from err

        self._check_active_owner()
        dash_resp = self._get_dashboard()
        self._check_active_owner()
        if self._is_login_page(dash_resp):
            self._raise_post_renewal_logged_out(dash_resp)
        if dash_resp.status_code != 200:
            raise PsegTransientError(
                f"Unexpected HTTP {dash_resp.status_code} from /Dashboard after SSO"
            )

        self.last_sso_renewal = datetime.now(UTC).isoformat()
        self.sso_renewals += 1
        self._mark_session_ok()
        self._note_confirmed_generation()
        self._capture_confirmed_session()
        _LOGGER.info("SSO renewal successful")
        return True

    @_locked
    def keepalive(self) -> bool:
        """Keep the session warm without ever sending credentials from the timer.

        Okta mode keeps the previous behaviour: a full SSO round trip every 10
        minutes, which resets Okta's idle timer and leaves a fresh portal session
        for the poll.

        Local (portal-only) mode gets one GET /Dashboard every 3 minutes instead.
        That includes a mixed jar (Okta cookie plus a saved login or MM_RememberMe):
        its usable renewal path is the portal, and it is host-restricted to it, so
        an SSO keepalive could only fail.

        A local GET answered with the sign-in page is a typed auth expiry and may
        spend ONE bounded, cookie-only renewal (see _renew_local_cookie_session).
        Network errors, 5xx, maintenance pages and malformed redirects never start
        a renewal, and the timer never posts the saved password or probes Okta.

        Returns False on transient errors; raises PsegOktaSessionExpired when the
        session is gone (or a CAPTCHA/security-step latch is set) so the coordinator
        can start reauth.
        """
        self.last_keepalive = datetime.now(UTC).isoformat()
        self._refuse_if_captcha_latched()
        self._refuse_if_security_step_latched()
        self._refuse_if_terminal_step()
        previous_in_keepalive = self._in_keepalive
        self._in_keepalive = True
        try:
            if self.is_local_mode:
                return self._keepalive_local()
            return self.renew_sso()
        except PsegTransientError as err:
            _LOGGER.debug("Keepalive network check encountered transient error: %s", err)
            return False
        finally:
            # Restore the previous value: a nested/composed caller keeps its own flag.
            self._in_keepalive = previous_in_keepalive

    @_locked
    def _keepalive_local(self) -> bool:
        """GET-only local keepalive: accept only a final /Dashboard page.

        A sign-in page is a typed auth expiry and the only condition that may spend
        one bounded, cookie-only renewal. A network error, 5xx, maintenance page or
        malformed redirect stays transient and never initiates a renewal.
        """
        self._check_active_owner()
        baseline = self._snapshot_session_state()
        try:
            resp = self._get_dashboard()
            self._check_active_owner()
            if not self._is_login_page(resp):
                if resp.status_code != 200 or not self._on_dashboard(resp):
                    raise PsegTransientError("PSE&G portal did not serve /Dashboard (maintenance?)")
                self._mark_session_ok()
                self._note_confirmed_generation()
                return True
        except Exception:
            self._restore_session_state(baseline)
            raise
        # Even the expiry probe can send Set-Cookie. It is not a confirmed jar.
        self._restore_session_jar(baseline)
        return self._renew_local_cookie_session(baseline=baseline)

    def _renew_local_cookie_session(self, *, baseline: dict[str, Any]) -> bool:
        """One bounded cookie-only renewal, transactional against jar and telemetry.

        Never posts the saved password (that is the poll's permitted fallback, not
        the timer's) and never probes Okta. The confirmed jar and telemetry are
        snapshotted first; a transient failure restores both, a terminal refusal
        keeps the confirmed jar and the first typed failure, and either way the
        spent budget and its cooldown remain.
        """
        if self._captcha_latched:
            self._mark_auth_failure(AUTH_REASON_CAPTCHA_REQUIRED)
            raise PsegCaptchaRequired(
                "MyMeter is waiting for a solved CAPTCHA; no renewal was sent"
            )
        if not self.has_remember_me:
            # No HTTP renewal at all: there is nothing the portal could accept.
            self._mark_auth_failure(self._session_expired_reason())
            raise PsegOktaSessionExpired(
                "PSE&G portal session expired and no Remember Me cookie is present; "
                "no credentials were sent"
            )
        try:
            return self._renew_remember_me_admitted(baseline=baseline)
        except PsegRenewalDeferred as deferred:
            return self._refuse_deferred_local_renewal(deferred)

    def _refuse_deferred_local_renewal(self, deferred: PsegRenewalDeferred) -> bool:
        """Apply the admission's decision without inventing a new auth failure."""
        if deferred.reason in {"cooldown", "busy", "retired"}:
            # A previous attempt is still inside its 15-minute window (or another
            # owner holds it): wait for the next tick instead of alarming the user
            # or re-posting anything. The retry remains scheduled.
            raise PsegTransientError("Remember Me renewal deferred; its retry window is still open")
        if deferred.reason == "uncertain":
            # Unreadable renewal metadata can never be repaired by an automatic
            # attempt: fail closed and let the normal re-authentication prompt
            # rewrite it (the config flow rearm is the only repair path).
            self._mark_auth_failure(self._session_expired_reason())
            _LOGGER.warning(
                "Stored renewal metadata is unusable; automatic cookie renewal is "
                "refused until a sign-in repairs it"
            )
            raise PsegOktaSessionExpired(
                "PSE&G renewal metadata is unusable; re-authentication is required"
            )
        if deferred.reason == "exhausted" and self._renewal_admission.sequences == 1:
            # An unchanged-cookie success (or unknown outcome) earned no retry.
            # Return the usual False check result, while the coordinator observes
            # the typed expiry timestamp and asks the human to sign in.
            self._mark_auth_failure(self._session_expired_reason())
            raise PsegTransientError("Remember Me generation has no retry; sign-in is required")
        if deferred.reason == "no_cookie":
            self._mark_auth_failure(self._session_expired_reason())
        elif self.auth_reason is None:
            # Exhausted or terminal generation: keep the recorded reason, and stamp
            # a portal expiry only when no failure was recorded (e.g. after a
            # transient attempt that was deliberately not stamped).
            self._mark_auth_failure(deferred.terminal or AUTH_REASON_PORTAL_SESSION_EXPIRED)
        raise PsegOktaSessionExpired(
            "PSE&G portal session expired; the bounded Remember Me renewal is not available"
        )

    @_locked
    def test_connection(self) -> bool:
        """Validate session during setup or re-auth."""
        return self.ensure_session()

    @_locked
    def _get_verification_token(self) -> str:
        """Extract __RequestVerificationToken from /Dashboard, renewing session if needed."""
        self._check_active_owner()
        baseline = self._snapshot_session_state()
        try:
            resp = self._get_dashboard(timeout=25)
        except Exception:
            self._restore_session_state(baseline)
            raise

        renewed = False
        post_renewal_leg: tuple[Any, frozenset[str]] | None = None
        if self._is_login_page(resp):
            _LOGGER.debug("Portal session expired during token check; attempting renewal")
            # The expiry probe itself may send Set-Cookie; it is not a confirmed jar.
            # Only the jar from before that response is a valid renewal baseline.
            self._restore_session_jar(baseline)
            self._renew(baseline=baseline)
            # The renewal (or a successful saved-login/SSO fallback) is now verified:
            # its jar, counters and budget settlement must survive a later maintenance,
            # 4xx, 5xx or missing-token page. Rolling back to pre-probe baseline
            # restored the dead jar, while leaving the failed post-renewal response's
            # Set-Cookie live let the next poll promote it. Snapshot the post-renewal
            # confirmed checkpoint and restore it on any post-renewal Dashboard failure.
            renewed = True
            post_renewal_leg = self._snapshot_cookie_leg()
            try:
                self._check_active_owner()
                resp = self._get_dashboard(timeout=25)
                self._check_active_owner()
            except Exception:
                self._restore_cookie_leg(post_renewal_leg)
                raise
            if self._is_login_page(resp):
                self._restore_cookie_leg(post_renewal_leg)
                self._raise_post_renewal_logged_out(resp)
        else:
            try:
                self._check_active_owner()
            except Exception:
                self._restore_session_state(baseline)
                raise

        if resp.status_code != 200 or not self._on_dashboard(resp):
            if not renewed:
                self._restore_session_state(baseline)
            if post_renewal_leg is not None:
                self._restore_cookie_leg(post_renewal_leg)
            raise PsegTransientError("PSE&G portal did not serve /Dashboard (maintenance?)")

        soup = BeautifulSoup(resp.text, "html.parser")
        tag = soup.find("input", attrs={"name": "__RequestVerificationToken"})
        if not tag or not tag.get("value"):
            # Logged in (no redirect to sign-in) but no token: maintenance page or a
            # layout change. Retry next cycle instead of forcing reauth, and keep a
            # session this call already proved.
            if post_renewal_leg is not None:
                self._restore_cookie_leg(post_renewal_leg)
            if not renewed:
                self._restore_session_state(baseline)
            raise PsegTransientError("__RequestVerificationToken not found on /Dashboard")
        self._mark_session_ok()
        self._note_confirmed_generation()
        return str(tag["value"])

    @_locked
    def fetch_history_range(
        self,
        start_date_str: str,
        end_date_str: str,
        chunk_days: int = 90,
    ) -> list[dict[str, Any]]:
        """Fetch historical usage and cost data across a date range in polite chunks."""
        self._check_active_owner()
        token = self._get_verification_token()

        try:
            start_dt = datetime.strptime(start_date_str, "%Y-%m-%d")
            end_dt = datetime.strptime(end_date_str, "%Y-%m-%d")
        except ValueError as err:
            raise ValueError(f"Invalid date format (expected YYYY-MM-DD): {err}") from err

        if start_dt > end_dt:
            start_dt, end_dt = end_dt, start_dt

        headers2 = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": PORTAL_BASE_URL,
        }

        records_map: dict[str, dict[str, Any]] = {}
        # (start, end, had_data) per chunk, to tell an outage from range edges.
        chunks: list[tuple[str, str, bool]] = []
        last_validated_leg = self._snapshot_cookie_leg()
        curr_start = start_dt

        while curr_start <= end_dt:
            curr_end = min(curr_start + timedelta(days=chunk_days), end_dt)
            chunk_start_str = curr_start.strftime("%Y-%m-%d")
            chunk_end_str = curr_end.strftime("%Y-%m-%d")
            _LOGGER.info(
                "Fetching PSE&G history chunk from %s to %s...", chunk_start_str, chunk_end_str
            )

            chart_setup_data = {
                "__RequestVerificationToken": token,
                "UsageInterval": USAGE_INTERVAL_DAILY,
                "UsageType": "1",
                "jsTargetName": "StorageType",
                "EnableHoverChart": "true",
                "Start": chunk_start_str,
                "End": chunk_end_str,
                "IsRangeOpen": "False",
                "MaintainMaxDate": "true",
                "SelectedViaDateRange": "False",
                "ChartComparison": "1",
                "ChartComparison2": "0",
                "ChartComparison3": "0",
                "ChartComparison4": "0",
            }

            chunk_leg = self._snapshot_cookie_leg()
            try:
                self._check_active_owner()
                resp2 = self.session.post(
                    f"{PORTAL_BASE_URL}/Dashboard/Chart",
                    data=chart_setup_data,
                    headers=headers2,
                    timeout=25,
                )
                self._raise_for_chart_auth(resp2, "history chart setup")
                if resp2.status_code >= 500:
                    raise PsegTransientError(
                        f"Server error {resp2.status_code} setting chart context"
                    )
                resp2.raise_for_status()

                self._check_active_owner()
                ts = int(time.time() * 1000)
                resp3 = self.session.get(
                    f"{PORTAL_BASE_URL}/Dashboard/ChartData",
                    params={"_": ts},
                    headers=headers2,
                    timeout=25,
                )
                self._raise_for_chart_auth(resp3, "history chart data")
                if resp3.status_code >= 500:
                    raise PsegTransientError(
                        f"Server error {resp3.status_code} fetching chart data"
                    )
                resp3.raise_for_status()
                data = self._validate_chart_envelope(resp3.json())
                chart_data = data.get("Data")
                if chart_data is not None and not isinstance(chart_data, dict):
                    raise PsegTransientError("Malformed chart Data from chart data")
                if not chart_data:
                    self._raise_if_redirect(data, "history backfill")
                    self._restore_cookie_leg(chunk_leg)
                    _LOGGER.warning("No chart data returned for range %s to %s", chunk_start_str, chunk_end_str)
                    chunks.append((chunk_start_str, chunk_end_str, False))
                else:
                    raw_series = chart_data.get("series", [])
                    if not isinstance(raw_series, list):
                        raise PsegTransientError("Malformed series list from chart data")
                    chunk_records, _, chunk_meters = self._merge_meter_series(raw_series)
                    if self._has_valid_meter_read(chunk_records, chunk_meters):
                        if _series_shape_anomalies(raw_series):
                            # Validated readings, broken unrelated series: import the
                            # data but never adopt that response's jar rotation.
                            self._restore_cookie_leg(chunk_leg)
                        else:
                            self._note_confirmed_generation()
                            last_validated_leg = self._snapshot_cookie_leg()
                        chunks.append((chunk_start_str, chunk_end_str, True))
                        for rec in chunk_records:
                            records_map[rec["date"]] = rec
                    else:
                        self._restore_cookie_leg(chunk_leg)
                        chunks.append((chunk_start_str, chunk_end_str, False))
            except (requests.Timeout, requests.ConnectionError) as err:
                self._restore_cookie_leg(chunk_leg)
                raise PsegTransientError(f"Network timeout/connection error: {err}") from err
            except json.JSONDecodeError as err:
                self._restore_cookie_leg(chunk_leg)
                raise PsegTransientError(f"Failed to decode JSON from chart data: {err}") from err
            except requests.RequestException as err:
                self._restore_cookie_leg(chunk_leg)
                raise PsegTransientError(f"Request error retrieving chart chunk: {err}") from err
            except PsegAuthError, PsegTransientError:
                self._restore_cookie_leg(chunk_leg)
                raise
            except Exception as err:
                self._restore_cookie_leg(chunk_leg)
                raise PsegTransientError(
                    f"Malformed history chart payload ({type(err).__name__})"
                ) from err

            curr_start = curr_end + timedelta(days=1)
            if curr_start <= end_dt:
                time.sleep(0.1)

        # Empty chunks at the edges are normal (before the meter existed, days not yet
        # published). An empty chunk BETWEEN populated ones is a portal hiccup; importing
        # around it would rewrite the range with a hole, so abort and retry later.
        populated = [i for i, (_, _, had_data) in enumerate(chunks) if had_data]
        if populated:
            for chunk_start_str, chunk_end_str, had_data in chunks[populated[0] : populated[-1]]:
                if not had_data:
                    self._restore_cookie_leg(last_validated_leg)
                    raise PsegTransientError(
                        f"PSE&G returned no data for {chunk_start_str} to {chunk_end_str} "
                        "between populated chunks; backfill aborted"
                    )

        sorted_records = [records_map[d] for d in sorted(records_map.keys())]
        _LOGGER.info(
            "Fetched %d historical records across range %s to %s",
            len(sorted_records),
            start_date_str,
            end_date_str,
        )
        return sorted_records

    @_locked
    def fetch_energy_data(self, days_back: int = 14, cost_permit: Any = None) -> dict[str, Any]:
        """Fetch daily plus hourly usage using the 3-step MyMeter chart sequence.

        The daily chart remains authoritative: it feeds the sensors, the daily
        backfill path and the check that gates hourly promotion. The hourly chart is
        a second, independent request. If the vendor does not honour it (or answers
        with a daily series), the poll keeps today's daily behaviour and reports the
        real granularity instead of inventing hourly rows.
        """
        self._check_active_owner()
        token = self._get_verification_token()

        end_dt = datetime.now()
        start_dt = end_dt - timedelta(days=days_back)
        start_str = start_dt.strftime("%Y-%m-%d")
        end_str = end_dt.strftime("%Y-%m-%d")
        now_utc = datetime.now(UTC)

        daily_leg = self._snapshot_cookie_leg()
        try:
            self._check_active_owner()
            daily_payload = self._fetch_chart_json(token, USAGE_INTERVAL_DAILY, start_str, end_str)
            result = self._parse_chart_data(daily_payload)
            if self._has_valid_meter_read(
                result.get("history_14d") or [],
                result.get("meter_ids") or [],
            ):
                proven_ids = list(
                    result.get("contributing_meter_ids")
                    or _contributing_meter_ids(result.get("history_14d") or [])
                )
                result["meter_ids"] = proven_ids
                result["contributing_meter_ids"] = proven_ids
                result["identity_confirmed"] = True
                if result.pop("payload_anomalies", 0):
                    # The readings proved the meter, but an unrelated series broke
                    # the shape contract: this response must not rotate the jar.
                    self._restore_cookie_leg(daily_leg)
                else:
                    self._note_confirmed_generation()
            else:
                self._restore_cookie_leg(daily_leg)
                label_ids = [str(value) for value in (result.get("meter_ids") or []) if value]
                if self._allow_label_identity and not self._expected_meter_ids and label_ids:
                    # Human, unattached sign-in with a lagging window: name the meter
                    # from the authenticated `Meter #N` labels only. No readings, no
                    # cookie confirmation, no statistics, no identity proof.
                    empty = self._empty_chart_result(result.get("last_updated"))
                    empty["meter"] = f"Meter #{label_ids[0]}"
                    empty["meter_ids"] = label_ids
                    empty["identity_source"] = "meter_label"
                    result = empty
                else:
                    result = self._empty_chart_result(result.get("last_updated"))
        except PsegAuthError, PsegTransientError:
            self._restore_cookie_leg(daily_leg)
            raise
        except Exception as err:
            self._restore_cookie_leg(daily_leg)
            raise PsegTransientError(
                f"Malformed daily chart payload ({type(err).__name__})"
            ) from err
        daily_records = [copy.copy(record) for record in result["history_14d"]]
        result["daily_records"] = daily_records

        hourly_leg = self._snapshot_cookie_leg()
        try:
            self._check_active_owner()
            hourly_payload = self._fetch_chart_json(
                token, USAGE_INTERVAL_HOURLY, start_str, end_str
            )
            try:
                self._capture_hourly_contract_sample(hourly_payload, start_str, end_str)
            except Exception as exc:
                _LOGGER.debug(
                    "Failed to capture hourly contract sample: %s",
                    type(exc).__name__,
                )
            hourly = self._parse_hourly_chart(hourly_payload)
            if not self._has_valid_meter_read(
                hourly["hourly_records"],
                hourly.get("meter_ids") or [],
            ):
                raise PsegTransientError(
                    "No valid hourly meter points returned for hourly statistics."
                )
        except PsegOktaSessionExpired:
            self._restore_cookie_leg(hourly_leg)
            raise
        except PsegTransientError as err:
            self._restore_cookie_leg(hourly_leg)
            # The optional hourly leg must not fail a poll that can still deliver
            # the authoritative daily readings.
            _LOGGER.warning("Hourly chart unavailable; keeping the daily statistics path: %s", err)
            hourly = {
                "hourly_records": [],
                "hourly_granularity": "unavailable",
                "hourly_invalid_points": 0,
            }
        except Exception:
            self._restore_cookie_leg(hourly_leg)
            raise
        else:
            if hourly.pop("payload_anomalies", 0):
                # Validated hourly points, contract-violating unrelated series:
                # keep the readings, never confirm/rotate the jar from it.
                self._restore_cookie_leg(hourly_leg)
            else:
                self._note_confirmed_generation()

        daily_totals: dict[date, float] = {}
        for record in daily_records:
            day = _parse_iso_day(record.get("date"))
            kwh = record.get("kwh")
            if day is not None and isinstance(kwh, (int, float)) and not isinstance(kwh, bool):
                daily_totals[day] = float(kwh)

        validations = validate_hourly_days(
            hourly["hourly_records"],
            daily_totals,
            now_utc,
            granularity=hourly["hourly_granularity"],
            days=daily_totals,
        )
        complete = {day: check for day, check in validations.items() if check.complete}
        closed = [check for check in validations.values() if ny_day_bounds(check.day)[1] <= now_utc]

        daily_contributors = [
            str(value) for value in (result.get("contributing_meter_ids") or []) if value
        ]
        daily_meter_ids = [str(value) for value in (result.get("meter_ids") or []) if value]
        hourly_contributors = [
            str(value) for value in (hourly.get("contributing_meter_ids") or []) if value
        ]
        label_identity = result.get("identity_source") == "meter_label"
        result.update(hourly)
        if label_identity:
            # A lagging human-flow window keeps its label-derived identity; the
            # hourly leg may neither replace nor narrow it.
            result["meter_ids"] = daily_meter_ids
        elif result.get("identity_confirmed") is True:
            # The DAILY leg is authoritative for identity, but a valid successor that
            # only the hourly leg names must still be learned: union the VALIDATED
            # contributors of both legs (never a raw series label).
            merged = list(daily_contributors)
            merged.extend(value for value in hourly_contributors if value not in merged)
            result["contributing_meter_ids"] = merged
            result["meter_ids"] = merged
        result["hourly_complete_days"] = len(complete)
        result["hourly_incomplete_days"] = sum(1 for check in closed if not check.complete)
        if complete and len(complete) >= len(closed):
            result["statistics_granularity"] = "hourly"
        elif complete:
            result["statistics_granularity"] = "mixed"
        elif daily_records:
            result["statistics_granularity"] = "daily"
        else:
            result["statistics_granularity"] = "unavailable"
        # Cost evidence leg (RC-02): executed after the normal daily+hourly kWh legs,
        # inside the same _locked client sequence, only for an attached current-owner
        # normal coordinator poll with proven daily identity and an immutable one-use permit.
        from .cost_evidence import NY_TZ

        expected_ny_date = datetime.now(NY_TZ).date().isoformat()
        is_attached = (
            self._renewal_runtime is not None
            and self._renewal_runtime.entry_id == getattr(cost_permit, "entry_id", None)
            and (
                getattr(self._renewal_runtime, "_is_current", None) is None
                or self._renewal_runtime._is_current(self._renewal_token)
            )
        )
        is_valid_permit = (
            cost_permit is not None
            and is_attached
            and getattr(cost_permit, "ny_date", None) == expected_ny_date
            and getattr(cost_permit, "usage_interval", None)
            in (USAGE_INTERVAL_DAILY, USAGE_INTERVAL_HOURLY)
            and getattr(cost_permit, "permit_id", None)
            and getattr(cost_permit, "permit_id", None) not in self._consumed_permits
        )

        if is_valid_permit and result.get("identity_confirmed") is True:
            self._check_active_owner()
            permit_id = getattr(cost_permit, "permit_id", None)
            if permit_id and permit_id not in self._consumed_permits:
                self._consumed_permits.add(permit_id)
                try:
                    from decimal import Decimal

                    from .cost_evidence import execute_cost_sampler

                    auth_meters = set(
                        result.get("contributing_meter_ids") or result.get("meter_ids") or []
                    )
                    daily_anchors = []
                    for r in daily_records:
                        d_str = r.get("date")
                        k_val = r.get("kwh")
                        if d_str and k_val is not None:
                            try:
                                daily_anchors.append(
                                    {
                                        "date": str(date.fromisoformat(str(d_str))),
                                        "kwh": f"{Decimal(str(k_val)):f}",
                                    }
                                )
                            except Exception:
                                pass

                    hourly_anchors = []
                    for hr in hourly.get("hourly_records") or []:
                        s_str = hr.get("start")
                        k_val = hr.get("kwh")
                        if s_str and k_val is not None:
                            try:
                                hourly_anchors.append(
                                    {
                                        "start": str(s_str),
                                        "kwh": f"{Decimal(str(k_val)):f}",
                                    }
                                )
                            except Exception:
                                pass

                    paired_anchors = {
                        "daily_kwh_count": len(daily_records),
                        "hourly_records_count": len(hourly.get("hourly_records") or []),
                        "meter_set_digest": hashlib.sha256(
                            ",".join(sorted(auth_meters)).encode()
                        ).hexdigest()[:16],
                        "daily_comparison": daily_anchors,
                        "hourly_comparison": hourly_anchors[:1500],
                    }
                    cost_status, cost_sample, _promotable = execute_cost_sampler(
                        seed_cookies=self.session.cookies,
                        token=token,
                        permit=cost_permit,
                        owner_check=self._check_active_owner,
                        authoritative_meters=auth_meters,
                        meter_placeholders=self._meter_placeholders,
                        paired_kwh_anchors=paired_anchors,
                    )
                    slot_key = (
                        "hourly"
                        if getattr(cost_permit, "usage_interval", None) == USAGE_INTERVAL_HOURLY
                        else "daily"
                    )
                    self._cost_contract_samples[slot_key] = cost_sample
                    result["cost_evidence"] = {
                        "status": str(cost_status),
                        "interval": getattr(cost_permit, "usage_interval", None),
                        "sample_captured": bool(cost_sample),
                    }
                except PsegTransientError:
                    raise
                except Exception as err:
                    _LOGGER.warning("PSE&G cost evidence sampling encountered an error: %s", err)
                    result["cost_evidence"] = {"status": "malformed", "reason": "sampling_error"}

        # Sensor history remains the authoritative daily series; hourly rows are
        # used only for statistics promotion and provenance.
        return result

    def _raise_for_chart_auth(self, resp: requests.Response, context: str) -> None:
        """Turn a chart auth status OR final login page into typed auth failure.

        A 302 to the anonymous portal home can finish as HTTP 200 login HTML, so
        the final response is inspected with the same strong signals used by the
        dashboard path before JSON decoding and before the optional hourly leg is
        allowed to fall back. A local portal client never enters an SSO renewal.
        """
        final_url = getattr(resp, "url", None)
        login_page = isinstance(final_url, str) and self._is_login_page(resp)
        if resp.status_code in (401, 403) or login_page:
            self._mark_auth_failure(self._session_expired_reason())
            raise PsegOktaSessionExpired(
                f"PSE&G session expired during {context} (HTTP {resp.status_code})"
            )

    def _fetch_chart_json(
        self,
        token: str,
        usage_interval: str,
        start_str: str,
        end_str: str,
    ) -> dict[str, Any]:
        """Run one POST /Dashboard/Chart + GET /Dashboard/ChartData cycle."""
        chart_setup_data = {
            "__RequestVerificationToken": token,
            "UsageInterval": usage_interval,
            "UsageType": "1",
            "jsTargetName": "StorageType",
            "EnableHoverChart": "true",
            "Start": start_str,
            "End": end_str,
            "IsRangeOpen": "False",
            "MaintainMaxDate": "true",
            "SelectedViaDateRange": "False",
            "ChartComparison": "1",
            "ChartComparison2": "0",
            "ChartComparison3": "0",
            "ChartComparison4": "0",
        }

        headers2 = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": PORTAL_BASE_URL,
        }

        leg_snapshot = self._snapshot_cookie_leg()
        try:
            resp2 = self.session.post(
                f"{PORTAL_BASE_URL}/Dashboard/Chart",
                data=chart_setup_data,
                headers=headers2,
                timeout=25,
            )
            self._raise_for_chart_auth(resp2, "chart setup")
            if resp2.status_code >= 500:
                raise PsegTransientError(f"Server error {resp2.status_code} setting chart context")
            resp2.raise_for_status()

            ts = int(time.time() * 1000)
            resp3 = self.session.get(
                f"{PORTAL_BASE_URL}/Dashboard/ChartData",
                params={"_": ts},
                headers=headers2,
                timeout=25,
            )
            self._raise_for_chart_auth(resp3, "chart data")
            if resp3.status_code >= 500:
                raise PsegTransientError(f"Server error {resp3.status_code} fetching chart data")
            resp3.raise_for_status()
            return self._validate_chart_envelope(resp3.json())
        except (requests.Timeout, requests.ConnectionError) as err:
            self._restore_cookie_leg(leg_snapshot)
            raise PsegTransientError(f"Network timeout/connection error: {err}") from err
        except json.JSONDecodeError as err:
            self._restore_cookie_leg(leg_snapshot)
            raise PsegTransientError(f"Failed to decode JSON from chart data: {err}") from err
        except requests.RequestException as err:
            self._restore_cookie_leg(leg_snapshot)
            raise PsegTransientError(f"Request error retrieving chart data: {err}") from err
        except Exception:
            self._restore_cookie_leg(leg_snapshot)
            raise

    @staticmethod
    def _validate_chart_envelope(data: Any) -> dict[str, Any]:
        """Validate the chart JSON envelope shared by the daily, hourly and history legs.

        A contract violation (root not an object, or an ``AjaxResults`` that is not a
        list) is a typed transient, so every caller's leg rollback runs instead of a
        raw ``TypeError`` escaping from a later shape check.
        """
        if not isinstance(data, dict):
            raise PsegTransientError("Malformed JSON root from chart data")
        ajax_results = data.get("AjaxResults")
        if ajax_results is not None and not isinstance(ajax_results, list):
            raise PsegTransientError("Malformed AjaxResults from chart data")
        return data

    def _raise_if_redirect(self, data: dict[str, Any], context: str) -> None:
        """Raise an auth expiry when the chart payload is a login redirect."""
        ajax_results = data.get("AjaxResults")
        if ajax_results is not None and not isinstance(ajax_results, list):
            raise PsegTransientError(f"Malformed AjaxResults from {context}")
        for result in ajax_results or []:
            if isinstance(result, dict) and result.get("Action") == "Redirect":
                self._mark_auth_failure(self._session_expired_reason())
                raise PsegOktaSessionExpired(
                    f"Session expired during {context}: Redirected to login"
                )

    def _capture_hourly_contract_sample(
        self,
        payload: Any,
        start_str: str,
        end_str: str,
    ) -> None:
        """Capture a passive, privacy-stripped hourly chart sample in memory."""
        try:
            sample: dict[str, Any] = {
                "sample_version": 1,
                "captured_at": datetime.now(UTC).isoformat(),
                "request": {
                    "start": start_str,
                    "end": end_str,
                    "usage_interval": USAGE_INTERVAL_HOURLY,
                },
            }

            if not isinstance(payload, dict):
                sample["payload_keys"] = []
                sample["data_keys"] = []
                sample["chart"] = {
                    "Data": {
                        "series": [],
                    }
                }
                sample["non_meter_series_count"] = 0
                sample["point_extra_keys"] = []
                sample["hs_extra_keys"] = []
                sample["truncated_points"] = 0
                sample["shape_note"] = "payload_not_object"
                self._hourly_contract_sample = sample
                return

            sample["payload_keys"] = sorted(
                str(k)[:64] for k in payload.keys() if isinstance(k, str)
            )[:50]

            chart_dict: dict[str, Any] = {}
            if "AjaxResults" in payload:
                ajax_results = payload["AjaxResults"]
                if isinstance(ajax_results, list):
                    filtered_ajax: list[dict[str, str]] = []
                    for item in ajax_results:
                        if isinstance(item, dict) and isinstance(item.get("Action"), str):
                            filtered_ajax.append({"Action": str(item["Action"])[:32]})
                            if len(filtered_ajax) == 10:
                                break
                    chart_dict["AjaxResults"] = filtered_ajax
                else:
                    sample["ajax_results_type"] = type(ajax_results).__name__

            raw_data = payload.get("Data")
            if not isinstance(raw_data, dict):
                sample["data_keys"] = []
                chart_dict["Data"] = {"series": []}
                sample["chart"] = chart_dict
                sample["non_meter_series_count"] = 0
                sample["point_extra_keys"] = []
                sample["hs_extra_keys"] = []
                sample["truncated_points"] = 0
                sample["shape_note"] = "data_not_object"
                self._hourly_contract_sample = sample
                return

            sample["data_keys"] = sorted(
                str(k)[:64] for k in raw_data.keys() if isinstance(k, str)
            )[:50]

            data_dict: dict[str, Any] = {}
            if isinstance(raw_data.get("unit"), str):
                data_dict["unit"] = raw_data["unit"][:16]

            raw_series = raw_data.get("series")
            meter_series_out: list[dict[str, Any]] = []
            non_meter_count = 0
            point_extra_keys_set: set[str] = set()
            hs_extra_keys_set: set[str] = set()
            total_kept_points = 0
            truncated_points = 0
            meter_placeholders: dict[str, str] = self._meter_placeholders

            if isinstance(raw_series, list):
                for series_item in raw_series:
                    if not isinstance(series_item, dict):
                        non_meter_count += 1
                        continue
                    name = str(series_item.get("name") or "")
                    match = _METER_SERIES.match(name)
                    if not match:
                        non_meter_count += 1
                        continue

                    real_meter_id = match.group(1)
                    if real_meter_id not in meter_placeholders:
                        placeholder = str(len(meter_placeholders) + 1)
                        meter_placeholders[real_meter_id] = placeholder
                    else:
                        placeholder = meter_placeholders[real_meter_id]

                    series_points: list[dict[str, Any]] = []
                    invalid_points = 0
                    raw_points = series_item.get("data")
                    if isinstance(raw_points, list):
                        for pt in raw_points:
                            if not isinstance(pt, dict):
                                invalid_points += 1
                                continue

                            for k in pt.keys():
                                if isinstance(k, str) and k not in ("x", "y", "hs"):
                                    point_extra_keys_set.add(k[:64])

                            raw_hs = pt.get("hs")
                            if isinstance(raw_hs, dict):
                                for k in raw_hs.keys():
                                    if isinstance(k, str) and k not in ("start", "end"):
                                        hs_extra_keys_set.add(k[:64])

                            if total_kept_points >= 1500:
                                truncated_points += 1
                                continue

                            pt_x: Any
                            raw_x = pt.get("x")
                            if isinstance(raw_x, bool):
                                pt_x = f"<{type(raw_x).__name__}>"
                            elif isinstance(raw_x, (int, float)) or raw_x is None:
                                pt_x = raw_x
                            else:
                                pt_x = f"<{type(raw_x).__name__}>"

                            pt_y: Any
                            raw_y = pt.get("y")
                            if isinstance(raw_y, bool):
                                pt_y = f"<{type(raw_y).__name__}>"
                            elif isinstance(raw_y, (int, float)) or raw_y is None:
                                pt_y = raw_y
                            else:
                                pt_y = f"<{type(raw_y).__name__}>"

                            point_obj: dict[str, Any] = {"x": pt_x, "y": pt_y}
                            if isinstance(raw_hs, dict):
                                raw_start = raw_hs.get("start")
                                if isinstance(raw_start, str):
                                    s_val: str | None = raw_start[:64]
                                elif raw_start is None:
                                    s_val = None
                                else:
                                    s_val = f"<{type(raw_start).__name__}>"

                                raw_end = raw_hs.get("end")
                                if isinstance(raw_end, str):
                                    e_val: str | None = raw_end[:64]
                                elif raw_end is None:
                                    e_val = None
                                else:
                                    e_val = f"<{type(raw_end).__name__}>"

                                point_obj["hs"] = {"start": s_val, "end": e_val}

                            series_points.append(point_obj)
                            total_kept_points += 1

                    series_dict: dict[str, Any] = {
                        "name": f"Meter #{placeholder}",
                        "data": series_points,
                    }
                    if invalid_points > 0:
                        series_dict["invalid_points"] = invalid_points
                    meter_series_out.append(series_dict)

            data_dict["series"] = meter_series_out
            chart_dict["Data"] = data_dict
            sample["chart"] = chart_dict
            sample["non_meter_series_count"] = non_meter_count
            sample["point_extra_keys"] = sorted(point_extra_keys_set)[:50]
            sample["hs_extra_keys"] = sorted(hs_extra_keys_set)[:50]
            sample["truncated_points"] = truncated_points

            self._hourly_contract_sample = sample
        except Exception as exc:
            _LOGGER.debug(
                "Failed to capture hourly contract sample: %s",
                type(exc).__name__,
            )

    def _parse_hourly_chart(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract timestamped hourly points without trusting the vendor contract.

        Only ``x`` milliseconds is used as the timestamp (the one field the
        upstream implementation and review agree on). Points that are missing,
        non-numeric, negative, not on the hour, or outside a plausible millisecond
        range are counted as invalid and never turned into zeroes. Promotion also
        needs positive interval-start evidence: both ``hs.start`` and ``hs.end`` must
        be timezone-aware and name ``[x, x+1h)``. Date-only or bare wall-clock labels
        are retained as unverified provenance, never as promotion evidence.
        """
        if not isinstance(data, dict):
            raise PsegTransientError("No chart data returned for hourly statistics.")
        chart_data = data.get("Data")
        if chart_data is not None and not isinstance(chart_data, dict):
            raise PsegTransientError("Malformed chart Data for hourly statistics.")
        if not chart_data:
            self._raise_if_redirect(data, "hourly statistics")
            raise PsegTransientError("No chart data returned for hourly statistics.")

        series_list = chart_data.get("series", [])
        if not isinstance(series_list, list) or not series_list:
            raise PsegTransientError("No series data returned for hourly statistics.")

        totals: dict[datetime, float] = {}
        hour_meters: dict[datetime, list[str]] = {}
        labels: dict[datetime, str | None] = {}
        label_ok: dict[datetime, bool | None] = {}
        interval_ok: dict[datetime, bool] = {}
        interval_reason: dict[datetime, str | None] = {}
        seen_meters: set[str] = set()
        invalid = 0

        for series in series_list:
            if not isinstance(series, dict):
                continue
            name = str(series.get("name") or "")
            match = _METER_SERIES.match(name)
            if not match:
                # Non-meter telemetry is not this parser's business: skip it before
                # any shape check so a bad Temperature series cannot fail the leg.
                continue
            raw_points = series.get("data")
            if raw_points is not None and not isinstance(raw_points, list):
                raise PsegTransientError("Malformed meter data series for hourly statistics.")
            meter_id = match.group(1)
            if meter_id in seen_meters:
                _LOGGER.debug("Skipping duplicate hourly meter series for %s", meter_id)
                continue
            seen_meters.add(meter_id)

            for point in raw_points or []:
                if not isinstance(point, dict):
                    invalid += 1
                    continue
                x = point.get("x")
                y = point.get("y")
                if (
                    isinstance(y, bool)
                    or not isinstance(y, (int, float))
                    or not math.isfinite(y)
                    or y < 0
                ):
                    invalid += 1
                    continue
                if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x):
                    invalid += 1
                    continue
                timestamp = float(x)
                # Milliseconds between 2001 and 2096. A seconds value, a label-only
                # point or a missing x is not silently reinterpreted.
                if not 1e12 <= timestamp <= 4e12:
                    invalid += 1
                    continue
                start, wall_status = ny_wall_ms_to_utc(timestamp)
                if wall_status == "dst_nonexistent" or start is None:
                    invalid += 1
                    continue
                wall = datetime.fromtimestamp(timestamp / 1000, tz=UTC)
                if wall.minute or wall.second or wall.microsecond:
                    invalid += 1
                    continue

                # Sum across meter series: a meter swap can split one hour between
                # the old and new meter, exactly like the daily aggregator does.
                totals[start] = totals.get(start, 0.0) + float(y)
                contributors = hour_meters.setdefault(start, [])
                if meter_id not in contributors:
                    contributors.append(meter_id)
                header = point.get("hs")
                start_label = header.get("start") if isinstance(header, dict) else None
                end_label = header.get("end") if isinstance(header, dict) else None

                start_aware = parse_aware_label(start_label)
                end_aware = parse_aware_label(end_label)
                if wall_status == "dst_ambiguous":
                    c0 = label_matches_ny_time(start_label, start)
                    c1 = label_matches_ny_time(start_label, start + timedelta(hours=1))
                    if c0 is True or c1 is True:
                        start_check = True
                    elif c0 is False and c1 is False:
                        start_check = False
                    else:
                        start_check = None
                    point_ok = False
                    point_reason = "dst_ambiguous"
                elif start_aware is not None and end_aware is not None:
                    start_check = (
                        abs((start_aware.astimezone(UTC) - start).total_seconds())
                        <= LABEL_TOLERANCE_SECONDS
                    )
                    end_check = (
                        abs(
                            (
                                end_aware.astimezone(UTC) - (start + timedelta(hours=1))
                            ).total_seconds()
                        )
                        <= LABEL_TOLERANCE_SECONDS
                    )
                    if not start_check:
                        point_reason = "label_mismatch"
                        point_ok = False
                    elif not end_check:
                        point_reason = "interval_end_mismatch"
                        point_ok = False
                    else:
                        point_reason = None
                        point_ok = True
                else:
                    start_date = parse_date_only_label(start_label)
                    end_date = parse_date_only_label(end_label)
                    if start_date is not None and end_date is not None:
                        start_ny_date = ny_day_of(start)
                        if start_date != start_ny_date:
                            start_check = False
                            point_ok = False
                            point_reason = "label_mismatch"
                        elif end_date not in (
                            start_ny_date,
                            start_ny_date + timedelta(days=1),
                        ):
                            start_check = True
                            point_ok = False
                            point_reason = "interval_end_mismatch"
                        else:
                            start_check = True
                            point_ok = True
                            point_reason = None
                    else:
                        start_check = label_matches_ny_time(start_label, start)
                        if start_check is False:
                            point_reason = "label_mismatch"
                            point_ok = False
                        else:
                            point_reason = "timestamp_semantics_unverified"
                            point_ok = False

                if start not in label_ok:
                    labels[start] = str(start_label) if start_label is not None else None
                    label_ok[start] = start_check
                elif start_check is False:
                    label_ok[start] = False
                elif label_ok[start] is None and start_check is True:
                    label_ok[start] = True

                interval_ok[start] = interval_ok.get(start, True) and point_ok
                if not point_ok and start not in interval_reason:
                    interval_reason[start] = point_reason

        records = [
            _MeterRecord(
                {
                    "start": start,
                    "kwh": round(totals[start], STATISTICS_PRECISION),
                    "label": labels.get(start),
                    "label_ok": label_ok.get(start),
                    "interval_ok": interval_ok.get(start, False),
                    "interval_reason": interval_reason.get(start),
                },
                contributing_meter_ids=hour_meters.get(start, ()),
            )
            for start in sorted(totals)
        ]
        contributing_ids = _contributing_meter_ids(records)
        return {
            "hourly_records": records,
            "hourly_granularity": self._hourly_granularity(records),
            "hourly_invalid_points": invalid,
            "meter_ids": contributing_ids,
            "contributing_meter_ids": contributing_ids,
            "payload_anomalies": _series_shape_anomalies(series_list),
        }

    @staticmethod
    def _hourly_granularity(records: list[dict[str, Any]]) -> str:
        """Report whether the payload is hourly, daily, mixed or unusable.

        One missing hour on one day must not erase the provenance of every other
        day, so the label is based on the shape of the payload (any day with three
        or more distinct hourly starts) while :func:`validate_hourly_day` still
        requires exact per-day coverage before promotion.
        """
        per_day: dict[date, set[datetime]] = {}
        for record in records:
            per_day.setdefault(ny_day_of(record["start"]), set()).add(record["start"])
        counts = [len(starts) for starts in per_day.values()]
        if any(count >= 3 for count in counts):
            return "hourly"
        if counts and all(count == 1 for count in counts):
            return "daily"
        return "unknown"

    def _merge_meter_series(
        self, series_list: list[Any]
    ) -> tuple[list[dict[str, Any]], str | None, list[str]]:
        """Sum daily kWh across every meter series on the account.

        An account can list a replaced meter next to its successor: the old one
        carries the history before the swap and an empty series after it. Summing
        per day keeps the account total continuous across the swap; picking one
        series by position silently dropped all usage. Returns (records sorted by
        date, name of the meter with the most recent reading, all meter ids).
        """
        totals: dict[str, float] = {}
        day_meters: dict[str, list[str]] = {}
        active_name: str | None = None
        active_x = -1
        meter_ids: list[str] = []
        for s in series_list:
            if not isinstance(s, dict):
                continue
            name = str(s.get("name") or "")
            match = _METER_SERIES.match(name)
            if not match:
                # Unrelated telemetry (e.g. a Temperature series) may carry any
                # shape: it never feeds the metered leg and must not fail it. Any
                # shape anomaly is reported by _series_shape_anomalies so the
                # response cannot confirm the jar.
                continue
            raw_points = s.get("data")
            if raw_points is not None and not isinstance(raw_points, list):
                raise PsegTransientError("Malformed meter data series from chart data")
            meter_id = match.group(1)
            if meter_id in meter_ids:
                _LOGGER.debug("Skipping duplicate meter series for meter %s", meter_id)
                continue
            meter_ids.append(meter_id)
            for pt in raw_points or []:
                if not isinstance(pt, dict):
                    continue
                hs = pt.get("hs")
                start_str = hs.get("start") if isinstance(hs, dict) else None
                try:
                    date_iso = datetime.strptime(start_str, "%m/%d/%Y").strftime("%Y-%m-%d")
                except TypeError, ValueError:
                    _LOGGER.debug("Skipping meter %s point with invalid date", meter_id)
                    continue
                y = pt.get("y")
                if isinstance(y, bool) or not isinstance(y, (int, float)) or not math.isfinite(y):
                    _LOGGER.debug("Skipping meter %s point with non-numeric usage", meter_id)
                    continue
                totals[date_iso] = totals.get(date_iso, 0.0) + float(y)
                contributors = day_meters.setdefault(date_iso, [])
                if meter_id not in contributors:
                    contributors.append(meter_id)
                if active_name is None:
                    active_name = name
                x = pt.get("x")
                if (
                    isinstance(x, (int, float))
                    and not isinstance(x, bool)
                    and math.isfinite(x)
                    and x > active_x
                ):
                    active_x, active_name = x, name

        records: list[dict[str, Any]] = []
        for date_iso in sorted(totals):
            kwh = round(totals[date_iso], 2)
            records.append(
                _MeterRecord(
                    {
                        "date": date_iso,
                        "kwh": kwh,
                        "cost": round(kwh * self.price_per_kwh, 2),
                    },
                    contributing_meter_ids=day_meters.get(date_iso, ()),
                )
            )
        return records, active_name, meter_ids

    def _parse_chart_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse series into clean sensor model."""
        if not isinstance(data, dict):
            raise PsegTransientError("No chart data returned from MyMeter.")
        chart_data = data.get("Data")
        if chart_data is not None and not isinstance(chart_data, dict):
            raise PsegTransientError("Malformed chart Data from MyMeter.")
        if not chart_data:
            self._raise_if_redirect(data, "daily chart")
            raise PsegTransientError("No chart data returned from MyMeter.")

        series_list = chart_data.get("series", [])
        if not isinstance(series_list, list) or not series_list:
            raise PsegTransientError("No series data returned from MyMeter.")

        first_series = series_list[0] if isinstance(series_list[0], dict) else {}
        nav_series = first_series.get("data") if isinstance(first_series.get("data"), list) else []
        temp_series: dict[str, Any] = {}
        for s in series_list:
            if isinstance(s, dict) and "Temperature" in str(s.get("name") or ""):
                temp_series = s

        history_14d, active_name, meter_ids = self._merge_meter_series(series_list)
        contributing_ids = _contributing_meter_ids(history_14d)
        meter_name = active_name or DEFAULT_METER_NAME
        raw_temp_pts = temp_series.get("data")
        temp_pts = raw_temp_pts if isinstance(raw_temp_pts, list) else []

        latest_record = (
            history_14d[-1] if history_14d else {"date": "None", "kwh": 0.0, "cost": 0.0}
        )
        prev_record = (
            history_14d[-2] if len(history_14d) > 1 else {"date": "None", "kwh": 0.0, "cost": 0.0}
        )

        latest_temp = temp_pts[-1] if temp_pts and isinstance(temp_pts[-1], dict) else {}
        temp_range = latest_temp.get("tr", "")
        temp_y = latest_temp.get("y")
        temp_avg = (
            round(float(temp_y), 1)
            if isinstance(temp_y, (int, float))
            and not isinstance(temp_y, bool)
            and math.isfinite(temp_y)
            else None
        )

        return {
            "meter": meter_name,
            "meter_ids": meter_ids,
            "contributing_meter_ids": contributing_ids,
            "payload_anomalies": _series_shape_anomalies(series_list),
            "last_updated": datetime.now(UTC).isoformat(),
            "latest_date": latest_record["date"],
            "latest_kwh": latest_record["kwh"],
            "latest_cost": latest_record["cost"],
            "previous_date": prev_record["date"],
            "previous_kwh": prev_record["kwh"],
            "previous_cost": prev_record["cost"],
            "history_14d": history_14d,
            "temperature_range": temp_range,
            "temperature_avg": temp_avg,
            "total_records": len(nav_series),
        }

"""PSE&G API Client for Home Assistant (New Jersey).

Uses domain-scoped session cookies to communicate directly with PSE&G MySmartEnergy portal
and Okta SAML SSO endpoints.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
import functools
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
from .statistics_hourly import (
    LABEL_TOLERANCE_SECONDS,
    label_matches_ny_time,
    ny_day_bounds,
    ny_day_of,
    parse_aware_label,
    validate_hourly_days,
)

_LOGGER = logging.getLogger(__name__)
_METER_SERIES = re.compile(r"^\s*Meter #(\d+)")


def _parse_iso_day(value: Any) -> date | None:
    """Parse a chart day label, returning None instead of raising."""
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None

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


class AllowlistedSession(requests.Session):
    """Requests session that enforces a host allowlist on every request and redirect."""

    def __init__(self) -> None:
        """Start with both PSE&G hosts; the client narrows this for local logins."""
        super().__init__()
        self.allowed_hosts: frozenset[str] = frozenset(ALLOWED_HOSTS)
        self.trace: list[str] = []

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        # Runs for the first request and every redirect hop (resolve_redirects calls
        # send), before the cookie-bearing request leaves the process.
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
        set_names = sorted({h.split("=", 1)[0].strip() for h in resp.raw.headers.getlist("Set-Cookie")}) if hasattr(getattr(resp, "raw", None), "headers") and hasattr(resp.raw.headers, "getlist") else []
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
        self.session = AllowlistedSession()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{PORTAL_BASE_URL}/Dashboard",
        })
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
        # True only while keepalive() runs: the timer may validate/renew with GETs
        # but must never POST the saved email/password.
        self._in_keepalive = False

        # Session telemetry
        self.session_established_at: str | None = None
        self.last_sso_renewal: str | None = None
        self.sso_renewals: int = 0
        self.last_keepalive: str | None = None
        self.okta_session_expired_at: str | None = None
        # Typed auth failure reason (see AUTH_REASON_* in const); None while healthy.
        self.auth_reason: str | None = None
        # Seconds between the last confirmed portal request and the failure; tells an
        # idle expiry (~10 min) apart from an absolute lifetime next time.
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
            cookie_data.append({
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path,
                "secure": c.secure,
            })
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

    def _seconds_since_last_success(self) -> float | None:
        """Seconds since the last confirmed portal request, or None if unknown."""
        if self._last_success_monotonic is None:
            return None
        return round(time.monotonic() - self._last_success_monotonic, 1)

    def _mark_auth_failure(self, reason: str) -> None:
        """Record a typed authentication failure, its timestamp and the idle gap.

        Logs the reason and the idle gap only: never a credential, cookie value or
        page body. ``okta_session_expired_at`` is still stamped for compatibility
        with existing automations/attributes, even when the reason is not Okta.
        """
        previous_reason = self.auth_reason
        self.auth_reason = reason
        self.okta_session_expired_at = datetime.now(UTC).isoformat()
        self.idle_gap_seconds = self._seconds_since_last_success()
        if reason == previous_reason:
            return
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
        """MyMeter local-login 'Remember Me' cookie present (lives ~1 year)."""
        return self._has_cookie(REMEMBER_ME_COOKIE, PORTAL_HOST)

    @property
    def has_okta_session(self) -> bool:
        """An Okta session cookie is present (SAML SSO renewal is possible)."""
        return any(self._has_cookie(name, OKTA_HOST) for name in ("idx", "sid"))

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
        resp = self._get_dashboard()
        if self._is_login_page(resp):
            return self._renew()
        if resp.status_code != 200:
            raise PsegTransientError(f"Unexpected HTTP {resp.status_code} from /Dashboard")
        if not self._on_dashboard(resp):
            # e.g. a /Maintenance page: neither signed in nor signed out.
            raise PsegTransientError("PSE&G portal did not serve /Dashboard (maintenance?)")
        self._mark_session_ok()
        return True

    @property
    def has_login(self) -> bool:
        return bool(self._email and self._password)

    @_locked
    def _login_form_token(self) -> str:
        """GET the login page and return its antiforgery token ('' if absent)."""
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
            raise PsegSecurityStepRequired(
                "MyMeter wants a security question or password change"
            )
        if message:
            self._mark_auth_failure(AUTH_REASON_REMEMBER_ME_REJECTED)
            raise PsegLoginRejected("MyMeter rejected the email/password")
        return result

    def _confirm_login_dashboard(self) -> None:
        """Verify the sign-in reached /Dashboard and record the renewal."""
        dash = self._get_dashboard()
        if self._is_login_page(dash) or not self._on_dashboard(dash):
            self._mark_auth_failure(AUTH_REASON_REMEMBER_ME_REJECTED)
            raise PsegLoginRejected("MyMeter login did not reach the dashboard")
        # A confirmed human/automatic sign-in clears a CAPTCHA latch: the fresh
        # session replaced whatever the portal was challenging.
        self._captcha_latched = False
        self.last_sso_renewal = datetime.now(UTC).isoformat()
        self.sso_renewals += 1
        self._mark_session_ok()

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

    def _renew(self) -> bool:
        """Renew a lapsed portal session: Remember Me, saved login, then Okta SSO.

        A Remember Me cookie the portal just rotated is the freshest credential, so
        it is tried first; that use is also what re-issues the cookie for the next
        cycle. Only a rejected/expired cookie falls through to the saved email and
        password (once), and only transports/transients keep their own errors.

        A portal-only entry with no renewal credential must not fall through to the
        Okta SSO probe: there is no Okta session to renew, and live 2026-10-22 that
        probe reported a misleading "Okta session expired" for a local entry.
        """
        if self.is_local_mode and not (self.has_login or self.has_remember_me):
            self._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
            raise PsegOktaSessionExpired(
                "PSE&G portal session expired and no local sign-in is stored"
            )
        self._refuse_if_captcha_latched()
        if self.has_remember_me:
            try:
                return self.renew_remember_me()
            except PsegOktaSessionExpired:
                if not self.has_login and not self.has_okta_session:
                    raise
                _LOGGER.info("MyMeter Remember Me cookie expired; trying the saved login")
        if self.has_login:
            if self._in_keepalive:
                # Hard rule: the background timer never posts the saved password.
                # A poll may still sign in; a lapsed keepalive asks the user instead.
                self._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
                raise PsegOktaSessionExpired(
                    "PSE&G portal session expired; the keepalive never posts the "
                    "saved sign-in"
                )
            return self.login_local()
        return self.renew_sso()

    @_locked
    def renew_remember_me(self) -> bool:
        """Let MyMeter re-issue MM_SID from its 'Remember Me' cookie.

        Accounts that use MyMeter's own email/password login with Remember Me get
        MM_RememberMe (expires ~1 year; seen live 2026-10-21) next to the
        session-only MM_SID. PSE&G's Okta sign-in has no 'keep me signed in' and
        dies ~1 h after login, so this is the only long-lived renewal path. The dead
        MM_SID is dropped first so the portal falls back to the remember cookie.

        A refused renewal KEEPS MM_RememberMe: one unverified GET bounce is not
        proof the cookie is dead (the only live bounce was a browser-pasted copy,
        and the portal may honour the same cookie later). Dropping it here destroyed
        the only long-lived renewal credential in the live jar (2026-10-22).
        """
        for cookie in [c for c in self.session.cookies if c.name == "MM_SID"]:
            self.session.cookies.clear(cookie.domain, cookie.path, cookie.name)
        resp = self._get_dashboard()
        if self._is_login_page(resp):
            # Some sites only honour the remember cookie on the landing page.
            try:
                self.session.get(f"{PORTAL_BASE_URL}/", allow_redirects=True, timeout=20)
            except requests.RequestException as err:
                raise PsegTransientError(f"Network error during Remember Me sign-in: {err}") from err
            resp = self._get_dashboard()
        if self._is_login_page(resp):
            # Keep the cookie (see docstring): record the rejection and let a later
            # poll retry it instead of destroying the live jar's renewal credential.
            self._mark_auth_failure(AUTH_REASON_REMEMBER_ME_REJECTED)
            raise PsegOktaSessionExpired("MyMeter Remember Me sign-in expired or was rejected")
        if resp.status_code == 200 and not self._on_dashboard(resp):
            # Neither signed in nor signed out (e.g. a maintenance page): retry later.
            raise PsegTransientError("Remember Me sign-in did not reach /Dashboard")
        if resp.status_code != 200:
            raise PsegTransientError(f"Unexpected HTTP {resp.status_code} after Remember Me sign-in")
        self._dedupe_domain_variants()
        self.last_sso_renewal = datetime.now(UTC).isoformat()
        self.sso_renewals += 1
        self._mark_session_ok()
        _LOGGER.info("MyMeter Remember Me renewal successful")
        return True

    @_locked
    def renew_sso(self) -> bool:
        """Perform SSO renewal using Okta session and SAML auto-post form.

        Only the Okta sign-in widget (or landing on an Okta sign-in path) means the Okta
        session is gone. Server errors, timeouts and unexpected pages are transient so a
        PSE&G outage never forces the user to re-paste cookies.
        """
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

        try:
            post_resp = self.session.post(action_url, data=data, allow_redirects=True, timeout=25)
            post_resp.raise_for_status()
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error posting SAML response: {err}") from err

        dash_resp = self._get_dashboard()
        if self._is_login_page(dash_resp):
            self._raise_post_renewal_logged_out(dash_resp)
        if dash_resp.status_code != 200:
            raise PsegTransientError(
                f"Unexpected HTTP {dash_resp.status_code} from /Dashboard after SSO"
            )

        self.last_sso_renewal = datetime.now(UTC).isoformat()
        self.sso_renewals += 1
        self._mark_session_ok()
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
        an SSO keepalive could only fail. Live 2026-10-22: a local entry's MM_SID
        lapsed on roughly a 10-minute idle timer, and the old keepalive answered
        that by blind-POSTing the saved password, which the portal refused with a
        CAPTCHA demand. The GET keeps the idle timer from firing; renewal stays on
        the poll path, so the timer can never post a password or trip a challenge.

        Returns False on transient errors; raises PsegOktaSessionExpired when the
        session is gone (or a CAPTCHA latch is set) so the coordinator can start
        reauth.
        """
        self.last_keepalive = datetime.now(UTC).isoformat()
        self._refuse_if_captcha_latched()
        self._in_keepalive = True
        try:
            if self.is_local_mode:
                return self._keepalive_local()
            return self.renew_sso()
        except PsegTransientError as err:
            _LOGGER.debug("Keepalive network check encountered transient error: %s", err)
            return False
        finally:
            self._in_keepalive = False

    @_locked
    def _keepalive_local(self) -> bool:
        """GET-only local keepalive: accept only a final /Dashboard page."""
        resp = self._get_dashboard()
        if self._is_login_page(resp):
            self._mark_auth_failure(AUTH_REASON_PORTAL_SESSION_EXPIRED)
            raise PsegOktaSessionExpired(
                "PSE&G portal session expired during a local keepalive; "
                "no credentials were sent"
            )
        if resp.status_code != 200 or not self._on_dashboard(resp):
            # e.g. a /Maintenance page: neither signed in nor signed out.
            raise PsegTransientError("PSE&G portal did not serve /Dashboard (maintenance?)")
        self._mark_session_ok()
        return True

    @_locked
    def test_connection(self) -> bool:
        """Validate session during setup or re-auth."""
        return self.ensure_session()

    @_locked
    def _get_verification_token(self) -> str:
        """Extract __RequestVerificationToken from /Dashboard, renewing session if needed."""
        resp = self._get_dashboard(timeout=25)

        if self._is_login_page(resp):
            _LOGGER.debug("Portal session expired during token check; attempting renewal")
            self._renew()
            resp = self._get_dashboard(timeout=25)
            if self._is_login_page(resp):
                self._raise_post_renewal_logged_out(resp)

        soup = BeautifulSoup(resp.text, "html.parser")
        tag = soup.find("input", attrs={"name": "__RequestVerificationToken"})
        if not tag or not tag.get("value"):
            # Logged in (no redirect to sign-in) but no token: maintenance page or a
            # layout change. Retry next cycle instead of forcing reauth.
            raise PsegTransientError("__RequestVerificationToken not found on /Dashboard")
        self._mark_session_ok()
        return str(tag["value"])

    @_locked
    def fetch_history_range(
        self,
        start_date_str: str,
        end_date_str: str,
        chunk_days: int = 90,
    ) -> list[dict[str, Any]]:
        """Fetch historical usage and cost data across a date range in polite chunks."""
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
        curr_start = start_dt

        while curr_start <= end_dt:
            curr_end = min(curr_start + timedelta(days=chunk_days), end_dt)
            chunk_start_str = curr_start.strftime("%Y-%m-%d")
            chunk_end_str = curr_end.strftime("%Y-%m-%d")
            _LOGGER.info("Fetching PSE&G history chunk from %s to %s...", chunk_start_str, chunk_end_str)

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

            try:
                resp2 = self.session.post(
                    f"{PORTAL_BASE_URL}/Dashboard/Chart",
                    data=chart_setup_data,
                    headers=headers2,
                    timeout=25,
                )
                self._raise_for_chart_auth(resp2, "history chart setup")
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
                self._raise_for_chart_auth(resp3, "history chart data")
                if resp3.status_code >= 500:
                    raise PsegTransientError(f"Server error {resp3.status_code} fetching chart data")
                resp3.raise_for_status()
                data = resp3.json()
            except (requests.Timeout, requests.ConnectionError) as err:
                raise PsegTransientError(f"Network timeout/connection error: {err}") from err
            except json.JSONDecodeError as err:
                raise PsegTransientError(f"Failed to decode JSON from chart data: {err}") from err
            except requests.RequestException as err:
                raise PsegTransientError(f"Request error retrieving chart chunk: {err}") from err

            chart_data = data.get("Data")
            if not chart_data or not isinstance(chart_data, dict):
                ajax_results = data.get("AjaxResults") or []
                for ar in ajax_results:
                    if isinstance(ar, dict) and ar.get("Action") == "Redirect":
                        self._mark_auth_failure(self._session_expired_reason())
                        raise PsegOktaSessionExpired("Session expired during history backfill: Redirected to login")
                _LOGGER.warning("No chart data returned for range %s to %s", chunk_start_str, chunk_end_str)
                chunks.append((chunk_start_str, chunk_end_str, False))
            else:
                chunk_records, _, _ = self._merge_meter_series(chart_data.get("series", []))
                chunks.append((chunk_start_str, chunk_end_str, bool(chunk_records)))
                for rec in chunk_records:
                    records_map[rec["date"]] = rec

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
    def fetch_energy_data(self, days_back: int = 14) -> dict[str, Any]:
        """Fetch daily plus hourly usage using the 3-step MyMeter chart sequence.

        The daily chart remains authoritative: it feeds the sensors, the daily
        backfill path and the check that gates hourly promotion. The hourly chart is
        a second, independent request. If the vendor does not honour it (or answers
        with a daily series), the poll keeps today's daily behaviour and reports the
        real granularity instead of inventing hourly rows.
        """
        token = self._get_verification_token()

        end_dt = datetime.now()
        start_dt = end_dt - timedelta(days=days_back)
        start_str = start_dt.strftime("%Y-%m-%d")
        end_str = end_dt.strftime("%Y-%m-%d")
        now_utc = datetime.now(UTC)

        daily_payload = self._fetch_chart_json(
            token, USAGE_INTERVAL_DAILY, start_str, end_str
        )
        result = self._parse_chart_data(daily_payload)
        daily_records = [dict(record) for record in result["history_14d"]]
        result["daily_records"] = daily_records

        try:
            hourly_payload = self._fetch_chart_json(
                token, USAGE_INTERVAL_HOURLY, start_str, end_str
            )
            hourly = self._parse_hourly_chart(hourly_payload)
        except PsegOktaSessionExpired:
            raise
        except PsegTransientError as err:
            # The optional hourly leg must not fail a poll that can still deliver
            # the authoritative daily readings.
            _LOGGER.warning(
                "Hourly chart unavailable; keeping the daily statistics path: %s", err
            )
            hourly = {
                "hourly_records": [],
                "hourly_granularity": "unavailable",
                "hourly_invalid_points": 0,
            }

        daily_totals: dict[date, float] = {}
        for record in daily_records:
            day = _parse_iso_day(record.get("date"))
            kwh = record.get("kwh")
            if (
                day is not None
                and isinstance(kwh, (int, float))
                and not isinstance(kwh, bool)
            ):
                daily_totals[day] = float(kwh)

        validations = validate_hourly_days(
            hourly["hourly_records"],
            daily_totals,
            now_utc,
            granularity=hourly["hourly_granularity"],
            days=daily_totals,
        )
        complete = {
            day: check for day, check in validations.items() if check.complete
        }
        closed = [
            check
            for check in validations.values()
            if ny_day_bounds(check.day)[1] <= now_utc
        ]

        result.update(hourly)
        result["hourly_complete_days"] = len(complete)
        result["hourly_incomplete_days"] = sum(
            1 for check in closed if not check.complete
        )
        if complete and len(complete) >= len(closed):
            result["statistics_granularity"] = "hourly"
        elif complete:
            result["statistics_granularity"] = "mixed"
        elif daily_records:
            result["statistics_granularity"] = "daily"
        else:
            result["statistics_granularity"] = "unavailable"
        # Sensor history remains the authoritative daily series; hourly rows are
        # used only for statistics promotion and provenance.
        return result

    def _raise_for_chart_auth(
        self, resp: requests.Response, context: str
    ) -> None:
        """Turn a chart auth status OR final login page into typed auth failure.

        A 302 to the anonymous portal home can finish as HTTP 200 login HTML, so
        the final response is inspected with the same strong signals used by the
        dashboard path before JSON decoding and before the optional hourly leg is
        allowed to fall back. A local portal client never enters an SSO renewal.
        """
        final_url = getattr(resp, "url", None)
        login_page = (
            isinstance(final_url, str) and self._is_login_page(resp)
        )
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

        try:
            resp2 = self.session.post(
                f"{PORTAL_BASE_URL}/Dashboard/Chart",
                data=chart_setup_data,
                headers=headers2,
                timeout=25,
            )
            self._raise_for_chart_auth(resp2, "chart setup")
            if resp2.status_code >= 500:
                raise PsegTransientError(
                    f"Server error {resp2.status_code} setting chart context"
                )
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
                raise PsegTransientError(
                    f"Server error {resp3.status_code} fetching chart data"
                )
            resp3.raise_for_status()
            return resp3.json()
        except (requests.Timeout, requests.ConnectionError) as err:
            raise PsegTransientError(
                f"Network timeout/connection error: {err}"
            ) from err
        except json.JSONDecodeError as err:
            raise PsegTransientError(
                f"Failed to decode JSON from chart data: {err}"
            ) from err
        except requests.RequestException as err:
            raise PsegTransientError(
                f"Request error retrieving chart data: {err}"
            ) from err

    def _raise_if_redirect(self, data: dict[str, Any], context: str) -> None:
        """Raise an auth expiry when the chart payload is a login redirect."""
        ajax_results = data.get("AjaxResults") or []
        for result in ajax_results:
            if isinstance(result, dict) and result.get("Action") == "Redirect":
                self._mark_auth_failure(self._session_expired_reason())
                raise PsegOktaSessionExpired(
                    f"Session expired during {context}: Redirected to login"
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
        chart_data = data.get("Data")
        if not chart_data or not isinstance(chart_data, dict):
            self._raise_if_redirect(data, "hourly statistics")
            raise PsegTransientError("No chart data returned for hourly statistics.")

        series_list = chart_data.get("series", [])
        if not isinstance(series_list, list) or not series_list:
            raise PsegTransientError("No series data returned for hourly statistics.")

        totals: dict[datetime, float] = {}
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
                continue
            meter_id = match.group(1)
            if meter_id in seen_meters:
                _LOGGER.debug("Skipping duplicate hourly meter series for %s", meter_id)
                continue
            seen_meters.add(meter_id)

            for point in series.get("data") or []:
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
                if (
                    isinstance(x, bool)
                    or not isinstance(x, (int, float))
                    or not math.isfinite(x)
                ):
                    invalid += 1
                    continue
                timestamp = float(x)
                # Milliseconds between 2001 and 2096. A seconds value, a label-only
                # point or a missing x is not silently reinterpreted.
                if not 1e12 <= timestamp <= 4e12:
                    invalid += 1
                    continue
                start = datetime.fromtimestamp(timestamp / 1000, tz=UTC)
                if start.minute or start.second or start.microsecond:
                    invalid += 1
                    continue

                # Sum across meter series: a meter swap can split one hour between
                # the old and new meter, exactly like the daily aggregator does.
                totals[start] = totals.get(start, 0.0) + float(y)
                header = point.get("hs")
                start_label = header.get("start") if isinstance(header, dict) else None
                end_label = header.get("end") if isinstance(header, dict) else None
                # Positive evidence requires BOTH labels to carry an explicit
                # timezone/offset and to name [x, x+1h). A bare clock, a date-only
                # label or a missing end cannot distinguish start from end.
                start_aware = parse_aware_label(start_label)
                end_aware = parse_aware_label(end_label)
                if start_aware is not None and end_aware is not None:
                    start_check = (
                        abs(
                            (start_aware.astimezone(UTC) - start).total_seconds()
                        )
                        <= LABEL_TOLERANCE_SECONDS
                    )
                    end_check = (
                        abs(
                            (
                                end_aware.astimezone(UTC)
                                - (start + timedelta(hours=1))
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
            {
                "start": start,
                "kwh": round(totals[start], STATISTICS_PRECISION),
                "label": labels.get(start),
                "label_ok": label_ok.get(start),
                "interval_ok": interval_ok.get(start, False),
                "interval_reason": interval_reason.get(start),
            }
            for start in sorted(totals)
        ]
        return {
            "hourly_records": records,
            "hourly_granularity": self._hourly_granularity(records),
            "hourly_invalid_points": invalid,
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
        active_name: str | None = None
        active_x = -1
        meter_ids: list[str] = []
        for s in series_list:
            if not isinstance(s, dict):
                continue
            name = str(s.get("name") or "")
            match = _METER_SERIES.match(name)
            if not match:
                continue
            meter_id = match.group(1)
            if meter_id in meter_ids:
                _LOGGER.debug("Skipping duplicate meter series for meter %s", meter_id)
                continue
            meter_ids.append(meter_id)
            if active_name is None:
                active_name = name
            for pt in s.get("data") or []:
                if not isinstance(pt, dict):
                    continue
                hs = pt.get("hs")
                start_str = hs.get("start") if isinstance(hs, dict) else None
                try:
                    date_iso = datetime.strptime(start_str, "%m/%d/%Y").strftime("%Y-%m-%d")
                except (TypeError, ValueError):
                    _LOGGER.debug("Skipping meter %s point with invalid date", meter_id)
                    continue
                y = pt.get("y")
                if isinstance(y, bool) or not isinstance(y, (int, float)) or not math.isfinite(y):
                    _LOGGER.debug("Skipping meter %s point with non-numeric usage", meter_id)
                    continue
                totals[date_iso] = totals.get(date_iso, 0.0) + float(y)
                x = pt.get("x")
                if isinstance(x, (int, float)) and x > active_x:
                    active_x, active_name = x, name

        records = []
        for date_iso in sorted(totals):
            kwh = round(totals[date_iso], 2)
            records.append({"date": date_iso, "kwh": kwh, "cost": round(kwh * self.price_per_kwh, 2)})
        return records, active_name, meter_ids

    def _parse_chart_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse series into clean sensor model."""
        chart_data = data.get("Data")
        if not chart_data or not isinstance(chart_data, dict):
            ajax_results = data.get("AjaxResults") or []
            for ar in ajax_results:
                if isinstance(ar, dict) and ar.get("Action") == "Redirect":
                    self._mark_auth_failure(self._session_expired_reason())
                    raise PsegOktaSessionExpired("Session expired: Redirected to login portal")
            raise PsegTransientError("No chart data returned from MyMeter.")

        series_list = chart_data.get("series", [])
        if not series_list:
            raise PsegTransientError("No series data returned from MyMeter.")

        nav_series = series_list[0].get("data", [])
        temp_series = {}
        for s in series_list:
            if "Temperature" in str(s.get("name") or ""):
                temp_series = s

        history_14d, active_name, meter_ids = self._merge_meter_series(series_list)
        meter_name = active_name or DEFAULT_METER_NAME
        temp_pts = temp_series.get("data", [])

        latest_record = history_14d[-1] if history_14d else {"date": "None", "kwh": 0.0, "cost": 0.0}
        prev_record = history_14d[-2] if len(history_14d) > 1 else {"date": "None", "kwh": 0.0, "cost": 0.0}

        latest_temp = temp_pts[-1] if temp_pts else {}
        temp_range = latest_temp.get("tr", "")

        return {
            "meter": meter_name,
            "meter_ids": meter_ids,
            "last_updated": datetime.now(UTC).isoformat(),
            "latest_date": latest_record["date"],
            "latest_kwh": latest_record["kwh"],
            "latest_cost": latest_record["cost"],
            "previous_date": prev_record["date"],
            "previous_kwh": prev_record["kwh"],
            "previous_cost": prev_record["cost"],
            "history_14d": history_14d,
            "temperature_range": temp_range,
            "temperature_avg": round(latest_temp.get("y", 0.0), 1) if "y" in latest_temp else None,
            "total_records": len(nav_series),
        }

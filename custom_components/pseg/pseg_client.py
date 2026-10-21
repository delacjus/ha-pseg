"""PSE&G API Client for Home Assistant (New Jersey).

Uses domain-scoped session cookies to communicate directly with PSE&G MySmartEnergy portal
and Okta SAML SSO endpoints.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import functools
import json
import logging
import threading
import time
from typing import Any
import urllib.parse

from bs4 import BeautifulSoup
import requests

from .const import (
    ALLOWED_HOSTS,
    DEFAULT_METER_NAME,
    DEFAULT_PRICE_PER_KWH,
    OKTA_HOST,
    PORTAL_BASE_URL,
    PORTAL_HOST,
)

_LOGGER = logging.getLogger(__name__)

# Path fragments that mean "you were sent to sign in" (portal or Okta).
_SIGNIN_PATH_MARKERS = ("/signin", "/sign-in", "/login")
# Portal paths that mean the request was bounced into the SSO handshake.
_LOGIN_PATH_MARKERS = (*_SIGNIN_PATH_MARKERS, "/saml/")
# Okta Identity Engine sign-in widget markers (case-sensitive JS identifiers).
_OKTA_WIDGET_MARKERS = ("OktaSignIn", "stateToken")


class PsegError(Exception):
    """Base exception for PSE&G errors."""


class PsegSecurityError(PsegError):
    """Exception raised when an unauthorized host or security restriction is violated."""


class PsegAuthError(PsegError):
    """Base exception for authentication failures."""


class PsegOktaSessionExpired(PsegAuthError):
    """Exception raised when Okta session is expired and requires user re-authentication."""


class PsegTransientError(PsegError):
    """Exception raised for transient network/server errors (timeouts, 5xx, connection)."""


class AllowlistedSession(requests.Session):
    """Requests session that strictly enforces host allowlist on all requests and redirects."""

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        # Runs for the first request and every redirect hop (resolve_redirects calls
        # send), before the cookie-bearing request leaves the process.
        parsed = urllib.parse.urlparse(request.url)
        if parsed.hostname not in ALLOWED_HOSTS:
            raise PsegSecurityError(
                f"Request to unauthorized host blocked: {parsed.hostname or request.url}"
            )
        if parsed.scheme != "https":
            raise PsegSecurityError(
                f"Request to {parsed.hostname} blocked: scheme {parsed.scheme!r} is not https"
            )
        try:
            port = parsed.port
        except ValueError as err:
            raise PsegSecurityError(f"Request to {parsed.hostname} blocked: bad port") from err
        if port not in (None, 443):
            raise PsegSecurityError(f"Request to {parsed.hostname} blocked: port {port}")
        return super().send(request, **kwargs)


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
    ) -> None:
        """Initialize the client with domain-scoped cookies."""
        self._lock = threading.RLock()
        self.session = AllowlistedSession()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{PORTAL_BASE_URL}/Dashboard",
        })
        self.price_per_kwh = price_per_kwh

        # Session telemetry
        self.session_established_at: str | None = None
        self.last_sso_renewal: str | None = None
        self.sso_renewals: int = 0
        self.last_keepalive: str | None = None
        self.okta_session_expired_at: str | None = None

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

    @_locked
    def export_cookies(self) -> list[dict[str, Any]]:
        """Export cookies as a list of dicts for persistence."""
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
        if path.strip("/") == "":
            return True
        if any(marker in path for marker in _LOGIN_PATH_MARKERS):
            return True
        if resp.status_code in (401, 403):
            return True
        return self._is_okta_widget(resp)

    @staticmethod
    def _is_okta_widget(resp: requests.Response) -> bool:
        """Return True if the response renders the Okta sign-in widget."""
        return any(marker in resp.text for marker in _OKTA_WIDGET_MARKERS)

    def _mark_session_ok(self) -> None:
        """Record a confirmed logged-in portal session."""
        if not self.session_established_at:
            self.session_established_at = datetime.now(UTC).isoformat()
        self.okta_session_expired_at = None

    def _mark_okta_expired(self) -> None:
        self.okta_session_expired_at = datetime.now(UTC).isoformat()

    def _get_dashboard(self, timeout: int = 20) -> requests.Response:
        """GET /Dashboard; network errors and 5xx are transient."""
        try:
            resp = self.session.get(
                f"{PORTAL_BASE_URL}/Dashboard", allow_redirects=True, timeout=timeout
            )
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error connecting to PSE&G: {err}") from err
        if resp.status_code >= 500:
            raise PsegTransientError(f"PSE&G portal returned HTTP {resp.status_code}")
        return resp

    @_locked
    def ensure_session(self) -> bool:
        """Validate whether portal session is active, attempting SSO renewal if expired."""
        resp = self._get_dashboard()
        if self._is_login_page(resp):
            return self.renew_sso()
        if resp.status_code != 200:
            raise PsegTransientError(f"Unexpected HTTP {resp.status_code} from /Dashboard")
        self._mark_session_ok()
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

        parsed_final = urllib.parse.urlparse(resp.url)
        on_okta_signin = parsed_final.hostname == OKTA_HOST and any(
            marker in parsed_final.path.lower() for marker in _SIGNIN_PATH_MARKERS
        )
        if self._is_okta_widget(resp) or on_okta_signin:
            self._mark_okta_expired()
            raise PsegOktaSessionExpired("Okta session expired: sign-in widget returned")

        if resp.status_code != 200:
            raise PsegTransientError(f"SSO sign-in returned HTTP {resp.status_code}")

        html = resp.text
        soup = BeautifulSoup(html, "html.parser")
        # Post the form that actually carries the assertion, not the first form on the
        # page (Okta pages can include other forms, e.g. sign-out).
        saml_input = soup.find("input", attrs={"name": "SAMLResponse"})
        form = saml_input.find_parent("form") if saml_input else None

        if not form:
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
            self._mark_okta_expired()
            raise PsegOktaSessionExpired("Failed to establish portal session after SAML post")
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
        """Cheap keepalive check run every 30 minutes in the executor.

        Returns False on transient errors; raises PsegOktaSessionExpired when the Okta
        session is gone so the coordinator can start reauth.
        """
        self.last_keepalive = datetime.now(UTC).isoformat()
        try:
            return self.ensure_session()
        except PsegTransientError as err:
            _LOGGER.debug("Keepalive network check encountered transient error: %s", err)
            return False

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
            self.renew_sso()
            resp = self._get_dashboard(timeout=25)
            if self._is_login_page(resp):
                self._mark_okta_expired()
                raise PsegOktaSessionExpired("Portal still logged out after SSO renewal")

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
                "UsageInterval": "6",
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
                        self.okta_session_expired_at = datetime.now(UTC).isoformat()
                        raise PsegOktaSessionExpired("Session expired during history backfill: Redirected to login")
                _LOGGER.warning("No chart data returned for range %s to %s", chunk_start_str, chunk_end_str)
                chunks.append((chunk_start_str, chunk_end_str, False))
            else:
                series_list = chart_data.get("series", [])
                meter_series = {}
                for s in series_list:
                    if "Meter" in str(s.get("name") or ""):
                        meter_series = s
                        break

                pts = meter_series.get("data", [])
                chunks.append(
                    (chunk_start_str, chunk_end_str, any(isinstance(pt, dict) for pt in pts))
                )
                for pt in pts:
                    if isinstance(pt, dict):
                        kwh = round(pt.get("y", 0.0), 2)
                        hs = pt.get("hs", {})
                        p_start = hs.get("start", "")
                        try:
                            dt = datetime.strptime(p_start, "%m/%d/%Y")
                            date_iso = dt.strftime("%Y-%m-%d")
                        except Exception:
                            date_iso = p_start

                        est_cost = round(kwh * self.price_per_kwh, 2)
                        records_map[date_iso] = {
                            "date": date_iso,
                            "kwh": kwh,
                            "cost": est_cost,
                        }

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
        """Fetch usage and temperature data using the 3-step MyMeter chart sequence."""
        token = self._get_verification_token()

        end_dt = datetime.now()
        start_dt = end_dt - timedelta(days=days_back)
        chart_setup_data = {
            "__RequestVerificationToken": token,
            "UsageInterval": "6",
            "UsageType": "1",
            "jsTargetName": "StorageType",
            "EnableHoverChart": "true",
            "Start": start_dt.strftime("%Y-%m-%d"),
            "End": end_dt.strftime("%Y-%m-%d"),
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
            if resp2.status_code >= 500:
                raise PsegTransientError(f"Server error {resp2.status_code} setting chart context")
            resp2.raise_for_status()
        except (requests.Timeout, requests.ConnectionError) as err:
            raise PsegTransientError(f"Network timeout/connection error: {err}") from err
        except requests.RequestException as err:
            raise PsegTransientError(f"Failed to set chart context: {err}") from err

        ts = int(time.time() * 1000)
        try:
            resp3 = self.session.get(
                f"{PORTAL_BASE_URL}/Dashboard/ChartData",
                params={"_": ts},
                headers=headers2,
                timeout=25,
            )
            if resp3.status_code >= 500:
                raise PsegTransientError(f"Server error {resp3.status_code} fetching chart data")
            resp3.raise_for_status()
            data = resp3.json()
        except (requests.Timeout, requests.ConnectionError) as err:
            raise PsegTransientError(f"Network timeout/connection error: {err}") from err
        except json.JSONDecodeError as err:
            raise PsegTransientError(f"Failed to decode JSON from chart data: {err}") from err
        except requests.RequestException as err:
            raise PsegTransientError(f"Failed to retrieve chart data: {err}") from err

        return self._parse_chart_data(data)

    def _parse_chart_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse series into clean sensor model."""
        chart_data = data.get("Data")
        if not chart_data or not isinstance(chart_data, dict):
            ajax_results = data.get("AjaxResults") or []
            for ar in ajax_results:
                if isinstance(ar, dict) and ar.get("Action") == "Redirect":
                    self.okta_session_expired_at = datetime.now(UTC).isoformat()
                    raise PsegOktaSessionExpired("Session expired: Redirected to login portal")
            raise PsegTransientError("No chart data returned from MyMeter.")

        series_list = chart_data.get("series", [])
        if not series_list:
            raise PsegTransientError("No series data returned from MyMeter.")

        nav_series = series_list[0].get("data", [])
        meter_series = {}
        temp_series = {}

        for s in series_list:
            name = str(s.get("name") or "")
            if "Meter" in name:
                meter_series = s
            elif "Temperature" in name:
                temp_series = s

        meter_name = meter_series.get("name") or DEFAULT_METER_NAME
        detailed_pts = meter_series.get("data", [])
        temp_pts = temp_series.get("data", [])

        history_14d = []
        for pt in detailed_pts:
            if isinstance(pt, dict):
                kwh = round(pt.get("y", 0.0), 2)
                hs = pt.get("hs", {})
                start_str = hs.get("start", "")
                try:
                    dt = datetime.strptime(start_str, "%m/%d/%Y")
                    date_iso = dt.strftime("%Y-%m-%d")
                except Exception:
                    date_iso = start_str

                est_cost = round(kwh * self.price_per_kwh, 2)
                history_14d.append({
                    "date": date_iso,
                    "kwh": kwh,
                    "cost": est_cost,
                })

        latest_record = history_14d[-1] if history_14d else {"date": "None", "kwh": 0.0, "cost": 0.0}
        prev_record = history_14d[-2] if len(history_14d) > 1 else {"date": "None", "kwh": 0.0, "cost": 0.0}

        latest_temp = temp_pts[-1] if temp_pts else {}
        temp_range = latest_temp.get("tr", "")

        return {
            "meter": meter_name,
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

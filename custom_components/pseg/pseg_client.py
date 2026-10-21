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
    DEFAULT_PRICE_PER_KWH,
    OKTA_HOST,
    PORTAL_BASE_URL,
    PORTAL_HOST,
)

_LOGGER = logging.getLogger(__name__)


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
        parsed = urllib.parse.urlparse(request.url)
        if parsed.hostname not in ALLOWED_HOSTS:
            raise PsegSecurityError(
                f"Request to unauthorized host blocked: {parsed.hostname or request.url}"
            )
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

        if cookie_list:
            self.import_cookies(cookie_list)
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
                self.session.cookies.set(name, val, domain=domain, path="/")

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
                self.session.cookies.set(name, val, domain=domain, path=path)

    def _is_login_page(self, resp: requests.Response) -> bool:
        """Check if response indicates an unauthenticated or login state."""
        url_lower = resp.url.lower()
        if "signin" in url_lower or "login" in url_lower:
            return True
        parsed = urllib.parse.urlparse(resp.url)
        if parsed.path.strip("/") == "":
            return True
        text_lower = resp.text.lower()
        if "oktasignin" in text_lower or "statetoken" in text_lower or "sign in" in text_lower or "login" in text_lower:
            return True
        return False

    @_locked
    def ensure_session(self) -> bool:
        """Validate whether portal session is active, attempting SSO renewal if expired."""
        try:
            resp = self.session.get(f"{PORTAL_BASE_URL}/Dashboard", allow_redirects=True, timeout=20)
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error connecting to PSE&G: {err}") from err

        if resp.status_code == 200 and not self._is_login_page(resp):
            if not self.session_established_at:
                self.session_established_at = datetime.now(UTC).isoformat()
            return True

        return self.renew_sso()

    @_locked
    def renew_sso(self) -> bool:
        """Perform SSO renewal using Okta session and SAML auto-post form."""
        _LOGGER.debug("Attempting SSO renewal via Okta...")
        try:
            resp = self.session.get(
                f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
                allow_redirects=True,
                timeout=25,
            )
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error during SSO sign-in: {err}") from err

        html = resp.text
        if "OktaSignIn" in html or "stateToken" in html or (OKTA_HOST in resp.url and "/signin" in resp.url.lower()):
            self.okta_session_expired_at = datetime.now(UTC).isoformat()
            raise PsegOktaSessionExpired("Okta session expired: sign-in widget returned")

        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        saml_input = soup.find("input", attrs={"name": "SAMLResponse"})

        if not form or not saml_input:
            if "sign in" in html.lower() or "login" in html.lower():
                self.okta_session_expired_at = datetime.now(UTC).isoformat()
                raise PsegOktaSessionExpired("Okta session expired: unauthenticated login page returned")
            self.okta_session_expired_at = datetime.now(UTC).isoformat()
            raise PsegOktaSessionExpired("SAML response form not found in SSO response")

        action = form.get("action")
        if not action:
            self.okta_session_expired_at = datetime.now(UTC).isoformat()
            raise PsegOktaSessionExpired("SAML form missing action attribute")

        action_url = urllib.parse.urljoin(resp.url, action)
        parsed_action = urllib.parse.urlparse(action_url)
        if parsed_action.hostname not in ALLOWED_HOSTS:
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

        try:
            dash_resp = self.session.get(f"{PORTAL_BASE_URL}/Dashboard", allow_redirects=True, timeout=20)
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error verifying dashboard after SSO: {err}") from err

        if dash_resp.status_code == 200 and not self._is_login_page(dash_resp):
            now_iso = datetime.now(UTC).isoformat()
            self.last_sso_renewal = now_iso
            self.sso_renewals += 1
            if not self.session_established_at:
                self.session_established_at = now_iso
            _LOGGER.info("SSO renewal successful")
            return True

        self.okta_session_expired_at = datetime.now(UTC).isoformat()
        raise PsegOktaSessionExpired("Failed to establish portal session after SAML post")

    @_locked
    def keepalive(self) -> bool:
        """Cheap keepalive check run every 30 minutes in the executor."""
        self.last_keepalive = datetime.now(UTC).isoformat()
        try:
            resp = self.session.get(f"{PORTAL_BASE_URL}/Dashboard", allow_redirects=True, timeout=15)
            if resp.status_code == 200 and not self._is_login_page(resp):
                return True
            return self.renew_sso()
        except (PsegTransientError, requests.RequestException) as err:
            _LOGGER.debug("Keepalive network check encountered transient error: %s", err)
            return False

    @_locked
    def test_connection(self) -> bool:
        """Validate session during setup or re-auth."""
        return self.ensure_session()

    @_locked
    def _get_verification_token(self) -> str:
        """Extract __RequestVerificationToken from /Dashboard, renewing session if needed."""
        try:
            resp = self.session.get(f"{PORTAL_BASE_URL}/Dashboard", timeout=25)
        except requests.RequestException as err:
            raise PsegTransientError(f"Network error fetching /Dashboard: {err}") from err

        if self._is_login_page(resp):
            _LOGGER.debug("Portal session expired during token check; attempting renewal")
            self.ensure_session()
            try:
                resp = self.session.get(f"{PORTAL_BASE_URL}/Dashboard", timeout=25)
            except requests.RequestException as err:
                raise PsegTransientError(f"Network error fetching /Dashboard after renewal: {err}") from err

        dash_html = resp.text
        soup = BeautifulSoup(dash_html, "html.parser")
        tag = soup.find("input", attrs={"name": "__RequestVerificationToken"})
        if not tag or not tag.get("value"):
            raise PsegOktaSessionExpired("Session invalid: __RequestVerificationToken not found on /Dashboard")
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
            else:
                series_list = chart_data.get("series", [])
                meter_series = {}
                for s in series_list:
                    if "Meter" in str(s.get("name") or ""):
                        meter_series = s
                        break

                pts = meter_series.get("data", [])
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

        meter_name = meter_series.get("name") or "PSE&G Electric Meter"
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

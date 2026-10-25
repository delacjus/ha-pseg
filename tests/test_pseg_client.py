"""Unit tests for PSE&G API client."""

from datetime import UTC, date, datetime, timedelta
import json
import logging
import traceback
from unittest.mock import patch
import urllib.parse

import pytest
import requests
import requests_mock

from custom_components.pseg.const import (
    AUTH_REASON_OKTA_SESSION_EXPIRED,
    AUTH_REASON_PORTAL_SESSION_EXPIRED,
    AUTH_REASON_REMEMBER_ME_REJECTED,
    OKTA_HOST,
    PORTAL_BASE_URL,
    PORTAL_HOST,
)
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegLoginRedirected,
    PsegLoginRejected,
    PsegOktaSessionExpired,
    PsegSecurityError,
    PsegTransientError,
)
from custom_components.pseg.statistics_hourly import (
    NY_TZ,
    expected_hour_starts,
    ny_midnight_utc,
    validate_hourly_day,
)

SAMPLE_AUTOPOST_FORM = f"""
<html>
  <body>
    <form id="appForm" method="POST" action="https://{PORTAL_HOST}/Saml/okta-prod/Acs">
      <input type="hidden" name="SAMLResponse" value="mock_saml_response_data"/>
      <input type="hidden" name="RelayState" value="mock_relay_state"/>
    </form>
  </body>
</html>
"""

# MyMeter bounces anonymous /Dashboard requests to its public home page.
LOGGED_OUT_REDIRECT = {"status_code": 302, "headers": {"Location": "/"}}
PORTAL_HOME = "<html><body><a href='/Saml/okta-prod/SignIn'>Sign in</a></body></html>"

SAMPLE_OKTA_WIDGET = """
<html>
  <head><title>Okta Sign-In</title></head>
  <body>
    <div id="okta-login-container"></div>
    <script>
      var oktaSignIn = new OktaSignIn({ stateToken: "00mockStateToken" });
      oktaSignIn.renderEl({ el: '#okta-login-container' });
    </script>
  </body>
</html>
"""


def test_cookie_parsing_domain_scoped() -> None:
    """Test that Okta and Portal cookies are loaded into their respective domains."""
    okta_str = "idx=mock_idx_123; sid=mock_sid_456"
    portal_str = "MM_SID=mock_portal_session; Saml2.auth=mock_saml"

    client = PsegClient(okta_cookies=okta_str, portal_cookies=portal_str)

    # Check cookies in jar
    cookie_dict = {c.name: (c.value, c.domain) for c in client.session.cookies}
    assert "idx" in cookie_dict
    assert cookie_dict["idx"] == ("mock_idx_123", OKTA_HOST)
    assert "sid" in cookie_dict
    assert cookie_dict["sid"] == ("mock_sid_456", OKTA_HOST)

    assert "MM_SID" in cookie_dict
    assert cookie_dict["MM_SID"] == ("mock_portal_session", PORTAL_HOST)
    assert "Saml2.auth" in cookie_dict
    assert cookie_dict["Saml2.auth"] == ("mock_saml", PORTAL_HOST)

    # Export & import
    exported = client.export_cookies()
    assert len(exported) == 4
    new_client = PsegClient(cookie_list=exported)
    new_dict = {c.name: (c.value, c.domain) for c in new_client.session.cookies}
    assert new_dict == cookie_dict


def test_host_allowlist_enforced() -> None:
    """Test that requests to hosts outside the allowlist are immediately blocked."""
    client = PsegClient()

    with pytest.raises(PsegSecurityError, match="unauthorized host"):
        client.session.get("http://10.0.1.51:8000/login")

    with pytest.raises(PsegSecurityError, match="unauthorized host"):
        client.session.get("http://127.0.0.1:8000/health")

    with pytest.raises(PsegSecurityError, match="unauthorized host"):
        client.session.get("http://localhost:8000/test")

    with pytest.raises(PsegSecurityError, match="unauthorized host"):
        client.session.get("https://evil-exfiltration.com/data")


def test_sso_renewal_success() -> None:
    """Test successful SSO renewal with SAML auto-post form."""
    client = PsegClient(okta_cookies="idx=mock_idx")

    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)

        # SSO Sign-In URL returns auto-post form
        m.get(
            f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
            text=SAMPLE_AUTOPOST_FORM,
            status_code=200,
        )

        # Posting SAML response to ACS
        m.post(
            f"https://{PORTAL_HOST}/Saml/okta-prod/Acs",
            headers={
                "Set-Cookie": "MM_SID=new_portal_session; Domain=mysmartenergy.nj.pseg.com; Path=/"
            },
            status_code=302,
        )

        # After renewal, Dashboard succeeds
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                LOGGED_OUT_REDIRECT,  # Initial ensure_session check bounces to home
                {
                    "text": "<html><head><title>Dashboard</title></head><body><h1>Welcome</h1></body></html>",
                    "status_code": 200,
                },  # Verification after SSO
            ],
        )

        assert client.ensure_session() is True
        assert client.sso_renewals == 1
        assert client.last_sso_renewal is not None
        assert client.session_established_at is not None


def test_sso_renewal_okta_widget_expired() -> None:
    """Test that encountering Okta Sign-In Widget raises PsegOktaSessionExpired."""
    client = PsegClient(okta_cookies="idx=expired_token")

    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.get(
            f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
            text=SAMPLE_OKTA_WIDGET,
            status_code=200,
        )

        with pytest.raises(PsegOktaSessionExpired, match="widget returned"):
            client.ensure_session()

        assert client.okta_session_expired_at is not None


def test_sso_renewal_unauthorized_form_action() -> None:
    """Test that a SAML form pointing to an external domain is rejected."""
    client = PsegClient(okta_cookies="idx=mock")

    malicious_form = """
    <html><body>
      <form id="appForm" method="POST" action="https://attacker.com/steal-saml">
        <input type="hidden" name="SAMLResponse" value="secret"/>
      </form>
    </body></html>
    """
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.get(
            f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
            text=malicious_form,
            status_code=200,
        )

        with pytest.raises(PsegSecurityError, match="untrusted host"):
            client.ensure_session()


def test_network_transient_error() -> None:
    """Test that network connection errors or timeouts raise PsegTransientError."""
    client = PsegClient()

    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", exc=requests.exceptions.ConnectTimeout("timeout"))

        with pytest.raises(PsegTransientError, match="Network error connecting"):
            client.ensure_session()


def test_keepalive() -> None:
    """Test keepalive behavior."""
    client = PsegClient(okta_cookies="idx=x")

    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text="<h1>Dashboard</h1>", status_code=200)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_AUTOPOST_FORM)
        m.post(f"https://{PORTAL_HOST}/Saml/okta-prod/Acs", text="ok")
        # Keepalive always goes through Okta, even with a live portal session, so the
        # Okta idle timer (~30 min observed) is reset every interval.
        assert client.keepalive() is True
        assert client.last_keepalive is not None
        assert sso.called is True
        assert client.sso_renewals == 1

        # Network blip during keepalive returns False, does not raise
        m.get(
            f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
            exc=requests.exceptions.ConnectionError("offline"),
        )
        assert client.keepalive() is False


def test_custom_price_per_kwh() -> None:
    """Test that custom price_per_kwh is used for cost estimation."""
    client = PsegClient(price_per_kwh=0.30)
    data = {
        "Data": {
            "series": [{"name": "Meter #1", "data": [{"y": 10.0, "hs": {"start": "10/15/2026"}}]}]
        }
    }
    parsed = client._parse_chart_data(data)
    assert parsed["latest_kwh"] == 10.0
    assert parsed["latest_cost"] == 3.0  # 10.0 * 0.30


# --- Review r1 H4: transient errors must never be classified as an expired Okta session ---

DASHBOARD_WITH_TOKEN = (
    '<html><input name="__RequestVerificationToken" value="tok"/>'
    '<a href="/Account/LogOff">Log out</a><script>var loginUrl="/";</script>'
    "<p>Sign in to see more</p></html>"
)
CHART_JSON = {
    "Data": {"series": [{"name": "Meter #1", "data": [{"y": 1.0, "hs": {"start": "10/20/2026"}}]}]}
}


def test_sso_signin_5xx_is_transient() -> None:
    """A 503 from the SSO endpoint is an outage, not an expired session."""
    client = PsegClient(okta_cookies="idx=abc")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.get(
            f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
            status_code=503,
            text="<html>Service Unavailable</html>",
        )
        with pytest.raises(PsegTransientError):
            client.ensure_session()
    assert client.okta_session_expired_at is None


def test_dashboard_5xx_is_transient_without_renewal() -> None:
    """A 5xx from /Dashboard is transient and must not trigger SSO renewal."""
    client = PsegClient(portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard", status_code=502, text="Bad gateway, please login later"
        )
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_OKTA_WIDGET)
        with pytest.raises(PsegTransientError):
            client.ensure_session()
    assert sso.called is False
    assert client.okta_session_expired_at is None


def test_logged_in_page_mentioning_login_is_logged_in() -> None:
    """Dashboard wording ("Log out", loginUrl, "Sign in") is not a logged-out signal."""
    client = PsegClient(portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_OKTA_WIDGET)
        assert client.ensure_session() is True
    assert sso.called is False


def test_missing_token_without_login_redirect_is_transient() -> None:
    """A maintenance page at /Dashboard (no token, no redirect) is transient."""
    client = PsegClient(portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            text="<html>Scheduled maintenance. Please sign in again later.</html>",
        )
        with pytest.raises(PsegTransientError, match="RequestVerificationToken"):
            client.fetch_energy_data(14)
    assert client.okta_session_expired_at is None


def test_sso_page_without_saml_form_is_transient() -> None:
    """An unexpected SSO page (no widget, no SAML form) is transient, not expired."""
    client = PsegClient(okta_cookies="idx=abc")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.get(
            f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
            text="<html>Something went wrong. Please login again.</html>",
        )
        with pytest.raises(PsegTransientError, match="SAML response form not found"):
            client.ensure_session()
    assert client.okta_session_expired_at is None


def test_redirect_to_okta_signin_path_is_expired() -> None:
    """Landing on Okta's /signin path (even without widget markers) means logged out."""
    client = PsegClient(okta_cookies="idx=old")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.get(
            f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
            status_code=302,
            headers={"Location": f"https://{OKTA_HOST}/signin?fromURI=%2Fapp"},
        )
        m.get(f"https://{OKTA_HOST}/signin", text="<html>Loading...</html>")
        with pytest.raises(PsegOktaSessionExpired):
            client.ensure_session()
    assert client.okta_session_expired_at is not None


def test_expired_flag_cleared_after_successful_fetch() -> None:
    """okta_session_expired_at is cleared once the portal session works again."""
    client = PsegClient(portal_cookies="MM_SID=x")
    client.okta_session_expired_at = "2026-10-20T00:00:00+00:00"
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="")
        m.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=CHART_JSON)
        data = client.fetch_energy_data(14)
    assert data["latest_kwh"] == 1.0
    assert client.okta_session_expired_at is None

    client.okta_session_expired_at = "2026-10-20T00:00:00+00:00"
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_AUTOPOST_FORM)
        m.post(f"https://{PORTAL_HOST}/Saml/okta-prod/Acs", text="ok")
        assert client.keepalive() is True
    assert client.okta_session_expired_at is None


# --- Review r1 L10: allowlist must also pin https and port 443 ---


def test_http_downgrade_redirect_blocked_before_cookies_sent() -> None:
    """A redirect to http:// on an allowlisted host must be refused before sending cookies."""
    client = PsegClient(okta_cookies="idx=SECRETOKTA", portal_cookies="MM_SID=SECRETPORTAL")
    seen: dict = {}
    with requests_mock.Mocker() as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            status_code=302,
            headers={"Location": f"http://{PORTAL_HOST}:8080/x"},
        )

        def capture(req, ctx):
            seen["cookie"] = req.headers.get("Cookie")
            return "<html>Dashboard</html>"

        m.get(f"http://{PORTAL_HOST}:8080/x", text=capture)
        with pytest.raises(PsegSecurityError):
            client.ensure_session()
    assert "cookie" not in seen


@pytest.mark.parametrize(
    "url",
    [
        f"http://{PORTAL_HOST}/Dashboard",
        f"https://{PORTAL_HOST}:8443/Dashboard",
        f"http://{OKTA_HOST}/signin",
    ],
)
def test_allowlist_requires_https_default_port(url: str) -> None:
    """Allowlisted hosts are only reachable over https on the default port."""
    client = PsegClient()
    with requests_mock.Mocker() as m:
        m.get(url, text="x")
        with pytest.raises(PsegSecurityError):
            client.session.get(url)
        assert m.called is False


def test_allowlist_permits_https_with_explicit_443() -> None:
    client = PsegClient()
    with requests_mock.Mocker() as m:
        m.get(f"https://{PORTAL_HOST}:443/Dashboard", text="ok")
        assert client.session.get(f"https://{PORTAL_HOST}:443/Dashboard").text == "ok"


def test_pasted_and_restored_cookies_are_secure() -> None:
    """Cookies from the paste (and from a persisted jar without the flag) are https-only."""
    client = PsegClient(okta_cookies="idx=a", portal_cookies="MM_SID=b")
    assert all(c.secure for c in client.session.cookies)
    restored = PsegClient(
        cookie_list=[{"name": "MM_SID", "value": "b", "domain": PORTAL_HOST, "path": "/"}]
    )
    assert all(c.secure for c in restored.session.cookies)


# --- Review r1 L13: SAML form selection and action host ---

OKTA_SAML_URL = f"https://{OKTA_HOST}/app/pseg/exk1/sso/saml"


def _sso_to_okta(m, html: str) -> None:
    m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
    m.get(
        f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
        status_code=302,
        headers={"Location": OKTA_SAML_URL},
    )
    m.get(OKTA_SAML_URL, text=html)


def test_saml_post_uses_form_containing_saml_response() -> None:
    """A decoy form before the SAML form must not be posted."""
    client = PsegClient(okta_cookies="idx=ok")
    html = f"""
    <html><body>
      <form id="signout" method="POST" action="/login/signout"><input name="x" value="1"/></form>
      <form id="appForm" method="POST" action="https://{PORTAL_HOST}/Saml/okta-prod/Acs">
        <input type="hidden" name="SAMLResponse" value="assertion"/>
        <input type="hidden" name="RelayState" value="relay"/>
      </form>
    </body></html>
    """
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, {"text": "<html>Dashboard</html>"}],
        )
        _sso_to_okta(m, html)
        signout = m.post(f"https://{OKTA_HOST}/login/signout", text="bye")
        acs = m.post(f"https://{PORTAL_HOST}/Saml/okta-prod/Acs", text="ok")
        assert client.ensure_session() is True
    assert signout.called is False
    assert acs.call_count == 1
    assert "SAMLResponse=assertion" in acs.last_request.text
    assert "RelayState=relay" in acs.last_request.text


def test_saml_action_must_be_portal_host() -> None:
    """The SAML assertion may only be posted to the portal, not to another allowlisted host."""
    client = PsegClient(okta_cookies="idx=ok")
    html = """
    <html><body>
      <form method="POST" action="/api/v1/sessions/me/lifecycle/refresh">
        <input type="hidden" name="SAMLResponse" value="assertion"/>
      </form>
    </body></html>
    """
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        _sso_to_okta(m, html)
        okta_post = m.post(f"https://{OKTA_HOST}/api/v1/sessions/me/lifecycle/refresh", text="x")
        with pytest.raises(PsegSecurityError, match="untrusted host"):
            client.ensure_session()
    assert okta_post.called is False


# --- Review r2 N4/N5: SAML success page and post-SAML bounce classification ---

SAML_FORM_TO_ACS = (
    f'<form method="post" action="https://{PORTAL_HOST}/Saml/okta-prod/Acs">'
    '<input name="SAMLResponse" value="x"/></form>'
)


def test_saml_success_page_mentioning_state_token_is_not_expired() -> None:
    """A SAML auto-post page wins over widget-marker text elsewhere on the page."""
    client = PsegClient(okta_cookies="idx=ok")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}],
        )
        _sso_to_okta(m, f"<script>var stateToken=null;</script>{SAML_FORM_TO_ACS}")
        acs = m.post(f"https://{PORTAL_HOST}/Saml/okta-prod/Acs", text="ok")
        assert client.ensure_session() is True
    assert acs.call_count == 1
    assert client.okta_session_expired_at is None


R2_WIDGET = (
    '<html><script src="/okta-sign-in.min.js"></script><script>'
    'var config = {stateToken: "02abc"}; new OktaSignIn(config);</script></html>'
)


@pytest.mark.parametrize("path", ["ensure_session", "fetch"])
def test_okta_sso_saml_widget_page_is_expired(path: str) -> None:
    """Okta rendering the sign-in widget at /sso/saml (live shape) means the session is gone."""
    client = PsegClient(okta_cookies="idx=old")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        _sso_to_okta(m, R2_WIDGET)
        with pytest.raises(PsegOktaSessionExpired):
            if path == "ensure_session":
                client.ensure_session()
            else:
                client.fetch_energy_data(14)
    assert client.okta_session_expired_at is not None


@pytest.mark.parametrize(
    "variant", ["dash_503", "dash_to_maintenance", "okta_503", "okta_plain_200", "acs_500"]
)
def test_portal_and_okta_outages_are_transient(variant: str) -> None:
    """Outage shapes from review r2 never classify as an expired session."""
    client = PsegClient(okta_cookies="idx=old")
    with requests_mock.Mocker(session=client.session) as m:
        if variant == "dash_503":
            m.get(f"{PORTAL_BASE_URL}/Dashboard", status_code=503, text="down")
        elif variant == "dash_to_maintenance":
            m.get(
                f"{PORTAL_BASE_URL}/Dashboard",
                status_code=302,
                headers={"Location": f"{PORTAL_BASE_URL}/Maintenance"},
            )
            m.get(f"{PORTAL_BASE_URL}/Maintenance", text="<html>Scheduled maintenance</html>")
        else:
            m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
            m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
            m.get(
                f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn",
                status_code=302,
                headers={"Location": OKTA_SAML_URL},
            )
            if variant == "okta_503":
                m.get(OKTA_SAML_URL, status_code=503, text="Service Unavailable")
            elif variant == "okta_plain_200":
                m.get(OKTA_SAML_URL, text="<html>Something went wrong</html>")
            else:
                m.get(OKTA_SAML_URL, text=SAML_FORM_TO_ACS)
                m.post(f"https://{PORTAL_HOST}/Saml/okta-prod/Acs", status_code=500)
        with pytest.raises(PsegTransientError):
            client.fetch_energy_data(14)
    assert client.okta_session_expired_at is None


def test_post_saml_home_bounce_without_widget_is_transient() -> None:
    """Okta issued an assertion but the portal still bounces to "/" (maintenance): transient."""
    client = PsegClient(okta_cookies="idx=ok")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        _sso_to_okta(m, SAML_FORM_TO_ACS)
        m.post(
            f"https://{PORTAL_HOST}/Saml/okta-prod/Acs",
            status_code=302,
            headers={"Location": f"{PORTAL_BASE_URL}/Dashboard"},
        )
        with pytest.raises(PsegTransientError):
            client.ensure_session()
        with pytest.raises(PsegTransientError):
            client.fetch_energy_data(14)
    assert client.okta_session_expired_at is None


def test_post_saml_landing_on_okta_widget_is_expired() -> None:
    """After the SAML post, ending on the Okta widget still means the session is gone."""
    client = PsegClient(okta_cookies="idx=ok")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                LOGGED_OUT_REDIRECT,
                {"status_code": 302, "headers": {"Location": f"https://{OKTA_HOST}/signin"}},
            ],
        )
        m.get(f"https://{OKTA_HOST}/signin", text=R2_WIDGET)
        _sso_to_okta(m, SAML_FORM_TO_ACS)
        m.post(f"https://{PORTAL_HOST}/Saml/okta-prod/Acs", text="ok")
        with pytest.raises(PsegOktaSessionExpired):
            client.ensure_session()


# --- Live 2026-10-21: account lists a replaced meter (empty series) after the active one ---


def _meter(name: str, days: list[tuple[str, float]]) -> dict:
    pts = []
    for start, y in days:
        x = int(datetime.strptime(start, "%m/%d/%Y").replace(tzinfo=UTC).timestamp() * 1000)
        pts.append({"x": x, "y": y, "hs": {"start": start, "end": start}, "v": False})
    return {"name": name, "type": "column", "data": pts}


TWO_METER_CHART = {
    "Data": {
        "series": [
            {"data": [[1792281600000, 17.6]], "showInLegend": False},  # unnamed navigator
            _meter(
                "Meter #000303817579 (Residential Service (RS))",
                [("10/18/2026", 17.586), ("10/19/2026", 14.5368)],
            ),
            _meter("Meter #000126274191 (Residential Service (RS))", []),
            {
                "name": "Temperature",
                "type": "spline",
                "data": [{"x": 1792368000000, "y": 46.66, "tr": "31° | 47° | 69°F"}],
            },
            {"name": "Energy Marker", "type": "flags", "data": []},
        ]
    }
}


def test_parse_uses_meter_with_data_when_replaced_meter_listed_last() -> None:
    """The empty replaced meter listed last must not blank out the active meter's usage."""
    parsed = PsegClient(price_per_kwh=0.25)._parse_chart_data(TWO_METER_CHART)
    assert [r["date"] for r in parsed["history_14d"]] == ["2026-10-18", "2026-10-19"]
    assert parsed["latest_kwh"] == 14.54
    assert parsed["previous_kwh"] == 17.59
    assert parsed["meter"].startswith("Meter #000303817579")
    assert parsed["meter_ids"] == ["000303817579", "000126274191"]


def test_parse_sums_both_meters_on_swap_day() -> None:
    """On the swap day both meters report part of the day; the account total is their sum."""
    chart = {
        "Data": {
            "series": [
                _meter("Meter #111 (RS)", [("01/08/2026", 10.0), ("01/09/2026", 4.0)]),
                _meter("Meter #222 (RS)", [("01/09/2026", 6.0), ("01/10/2026", 12.0)]),
            ]
        }
    }
    parsed = PsegClient(price_per_kwh=0.5)._parse_chart_data(chart)
    assert [(r["date"], r["kwh"], r["cost"]) for r in parsed["history_14d"]] == [
        ("2026-01-08", 10.0, 5.0),
        ("2026-01-09", 10.0, 5.0),
        ("2026-01-10", 12.0, 6.0),
    ]
    assert parsed["meter"] == "Meter #222 (RS)"


def test_history_range_reads_every_meter_series() -> None:
    """Backfill takes usage from the active meter even when the empty one is listed first."""
    client = PsegClient(portal_cookies="MM_SID=x")
    chart = {
        "Data": {
            "series": [
                _meter("Meter #000126274191 (RS)", []),
                _meter("Meter #000303817579 (RS)", [("10/18/2026", 17.586)]),
            ]
        }
    }
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        m.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=chart)
        records = client.fetch_history_range("2026-10-18", "2026-10-18")
    assert records == [
        {"date": "2026-10-18", "kwh": 17.59, "cost": round(17.59 * client.price_per_kwh, 2)}
    ]


def test_merge_deduplicates_meter_and_ignores_non_meter_series(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Only the first anchored series for each meter contributes usage."""
    chart = {
        "Data": {
            "series": [
                _meter("Meter #111 (RS)", [("10/18/2026", 10.0)]),
                _meter("Meter #111 (RS) - Previous Year", [("10/18/2026", 99.0)]),
                _meter("Previous Year Meter #222", [("10/18/2026", 50.0)]),
                _meter("  Meter #222 (RS)", [("10/18/2026", 3.0)]),
            ]
        }
    }
    with caplog.at_level("DEBUG"):
        parsed = PsegClient()._parse_chart_data(chart)
    assert parsed["history_14d"][0]["kwh"] == 13.0
    assert parsed["meter_ids"] == ["111", "222"]
    assert "duplicate" in caplog.text.lower()


def test_merge_skips_missing_usage_and_bad_date(caplog: pytest.LogCaptureFixture) -> None:
    """Invalid points must not create zero-kWh or empty-date statistics rows."""
    chart = {
        "Data": {
            "series": [
                {
                    "name": "Meter #111 (RS)",
                    "data": [
                        {"y": None, "hs": {"start": "10/18/2026"}},
                        {"y": "bad", "hs": {"start": "10/19/2026"}},
                        {"y": 2.0, "hs": {"start": "bad date"}},
                        {"y": 1.0, "hs": "bad"},
                        {"y": 3.0, "hs": {"start": "10/20/2026"}},
                    ],
                }
            ]
        }
    }
    with caplog.at_level("DEBUG"):
        parsed = PsegClient()._parse_chart_data(chart)
    assert [(r["date"], r["kwh"]) for r in parsed["history_14d"]] == [("2026-10-20", 3.0)]
    assert "Skipping" in caplog.text


def test_keepalive_reports_okta_expiry() -> None:
    """A keepalive that hits the Okta sign-in widget raises so reauth can start."""
    client = PsegClient(okta_cookies="idx=x", portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_OKTA_WIDGET)
        with pytest.raises(PsegOktaSessionExpired):
            client.keepalive()
    assert client.okta_session_expired_at is not None


# --- Live 2026-10-21: MyMeter local login 'Remember Me' (MM_RememberMe ~1 year) ---

REMEMBER_PORTAL = "MM_SID=dead; MM_RememberMe=remember_token"


def _renewal_identity_fixture(client, mocker):
    """Give admitted renewal tests a real DAILY proof for their known entry."""
    client.set_expected_meter_ids({"12345"})
    mocker.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
    mocker.get(
        f"{PORTAL_BASE_URL}/Dashboard/ChartData",
        json={
            "Data": {
                "series": [
                    {
                        "name": "Meter #12345",
                        "data": [{"y": 4.0, "hs": {"start": "10/22/2026"}}],
                    }
                ]
            }
        },
    )


def test_remember_me_renews_without_okta() -> None:
    """A lapsed MM_SID is re-issued from MM_RememberMe; Okta is never contacted."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    assert client.has_remember_me and not client.has_okta_session
    with requests_mock.Mocker(session=client.session) as m:
        _renewal_identity_fixture(client, m)
        dash = m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_OKTA_WIDGET)
        assert client.ensure_session() is True
    assert sso.called is False
    assert client.sso_renewals == 1
    # The dead MM_SID was dropped before the renewal request.
    retry = [r for r in dash.request_history][-1]
    assert "MM_SID=dead" not in (retry.headers.get("Cookie") or "")
    assert "MM_RememberMe=remember_token" in (retry.headers.get("Cookie") or "")


def test_remember_me_rejected_without_okta_is_auth_expiry() -> None:
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        with pytest.raises(PsegOktaSessionExpired, match="Remember Me"):
            client.ensure_session()
    assert client.okta_session_expired_at is not None


def test_rejected_remember_me_keeps_the_cookie_in_the_jar_and_export() -> None:
    """One unverified GET bounce must not delete the only long-lived renewal cookie.

    Live 2026-10-22 the only datum that bounced was a browser-pasted cookie, so a
    single refusal is not proof the cookie is dead; a later poll may still use it.
    """
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        with pytest.raises(PsegOktaSessionExpired, match="Remember Me"):
            client.renew_remember_me()

    assert client.has_remember_me is True
    assert client.auth_reason == AUTH_REASON_REMEMBER_ME_REJECTED
    assert client.okta_session_expired_at is not None
    exported = {c["name"]: c["value"] for c in client.export_cookies()}
    assert exported.get("MM_RememberMe") == "remember_token"
    # The attempt itself dropped MM_SID, which is why the coordinator must refuse to
    # persist this jar (tests/test_session_lifecycle.py).
    assert "MM_SID" not in exported


def test_remember_me_rejected_falls_back_to_okta_sso() -> None:
    client = PsegClient(okta_cookies="idx=abc", portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                LOGGED_OUT_REDIRECT,
                LOGGED_OUT_REDIRECT,
                LOGGED_OUT_REDIRECT,
                {"text": DASHBOARD_WITH_TOKEN},
            ],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_AUTOPOST_FORM)
        m.post(f"https://{PORTAL_HOST}/Saml/okta-prod/Acs", text="ok")
        assert client.ensure_session() is True
    assert sso.called is True


def test_keepalive_remember_me_only_stays_on_portal() -> None:
    """Without an Okta session the keepalive only touches the portal."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_AUTOPOST_FORM)
        assert client.keepalive() is True
    assert sso.called is False


# --- Review f73a0c0e (Remember Me FIX-FIRST) ---

ANON_HOME = '<html><form action="/Home/Login"><input name="LoginEmail"/><input id="LoginPassword"/></form></html>'


def test_poll_token_renews_via_remember_me_not_okta() -> None:
    """A poll after MM_SID lapse renews from MM_RememberMe (incl. the / fallback), never Okta."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        _renewal_identity_fixture(client, m)
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                LOGGED_OUT_REDIRECT,
                LOGGED_OUT_REDIRECT,
                {"text": DASHBOARD_WITH_TOKEN},
                {"text": DASHBOARD_WITH_TOKEN},
            ],
        )
        home = m.get(f"{PORTAL_BASE_URL}/", text=ANON_HOME)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_OKTA_WIDGET)
        assert client._get_verification_token() == "tok"
    assert sso.called is False
    assert home.called is True
    assert client.sso_renewals == 1


def test_keepalive_mixed_jar_prefers_remember_me() -> None:
    """With both cookie types, keepalive stays on the portal (Okta caps at ~1 h)."""
    client = PsegClient(okta_cookies="idx=x", portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_AUTOPOST_FORM)
        assert client.keepalive() is True
    assert sso.called is False


def test_remember_me_bounce_to_anonymous_page_is_rejected() -> None:
    """A 200 that is not the dashboard (anon /Home/Index) is not a successful renewal."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", status_code=302, headers={"Location": "/Home/Index"})
        m.get(f"{PORTAL_BASE_URL}/Home/Index", text="<html>Welcome</html>")
        m.get(f"{PORTAL_BASE_URL}/", text=ANON_HOME)
        with pytest.raises(PsegOktaSessionExpired):
            client.renew_remember_me()
    assert client.sso_renewals == 0


def test_anonymous_login_form_counts_as_logged_out() -> None:
    client = PsegClient(portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", status_code=302, headers={"Location": "/Home/Index"})
        m.get(f"{PORTAL_BASE_URL}/Home/Index", text=ANON_HOME)
        resp = client._get_dashboard()
    assert client._is_login_page(resp) is True


def test_rotated_dotted_cookie_replaces_pasted_host_cookie() -> None:
    """A server-set .host MM_RememberMe supersedes the pasted host-only copy on export."""
    client = PsegClient(portal_cookies="MM_RememberMe=old")
    client.session.cookies.set("MM_RememberMe", "new", domain=f".{PORTAL_HOST}", path="/")
    exported = [c for c in client.export_cookies() if c["name"] == "MM_RememberMe"]
    assert [c["value"] for c in exported] == ["new"]
    restored = PsegClient(cookie_list=client.export_cookies())
    assert [c.value for c in restored.session.cookies if c.name == "MM_RememberMe"] == ["new"]


# --- Review b786a886 (Remember Me r2) ---


def test_bounce_to_anonymous_home_index_renews() -> None:
    """/Dashboard → /Home/Index without form markers is signed out, so Remember Me renews."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        _renewal_identity_fixture(client, m)
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                {"status_code": 302, "headers": {"Location": "/Home/Index"}},
                {"text": DASHBOARD_WITH_TOKEN},
            ],
        )
        m.get(f"{PORTAL_BASE_URL}/Home/Index", text="<html>Welcome</html>")
        assert client.ensure_session() is True
    assert client.sso_renewals == 1


def test_remember_me_landing_on_maintenance_is_transient() -> None:
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", status_code=302, headers={"Location": "/Maintenance"})
        m.get(f"{PORTAL_BASE_URL}/Maintenance", text="<html>Scheduled maintenance</html>")
        with pytest.raises(PsegTransientError):
            client.renew_remember_me()
    assert client.okta_session_expired_at is None


def test_dedupe_keeps_newer_host_only_cookie_over_older_dotted() -> None:
    """A host-only cookie the server updated is never dropped for an older dotted copy."""
    client = PsegClient(
        cookie_list=[
            {"name": "idx", "value": "old", "domain": f".{OKTA_HOST}", "path": "/"},
            {"name": "idx", "value": "seed", "domain": OKTA_HOST, "path": "/"},
        ]
    )
    client.session.cookies.set("idx", "fresh", domain=OKTA_HOST, path="/")
    values = [c["value"] for c in client.export_cookies() if c["name"] == "idx"]
    assert values == ["fresh"]


# --- Review 6fcb6d2a (Remember Me r3) ---


def test_initial_maintenance_redirect_is_transient_not_success() -> None:
    client = PsegClient(portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", status_code=302, headers={"Location": "/Maintenance"})
        m.get(f"{PORTAL_BASE_URL}/Maintenance", text="<html>Scheduled maintenance</html>")
        with pytest.raises(PsegTransientError):
            client.ensure_session()
    assert client.session_established_at is None


def test_untouched_seed_pair_kept_and_dotted_rotation_wins() -> None:
    pair = [
        {"name": "MM_RememberMe", "value": "a", "domain": f".{PORTAL_HOST}", "path": "/"},
        {"name": "MM_RememberMe", "value": "b", "domain": PORTAL_HOST, "path": "/"},
    ]
    untouched = PsegClient(cookie_list=pair)
    assert sorted(
        c["value"] for c in untouched.export_cookies() if c["name"] == "MM_RememberMe"
    ) == ["a", "b"]
    rotated = PsegClient(cookie_list=pair)
    rotated.session.cookies.set("MM_RememberMe", "new", domain=f".{PORTAL_HOST}", path="/")
    assert [c["value"] for c in rotated.export_cookies() if c["name"] == "MM_RememberMe"] == ["new"]


def test_diag_trace_keeps_only_first_path_segment() -> None:
    client = PsegClient(portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard/secret_token_123?x=y", text="ok")
        client.session.get(f"{PORTAL_BASE_URL}/Dashboard/secret_token_123?x=y")
    diag = client.auth_diagnostics()
    assert "secret_token_123" not in diag and "x=y" not in diag and "MM_SID" in diag


# --- MyMeter email/password login (live 2026-10-21: no captcha on first attempt) ---

LOGIN_OK = {"AjaxResults": [], "Data": {}}


def test_login_local_success_and_password_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    client = PsegClient(email="me@example.com", password="s3cret-pass-998")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/",
            text=ANON_HOME.replace(
                "</form>", '<input name="__RequestVerificationToken" value="af"/></form>'
            ),
        )
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        m.get(f"{PORTAL_BASE_URL}/Dashboard", [LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}])
        assert client.ensure_session() is True
    body = login.last_request.text
    assert "LoginEmail=me%40example.com" in body and "RememberMe=true" in body
    assert login.last_request.headers["RequestVerificationToken"] == "af"
    assert client.sso_renewals == 1
    assert (
        "s3cret-pass-998" not in caplog.text and "s3cret-pass-998" not in client.auth_diagnostics()
    )


@pytest.mark.parametrize(
    "data",
    [
        {"LoginErrorMessage": "Invalid email address or password"},
        {"RecaptchaOnLogin": True},
        {"SecretQuestionError": "x"},
    ],
)
def test_login_local_refusals_raise_without_retry(data: dict) -> None:
    client = PsegClient(email="me@example.com", password="pw")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/", text=ANON_HOME)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json={"AjaxResults": [], "Data": data})
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        with pytest.raises(PsegLoginRejected):
            client.ensure_session()
    assert login.call_count == 1


def test_login_local_that_does_not_reach_dashboard_is_rejected() -> None:
    client = PsegClient(email="me@example.com", password="pw")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/", text=ANON_HOME)
        m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        with pytest.raises(PsegLoginRejected, match="did not reach"):
            client.login_local()


def test_keepalive_with_login_stays_on_portal() -> None:
    client = PsegClient(okta_cookies="idx=x", email="me@example.com", password="pw")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_AUTOPOST_FORM)
        assert client.keepalive() is True
    assert sso.called is False


# --- Review r1: renewal must use a rotated RememberMe before the saved password ---

LOGIN_PAGE_WITH_TOKEN = ANON_HOME.replace(
    "</form>", '<input name="__RequestVerificationToken" value="af"/></form>'
)


def test_renew_tries_remember_me_before_the_saved_login() -> None:
    """A saved RememberMe renews first; the stored password is not used."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL, email="me@example.com", password="pw")
    with requests_mock.Mocker(session=client.session) as m:
        _renewal_identity_fixture(client, m)
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}],
        )
        home = m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)

        assert client._renew() is True

    # requests_mock counts the followed redirect to "/" plus the landing retry.
    assert home.call_count == 2
    assert login.call_count == 0
    assert client.sso_renewals == 1


def test_expired_remember_me_falls_back_to_the_saved_login_once() -> None:
    """A rejected RememberMe is dropped, then the password signs in exactly once."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL, email="me@example.com", password="pw")
    assert client.has_remember_me is True
    with requests_mock.Mocker(session=client.session) as m:
        dash = m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                LOGGED_OUT_REDIRECT,  # Remember Me attempt
                LOGGED_OUT_REDIRECT,  # Remember Me landing retry
                {"text": DASHBOARD_WITH_TOKEN},  # post-login confirmation
            ],
        )
        home = m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)

        assert client._renew() is True

    assert dash.call_count == 3
    # Two followed redirects, the Remember Me landing retry, then the login form.
    assert home.call_count == 4
    assert login.call_count == 1
    # The refused cookie is kept: one GET bounce is not proof it is dead (r2 fix).
    assert client.has_remember_me is True


def test_expired_remember_me_and_rejected_login_does_not_loop() -> None:
    """RememberMe expires once, the password is rejected once, and it stops."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL, email="me@example.com", password="pw")
    with requests_mock.Mocker(session=client.session) as m:
        dash = m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        login = m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={
                "AjaxResults": [],
                "Data": {"LoginErrorMessage": "Invalid email address or password"},
            },
        )

        with pytest.raises(PsegLoginRejected):
            client._renew()

    assert dash.call_count == 2  # one Remember Me attempt, never repeated
    assert login.call_count == 1


def test_remember_me_transient_never_falls_back_to_the_password() -> None:
    """A portal outage is transient: no password attempt and the cookie is kept."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL, email="me@example.com", password="pw")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            status_code=302,
            headers={"Location": "/Maintenance"},
        )
        m.get(f"{PORTAL_BASE_URL}/Maintenance", text="<html>Scheduled maintenance</html>")
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)

        with pytest.raises(PsegTransientError):
            client._renew()

    assert login.call_count == 0
    assert client.has_remember_me is True


# --- Review r2: local email/password sign-in stays on the portal (no Okta hop) ---

LOCAL_EMAIL = "fixture@example.invalid"
LOCAL_PASSWORD = "synthetic-test-only"


@pytest.mark.parametrize("status", [307, 308])
def test_local_login_redirect_to_okta_never_forwards_the_password(status: int) -> None:
    """A 307/308 after the credential POST must not be replayed onto Okta."""
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        post = m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            status_code=status,
            headers={"Location": f"https://{OKTA_HOST}/synthetic-local-route-check"},
        )
        okta = m.post(
            f"https://{OKTA_HOST}/synthetic-local-route-check",
            text="must not receive the password",
        )
        with pytest.raises(PsegLoginRedirected) as err:
            client.login_local()

    assert post.call_count == 1  # the body is sent once, never replayed
    assert okta.call_count == 0
    message = str(err.value) + repr(err.value)
    assert LOCAL_PASSWORD not in message
    assert "synthetic-local-route-check" not in message  # no raw Location echoed


def test_local_login_external_redirect_is_refused_without_a_request(caplog) -> None:
    """A redirect to an arbitrary host is refused and its URL is never logged."""
    caplog.set_level(logging.DEBUG)
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            status_code=302,
            headers={"Location": "https://collector.invalid/synthetic-capture"},
        )
        external = m.post("https://collector.invalid/synthetic-capture", text="captured")
        with pytest.raises(PsegLoginRedirected):
            client.login_local()

    assert external.call_count == 0
    assert "collector.invalid" not in caplog.text
    assert LOCAL_PASSWORD not in caplog.text


def test_local_login_portal_redirect_is_verified_without_reposting_the_body() -> None:
    """A same-portal redirect is accepted; the dashboard GET confirms the session."""
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        post = m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            status_code=302,
            headers={"Location": "/Dashboard"},
        )
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        assert client.login_local() is True

    assert post.call_count == 1
    assert client.sso_renewals == 1


def test_local_login_client_cannot_reach_the_okta_host_at_all() -> None:
    """The saved-login client is restricted to the portal, covering every request."""
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)
    assert client.session.allowed_hosts == frozenset({PORTAL_HOST})
    with pytest.raises(PsegSecurityError):
        client.session.get(f"https://{OKTA_HOST}/sso/saml")
    with pytest.raises(PsegSecurityError):
        client.session.post(f"https://{OKTA_HOST}/synthetic-local-route-check")


def test_legacy_okta_cookie_client_keeps_both_hosts() -> None:
    """Explicit legacy Okta cookie clients retain the original SAML flow."""
    client = PsegClient(okta_cookies="idx=synthetic")
    assert client.session.allowed_hosts == frozenset({OKTA_HOST, PORTAL_HOST})
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"https://{OKTA_HOST}/sso/saml", text="ok")
        assert client.session.get(f"https://{OKTA_HOST}/sso/saml").status_code == 200


@pytest.mark.parametrize(
    "error",
    [
        PsegCaptchaRequired("synthetic captcha"),
        PsegLoginRejected("synthetic rejection"),
        PsegLoginRedirected("synthetic redirect"),
    ],
)
def test_local_login_refusal_never_falls_back_to_okta(error, monkeypatch) -> None:
    """A refused local sign-in raises; it never calls renew_sso."""
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)

    def never_sso(self) -> bool:
        raise AssertionError("local sign-in must not fall back to Okta SSO")

    def reject(self) -> bool:
        raise error

    monkeypatch.setattr(PsegClient, "renew_sso", never_sso)
    monkeypatch.setattr(PsegClient, "login_local", reject)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        with pytest.raises(type(error)):
            client.ensure_session()


class _CannedAdapter(requests.adapters.HTTPAdapter):
    """Network-only mock that runs under the real AllowlistedSession.send.

    requests_mock replaces Session.send, which would bypass the host check under
    test; this adapter only answers the canned URLs and records every request that
    reached the transport layer.
    """

    def __init__(self, responses: dict) -> None:
        super().__init__()
        self.responses = responses
        self.sent: list[tuple[str, str]] = []

    def send(self, request, **kwargs):
        self.sent.append((request.method, request.url))
        spec = self.responses.get(request.url)
        if spec is None:
            raise AssertionError(f"unexpected request {request.method} {request.url}")
        status, headers, body = spec
        resp = requests.Response()
        resp.status_code = status
        resp.headers.update(headers)
        resp._content = body.encode("utf-8")
        resp.encoding = "utf-8"
        resp.url = request.url
        resp.request = request
        return resp


def test_local_dashboard_redirect_to_okta_is_a_login_rejection() -> None:
    """Following a post-login redirect would hit Okta; the host check refuses first."""
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)
    adapter = _CannedAdapter(
        {
            f"{PORTAL_BASE_URL}/": (200, {}, LOGIN_PAGE_WITH_TOKEN),
            f"{PORTAL_BASE_URL}/Home/Login": (200, {}, json.dumps(LOGIN_OK)),
            f"{PORTAL_BASE_URL}/Dashboard": (
                302,
                {"Location": f"https://{OKTA_HOST}/synthetic-after-login"},
                "",
            ),
        }
    )
    client.session.mount("https://", adapter)

    with pytest.raises(PsegLoginRedirected):
        client.login_local()

    assert adapter.sent
    assert all(OKTA_HOST not in url for _, url in adapter.sent)


@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.parametrize(
    "location",
    [
        f"https://{PORTAL_HOST}:PROOF-CANARY/x",
        "https://[PROOF-CANARY",
    ],
)
def test_local_login_unparseable_redirect_has_no_exception_context(
    status: int, location: str
) -> None:
    """R2: a malformed Location must not ride along as __context__/__cause__.

    requests puts the URL in its own ValueError text, so raising the sanitized
    refusal from inside the parsing handler chained the raw Location (which can
    carry the one-use proof) as __context__ even with ``from None``.
    """
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        post = m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            status_code=status,
            headers={"Location": location},
        )
        with pytest.raises(PsegLoginRedirected) as err:
            client.login_local()

    assert post.call_count == 1
    assert err.value.__context__ is None
    assert err.value.__cause__ is None
    assert "CANARY" not in str(err.value) + repr(err.value)


def test_dashboard_malformed_redirect_is_a_sanitized_transient_error() -> None:
    """R3: a malformed /Dashboard Location must not reach logs or an exception chain.

    requests parses the server's Location eagerly while following redirects. An
    NFKC-invalid netloc raises ValueError whose text carries the raw Location. The
    plain dashboard GET carries no proof or credentials, but its error must still be
    generic and unchained, like the POST path fixed in R2.
    """
    canary = "LOCCANARY"
    malformed = f"https://{canary}\u2100.example/".encode().decode("latin-1")
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)
    adapter = _CannedAdapter({f"{PORTAL_BASE_URL}/Dashboard": (302, {"Location": malformed}, "")})
    client.session.mount("https://", adapter)

    with pytest.raises(PsegTransientError) as err:
        client._get_dashboard()

    assert adapter.sent == [("GET", f"{PORTAL_BASE_URL}/Dashboard")]
    assert str(err.value) == "PSE&G portal returned an invalid redirect"
    assert err.value.__context__ is None
    assert err.value.__cause__ is None
    rendered = "".join(traceback.format_exception(err.value))
    assert canary not in rendered
    assert "\u2100" not in rendered


def test_allowlisted_session_bad_port_error_keeps_no_url_context() -> None:
    """The allowlist's sanitized bad-port refusal must not chain the raw URL."""
    client = PsegClient(email=LOCAL_EMAIL, password=LOCAL_PASSWORD)
    request = requests.PreparedRequest()
    request.method = "GET"
    request.url = f"{PORTAL_BASE_URL}:99999999999999999999/synthetic-canary"
    request.headers = {}

    with pytest.raises(PsegSecurityError) as err:
        client.session.send(request)

    assert err.value.__context__ is None
    assert err.value.__cause__ is None
    assert "canary" not in str(err.value)


# --- Hourly chart leg: defensive parsing, daily authority and explicit fallback ---


def _hourly_chart(
    day: date,
    kwh: float = 1.0,
    *,
    date_only_labels: bool = False,
) -> dict:
    """Build a synthetic hourly payload adhering to the proven contract."""
    points = []
    for start in expected_hour_starts(day):
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        if date_only_labels:
            label = local.strftime("%m/%d/%Y")
            end_label = label
        else:
            label = start.isoformat().replace("+00:00", "Z")
            end_label = (start + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": kwh,
                "hs": {"start": label, "end": end_label},
            }
        )
    return {"Data": {"series": [{"name": "Meter #12345 (RS)", "data": points}]}}


def _daily_chart(day: date, kwh: float) -> dict:
    return {
        "Data": {
            "series": [
                {
                    "name": "Meter #12345 (RS)",
                    "data": [
                        {
                            "x": int(ny_midnight_utc(day).timestamp() * 1000),
                            "y": kwh,
                            "hs": {
                                "start": day.strftime("%m/%d/%Y"),
                                "end": day.strftime("%m/%d/%Y"),
                            },
                        }
                    ],
                }
            ]
        }
    }


def test_fetch_energy_data_requests_hourly_and_keeps_daily_authority() -> None:
    """The poll asks daily then hourly; hourly history is used only when validated."""
    client = PsegClient(portal_cookies="MM_SID=x", price_per_kwh=0.25)
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    daily = _daily_chart(day, 24.04)
    hourly = _hourly_chart(day, 1.0)
    intervals: list[str] = []

    with requests_mock.Mocker(session=client.session) as mock:
        mock.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)

        def chart(request, context):
            interval = urllib.parse.parse_qs(request.text)["UsageInterval"][0]
            intervals.append(interval)
            return "ok"

        def chart_data(request, context):
            return hourly if intervals[-1] == "5" else daily

        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=chart)
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=chart_data)
        parsed = client.fetch_energy_data(14)

    assert intervals == ["6", "5"]
    assert parsed["daily_records"][0]["kwh"] == 24.04
    assert parsed["history_14d"][0]["kwh"] == 24.04  # authoritative daily history
    assert parsed["latest_kwh"] == 24.04
    assert parsed["latest_cost"] == 6.01
    assert parsed["hourly_granularity"] == "hourly"
    assert parsed["hourly_complete_days"] == 1
    assert parsed["statistics_granularity"] == "hourly"
    assert parsed["hourly_records"][0]["start"] == expected_hour_starts(day)[0]
    assert parsed["hourly_records"][-1]["start"] == expected_hour_starts(day)[-1]


@pytest.mark.parametrize("status", [500, 503])
def test_hourly_chart_failure_keeps_daily_statistics(status) -> None:
    """A 5xx on the optional hourly leg must not fail an otherwise good poll."""
    client = PsegClient(portal_cookies="MM_SID=x", price_per_kwh=0.25)
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    daily = _daily_chart(day, 24.02)
    intervals: list[str] = []

    with requests_mock.Mocker(session=client.session) as mock:
        mock.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)

        def chart(request, context):
            intervals.append(urllib.parse.parse_qs(request.text)["UsageInterval"][0])
            return "ok"

        def chart_data(request, context):
            if intervals[-1] == "5":
                context.status_code = status
                return {"error": "unavailable"}
            return daily

        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=chart)
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=chart_data)
        parsed = client.fetch_energy_data(14)

    assert intervals == ["6", "5"]
    assert parsed["hourly_records"] == []
    assert parsed["hourly_granularity"] == "unavailable"
    assert parsed["statistics_granularity"] == "daily"
    assert parsed["history_14d"][0]["kwh"] == 24.02


def test_hourly_chart_redirect_is_an_auth_failure() -> None:
    """A login redirect on the hourly leg is auth loss, not a silent fallback."""
    client = PsegClient(portal_cookies="MM_SID=x")
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    daily = _daily_chart(day, 24.0)
    intervals: list[str] = []

    with requests_mock.Mocker(session=client.session) as mock:
        mock.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)

        def chart(request, context):
            intervals.append(urllib.parse.parse_qs(request.text)["UsageInterval"][0])
            return "ok"

        def chart_data(request, context):
            if intervals[-1] == "5":
                return {"AjaxResults": [{"Action": "Redirect"}]}
            return daily

        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=chart)
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=chart_data)
        with pytest.raises(PsegOktaSessionExpired):
            client.fetch_energy_data(14)


def test_hourly_parser_keeps_zero_and_rejects_invalid_points() -> None:
    """Zero is data; missing x, negative usage and off-hour points are not."""
    client = PsegClient()
    day = date(2026, 10, 20)
    starts = expected_hour_starts(day)

    def _wall_ms(st: datetime) -> int:
        loc = st.astimezone(NY_TZ)
        return int(datetime.combine(loc.date(), loc.time(), tzinfo=UTC).timestamp() * 1000)

    points = [
        {
            "x": _wall_ms(starts[0]),
            "y": 0.0,
            "hs": {"start": "10/20/2026 12:00 AM"},
        },
        {
            "x": _wall_ms(starts[1]),
            "y": 2.0,
            "hs": {"start": "10/20/2026 01:00 AM"},
        },
        {
            "x": _wall_ms(starts[2]),
            "y": 3.0,
            "hs": {"start": "10/20/2026 02:00 AM"},
        },
        {"x": None, "y": 1.0, "hs": {"start": "10/20/2026 03:00 AM"}},
        {"x": _wall_ms(starts[3]), "y": -1.0},
        {"x": _wall_ms(starts[4]) + 1_800_000, "y": 1.0},
    ]
    payload = {
        "Data": {
            "series": [
                {"name": "Meter #1 (RS)", "data": points},
                {
                    "name": "Meter #1 - Previous Year",
                    "data": [{"x": _wall_ms(starts[5]), "y": 99.0}],
                },
            ]
        }
    }

    parsed = client._parse_hourly_chart(payload)

    assert [record["kwh"] for record in parsed["hourly_records"]] == [0.0, 2.0, 3.0]
    assert parsed["hourly_invalid_points"] == 3
    assert parsed["hourly_granularity"] == "hourly"


def test_hourly_label_mismatch_blocks_promotion() -> None:
    """A label that contradicts the UTC hour makes the day ineligible."""
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    payload = _hourly_chart(day)
    for point in payload["Data"]["series"][0]["data"]:
        shifted = datetime.fromtimestamp(point["x"] / 1000, tz=UTC).replace(
            tzinfo=NY_TZ
        ) + timedelta(hours=2)
        point["hs"]["start"] = shifted.strftime("%m/%d/%Y %I:%M %p")

    parsed = PsegClient()._parse_hourly_chart(payload)
    assert all(record["label_ok"] is False for record in parsed["hourly_records"])

    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        float(len(parsed["hourly_records"])),
        datetime.now(UTC),
    )
    assert result.complete is False
    assert result.reason == "label_mismatch"


def test_date_only_labels_prove_interval_start() -> None:
    """Date-only labels now prove interval start under the verified contract."""
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    parsed = PsegClient()._parse_hourly_chart(_hourly_chart(day, date_only_labels=True))
    assert all(record["interval_ok"] is True for record in parsed["hourly_records"])
    assert all(record["interval_reason"] is None for record in parsed["hourly_records"])

    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        float(len(parsed["hourly_records"])),
        datetime.now(UTC),
    )
    assert result.complete is True
    assert result.reason is None


def test_history_range_still_requests_the_daily_interval() -> None:
    """Manual backfill remains daily: hourly promotion only comes from the poll."""
    client = PsegClient(portal_cookies="MM_SID=x")
    day = date(2026, 10, 18)
    intervals: list[str] = []

    with requests_mock.Mocker(session=client.session) as mock:
        mock.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)

        def chart(request, context):
            intervals.append(urllib.parse.parse_qs(request.text)["UsageInterval"][0])
            return "ok"

        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=chart)
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=_daily_chart(day, 17.5))
        records = client.fetch_history_range("2026-10-18", "2026-10-18")

    assert intervals == ["6"]
    assert records == [{"date": "2026-10-18", "kwh": 17.5, "cost": 4.32}]


def test_mixed_granularity_when_one_closed_day_is_incomplete() -> None:
    """Granularity is explicit about partial hourly coverage, not just hourly>0."""
    client = PsegClient(portal_cookies="MM_SID=x", price_per_kwh=0.25)
    yesterday = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    day_before = yesterday - timedelta(days=1)
    daily = {
        "Data": {
            "series": [
                {
                    "name": "Meter #12345 (RS)",
                    "data": [
                        {
                            "x": int(ny_midnight_utc(day).timestamp() * 1000),
                            "y": kwh,
                            "hs": {
                                "start": day.strftime("%m/%d/%Y"),
                                "end": day.strftime("%m/%d/%Y"),
                            },
                        }
                        for day, kwh in ((day_before, 24.0), (yesterday, 2.0))
                    ],
                }
            ]
        }
    }
    hourly = _hourly_chart(day_before, 1.0)
    hourly["Data"]["series"][0]["data"] += _hourly_chart(yesterday, 1.0)["Data"]["series"][0][
        "data"
    ][:2]
    intervals: list[str] = []

    with requests_mock.Mocker(session=client.session) as mock:
        mock.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)

        def chart(request, context):
            intervals.append(urllib.parse.parse_qs(request.text)["UsageInterval"][0])
            return "ok"

        def chart_data(request, context):
            return hourly if intervals[-1] == "5" else daily

        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text=chart)
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", json=chart_data)
        parsed = client.fetch_energy_data(14)

    assert parsed["hourly_complete_days"] == 1
    assert parsed["hourly_incomplete_days"] == 1
    assert parsed["statistics_granularity"] == "mixed"
    assert parsed["history_14d"][0]["kwh"] == 24.0
    assert parsed["history_14d"][1]["kwh"] == 2.0


def test_hourly_http401_raises_mode_specific_auth_expiry() -> None:
    """A 401 on the optional hourly leg is auth loss, not a silent fallback."""
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    daily = _daily_chart(day, 24.0)
    for client, expected in (
        (
            PsegClient(portal_cookies="MM_SID=x"),
            AUTH_REASON_PORTAL_SESSION_EXPIRED,
        ),
        (PsegClient(okta_cookies="idx=x"), AUTH_REASON_OKTA_SESSION_EXPIRED),
    ):
        with (
            requests_mock.Mocker() as mock,
            patch.object(client, "_get_verification_token", return_value="token"),
        ):
            mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", status_code=200)
            mock.get(
                f"{PORTAL_BASE_URL}/Dashboard/ChartData",
                [
                    {"json": daily},
                    {"status_code": 401, "text": "Unauthorized"},
                ],
            )
            with pytest.raises(PsegOktaSessionExpired):
                client.fetch_energy_data(14)
        assert client.auth_reason == expected


def test_end_stamped_payload_is_not_promoted() -> None:
    """Exact coverage and a daily total do not prove x is the interval start."""
    day = date(2026, 10, 2)
    starts = expected_hour_starts(day)
    points = [
        {
            "x": int(
                datetime.combine(
                    start.astimezone(NY_TZ).date(),
                    start.astimezone(NY_TZ).time(),
                    tzinfo=UTC,
                ).timestamp()
                * 1000
            ),
            "y": 24 if index == 0 else index,
            "hs": {"start": "10/01/2026" if index == 0 else "10/02/2026"},
        }
        for index, start in enumerate(starts)
    ]
    parsed = PsegClient(price_per_kwh=0.25)._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is False for record in parsed["hourly_records"])

    check = validate_hourly_day(
        day,
        parsed["hourly_records"],
        300.0,
        datetime(2026, 10, 4, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
    )
    assert check.complete is False
    assert check.reason == "timestamp_semantics_unverified"


def test_aware_start_and_end_labels_are_positive_evidence() -> None:
    """Explicit aware [start, start+1h) labels are the only accepted proof."""
    day = date(2026, 10, 2)
    parsed = PsegClient()._parse_hourly_chart(_hourly_chart(day))
    assert all(record["interval_ok"] is True for record in parsed["hourly_records"])

    check = validate_hourly_day(
        day,
        parsed["hourly_records"],
        float(len(parsed["hourly_records"])),
        datetime(2026, 10, 4, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
    )
    assert check.complete is True


def test_bare_clock_labels_are_not_positive_evidence() -> None:
    """A naked wall-clock label matching x could still be an end timestamp."""
    day = date(2026, 10, 2)
    points = []
    for start in expected_hour_starts(day):
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        label = local.strftime("%m/%d/%Y %I:%M %p")
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {"start": label, "end": label},
            }
        )
    parsed = PsegClient()._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is False for record in parsed["hourly_records"])

    check = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24.0,
        datetime(2026, 10, 4, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
    )
    assert check.complete is False
    assert check.reason == "timestamp_semantics_unverified"


def test_unparseable_or_missing_labels_remain_unverified() -> None:
    """Labels that are absent or unparseable retain timestamp_semantics_unverified."""
    day = date(2026, 10, 2)
    points = []
    for start in expected_hour_starts(day):
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {"start": "unparseable_garbage"},
            }
        )
    parsed = PsegClient()._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is False for record in parsed["hourly_records"])
    assert all(
        record["interval_reason"] == "timestamp_semantics_unverified"
        for record in parsed["hourly_records"]
    )

    check = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24.0,
        datetime(2026, 10, 4, tzinfo=UTC),
        granularity=parsed["hourly_granularity"],
    )
    assert check.complete is False
    assert check.reason == "timestamp_semantics_unverified"


@pytest.mark.parametrize("mode", ["portal", "okta"])
@pytest.mark.parametrize("leg", ["setup", "data"])
def test_hourly_login_redirect_is_typed_auth_loss(mode, leg) -> None:
    """A 302 to the anonymous portal home must not become a daily fallback."""
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    daily = _daily_chart(day, 24.0)
    client = PsegClient(
        portal_cookies="MM_SID=x" if mode == "portal" else "",
        okta_cookies="idx=x" if mode == "okta" else "",
    )
    login = f"{PORTAL_BASE_URL}/"
    posts = (
        [{"text": "ok"}, {"status_code": 302, "headers": {"Location": login}}]
        if leg == "setup"
        else [{"text": "ok"}, {"text": "ok"}]
    )
    gets = (
        [{"json": daily}]
        if leg == "setup"
        else [{"json": daily}, {"status_code": 302, "headers": {"Location": login}}]
    )
    with (
        requests_mock.Mocker(session=client.session) as mock,
        patch.object(client, "_get_verification_token", return_value="token"),
    ):
        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", posts)
        mock.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", gets)
        mock.get(login, text="<html>anonymous portal page</html>")
        with pytest.raises(PsegOktaSessionExpired):
            client.fetch_energy_data(14)

    expected = (
        AUTH_REASON_OKTA_SESSION_EXPIRED if mode == "okta" else AUTH_REASON_PORTAL_SESSION_EXPIRED
    )
    assert client.auth_reason == expected


def test_hourly_contract_sample_projection_allowed_fields() -> None:
    """The sample keeps only the allowed fields and strips extra metadata."""
    client = PsegClient()
    payload = {
        "cookies": "secret_cookie",
        "token": "secret_token",
        "extra_root_field": "secret_root",
        "AjaxResults": [
            {"Action": "Redirect", "Extra": "secret_action"},
            {"NonAction": "ignore"},
        ],
        "Data": {
            "unit": "kWh",
            "extra_data_key": "secret_data",
            "series": [
                {
                    "name": "Meter #99999",
                    "unit": "kWh",
                    "extra_series_key": "secret_series",
                    "data": [
                        {
                            "x": 1788259200000,
                            "y": 1.25,
                            "extra_point_key": "secret_point",
                            "hs": {
                                "start": "2026-09-01T00:00:00Z",
                                "end": "2026-09-01T01:00:00Z",
                                "extra_hs_key": "secret_hs",
                            },
                        }
                    ],
                }
            ],
        },
    }
    client._capture_hourly_contract_sample(payload, "2026-09-01", "2026-09-02")
    sample = client.hourly_contract_sample
    assert sample is not None

    allowed_top_keys = {
        "sample_version",
        "captured_at",
        "request",
        "payload_keys",
        "data_keys",
        "chart",
        "non_meter_series_count",
        "point_extra_keys",
        "hs_extra_keys",
        "truncated_points",
    }
    assert set(sample.keys()) == allowed_top_keys
    assert sample["sample_version"] == 1
    assert set(sample["request"].keys()) == {"start", "end", "usage_interval"}
    assert sample["request"]["start"] == "2026-09-01"
    assert sample["request"]["end"] == "2026-09-02"

    assert set(sample["chart"].keys()) == {"AjaxResults", "Data"}
    assert sample["chart"]["AjaxResults"] == [{"Action": "Redirect"}]
    assert set(sample["chart"]["Data"].keys()) == {"unit", "series"}
    assert sample["chart"]["Data"]["unit"] == "kWh"

    series_list = sample["chart"]["Data"]["series"]
    assert len(series_list) == 1
    series = series_list[0]
    assert set(series.keys()) == {"name", "data"}
    assert series["name"] == "Meter #1"

    points = series["data"]
    assert len(points) == 1
    point = points[0]
    assert set(point.keys()) == {"x", "y", "hs"}
    assert point["x"] == 1788259200000
    assert point["y"] == 1.25
    assert set(point["hs"].keys()) == {"start", "end"}
    assert point["hs"]["start"] == "2026-09-01T00:00:00Z"
    assert point["hs"]["end"] == "2026-09-01T01:00:00Z"

    dumped = json.dumps(sample)
    for forbidden in (
        "secret_cookie",
        "secret_token",
        "secret_root",
        "secret_action",
        "secret_data",
        "secret_series",
        "secret_point",
        "secret_hs",
        "99999",
    ):
        assert forbidden not in dumped


def test_hourly_contract_sample_meter_ids_replaced_and_duplicates() -> None:
    """Meter ids are replaced with sequential placeholders; duplicates share placeholder."""
    client = PsegClient()
    payload = {
        "Data": {
            "unit": "kWh",
            "series": [
                {
                    "name": "Meter #88888",
                    "data": [{"x": 1000, "y": 0.5}],
                },
                {
                    "name": "Meter #77777",
                    "data": [{"x": 1000, "y": 0.6}],
                },
                {
                    "name": "Meter #88888",
                    "data": [{"x": 2000, "y": 0.7}],
                },
                {
                    "name": "Temperature (F)",
                    "data": [{"x": 1000, "y": 72.0}],
                },
            ],
        }
    }
    client._capture_hourly_contract_sample(payload, "2026-09-01", "2026-09-02")
    sample = client.hourly_contract_sample
    assert sample is not None

    series = sample["chart"]["Data"]["series"]
    assert len(series) == 3
    assert series[0]["name"] == "Meter #1"
    assert series[1]["name"] == "Meter #2"
    assert series[2]["name"] == "Meter #1"
    assert sample["non_meter_series_count"] == 1

    dumped = json.dumps(sample)
    assert "88888" not in dumped
    assert "77777" not in dumped


def test_hourly_contract_sample_extra_keys_listed_without_values() -> None:
    """Extra point and hs keys are collected by name only into sorted lists."""
    client = PsegClient()
    payload = {
        "Data": {
            "series": [
                {
                    "name": "Meter #12345",
                    "data": [
                        {
                            "x": 1000,
                            "y": 1.0,
                            "custom_field": "secret_custom",
                            "alpha_field": "secret_alpha",
                            "hs": {
                                "start": "2026-09-01T00:00:00Z",
                                "end": "2026-09-01T01:00:00Z",
                                "custom_hs": "secret_hs_val",
                            },
                        }
                    ],
                }
            ]
        }
    }
    client._capture_hourly_contract_sample(payload, "2026-09-01", "2026-09-02")
    sample = client.hourly_contract_sample
    assert sample is not None
    assert sample["point_extra_keys"] == ["alpha_field", "custom_field"]
    assert sample["hs_extra_keys"] == ["custom_hs"]

    dumped = json.dumps(sample)
    assert "secret_custom" not in dumped
    assert "secret_alpha" not in dumped
    assert "secret_hs_val" not in dumped


def test_hourly_contract_sample_caps_and_sanitization() -> None:
    """String lengths, list lengths, point caps and invalid points are strictly capped."""
    client = PsegClient()
    long_key = "a" * 100
    long_action = "a" * 100
    long_unit = "u" * 100
    long_hs_start = "s" * 100
    long_hs_end = "e" * 100

    payload = {
        long_key: "val",
        **{f"extra_{i:02d}": "val" for i in range(60)},
        "AjaxResults": [{"Action": long_action}] * 15,
        "Data": {
            "unit": long_unit,
            long_key: "data_val",
            "series": [
                {
                    "name": "Meter #11111",
                    "data": [
                        "invalid_string_point",
                        {
                            "x": True,
                            "y": "not_a_number",
                            "hs": {"start": long_hs_start, "end": long_hs_end},
                        },
                    ]
                    + [{"x": 1000 + i, "y": 1.0, "hs": None} for i in range(1600)],
                }
            ],
        },
    }
    client._capture_hourly_contract_sample(payload, "2026-09-01", "2026-09-02")
    sample = client.hourly_contract_sample
    assert sample is not None

    assert len(sample["payload_keys"]) == 50
    assert any(len(k) == 64 for k in sample["payload_keys"])
    assert long_key[:64] in sample["data_keys"]

    ajax = sample["chart"]["AjaxResults"]
    assert len(ajax) == 10
    assert ajax[0]["Action"] == long_action[:32]

    assert sample["chart"]["Data"]["unit"] == long_unit[:16]

    series = sample["chart"]["Data"]["series"][0]
    assert series["invalid_points"] == 1

    assert len(series["data"]) == 1500
    assert sample["truncated_points"] == 101

    first_pt = series["data"][0]
    assert first_pt["x"] == "<bool>"
    assert first_pt["y"] == "<str>"
    assert first_pt["hs"]["start"] == long_hs_start[:64]
    assert first_pt["hs"]["end"] == long_hs_end[:64]

    second_pt = series["data"][1]
    assert "hs" not in second_pt


def test_hourly_contract_sample_shape_notes_and_types() -> None:
    """Non-dict payload or Data records shape_note; non-list AjaxResults records type."""
    client = PsegClient()

    client._capture_hourly_contract_sample("string_payload", "2026-09-01", "2026-09-02")
    s1 = client.hourly_contract_sample
    assert s1 is not None
    assert s1["shape_note"] == "payload_not_object"
    assert s1["chart"]["Data"]["series"] == []

    client._capture_hourly_contract_sample({"Data": 12345}, "2026-09-01", "2026-09-02")
    s2 = client.hourly_contract_sample
    assert s2 is not None
    assert s2["shape_note"] == "data_not_object"
    assert s2["chart"]["Data"]["series"] == []

    client._capture_hourly_contract_sample(
        {"AjaxResults": "not_a_list", "Data": {}}, "2026-09-01", "2026-09-02"
    )
    s3 = client.hourly_contract_sample
    assert s3 is not None
    assert s3["ajax_results_type"] == "str"
    assert "AjaxResults" not in s3["chart"]


def test_hourly_contract_sample_capture_raising_does_not_fail_poll(caplog) -> None:
    """If capture raises, the error is swallowed and logged at DEBUG with class name only."""
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    daily = _daily_chart(day, 24.0)
    hourly = _hourly_chart(day, 1.0)
    client = PsegClient(portal_cookies="MM_SID=valid_sid")

    with (
        requests_mock.Mocker(session=client.session) as mock,
        patch.object(client, "_get_verification_token", return_value="token"),
        patch.object(
            client,
            "_capture_hourly_contract_sample",
            side_effect=RuntimeError("capture_test_failure"),
        ),
        caplog.at_level(logging.DEBUG),
    ):
        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        mock.get(
            f"{PORTAL_BASE_URL}/Dashboard/ChartData",
            [{"json": daily}, {"json": hourly}],
        )
        data = client.fetch_energy_data(14)

    assert data["latest_kwh"] == 24.0
    assert "Failed to capture hourly contract sample: RuntimeError" in caplog.text
    assert "capture_test_failure" not in caplog.text


def test_hourly_contract_sample_hourly_leg_calls_parser_with_identical_object() -> None:
    """The hourly leg passes the exact, unmodified payload object to _parse_hourly_chart."""
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    daily = _daily_chart(day, 24.0)
    hourly = _hourly_chart(day, 1.0)
    client = PsegClient(portal_cookies="MM_SID=valid_sid")

    fetched_payload: dict | None = None
    parsed_arg: dict | None = None
    real_fetch = client._fetch_chart_json
    real_parse = client._parse_hourly_chart

    def spy_fetch(*args, **kwargs):
        nonlocal fetched_payload
        fetched_payload = real_fetch(*args, **kwargs)
        return fetched_payload

    def spy_parse(payload):
        nonlocal parsed_arg
        parsed_arg = payload
        return real_parse(payload)

    with (
        requests_mock.Mocker(session=client.session) as mock,
        patch.object(client, "_get_verification_token", return_value="token"),
        patch.object(client, "_fetch_chart_json", side_effect=spy_fetch),
        patch.object(client, "_parse_hourly_chart", side_effect=spy_parse),
    ):
        mock.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text="ok")
        mock.get(
            f"{PORTAL_BASE_URL}/Dashboard/ChartData",
            [{"json": daily}, {"json": hourly}],
        )
        client.fetch_energy_data(14)

    assert fetched_payload is not None
    assert parsed_arg is not None
    # Identity check: exact same object instance passed from fetch to parse
    assert parsed_arg is fetched_payload
    assert parsed_arg == hourly


def test_hourly_contract_sample_comparator_consumable_shape() -> None:
    """The captured sample chart field matches the comparator's expected document format."""
    client = PsegClient()
    payload = {
        "AjaxResults": [],
        "Data": {
            "unit": "kWh",
            "series": [
                {
                    "name": "Meter #99999 (RS)",
                    "data": [
                        {
                            "x": 1788259200000,
                            "y": 1.23,
                            "hs": {
                                "start": "2026-09-01T00:00:00Z",
                                "end": "2026-09-01T01:00:00Z",
                            },
                        }
                    ],
                }
            ],
        },
    }
    client._capture_hourly_contract_sample(payload, "2026-08-30", "2026-09-06")
    sample = client.hourly_contract_sample
    assert sample is not None

    document = {
        "document_version": 1,
        "chart_schema_version": 1,
        "chart": sample["chart"],
        "context": {
            "context_version": 2,
            "expected_meter_ids": ["1"],
            "unit": "kWh",
            "chart_display": {
                "resolution_kwh": "0.01",
                "rounding": "half_up",
                "contributors": 1,
            },
            "request": {"start": "2026-08-30", "end": "2026-09-06"},
        },
    }

    assert document["document_version"] == 1
    assert document["chart_schema_version"] == 1
    assert "chart" in document
    assert "Data" in document["chart"]
    assert document["chart"]["Data"]["unit"] == "kWh"
    series = document["chart"]["Data"]["series"]
    assert isinstance(series, list)
    assert len(series) == 1
    assert series[0]["name"] == "Meter #1"
    pt = series[0]["data"][0]
    assert pt["x"] == 1788259200000
    assert pt["y"] == 1.23
    assert pt["hs"]["start"] == "2026-09-01T00:00:00Z"
    assert pt["hs"]["end"] == "2026-09-01T01:00:00Z"
    assert document["context"]["expected_meter_ids"] == ["1"]


def test_hourly_contract_realistic_edt_day_promoted() -> None:
    """A realistic closed EDT day with wall-clock ms and date-only labels promotes with 04:00Z starts."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    points = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.25,
                "hs": {"start": "10/15/2026", "end": "10/15/2026"},
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is True for record in parsed["hourly_records"])
    assert all(record["interval_reason"] is None for record in parsed["hourly_records"])

    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24 * 1.25,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is True
    assert result.reason is None
    assert result.records[0]["start"] == datetime(2026, 10, 15, 4, 0, tzinfo=UTC)
    assert result.records[-1]["start"] == datetime(2026, 10, 16, 3, 0, tzinfo=UTC)


def test_hourly_contract_true_utc_reading_rejected() -> None:
    """True-UTC reading shifts EDT starts by 4h and is rejected (regression proof)."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    points = [
        {
            "x": int(start.timestamp() * 1000),
            "y": 1.25,
            "hs": {"start": "10/15/2026", "end": "10/15/2026"},
        }
        for start in starts
    ]
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24 * 1.25,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason in ("unexpected_start", "label_mismatch")


def test_hourly_contract_est_day_promoted() -> None:
    """An EST day in December promotes with starts at 05:00Z."""
    day = date(2026, 12, 1)
    starts = expected_hour_starts(day)
    points = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.5,
                "hs": {"start": "12/01/2026", "end": "12/01/2026"},
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is True for record in parsed["hourly_records"])

    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24 * 1.5,
        datetime(2026, 12, 3, tzinfo=UTC),
    )
    assert result.complete is True
    assert result.reason is None
    assert result.records[0]["start"] == datetime(2026, 12, 1, 5, 0, tzinfo=UTC)
    assert result.records[-1]["start"] == datetime(2026, 12, 2, 4, 0, tzinfo=UTC)


def test_hourly_contract_fall_back_day_dst_ambiguous() -> None:
    """Fall-back day 2026-11-01 yields reason dst_ambiguous, not promoted, no exception."""
    day = date(2026, 11, 1)
    starts = expected_hour_starts(day)
    points_25 = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points_25.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {"start": "11/01/2026", "end": "11/01/2026"},
            }
        )
    client = PsegClient()
    parsed_25 = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points_25}]}}
    )
    result_25 = validate_hourly_day(
        day,
        parsed_25["hourly_records"],
        25.0,
        datetime(2026, 11, 3, tzinfo=UTC),
    )
    assert result_25.complete is False
    assert result_25.reason == "dst_ambiguous"

    points_24 = [p for i, p in enumerate(points_25) if i != 1]
    parsed_24 = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points_24}]}}
    )
    result_24 = validate_hourly_day(
        day,
        parsed_24["hourly_records"],
        24.0,
        datetime(2026, 11, 3, tzinfo=UTC),
    )
    assert result_24.complete is False
    assert result_24.reason == "dst_ambiguous"


def test_hourly_contract_spring_forward_invalid_point_not_promoted() -> None:
    """Spring-forward 2027-03-14 with a 02:00 point is counted invalid and not promoted."""
    day = date(2027, 3, 14)
    points = [
        {
            "x": int(datetime(2027, 3, 14, h, 0, tzinfo=UTC).timestamp() * 1000),
            "y": 1.0,
            "hs": {"start": "03/14/2027", "end": "03/14/2027"},
        }
        for h in range(24)
    ]
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert parsed["hourly_invalid_points"] == 1
    assert len(parsed["hourly_records"]) == 23

    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24.0,
        datetime(2027, 3, 16, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "sum_mismatch"


def test_hourly_contract_date_label_different_day_is_label_mismatch() -> None:
    """A date label for a different day triggers label_mismatch."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    local = starts[0].astimezone(NY_TZ)
    wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
    points = [
        {
            "x": int(wall_utc.timestamp() * 1000),
            "y": 1.0,
            "hs": {"start": "10/16/2026", "end": "10/16/2026"},
        }
    ]
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert parsed["hourly_records"][0]["interval_ok"] is False
    assert parsed["hourly_records"][0]["interval_reason"] == "label_mismatch"

    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        1.0,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "label_mismatch"


def test_hourly_contract_end_label_two_days_off_is_interval_end_mismatch() -> None:
    """An end label two days off triggers interval_end_mismatch."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    local = starts[0].astimezone(NY_TZ)
    wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
    points = [
        {
            "x": int(wall_utc.timestamp() * 1000),
            "y": 1.0,
            "hs": {"start": "10/15/2026", "end": "10/17/2026"},
        }
    ]
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert parsed["hourly_records"][0]["interval_ok"] is False
    assert parsed["hourly_records"][0]["interval_reason"] == "interval_end_mismatch"

    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        1.0,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "interval_end_mismatch"


def test_hourly_contract_sum_mismatch_still_rejects() -> None:
    """Sum mismatch between hourly points and daily total rejects promotion."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    points = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {"start": "10/15/2026", "end": "10/15/2026"},
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is True for record in parsed["hourly_records"])

    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        30.0,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "sum_mismatch"


def test_hourly_contract_aware_start_missing_end_rejected() -> None:
    """Matching aware start label with missing end label is not promoted."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    points = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {"start": start.isoformat()},
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is False for record in parsed["hourly_records"])
    assert all(
        record["interval_reason"] == "timestamp_semantics_unverified"
        for record in parsed["hourly_records"]
    )
    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24.0,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "timestamp_semantics_unverified"


def test_hourly_contract_bare_clock_start_equals_end_rejected() -> None:
    """Bare clock labels with start == end are zero-length intervals and not promoted."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    points = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        clock = local.strftime("%m/%d/%Y %H:%M")
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {"start": clock, "end": clock},
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is False for record in parsed["hourly_records"])
    assert all(
        record["interval_reason"] == "timestamp_semantics_unverified"
        for record in parsed["hourly_records"]
    )
    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24.0,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "timestamp_semantics_unverified"


def test_hourly_contract_date_start_aware_noon_end_rejected() -> None:
    """Date-only start with aware noon end does not prove 1h interval and is rejected."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    points = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {
                    "start": "10/15/2026",
                    "end": "2026-10-15T12:00:00-04:00",
                },
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert all(record["interval_ok"] is False for record in parsed["hourly_records"])
    assert all(
        record["interval_reason"] == "timestamp_semantics_unverified"
        for record in parsed["hourly_records"]
    )
    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24.0,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "timestamp_semantics_unverified"


def test_hourly_contract_mixed_series_date_start_aware_noon_end_rejected() -> None:
    """Mixed series with alternating aware and date-start/aware-noon-end points is rejected."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    points = []
    for i, start in enumerate(starts):
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        if i % 2 == 0:
            hs = {
                "start": start.isoformat(),
                "end": (start + timedelta(hours=1)).isoformat(),
            }
        else:
            hs = {
                "start": "10/15/2026",
                "end": "2026-10-15T12:00:00-04:00",
            }
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": hs,
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    assert sum(r["interval_ok"] for r in parsed["hourly_records"]) == 12
    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24.0,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "timestamp_semantics_unverified"


def test_hourly_contract_iso_basic_aware_start_date_end_rejected() -> None:
    """ISO basic aware start with date-only end fails label_mismatch."""
    day = date(2026, 10, 15)
    starts = expected_hour_starts(day)
    points = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {
                    "start": "20261015T230000-0400",
                    "end": "10/15/2026",
                },
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        24.0,
        datetime(2026, 10, 17, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "label_mismatch"


def test_hourly_contract_fall_back_aware_25_points_dst_ambiguous() -> None:
    """Fully-aware 25-point fall-back day yields reason dst_ambiguous, not label_mismatch."""
    day = date(2026, 11, 1)
    starts = expected_hour_starts(day)
    points = []
    for start in starts:
        local = start.astimezone(NY_TZ)
        wall_utc = datetime.combine(local.date(), local.time(), tzinfo=UTC)
        points.append(
            {
                "x": int(wall_utc.timestamp() * 1000),
                "y": 1.0,
                "hs": {
                    "start": start.isoformat(),
                    "end": (start + timedelta(hours=1)).isoformat(),
                },
            }
        )
    client = PsegClient()
    parsed = client._parse_hourly_chart(
        {"Data": {"series": [{"name": "Meter #1", "data": points}]}}
    )
    ambiguous_records = [
        r for r in parsed["hourly_records"] if r["interval_reason"] == "dst_ambiguous"
    ]
    assert len(ambiguous_records) >= 1
    result = validate_hourly_day(
        day,
        parsed["hourly_records"],
        25.0,
        datetime(2026, 11, 3, tzinfo=UTC),
    )
    assert result.complete is False
    assert result.reason == "dst_ambiguous"


def test_cost_contract_sample_property_and_slots() -> None:
    """The client stores up to two bounded cost sample slots."""
    client = PsegClient()
    assert client.cost_contract_sample is None

    client._cost_contract_samples["daily"] = {"sample_version": 1, "status": "ok"}
    assert client.cost_contract_sample == {"daily": {"sample_version": 1, "status": "ok"}}

    client._cost_contract_samples["hourly"] = {"sample_version": 1, "status": "ok"}
    assert len(client.cost_contract_sample) == 2


def test_cost_auth_rejected_never_marks_auth_failure() -> None:
    """Contract: HTTP 401 or auth_rejected in cost sampler never calls _mark_auth_failure."""
    client = PsegClient(portal_cookies="MM_SID=synthetic")
    client.set_expected_meter_ids(["12345678"])
    from custom_components.pseg.cost_evidence import NY_TZ, CostEvidenceStatus, CostPermit
    from custom_components.pseg.renewal_admission import RenewalEntryRuntime

    runtime = RenewalEntryRuntime("test-entry")
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
    hourly = {"Data": {"series": []}}
    ny_today = datetime.now(NY_TZ).date().isoformat()
    permit = CostPermit("p1", "test-entry", ny_today, "6", "2026-10-11", "2026-10-25", "ts")

    with (
        patch.object(client, "_get_verification_token", return_value="tok"),
        patch.object(client, "_fetch_chart_json", side_effect=[daily, hourly]),
        patch(
            "custom_components.pseg.cost_evidence.execute_cost_sampler",
            return_value=(CostEvidenceStatus.AUTH_REJECTED, {"status": "auth_rejected"}, False),
        ),
        patch.object(client, "_mark_auth_failure") as mock_mark_auth,
    ):
        res = client.fetch_energy_data(cost_permit=permit)
        assert res["identity_confirmed"] is True
        assert res["cost_evidence"]["status"] == "auth_rejected"
        mock_mark_auth.assert_not_called()

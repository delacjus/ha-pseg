"""Unit tests for PSE&G API client."""

from datetime import UTC, datetime
import json
import logging

import pytest
import requests
import requests_mock

from custom_components.pseg.const import OKTA_HOST, PORTAL_BASE_URL, PORTAL_HOST
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegLoginRedirected,
    PsegLoginRejected,
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
        m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", exc=requests.exceptions.ConnectionError("offline"))
        assert client.keepalive() is False


def test_custom_price_per_kwh() -> None:
    """Test that custom price_per_kwh is used for cost estimation."""
    client = PsegClient(price_per_kwh=0.30)
    data = {
        "Data": {
            "series": [
                {"name": "Meter #1", "data": [{"y": 10.0, "hs": {"start": "10/15/2026"}}]}
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
CHART_JSON = {"Data": {"series": [{"name": "Meter #1", "data": [{"y": 1.0, "hs": {"start": "10/20/2026"}}]}]}}


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
            _meter("Meter #000303817579 (Residential Service (RS))", [("10/18/2026", 17.586), ("10/19/2026", 14.5368)]),
            _meter("Meter #000126274191 (Residential Service (RS))", []),
            {"name": "Temperature", "type": "spline", "data": [{"x": 1792368000000, "y": 46.66, "tr": "31° | 47° | 69°F"}]},
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
    assert records == [{"date": "2026-10-18", "kwh": 17.59, "cost": round(17.59 * client.price_per_kwh, 2)}]


def test_merge_deduplicates_meter_and_ignores_non_meter_series(caplog: pytest.LogCaptureFixture) -> None:
    """Only the first anchored series for each meter contributes usage."""
    chart = {"Data": {"series": [
        _meter("Meter #111 (RS)", [("10/18/2026", 10.0)]),
        _meter("Meter #111 (RS) - Previous Year", [("10/18/2026", 99.0)]),
        _meter("Previous Year Meter #222", [("10/18/2026", 50.0)]),
        _meter("  Meter #222 (RS)", [("10/18/2026", 3.0)]),
    ]}}
    with caplog.at_level("DEBUG"):
        parsed = PsegClient()._parse_chart_data(chart)
    assert parsed["history_14d"][0]["kwh"] == 13.0
    assert parsed["meter_ids"] == ["111", "222"]
    assert "duplicate" in caplog.text.lower()


def test_merge_skips_missing_usage_and_bad_date(caplog: pytest.LogCaptureFixture) -> None:
    """Invalid points must not create zero-kWh or empty-date statistics rows."""
    chart = {"Data": {"series": [{"name": "Meter #111 (RS)", "data": [
        {"y": None, "hs": {"start": "10/18/2026"}},
        {"y": "bad", "hs": {"start": "10/19/2026"}},
        {"y": 2.0, "hs": {"start": "bad date"}},
        {"y": 1.0, "hs": "bad"},
        {"y": 3.0, "hs": {"start": "10/20/2026"}},
    ]}]}}
    with caplog.at_level("DEBUG"):
        parsed = PsegClient()._parse_chart_data(chart)
    assert [(r["date"], r["kwh"]) for r in parsed["history_14d"]] == [
        ("2026-10-20", 3.0)
    ]
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


def test_remember_me_renews_without_okta() -> None:
    """A lapsed MM_SID is re-issued from MM_RememberMe; Okta is never contacted."""
    client = PsegClient(portal_cookies=REMEMBER_PORTAL)
    assert client.has_remember_me and not client.has_okta_session
    with requests_mock.Mocker(session=client.session) as m:
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


def test_remember_me_rejected_falls_back_to_okta_sso() -> None:
    client = PsegClient(okta_cookies="idx=abc", portal_cookies=REMEMBER_PORTAL)
    with requests_mock.Mocker(session=client.session) as m:
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}],
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
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}, {"text": DASHBOARD_WITH_TOKEN}],
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
        m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [{"status_code": 302, "headers": {"Location": "/Home/Index"}}, {"text": DASHBOARD_WITH_TOKEN}],
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
    client = PsegClient(cookie_list=[
        {"name": "idx", "value": "old", "domain": f".{OKTA_HOST}", "path": "/"},
        {"name": "idx", "value": "seed", "domain": OKTA_HOST, "path": "/"},
    ])
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
    assert sorted(c["value"] for c in untouched.export_cookies() if c["name"] == "MM_RememberMe") == ["a", "b"]
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
        m.get(f"{PORTAL_BASE_URL}/", text=ANON_HOME.replace("</form>", '<input name="__RequestVerificationToken" value="af"/></form>'))
        login = m.post(f"{PORTAL_BASE_URL}/Home/Login", json=LOGIN_OK)
        m.get(f"{PORTAL_BASE_URL}/Dashboard", [LOGGED_OUT_REDIRECT, {"text": DASHBOARD_WITH_TOKEN}])
        assert client.ensure_session() is True
    body = login.last_request.text
    assert "LoginEmail=me%40example.com" in body and "RememberMe=true" in body
    assert login.last_request.headers["RequestVerificationToken"] == "af"
    assert client.sso_renewals == 1
    assert "s3cret-pass-998" not in caplog.text and "s3cret-pass-998" not in client.auth_diagnostics()


@pytest.mark.parametrize(
    "data", [{"LoginErrorMessage": "Invalid email address or password"}, {"RecaptchaOnLogin": True}, {"SecretQuestionError": "x"}]
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
    client = PsegClient(
        portal_cookies=REMEMBER_PORTAL, email="me@example.com", password="pw"
    )
    with requests_mock.Mocker(session=client.session) as m:
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
    client = PsegClient(
        portal_cookies=REMEMBER_PORTAL, email="me@example.com", password="pw"
    )
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
    # The dead cookie is not left in the jar that Home Assistant may persist.
    assert client.has_remember_me is False


def test_expired_remember_me_and_rejected_login_does_not_loop() -> None:
    """RememberMe expires once, the password is rejected once, and it stops."""
    client = PsegClient(
        portal_cookies=REMEMBER_PORTAL, email="me@example.com", password="pw"
    )
    with requests_mock.Mocker(session=client.session) as m:
        dash = m.get(
            f"{PORTAL_BASE_URL}/Dashboard",
            [LOGGED_OUT_REDIRECT, LOGGED_OUT_REDIRECT],
        )
        m.get(f"{PORTAL_BASE_URL}/", text=LOGIN_PAGE_WITH_TOKEN)
        login = m.post(
            f"{PORTAL_BASE_URL}/Home/Login",
            json={"AjaxResults": [], "Data": {"LoginErrorMessage": "Invalid email address or password"}},
        )

        with pytest.raises(PsegLoginRejected):
            client._renew()

    assert dash.call_count == 2  # one Remember Me attempt, never repeated
    assert login.call_count == 1


def test_remember_me_transient_never_falls_back_to_the_password() -> None:
    """A portal outage is transient: no password attempt and the cookie is kept."""
    client = PsegClient(
        portal_cookies=REMEMBER_PORTAL, email="me@example.com", password="pw"
    )
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

"""Security guard tests for credentials, allowlists, and entity architecture."""

import logging
from pathlib import Path
import re

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
import requests_mock

from custom_components.pseg.button import PsegRefreshButton
from custom_components.pseg.const import (
    ATTR_LAST_KEEPALIVE,
    ATTR_LAST_SSO_RENEWAL,
    ATTR_OKTA_SESSION_EXPIRED_AT,
    ATTR_SESSION_ESTABLISHED_AT,
    ATTR_SSO_RENEWALS,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    DOMAIN,
    PORTAL_BASE_URL,
)
from custom_components.pseg.coordinator import PsegDataUpdateCoordinator
from custom_components.pseg.pseg_client import PsegClient
from custom_components.pseg.sensor import (
    PsegConnectionStatusSensor,
    PsegElectricityConsumptionSensor,
    PsegElectricityCostSensor,
)


def test_guard_no_rfc1918_or_localhost_in_package() -> None:
    """Guard test: ensure no RFC1918 private IPs, 127.0.0.1, or localhost are hard-coded in custom_components/pseg."""
    pkg_dir = Path(__file__).parent.parent / "custom_components" / "pseg"
    ip_pattern = re.compile(
        r"(?:https?://)?(?:127\.0\.0\.1|localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?",
        re.IGNORECASE,
    )

    violations = []
    for file_path in pkg_dir.rglob("*"):
        if file_path.suffix not in (".py", ".json", ".js"):
            continue
        with open(file_path, encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                # Allow User-Agent "Windows NT 10.0" and SVG viewBox
                if "Windows NT 10.0" in line:
                    continue
                match = ip_pattern.search(line)
                if match:
                    violations.append(f"{file_path.name}:{line_no}: {line.strip()}")

    assert not violations, f"RFC1918 / localhost guard violations detected: {violations}"


def test_guard_no_cookie_values_in_caplog(caplog) -> None:
    """Guard test: assert no cookie secret strings appear in logs during client session handling."""
    caplog.set_level(logging.DEBUG)

    secret_okta = "idx=secret_okta_token_998877; sid=sid_secret_665544"
    secret_portal = "MM_SID=secret_portal_session_112233; Saml2.auth=secret_saml_xyz"

    client = PsegClient(okta_cookies=secret_okta, portal_cookies=secret_portal)
    exported = client.export_cookies()
    assert len(exported) == 4

    new_client = PsegClient(cookie_list=exported)
    assert len(new_client.session.cookies) == 4

    with requests_mock.Mocker(session=client.session) as m:
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text="<html>Dashboard OK</html>", status_code=200)
        _mock_sso_ok(m)
        client.ensure_session()
        client.keepalive()

    log_text = caplog.text
    assert "secret_okta_token_998877" not in log_text
    assert "sid_secret_665544" not in log_text
    assert "secret_portal_session_112233" not in log_text
    assert "secret_saml_xyz" not in log_text


def test_sensor_architecture_and_attributes(hass: HomeAssistant) -> None:
    """Test sensors and button adhere to entity name architecture without hardcoded entity_ids."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        title="PSE&G (12345)",
    )
    entry.add_to_hass(hass)

    client = PsegClient()
    client.session_established_at = "2026-10-20T10:00:00Z"
    client.last_sso_renewal = "2026-10-20T10:30:00Z"
    client.sso_renewals = 1
    client.last_keepalive = "2026-10-20T11:00:00Z"
    client.okta_session_expired_at = None

    coord = PsegDataUpdateCoordinator(hass, client, {}, config_entry=entry)

    consumption_sensor = PsegElectricityConsumptionSensor(coord, entry)
    cost_sensor = PsegElectricityCostSensor(coord, entry)
    status_sensor = PsegConnectionStatusSensor(coord, entry)
    button = PsegRefreshButton(coord, entry)

    # 1. Audit Fix A: Do NOT add state_class to consumption sensor
    assert not hasattr(consumption_sensor, "state_class") or consumption_sensor.state_class is None

    # 2. Audit Fix D: has_entity_name + translation_key, NO hardcoded entity_id
    assert consumption_sensor.has_entity_name is True
    assert consumption_sensor.translation_key == "electricity_consumption"
    assert not hasattr(consumption_sensor, "entity_id") or consumption_sensor.entity_id is None

    assert cost_sensor.has_entity_name is True
    assert cost_sensor.translation_key == "electricity_cost"
    assert not hasattr(cost_sensor, "entity_id") or cost_sensor.entity_id is None

    assert button.has_entity_name is True
    assert button.translation_key == "refresh_data"
    assert not hasattr(button, "entity_id") or button.entity_id is None

    # 3. Connection status sensor has session telemetry attributes
    attrs = status_sensor.extra_state_attributes
    assert attrs[ATTR_SESSION_ESTABLISHED_AT] == "2026-10-20T10:00:00Z"
    assert attrs[ATTR_LAST_SSO_RENEWAL] == "2026-10-20T10:30:00Z"
    assert attrs[ATTR_SSO_RENEWALS] == 1
    assert attrs[ATTR_LAST_KEEPALIVE] == "2026-10-20T11:00:00Z"
    assert attrs[ATTR_OKTA_SESSION_EXPIRED_AT] is None


SECRET_VALUES = (
    "secret_okta_token_998877",
    "sid_secret_665544",
    "secret_portal_session_112233",
    "secret_saml_assertion_445566",
)
SECRET_OKTA = f"idx={SECRET_VALUES[0]}; sid={SECRET_VALUES[1]}"
SECRET_PORTAL = f"MM_SID={SECRET_VALUES[2]}"
OKTA_WIDGET = '<html><script>new OktaSignIn({stateToken: "x"})</script></html>'
LOGGED_OUT = {"status_code": 302, "headers": {"Location": "/"}}


def _assert_no_secrets(text: str) -> None:
    for value in SECRET_VALUES:
        assert value not in text, f"secret {value[:12]}... leaked"


async def test_guard_no_cookie_values_in_caplog_on_error_paths(hass: HomeAssistant, caplog) -> None:
    """Expired, transient and SSO-failure paths must not log or raise cookie/assertion values."""
    caplog.set_level(logging.DEBUG)
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="12345",
        data={CONF_OKTA_COOKIES: SECRET_OKTA, CONF_PORTAL_COOKIES: SECRET_PORTAL},
    )
    entry.add_to_hass(hass)
    client = PsegClient(okta_cookies=SECRET_OKTA, portal_cookies=SECRET_PORTAL)
    coord = PsegDataUpdateCoordinator(hass, client, dict(entry.data), config_entry=entry)
    messages: list[str] = []

    scenarios = {
        "okta_expired": {"sso": {"text": OKTA_WIDGET}},
        "sso_503": {"sso": {"status_code": 503, "text": "down"}},
        "sso_no_form": {"sso": {"text": "<html>oops</html>"}},
        "sso_network": {"sso": {"exc": requests.ConnectionError("reset by peer")}},
        "saml_untrusted": {
            "sso": {
                "text": (
                    '<form action="https://evil.example/x">'
                    f'<input name="SAMLResponse" value="{SECRET_VALUES[3]}"/></form>'
                )
            }
        },
        "dashboard_503": {"dashboard": {"status_code": 503, "text": "down"}},
    }
    for name, scenario in scenarios.items():
        with requests_mock.Mocker(session=client.session) as m:
            m.get(f"{PORTAL_BASE_URL}/Dashboard", **scenario.get("dashboard", LOGGED_OUT))
            m.get(f"{PORTAL_BASE_URL}/", text="home")
            m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", **scenario.get("sso", {"text": ""}))
            try:
                await coord._async_update_data()
            except (ConfigEntryAuthFailed, UpdateFailed) as err:
                messages.append(f"{name}: {err!r} {err.__cause__!r}")
            await coord._async_keepalive(None)
    await hass.async_block_till_done()

    assert len(messages) == len(scenarios)
    _assert_no_secrets("\n".join(messages))
    _assert_no_secrets(caplog.text)

def _mock_sso_ok(m) -> None:
    """Okta session alive: SignIn returns the SAML auto-post form, ACS accepts it."""
    m.get(f"{PORTAL_BASE_URL}/Saml/okta-prod/SignIn", text=_AUTOPOST_FORM)
    m.post(f"{PORTAL_BASE_URL}/Saml/okta-prod/Acs", status_code=200, text="ok")


_AUTOPOST_FORM = (
    f'<form method="POST" action="{PORTAL_BASE_URL}/Saml/okta-prod/Acs">'
    '<input type="hidden" name="SAMLResponse" value="assertion"/></form>'
)

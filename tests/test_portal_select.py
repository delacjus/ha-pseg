"""Tests for choosing the MyMeter portal per config entry (upstream #13).

New Jersey stays the default for entries created before portal selection. Long
Island shares the MyMeter client but has no Okta sign-in and no CAPTCHA helper.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from homeassistant.components.diagnostics import REDACTED
from homeassistant.config_entries import SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests
import requests_mock

from custom_components.pseg.const import (
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PORTAL_URL,
    DEFAULT_PORTAL_URL,
    DOMAIN,
    OKTA_HOST,
    PORTAL_URL_LI,
    PORTAL_URL_NJ,
    USAGE_INTERVAL_DAILY,
    resolve_portal_url,
)
from custom_components.pseg.cost_evidence import (
    NY_TZ,
    CostEvidenceStatus,
    CostPermit,
    execute_cost_sampler,
)
from custom_components.pseg.diagnostics import async_get_config_entry_diagnostics
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegOktaSessionExpired,
    PsegSecurityError,
)

PORTAL_HOST_LI = "mysmartenergy.psegliny.com"

RAW_VALID_COST_PAYLOAD = {
    "Data": {
        "usageType": "Dollar",
        "tooltipOptions": {"currency": "USD", "usageTypeDisplayName": "Dollar"},
        "series": [
            {
                "name": "Meter #12345678",
                "tooltip": {"valuePrefix": "$", "valueDecimals": 2},
                "data": [
                    {
                        "x": 1729828800000,
                        "y": 1.25,
                        "hs": {
                            "start": "2026-10-25 00:00:00",
                            "end": "2026-10-25 01:00:00",
                        },
                    }
                ],
            }
        ],
    }
}


def _hourly_proof_client(portal_url: str) -> PsegClient:
    """Client whose jar proves the meter before the cost leg is admitted."""
    return PsegClient(
        portal_cookies="MM_SID=abc; MM_RememberMe=gen",
        portal_url=portal_url,
    )


def test_default_client_is_nj() -> None:
    """A client without a portal keeps the New Jersey base URL and both hosts."""
    client = PsegClient(portal_cookies="MM_SID=abc")
    assert client.portal_base_url == PORTAL_URL_NJ == DEFAULT_PORTAL_URL
    assert client.portal_host == "mysmartenergy.nj.pseg.com"
    assert client.session.allowed_hosts == frozenset({"mysmartenergy.nj.pseg.com", OKTA_HOST})


def test_unknown_or_empty_portal_falls_back_to_nj() -> None:
    """Only a known PORTALS key is accepted; anything else means New Jersey."""
    assert resolve_portal_url(None) == DEFAULT_PORTAL_URL
    assert resolve_portal_url("") == DEFAULT_PORTAL_URL
    assert resolve_portal_url("https://example.invalid") == DEFAULT_PORTAL_URL
    assert resolve_portal_url(PORTAL_URL_LI) == PORTAL_URL_LI

    client = PsegClient(portal_url="https://example.invalid")
    assert client.portal_base_url == PORTAL_URL_NJ
    assert client.portal_host == "mysmartenergy.nj.pseg.com"


def test_li_client_uses_li_host_for_requests_cookies_and_allowlist() -> None:
    """A Long Island client scopes cookies, headers and requests to its own host."""
    client = _hourly_proof_client(PORTAL_URL_LI)

    assert client.portal_base_url == PORTAL_URL_LI
    assert client.portal_host == PORTAL_HOST_LI
    # Okta is New Jersey only, so only the Long Island host is allowlisted.
    assert client.session.allowed_hosts == frozenset({PORTAL_HOST_LI})
    assert OKTA_HOST not in client.session.allowed_hosts
    assert {c.domain for c in client.session.cookies} == {PORTAL_HOST_LI}
    assert client.session.headers["Referer"] == f"{PORTAL_URL_LI}/Dashboard"

    with requests_mock.Mocker(session=client.session) as mock:
        mock.get(f"{PORTAL_URL_LI}/Dashboard", text="ok")
        assert client.session.get(f"{PORTAL_URL_LI}/Dashboard").status_code == 200
        assert mock.request_history[0].url == f"{PORTAL_URL_LI}/Dashboard"

    with pytest.raises(PsegSecurityError):
        client.session.get(f"{PORTAL_URL_NJ}/Dashboard")
    with pytest.raises(PsegSecurityError):
        client.session.get(f"https://{OKTA_HOST}/sso/saml")


def test_li_client_ignores_okta_cookies_and_has_no_okta_session() -> None:
    """Okta cookies on a Long Island entry never become an SSO session."""
    client = PsegClient(
        okta_cookies="idx=okta-secret",
        portal_cookies="MM_SID=abc",
        portal_url=PORTAL_URL_LI,
    )
    assert client.has_okta_session is False
    assert all(c.domain != OKTA_HOST for c in client.session.cookies)


def test_li_client_refuses_the_okta_path() -> None:
    """renew_sso raises the coordinator's typed auth error without any HTTP."""
    client = PsegClient(okta_cookies="idx=x", portal_url=PORTAL_URL_LI)
    with requests_mock.Mocker(session=client.session) as mock:
        with pytest.raises(PsegOktaSessionExpired):
            client.renew_sso()
        assert mock.request_history == []


def _successful_session(client: PsegClient) -> bool:
    client.sso_renewals = 1
    return True


async def test_user_flow_stores_the_selected_portal(hass: HomeAssistant) -> None:
    """The first setup step writes the chosen portal into the new entry."""
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Electric Meter 88776655"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={
                CONF_PORTAL_URL: PORTAL_URL_NJ,
                CONF_OKTA_COOKIES: "idx=good",
                CONF_PORTAL_COOKIES: "MM_SID=good",
            },
        )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PORTAL_URL] == PORTAL_URL_NJ


async def test_user_flow_without_portal_stays_nj(hass: HomeAssistant) -> None:
    """An older caller that sends no portal still creates a New Jersey entry."""
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Electric Meter 88776655"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_OKTA_COOKIES: "idx=good", CONF_PORTAL_COOKIES: "MM_SID=good"},
        )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PORTAL_URL] == PORTAL_URL_NJ


async def test_user_flow_creates_a_li_entry_with_li_cookies(
    hass: HomeAssistant,
) -> None:
    """A Long Island sign-in uses the Long Island host for the saved jar."""

    def renew(client: PsegClient) -> bool:
        client.sso_renewals = 1
        return True

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.renew_remember_me",
            new=renew,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 55443322"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={
                CONF_PORTAL_URL: PORTAL_URL_LI,
                CONF_PORTAL_COOKIES: "MM_SID=a; MM_RememberMe=b",
            },
        )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PORTAL_URL] == PORTAL_URL_LI
    assert {cookie["domain"] for cookie in result["data"]["cookies"]} == {PORTAL_HOST_LI}


async def test_li_with_okta_cookies_is_refused(hass: HomeAssistant) -> None:
    """Okta cookies only make sense on New Jersey and are refused before any HTTP."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
        data={CONF_PORTAL_URL: PORTAL_URL_LI, CONF_OKTA_COOKIES: "idx=good"},
    )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "okta_nj_only"}


async def test_li_captcha_step_is_not_offered(hass: HomeAssistant) -> None:
    """The CAPTCHA helper is New Jersey only, so Long Island gets a form error."""

    def want_captcha(self: PsegClient) -> bool:
        raise PsegCaptchaRequired("synthetic")

    with patch("custom_components.pseg.pseg_client.PsegClient.login_local", new=want_captcha):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={
                CONF_PORTAL_URL: PORTAL_URL_LI,
                CONF_MYMETER_EMAIL: "user@example.com",
                CONF_MYMETER_PASSWORD: "synthetic-password",
            },
        )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "captcha_nj_only"}


async def test_reauth_keeps_the_stored_portal(hass: HomeAssistant) -> None:
    """Reauth hides the portal choice and never rewrites it."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="11223344",
        data={
            CONF_PORTAL_URL: PORTAL_URL_LI,
            CONF_PORTAL_COOKIES: "MM_SID=old; MM_RememberMe=oldgen",
        },
    )
    entry.add_to_hass(hass)

    result = await entry.start_reauth_flow(hass)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"
    schema_keys = {getattr(key, "schema", key) for key in result["data_schema"].schema}
    assert CONF_PORTAL_URL not in schema_keys

    def renew(client: PsegClient) -> bool:
        client.sso_renewals = 1
        return True

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.renew_remember_me",
            new=renew,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 11223344"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={CONF_PORTAL_COOKIES: "MM_SID=new; MM_RememberMe=newgen"},
        )

    assert result2["type"] == FlowResultType.ABORT
    assert result2["reason"] == "reauth_successful"
    assert entry.data[CONF_PORTAL_URL] == PORTAL_URL_LI


def _dummy_permit() -> CostPermit:
    return CostPermit(
        permit_id="portal-permit",
        entry_id="test_entry_001",
        ny_date=datetime.now(NY_TZ).date().isoformat(),
        usage_interval=USAGE_INTERVAL_DAILY,
        start_str="2026-10-11",
        end_str="2026-10-25",
        created_at=datetime.now(UTC).isoformat(),
    )


def _identity_charts() -> tuple[dict, dict]:
    """Daily and hourly payloads that prove meter 12345678."""
    day = (datetime.now(NY_TZ) - timedelta(days=1)).date()
    daily = {
        "Data": {
            "series": [
                {
                    "name": "Meter #12345678 (RS)",
                    "data": [
                        {
                            "x": int(
                                datetime.combine(day, datetime.min.time(), tzinfo=NY_TZ).timestamp()
                                * 1000
                            ),
                            "y": 10.0,
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
    hourly = {
        "Data": {
            "series": [
                {
                    "name": "Meter #12345678 (RS)",
                    "data": [
                        {
                            "x": int(
                                (
                                    datetime.combine(day, datetime.min.time(), tzinfo=NY_TZ)
                                    + timedelta(hours=hour)
                                ).timestamp()
                                * 1000
                            ),
                            "y": 1.0,
                        }
                        for hour in range(24)
                    ],
                }
            ]
        }
    }
    return daily, hourly


def test_cost_evidence_session_follows_the_client_portal() -> None:
    """The cost sampler receives the client's Long Island base URL and host."""
    client = _hourly_proof_client(PORTAL_URL_LI)
    client._renewal_runtime = SimpleNamespace(
        entry_id="test_entry_001", _is_current=lambda token: True
    )
    client._renewal_token = 1
    daily, hourly = _identity_charts()

    with (
        patch.object(client, "_get_verification_token", return_value="tok"),
        patch.object(client, "_fetch_chart_json", side_effect=[daily, hourly]),
        patch(
            "custom_components.pseg.cost_evidence.validate_permit_against_registry",
            return_value=True,
        ),
        patch("custom_components.pseg.cost_evidence.consume_issued_permit"),
        patch(
            "custom_components.pseg.cost_evidence.execute_cost_sampler",
            return_value=(CostEvidenceStatus.OK, {"status": "ok"}, True),
        ) as sampler,
    ):
        result = client.fetch_energy_data(days_back=14, cost_permit=_dummy_permit())

    assert result.get("identity_confirmed") is True
    assert sampler.call_args.kwargs["portal_base_url"] == PORTAL_URL_LI
    assert sampler.call_args.kwargs["portal_host"] == PORTAL_HOST_LI


def test_cost_sampler_dispatches_to_the_given_portal() -> None:
    """The sampler's session allowlists and requests only the supplied portal."""
    permit = _dummy_permit()
    seed = requests.cookies.RequestsCookieJar()
    seed.set("MM_SID", "abc", domain=PORTAL_HOST_LI, path="/")

    with requests_mock.Mocker() as mock:
        mock.post(f"{PORTAL_URL_LI}/Dashboard/Chart", text="ok")
        mock.get(
            f"{PORTAL_URL_LI}/Dashboard/ChartData",
            json=RAW_VALID_COST_PAYLOAD,
        )
        status, _sample, promotable = execute_cost_sampler(
            seed_cookies=seed,
            token="tok",
            permit=permit,
            owner_check=lambda: None,
            authoritative_meters={"12345678"},
            meter_placeholders={},
            portal_base_url=PORTAL_URL_LI,
            portal_host=PORTAL_HOST_LI,
        )

    assert status == CostEvidenceStatus.OK
    assert promotable is True
    assert len(mock.request_history) == 2
    assert all(request.url.startswith(PORTAL_URL_LI) for request in mock.request_history)
    assert mock.request_history[0].headers["Origin"] == PORTAL_URL_LI


async def test_diagnostics_includes_the_portal_without_secrets(
    hass: HomeAssistant,
) -> None:
    """Diagnostics reports the portal while the cookie stays redacted."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="11223344",
        data={
            CONF_PORTAL_URL: PORTAL_URL_LI,
            CONF_PORTAL_COOKIES: "MM_SID=secret-value",
        },
    )
    entry.add_to_hass(hass)

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert diagnostics["entry"]["data"][CONF_PORTAL_URL] == PORTAL_URL_LI
    assert diagnostics["entry"]["data"][CONF_PORTAL_COOKIES] == REDACTED
    assert "secret-value" not in str(diagnostics)

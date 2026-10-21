"""Tests for PSE&G config flow and options flow."""

from unittest.mock import patch

from homeassistant.config_entries import SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pseg.const import (
    CONF_METER_ID,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    DEFAULT_METER_NAME,
    DOMAIN,
)
from custom_components.pseg.pseg_client import (
    PsegOktaSessionExpired,
    PsegTransientError,
)


async def test_user_flow_shows_form(hass: HomeAssistant) -> None:
    """Test initial user step presents the cookie form."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {}


async def test_user_flow_missing_credentials(hass: HomeAssistant) -> None:
    """Test submitting without Okta cookies fails with missing_credentials."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
        data={CONF_OKTA_COOKIES: "", CONF_PORTAL_COOKIES: ""},
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "missing_credentials"}


async def test_user_flow_okta_session_invalid(hass: HomeAssistant) -> None:
    """Test expired Okta session shows okta_session_invalid error."""
    with patch(
        "custom_components.pseg.pseg_client.PsegClient.ensure_session",
        side_effect=PsegOktaSessionExpired("expired"),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_OKTA_COOKIES: "idx=expired_token"},
        )
        assert result["type"] == FlowResultType.FORM
        assert result["errors"] == {"base": "okta_session_invalid"}


async def test_user_flow_cannot_connect(hass: HomeAssistant) -> None:
    """Test network error shows cannot_connect error."""
    with patch(
        "custom_components.pseg.pseg_client.PsegClient.ensure_session",
        side_effect=PsegTransientError("timeout"),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_OKTA_COOKIES: "idx=valid_token"},
        )
        assert result["type"] == FlowResultType.FORM
        assert result["errors"] == {"base": "cannot_connect"}


async def test_user_flow_success_creates_entry(hass: HomeAssistant) -> None:
    """Test valid cookies successfully create a config entry with unique_id."""
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            return_value=True,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Electric Meter 88776655"},
        ),
        patch(
            "custom_components.pseg.async_setup_entry",
            return_value=True,
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={
                CONF_OKTA_COOKIES: "idx=good_okta_cookie",
                CONF_PORTAL_COOKIES: "MM_SID=good_portal_cookie",
            },
        )
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert result["title"] == "PSE&G (88776655)"
        assert result["result"].unique_id == "88776655"
        assert result["data"][CONF_METER_ID] == "88776655"
        assert result["data"][CONF_OKTA_COOKIES] == "idx=good_okta_cookie"
        assert result["data"][CONF_PORTAL_COOKIES] == "MM_SID=good_portal_cookie"


async def test_user_flow_duplicate_aborts(hass: HomeAssistant) -> None:
    """Test adding an account that is already configured aborts."""
    existing_entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="88776655",
        data={CONF_OKTA_COOKIES: "idx=existing"},
    )
    existing_entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            return_value=True,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Electric Meter 88776655"},
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_OKTA_COOKIES: "idx=new_attempt"},
        )
        assert result["type"] == FlowResultType.ABORT
        assert result["reason"] == "already_configured"


async def test_reauth_flow_matching_account(hass: HomeAssistant) -> None:
    """Test re-authenticating existing entry with matching meter id succeeds."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="11223344",
        data={
            CONF_OKTA_COOKIES: "idx=old_expired",
            CONF_PORTAL_COOKIES: "MM_SID=old",
        },
    )
    entry.add_to_hass(hass)

    result = await entry.start_reauth_flow(hass)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            return_value=True,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 11223344"},
        ),
        patch(
            "custom_components.pseg.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                CONF_OKTA_COOKIES: "idx=fresh_token",
                CONF_PORTAL_COOKIES: "MM_SID=fresh_portal",
            },
        )
        assert result2["type"] == FlowResultType.ABORT
        assert result2["reason"] == "reauth_successful"
        assert entry.data[CONF_OKTA_COOKIES] == "idx=fresh_token"


async def test_reauth_flow_account_mismatch(hass: HomeAssistant) -> None:
    """Test re-authenticating with cookies for a different meter aborts."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="11223344",
        data={CONF_OKTA_COOKIES: "idx=old"},
    )
    entry.add_to_hass(hass)

    result = await entry.start_reauth_flow(hass)

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            return_value=True,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Different Meter 99999999"},
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={CONF_OKTA_COOKIES: "idx=different_account"},
        )
        assert result2["type"] == FlowResultType.ABORT
        assert result2["reason"] == "reauth_account_mismatch"


async def test_reconfigure_flow_success(hass: HomeAssistant) -> None:
    """Test manual reconfiguration updates session cookies."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="11223344",
        data={CONF_OKTA_COOKIES: "idx=initial"},
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "reconfigure", "entry_id": entry.entry_id},
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reconfigure"

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            return_value=True,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 11223344"},
        ),
        patch(
            "custom_components.pseg.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={CONF_OKTA_COOKIES: "idx=updated_token"},
        )
        assert result2["type"] == FlowResultType.ABORT
        assert result2["reason"] == "reconfigure_successful"
        assert entry.data[CONF_OKTA_COOKIES] == "idx=updated_token"


async def test_options_flow_rate_update(hass: HomeAssistant) -> None:
    """Test options flow updates estimated price_per_kwh."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="11223344",
        data={CONF_OKTA_COOKIES: "idx=valid"},
        options={CONF_PRICE_PER_KWH: 0.247},
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "init"

    result2 = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={CONF_PRICE_PER_KWH: 0.325},
    )
    assert result2["type"] == FlowResultType.CREATE_ENTRY
    assert result2["data"][CONF_PRICE_PER_KWH] == 0.325


@pytest.mark.parametrize(
    ("fetch_kwargs", "error"),
    [
        ({"side_effect": PsegTransientError("chart 503")}, "cannot_connect"),
        ({"side_effect": RuntimeError("parse error")}, "cannot_connect"),
        ({"return_value": {}}, "cannot_connect"),
        ({"return_value": {"meter": DEFAULT_METER_NAME}}, "cannot_connect"),
        ({"side_effect": PsegOktaSessionExpired("redirect")}, "okta_session_invalid"),
    ],
)
async def test_user_flow_meter_lookup_failure_creates_no_entry(
    hass: HomeAssistant, fetch_kwargs, error
) -> None:
    """A failed meter lookup must not create an entry pinned to a placeholder unique_id."""
    with (
        patch("custom_components.pseg.pseg_client.PsegClient.ensure_session", return_value=True),
        patch("custom_components.pseg.pseg_client.PsegClient.fetch_energy_data", **fetch_kwargs),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_OKTA_COOKIES: "idx=valid_token"},
        )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": error}
    assert hass.config_entries.async_entries(DOMAIN) == []


async def test_reauth_meter_lookup_failure_is_not_account_mismatch(hass: HomeAssistant) -> None:
    """A transient meter lookup failure during reauth shows cannot_connect, not a mismatch abort."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="11223344", data={CONF_OKTA_COOKIES: "idx=old"}
    )
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    with (
        patch("custom_components.pseg.pseg_client.PsegClient.ensure_session", return_value=True),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            side_effect=PsegTransientError("chart 503"),
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input={CONF_OKTA_COOKIES: "idx=fresh"}
        )
    assert result2["type"] == FlowResultType.FORM
    assert result2["errors"] == {"base": "cannot_connect"}
    assert entry.data[CONF_OKTA_COOKIES] == "idx=old"

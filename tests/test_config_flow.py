"""Tests for PSE&G config flow and options flow."""

import json
from pathlib import Path
from unittest.mock import call, patch

from homeassistant.config_entries import SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import requests

from custom_components.pseg.const import (
    CONF_KNOWN_METER_IDS,
    CONF_METER_ID,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    DEFAULT_METER_NAME,
    DOMAIN,
)
from custom_components.pseg.pseg_client import (
    PsegClient,
    PsegOktaSessionExpired,
    PsegTransientError,
)


def _successful_session(client: PsegClient) -> bool:
    """Model a usable Okta session when tests are focused on another behavior."""
    client.sso_renewals = 1
    return True


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
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={
                "meter": "Electric Meter 88776655",
                "meter_ids": ["88776655", "11223344"],
            },
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
        assert result["data"][CONF_KNOWN_METER_IDS] == ["88776655", "11223344"]



async def test_user_flow_remember_me_portal_only(hass: HomeAssistant) -> None:
    """Portal cookies with MM_RememberMe and no Okta cookies set up via Remember Me."""

    def renew(client: PsegClient) -> bool:
        client.sso_renewals = 1
        return True

    with (
        patch("custom_components.pseg.pseg_client.PsegClient.ensure_session", return_value=True),
        patch("custom_components.pseg.pseg_client.PsegClient.renew_remember_me", new=renew),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 55443322"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_OKTA_COOKIES: "", CONF_PORTAL_COOKIES: "MM_SID=a; MM_RememberMe=b"},
        )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert any(c["name"] == "MM_RememberMe" for c in result["data"]["cookies"])


async def test_user_flow_remember_me_rejected(hass: HomeAssistant) -> None:
    with (
        patch("custom_components.pseg.pseg_client.PsegClient.ensure_session", return_value=True),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.renew_remember_me",
            side_effect=PsegOktaSessionExpired("rejected"),
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 55443322"},
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_OKTA_COOKIES: "", CONF_PORTAL_COOKIES: "MM_SID=a; MM_RememberMe=b"},
        )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "remember_me_failed"}


async def test_user_flow_requires_some_cookies(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
        data={CONF_OKTA_COOKIES: "", CONF_PORTAL_COOKIES: ""},
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "missing_credentials"}

async def test_user_flow_proves_okta_only_renewal(hass: HomeAssistant) -> None:
    """Setup needs a second client that renews without the pasted portal session."""
    sessions: list[PsegClient] = []

    def ensure_session(client: PsegClient) -> bool:
        sessions.append(client)
        if len(sessions) == 2:
            client.sso_renewals = 1
        return True

    with (
        patch("custom_components.pseg.config_flow.PsegClient", wraps=PsegClient) as clients,
        patch("custom_components.pseg.pseg_client.PsegClient.ensure_session", new=ensure_session),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 88776655"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={
                CONF_OKTA_COOKIES: "idx=example",
                CONF_PORTAL_COOKIES: "MM_SID=example",
            },
        )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert clients.call_args_list == [
        call(okta_cookies="idx=example", portal_cookies="MM_SID=example", email="", password=""),
        call(okta_cookies="idx=example"),
    ]
    assert len(sessions) == 2
    assert sessions[0] is not sessions[1]
    assert sessions[1].sso_renewals == 1
    assert any(cookie["name"] == "MM_SID" for cookie in result["data"]["cookies"])


@pytest.mark.parametrize(
    ("renewal_result", "error"),
    [
        (PsegOktaSessionExpired("sign-in widget"), "okta_no_session"),
        (True, "okta_no_session"),
        (PsegTransientError("timeout"), "cannot_connect"),
        (requests.Timeout("timeout"), "cannot_connect"),
    ],
)
async def test_user_flow_rejects_unrenewable_okta_cookies(
    hass: HomeAssistant, renewal_result: bool | Exception, error: str
) -> None:
    """A valid portal session alone cannot establish durable Okta access."""
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            side_effect=[True, renewal_result],
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 88776655"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={
                CONF_OKTA_COOKIES: "idx=example",
                CONF_PORTAL_COOKIES: "MM_SID=example",
            },
        )

    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": error}
    assert hass.config_entries.async_entries(DOMAIN) == []


@pytest.mark.parametrize("source", ["reauth", "reconfigure"])
async def test_reauthentication_requires_okta_only_renewal(
    hass: HomeAssistant, source: str
) -> None:
    """Replacing stored cookies also needs proof that Okta can renew them."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="88776655",
        data={CONF_OKTA_COOKIES: "idx=old", CONF_PORTAL_COOKIES: "MM_SID=old"},
    )
    entry.add_to_hass(hass)
    if source == "reauth":
        flow = await entry.start_reauth_flow(hass)
    else:
        flow = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": source, "entry_id": entry.entry_id}
        )

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            side_effect=[True, PsegOktaSessionExpired("sign-in widget")],
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 88776655"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            flow["flow_id"],
            user_input={
                CONF_OKTA_COOKIES: "idx=new",
                CONF_PORTAL_COOKIES: "MM_SID=new",
            },
        )

    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "okta_no_session"}
    assert entry.data[CONF_OKTA_COOKIES] == "idx=old"


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
            new=_successful_session,
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


@pytest.mark.parametrize("known_ids", [[], ["000303817579"]])
async def test_user_flow_aborts_for_any_existing_account_meter(
    hass: HomeAssistant, known_ids: list[str]
) -> None:
    """A successor meter must not create a second entry for the same account."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="000126274191",
        data={CONF_KNOWN_METER_IDS: known_ids},
    )
    entry.add_to_hass(hass)
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={
                "meter": "Meter #000303817579 (RS)",
                "meter_ids": ["000303817579", "000126274191"] if not known_ids else ["000303817579"],
            },
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
            new=_successful_session,
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
            new=_successful_session,
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


async def test_reauth_accepts_replaced_meter_still_on_account(hass: HomeAssistant) -> None:
    """Entry keyed on a replaced meter reauths fine while that meter is still on the account."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="000126274191",
        data={CONF_OKTA_COOKIES: "idx=old"},
    )
    entry.add_to_hass(hass)

    result = await entry.start_reauth_flow(hass)

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={
                "meter": "Meter #000303817579 (Residential Service (RS))",
                "meter_ids": ["000303817579", "000126274191"],
            },
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={CONF_OKTA_COOKIES: "idx=fresh"},
        )
        assert result2["type"] == FlowResultType.ABORT
        assert result2["reason"] == "reauth_successful"
    assert entry.data[CONF_OKTA_COOKIES] == "idx=fresh"


@pytest.mark.parametrize("source", ["reauth", "reconfigure"])
async def test_reauthentication_survives_removed_old_meter(
    hass: HomeAssistant, source: str
) -> None:
    """A known successor proves account identity after the unique-id meter vanishes."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="000126274191",
        data={CONF_KNOWN_METER_IDS: ["000126274191", "000303817579"]},
    )
    entry.add_to_hass(hass)
    if source == "reauth":
        result = await entry.start_reauth_flow(hass)
    else:
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": source, "entry_id": entry.entry_id}
        )
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={
                "meter": "Meter #000303817579 (RS)",
                "meter_ids": ["000303817579", "000999999999"],
            },
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        updated = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input={CONF_OKTA_COOKIES: "idx=fresh"}
        )
    assert updated["type"] == FlowResultType.ABORT
    assert updated["reason"] == f"{source}_successful"
    assert entry.unique_id == "000126274191"
    assert set(entry.data[CONF_KNOWN_METER_IDS]) == {
        "000126274191", "000303817579", "000999999999"
    }


@pytest.mark.parametrize("source", ["reauth", "reconfigure"])
async def test_reauthentication_rejects_disjoint_account(
    hass: HomeAssistant, source: str
) -> None:
    """A nonempty meter set with no known id is a different account."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="111",
        data={CONF_KNOWN_METER_IDS: ["111", "222"]},
    )
    entry.add_to_hass(hass)
    if source == "reauth":
        result = await entry.start_reauth_flow(hass)
    else:
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": source, "entry_id": entry.entry_id}
        )
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter #999 (RS)", "meter_ids": ["999"]},
        ),
    ):
        updated = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input={CONF_OKTA_COOKIES: "idx=other"}
        )
    assert updated["type"] == FlowResultType.ABORT
    assert updated["reason"] == "reauth_account_mismatch"


async def test_reauth_legacy_entry_accepts_its_original_meter(hass: HomeAssistant) -> None:
    """Entries created before known_meter_ids still trust their stored meter id."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="111", data={CONF_METER_ID: "222"}
    )
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter #222 (RS)", "meter_ids": ["222"]},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        updated = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input={CONF_OKTA_COOKIES: "idx=fresh"}
        )
    assert updated["reason"] == "reauth_successful"
    assert set(entry.data[CONF_KNOWN_METER_IDS]) == {"111", "222"}


async def test_reauth_with_empty_meter_list_keeps_existing_identity(hass: HomeAssistant) -> None:
    """An empty meter list is inconclusive and must not strand the entry."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, unique_id="111", data={})
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter #999 (RS)", "meter_ids": []},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        updated = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input={CONF_OKTA_COOKIES: "idx=fresh"}
        )
    assert updated["reason"] == "reauth_successful"
    assert entry.unique_id == "111"
    assert entry.data[CONF_KNOWN_METER_IDS] == ["111"]


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
            new=_successful_session,
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
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
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
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_session,
        ),
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


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("abc123TOKEN", "MM_RememberMe=abc123TOKEN"),
        ("  abc123TOKEN \n", "MM_RememberMe=abc123TOKEN"),
        ("cookie: MM_SID=a; MM_RememberMe=b", "MM_SID=a; MM_RememberMe=b"),
        ("MM_SID=a; MM_RememberMe=b", "MM_SID=a; MM_RememberMe=b"),
        ("", ""),
    ],
)
def test_normalize_portal_cookies(raw: str, expected: str) -> None:
    from custom_components.pseg.config_flow import _normalize_portal_cookies

    assert _normalize_portal_cookies(raw) == expected


async def test_user_flow_email_password_login(hass: HomeAssistant) -> None:
    """Email/password only: setup proves login_local and stores the login."""
    calls: list[str] = []

    def login(client: PsegClient) -> bool:
        calls.append("login")
        client.sso_renewals = 1
        return True

    with (
        patch("custom_components.pseg.pseg_client.PsegClient.ensure_session", return_value=True),
        patch("custom_components.pseg.pseg_client.PsegClient.login_local", new=login),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 66554433"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={"mymeter_email": "me@example.com", "mymeter_password": "pw"},
        )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert calls == ["login"]
    assert result["data"]["mymeter_email"] == "me@example.com"
    assert result["data"]["mymeter_password"] == "pw"


async def test_user_flow_email_password_rejected(hass: HomeAssistant) -> None:
    from custom_components.pseg.pseg_client import PsegLoginRejected

    with patch(
        "custom_components.pseg.pseg_client.PsegClient.login_local",
        side_effect=PsegLoginRejected("bad"),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={"mymeter_email": "me@example.com", "mymeter_password": "wrong"},
        )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "login_failed"}



STORED_EMAIL = "me@example.com"
STORED_PASSWORD = "stored-secret"


def _stored_login_entry(hass: HomeAssistant) -> MockConfigEntry:
    """Create an entry that already holds a MyMeter email/password login."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="11223344",
        data={
            CONF_MYMETER_EMAIL: STORED_EMAIL,
            CONF_MYMETER_PASSWORD: STORED_PASSWORD,
        },
    )
    entry.add_to_hass(hass)
    return entry


async def _start_credentials_flow(hass: HomeAssistant, entry, source: str):
    """Open the reauth or reconfigure form for an entry."""
    if source == "reauth":
        return await entry.start_reauth_flow(hass)
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": source, "entry_id": entry.entry_id}
    )


def _recording_login(seen: dict[str, str]):
    """Record which email/password the flow asked PsegClient to sign in with."""

    def login(client: PsegClient) -> bool:
        seen["email"] = client._email
        seen["password"] = client._password
        client.sso_renewals = 1
        return True

    return login


@pytest.mark.parametrize("source", ["reauth", "reconfigure"])
async def test_blank_credentials_reuse_stored_login(
    hass: HomeAssistant, source: str
) -> None:
    """Submitting an empty form re-runs the stored login (one-click retry)."""
    entry = _stored_login_entry(hass)
    result = await _start_credentials_flow(hass, entry, source)
    assert result["type"] == FlowResultType.FORM
    # The stored password must never be offered back as a form default.
    assert result["data_schema"]({})[CONF_MYMETER_PASSWORD] == ""

    seen: dict[str, str] = {}
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            return_value=True,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.login_local",
            new=_recording_login(seen),
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 11223344"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        updated = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                CONF_MYMETER_EMAIL: "",
                CONF_MYMETER_PASSWORD: "",
                CONF_OKTA_COOKIES: "",
                CONF_PORTAL_COOKIES: "",
            },
        )
    assert updated["type"] == FlowResultType.ABORT
    assert updated["reason"] == f"{source}_successful"
    assert seen == {"email": STORED_EMAIL, "password": STORED_PASSWORD}
    assert entry.data[CONF_MYMETER_EMAIL] == STORED_EMAIL
    assert entry.data[CONF_MYMETER_PASSWORD] == STORED_PASSWORD


@pytest.mark.parametrize("source", ["reauth", "reconfigure"])
async def test_same_email_blank_password_reuses_stored_password(
    hass: HomeAssistant, source: str
) -> None:
    """Retyping the same email with a blank password keeps the stored password."""
    entry = _stored_login_entry(hass)
    result = await _start_credentials_flow(hass, entry, source)

    seen: dict[str, str] = {}
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            return_value=True,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.login_local",
            new=_recording_login(seen),
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 11223344"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        updated = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                CONF_MYMETER_EMAIL: STORED_EMAIL,
                CONF_MYMETER_PASSWORD: "",
            },
        )
    assert updated["type"] == FlowResultType.ABORT
    assert updated["reason"] == f"{source}_successful"
    assert seen == {"email": STORED_EMAIL, "password": STORED_PASSWORD}
    assert entry.data[CONF_MYMETER_PASSWORD] == STORED_PASSWORD


@pytest.mark.parametrize("source", ["reauth", "reconfigure"])
async def test_different_email_blank_password_is_missing_credentials(
    hass: HomeAssistant, source: str
) -> None:
    """A new email with no password cannot borrow the stored password."""
    entry = _stored_login_entry(hass)
    result = await _start_credentials_flow(hass, entry, source)

    with patch(
        "custom_components.pseg.pseg_client.PsegClient.ensure_session",
        side_effect=AssertionError("must not validate incomplete credentials"),
    ):
        updated = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                CONF_MYMETER_EMAIL: "other@example.com",
                CONF_MYMETER_PASSWORD: "",
            },
        )
    assert updated["type"] == FlowResultType.FORM
    assert updated["errors"] == {"base": "missing_credentials"}
    assert entry.data[CONF_MYMETER_PASSWORD] == STORED_PASSWORD


@pytest.mark.parametrize("source", ["reauth", "reconfigure"])
async def test_blank_credentials_without_stored_login_is_missing_credentials(
    hass: HomeAssistant, source: str
) -> None:
    """An entry with no saved login still needs cookies or a login."""
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="11223344", data={}
    )
    entry.add_to_hass(hass)
    result = await _start_credentials_flow(hass, entry, source)
    with patch(
        "custom_components.pseg.pseg_client.PsegClient.ensure_session",
        side_effect=AssertionError("must not validate incomplete credentials"),
    ):
        updated = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                CONF_MYMETER_EMAIL: "",
                CONF_MYMETER_PASSWORD: "",
                CONF_OKTA_COOKIES: "",
                CONF_PORTAL_COOKIES: "",
            },
        )
    assert updated["type"] == FlowResultType.FORM
    assert updated["errors"] == {"base": "missing_credentials"}


async def test_user_flow_redirected_local_login_is_not_followed(hass: HomeAssistant) -> None:
    """A redirect to Okta becomes a clear error, never an entry or an Okta login."""
    from custom_components.pseg.pseg_client import PsegLoginRedirected

    with patch(
        "custom_components.pseg.pseg_client.PsegClient.login_local",
        side_effect=PsegLoginRedirected("redirected"),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={"mymeter_email": "me@example.com", "mymeter_password": "pw"},
        )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "login_redirected"}
    assert hass.config_entries.async_entries(DOMAIN) == []


def test_captcha_step_description_reaches_the_renderer_as_real_newlines() -> None:
    """R2: the shipped JSON must decode to newlines, not literal backslash-n.

    The step description was double escaped, so HA rendered one run-on paragraph
    with visible ``\\n`` text instead of the numbered helper steps.
    """
    package = Path(__file__).parent.parent / "custom_components" / "pseg"
    for name in ("strings.json", "translations/en.json"):
        description = json.loads((package / name).read_text(encoding="utf-8"))[
            "config"
        ]["step"]["captcha"]["description"]
        assert "\\n" not in description
        assert description.count("\n") == 8
        assert "\n\n1. " in description
        assert "\n5. " in description
        assert "\n\nThe proof " in description

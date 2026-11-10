"""Tests for the setup portal step and the sign-in method menu.

The first setup step only chooses the portal; a menu then offers the sign-in
methods for that portal (MyMeter email/password, MyMeter cookie, and, on New
Jersey only, Okta cookies). Every method step shows its own fields only.
"""

from unittest.mock import patch

from homeassistant.config_entries import SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
import pytest

from custom_components.pseg.const import (
    CONF_CAPTCHA_RESPONSE,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PORTAL_URL,
    DEFAULT_PORTAL_URL,
    DOMAIN,
    PORTAL_URL_LI,
    PORTAL_URL_NJ,
)
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegLoginRejected,
)

PORTAL_HOST_LI = "mysmartenergy.psegliny.com"
EMAIL = "me@example.com"
PASSWORD = "synthetic-password"
PROOF = "menu-proof-11bb"


def _successful_login(client: PsegClient) -> bool:
    """Model a proven MyMeter email/password sign-in."""
    client.sso_renewals = 1
    return True


def _successful_renewal(client: PsegClient) -> bool:
    """Model a Remember Me cookie that renewed itself."""
    client.sso_renewals = 1
    return True


async def _async_true(*args, **kwargs) -> bool:
    return True


async def _start_setup(hass: HomeAssistant) -> dict:
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )


async def _to_menu(hass: HomeAssistant, portal: str = PORTAL_URL_NJ) -> dict:
    """Submit the portal-only form and return the method menu."""
    started = await _start_setup(hass)
    return await hass.config_entries.flow.async_configure(
        started["flow_id"], user_input={CONF_PORTAL_URL: portal}
    )


async def _method_form(
    hass: HomeAssistant, method: str, portal: str = PORTAL_URL_NJ
) -> dict:
    """Open one sign-in method's form through the menu."""
    menu = await _to_menu(hass, portal)
    return await hass.config_entries.flow.async_configure(
        menu["flow_id"], user_input={"next_step_id": method}
    )


def _schema_keys(form: dict) -> set[str]:
    return {getattr(key, "schema", key) for key in form["data_schema"].schema}


async def test_initial_setup_offers_only_the_portal(hass: HomeAssistant) -> None:
    """A new flow starts with the portal choice and no sign-in fields."""
    result = await _start_setup(hass)

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {}
    assert _schema_keys(result) == {CONF_PORTAL_URL}
    assert result["data_schema"]({})[CONF_PORTAL_URL] == DEFAULT_PORTAL_URL


async def test_new_jersey_portal_offers_every_sign_in_method(
    hass: HomeAssistant,
) -> None:
    """New Jersey offers MyMeter login, MyMeter cookie and Okta cookies."""
    menu = await _to_menu(hass, PORTAL_URL_NJ)

    assert menu["type"] == FlowResultType.MENU
    assert menu["step_id"] == "auth_method"
    # Login first: it is the recommended method.
    assert list(menu["menu_options"]) == [
        "mymeter_login",
        "mymeter_cookie",
        "okta_cookies",
    ]


async def test_long_island_portal_has_no_okta_method(hass: HomeAssistant) -> None:
    """Okta sign-in exists only on the New Jersey portal."""
    menu = await _to_menu(hass, PORTAL_URL_LI)

    assert menu["type"] == FlowResultType.MENU
    assert list(menu["menu_options"]) == ["mymeter_login", "mymeter_cookie"]


@pytest.mark.parametrize(
    ("method", "expected"),
    [
        ("mymeter_login", {CONF_MYMETER_EMAIL, CONF_MYMETER_PASSWORD}),
        ("mymeter_cookie", {CONF_PORTAL_COOKIES}),
        ("okta_cookies", {CONF_OKTA_COOKIES}),
    ],
)
async def test_method_step_shows_only_its_own_fields(
    hass: HomeAssistant, method: str, expected: set[str]
) -> None:
    """Each method form carries exactly that method's fields."""
    form = await _method_form(hass, method)

    assert form["type"] == FlowResultType.FORM
    assert form["step_id"] == method
    assert form["errors"] == {}
    assert _schema_keys(form) == expected


async def test_mymeter_login_creates_an_entry_for_the_chosen_portal(
    hass: HomeAssistant,
) -> None:
    """The email/password method stores the chosen portal and the login."""
    form = await _method_form(hass, "mymeter_login", PORTAL_URL_NJ)

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.login_local",
            new=_successful_login,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 88776655"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            user_input={CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PORTAL_URL] == PORTAL_URL_NJ
    assert result["data"][CONF_MYMETER_EMAIL] == EMAIL
    assert result["data"][CONF_MYMETER_PASSWORD] == PASSWORD
    # The unused methods are stored empty, as before.
    assert result["data"][CONF_OKTA_COOKIES] == ""
    assert result["data"][CONF_PORTAL_COOKIES] == ""


async def test_mymeter_cookie_creates_a_long_island_entry(
    hass: HomeAssistant,
) -> None:
    """The paste-cookie method uses the Long Island portal chosen in step 1."""
    form = await _method_form(hass, "mymeter_cookie", PORTAL_URL_LI)

    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.renew_remember_me",
            new=_successful_renewal,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 55443322"},
        ),
        patch("custom_components.pseg.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            user_input={CONF_PORTAL_COOKIES: "MM_SID=a; MM_RememberMe=b"},
        )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PORTAL_URL] == PORTAL_URL_LI
    assert {cookie["domain"] for cookie in result["data"]["cookies"]} == {
        PORTAL_HOST_LI
    }


async def test_okta_step_on_long_island_is_refused(hass: HomeAssistant) -> None:
    """Reaching the Okta step on Long Island refuses before any request."""
    menu = await _to_menu(hass, PORTAL_URL_LI)
    flow = hass.config_entries.flow._progress[menu["flow_id"]]

    result = await flow.async_step_okta_cookies({CONF_OKTA_COOKIES: "idx=good"})

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "okta_cookies"
    assert result["errors"] == {"base": "okta_nj_only"}
    assert hass.config_entries.async_entries(DOMAIN) == []


@pytest.mark.parametrize(
    ("method", "field"),
    [("mymeter_cookie", CONF_PORTAL_COOKIES), ("okta_cookies", CONF_OKTA_COOKIES)],
)
async def test_empty_cookie_form_asks_for_a_cookie(
    hass: HomeAssistant, method: str, field: str
) -> None:
    """An empty cookie form asks for the cookie, not for an email and password."""
    form = await _method_form(hass, method)

    result = await hass.config_entries.flow.async_configure(
        form["flow_id"], user_input={field: "  "}
    )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == method
    assert result["errors"] == {"base": "missing_cookie"}


async def test_failed_login_reshows_only_that_methods_form(
    hass: HomeAssistant,
) -> None:
    """A rejected login re-renders the same step with only its own fields."""
    form = await _method_form(hass, "mymeter_login")

    with patch(
        "custom_components.pseg.pseg_client.PsegClient.login_local",
        side_effect=PsegLoginRejected("rejected"),
    ):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            user_input={CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "mymeter_login"
    assert result["errors"] == {"base": "login_failed"}
    assert _schema_keys(result) == {CONF_MYMETER_EMAIL, CONF_MYMETER_PASSWORD}


async def test_legacy_one_shot_form_still_creates_an_entry(
    hass: HomeAssistant,
) -> None:
    """A submit that carries its own sign-in fields keeps working unchanged."""
    with (
        patch(
            "custom_components.pseg.pseg_client.PsegClient.ensure_session",
            new=_successful_login,
        ),
        patch(
            "custom_components.pseg.pseg_client.PsegClient.fetch_energy_data",
            return_value={"meter": "Meter 11223344"},
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
    assert result["data"][CONF_OKTA_COOKIES] == "idx=good"


async def test_captcha_from_mymeter_login_creates_a_new_entry(
    hass: HomeAssistant,
) -> None:
    """A CAPTCHA asked by the email/password method still creates the entry."""
    prepared: list[PsegClient] = []
    proofs: list[str] = []

    def want_captcha(client: PsegClient) -> bool:
        raise PsegCaptchaRequired("synthetic")

    def prepare(client: PsegClient) -> None:
        prepared.append(client)

    def submit(client: PsegClient, proof: str) -> bool:
        proofs.append(proof)
        client.sso_renewals = 1
        return True

    form = await _method_form(hass, "mymeter_login")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", want_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", prepare)
        mp.setattr(PsegClient, "submit_login_captcha", submit)
        mp.setattr(
            PsegClient,
            "fetch_energy_data",
            lambda client, days: {"meter": "Meter 66554433"},
        )
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)

        captcha = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            user_input={CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        assert captcha["type"] == FlowResultType.FORM
        assert captcha["step_id"] == "captcha"
        done = await hass.config_entries.flow.async_configure(
            captcha["flow_id"], user_input={CONF_CAPTCHA_RESPONSE: PROOF}
        )

    assert proofs == [PROOF]
    assert prepared and prepared[0]._email == EMAIL
    assert done["type"] == FlowResultType.CREATE_ENTRY
    assert done["data"][CONF_PORTAL_URL] == PORTAL_URL_NJ
    assert done["data"][CONF_MYMETER_EMAIL] == EMAIL
    assert done["data"][CONF_MYMETER_PASSWORD] == PASSWORD
    assert PROOF not in str(done["data"])

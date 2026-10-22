"""Config flow for the PSE&G Energy integration."""

from __future__ import annotations

import logging
import re
from typing import Any

from homeassistant import config_entries
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlowResult,
    OptionsFlow,
    OptionsFlowWithReload,
)
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
import requests
import voluptuous as vol

from .const import (
    CONF_KNOWN_METER_IDS,
    CONF_METER_ID,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    DEFAULT_METER_NAME,
    DEFAULT_PRICE_PER_KWH,
    DOMAIN,
    REMEMBER_ME_COOKIE,
)
from .pseg_client import (
    PsegClient,
    PsegLoginRejected,
    PsegOktaSessionExpired,
    PsegTransientError,
)

_LOGGER = logging.getLogger(__name__)


def _normalize_portal_cookies(raw: str) -> str:
    """Accept a full Cookie header, a 'cookie: ...' line, or a bare MM_RememberMe value.

    Live 2026-10-21: the Cookie header of a refreshed Dashboard request carries the
    values the browser SENT, which MyMeter may have just rotated, so the Remember Me
    value is best copied from DevTools > Application > Cookies, where it is a bare
    value without 'name='.
    """
    text = raw.strip()
    if text.lower().startswith("cookie:"):
        text = text[len("cookie:"):].strip()
    if text and "=" not in text and ";" not in text:
        return f"{REMEMBER_ME_COOKIE}={text}"
    return text


def _fill_stored_login(
    entry: ConfigEntry, email: str, password: str
) -> tuple[str, str]:
    """Reuse the entry's saved MyMeter login for fields the user left blank.

    Re-authentication is often just "the captcha/password prompt was for me, try
    again": submitting the empty form retries the stored login. Retyping the stored
    email with a blank password reuses the stored password, so the password never
    has to be echoed back into the form as a default value.
    """
    stored_email = str(entry.data.get(CONF_MYMETER_EMAIL) or "").strip()
    stored_password = str(entry.data.get(CONF_MYMETER_PASSWORD) or "")
    if not stored_email or not stored_password:
        return email, password
    if not email and not password:
        return stored_email, stored_password
    if email and not password and email == stored_email:
        return email, stored_password
    return email, password


def _known_meter_ids(entry: ConfigEntry) -> set[str]:
    """Return all meter ids previously associated with this entry."""
    known = set(entry.data.get(CONF_KNOWN_METER_IDS) or [])
    known.update(filter(None, (entry.unique_id, entry.data.get(CONF_METER_ID))))
    return known


class PsegConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for PSE&G Energy."""

    VERSION = 2

    def __init__(self) -> None:
        """Initialize the flow."""
        self._reauth_entry: ConfigEntry | None = None

    async def _async_validate_and_extract_meter(
        self, okta_cookies: str, portal_cookies: str, email: str = "", password: str = ""
    ) -> tuple[dict[str, str], PsegClient | None, str | None, list[str]]:
        """Validate credentials; return the active meter id and every meter id on the account."""
        errors: dict[str, str] = {}
        client = PsegClient(
            okta_cookies=okta_cookies, portal_cookies=portal_cookies, email=email, password=password
        )
        meter_id = None

        try:
            await self.hass.async_add_executor_job(client.ensure_session)
        except PsegLoginRejected:
            _LOGGER.warning("PSE&G MyMeter login rejected at setup: %s", client.auth_diagnostics())
            errors["base"] = "login_failed"
            return errors, None, None, []
        except PsegOktaSessionExpired:
            _LOGGER.warning("PSE&G cookies rejected at setup: %s", client.auth_diagnostics())
            errors["base"] = "okta_session_invalid"
            return errors, None, None, []
        except (PsegTransientError, requests.RequestException):
            errors["base"] = "cannot_connect"
            return errors, None, None, []
        except Exception as err:
            _LOGGER.exception("Unexpected error validating session: %s", err)
            errors["base"] = "unknown"
            return errors, None, None, []

        # The meter id becomes the entry unique_id (the stable statistic key),
        # so a failed lookup must fail the step rather than fall back to a placeholder
        # that every account would share.
        try:
            data = await self.hass.async_add_executor_job(client.fetch_energy_data, 1)
        except PsegOktaSessionExpired:
            _LOGGER.warning("PSE&G cookies rejected at setup: %s", client.auth_diagnostics())
            errors["base"] = "okta_session_invalid"
            return errors, None, None, []
        except Exception as err:
            _LOGGER.debug("Could not determine meter id during config flow: %s", type(err).__name__)
            errors["base"] = "cannot_connect"
            return errors, None, None, []

        meter_str = str(data.get("meter") or "")
        if meter_str and meter_str != DEFAULT_METER_NAME:
            match = re.search(r"\d+", meter_str)
            if match:
                meter_id = match.group(0)
            else:
                meter_id = re.sub(r"[^a-z0-9_]+", "_", meter_str.lower()).strip("_")

        if not meter_id:
            errors["base"] = "cannot_connect"
            return errors, None, None, []

        meter_ids = list(data.get("meter_ids") or []) if "meter_ids" in data else [meter_id]

        # A live MM_SID can mask cookies that cannot renew. Prove renewal on a fresh
        # throwaway client: via MyMeter Remember Me when the portal header carries
        # it (PSE&G's Okta session dies ~1 h after login), else via Okta SSO.
        if client.has_login:
            # Signing in with the stored email/password IS the renewal path; prove it
            # explicitly even if a pasted portal session made ensure_session pass.
            renewal_client = client
            renew = renewal_client.login_local
            no_session_error = "login_failed"
        elif client.has_remember_me:
            # Run on the client whose jar gets saved: renew_remember_me drops MM_SID
            # first (so nothing is masked), and a remember token rotated by this use
            # must not be left behind in a throwaway jar.
            renewal_client = client
            renew = renewal_client.renew_remember_me
            no_session_error = "remember_me_failed"
        else:
            renewal_client = PsegClient(okta_cookies=okta_cookies)
            renew = renewal_client.ensure_session
            no_session_error = "okta_no_session"
        try:
            renewed = await self.hass.async_add_executor_job(renew)
        except PsegOktaSessionExpired:
            _LOGGER.warning("PSE&G renewal check failed at setup: %s", renewal_client.auth_diagnostics())
            errors["base"] = no_session_error
            return errors, None, None, []
        except (PsegTransientError, requests.RequestException):
            errors["base"] = "cannot_connect"
            return errors, None, None, []
        except Exception as err:
            _LOGGER.exception("Unexpected error validating Okta renewal: %s", err)
            errors["base"] = "unknown"
            return errors, None, None, []

        if not renewed or renewal_client.sso_renewals < 1:
            errors["base"] = no_session_error
            return errors, None, None, []

        return errors, client, meter_id, meter_ids

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 1: Enter Okta and optional portal cookies."""
        errors: dict[str, str] = {}

        if user_input is not None:
            okta_cookies = user_input.get(CONF_OKTA_COOKIES, "").strip()
            portal_cookies = _normalize_portal_cookies(user_input.get(CONF_PORTAL_COOKIES, ""))
            email = user_input.get(CONF_MYMETER_EMAIL, "").strip()
            password = user_input.get(CONF_MYMETER_PASSWORD, "")

            if not okta_cookies and not portal_cookies and not (email and password):
                errors["base"] = "missing_credentials"
            else:
                errors, client, meter_id, meter_ids = await self._async_validate_and_extract_meter(
                    okta_cookies, portal_cookies, email, password
                )
                if not errors and client and meter_id:
                    await self.async_set_unique_id(meter_id)
                    self._abort_if_unique_id_configured()
                    if any(
                        set(meter_ids) & _known_meter_ids(entry)
                        for entry in self.hass.config_entries.async_entries(DOMAIN)
                    ):
                        return self.async_abort(reason="already_configured")

                    return self.async_create_entry(
                        title=f"PSE&G ({meter_id})",
                        data={
                            CONF_OKTA_COOKIES: okta_cookies,
                            CONF_PORTAL_COOKIES: portal_cookies,
                            CONF_MYMETER_EMAIL: email,
                            CONF_MYMETER_PASSWORD: password,
                            CONF_METER_ID: meter_id,
                            CONF_KNOWN_METER_IDS: meter_ids,
                            "cookies": client.export_cookies(),
                        },
                    )

        schema = vol.Schema(
            {
                vol.Optional(CONF_MYMETER_EMAIL, default=""): str,
                vol.Optional(CONF_MYMETER_PASSWORD, default=""): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
                vol.Optional(CONF_OKTA_COOKIES, default=""): str,
                vol.Optional(CONF_PORTAL_COOKIES, default=""): str,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-authentication triggered by HA."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm re-authentication with fresh session cookies or the saved login."""
        errors: dict[str, str] = {}

        if user_input is not None and self._reauth_entry:
            okta_cookies = user_input.get(CONF_OKTA_COOKIES, "").strip()
            portal_cookies = _normalize_portal_cookies(user_input.get(CONF_PORTAL_COOKIES, ""))
            email = user_input.get(CONF_MYMETER_EMAIL, "").strip()
            password = user_input.get(CONF_MYMETER_PASSWORD, "")

            if not okta_cookies and not portal_cookies:
                email, password = _fill_stored_login(
                    self._reauth_entry, email, password
                )

            if not okta_cookies and not portal_cookies and not (email and password):
                errors["base"] = "missing_credentials"
            else:
                errors, client, meter_id, meter_ids = await self._async_validate_and_extract_meter(
                    okta_cookies, portal_cookies, email, password
                )
                if not errors and client and meter_id:
                    known = _known_meter_ids(self._reauth_entry)
                    if meter_ids and known.isdisjoint(meter_ids):
                        return self.async_abort(reason="reauth_account_mismatch")

                    return self.async_update_reload_and_abort(
                        self._reauth_entry,
                        data={
                            **self._reauth_entry.data,
                            CONF_OKTA_COOKIES: okta_cookies,
                            CONF_PORTAL_COOKIES: portal_cookies,
                            CONF_MYMETER_EMAIL: email,
                            CONF_MYMETER_PASSWORD: password,
                            CONF_KNOWN_METER_IDS: sorted(known.union(meter_ids)),
                            "cookies": client.export_cookies(),
                        },
                    )

        schema = vol.Schema(
            {
                vol.Optional(CONF_MYMETER_EMAIL, default=""): str,
                vol.Optional(CONF_MYMETER_PASSWORD, default=""): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
                vol.Optional(CONF_OKTA_COOKIES, default=""): str,
                vol.Optional(CONF_PORTAL_COOKIES, default=""): str,
            }
        )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle manual reconfiguration from device/service settings."""
        errors: dict[str, str] = {}
        reconfigure_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )

        if user_input is not None and reconfigure_entry:
            okta_cookies = user_input.get(CONF_OKTA_COOKIES, "").strip()
            portal_cookies = _normalize_portal_cookies(user_input.get(CONF_PORTAL_COOKIES, ""))
            email = user_input.get(CONF_MYMETER_EMAIL, "").strip()
            password = user_input.get(CONF_MYMETER_PASSWORD, "")

            if not okta_cookies and not portal_cookies:
                email, password = _fill_stored_login(
                    reconfigure_entry, email, password
                )

            if not okta_cookies and not portal_cookies and not (email and password):
                errors["base"] = "missing_credentials"
            else:
                errors, client, meter_id, meter_ids = await self._async_validate_and_extract_meter(
                    okta_cookies, portal_cookies, email, password
                )
                if not errors and client and meter_id:
                    known = _known_meter_ids(reconfigure_entry)
                    if meter_ids and known.isdisjoint(meter_ids):
                        return self.async_abort(reason="reauth_account_mismatch")

                    return self.async_update_reload_and_abort(
                        reconfigure_entry,
                        data={
                            **reconfigure_entry.data,
                            CONF_OKTA_COOKIES: okta_cookies,
                            CONF_PORTAL_COOKIES: portal_cookies,
                            CONF_MYMETER_EMAIL: email,
                            CONF_MYMETER_PASSWORD: password,
                            CONF_KNOWN_METER_IDS: sorted(known.union(meter_ids)),
                            "cookies": client.export_cookies(),
                        },
                    )

        schema = vol.Schema(
            {
                vol.Optional(CONF_MYMETER_EMAIL, default=""): str,
                vol.Optional(CONF_MYMETER_PASSWORD, default=""): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
                vol.Optional(CONF_OKTA_COOKIES, default=""): str,
                vol.Optional(CONF_PORTAL_COOKIES, default=""): str,
            }
        )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=schema,
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> OptionsFlow:
        """Get options flow for this entry."""
        return PsegOptionsFlowHandler()


class PsegOptionsFlowHandler(OptionsFlowWithReload):
    """Handle options flow for PSE&G Energy (HA reloads the entry on save)."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage integration options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_PRICE_PER_KWH,
                    default=self.config_entry.options.get(
                        CONF_PRICE_PER_KWH, DEFAULT_PRICE_PER_KWH
                    ),
                ): vol.Coerce(float),
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema)

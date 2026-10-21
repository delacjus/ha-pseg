"""Config flow for the PSE&G Energy integration."""

from __future__ import annotations

import logging
import re
from typing import Any

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry, ConfigFlowResult, OptionsFlow
from homeassistant.core import callback
import requests
import voluptuous as vol

from .const import (
    CONF_METER_ID,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    DEFAULT_PRICE_PER_KWH,
    DOMAIN,
)
from .pseg_client import (
    PsegClient,
    PsegOktaSessionExpired,
    PsegTransientError,
)

_LOGGER = logging.getLogger(__name__)


class PsegConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for PSE&G Energy."""

    VERSION = 2

    def __init__(self) -> None:
        """Initialize the flow."""
        self._reauth_entry: ConfigEntry | None = None

    async def _async_validate_and_extract_meter(
        self, okta_cookies: str, portal_cookies: str
    ) -> tuple[dict[str, str], PsegClient | None, str | None]:
        """Validate credentials and extract the meter ID."""
        errors: dict[str, str] = {}
        client = PsegClient(okta_cookies=okta_cookies, portal_cookies=portal_cookies)
        meter_id = None

        try:
            await self.hass.async_add_executor_job(client.ensure_session)
        except PsegOktaSessionExpired:
            errors["base"] = "okta_session_invalid"
            return errors, None, None
        except (PsegTransientError, requests.RequestException):
            errors["base"] = "cannot_connect"
            return errors, None, None
        except Exception as err:
            _LOGGER.exception("Unexpected error validating session: %s", err)
            errors["base"] = "unknown"
            return errors, None, None

        try:
            data = await self.hass.async_add_executor_job(client.fetch_energy_data, 1)
            meter_str = str(data.get("meter") or "")
            match = re.search(r"\d+", meter_str)
            if match:
                meter_id = match.group(0)
            else:
                meter_id = re.sub(r"[^a-z0-9_]+", "_", meter_str.lower()).strip("_")
        except Exception as err:
            _LOGGER.debug("Could not determine meter id during config flow: %s", err)

        if not meter_id:
            meter_id = "electric_meter"

        return errors, client, meter_id

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 1: Enter Okta and optional portal cookies."""
        errors: dict[str, str] = {}

        if user_input is not None:
            okta_cookies = user_input.get(CONF_OKTA_COOKIES, "").strip()
            portal_cookies = user_input.get(CONF_PORTAL_COOKIES, "").strip()

            if not okta_cookies:
                errors["base"] = "missing_credentials"
            else:
                errors, client, meter_id = await self._async_validate_and_extract_meter(
                    okta_cookies, portal_cookies
                )
                if not errors and client and meter_id:
                    await self.async_set_unique_id(meter_id)
                    self._abort_if_unique_id_configured()

                    return self.async_create_entry(
                        title=f"PSE&G ({meter_id})",
                        data={
                            CONF_OKTA_COOKIES: okta_cookies,
                            CONF_PORTAL_COOKIES: portal_cookies,
                            CONF_METER_ID: meter_id,
                            "cookies": client.export_cookies(),
                        },
                    )

        schema = vol.Schema(
            {
                vol.Required(CONF_OKTA_COOKIES): str,
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
        """Confirm re-authentication with fresh session cookies."""
        errors: dict[str, str] = {}

        if user_input is not None and self._reauth_entry:
            okta_cookies = user_input.get(CONF_OKTA_COOKIES, "").strip()
            portal_cookies = user_input.get(CONF_PORTAL_COOKIES, "").strip()

            if not okta_cookies:
                errors["base"] = "missing_credentials"
            else:
                errors, client, meter_id = await self._async_validate_and_extract_meter(
                    okta_cookies, portal_cookies
                )
                if not errors and client and meter_id:
                    if self._reauth_entry.unique_id and self._reauth_entry.unique_id != meter_id:
                        return self.async_abort(reason="reauth_account_mismatch")

                    return self.async_update_reload_and_abort(
                        self._reauth_entry,
                        data={
                            **self._reauth_entry.data,
                            CONF_OKTA_COOKIES: okta_cookies,
                            CONF_PORTAL_COOKIES: portal_cookies,
                            "cookies": client.export_cookies(),
                        },
                    )

        schema = vol.Schema(
            {
                vol.Required(CONF_OKTA_COOKIES): str,
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
            portal_cookies = user_input.get(CONF_PORTAL_COOKIES, "").strip()

            if not okta_cookies:
                errors["base"] = "missing_credentials"
            else:
                errors, client, meter_id = await self._async_validate_and_extract_meter(
                    okta_cookies, portal_cookies
                )
                if not errors and client and meter_id:
                    if reconfigure_entry.unique_id and reconfigure_entry.unique_id != meter_id:
                        return self.async_abort(reason="reauth_account_mismatch")

                    return self.async_update_reload_and_abort(
                        reconfigure_entry,
                        data={
                            **reconfigure_entry.data,
                            CONF_OKTA_COOKIES: okta_cookies,
                            CONF_PORTAL_COOKIES: portal_cookies,
                            "cookies": client.export_cookies(),
                        },
                    )

        schema = vol.Schema(
            {
                vol.Required(CONF_OKTA_COOKIES): str,
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


class PsegOptionsFlowHandler(OptionsFlow):
    """Handle options flow for PSE&G Energy."""

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

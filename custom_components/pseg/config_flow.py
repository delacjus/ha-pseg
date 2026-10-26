"""Config flow for the PSE&G Energy integration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import hashlib
import logging
import re
import time
from typing import Any

from homeassistant import config_entries
from homeassistant.config_entries import (
    SOURCE_IGNORE,
    ConfigEntry,
    ConfigEntryState,
    ConfigFlowResult,
    OptionsFlow,
    OptionsFlowWithReload,
)
from homeassistant.core import CALLBACK_TYPE, callback
from homeassistant.data_entry_flow import UnknownFlow
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
import requests
import voluptuous as vol

from .captcha_helper import HELPER_URL_PATH, async_ensure_helper_view
from .const import (
    CAPTCHA_ATTEMPT_TTL_SECONDS,
    CONF_CAPTCHA_CANCEL,
    CONF_CAPTCHA_RESPONSE,
    CONF_KNOWN_METER_IDS,
    CONF_METER_ID,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_OKTA_COOKIES,
    CONF_PORTAL_COOKIES,
    CONF_PRICE_PER_KWH,
    CONF_RENEWAL_ADMISSION,
    CONF_STATISTICS_IMPORT_ENABLED,
    DEFAULT_METER_NAME,
    DEFAULT_PRICE_PER_KWH,
    DEFAULT_STATISTICS_IMPORT_ENABLED,
    DOMAIN,
    PORTAL_BASE_URL,
    REMEMBER_ME_COOKIE,
    parse_price_per_kwh,
    sanitized_price_per_kwh,
)
from .pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegLoginRedirected,
    PsegLoginRejected,
    PsegOktaSessionExpired,
    PsegSecurityStepRequired,
    PsegTransientError,
)
from .renewal_admission import rearm_entry_admission

_LOGGER = logging.getLogger(__name__)

# Internal marker: validation wants the human CAPTCHA step, never shown as an error.
_CAPTCHA_REQUIRED = "captcha_required"
_CAPTCHA_STEP_ID = "captcha"

# Reload only an enabled entry Home Assistant already tried to set up. Reloading an
# enabled NOT_LOADED entry would start it; reloading a disabled entry is needless
# work and can abort a reauth flow even though setup is skipped.
_RELOADABLE_ENTRY_STATES = frozenset(
    {ConfigEntryState.LOADED, ConfigEntryState.SETUP_RETRY, ConfigEntryState.SETUP_ERROR}
)


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


def _credentials_schema() -> vol.Schema:
    """Credentials/cookies form shared by setup, reauth and reconfigure."""
    return vol.Schema(
        {
            vol.Optional(CONF_MYMETER_EMAIL, default=""): str,
            vol.Optional(CONF_MYMETER_PASSWORD, default=""): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
            vol.Optional(CONF_OKTA_COOKIES, default=""): str,
            vol.Optional(CONF_PORTAL_COOKIES, default=""): str,
        }
    )


class PsegConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for PSE&G Energy."""

    VERSION = 2

    def __init__(self) -> None:
        """Initialize the flow."""
        self._reauth_entry: ConfigEntry | None = None
        # Assisted CAPTCHA state: the same client/jar/antiforgery token, in memory
        # only, so the human proof posts to the session that issued the challenge.
        self._captcha_pending: dict[str, Any] | None = None
        # Active Home Assistant timer that drops the pending sign-in when it idles.
        self._captcha_cleanup: CALLBACK_TYPE | None = None
        # The one credential submission allowed to run in this flow, from the first
        # credential request through CAPTCHA preparation or the entry write. A
        # second tab or double submit must never start a second MyMeter login.
        self._sign_in_operation: object | None = None
        # Set by async_remove(): Home Assistant has taken this flow out of progress,
        # so any request still in the executor must never commit or transition it.
        self._flow_removed = False

    @callback
    def async_remove(self) -> None:
        """Drop the pending sign-in when HA removes this flow (cancel/abort/finish)."""
        self._flow_removed = True
        self._clear_captcha_pending()

    async def _async_fetch_meter(
        self, client: PsegClient
    ) -> tuple[dict[str, str], str | None, list[str]]:
        """Read the meter identity from a signed-in client (no second login)."""
        try:
            data = await self.hass.async_add_executor_job(client.fetch_energy_data, 1)
        except PsegOktaSessionExpired:
            _LOGGER.warning("PSE&G cookies rejected at setup: %s", client.auth_diagnostics())
            return {"base": "okta_session_invalid"}, None, []
        except Exception as err:
            _LOGGER.debug("Could not determine meter id during config flow: %s", type(err).__name__)
            return {"base": "cannot_connect"}, None, []

        # The meter id becomes the entry unique_id (the stable statistic key),
        # so a failed lookup must fail the step rather than fall back to a placeholder
        # that every account would share.
        meter_str = str(data.get("meter") or "")
        meter_id = None
        if meter_str and meter_str != DEFAULT_METER_NAME:
            match = re.search(r"\d+", meter_str)
            if match:
                meter_id = match.group(0)
            else:
                meter_id = re.sub(r"[^a-z0-9_]+", "_", meter_str.lower()).strip("_")

        if not meter_id:
            return {"base": "cannot_connect"}, None, []

        meter_ids = list(data.get("meter_ids") or []) if "meter_ids" in data else [meter_id]
        return {}, meter_id, meter_ids

    async def _async_validate_and_extract_meter(
        self, okta_cookies: str, portal_cookies: str, email: str = "", password: str = ""
    ) -> tuple[dict[str, str], PsegClient | None, str | None, list[str]]:
        """Validate credentials; return the active meter id and every meter id on the account."""
        client = PsegClient(
            okta_cookies=okta_cookies, portal_cookies=portal_cookies, email=email, password=password
        )
        # A human sign-in may name the account's meter from the authenticated
        # payload's `Meter #N` labels when this window's usage is not published yet
        # (vendor lag). The read never confirms cookies or publishes readings, and
        # only this unattached interactive client may use it.
        client.enable_label_identity_discovery()

        if client.has_login:
            # The saved login is the strongest proof and one sign-in is enough: this
            # replaces the old ensure_session-then-login_local double sign-in. A
            # CAPTCHA refusal hands the same client to the human step below.
            try:
                await self.hass.async_add_executor_job(client.login_local)
            except PsegCaptchaRequired:
                _LOGGER.info("MyMeter wants a CAPTCHA for this sign-in; asking the user")
                return {"base": _CAPTCHA_REQUIRED}, client, None, []
            except PsegSecurityStepRequired:
                _LOGGER.warning(
                    "MyMeter asked for a security step at setup: %s", client.auth_diagnostics()
                )
                return {"base": "security_step_unsupported"}, None, None, []
            except PsegLoginRedirected:
                _LOGGER.warning(
                    "PSE&G redirected the MyMeter login away from the portal; "
                    "local sign-in stays on the portal"
                )
                return {"base": "login_redirected"}, None, None, []
            except PsegLoginRejected:
                _LOGGER.warning(
                    "PSE&G MyMeter login rejected at setup: %s", client.auth_diagnostics()
                )
                return {"base": "login_failed"}, None, None, []
            except (PsegTransientError, requests.RequestException):
                return {"base": "cannot_connect"}, None, None, []
            except Exception as err:
                _LOGGER.exception("Unexpected error signing in to MyMeter: %s", err)
                return {"base": "unknown"}, None, None, []
            renewal_client = client
            renewed = True
            no_session_error = "login_failed"
        else:
            try:
                if not client.has_remember_me:
                    await self.hass.async_add_executor_job(client.ensure_session)
                # A fresh human cookie flow has no saved meter identity yet. Its
                # existing forced renewal + meter extraction below is the proof;
                # do not send it through the entry's admitted polling path first.
            except PsegLoginRejected:
                _LOGGER.warning("PSE&G MyMeter login rejected at setup: %s", client.auth_diagnostics())
                return {"base": "login_failed"}, None, None, []
            except PsegOktaSessionExpired:
                _LOGGER.warning("PSE&G cookies rejected at setup: %s", client.auth_diagnostics())
                return {"base": "okta_session_invalid"}, None, None, []
            except (PsegTransientError, requests.RequestException):
                return {"base": "cannot_connect"}, None, None, []
            except Exception as err:
                _LOGGER.exception("Unexpected error validating session: %s", err)
                return {"base": "unknown"}, None, None, []

            # A live MM_SID can mask cookies that cannot renew. Prove renewal on a fresh
            # throwaway client: via MyMeter Remember Me when the portal header carries
            # it (PSE&G's Okta session dies ~1 h after login), else via Okta SSO.
            if client.has_remember_me:
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
                _LOGGER.warning(
                    "PSE&G renewal check failed at setup: %s", renewal_client.auth_diagnostics()
                )
                return {"base": no_session_error}, None, None, []
            except (PsegTransientError, requests.RequestException):
                return {"base": "cannot_connect"}, None, None, []
            except Exception as err:
                _LOGGER.exception("Unexpected error validating Okta renewal: %s", err)
                return {"base": "unknown"}, None, None, []

        if not renewed or renewal_client.sso_renewals < 1:
            return {"base": no_session_error}, None, None, []

        errors, meter_id, meter_ids = await self._async_fetch_meter(client)
        if errors:
            return errors, None, None, []
        return {}, client, meter_id, meter_ids

    async def _async_begin_captcha(
        self,
        step_id: str,
        client: PsegClient,
        entry: ConfigEntry | None,
        okta_cookies: str,
        portal_cookies: str,
        email: str,
        password: str,
    ) -> str | None:
        """Prepare a fresh antiforgery state and hold the pending sign-in in memory.

        Returns an error key for the sign-in form, or None when the CAPTCHA form can
        be shown. The pending client/credentials live only in this flow's memory and
        are dropped on abort, cancellation, completion or the idle timer.
        """
        await async_ensure_helper_view(self.hass)
        try:
            await self.hass.async_add_executor_job(client.prepare_login_captcha)
        except (PsegLoginRejected, PsegTransientError, requests.RequestException):
            return "cannot_connect"
        except Exception as err:
            _LOGGER.exception(
                "Could not prepare the MyMeter CAPTCHA sign-in: %s", type(err).__name__
            )
            return "unknown"

        if self._flow_removed:
            # Aborted while the login form was loading: hold nothing.
            return "sign_in_cancelled"

        if self._captcha_pending is not None:
            # Only an idle pending sign-in can be replaced (an in-flight attempt is
            # refused before this point); cancel its timer so no timer is orphaned.
            self._clear_captcha_pending()

        self._captcha_pending = {
            "step_id": step_id,
            "entry": entry,
            "client": client,
            "okta_cookies": okta_cookies,
            "portal_cookies": portal_cookies,
            "email": email,
            "password": password,
            # The pending window starts now and is not extended by a new challenge.
            "prepared_at": time.monotonic(),
            "used_proofs": set(),
            "in_flight": False,
            "attempt": None,
            "cancelled": False,
            "expired": False,
        }
        self._captcha_cleanup = async_call_later(
            self.hass, CAPTCHA_ATTEMPT_TTL_SECONDS, self._async_captcha_expired
        )
        return None

    @callback
    def _clear_captcha_pending(self) -> None:
        """Drop the pending sign-in, its timer and any challenge state from memory."""
        if self._captcha_cleanup is not None:
            self._captcha_cleanup()
            self._captcha_cleanup = None
        pending = self._captcha_pending
        if pending is not None:
            # A request may still be in the executor: mark it so every post-await
            # guard sees that this attempt must not commit anything.
            pending["cancelled"] = True
        self._captcha_pending = None

    def _attempt_expired(self, pending: dict[str, Any]) -> bool:
        """True when the prepared sign-in idled past the pending-window limit."""
        return (
            time.monotonic() - pending["prepared_at"] > CAPTCHA_ATTEMPT_TTL_SECONDS
        )

    @callback
    def _async_captcha_expired(self, _now: datetime) -> None:
        """Timer: drop an idle pending sign-in, or mark an in-flight one to abort."""
        self._captcha_cleanup = None
        pending = self._captcha_pending
        if pending is None:
            return
        if pending["in_flight"]:
            # An executor job still holds this client (and its jar/credentials).
            # Let it come back and abort through the post-await guard instead of
            # pulling state out from under a running request.
            pending["expired"] = True
            _LOGGER.debug("A pending PSE&G CAPTCHA sign-in expired during a request")
            return
        _LOGGER.info(
            "Dropped a pending PSE&G CAPTCHA sign-in after %s seconds without a proof",
            CAPTCHA_ATTEMPT_TTL_SECONDS,
        )
        self._clear_captcha_pending()
        self._async_abort_flow("captcha_expired")

    @callback
    def _async_abort_flow(self, reason: str) -> None:
        """Abort this flow from outside a step (the pending-window timer)."""
        try:
            self.hass.config_entries.flow.async_abort(self.flow_id)
        except UnknownFlow:
            pass

    def _async_removed_result(self) -> ConfigFlowResult | None:
        """Return an abort result if HA already removed this flow, else None."""
        if not self._flow_removed:
            return None
        self._clear_captcha_pending()
        return self.async_abort(reason="sign_in_cancelled")

    def _async_begin_sign_in(self) -> object | None:
        """Take this flow's one sign-in operation, or None if one is running."""
        if self._flow_removed or self._sign_in_operation is not None:
            return None
        pending = self._captcha_pending
        if pending is not None and (pending["in_flight"] or pending["attempt"] is not None):
            # A proof POST and its meter read own that client: never drop them.
            return None
        operation: object = object()
        self._sign_in_operation = operation
        return operation

    def _end_sign_in(self, operation: object) -> None:
        """Release the sign-in operation, but only for the operation that owns it."""
        if self._sign_in_operation is operation:
            self._sign_in_operation = None

    def _async_sign_in_stopped(self, operation: object) -> ConfigFlowResult | None:
        """Return an abort result when this sign-in may no longer commit."""
        if self._flow_removed:
            return self._async_removed_result()
        if self._sign_in_operation is not operation:
            return self.async_abort(reason="sign_in_cancelled")
        return None

    def _attempt_lost(self, pending: dict[str, Any]) -> bool:
        """True when this attempt was cancelled, expired or removed while awaiting."""
        return (
            self._flow_removed
            or self._captcha_pending is not pending
            or pending["cancelled"]
            or pending["expired"]
        )

    def _async_abort_lost_attempt(
        self, pending: dict[str, Any]
    ) -> ConfigFlowResult:
        """Finish a step whose attempt was cancelled/expired without committing."""
        expired = bool(pending["expired"])
        self._clear_captcha_pending()
        return self.async_abort(
            reason="captcha_expired" if expired else "sign_in_cancelled"
        )

    def _release_attempt(self, pending: dict[str, Any], attempt: object) -> None:
        """Release the exclusive attempt guard, but only for the attempt that owns it."""
        if self._captcha_pending is pending and pending["attempt"] is attempt:
            pending["attempt"] = None
            pending["in_flight"] = False

    def _helper_url(self) -> str:
        base = self.hass.config.internal_url or self.hass.config.external_url
        if not base:
            return HELPER_URL_PATH
        return f"{base.rstrip('/')}{HELPER_URL_PATH}"

    def _async_show_captcha_form(self, errors: dict[str, str]) -> ConfigFlowResult:
        return self.async_show_form(
            step_id=_CAPTCHA_STEP_ID,
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_CAPTCHA_RESPONSE, default=""): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    ),
                    vol.Optional(CONF_CAPTCHA_CANCEL, default=False): bool,
                }
            ),
            errors=errors,
            description_placeholders={
                "helper_url": self._helper_url(),
                # hassfest rejects URLs inside translation strings.
                "chrome_extensions_url": "chrome://extensions",
                "edge_extensions_url": "edge://extensions",
                "portal_url": PORTAL_BASE_URL,
            },
        )

    def _async_show_credentials_form(
        self, step_id: str, error: str
    ) -> ConfigFlowResult:
        return self.async_show_form(
            step_id=step_id,
            data_schema=_credentials_schema(),
            errors={"base": error},
        )

    async def _async_refresh_captcha_challenge(self, pending: dict[str, Any]) -> bool:
        """Fetch a fresh antiforgery token for another attempt on the same jar."""
        try:
            await self.hass.async_add_executor_job(pending["client"].prepare_login_captcha)
        except Exception as err:
            _LOGGER.debug("Could not refresh the MyMeter login form: %s", type(err).__name__)
            return False
        # A new server challenge, but the pending window still runs from the original
        # preparation: refreshing never extends how long the sign-in is kept.
        return True

    async def async_step_captcha(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask the user for one human-solved CAPTCHA proof captured by the helper."""
        pending = self._captcha_pending
        if pending is None:
            return self.async_abort(reason="captcha_not_pending")

        step_id: str = pending["step_id"]

        if user_input is None:
            if self._attempt_expired(pending):
                self._clear_captcha_pending()
                return self.async_abort(reason="captcha_expired")
            return self._async_show_captcha_form({})

        if user_input.get(CONF_CAPTCHA_CANCEL):
            # Cancelling wins even while a request is in flight: the running
            # attempt sees the cancelled marker and cannot commit.
            self._clear_captcha_pending()
            return self.async_abort(reason="captcha_cancelled")

        proof = str(user_input.get(CONF_CAPTCHA_RESPONSE) or "").strip()
        if not proof:
            return self._async_show_captcha_form({"base": "captcha_response_required"})

        if self._attempt_expired(pending):
            self._clear_captcha_pending()
            return self.async_abort(reason="captcha_expired")

        # Compare digests so a spent proof is never kept (or logged) verbatim.
        digest = hashlib.sha256(proof.encode("utf-8")).hexdigest()
        if digest in pending["used_proofs"]:
            return self._async_show_captcha_form({"base": "captcha_proof_used"})
        if pending["in_flight"]:
            return self._async_show_captcha_form({"base": "captcha_busy"})

        # One attempt owns this client from the proof submit through the meter read
        # and the entry update: a second submission (another tab, a double click)
        # is refused instead of posting a second login on the same pending sign-in.
        # The guard is released only by the attempt that took it.
        attempt = pending["attempt"] = object()
        pending["in_flight"] = True
        # Mark it spent before the request: a proof that reached PSE&G is gone even
        # if the reply is lost, so it is never resent and never reused.
        pending["used_proofs"].add(digest)
        client: PsegClient = pending["client"]
        try:
            try:
                await self.hass.async_add_executor_job(
                    client.submit_login_captcha, proof
                )
            except PsegCaptchaRequired:
                if self._attempt_lost(pending):
                    return self._async_abort_lost_attempt(pending)
                if not await self._async_refresh_captcha_challenge(pending):
                    if self._attempt_lost(pending):
                        return self._async_abort_lost_attempt(pending)
                    return self._async_show_captcha_form({"base": "cannot_connect"})
                if self._attempt_lost(pending):
                    return self._async_abort_lost_attempt(pending)
                return self._async_show_captcha_form({"base": "captcha_rejected"})
            except PsegSecurityStepRequired:
                if self._attempt_lost(pending):
                    return self._async_abort_lost_attempt(pending)
                self._clear_captcha_pending()
                return self._async_show_credentials_form(
                    step_id, "security_step_unsupported"
                )
            except PsegLoginRedirected:
                if self._attempt_lost(pending):
                    return self._async_abort_lost_attempt(pending)
                self._clear_captcha_pending()
                return self._async_show_credentials_form(step_id, "login_redirected")
            except PsegLoginRejected:
                if self._attempt_lost(pending):
                    return self._async_abort_lost_attempt(pending)
                self._clear_captcha_pending()
                return self._async_show_credentials_form(step_id, "login_failed")
            except (PsegTransientError, requests.RequestException):
                # The proof may already be spent server-side: keep the same sign-in but
                # require a fresh proof, never an automatic resend.
                if self._attempt_lost(pending):
                    return self._async_abort_lost_attempt(pending)
                return self._async_show_captcha_form({"base": "cannot_connect"})
            except Exception as err:
                _LOGGER.exception(
                    "Unexpected error submitting the CAPTCHA proof: %s", type(err).__name__
                )
                if self._attempt_lost(pending):
                    return self._async_abort_lost_attempt(pending)
                self._clear_captcha_pending()
                return self._async_show_credentials_form(step_id, "unknown")

            # The proof was spent and MyMeter issued this session.
            if self._attempt_lost(pending):
                return self._async_abort_lost_attempt(pending)
            errors, meter_id, meter_ids = await self._async_fetch_meter(client)
            if self._attempt_lost(pending):
                return self._async_abort_lost_attempt(pending)
            if errors or not meter_id:
                self._clear_captcha_pending()
                return self._async_show_credentials_form(
                    step_id, errors.get("base", "cannot_connect")
                )
            return await self._async_finish_captcha(
                pending, client, meter_id, meter_ids
            )
        finally:
            self._release_attempt(pending, attempt)

    @callback
    def _entries_claiming(self, meter_ids: set[str]) -> list[ConfigEntry]:
        """Return every PSE&G entry whose stored identity intersects these meter ids.

        Ignored entries are included here on purpose: they must still block a duplicate,
        exactly as the old explicit overlap check did.
        """
        return [
            other
            for other in self.hass.config_entries.async_entries(DOMAIN)
            if meter_ids & _known_meter_ids(other)
        ]

    @callback
    def _async_update_existing_login(
        self,
        entry: ConfigEntry,
        fields: dict[str, Any],
        meter_ids: set[str],
    ) -> ConfigFlowResult:
        """Refresh one existing entry's saved sign-in instead of adding a duplicate.

        Only entry data changes: unique_id (the statistics key), title, options,
        disabled_by and the registries stay as they are. A disabled entry is updated
        without scheduling a needless reload. An enabled entry that
        HA already set up (loaded/retry/error) is reloaded once so the new session is
        used immediately.
        """
        changed = self.hass.config_entries.async_update_entry(
            entry,
            data={
                **entry.data,
                **fields,
                CONF_KNOWN_METER_IDS: sorted(_known_meter_ids(entry).union(meter_ids)),
            },
        )
        _LOGGER.info("Updated the saved sign-in of an existing PSE&G entry")
        if changed and not entry.disabled_by and entry.state in _RELOADABLE_ENTRY_STATES:
            self.hass.config_entries.async_schedule_reload(entry.entry_id)
        return self.async_abort(reason="login_updated_existing")

    async def _async_commit_sign_in(
        self,
        *,
        entry: ConfigEntry | None,
        fields: dict[str, Any],
        meter_id: str,
        meter_ids: list[str],
        local_login: bool,
        stopped: Callable[[], ConfigFlowResult | None],
    ) -> ConfigFlowResult:
        """Write a proven sign-in: update the owning entry or create a new one.

        `stopped` returns an abort result when this attempt may no longer commit; it is
        checked after every await so an aborted flow never touches an entry.
        """
        fields = dict(fields)
        if entry is not None:
            # A completed human sign-in starts a fresh renewal generation; the
            # cross-generation 15-minute clock is preserved in the shared runtime.
            known = _known_meter_ids(entry)
            if meter_ids and known.isdisjoint(meter_ids):
                return self.async_abort(reason="reauth_account_mismatch")
            fields[CONF_RENEWAL_ADMISSION] = rearm_entry_admission(
                self.hass, entry.entry_id, entry.data.get(CONF_RENEWAL_ADMISSION),
                CONF_RENEWAL_ADMISSION in entry.data,
            )
            return self.async_update_reload_and_abort(
                entry,
                data={
                    **entry.data,
                    **fields,
                    CONF_KNOWN_METER_IDS: sorted(known.union(meter_ids)),
                },
            )

        # A local email/password sign-in already proved this account works. If exactly
        # one existing entry owns a meter on it, that entry IS this account: refresh it
        # instead of discarding the proven session with an "already configured" abort.
        authenticated = {meter_id, *meter_ids}
        matches = self._entries_claiming(authenticated)
        if local_login and len(matches) == 1 and matches[0].source != SOURCE_IGNORE:
            target = matches[0]
            fields[CONF_RENEWAL_ADMISSION] = rearm_entry_admission(
                self.hass, target.entry_id, target.data.get(CONF_RENEWAL_ADMISSION),
                CONF_RENEWAL_ADMISSION in target.data,
            )
            return self._async_update_existing_login(target, fields, authenticated)

        await self.async_set_unique_id(meter_id)
        # async_set_unique_id can abort other flows and yields: re-check that this
        # attempt is still live, and re-read the entries, before creating anything.
        stopped_result = stopped()
        if stopped_result is not None:
            return stopped_result
        self._abort_if_unique_id_configured()
        if matches or self._entries_claiming(authenticated):
            # Two matches, an ignored entry, or a cookie/Okta-only duplicate keeps the
            # old behavior: never guess which entry is meant and never create a second.
            return self.async_abort(reason="already_configured")
        return self.async_create_entry(
            title=f"PSE&G ({meter_id})",
            data={**fields, CONF_METER_ID: meter_id, CONF_KNOWN_METER_IDS: meter_ids},
        )

    async def _async_finish_captcha(
        self,
        pending: dict[str, Any],
        client: PsegClient,
        meter_id: str,
        meter_ids: list[str],
    ) -> ConfigFlowResult:
        """Create or update the entry from a CAPTCHA-assisted sign-in."""
        if self._attempt_lost(pending):
            return self._async_abort_lost_attempt(pending)

        fields = {
            CONF_OKTA_COOKIES: pending["okta_cookies"],
            CONF_PORTAL_COOKIES: pending["portal_cookies"],
            CONF_MYMETER_EMAIL: pending["email"],
            CONF_MYMETER_PASSWORD: pending["password"],
            "cookies": client.export_cookies(),
        }
        return await self._async_commit_sign_in(
            entry=pending["entry"],
            fields=fields,
            meter_id=meter_id,
            meter_ids=meter_ids,
            local_login=client.has_login,
            stopped=lambda: (
                self._async_abort_lost_attempt(pending)
                if self._attempt_lost(pending)
                else None
            ),
        )

    async def _async_guarded_sign_in(
        self,
        step_id: str,
        entry: ConfigEntry | None,
        okta_cookies: str,
        portal_cookies: str,
        email: str,
        password: str,
    ) -> ConfigFlowResult:
        """Run one credential submission as this flow's only sign-in.

        The guard is taken before the first credential request, so a second tab, a
        double submit or a late completion cannot start a second MyMeter login,
        replace the pending CAPTCHA client/timer, or commit over it. It is held
        through CAPTCHA preparation and the entry write, then released so the human
        CAPTCHA step continues from the same pending sign-in without a second login.
        """
        removed = self._async_removed_result()
        if removed is not None:
            return removed
        operation = self._async_begin_sign_in()
        if operation is None:
            # Another submission in this flow is still signing in; refuse instead of
            # clearing its pending client/timer or posting a second login.
            return self._async_show_credentials_form(step_id, "sign_in_busy")
        try:
            # Safe here: only an idle pending sign-in can be replaced.
            self._clear_captcha_pending()
            errors, client, meter_id, meter_ids = await self._async_validate_and_extract_meter(
                okta_cookies, portal_cookies, email, password
            )
            # Every await above may have outlived an abort; check before any commit.
            stopped = self._async_sign_in_stopped(operation)
            if stopped is not None:
                return stopped

            if client is not None and errors.get("base") == _CAPTCHA_REQUIRED:
                captcha_error = await self._async_begin_captcha(
                    step_id, client, entry, okta_cookies, portal_cookies, email, password
                )
                stopped = self._async_sign_in_stopped(operation)
                if stopped is not None:
                    return stopped
                if captcha_error is None:
                    return await self.async_step_captcha()
                errors["base"] = captcha_error

            if not errors and client and meter_id:
                fields = {
                    CONF_OKTA_COOKIES: okta_cookies,
                    CONF_PORTAL_COOKIES: portal_cookies,
                    CONF_MYMETER_EMAIL: email,
                    CONF_MYMETER_PASSWORD: password,
                    "cookies": client.export_cookies(),
                }
                return await self._async_commit_sign_in(
                    entry=entry,
                    fields=fields,
                    meter_id=meter_id,
                    meter_ids=meter_ids,
                    local_login=client.has_login,
                    stopped=lambda: self._async_sign_in_stopped(operation),
                )
        finally:
            self._end_sign_in(operation)

        return self.async_show_form(
            step_id=step_id,
            data_schema=_credentials_schema(),
            errors=errors,
        )

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
                return await self._async_guarded_sign_in(
                    "user", None, okta_cookies, portal_cookies, email, password
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_credentials_schema(),
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
                return await self._async_guarded_sign_in(
                    "reauth_confirm",
                    self._reauth_entry,
                    okta_cookies,
                    portal_cookies,
                    email,
                    password,
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=_credentials_schema(),
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
                return await self._async_guarded_sign_in(
                    "reconfigure",
                    reconfigure_entry,
                    okta_cookies,
                    portal_cookies,
                    email,
                    password,
                )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_credentials_schema(),
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
        errors: dict[str, str] = {}
        if user_input is not None:
            price = parse_price_per_kwh(user_input.get(CONF_PRICE_PER_KWH, DEFAULT_PRICE_PER_KWH))
            if price is None:
                errors[CONF_PRICE_PER_KWH] = "invalid_price"
            else:
                return self.async_create_entry(
                    title="", data={**user_input, CONF_PRICE_PER_KWH: price}
                )

        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_PRICE_PER_KWH,
                    # Never prefill an unusable saved rate; the shared rule decides
                    # what the form may keep. A form default is not a rate in use, so
                    # this read stays silent (setup already warned once).
                    default=sanitized_price_per_kwh(
                        self.config_entry.options.get(CONF_PRICE_PER_KWH, DEFAULT_PRICE_PER_KWH),
                        warn=False,
                    ),
                ): vol.All(vol.Coerce(float), vol.Range(min=0)),
                vol.Optional(
                    CONF_STATISTICS_IMPORT_ENABLED,
                    default=self.config_entry.options.get(
                        CONF_STATISTICS_IMPORT_ENABLED,
                        DEFAULT_STATISTICS_IMPORT_ENABLED,
                    ),
                ): bool,
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)

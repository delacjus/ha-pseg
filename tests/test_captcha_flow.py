"""Config-flow tests for the human CAPTCHA step (setup, reauth, reconfigure)."""

import asyncio
from datetime import timedelta
import json
import threading
import urllib.parse

from homeassistant.config_entries import (
    SOURCE_USER,
    ConfigEntryDisabler,
    ConfigEntryState,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.util import dt as dt_util
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)
import requests_mock

from custom_components.pseg.captcha_helper import HELPER_URL_PATH
from custom_components.pseg.const import (
    CAPTCHA_ATTEMPT_TTL_SECONDS,
    CONF_CAPTCHA_CANCEL,
    CONF_CAPTCHA_RESPONSE,
    CONF_KNOWN_METER_IDS,
    CONF_MYMETER_EMAIL,
    CONF_MYMETER_PASSWORD,
    CONF_PRICE_PER_KWH,
    DOMAIN,
    PORTAL_BASE_URL,
)
from custom_components.pseg.pseg_client import (
    PsegCaptchaRequired,
    PsegClient,
    PsegLoginRejected,
    PsegSecurityStepRequired,
    PsegTransientError,
)

PROOF = "flow-proof-77aa-once"
EMAIL = "me@example.com"
PASSWORD = "synthetic-password"


def _raise_captcha(client: PsegClient) -> bool:
    raise PsegCaptchaRequired("MyMeter requires a solved CAPTCHA")


def _fetch_meter(client: PsegClient, days: int) -> dict:
    meter = {"a@example.com": "11111111", "b@example.com": "22222222"}.get(
        client._email, "12345678"
    )
    return {"meter": f"Meter {meter}", "meter_ids": [meter], "history_14d": []}


class _ProofRecorder:
    """Record prepared clients and submitted proofs; fail the first N proofs."""

    def __init__(self, failures: tuple[Exception, ...] = ()) -> None:
        self.clients: list[PsegClient] = []
        self.proofs: list[str] = []
        self.failures = list(failures)


def _prepare_fn(recorder: _ProofRecorder):
    def prepare(client: PsegClient) -> None:
        recorder.clients.append(client)

    return prepare


def _submit_fn(recorder: _ProofRecorder):
    def submit(client: PsegClient, proof: str) -> bool:
        recorder.proofs.append(proof)
        if recorder.failures:
            raise recorder.failures.pop(0)
        client.sso_renewals = 1
        return True

    return submit


def _entry(hass: HomeAssistant, **kwargs) -> MockConfigEntry:
    data = kwargs.pop("data", None) or {
        CONF_MYMETER_EMAIL: EMAIL,
        CONF_MYMETER_PASSWORD: PASSWORD,
        CONF_KNOWN_METER_IDS: ["12345678"],
    }
    entry = MockConfigEntry(
        domain=DOMAIN, version=2, unique_id="12345678", data=data, **kwargs
    )
    entry.add_to_hass(hass)
    return entry


async def _configure(hass: HomeAssistant, flow_id: str, user_input: dict):
    return await hass.config_entries.flow.async_configure(flow_id, user_input=user_input)


_CREDENTIAL_STEP = {"user": "user", "reauth": "reauth_confirm", "reconfigure": "reconfigure"}


async def _begin_entry_flow(hass: HomeAssistant, start: str):
    """Start setup, reauth or reconfigure; return (entry, credential form)."""
    entry = None
    if start == "user":
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
    else:
        entry = _entry(hass)
        if start == "reauth":
            result = await entry.start_reauth_flow(hass)
        else:
            result = await hass.config_entries.flow.async_init(
                DOMAIN, context={"source": "reconfigure", "entry_id": entry.entry_id}
            )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == _CREDENTIAL_STEP[start]
    return entry, result


def _credential_input(start: str) -> dict:
    """Typed login for setup; blank reuses the stored login for reauth/reconfigure."""
    if start == "user":
        return {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD}
    return {}


def _login_raises_captcha(logins: list[PsegClient]):
    """Record each MyMeter login and answer with a CAPTCHA demand."""

    def login(client: PsegClient) -> bool:
        logins.append(client)
        raise PsegCaptchaRequired("MyMeter requires a solved CAPTCHA")

    return login


class _Blocker:
    """Hold one executor call so the test can abort/overlap the flow for real."""

    def __init__(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.release = threading.Event()
        self.entered = asyncio.Event()
        self.calls = 0

    def enter(self) -> None:
        """Called from the executor thread: signal the test, then wait for it."""
        self.calls += 1
        self.loop.call_soon_threadsafe(self.entered.set)
        assert self.release.wait(timeout=5), "the blocked call was never released"

    def wrap(self, fn):
        def wrapper(*args, **kwargs):
            self.enter()
            return fn(*args, **kwargs)

        return wrapper


def _flow_object(hass: HomeAssistant, flow_id: str):
    """Return the live flow handler; the manager only exposes progress dicts."""
    return hass.config_entries.flow._progress[flow_id]


def _holds_client(flow, client: PsegClient) -> bool:
    """True when the flow object still references the pending client."""
    return any(value is client for value in vars(flow).values())


@pytest.mark.parametrize(
    ("start", "expected_reason", "expected_step"),
    [
        ("user", None, "captcha"),
        ("reauth", None, "captcha"),
        ("reconfigure", None, "captcha"),
    ],
)
async def test_captcha_step_completes_setup_reauth_and_reconfigure(
    hass: HomeAssistant, start: str, expected_reason, expected_step
) -> None:
    """All three entry paths share the same assisted CAPTCHA step."""
    entry = None
    if start == "reauth":
        entry = _entry(hass)
        result = await entry.start_reauth_flow(hass)
    elif start == "reconfigure":
        entry = _entry(hass)
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "reconfigure", "entry_id": entry.entry_id}
        )
    else:
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
    assert result["type"] == FlowResultType.FORM

    recorder = _ProofRecorder()
    logins: list[PsegClient] = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _login_raises_captcha(logins))
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        if start == "user":
            first = await _configure(
                hass,
                result["flow_id"],
                {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
            )
        else:
            first = await _configure(hass, result["flow_id"], {})

        assert first["type"] == FlowResultType.FORM
        assert first["step_id"] == expected_step
        assert first["errors"] == {}
        assert first["description_placeholders"]["helper_url"].endswith(HELPER_URL_PATH)
        schema_defaults = first["data_schema"]({})
        assert schema_defaults[CONF_CAPTCHA_RESPONSE] == ""
        assert schema_defaults[CONF_CAPTCHA_CANCEL] is False
        assert recorder.clients and recorder.proofs == []
        # One credential submission, one MyMeter login, one paired CAPTCHA prepare.
        assert len(logins) == 1
        assert logins[0] is recorder.clients[0]

        done = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF}
        )

    assert recorder.proofs == [PROOF]
    assert len(logins) == 1
    if entry is None:
        assert done["type"] == FlowResultType.CREATE_ENTRY
    else:
        assert done["type"] == FlowResultType.ABORT
    if entry is None:
        assert done["result"].unique_id == "12345678"
        assert done["data"][CONF_MYMETER_EMAIL] == EMAIL
        assert done["data"][CONF_MYMETER_PASSWORD] == PASSWORD
        assert CONF_CAPTCHA_RESPONSE not in done["data"]
        assert PROOF not in json.dumps(done["data"])
    else:
        assert done["reason"] == f"{start}_successful"
        assert entry.unique_id == "12345678"
        assert entry.data[CONF_MYMETER_EMAIL] == EMAIL
        assert PROOF not in json.dumps(dict(entry.data))


async def _async_true(*args, **kwargs) -> bool:
    return True


FRESH_EMAIL = "fresh@example.com"
FRESH_PASSWORD = "fresh-synthetic-password"


def _fetch_meter_with_successor(client: PsegClient, days: int) -> dict:
    """Report the account's active meter plus a successor meter."""
    return {
        "meter": "Meter 12345678",
        "meter_ids": ["12345678", "000011112222"],
        "history_14d": [],
    }


async def test_captcha_duplicate_sign_in_updates_existing_entry(hass: HomeAssistant) -> None:
    """A CAPTCHA-completed Add flow refreshes the single entry owning the account."""
    existing = _entry(
        hass,
        disabled_by=ConfigEntryDisabler.USER,
        options={CONF_PRICE_PER_KWH: 0.3},
        data={
            CONF_MYMETER_EMAIL: EMAIL,
            CONF_MYMETER_PASSWORD: PASSWORD,
            CONF_KNOWN_METER_IDS: ["12345678"],
        },
    )
    title = existing.title
    entry_id = existing.entry_id
    reloads: list[str] = []
    recorder = _ProofRecorder()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter_with_successor)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        mp.setattr(hass.config_entries, "async_schedule_reload", reloads.append)
        started = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
        form = await _configure(
            hass,
            started["flow_id"],
            {CONF_MYMETER_EMAIL: FRESH_EMAIL, CONF_MYMETER_PASSWORD: FRESH_PASSWORD},
        )
        assert form["step_id"] == "captcha"
        done = await _configure(hass, form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})

    assert done["type"] == FlowResultType.ABORT
    assert done["reason"] == "login_updated_existing"
    # One entry, same identity: no duplicate and nothing else replaced.
    assert hass.config_entries.async_entries(DOMAIN) == [existing]
    assert existing.entry_id == entry_id
    assert existing.unique_id == "12345678"
    assert existing.title == title
    assert existing.options == {CONF_PRICE_PER_KWH: 0.3}
    assert existing.disabled_by is ConfigEntryDisabler.USER
    assert existing.state is ConfigEntryState.NOT_LOADED
    # The proven local login and the union of account meters are stored.
    assert existing.data[CONF_MYMETER_EMAIL] == FRESH_EMAIL
    assert existing.data[CONF_MYMETER_PASSWORD] == FRESH_PASSWORD
    assert set(existing.data[CONF_KNOWN_METER_IDS]) == {"12345678", "000011112222"}
    assert PROOF not in json.dumps(dict(existing.data))
    # A disabled entry is updated only: no reload (it would set it up).
    assert reloads == []
    assert recorder.proofs == [PROOF]


async def test_captcha_ambiguous_duplicates_are_not_updated(hass: HomeAssistant) -> None:
    """Two entries claim the account: the plain duplicate abort stays, untouched."""
    first = _entry(hass)
    second = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="000011112222",
        data={
            CONF_MYMETER_EMAIL: "other@example.com",
            CONF_MYMETER_PASSWORD: "other-secret",
            CONF_KNOWN_METER_IDS: ["000011112222", "12345678"],
        },
    )
    second.add_to_hass(hass)
    before = (dict(first.data), dict(second.data))
    reloads: list[str] = []
    recorder = _ProofRecorder()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        mp.setattr(hass.config_entries, "async_schedule_reload", reloads.append)
        started = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
        form = await _configure(
            hass,
            started["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        done = await _configure(hass, form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})

    assert done["type"] == FlowResultType.ABORT
    assert done["reason"] == "already_configured"
    assert (dict(first.data), dict(second.data)) == before
    assert reloads == []
    assert len(hass.config_entries.async_entries(DOMAIN)) == 2


async def test_cancel_while_meter_blocked_leaves_existing_entry_unchanged(
    hass: HomeAssistant,
) -> None:
    """Cancelling during the post-proof meter read must not touch a matching entry."""
    existing = _entry(
        hass,
        disabled_by=ConfigEntryDisabler.USER,
        data={
            CONF_MYMETER_EMAIL: EMAIL,
            CONF_MYMETER_PASSWORD: PASSWORD,
            CONF_KNOWN_METER_IDS: ["12345678"],
        },
    )
    before = dict(existing.data)
    blocker = _Blocker()
    recorder = _ProofRecorder()
    reloads: list[str] = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", blocker.wrap(_fetch_meter))
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        mp.setattr(hass.config_entries, "async_schedule_reload", reloads.append)
        started = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
        form = await _configure(
            hass,
            started["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        assert form["step_id"] == "captcha"
        task = hass.async_create_task(
            _configure(hass, form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        cancelled = await _configure(
            hass, form["flow_id"], {CONF_CAPTCHA_CANCEL: True}
        )
        assert cancelled["type"] == FlowResultType.ABORT
        assert cancelled["reason"] == "captcha_cancelled"

        blocker.release.set()
        late = await task
        assert late["type"] == FlowResultType.ABORT
        assert late["reason"] in ("captcha_cancelled", "sign_in_cancelled")

    assert dict(existing.data) == before
    assert reloads == []
    assert hass.config_entries.async_entries(DOMAIN) == [existing]
    assert recorder.proofs == [PROOF]


async def test_reauth_captcha_keeps_disabled_entry_and_known_meters(hass: HomeAssistant) -> None:
    """A CAPTCHA reauth must not enable the entry or drop its identity."""
    entry = _entry(
        hass,
        disabled_by=ConfigEntryDisabler.USER,
        data={
            CONF_MYMETER_EMAIL: EMAIL,
            CONF_MYMETER_PASSWORD: PASSWORD,
            CONF_KNOWN_METER_IDS: ["12345678", "000011112222"],
        },
    )
    result = await entry.start_reauth_flow(hass)
    recorder = _ProofRecorder()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        first = await _configure(hass, result["flow_id"], {})
        assert first["step_id"] == "captcha"
        done = await _configure(hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})

    assert done["reason"] == "reauth_successful"
    assert entry.disabled_by is ConfigEntryDisabler.USER
    assert entry.unique_id == "12345678"
    assert set(entry.data[CONF_KNOWN_METER_IDS]) == {"12345678", "000011112222"}
    assert entry.data[CONF_MYMETER_EMAIL] == EMAIL
    assert entry.data[CONF_MYMETER_PASSWORD] == PASSWORD


async def test_captcha_cancel_aborts_and_creates_nothing(hass: HomeAssistant) -> None:
    """The user can drop the attempt from the CAPTCHA form."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        done = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_CANCEL: True}
        )

    assert done["type"] == FlowResultType.ABORT
    assert done["reason"] == "captcha_cancelled"
    assert hass.config_entries.async_entries(DOMAIN) == []
    assert recorder.proofs == []


async def test_proof_after_two_minutes_still_submits_inside_pending_window(
    hass: HomeAssistant,
) -> None:
    """A proof captured >2 min ago is submitted; only Google can judge its age.

    The old flow rejected anything older than 120 s because it ran the proof's
    lifetime as its own timer. The pending window is ten minutes, so a user who
    waited four minutes but pasted a fresh proof must still sign in.
    """
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        flow = _flow_object(hass, first["flow_id"])
        # Four minutes of human/browser delay: past Google's two-minute response
        # life, well inside the ten-minute pending window.
        flow._captcha_pending["prepared_at"] -= 240
        done = await _configure(hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})

    assert done["type"] == FlowResultType.CREATE_ENTRY
    assert recorder.proofs == [PROOF]
    # Completion drops the pending state and cancels the cleanup timer.
    assert flow._captcha_pending is None
    assert flow._captcha_cleanup is None


async def test_idle_pending_sign_in_is_actively_dropped(
    hass: HomeAssistant,
) -> None:
    """Ten idle minutes clear the jar/credentials and end the flow with no input."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        assert first["step_id"] == "captcha"
        flow = _flow_object(hass, first["flow_id"])
        pending = flow._captcha_pending
        client = pending["client"]
        assert flow._captcha_cleanup is not None

        async_fire_time_changed(
            hass, dt_util.utcnow() + timedelta(seconds=CAPTCHA_ATTEMPT_TTL_SECONDS + 1)
        )

        assert flow._captcha_pending is None
        assert flow._captcha_cleanup is None
        assert flow._flow_removed is True
        assert pending["cancelled"] is True
        assert _holds_client(flow, client) is False
        assert hass.config_entries.flow.async_progress_by_handler(DOMAIN) == []

    assert hass.config_entries.async_entries(DOMAIN) == []
    assert recorder.proofs == []


async def test_abort_while_proof_request_in_flight_never_touches_the_entry(
    hass: HomeAssistant,
) -> None:
    """A real flow-manager abort during the login POST must stop the update.

    Cancelling only cleared the flow's pending dict: the suspended step still
    called async_update_reload_and_abort, so the entry was updated and reloaded
    after the user had already aborted.
    """
    entry = _entry(hass)
    before = dict(entry.data)
    result = await entry.start_reauth_flow(hass)
    recorder = _ProofRecorder()
    blocker = _Blocker()
    reloads: list[str] = []

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(
            PsegClient, "submit_login_captcha", blocker.wrap(_submit_fn(recorder))
        )
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        mp.setattr(hass.config_entries, "async_schedule_reload", reloads.append)

        form = await _configure(hass, result["flow_id"], {})
        assert form["step_id"] == "captcha"
        flow = _flow_object(hass, form["flow_id"])
        pending = flow._captcha_pending
        client = pending["client"]

        task = hass.async_create_task(
            _configure(hass, form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        # The user closes the dialog while the login request is still running.
        hass.config_entries.flow.async_abort(form["flow_id"])
        assert flow._captcha_pending is None
        assert flow._captcha_cleanup is None
        assert pending["cancelled"] is True
        assert _holds_client(flow, client) is False

        blocker.release.set()
        # HA still receives the abort result; nothing is committed either way.
        late = await task
        assert late["type"] == FlowResultType.ABORT
        assert late["reason"] == "sign_in_cancelled"

    assert dict(entry.data) == before
    assert entry.unique_id == "12345678"
    assert reloads == []
    assert hass.config_entries.async_entries(DOMAIN) == [entry]
    assert recorder.proofs == [PROOF]  # one POST, never re-sent


async def test_abort_during_meter_fetch_never_creates_or_updates(
    hass: HomeAssistant,
) -> None:
    """An abort during the post-login meter read must not commit either."""
    entry = _entry(hass)
    before = dict(entry.data)
    result = await entry.start_reauth_flow(hass)
    recorder = _ProofRecorder()
    blocker = _Blocker()
    reloads: list[str] = []

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", blocker.wrap(_fetch_meter))
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        mp.setattr(hass.config_entries, "async_schedule_reload", reloads.append)

        form = await _configure(hass, result["flow_id"], {})
        flow = _flow_object(hass, form["flow_id"])
        task = hass.async_create_task(
            _configure(hass, form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        hass.config_entries.flow.async_abort(form["flow_id"])
        blocker.release.set()
        late = await task
        assert late["type"] == FlowResultType.ABORT
        assert late["reason"] == "sign_in_cancelled"

        assert flow._captcha_pending is None
        assert recorder.proofs == [PROOF]

    assert dict(entry.data) == before
    assert reloads == []
    assert hass.config_entries.async_entries(DOMAIN) == [entry]


async def test_second_submission_is_busy_while_the_meter_read_runs(
    hass: HomeAssistant,
) -> None:
    """The exclusive guard covers the meter read: no second login in one flow."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder()
    blocker = _Blocker()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", blocker.wrap(_fetch_meter))
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)

        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        task = hass.async_create_task(
            _configure(hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: "proof-one"})
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        second = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: "proof-two"}
        )
        assert second["type"] == FlowResultType.FORM
        assert second["step_id"] == "captcha"
        assert second["errors"] == {"base": "captcha_busy"}
        assert recorder.proofs == ["proof-one"]

        blocker.release.set()
        done = await task

    assert done["type"] == FlowResultType.CREATE_ENTRY
    assert recorder.proofs == ["proof-one"]
    assert blocker.calls == 1
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1


async def test_guard_held_through_rejection_refresh_until_that_attempt_ends(
    hass: HomeAssistant,
) -> None:
    """A rejected attempt keeps ownership while it refreshes its challenge."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder(failures=(PsegCaptchaRequired("not accepted"),))
    blocker = _Blocker()
    prepared = 0

    def prepare(client: PsegClient) -> None:
        nonlocal prepared
        prepared += 1
        recorder.clients.append(client)
        if prepared > 1:
            # The refresh after the rejection is where the old guard was already
            # released, letting a second proof post a concurrent login.
            blocker.enter()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", prepare)
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)

        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        task = hass.async_create_task(
            _configure(hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: "proof-one"})
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        second = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: "proof-two"}
        )
        assert second["type"] == FlowResultType.FORM
        assert second["errors"] == {"base": "captcha_busy"}
        assert recorder.proofs == ["proof-one"]

        blocker.release.set()
        rejected = await task
        assert rejected["errors"] == {"base": "captcha_rejected"}

        done = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: "proof-three"}
        )

    assert done["type"] == FlowResultType.CREATE_ENTRY
    assert recorder.proofs == ["proof-one", "proof-three"]


async def test_stale_attempt_cannot_release_a_newer_attempts_guard(
    hass: HomeAssistant,
) -> None:
    """A late finally from attempt N must not clear attempt N+1's busy guard."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        flow = _flow_object(hass, first["flow_id"])
        pending = flow._captcha_pending
        stale_attempt = object()
        current_attempt = object()
        pending["attempt"] = current_attempt
        pending["in_flight"] = True

        flow._release_attempt(pending, stale_attempt)
        assert pending["in_flight"] is True
        assert pending["attempt"] is current_attempt

        flow._release_attempt(pending, current_attempt)
        assert pending["in_flight"] is False
        assert pending["attempt"] is None
        hass.config_entries.flow.async_abort(first["flow_id"])
        assert flow._captcha_cleanup is None


async def test_cancel_while_proof_in_flight_aborts_without_update(
    hass: HomeAssistant,
) -> None:
    """The in-dialog Cancel button wins over a running login request."""
    entry = _entry(hass)
    before = dict(entry.data)
    result = await entry.start_reauth_flow(hass)
    recorder = _ProofRecorder()
    blocker = _Blocker()
    reloads: list[str] = []

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(
            PsegClient, "submit_login_captcha", blocker.wrap(_submit_fn(recorder))
        )
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        mp.setattr(hass.config_entries, "async_schedule_reload", reloads.append)

        form = await _configure(hass, result["flow_id"], {})
        task = hass.async_create_task(
            _configure(hass, form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        cancelled = await _configure(
            hass, form["flow_id"], {CONF_CAPTCHA_CANCEL: True}
        )
        assert cancelled["type"] == FlowResultType.ABORT
        assert cancelled["reason"] == "captcha_cancelled"

        blocker.release.set()
        late = await task
        assert late["type"] == FlowResultType.ABORT
        assert late["reason"] in ("captcha_cancelled", "sign_in_cancelled")

    assert dict(entry.data) == before
    assert reloads == []
    assert recorder.proofs == [PROOF]


async def test_pending_window_expiry_during_meter_read_never_commits(
    hass: HomeAssistant,
) -> None:
    """Expiry while a request is in flight lets the job finish, then aborts."""
    entry = _entry(hass)
    before = dict(entry.data)
    result = await entry.start_reauth_flow(hass)
    recorder = _ProofRecorder()
    blocker = _Blocker()
    reloads: list[str] = []

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", blocker.wrap(_fetch_meter))
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        mp.setattr(hass.config_entries, "async_schedule_reload", reloads.append)

        form = await _configure(hass, result["flow_id"], {})
        flow = _flow_object(hass, form["flow_id"])
        task = hass.async_create_task(
            _configure(hass, form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        async_fire_time_changed(
            hass, dt_util.utcnow() + timedelta(seconds=CAPTCHA_ATTEMPT_TTL_SECONDS + 1)
        )
        # The timer marks the attempt instead of pulling the client out of the job.
        assert flow._captcha_pending is not None
        assert flow._captcha_pending["expired"] is True
        assert flow._captcha_cleanup is None

        blocker.release.set()
        late = await task
        assert late["type"] == FlowResultType.ABORT
        assert late["reason"] == "captcha_expired"

        assert flow._captcha_pending is None
        assert recorder.proofs == [PROOF]

    assert dict(entry.data) == before
    assert reloads == []
    assert hass.config_entries.async_entries(DOMAIN) == [entry]


async def test_captcha_rejection_requires_a_fresh_unused_proof(hass: HomeAssistant) -> None:
    """A refused proof is spent: the same value is blocked, a fresh one is accepted."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder(failures=(PsegCaptchaRequired("not accepted"),))
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        rejected = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF}
        )
        reused = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF}
        )
        done = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: "fresh-proof-88bb"}
        )

    assert rejected["type"] == FlowResultType.FORM
    assert rejected["step_id"] == "captcha"
    assert rejected["errors"] == {"base": "captcha_rejected"}
    assert reused["errors"] == {"base": "captcha_proof_used"}
    assert done["type"] == FlowResultType.CREATE_ENTRY
    assert recorder.proofs == [PROOF, "fresh-proof-88bb"]
    # Rejected proof refreshes the form token only; no automatic resend happened.
    assert len(recorder.clients) == 2


async def test_captcha_network_error_keeps_challenge_but_never_resends(
    hass: HomeAssistant,
) -> None:
    """A lost proof reply may have spent the proof: show an error, send nothing twice."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder(failures=(PsegTransientError("timeout"),))
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        failed = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF}
        )
        retried_same = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF}
        )

        assert failed["type"] == FlowResultType.FORM
        assert failed["step_id"] == "captcha"
        assert failed["errors"] == {"base": "cannot_connect"}
        assert retried_same["errors"] == {"base": "captcha_proof_used"}
        assert recorder.proofs == [PROOF]
        # Drop the pending challenge so no timer outlives the test.
        hass.config_entries.flow.async_abort(first["flow_id"])


@pytest.mark.parametrize(
    ("error", "form_step", "form_error"),
    [
        (PsegSecurityStepRequired("question"), "user", "security_step_unsupported"),
        (PsegLoginRejected("bad password"), "user", "login_failed"),
    ],
)
async def test_captcha_follow_up_errors_never_loop_on_the_captcha_step(
    hass: HomeAssistant, error, form_step: str, form_error: str
) -> None:
    """Invalid credentials or an unsupported security step return to the sign-in form."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    recorder = _ProofRecorder(failures=(error,))
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        first = await _configure(
            hass,
            result["flow_id"],
            {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
        )
        done = await _configure(
            hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF}
        )

    assert done["type"] == FlowResultType.FORM
    assert done["step_id"] == form_step
    assert done["errors"] == {"base": form_error}
    assert hass.config_entries.async_entries(DOMAIN) == []


async def test_concurrent_captcha_flows_keep_their_own_pending_sign_in(
    hass: HomeAssistant,
) -> None:
    """Two open flows each hold their own client/proof; one cannot consume the other."""
    recorder = _ProofRecorder()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)

        flow_a = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
        form_a = await _configure(
            hass, flow_a["flow_id"], {CONF_MYMETER_EMAIL: "a@example.com", CONF_MYMETER_PASSWORD: PASSWORD}
        )
        flow_b = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
        form_b = await _configure(
            hass, flow_b["flow_id"], {CONF_MYMETER_EMAIL: "b@example.com", CONF_MYMETER_PASSWORD: PASSWORD}
        )
        assert form_a["step_id"] == form_b["step_id"] == "captcha"
        assert [c._email for c in recorder.clients] == ["a@example.com", "b@example.com"]
        assert recorder.clients[0] is not recorder.clients[1]

        done_a = await _configure(
            hass, form_a["flow_id"], {CONF_CAPTCHA_RESPONSE: "proof-for-a"}
        )
        # Flow B is untouched: no cross-flow proof reuse or broken challenge.
        done_b = await _configure(
            hass, form_b["flow_id"], {CONF_CAPTCHA_RESPONSE: "proof-for-b"}
        )

    assert done_a["type"] == FlowResultType.CREATE_ENTRY
    assert done_a["result"].unique_id == "11111111"
    assert done_b["type"] == FlowResultType.CREATE_ENTRY
    assert done_b["result"].unique_id == "22222222"
    assert recorder.proofs == ["proof-for-a", "proof-for-b"]


async def test_end_to_end_captcha_sign_in_uses_one_paired_proof(hass: HomeAssistant) -> None:
    """A real PsegClient through the flow: one proof, one sign-in, one meter read.

    requests_mock intercepts the client's own session, so the antiforgery token
    pairing and the proof field are checked on the wire rather than stubbed.
    """
    state = {"token": "", "captcha_posts": 0, "proof_posts": 0}

    def login_page(request, context):
        state["token"] = f"af-token-{state['captcha_posts']}-{state['proof_posts']}"
        return (
            "<html><form>"
            f'<input type="hidden" name="__RequestVerificationToken" value="{state["token"]}">'
            "</form></html>"
        )

    def login_post(request, context):
        body = urllib.parse.parse_qs(request.body or "")
        assert body["__RequestVerificationToken"] == [state["token"]]
        if body.get("g-recaptcha-response"):
            state["proof_posts"] += 1
            return json.dumps({"Data": {"RedirectUrl": "/Dashboard"}})
        state["captcha_posts"] += 1
        return json.dumps(
            {
                "Data": {
                    "LoginErrorMessage": "Please provide a valid login captcha.",
                    "RecaptchaOnLogin": True,
                }
            }
        )

    chart_data = json.dumps(
        {
            "Data": {
                "series": [
                    {
                        "name": "Meter #12345678",
                        "data": [
                            {"hs": {"start": "10/20/2026"}, "y": 12.5, "x": 1},
                        ],
                    }
                ]
            }
        }
    )
    dashboard = (
        '<html><input name="__RequestVerificationToken" value="dashboard-token"></html>'
    )

    with requests_mock.Mocker() as m:
        m.get(f"{PORTAL_BASE_URL}/", text=login_page)
        m.post(f"{PORTAL_BASE_URL}/Home/Login", text=login_post)
        m.get(f"{PORTAL_BASE_URL}/Dashboard", text=dashboard)
        m.post(f"{PORTAL_BASE_URL}/Dashboard/Chart", text='{"ok": true}')
        m.get(f"{PORTAL_BASE_URL}/Dashboard/ChartData", text=chart_data)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("custom_components.pseg.async_setup_entry", _async_true)
            result = await hass.config_entries.flow.async_init(
                DOMAIN, context={"source": SOURCE_USER}
            )
            captcha_form = await _configure(
                hass,
                result["flow_id"],
                {CONF_MYMETER_EMAIL: EMAIL, CONF_MYMETER_PASSWORD: PASSWORD},
            )
            assert captcha_form["step_id"] == "captcha"
            done = await _configure(
                hass, captcha_form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF}
            )

    assert state["captcha_posts"] == 1
    assert state["proof_posts"] == 1
    assert done["type"] == FlowResultType.CREATE_ENTRY
    assert done["result"].unique_id == "12345678"
    assert done["data"][CONF_MYMETER_EMAIL] == EMAIL
    assert CONF_CAPTCHA_RESPONSE not in done["data"]
    assert PROOF not in json.dumps(done["data"])


@pytest.mark.parametrize("start", ["user", "reauth", "reconfigure"])
async def test_overlapping_credential_submit_runs_one_sign_in(
    hass: HomeAssistant, start: str
) -> None:
    """R2: a second submit while the first signs in must not replace its attempt.

    Review timeline: submit A, hold its login; submit B; release A. The old code
    ran two MyMeter logins and let A's late CAPTCHA preparation replace B's pending
    client and cleanup timer, so B aborted after a successful proof and an orphaned
    timer outlived the flow.
    """
    entry, started = await _begin_entry_flow(hass, start)
    recorder = _ProofRecorder()
    blocker = _Blocker()
    logins: list[PsegClient] = []
    flow = _flow_object(hass, started["flow_id"])

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            PsegClient, "login_local", blocker.wrap(_login_raises_captcha(logins))
        )
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)

        first_task = hass.async_create_task(
            _configure(hass, started["flow_id"], _credential_input(start))
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        second = await _configure(hass, started["flow_id"], _credential_input(start))
        assert second["type"] == FlowResultType.FORM
        assert second["step_id"] == _CREDENTIAL_STEP[start]
        assert second["errors"] == {"base": "sign_in_busy"}

        blocker.release.set()
        first = await first_task
        assert first["type"] == FlowResultType.FORM
        assert first["step_id"] == "captcha"
        assert len(logins) == 1
        assert len(recorder.clients) == 1
        assert logins[0] is recorder.clients[0]
        assert flow._captcha_cleanup is not None

        done = await _configure(hass, first["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})

    assert recorder.proofs == [PROOF]
    assert len(logins) == 1
    if entry is None:
        assert done["type"] == FlowResultType.CREATE_ENTRY
    else:
        assert done["type"] == FlowResultType.ABORT
        assert done["reason"] == f"{start}_successful"
        assert entry.data[CONF_MYMETER_EMAIL] == EMAIL
    # Completion dropped the pending sign-in and its cleanup timer, nothing orphaned.
    assert flow._captcha_pending is None
    assert flow._captcha_cleanup is None
    assert flow._sign_in_operation is None
    assert hass.config_entries.flow.async_progress_by_handler(DOMAIN) == []


@pytest.mark.parametrize("start", ["user", "reauth", "reconfigure"])
async def test_abort_during_initial_credential_request_leaves_nothing(
    hass: HomeAssistant, start: str
) -> None:
    """An abort while the first credential request runs must not commit or hold."""
    entry, started = await _begin_entry_flow(hass, start)
    before = dict(entry.data) if entry is not None else None
    recorder = _ProofRecorder()
    blocker = _Blocker()
    logins: list[PsegClient] = []
    flow = _flow_object(hass, started["flow_id"])

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            PsegClient, "login_local", blocker.wrap(_login_raises_captcha(logins))
        )
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", _fetch_meter)
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)

        task = hass.async_create_task(
            _configure(hass, started["flow_id"], _credential_input(start))
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        hass.config_entries.flow.async_abort(started["flow_id"])
        assert flow._flow_removed is True
        blocker.release.set()
        late = await task

    assert late["type"] == FlowResultType.ABORT
    assert late["reason"] == "sign_in_cancelled"
    assert len(logins) == 1
    assert recorder.clients == []
    assert recorder.proofs == []
    assert flow._captcha_pending is None
    assert flow._captcha_cleanup is None
    assert flow._sign_in_operation is None
    if entry is None:
        assert hass.config_entries.async_entries(DOMAIN) == []
    else:
        assert dict(entry.data) == before
        assert hass.config_entries.async_entries(DOMAIN) == [entry]


@pytest.mark.parametrize("start", ["user", "reauth", "reconfigure"])
async def test_abort_during_initial_captcha_preparation_leaves_no_timer(
    hass: HomeAssistant, start: str
) -> None:
    """An abort while the first CAPTCHA form loads must hold no client or timer."""
    entry, started = await _begin_entry_flow(hass, start)
    before = dict(entry.data) if entry is not None else None
    recorder = _ProofRecorder()
    blocker = _Blocker()
    logins: list[PsegClient] = []
    flow = _flow_object(hass, started["flow_id"])

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _login_raises_captcha(logins))
        mp.setattr(
            PsegClient, "prepare_login_captcha", blocker.wrap(_prepare_fn(recorder))
        )
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)

        task = hass.async_create_task(
            _configure(hass, started["flow_id"], _credential_input(start))
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        hass.config_entries.flow.async_abort(started["flow_id"])
        blocker.release.set()
        late = await task

    assert late["type"] == FlowResultType.ABORT
    assert late["reason"] == "sign_in_cancelled"
    assert len(logins) == 1
    assert len(recorder.clients) == 1
    assert recorder.proofs == []
    assert flow._captcha_pending is None
    assert flow._captcha_cleanup is None
    assert flow._sign_in_operation is None
    assert _holds_client(flow, recorder.clients[0]) is False
    if entry is None:
        assert hass.config_entries.async_entries(DOMAIN) == []
    else:
        assert dict(entry.data) == before
        assert hass.config_entries.async_entries(DOMAIN) == [entry]


async def test_credential_submit_during_in_flight_proof_keeps_pending_and_timer(
    hass: HomeAssistant,
) -> None:
    """A resubmitted credential form cannot replace an attempt that is committing."""
    _, started = await _begin_entry_flow(hass, "user")
    recorder = _ProofRecorder()
    blocker = _Blocker()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(PsegClient, "login_local", _raise_captcha)
        mp.setattr(PsegClient, "prepare_login_captcha", _prepare_fn(recorder))
        mp.setattr(PsegClient, "submit_login_captcha", _submit_fn(recorder))
        mp.setattr(PsegClient, "fetch_energy_data", blocker.wrap(_fetch_meter))
        mp.setattr("custom_components.pseg.async_setup_entry", _async_true)

        form = await _configure(hass, started["flow_id"], _credential_input("user"))
        assert form["step_id"] == "captcha"
        flow = _flow_object(hass, form["flow_id"])
        pending = flow._captcha_pending
        cleanup = flow._captcha_cleanup
        assert cleanup is not None

        task = hass.async_create_task(
            _configure(hass, form["flow_id"], {CONF_CAPTCHA_RESPONSE: PROOF})
        )
        await asyncio.wait_for(blocker.entered.wait(), 5)

        busy = await flow.async_step_user(_credential_input("user"))
        assert busy["type"] == FlowResultType.FORM
        assert busy["errors"] == {"base": "sign_in_busy"}
        assert flow._captcha_pending is pending
        assert flow._captcha_cleanup is cleanup

        blocker.release.set()
        done = await task

    assert done["type"] == FlowResultType.CREATE_ENTRY
    assert recorder.proofs == [PROOF]
    assert flow._captcha_pending is None
    assert flow._captcha_cleanup is None

"""DataUpdateCoordinator for the PSE&G Energy integration."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
import logging
import math
import re
from typing import Any

from homeassistant.components import persistent_notification
from homeassistant.components.recorder import get_instance
from homeassistant.components.recorder.models import (
    StatisticData,
    StatisticMeanType,
    StatisticMetaData,
)
from homeassistant.components.recorder.statistics import (
    async_add_external_statistics,
    statistics_during_period,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.recorder import DATA_INSTANCE
from homeassistant.helpers.start import async_at_started
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util
import requests

from .const import (
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_OKTA_SESSION_EXPIRED,
    AUTH_REASON_PORTAL_SESSION_EXPIRED,
    AUTH_REASON_REMEMBER_ME_REJECTED,
    AUTH_REASON_SECURITY_STEP,
    CONF_KNOWN_METER_IDS,
    CONF_METER_ID,
    CONF_PRICE_PER_KWH,
    CONF_RENEWAL_ADMISSION,
    CONF_STATISTICS_IMPORT_ENABLED,
    DEFAULT_PRICE_PER_KWH,
    DEFAULT_SCAN_INTERVAL_HOURS,
    DEFAULT_STATISTICS_IMPORT_ENABLED,
    DOMAIN,
    KEEPALIVE_INTERVAL_MINUTES,
    LOCAL_KEEPALIVE_INTERVAL_MINUTES,
    SESSION_COOKIE_NAMES,
    STATISTICS_PRECISION,
)
from .pseg_client import (
    PsegClient,
    PsegOktaSessionExpired,
    PsegTransientError,
)
from .renewal_admission import RenewalAdmission, renewal_runtime_for
from .statistics_hourly import (
    COST_REL_TOLERANCE,
    PROMOTION_ABS_TOLERANCE_KWH,
    PROMOTION_REL_TOLERANCE,
    STATISTICS_INCOMPLETE_REASONS,
    chain_rows,
    cost_tolerance,
    day_records_match,
    detect_hourly_days,
    merge_series_rows,
    ny_midnight_utc,
    parse_day,
    rows_by_day,
    validate_hourly_days,
    values_close,
)
from .statistics_state import StatisticsEntryRuntime

_LOGGER = logging.getLogger(__name__)


class PsegStatisticsError(HomeAssistantError):
    """Recorder query failed; the import is aborted to keep the sum chain intact."""


class PsegStatisticsConflictError(PsegStatisticsError):
    """A daily total contradicts a promoted hourly day; nothing was written."""


# Upper bound on waiting for the recorder to commit an import (seconds).
RECORDER_COMMIT_TIMEOUT = 120.0

# Earliest start considered when looking for the baseline row (before any AMI data).
_STATS_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)


def _row_start(stat: Any) -> datetime | None:
    """Return a statistics row start as an aware UTC datetime."""
    stat_start = stat.get("start")
    if isinstance(stat_start, (int, float)):
        return datetime.fromtimestamp(stat_start, tz=UTC)
    if isinstance(stat_start, datetime):
        return dt_util.as_utc(stat_start)
    return None


def _session_cookie_names(cookies: Any) -> frozenset[str]:
    """Return the session-cookie names in a persisted jar snapshot."""
    if not isinstance(cookies, list):
        return frozenset()
    return frozenset(
        cookie["name"]
        for cookie in cookies
        if isinstance(cookie, dict) and cookie.get("name") in SESSION_COOKIE_NAMES
    )


async def _async_get_last_stat_before(
    hass: HomeAssistant,
    statistic_id: str,
    before_dt: datetime,
) -> float | None:
    """Get the cumulative sum of the last statistic strictly before before_dt.

    Reads the hourly statistics table (where the daily rows live) with
    end_time=before_dt. A "day" period would aggregate in HA's configured time zone,
    and for any zone other than America/New_York the bucket ending before before_dt
    contains the row AT before_dt, so re-imports added that day twice.

    Raises PsegStatisticsError if the query fails: treating a failure as "no prior
    data" would restart the chain at 0 and write a negative step.
    """
    try:
        stats = await get_instance(hass).async_add_executor_job(
            statistics_during_period,
            hass,
            _STATS_EPOCH,
            before_dt,
            {statistic_id},
            "hour",
            None,
            {"sum"},
        )
    except Exception as err:
        raise PsegStatisticsError(
            f"Could not read prior statistics for {statistic_id}: {err}"
        ) from err

    best_start: datetime | None = None
    best_sum: float | None = None
    for stat in stats.get(statistic_id, []):
        start = _row_start(stat)
        val = stat.get("sum")
        if start is None or val is None or start >= before_dt:
            continue
        if best_start is None or start > best_start:
            best_start, best_sum = start, float(val)
    return best_sum


async def _async_get_stats_from(
    hass: HomeAssistant,
    statistic_id: str,
    from_dt: datetime,
) -> list[tuple[datetime, float | None]]:
    """Return (start, state) of existing rows with start >= from_dt, oldest first."""
    try:
        stats = await get_instance(hass).async_add_executor_job(
            statistics_during_period,
            hass,
            from_dt,
            None,
            {statistic_id},
            "hour",
            None,
            {"state"},
        )
    except Exception as err:
        raise PsegStatisticsError(
            f"Could not read existing statistics for {statistic_id}: {err}"
        ) from err

    rows: list[tuple[datetime, float | None]] = []
    for stat in stats.get(statistic_id, []):
        start = _row_start(stat)
        if start is not None and start >= from_dt:
            state = stat.get("state")
            rows.append((start, None if state is None else float(state)))
    rows.sort(key=lambda row: row[0])
    return rows


async def _async_get_series_with_sums(
    hass: HomeAssistant,
    statistic_id: str,
    from_dt: datetime,
) -> list[tuple[datetime, float, float]]:
    """Return (start, state, sum) for verification after a recorder write."""
    try:
        stats = await get_instance(hass).async_add_executor_job(
            statistics_during_period,
            hass,
            from_dt,
            None,
            {statistic_id},
            "hour",
            None,
            {"state", "sum"},
        )
    except Exception as err:
        raise PsegStatisticsError(
            f"Could not verify statistics for {statistic_id}: {err}"
        ) from err

    rows: list[tuple[datetime, float, float]] = []
    for stat in stats.get(statistic_id, []):
        start = _row_start(stat)
        state = stat.get("state")
        total = stat.get("sum")
        if start is None or state is None or total is None:
            continue
        if start >= from_dt:
            rows.append((start, float(state), float(total)))
    rows.sort(key=lambda row: row[0])
    return rows


def _series_rows_match(
    live: list[tuple[datetime, float, float]],
    intended: list[tuple[datetime, float, float]],
    *,
    abs_tol: float = 1e-6,
) -> bool:
    """Return True when the recorder holds the exact intended rows and sums."""
    if len(live) != len(intended):
        return False
    for (start, state, total), (want_start, want_state, want_total) in zip(
        live, intended
    ):
        if start != want_start:
            return False
        if not values_close(state, want_state, abs_tol=abs_tol):
            return False
        if not values_close(total, want_total, abs_tol=abs_tol, rel_tol=1e-9):
            return False
    return True


def _statistics_runtime_for(
    hass: HomeAssistant, entry_id: str
) -> StatisticsEntryRuntime:
    """Return the one statistics runtime shared by every coordinator of an entry."""
    registry = hass.data.setdefault(f"{DOMAIN}_statistics_runtimes", {})
    runtime = registry.get(entry_id)
    if runtime is None:
        runtime = StatisticsEntryRuntime(hass, entry_id)
        registry[entry_id] = runtime
    return runtime


async def _async_wait_for_recorder_commit(hass: HomeAssistant) -> None:
    """Wait until queued statistics imports are committed to the database.

    async_add_external_statistics only queues an import task on the recorder thread;
    the next baseline query runs on a different executor and would otherwise read the
    pre-import sums. The caller bounds it with RECORDER_COMMIT_TIMEOUT: it runs while
    the update/stats locks are held, and a broken recorder never runs the synchronize
    task, which would freeze polls and backfills forever.
    """
    instance = hass.data.get(DATA_INSTANCE)
    if instance is not None:
        await instance.async_block_till_done()


def _canonical_records(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the canonical [start, value] journal rows into merge inputs."""
    records: list[dict[str, Any]] = []
    for raw_start, raw_value in entry.get("records") or []:
        try:
            start = datetime.fromisoformat(str(raw_start))
            value = float(raw_value)
        except (TypeError, ValueError):
            continue
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        records.append({"start": start, "kwh": value})
    return sorted(records, key=lambda item: item["start"])


def _journal_records_match(
    live_rows: list[tuple[datetime, float | None]],
    entry: dict[str, Any],
) -> bool:
    """Return True when the recorder already holds every canonical journal row."""
    raw_records = entry.get("records") or []
    if not raw_records or len(live_rows) != len(raw_records):
        return False
    by_start = {start: state for start, state in live_rows}
    for raw_start, raw_value in raw_records:
        try:
            start = datetime.fromisoformat(str(raw_start))
            value = float(raw_value)
        except (TypeError, ValueError):
            return False
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if start not in by_start:
            return False
        if not values_close(by_start[start], value, abs_tol=1e-6):
            return False
    return True


def _statistic_metadata(
    clean_meter: str,
) -> tuple[StatisticMetaData, StatisticMetaData]:
    """Return the stable consumption/cost metadata for one meter.

    The statistic ids and metadata never change during the hourly migration: the
    Energy Dashboard keeps its existing history and entity links.
    """
    return (
        StatisticMetaData(
            has_mean=False,
            mean_type=StatisticMeanType.NONE,
            has_sum=True,
            name="PSE&G Electricity Consumption",
            source=DOMAIN,
            statistic_id=f"{DOMAIN}:{clean_meter}_energy_consumption",
            unit_class="energy",
            unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        ),
        StatisticMetaData(
            has_mean=False,
            mean_type=StatisticMeanType.NONE,
            has_sum=True,
            name="PSE&G Electricity Cost (Estimated)",
            source=DOMAIN,
            statistic_id=f"{DOMAIN}:{clean_meter}_energy_cost",
            unit_class=None,
            unit_of_measurement="USD",
        ),
    )


def _normalise_daily(
    records: list[dict[str, Any]],
    price_per_kwh: float,
) -> dict[date, dict[str, float]]:
    """Collapse daily records to one entry per New York day, dropping invalid rows."""
    daily: dict[date, dict[str, float]] = {}
    for record in records:
        day = parse_day(record.get("date"))
        if day is None:
            _LOGGER.debug("Skipping statistics record with an invalid date")
            continue
        try:
            kwh = float(record.get("kwh"))
        except (TypeError, ValueError):
            _LOGGER.debug("Skipping statistics record with non-numeric usage")
            continue
        if not math.isfinite(kwh):
            continue
        raw_cost = record.get("cost")
        if raw_cost is None:
            # Daily fallback cost keeps the portal's cents precision; hourly cost
            # states use six decimals so 24 hours never accumulate cent rounding.
            cost = round(kwh * price_per_kwh, 2)
        else:
            try:
                cost = float(raw_cost)
            except (TypeError, ValueError):
                _LOGGER.debug("Skipping statistics record with non-numeric cost")
                continue
            if not math.isfinite(cost):
                continue
        daily[day] = {"kwh": kwh, "cost": cost}
    return daily


def build_external_statistics(
    records: list[dict[str, Any]],
    meter_id: str,
    prior_consumption_sum: float | None = None,
    prior_cost_sum: float | None = None,
    price_per_kwh: float = DEFAULT_PRICE_PER_KWH,
) -> tuple[StatisticMetaData, list[StatisticData], StatisticMetaData, list[StatisticData]]:
    """Build daily consumption and cost statistics with running cumulative sums.

    Kept as the pure daily builder used by tests and by callers that only have daily
    records; the coordinator itself routes through the shared reconciliation so the
    hourly provenance and the stored-row rechain are never bypassed.
    """
    clean_meter = (
        re.sub(r"[^a-z0-9_]+", "_", str(meter_id).lower()).strip("_") or "meter"
    )
    consumption_metadata, cost_metadata = _statistic_metadata(clean_meter)

    daily = _normalise_daily(records, price_per_kwh)
    if not daily:
        return consumption_metadata, [], cost_metadata, []

    consumption_by_start = {
        ny_midnight_utc(day): values["kwh"] for day, values in daily.items()
    }
    cost_by_start = {
        ny_midnight_utc(day): values["cost"] for day, values in daily.items()
    }
    return (
        consumption_metadata,
        chain_rows(consumption_by_start, prior_consumption_sum),
        cost_metadata,
        chain_rows(cost_by_start, prior_cost_sum),
    )


class PsegDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Class to manage fetching PSE&G energy data from MyMeter."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: PsegClient,
        entry_data: dict[str, Any],
        config_entry: ConfigEntry | None = None,
    ) -> None:
        """Initialize the coordinator."""
        self.client = client
        self.entry_data = entry_data
        self.config_entry = config_entry
        self.next_update_time: datetime | None = None
        self._last_valid_data: dict[str, Any] | None = None
        self.auth_required: bool = False
        self.status: str = "connected"
        self.last_successful_update: str | None = None
        # Avoids repeating the typed identity-rejection warning on every poll; reset
        # by the next fully confirmed update.
        self._identity_rejection_logged = False
        self._unsub_keepalive: Callable[[], None] | None = None
        # Set on unload. A keepalive/poll still in the executor at that point belongs
        # to a dead coordinator and must not write to the entry or start reauth.
        self._stopped = False
        # The jar this coordinator loaded or last wrote. If entry.data["cookies"]
        # differs, reauth/reconfigure replaced it and our in-memory jar is stale.
        self._jar_baseline = config_entry.data.get("cookies") if config_entry else None
        self._jar_writing_target: list[dict[str, Any]] | None = None
        # Session-cookie names the last persist (or the loaded jar) carried. A jar
        # that loses one of them is a half-empty jar from a failed renewal.
        self._persisted_session_cookies = _session_cookie_names(self._jar_baseline)
        # Serializes portal fetch + statistics import for poll, refresh and backfill.
        self._update_lock = asyncio.Lock()
        # Entry-level serialization and ownership survive coordinator unload/reload.
        self._stats_runtime = _statistics_runtime_for(
            hass, config_entry.entry_id if config_entry else "default"
        )
        self._stats_token = self._stats_runtime.activate()
        self._stats_lock = self._stats_runtime.lock
        # Durable promoted-day provenance and the pre-write mutation journal.
        self._stats_state = self._stats_runtime.store
        self.last_statistics_import: str | None = None
        # Last hourly evaluation, kept small and value-free for diagnostics.
        self._hourly_summary: dict[str, Any] = {
            "complete_days": 0,
            "incomplete_days": 0,
            "promoted_last_run": 0,
            "reason_counts": {},
        }
        # Shared, non-secret renewal budget (attempts, cooldown, terminal reason). It
        # lives in entry.data next to the cookie jar so an options reload cannot
        # reset it, and the client spends it for both the poll and the keepalive.
        self._renewal_runtime = None
        self._renewal_token = None
        if config_entry:
            self._renewal_runtime = renewal_runtime_for(hass, config_entry.entry_id)
            self._renewal_runtime.bind(config_entry.data)
            self._renewal_runtime.bind_persistence(hass, config_entry)
            self._renewal_token = self._renewal_runtime.activate(
                lambda: not self._stopped and not self._jar_replaced()
            )
            self._renewal_admission = self._renewal_runtime.admission
        else:
            self._renewal_admission = RenewalAdmission.from_entry_data(entry_data)
        client.attach_renewal_admission(
            self._renewal_admission, self._renewal_runtime, self._renewal_token
        )
        client.set_expected_meter_ids(self._known_meter_ids())

        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=timedelta(hours=DEFAULT_SCAN_INTERVAL_HOURS),
        )

    def keepalive_interval(self) -> timedelta:
        """Return the per-mode keepalive period.

        Okta sessions tolerate a 10-minute SSO round trip. A local portal session is
        touched every 3 minutes with a credential-free GET: one observed lapse
        happened after ~9 minutes without an accepted request (2026-10-23), but the
        server's real rule is unknown, so this is a product cadence, not a TTL claim.
        """
        minutes = (
            LOCAL_KEEPALIVE_INTERVAL_MINUTES
            if self.client.is_local_mode
            else KEEPALIVE_INTERVAL_MINUTES
        )
        return timedelta(minutes=minutes)

    def start_keepalive(self) -> None:
        """Start the recurring, per-mode keepalive (see keepalive_interval)."""
        if self._unsub_keepalive is None:
            self._unsub_keepalive = async_track_time_interval(
                self.hass,
                self._async_keepalive,
                self.keepalive_interval(),
            )

    def stop_keepalive(self) -> None:
        """Cancel recurring keepalive timer and retire this coordinator's session."""
        # Best effort before retirement: keep the spent renewal budget and any jar a
        # renewal already confirmed durable across a reload/stop. A jar replaced by
        # reauth is newer than this coordinator's state, so nothing is written then.
        self._persist_auth_metadata()
        self._persist_confirmed_session()
        self._stopped = True
        if self._renewal_runtime is not None:
            self._renewal_runtime.retire(self._renewal_token)
        self._stats_runtime.retire(self._stats_token)
        if self._unsub_keepalive is not None:
            self._unsub_keepalive()
            self._unsub_keepalive = None

    async def _async_keepalive(self, _now: datetime) -> None:
        """Run keepalive check, persist rotated cookies and settle auth state."""
        minutes = int(self.keepalive_interval().total_seconds() // 60)
        mode = "local" if self.client.is_local_mode else "okta"
        _LOGGER.debug("Running %d-minute PSE&G keepalive (%s mode)", minutes, mode)
        expired = False
        recovered = False
        try:
            recovered = bool(await self.hass.async_add_executor_job(self.client.keepalive))
        except PsegOktaSessionExpired:
            expired = True
        except Exception as err:
            _LOGGER.debug("Error during keepalive check: %s", err)

        if self._is_stale():
            _LOGGER.debug("Ignoring keepalive result from a retired PSE&G session")
            return

        # Budget first: a reservation spent before the HTTP request must survive even
        # when the cookie snapshot itself is refused as unconfirmed.
        self._persist_auth_metadata()
        await self._async_persist_cookies()
        self._persist_confirmed_session()
        if self._is_stale():
            return

        if expired or self.client.okta_session_expired_at:
            if not self.auth_required:
                self.auth_required = True
                self.status = "auth_required"
                self._log_auth_failure("keepalive")
                self._raise_auth_issues("Authentication expired during background keepalive")
                # Same outcome as a poll raising ConfigEntryAuthFailed: ask the user now
                # instead of waiting up to a full poll interval. Guarded by auth_required so
                # it fires once per expiry; HA also refuses a second concurrent reauth flow.
                if self.config_entry:
                    self.config_entry.async_start_reauth(self.hass)
                self.async_update_listeners()
            return

        if recovered and (self.auth_required or self.status == "auth_required"):
            # A keepalive that succeeds again proves the session works, but only a
            # successful poll used to clear this: a recovered keepalive left "auth
            # required" and its repair/notification up to a full 4-hour poll interval.
            self.auth_required = False
            self.status = "connected"
            self._dismiss_auth_issues()
            self.async_update_listeners()

    def _jar_replaced(self) -> bool:
        """Return True when reauth/reconfigure replaced the jar this client loaded."""
        if not self.config_entry:
            return False
        current = self.config_entry.data.get("cookies")
        if current == self._jar_baseline:
            return False
        writing = self._jar_writing_target
        return not (writing is not None and current == writing)

    def _is_stale(self) -> bool:
        """Return True if this coordinator was unloaded or its jar was replaced."""
        return (
            self._stopped
            or self._jar_replaced()
            or (
                self._renewal_runtime is not None
                and not self._renewal_runtime.is_active(self._renewal_token)
            )
        )

    def _known_meter_ids(self) -> set[str]:
        """Every meter id this entry already owns (account-identity guard)."""
        if not self.config_entry:
            return set()
        known = {
            str(value)
            for value in (self.config_entry.data.get(CONF_KNOWN_METER_IDS) or [])
            if value
        }
        for value in (self.config_entry.unique_id, self.config_entry.data.get(CONF_METER_ID)):
            if value:
                known.add(str(value))
        return known

    def _persist_auth_metadata(self) -> None:
        """Persist the non-secret renewal budget next to the cookies (no reload)."""
        if not self.config_entry or self._is_stale():
            return
        self._renewal_runtime.persist(self.hass, self.config_entry)

    async def _async_persist_cookies(self) -> None:
        """Persist rotated session cookies to entry.data without logging values.

        The jar and the auth reason come from ONE locked client snapshot. Checking
        auth_reason before awaiting the export let an overlapping renewal drop MM_SID
        and set the reason while the export was queued; that half-empty jar then
        overwrote the entry's last known-good one (review r1, reproduced 2026-10-22
        as auth_reason=remember_me_rejected with only MM_RememberMe persisted).
        """
        if not self.config_entry:
            return
        # Remember which confirmation was current before the executor snapshot: a
        # keepalive may confirm a newer renewal while the export is queued, and that
        # newer snapshot must stay pending for the next exit.
        pending_before = self.client.pending_confirmed_snapshot()
        # Executor: the snapshot takes the client's portal lock, which a long
        # backfill may hold.
        exported, auth_reason = await self.hass.async_add_executor_job(
            self.client.export_cookies_and_auth_reason
        )
        if not self.client.cookies_confirmed:
            # A failed renewal rolled the jar back; only a confirmed transaction may
            # replace the saved jar.
            _LOGGER.debug("Not persisting a cookie jar from an unconfirmed transaction")
            return
        if auth_reason is not None:
            # The snapshot belongs to a session the portal just refused. A failed
            # Remember Me renewal drops MM_SID before its GET, so persisting now
            # would replace the last known-good jar with a half-empty one. A later
            # confirmed sign-in clears auth_reason and persistence resumes.
            _LOGGER.debug("Not persisting cookies from an unconfirmed PSE&G session")
            return
        if not exported:
            return
        session_cookies = _session_cookie_names(exported)
        if not self._persisted_session_cookies <= session_cookies:
            # auth_reason can be clear again (a parallel GET succeeded) while the
            # jar still lacks the session cookie a failed renewal removed. Never
            # trade the good jar for a partial one.
            _LOGGER.debug("Not persisting a partial PSE&G cookie jar")
            return
        if self._is_stale():
            _LOGGER.debug("Not persisting cookies from a retired PSE&G session")
            return
        confirmed_cookies = (
            self.client.confirmed_cookies()
            if hasattr(self.client, "confirmed_cookies")
            else None
        )
        if confirmed_cookies is not None and exported != confirmed_cookies:
            _LOGGER.debug(
                "Not persisting unconfirmed live-jar mutations over a confirmed PSE&G jar"
            )
            return
        self._write_cookie_handoff(exported, session_cookies)
        pending_after = self.client.pending_confirmed_snapshot()
        if (
            pending_before is not None
            and pending_after is not None
            and pending_after["id"] == pending_before["id"]
        ):
            # The live fully-confirmed jar is durable now; this failure-exit
            # snapshot must not overwrite it later in the same poll/keepalive.
            self.client.clear_confirmed_snapshot(pending_before["id"])

    def _write_cookie_handoff(
        self, exported: list[dict[str, Any]], session_cookies: frozenset[str]
    ) -> None:
        """Write the jar and the current budget together, without an await.

        Keeping the confirmed jar and the settled admission in one entry update
        prevents a reload/process stop from observing a rearmed budget next to the
        previous cookie generation. Policy is omitted only when it is unreadable
        (``None``), so corrupt bytes stay untouched and fail closed.
        """
        if not self.config_entry:
            return
        admission = (
            self._renewal_runtime.admission_dict()
            if self._renewal_runtime is not None
            else None
        )
        current_cookies = self.config_entry.data.get("cookies")
        current_admission = self.config_entry.data.get(CONF_RENEWAL_ADMISSION)
        if current_cookies == exported and (
            admission is None or current_admission == admission
        ):
            self._jar_baseline = exported
            self._persisted_session_cookies = session_cookies
            return
        new_data = dict(self.config_entry.data)
        new_data["cookies"] = exported
        if admission is not None:
            new_data[CONF_RENEWAL_ADMISSION] = admission
        if new_data != self.config_entry.data:
            _LOGGER.debug("Persisting rotated session cookies to entry.data")
            self._jar_writing_target = exported
            try:
                self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)
            finally:
                if self.config_entry.data.get("cookies") == exported:
                    self._jar_baseline = exported
                    self._persisted_session_cookies = session_cookies
                self._jar_writing_target = None
            return
        self._jar_baseline = exported
        self._persisted_session_cookies = session_cookies

    def _persist_confirmed_session(self) -> None:
        """Hand off the jar a renewal/sign-in verified, on every exit path.

        A later DAILY chart timeout, token-maintenance page, failed setup, unload,
        stop, or backfill failure used to leave a verified renewal only in memory
        while its spent budget was durable. Only the immutable snapshot captured at
        confirmation is written here: never the live jar, which a later failed
        response may have poisoned with its own Set-Cookie.
        """
        if not self.config_entry or self._is_stale():
            return
        snapshot = self.client.pending_confirmed_snapshot()
        if snapshot is None:
            return
        if not snapshot["cookies_confirmed"] or snapshot["auth_reason"] is not None:
            return
        exported = snapshot["cookies"]
        if not exported:
            return
        session_cookies = _session_cookie_names(exported)
        if not self._persisted_session_cookies <= session_cookies:
            _LOGGER.debug("Not persisting a partial confirmed cookie jar")
            return
        try:
            self._write_cookie_handoff(exported, session_cookies)
        except Exception:
            _LOGGER.warning(
                "Confirmed cookie handoff failed; the next failure or stop retries it"
            )
            return
        self.client.clear_confirmed_snapshot(snapshot["id"])

    def _async_persist_meter_ids(self, meter_ids: list[str]) -> None:
        """Remember meters proven on this account without reloading the entry."""
        if not self.config_entry or self._is_stale():
            return
        known = self._known_meter_ids()
        # The client needs the entry's known ids to confirm a renewed session's
        # account identity before it publishes or persists that transaction.
        self.client.set_expected_meter_ids(known)
        cleaned = [str(value) for value in (meter_ids or []) if value]
        if not cleaned:
            return
        if not set(cleaned).issubset(known):
            new_data = dict(self.config_entry.data)
            new_data[CONF_KNOWN_METER_IDS] = sorted(known.union(cleaned))
            self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)
            self.client.set_expected_meter_ids(self._known_meter_ids())

    def _dismiss_auth_issues(self) -> None:
        """Dismiss persistent notification and repairs issue once authenticated."""
        if not self.config_entry:
            return
        persistent_notification.async_dismiss(
            self.hass,
            notification_id=f"pseg_reauth_{self.config_entry.entry_id}",
        )
        ir.async_delete_issue(
            self.hass,
            DOMAIN,
            f"reauth_required_{self.config_entry.entry_id}",
        )

    def _auth_failure_reason(self) -> str:
        """Return the typed reason for the current auth failure.

        The fallback keeps pre-1.4.2 behaviour (no reason recorded) while still
        telling local portal entries apart from Okta ones.
        """
        if self.client.auth_reason:
            return self.client.auth_reason
        if self.client.is_local_mode:
            return AUTH_REASON_PORTAL_SESSION_EXPIRED
        return AUTH_REASON_OKTA_SESSION_EXPIRED

    def _auth_failure_detail(self) -> str:
        """One user-facing sentence for the current typed auth failure."""
        return {
            AUTH_REASON_PORTAL_SESSION_EXPIRED: "Your PSE&G portal session has expired.",
            AUTH_REASON_CAPTCHA_REQUIRED: (
                "PSE&G MyMeter is asking for a CAPTCHA, which Home Assistant cannot solve."
            ),
            AUTH_REASON_REMEMBER_ME_REJECTED: (
                "PSE&G refused the saved MyMeter sign-in."
            ),
            AUTH_REASON_SECURITY_STEP: (
                "PSE&G MyMeter is asking for a security question or password change."
            ),
            AUTH_REASON_OKTA_SESSION_EXPIRED: "Your PSE&G Okta session has expired.",
        }.get(self._auth_failure_reason(), "Your PSE&G session has expired.")

    def _auth_failed_message(self) -> str:
        """ConfigEntryAuthFailed text for the current typed auth failure (no secrets)."""
        prefix = {
            AUTH_REASON_PORTAL_SESSION_EXPIRED: "PSE&G portal session expired",
            AUTH_REASON_CAPTCHA_REQUIRED: "PSE&G MyMeter requires a solved CAPTCHA",
            AUTH_REASON_REMEMBER_ME_REJECTED: "PSE&G refused the saved MyMeter sign-in",
            AUTH_REASON_SECURITY_STEP: "PSE&G MyMeter requires a security step",
            AUTH_REASON_OKTA_SESSION_EXPIRED: "PSE&G Okta session expired",
        }.get(self._auth_failure_reason(), "PSE&G session expired")
        return (
            f"{prefix}. Please re-authenticate under Settings > Devices & Services > PSE&G."
        )

    def _log_auth_failure(self, source: str) -> None:
        """Log one line: typed reason plus idle gap (never a credential or cookie)."""
        reason = self._auth_failure_reason()
        gap = self.client.idle_gap_seconds
        if gap is None:
            _LOGGER.warning("PSE&G %s authentication failure (%s)", source, reason)
        else:
            _LOGGER.warning(
                "PSE&G %s authentication failure (%s); "
                "last successful portal request %.0f s ago",
                source,
                reason,
                gap,
            )

    def _raise_auth_issues(self, err_msg: str) -> None:
        """Raise persistent notification and repairs issue when authentication is required."""
        entry_id = self.config_entry.entry_id if self.config_entry else "default"
        _LOGGER.debug("Raising PSE&G auth issue: %s", err_msg)
        msg = (
            f"{self._auth_failure_detail()} "
            "Please go to **Settings > Devices & Services > PSE&G**, open the entry, "
            "and follow the **Re-authenticate** prompt. If PSE&G asks for a CAPTCHA, "
            "the prompt walks you through solving it in your browser."
        )
        persistent_notification.async_create(
            self.hass,
            title="PSE&G Authentication Required",
            message=msg,
            notification_id=f"pseg_reauth_{entry_id}",
        )
        if self.config_entry:
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                f"reauth_required_{entry_id}",
                # No repairs.py flow: the fix is the reauth flow HA already offers.
                is_fixable=False,
                is_persistent=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key="reauth_required",
                data={"entry_id": entry_id},
            )

    def _get_meter_id(self, data: dict[str, Any] | None = None) -> str:
        """Extract a clean meter identifier for external statistics."""
        if self.config_entry and self.config_entry.unique_id:
            return self.config_entry.unique_id
        if data and "meter" in data:
            meter_str = str(data["meter"])
            match = re.search(r"\d+", meter_str)
            if match:
                return match.group(0)
            return re.sub(r"[^a-z0-9_]+", "_", meter_str.lower()).strip("_")
        return "electric_meter"

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from PSE&G."""
        if self.config_entry and self.config_entry.options:
            self.client.price_per_kwh = self.config_entry.options.get(
                CONF_PRICE_PER_KWH, DEFAULT_PRICE_PER_KWH
            )

        try:
            async with self._update_lock:
                data = await self.hass.async_add_executor_job(
                    self.client.fetch_energy_data, 14
                )
                if self._is_stale():
                    raise UpdateFailed("Ignoring poll result from a retired PSE&G session")
                self._persist_auth_metadata()
                await self._async_persist_cookies()
                if self._is_stale():
                    raise UpdateFailed("Ignoring poll result from a retired PSE&G session")
                if data.get("identity_confirmed") is False:
                    # The DAILY leg is authoritative. An unconfirmed account identity
                    # must never publish readings, statistics or identity, must never
                    # look like a success, and must never be reported as connected.
                    # Keep the previous data (the sensors fall back to it) and fail
                    # typed, so HA keeps the poll scheduled and entities stay put.
                    self.status = "error"
                    if not self._identity_rejection_logged:
                        self._identity_rejection_logged = True
                        _LOGGER.warning(
                            "PSE&G daily usage did not confirm this entry's meter; "
                            "keeping the previous readings"
                        )
                    raise UpdateFailed(
                        "PSE&G daily usage did not confirm this entry's meter identity"
                    )
                candidate_meters = (
                    data.get("contributing_meter_ids")
                    if "contributing_meter_ids" in data
                    else (data.get("meter_ids") or [])
                )
                if "history_14d" in data:
                    if self.client._has_valid_meter_read(
                        data.get("history_14d") or [],
                        candidate_meters,
                    ):
                        self._async_persist_meter_ids(candidate_meters)
                    else:
                        self.client.set_expected_meter_ids(self._known_meter_ids())
                else:
                    self._async_persist_meter_ids(candidate_meters)

                daily_records = (
                    data.get("daily_records") or data.get("history_14d") or []
                )
                hourly_records = data.get("hourly_records") or []
                if daily_records:
                    meter_id = self._get_meter_id(data)
                    hourly_granularity = data.get(
                        "hourly_granularity", "unavailable"
                    )
                    if self.hass.state is CoreState.running:
                        await self._async_record_statistics_logged(
                            daily_records,
                            meter_id,
                            hourly_records,
                            hourly_granularity,
                        )
                    else:
                        self._defer_statistics_until_started(
                            daily_records,
                            meter_id,
                            hourly_records,
                            hourly_granularity,
                        )

            if self._is_stale():
                # A reauth/reload replaced this session while the poll ran: its data,
                # status and cookie snapshot belong to a retired coordinator.
                raise UpdateFailed("Ignoring poll result from a retired PSE&G session")
            self.next_update_time = dt_util.utcnow() + self.update_interval
            data["next_update"] = self.next_update_time.isoformat()
            self._last_valid_data = data
            self.last_successful_update = dt_util.utcnow().isoformat()
            self.auth_required = False
            self.status = "connected"
            self._identity_rejection_logged = False
            self._dismiss_auth_issues()
            return data
        except UpdateFailed:
            raise
        except PsegOktaSessionExpired as err:
            if self._is_stale():
                # A retired coordinator (unloaded or jar replaced by reauth) must not
                # start another reauth flow over the fresh cookies.
                raise UpdateFailed("Ignoring auth failure from a retired PSE&G session") from err
            self.auth_required = True
            self.status = "auth_required"
            self._log_auth_failure("poll")
            self._raise_auth_issues(str(err))
            raise ConfigEntryAuthFailed(self._auth_failed_message()) from err
        except (PsegTransientError, requests.RequestException) as err:
            if not self._is_stale():
                self.status = "error"
            raise UpdateFailed(f"Transient error communicating with PSE&G: {err}") from err
        except Exception as err:
            if not self._is_stale():
                self.status = "error"
            raise UpdateFailed(f"Error communicating with PSE&G: {err}") from err
        finally:
            self._persist_auth_metadata()
            self._persist_confirmed_session()

    async def _async_record_statistics_logged(
        self,
        records: list[dict[str, Any]],
        meter_id: str,
        hourly_records: list[dict[str, Any]] | None = None,
        hourly_granularity: str = "unavailable",
    ) -> None:
        """Import statistics; a failure is logged and never fails the poll."""
        try:
            if hourly_records:
                await self.async_record_statistics(
                    records,
                    meter_id=meter_id,
                    hourly_records=hourly_records,
                    hourly_granularity=hourly_granularity,
                )
            else:
                await self.async_record_statistics(records, meter_id=meter_id)
        except Exception as stat_err:
            _LOGGER.warning("Could not record statistics into LTS: %s", stat_err)

    def _defer_statistics_until_started(
        self,
        records: list[dict[str, Any]],
        meter_id: str,
        hourly_records: list[dict[str, Any]] | None = None,
        hourly_granularity: str = "unavailable",
    ) -> None:
        """Import after Home Assistant has started instead of during setup.

        The recorder only processes its queue once HA has started, and HA only
        starts once this first refresh returns, so waiting for the commit here
        deadlocked bootstrap until RECORDER_COMMIT_TIMEOUT (seen live 2026-10-21).
        """

        async def _import_when_started(_hass: HomeAssistant) -> None:
            if self._is_stale() or not self.statistics_imports_enabled():
                return
            await self._async_record_statistics_logged(
                records, meter_id, hourly_records, hourly_granularity
            )

        unsub = async_at_started(self.hass, _import_when_started)
        if self.config_entry is not None:
            self.config_entry.async_on_unload(unsub)

    def statistics_imports_enabled(self) -> bool:
        """Return whether any statistics import is allowed for this entry.

        Authentication and keepalive never consult this switch: it exists so an
        operator can stop every recorder write (automatic poll, deferred startup
        import and manual backfill) while the signed-in session keeps running,
        for example before exporting or restoring statistics.
        """
        if self.config_entry is None:
            return True
        return bool(
            self.config_entry.options.get(
                CONF_STATISTICS_IMPORT_ENABLED,
                DEFAULT_STATISTICS_IMPORT_ENABLED,
            )
        )

    def _can_mutate_statistics(self) -> bool:
        """Re-check ownership and the live pause option immediately before a write."""
        if self._is_stale() or not self._stats_runtime.is_current(self._stats_token):
            _LOGGER.debug("Skipping statistics mutation for a retired PSE&G session")
            return False
        if not self.statistics_imports_enabled():
            _LOGGER.debug("Statistics imports are disabled for this PSE&G entry")
            return False
        return True

    async def async_record_statistics(
        self,
        records: list[dict[str, Any]],
        meter_id: str | None = None,
        *,
        hourly_records: list[dict[str, Any]] | None = None,
        hourly_granularity: str = "unavailable",
    ) -> None:
        """Reconcile authoritative daily records and optional hourly points.

        One path serves the poll and the manual daily backfill. Daily records are
        always eligible for import; a closed hourly day is promoted only when it is
        complete, carries positive interval-start evidence and its total agrees with
        the daily total. A promoted day is never overwritten by a daily retry.
        """
        if not records and not hourly_records:
            return
        if not self.statistics_imports_enabled():
            _LOGGER.debug("Statistics imports are disabled for this PSE&G entry")
            return

        async with self._stats_lock:
            if not self._can_mutate_statistics():
                return
            await self._async_record_statistics_locked(
                records, meter_id, hourly_records or [], hourly_granularity
            )

    async def _async_record_statistics_locked(
        self,
        records: list[dict[str, Any]],
        meter_id: str | None,
        hourly_records: list[dict[str, Any]],
        hourly_granularity: str,
    ) -> None:
        """Reconcile and import statistics; caller holds the entry lock."""
        meter_id = meter_id or self._get_meter_id()
        clean_meter = (
            re.sub(r"[^a-z0-9_]+", "_", str(meter_id).lower()).strip("_") or "meter"
        )
        consumption_statistic_id = f"{DOMAIN}:{clean_meter}_energy_consumption"
        cost_statistic_id = f"{DOMAIN}:{clean_meter}_energy_cost"
        await self._stats_state.async_load()
        if not self._can_mutate_statistics():
            return

        # Finish a crashed or timed-out mutation before reconciling new data, so a
        # daily retry can never land on top of a half-written day.
        await self._async_recover_pending()
        if not self._can_mutate_statistics():
            return

        now = dt_util.utcnow()
        daily = _normalise_daily(records, self.client.price_per_kwh)
        daily_totals = {day: item["kwh"] for day, item in daily.items()}
        # A daily-only import (manual backfill or a poll without an hourly leg) has
        # no hourly provenance to evaluate; daily rows keep today's behaviour.
        validations = (
            validate_hourly_days(
                hourly_records,
                daily_totals,
                now,
                granularity=hourly_granularity,
            )
            if hourly_records
            else {}
        )
        complete = {
            day: check for day, check in validations.items() if check.complete
        }
        if not daily and not complete:
            self._log_hourly_outcome(validations, {})
            return

        first_start = min(
            [ny_midnight_utc(day) for day in daily]
            + [check.records[0]["start"] for check in complete.values()]
        )

        # Every read happens before the first write: a failed read imports nothing,
        # and both series are chained from one consistent snapshot.
        prior_consumption = await _async_get_last_stat_before(
            self.hass, consumption_statistic_id, first_start
        )
        prior_cost = await _async_get_last_stat_before(
            self.hass, cost_statistic_id, first_start
        )
        existing_consumption = await _async_get_stats_from(
            self.hass, consumption_statistic_id, first_start
        )
        existing_cost = await _async_get_stats_from(
            self.hass, cost_statistic_id, first_start
        )
        if not self._can_mutate_statistics():
            return

        pending_days = self._stats_state.pending_days(
            consumption_statistic_id
        ) | self._stats_state.pending_days(cost_statistic_id)
        # Consumption states are kWh; cost states are dollars. Keep consumption's
        # total authoritative for the daily-total conflict check.
        detected_consumption = detect_hourly_days(existing_consumption)
        detected_cost = detect_hourly_days(existing_cost)
        detected = {**detected_cost, **detected_consumption}
        protected = set(pending_days) | set(detected)
        for statistic_id in (consumption_statistic_id, cost_statistic_id):
            for key in self._stats_state.promoted(statistic_id):
                day = parse_day(key)
                if day is not None:
                    protected.add(day)

        promoted_totals: dict[date, float] = {
            day: info["total_kwh"] for day, info in detected.items()
        }
        promoted_cost_totals: dict[date, float] = {
            day: info["total_kwh"] for day, info in detected_cost.items()
        }
        for key, info in self._stats_state.promoted(
            consumption_statistic_id
        ).items():
            day = parse_day(key)
            if day is not None:
                promoted_totals.setdefault(
                    day, float(info.get("total_kwh", 0.0))
                )
        for key, info in self._stats_state.promoted(cost_statistic_id).items():
            day = parse_day(key)
            if day is not None:
                promoted_cost_totals.setdefault(
                    day, float(info.get("total_cost", 0.0))
                )

        # A daily retry for a promoted or pending day may confirm it, never rewrite
        # it. A changed total is an explicit conflict: reject the whole import before
        # any write instead of silently skipping the correction.
        for day, item in daily.items():
            if day not in protected or day in complete:
                continue
            stored = promoted_totals.get(day)
            if stored is None:
                # Pending with no live rows yet: recovery owns that write.
                continue
            if not values_close(
                item["kwh"],
                stored,
                abs_tol=PROMOTION_ABS_TOLERANCE_KWH,
                rel_tol=PROMOTION_REL_TOLERANCE,
            ):
                raise PsegStatisticsConflictError(
                    f"Daily total {item['kwh']:.4f} kWh for {day.isoformat()} does "
                    f"not match the promoted hourly total {stored:.4f} kWh; the "
                    "import was rejected before any statistics were written"
                )
            # Cost is an estimate and a rate change legitimately changes it. Compare
            # with the daily cents vs hourly six-decimal tolerance; never reject on
            # cost alone, and never rewrite the promoted day from a daily retry.
            stored_cost = promoted_cost_totals.get(day)
            if stored_cost is not None and not values_close(
                item["cost"],
                stored_cost,
                abs_tol=cost_tolerance(stored_cost),
                rel_tol=COST_REL_TOLERANCE,
            ):
                _LOGGER.debug(
                    "Keeping the promoted hourly cost for %s; the daily estimate "
                    "differs by more than rounding",
                    day.isoformat(),
                )

        price = float(self.client.price_per_kwh)
        existing_by_day = rows_by_day(existing_consumption)
        existing_cost_by_day = rows_by_day(existing_cost)
        promote: dict[date, Any] = {}
        for day, check in complete.items():
            cost_records = [
                {
                    "start": record["start"],
                    "kwh": round(record["kwh"] * price, STATISTICS_PRECISION),
                }
                for record in check.records
            ]
            if day_records_match(
                existing_by_day.get(day, ()), check.records
            ) and day_records_match(existing_cost_by_day.get(day, ()), cost_records):
                # A repeat poll or a stable day: nothing to write.
                continue
            promote[day] = check

        daily_consumption: dict[datetime, float] = {}
        daily_cost: dict[datetime, float] = {}
        for day, item in daily.items():
            if day in promote or day in protected:
                # Promoted/pending days are written (or kept) as full hourly sets.
                continue
            start = ny_midnight_utc(day)
            daily_consumption[start] = item["kwh"]
            daily_cost[start] = item["cost"]

        hourly_consumption = {
            day: [
                {"start": record["start"], "kwh": record["kwh"]}
                for record in check.records
            ]
            for day, check in promote.items()
        }
        hourly_cost = {
            day: [
                {
                    "start": record["start"],
                    "kwh": round(record["kwh"] * price, STATISTICS_PRECISION),
                }
                for record in check.records
            ]
            for day, check in promote.items()
        }

        if not daily_consumption and not daily_cost and not promote:
            self._log_hourly_outcome(validations, {})
            return

        consumption_stats, consumption_changed = merge_series_rows(
            existing_consumption,
            daily_consumption,
            hourly_consumption,
            protected,
            prior_consumption,
        )
        cost_stats, cost_changed = merge_series_rows(
            existing_cost,
            daily_cost,
            hourly_cost,
            protected,
            prior_cost,
        )
        if not consumption_changed and not cost_changed:
            self._log_hourly_outcome(validations, promote)
            return

        mutation = self._build_mutation(
            consumption_stats,
            cost_stats,
            promote,
            daily,
            price,
            now,
            first_start,
            consumption_statistic_id,
            cost_statistic_id,
        )
        if not self._can_mutate_statistics():
            return
        try:
            mutation_id = await self._stats_state.async_begin(mutation)
        except Exception as err:
            raise PsegStatisticsError(
                f"Could not journal the statistics mutation: {err}"
            ) from err
        if not await self._stats_state.async_wait_durable(
            refuse_outstanding=True
        ):
            raise PsegStatisticsError(
                "Statistics journal is not durable; no recorder write was made"
            )
        if not self._can_mutate_statistics():
            # The journal is durable but the operator paused/retired before any
            # recorder write; remove our own uncommitted mutation.
            await self._stats_state.async_discard(mutation_id)
            return

        consumption_metadata, cost_metadata = _statistic_metadata(clean_meter)
        async_add_external_statistics(
            self.hass, consumption_metadata, consumption_stats
        )
        async_add_external_statistics(self.hass, cost_metadata, cost_stats)
        # Bounded at the call site so nothing inside the wait can hold the locks forever.
        try:
            async with asyncio.timeout(RECORDER_COMMIT_TIMEOUT):
                await _async_wait_for_recorder_commit(self.hass)
        except TimeoutError as err:
            raise PsegStatisticsError(
                f"Recorder did not commit the statistics import within {RECORDER_COMMIT_TIMEOUT}s"
            ) from err

        if not await self._async_verify_mutation(mutation):
            raise PsegStatisticsError(
                "Recorder did not persist both statistics series; the journal was "
                "retained for the next recovery attempt"
            )
        if not self._can_mutate_statistics():
            # Rows are valid but the operator paused or the entry retired before the
            # provenance commit; recovery commits it once writes are allowed again.
            return
        await self._stats_state.async_commit(mutation_id)

        self.last_statistics_import = now.isoformat()
        self._log_hourly_outcome(validations, promote)
        _LOGGER.info(
            "Imported %d statistics rows (hourly days promoted: %d, range: %s to %s, id: %s)",
            len(consumption_stats),
            len(promote),
            consumption_stats[0]["start"].isoformat(),
            consumption_stats[-1]["start"].isoformat(),
            clean_meter,
        )

    def _build_mutation(
        self,
        consumption_stats: list[dict[str, Any]],
        cost_stats: list[dict[str, Any]],
        promote: dict[date, Any],
        daily: dict[date, dict[str, float]],
        price: float,
        now: datetime,
        first_start: datetime,
        consumption_statistic_id: str,
        cost_statistic_id: str,
    ) -> dict[str, Any]:
        """Snapshot both complete series before any recorder write."""
        return {
            "created_at": now.isoformat(),
            "first_start": first_start.isoformat(),
            "series": {
                consumption_statistic_id: [
                    [row["start"].isoformat(), row["state"], row["sum"]]
                    for row in consumption_stats
                ],
                cost_statistic_id: [
                    [row["start"].isoformat(), row["state"], row["sum"]]
                    for row in cost_stats
                ],
            },
            "promoted": (
                self._promoted_entries(
                    promote,
                    daily,
                    price,
                    now,
                    consumption_statistic_id,
                    cost_statistic_id,
                )
                if promote
                else {}
            ),
        }

    @staticmethod
    def _promoted_entries(
        promote: dict[date, Any],
        daily: dict[date, dict[str, float]],
        price: float,
        now: datetime,
        consumption_statistic_id: str,
        cost_statistic_id: str,
    ) -> dict[str, dict[str, dict[str, Any]]]:
        """Build only the promoted-day provenance; rows live in the mutation."""
        entries: dict[str, dict[str, dict[str, Any]]] = {
            consumption_statistic_id: {},
            cost_statistic_id: {},
        }
        for day, check in promote.items():
            cost_total = round(
                sum(
                    round(record["kwh"] * price, STATISTICS_PRECISION)
                    for record in check.records
                ),
                STATISTICS_PRECISION,
            )
            common = {
                "total_kwh": round(check.total_kwh, STATISTICS_PRECISION),
                "total_cost": cost_total,
                "daily_kwh": daily.get(day, {}).get("kwh"),
                "daily_cost": daily.get(day, {}).get("cost"),
                "promoted_at": now.isoformat(),
            }
            entries[consumption_statistic_id][day.isoformat()] = dict(common)
            entries[cost_statistic_id][day.isoformat()] = dict(common)
        return entries

    def _log_hourly_outcome(
        self,
        validations: dict[date, Any],
        promoted: dict[date, Any],
    ) -> None:
        """Log one line about hourly completeness (never a meter identifier)."""
        if not validations:
            return
        incomplete = [
            check for check in validations.values() if not check.complete
        ]
        reason_counts: dict[str, int] = {}
        for check in incomplete:
            if check.reason in STATISTICS_INCOMPLETE_REASONS:
                reason_counts[check.reason] = (
                    reason_counts.get(check.reason, 0) + 1
                )
        self._hourly_summary = {
            "complete_days": sum(
                1 for check in validations.values() if check.complete
            ),
            "incomplete_days": len(incomplete),
            "promoted_last_run": len(promoted),
            "reason_counts": reason_counts,
        }
        reasons = sorted(reason_counts)
        _LOGGER.info(
            "PSE&G hourly statistics: %d day(s) promoted, %d incomplete%s",
            len(promoted),
            len(incomplete),
            f" ({', '.join(reasons)})" if reasons else "",
        )

    async def async_statistics_summary(self) -> dict[str, Any]:
        """Return a small, value-free hourly-import summary for diagnostics.

        Deliberately contains no meter id, statistic id, raw point, kWh value or
        credential: only counts, fixed reason codes, the pause/recovery booleans and
        the last import timestamp.
        """
        await self._stats_state.async_load()
        clean_meter = (
            re.sub(r"[^a-z0-9_]+", "_", str(self._get_meter_id()).lower()).strip("_")
            or "meter"
        )
        consumption_statistic_id = f"{DOMAIN}:{clean_meter}_energy_consumption"
        promoted = self._stats_state.promoted(consumption_statistic_id)
        data = self.data or {}
        stored = self._hourly_summary
        reason_counts = {
            reason: int(count)
            for reason, count in (stored.get("reason_counts") or {}).items()
            if reason in STATISTICS_INCOMPLETE_REASONS
        }
        return {
            "paused": not self.statistics_imports_enabled(),
            "granularity": data.get("statistics_granularity"),
            "complete_days": int(
                data.get("hourly_complete_days", stored.get("complete_days", 0)) or 0
            ),
            "incomplete_days": int(
                data.get("hourly_incomplete_days", stored.get("incomplete_days", 0))
                or 0
            ),
            "promoted_days": len(promoted),
            "promoted_last_run": int(stored.get("promoted_last_run", 0) or 0),
            "reason_counts": reason_counts,
            "pending_recovery": self._stats_state.has_pending(),
            "last_import": self.last_statistics_import,
        }

    async def _async_verify_mutation(self, mutation: dict[str, Any]) -> bool:
        """Verify both series' rows and cumulative sums in the recorder."""
        try:
            first_start = datetime.fromisoformat(str(mutation["first_start"]))
        except (KeyError, TypeError, ValueError):
            return False
        series = mutation.get("series")
        if not isinstance(series, dict) or not series:
            return False
        for statistic_id, raw_rows in series.items():
            intended: list[tuple[datetime, float, float]] = []
            try:
                for raw_start, raw_state, raw_sum in raw_rows:
                    start = datetime.fromisoformat(str(raw_start))
                    if start.tzinfo is None:
                        return False
                    intended.append(
                        (start, float(raw_state), float(raw_sum))
                    )
            except (TypeError, ValueError):
                return False
            live = await _async_get_series_with_sums(
                self.hass, statistic_id, first_start
            )
            if not _series_rows_match(live, intended):
                _LOGGER.warning(
                    "Statistics verification failed for one series; journal retained"
                )
                return False
        return True

    async def _async_replay_mutation(self, mutation: dict[str, Any]) -> None:
        """Replay the exact journal rows for both series, then wait for commit."""
        series = mutation.get("series") or {}
        if not isinstance(series, dict) or not series:
            raise PsegStatisticsError("Pending statistics journal has no series")
        for statistic_id, raw_rows in series.items():
            clean_meter = statistic_id.removeprefix(f"{DOMAIN}:").removesuffix(
                "_energy_consumption"
            ).removesuffix("_energy_cost")
            consumption_metadata, cost_metadata = _statistic_metadata(clean_meter)
            metadata = (
                consumption_metadata
                if statistic_id.endswith("_energy_consumption")
                else cost_metadata
            )
            stats = []
            for raw_start, raw_state, raw_sum in raw_rows:
                start = datetime.fromisoformat(str(raw_start))
                if start.tzinfo is None:
                    start = start.replace(tzinfo=UTC)
                stats.append(
                    {
                        "start": start,
                        "state": float(raw_state),
                        "sum": float(raw_sum),
                    }
                )
            async_add_external_statistics(self.hass, metadata, stats)
        try:
            async with asyncio.timeout(RECORDER_COMMIT_TIMEOUT):
                await _async_wait_for_recorder_commit(self.hass)
        except TimeoutError as err:
            raise PsegStatisticsError(
                "Recorder did not commit the replayed statistics within "
                f"{RECORDER_COMMIT_TIMEOUT}s"
            ) from err

    async def _async_recover_pending(self) -> int:
        """Verify, replay and commit unfinished mutations before new work.

        Both series and their cumulative sums must match the journal. If they do,
        only the provenance commit was missing. Otherwise the exact journal rows are
        replayed idempotently and verified again. A mismatch or a pause leaves the
        journal in place for the next attempt.
        """
        if not await self._stats_state.async_wait_durable(
            refuse_outstanding=True
        ):
            raise PsegStatisticsError(
                "Statistics journal is not durable yet; recovery refused"
            )
        pending = self._stats_state.pending_mutations()
        if not pending:
            return 0
        if not self._can_mutate_statistics():
            return 0

        recovered = 0
        for mutation_id, mutation in pending.items():
            if not self._can_mutate_statistics():
                return recovered
            if await self._async_verify_mutation(mutation):
                if not self._can_mutate_statistics():
                    return recovered
                await self._stats_state.async_commit(mutation_id)
                recovered += 1
                continue

            if not self._can_mutate_statistics():
                return recovered
            await self._async_replay_mutation(mutation)
            if not await self._async_verify_mutation(mutation):
                raise PsegStatisticsError(
                    "Replayed statistics did not persist both series; journal retained"
                )
            if not self._can_mutate_statistics():
                return recovered
            await self._stats_state.async_commit(mutation_id)
            recovered += 1
        if recovered:
            _LOGGER.info(
                "Recovered %d pending statistics mutation(s)", recovered
            )
        return recovered

    async def async_backfill_history(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> int:
        """Fetch and import historical data into Long-Term Statistics."""
        if not self.statistics_imports_enabled():
            _LOGGER.warning(
                "Statistics imports are disabled for this PSE&G entry; backfill skipped"
            )
            return 0

        now = dt_util.now()
        if not end_date:
            end_date_str = now.strftime("%Y-%m-%d")
        elif hasattr(end_date, "strftime"):
            end_date_str = end_date.strftime("%Y-%m-%d")
        else:
            end_date_str = str(end_date)

        if not start_date:
            start_dt = now - timedelta(days=730)
            start_date_str = start_dt.strftime("%Y-%m-%d")
        elif hasattr(start_date, "strftime"):
            start_date_str = start_date.strftime("%Y-%m-%d")
        else:
            start_date_str = str(start_date)

        _LOGGER.info(
            "Starting PSE&G historical backfill from %s to %s...",
            start_date_str,
            end_date_str,
        )

        async with self._update_lock:
            try:
                records = await self.hass.async_add_executor_job(
                    self.client.fetch_history_range,
                    start_date_str,
                    end_date_str,
                    90,
                )
            finally:
                # Auth-only handoff: a backfill's token GET can complete a bounded
                # renewal, and its jar must survive a later chart failure or a stop.
                self._persist_auth_metadata()
                self._persist_confirmed_session()

            if not records:
                _LOGGER.warning(
                    "No historical records returned from PSE&G for %s to %s",
                    start_date_str,
                    end_date_str,
                )
                return 0

            meter_id = self._get_meter_id()
            await self.async_record_statistics(records, meter_id=meter_id)
            if not self._can_mutate_statistics():
                _LOGGER.debug(
                    "PSE&G backfill stopped after the entry was paused or retired"
                )
                return 0

        # Statistics only: sensor values (latest_*, history_14d) stay from the regular
        # poll. A backfill of a past range must not make "latest" show old readings.
        _LOGGER.info("Completed PSE&G backfill: imported %d days of statistics", len(records))
        return len(records)

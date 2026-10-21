"""DataUpdateCoordinator for the PSE&G Energy integration."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import logging
import re
from typing import Any
import zoneinfo

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
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.recorder import DATA_INSTANCE
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util
import requests

from .const import (
    CONF_PRICE_PER_KWH,
    DEFAULT_PRICE_PER_KWH,
    DEFAULT_SCAN_INTERVAL_HOURS,
    DOMAIN,
    KEEPALIVE_INTERVAL_MINUTES,
)
from .pseg_client import (
    PsegClient,
    PsegOktaSessionExpired,
    PsegTransientError,
)

_LOGGER = logging.getLogger(__name__)


class PsegStatisticsError(HomeAssistantError):
    """Recorder query failed; the import is aborted to keep the sum chain intact."""


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


def _merge_and_chain(
    existing: list[tuple[datetime, float | None]],
    new: list[StatisticData],
    prior_sum: float | None,
) -> list[StatisticData]:
    """Merge stored daily values with newly fetched ones and recompute every sum.

    Every stored row from the window start onward is rewritten: fetched days replace
    the stored value, days the fetch did not return (a missing day inside the window,
    or newer rows after it) keep their stored value. One chain over the union means a
    partial fetch can never leave a row whose sum was built on a different baseline.
    """
    by_start: dict[datetime, float | None] = dict(existing)
    for stat in new:
        by_start[stat["start"]] = stat["state"]

    running = float(prior_sum or 0.0)
    out: list[StatisticData] = []
    for start in sorted(by_start):
        state = by_start[start]
        running += state or 0.0
        out.append(StatisticData(start=start, state=state, sum=round(running, 2)))
    return out


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


def build_external_statistics(
    records: list[dict[str, Any]],
    meter_id: str,
    prior_consumption_sum: float | None = None,
    prior_cost_sum: float | None = None,
    price_per_kwh: float = DEFAULT_PRICE_PER_KWH,
) -> tuple[StatisticMetaData, list[StatisticData], StatisticMetaData, list[StatisticData]]:
    """Build consumption and cost external statistic records with running cumulative sums."""
    clean_meter = (
        re.sub(r"[^a-z0-9_]+", "_", str(meter_id).lower()).strip("_") or "meter"
    )

    consumption_statistic_id = f"{DOMAIN}:{clean_meter}_energy_consumption"
    cost_statistic_id = f"{DOMAIN}:{clean_meter}_energy_cost"

    consumption_metadata = StatisticMetaData(
        has_mean=False,
        mean_type=StatisticMeanType.NONE,
        has_sum=True,
        name="PSE&G Electricity Consumption",
        source=DOMAIN,
        statistic_id=consumption_statistic_id,
        unit_class="energy",
        unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
    )

    cost_metadata = StatisticMetaData(
        has_mean=False,
        mean_type=StatisticMeanType.NONE,
        has_sum=True,
        name="PSE&G Electricity Cost (Estimated)",
        source=DOMAIN,
        statistic_id=cost_statistic_id,
        unit_class=None,
        unit_of_measurement="USD",
    )

    if not records:
        return consumption_metadata, [], cost_metadata, []

    sorted_records = sorted(records, key=lambda x: x["date"])
    tz = zoneinfo.ZoneInfo("America/New_York")

    running_consumption = float(prior_consumption_sum or 0.0)
    running_cost = float(prior_cost_sum or 0.0)

    consumption_stats: list[StatisticData] = []
    cost_stats: list[StatisticData] = []

    for r in sorted_records:
        date_str = r["date"]
        kwh = float(r.get("kwh") or 0.0)
        cost = float(r.get("cost") or round(kwh * price_per_kwh, 2))

        local_dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=tz)
        start_utc = dt_util.as_utc(local_dt)

        running_consumption += kwh
        running_cost += cost

        consumption_stats.append(
            StatisticData(
                start=start_utc,
                state=kwh,
                sum=round(running_consumption, 2),
            )
        )
        cost_stats.append(
            StatisticData(
                start=start_utc,
                state=cost,
                sum=round(running_cost, 2),
            )
        )

    return consumption_metadata, consumption_stats, cost_metadata, cost_stats


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
        self._unsub_keepalive: Callable[[], None] | None = None
        # Set on unload. A keepalive/poll still in the executor at that point belongs
        # to a dead coordinator and must not write to the entry or start reauth.
        self._stopped = False
        # The jar this coordinator loaded or last wrote. If entry.data["cookies"]
        # differs, reauth/reconfigure replaced it and our in-memory jar is stale.
        self._jar_baseline = config_entry.data.get("cookies") if config_entry else None
        # Serializes portal fetch + statistics import for poll, refresh and backfill.
        self._update_lock = asyncio.Lock()
        # Serializes baseline read -> import -> commit so concurrent imports chain.
        self._stats_lock = asyncio.Lock()

        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=timedelta(hours=DEFAULT_SCAN_INTERVAL_HOURS),
        )

    def start_keepalive(self) -> None:
        """Start recurring 30-minute keepalive."""
        if self._unsub_keepalive is None:
            self._unsub_keepalive = async_track_time_interval(
                self.hass,
                self._async_keepalive,
                timedelta(minutes=KEEPALIVE_INTERVAL_MINUTES),
            )

    def stop_keepalive(self) -> None:
        """Cancel recurring keepalive timer and retire this coordinator's session."""
        self._stopped = True
        if self._unsub_keepalive is not None:
            self._unsub_keepalive()
            self._unsub_keepalive = None

    async def _async_keepalive(self, _now: datetime) -> None:
        """Run keepalive check and persist rotated cookies."""
        _LOGGER.debug("Running 30-minute PSE&G keepalive")
        expired = False
        try:
            await self.hass.async_add_executor_job(self.client.keepalive)
        except PsegOktaSessionExpired:
            expired = True
        except Exception as err:
            _LOGGER.debug("Error during keepalive check: %s", err)

        if self._is_stale():
            _LOGGER.debug("Ignoring keepalive result from a retired PSE&G session")
            return

        await self._async_persist_cookies()

        if (expired or self.client.okta_session_expired_at) and not self.auth_required:
            self.auth_required = True
            self.status = "auth_required"
            self._raise_auth_issues("Okta session expired during background keepalive")
            # Same outcome as a poll raising ConfigEntryAuthFailed: ask the user now
            # instead of waiting up to a full poll interval. Guarded by auth_required so
            # it fires once per expiry; HA also refuses a second concurrent reauth flow.
            if self.config_entry:
                self.config_entry.async_start_reauth(self.hass)
            self.async_update_listeners()

    def _is_stale(self) -> bool:
        """Return True if this coordinator was unloaded or its jar was replaced."""
        if self._stopped:
            return True
        return bool(
            self.config_entry
            and self.config_entry.data.get("cookies") != self._jar_baseline
        )

    async def _async_persist_cookies(self) -> None:
        """Persist rotated session cookies to entry.data without logging values."""
        if not self.config_entry:
            return
        # Executor: export takes the client's portal lock, which a long backfill may hold.
        exported = await self.hass.async_add_executor_job(self.client.export_cookies)
        if not exported:
            return
        if self._is_stale():
            _LOGGER.debug("Not persisting cookies from a retired PSE&G session")
            return
        current_cookies = self.config_entry.data.get("cookies")
        if current_cookies != exported:
            _LOGGER.debug("Persisting rotated session cookies to entry.data")
            new_data = dict(self.config_entry.data)
            new_data["cookies"] = exported
            self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)
        self._jar_baseline = exported

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

    def _raise_auth_issues(self, err_msg: str) -> None:
        """Raise persistent notification and repairs issue when authentication is required."""
        entry_id = self.config_entry.entry_id if self.config_entry else "default"
        msg = (
            "Your PSE&G session has expired. "
            "Please go to **Settings > Devices & Services > PSE&G** and click **Reconfigure** to paste a fresh Okta session cookie."
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
                await self._async_persist_cookies()

                if "history_14d" in data and data["history_14d"]:
                    meter_id = self._get_meter_id(data)
                    try:
                        await self.async_record_statistics(
                            data["history_14d"], meter_id=meter_id
                        )
                    except Exception as stat_err:
                        _LOGGER.warning("Could not record statistics into LTS: %s", stat_err)

            self.next_update_time = dt_util.utcnow() + self.update_interval
            data["next_update"] = self.next_update_time.isoformat()
            self._last_valid_data = data
            self.last_successful_update = dt_util.utcnow().isoformat()
            self.auth_required = False
            self.status = "connected"
            self._dismiss_auth_issues()
            return data
        except PsegOktaSessionExpired as err:
            self.auth_required = True
            self.status = "auth_required"
            self._raise_auth_issues(str(err))
            raise ConfigEntryAuthFailed(
                "PSE&G Okta session expired. Please re-authenticate under Settings > Devices & Services > PSE&G."
            ) from err
        except (PsegTransientError, requests.RequestException) as err:
            self.status = "error"
            raise UpdateFailed(f"Transient error communicating with PSE&G: {err}") from err
        except Exception as err:
            self.status = "error"
            raise UpdateFailed(f"Error communicating with PSE&G: {err}") from err

    async def async_record_statistics(
        self, records: list[dict[str, Any]], meter_id: str | None = None
    ) -> None:
        """Import daily energy consumption and cost records as external statistics."""
        if not records:
            return

        async with self._stats_lock:
            await self._async_record_statistics_locked(records, meter_id)

    async def _async_record_statistics_locked(
        self, records: list[dict[str, Any]], meter_id: str | None
    ) -> None:
        """Import statistics; caller holds _stats_lock."""
        meter_id = meter_id or self._get_meter_id()
        clean_meter = (
            re.sub(r"[^a-z0-9_]+", "_", str(meter_id).lower()).strip("_") or "meter"
        )
        consumption_statistic_id = f"{DOMAIN}:{clean_meter}_energy_consumption"
        cost_statistic_id = f"{DOMAIN}:{clean_meter}_energy_cost"

        sorted_records = sorted(records, key=lambda x: x["date"])
        tz = zoneinfo.ZoneInfo("America/New_York")

        first_date_str = sorted_records[0]["date"]
        first_local_dt = datetime.strptime(first_date_str, "%Y-%m-%d").replace(tzinfo=tz)
        first_start_utc = dt_util.as_utc(first_local_dt)

        # Baseline running sum strictly before the first start timestamp
        prior_consumption = await _async_get_last_stat_before(
            self.hass, consumption_statistic_id, first_start_utc
        )
        prior_cost = await _async_get_last_stat_before(
            self.hass, cost_statistic_id, first_start_utc
        )

        (
            consumption_metadata,
            consumption_stats,
            cost_metadata,
            cost_stats,
        ) = build_external_statistics(
            records=sorted_records,
            meter_id=meter_id,
            prior_consumption_sum=prior_consumption,
            prior_cost_sum=prior_cost,
            price_per_kwh=self.client.price_per_kwh,
        )

        # Stored rows from the window start onward were chained off the old baseline:
        # days missing from this fetch and rows newer than it (e.g. a backfill ending
        # before the newest poll). Merge and re-chain them so the sum never steps back.
        # All reads happen before any write, so a failed read imports nothing.
        existing_consumption = await _async_get_stats_from(
            self.hass, consumption_statistic_id, first_start_utc
        )
        existing_cost = await _async_get_stats_from(self.hass, cost_statistic_id, first_start_utc)
        consumption_stats = _merge_and_chain(
            existing_consumption, consumption_stats, prior_consumption
        )
        cost_stats = _merge_and_chain(existing_cost, cost_stats, prior_cost)

        async_add_external_statistics(self.hass, consumption_metadata, consumption_stats)
        async_add_external_statistics(self.hass, cost_metadata, cost_stats)
        # Bounded at the call site so nothing inside the wait can hold the locks forever.
        try:
            async with asyncio.timeout(RECORDER_COMMIT_TIMEOUT):
                await _async_wait_for_recorder_commit(self.hass)
        except TimeoutError as err:
            raise PsegStatisticsError(
                f"Recorder did not commit the statistics import within {RECORDER_COMMIT_TIMEOUT}s"
            ) from err
        _LOGGER.info(
            "Imported %d daily external statistics (range: %s to %s, id: %s)",
            len(sorted_records),
            sorted_records[0]["date"],
            sorted_records[-1]["date"],
            clean_meter,
        )

    async def async_backfill_history(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> int:
        """Fetch and import historical data into Long-Term Statistics."""
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
            records = await self.hass.async_add_executor_job(
                self.client.fetch_history_range,
                start_date_str,
                end_date_str,
                90,
            )

            if not records:
                _LOGGER.warning(
                    "No historical records returned from PSE&G for %s to %s",
                    start_date_str,
                    end_date_str,
                )
                return 0

            meter_id = self._get_meter_id()
            await self.async_record_statistics(records, meter_id=meter_id)

        # Statistics only: sensor values (latest_*, history_14d) stay from the regular
        # poll. A backfill of a past range must not make "latest" show old readings.
        _LOGGER.info("Completed PSE&G backfill: imported %d days of statistics", len(records))
        return len(records)

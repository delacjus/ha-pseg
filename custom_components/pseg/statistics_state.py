"""Durable statistics provenance, the write journal and entry-level ownership.

A config entry can outlive a coordinator (unload, reload, reauth). Statistics work
must therefore be serialized per *entry*, not per coordinator, and a retired
coordinator must stop before its next recorder or Store mutation. The runtime below
is shared by every coordinator built for the same entry and carries the shared
Store, one lock and a generation token.

Before any recorder write the exact rows for **both** series (daily corrections and
hourly promotions, with their cumulative sums) are saved as one pending mutation.
The coordinator waits for that save to complete; recovery refuses to replay an
in-memory mutation while a physical save is outstanding or failed. The rows move
to the promoted map only after both series and their sums were read back from the
recorder. A partial write, a swallowed recorder error, a commit barrier timeout or
a cancelled save leaves the journal in place for an idempotent replay. The journal
never contains authentication data, and it is bounded.
"""

from __future__ import annotations

import asyncio
import copy
from datetime import date, datetime
import json
import logging
from typing import Any
import uuid

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .statistics_hourly import ny_day_of, parse_day

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 2
# One mutation normally holds a 14-day window (at most a few hundred rows per series
# when older daily rows are re-chained). The cap refuses a journal it cannot bound.
MAX_PENDING_ROWS = 20000
MAX_PENDING_MUTATIONS = 2
# Provenance for older days is also detectable from the stored hourly rows.
MAX_PROMOTED_DAYS = 800
# A cancelled awaiting task does not cancel executor/file I/O. Hold the entry lock
# (the caller is still inside it) until the physical save finishes, bounded.
STORE_SAVE_DRAIN_TIMEOUT = 5.0
# Recovery must not replay an in-memory mutation before the physical save that
# contains it is durable. A save already outstanding when recovery starts is
# refused immediately; a dirty store with no outstanding task gets this bounded
# retry window.
DURABILITY_WAIT_TIMEOUT = 5.0
READBACK_TIMEOUT = 5.0

_PROMOTED_KEYS = ("total_kwh", "total_cost", "daily_kwh", "daily_cost", "promoted_at")


class StorePersistenceError(RuntimeError):
    """The saved snapshot was not found byte-for-byte on disk."""


def _read_json_file(path: str) -> Any:
    """Read one persisted JSON document; callers never log its content."""
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def _consume_task_result(task: asyncio.Task[None]) -> None:
    """Retrieve a detached save exception so HA does not report an unhandled job."""
    if task.cancelled():
        return
    try:
        task.exception()
    except Exception:
        return


class StatisticsEntryRuntime:
    """Shared per-entry lock, Store and ownership generation.

    ``activate`` is called by each new coordinator. ``retire`` invalidates the
    current generation when the entry unloads; an in-flight operation notices at
    its next ownership check and performs no further mutation. A new coordinator
    after unload activates the next generation, so it can continue.
    """

    def __init__(self, hass: HomeAssistant, entry_id: str) -> None:
        """Create the entry runtime and its shared store."""
        self.entry_id = entry_id
        self.store = StatisticsStateStore(hass, entry_id)
        self.lock = asyncio.Lock()
        self._generation = 0
        self._retired = True

    def activate(self) -> int:
        """Return a token for a live coordinator."""
        self._retired = False
        return self._generation

    def is_current(self, token: int) -> bool:
        """Return True while this token may still mutate."""
        return not self._retired and token == self._generation

    def retire(self, token: int | None = None) -> None:
        """Invalidate the current generation (idempotent for an old token)."""
        if token is not None and token != self._generation:
            return
        self._generation += 1
        self._retired = True


class StatisticsStateStore:
    """Store promoted days and one complete pending mutation per series pair."""

    def __init__(self, hass: HomeAssistant, entry_id: str) -> None:
        """Create the store for one config entry (auth data is never written)."""
        self._hass = hass
        self._store = Store(
            hass,
            STORAGE_VERSION,
            f"pseg.statistics.{entry_id}",
            atomic_writes=True,
        )
        self._data: dict[str, Any] = {
            "version": STORAGE_VERSION,
            "promoted": {},
            "pending": {},
        }
        self._loaded = False
        self._load_failed = False
        self._io_lock = asyncio.Lock()
        self._revision = 0
        self._saved_revision = 0
        self._save_task: asyncio.Task[None] | None = None
        self._save_target = -1

    async def async_load(self) -> None:
        """Load the store once from the actual Store path, not a cached load."""
        if self._loaded:
            return
        async with self._io_lock:
            if self._loaded:
                return
            wrapper = None
            try:
                async with asyncio.timeout(READBACK_TIMEOUT):
                    wrapper = await self._hass.async_add_executor_job(
                        _read_json_file, self._store.path
                    )
            except FileNotFoundError:
                wrapper = None
            except Exception:
                # Do not treat an unreadable/malformed existing file as an empty
                # durable store: refusing writes preserves the old good disk.
                self._load_failed = True
                _LOGGER.warning(
                    "Could not read PSE&G statistics provenance; writes refused"
                )
                wrapper = None

            loaded = None
            if isinstance(wrapper, dict) and wrapper.get("key") == self._store.key:
                loaded = wrapper.get("data")

            if (
                isinstance(loaded, dict)
                and loaded.get("version") == STORAGE_VERSION
                and isinstance(loaded.get("promoted"), dict)
                and isinstance(loaded.get("pending"), dict)
            ):
                self._data = loaded
            elif isinstance(loaded, dict) and isinstance(loaded.get("series"), dict):
                # Version 1 (never deployed) kept promoted days per statistic id.
                self._data = {
                    "version": STORAGE_VERSION,
                    "promoted": {
                        statistic_id: dict(series.get("promoted") or {})
                        for statistic_id, series in loaded["series"].items()
                        if isinstance(series, dict)
                    },
                    "pending": {},
                }
                _LOGGER.warning(
                    "Dropped version-1 pending statistics journal; "
                    "recorder rows remain the recovery source"
                )
            elif wrapper is not None:
                # Existing bytes with an unknown shape: preserve them and refuse
                # writes instead of replacing a possibly good journal.
                self._load_failed = True
                _LOGGER.warning(
                    "Unrecognized PSE&G statistics provenance; writes refused"
                )
            self._data.setdefault("version", STORAGE_VERSION)
            self._data.setdefault("promoted", {})
            self._data.setdefault("pending", {})
            # Loaded bytes are durable by definition.
            self._revision = 0
            self._saved_revision = 0
            self._save_task = None
            self._save_target = -1
            self._loaded = True

    def promoted(self, statistic_id: str) -> dict[str, dict[str, Any]]:
        """Return the promoted-day map for one statistic id (a copy)."""
        return dict(self._data["promoted"].get(statistic_id) or {})

    def pending_mutations(self) -> dict[str, dict[str, Any]]:
        """Return every unfinished mutation (a shallow copy)."""
        return dict(self._data["pending"])

    def has_pending(self) -> bool:
        """Return True when a mutation is waiting for verification or replay."""
        return bool(self._data["pending"])

    def pending_days(self, statistic_id: str | None = None) -> set[date]:
        """Return days mentioned by pending mutations (newest state)."""
        days: set[date] = set()
        for mutation in self._data["pending"].values():
            promoted = mutation.get("promoted") or {}
            if statistic_id is not None:
                for key in (promoted.get(statistic_id) or {}):
                    day = parse_day(key)
                    if day is not None:
                        days.add(day)
                rows = (mutation.get("series") or {}).get(statistic_id) or []
            else:
                for per_series in promoted.values():
                    for key in per_series:
                        day = parse_day(key)
                        if day is not None:
                            days.add(day)
                rows = [
                    row
                    for per_series in (mutation.get("series") or {}).values()
                    for row in per_series
                ]
            for row in rows:
                try:
                    start = datetime.fromisoformat(str(row[0]))
                except (TypeError, ValueError, IndexError):
                    continue
                if start.tzinfo is None:
                    continue
                days.add(ny_day_of(start))
        return days

    def _mark_dirty(self) -> None:
        """Mark the in-memory snapshot as not yet known-durable."""
        self._revision += 1

    def _start_save(self) -> None:
        """Start one physical save of a deep-copied snapshot."""
        snapshot = copy.deepcopy(self._data)
        target = self._revision

        async def _save_under_lock() -> None:
            async with self._io_lock:
                # Store.async_save may swallow a real WriteError and return. It is
                # not proof of durability: read the actual Store path back and
                # require the exact saved snapshot/wrapper identity before advancing.
                await self._store.async_save(snapshot)
                await self._async_verify_persisted(snapshot)

        self._save_target = target
        self._save_task = asyncio.create_task(_save_under_lock())
        self._save_task.add_done_callback(_consume_task_result)

    async def _async_verify_persisted(self, snapshot: dict[str, Any]) -> None:
        """Require the exact snapshot on disk, independent of Store caches."""
        path = self._store.path
        try:
            async with asyncio.timeout(READBACK_TIMEOUT):
                persisted = await self._hass.async_add_executor_job(
                    _read_json_file, path
                )
        except Exception:
            raise StorePersistenceError from None
        if not isinstance(persisted, dict):
            raise StorePersistenceError
        if (
            persisted.get("version") != self._store.version
            or persisted.get("minor_version") != self._store.minor_version
            or persisted.get("key") != self._store.key
            or persisted.get("data") != snapshot
        ):
            raise StorePersistenceError

    async def async_wait_durable(
        self,
        *,
        refuse_outstanding: bool = False,
        drain_on_cancel: bool = False,
    ) -> bool:
        """Wait boundedly until the current in-memory state is on disk.

        ``refuse_outstanding`` is used by recovery: if a cancelled/blocked save
        task is already running, recovery refuses immediately instead of replaying
        the in-memory pending mutation. The next attempt re-checks the completed
        task. A dirty store with no outstanding task gets one bounded save attempt.
        """
        if self._load_failed:
            return False
        if (
            refuse_outstanding
            and self._save_task is not None
            and not self._save_task.done()
        ):
            return False
        if self._save_task is None:
            if self._saved_revision >= self._revision:
                return True
            self._start_save()

        task = self._save_task
        target = self._save_target
        if task is None:
            return self._saved_revision >= self._revision
        try:
            async with asyncio.timeout(DURABILITY_WAIT_TIMEOUT):
                await asyncio.wait({task})
        except asyncio.CancelledError:
            if drain_on_cancel:
                try:
                    async with asyncio.timeout(STORE_SAVE_DRAIN_TIMEOUT):
                        await asyncio.wait({task})
                except (TimeoutError, asyncio.CancelledError):
                    _LOGGER.error(
                        "Statistics store save still running after cancellation; "
                        "recovery will refuse until it is durable"
                    )
            if task.done():
                try:
                    task.exception()
                except Exception:
                    pass
            raise
        except TimeoutError:
            return False
        if not task.done():
            return False
        try:
            await task
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed write is a refusal
            _LOGGER.error("Statistics store save failed; journal retained")
            if self._save_task is task:
                self._save_task = None
            return False
        if self._save_task is task:
            self._save_task = None
        self._saved_revision = max(self._saved_revision, target)
        if self._saved_revision >= self._revision:
            return True
        # A newer snapshot appeared while that save was in flight; one more
        # bounded round is enough for our single-writer entry lock.
        return await self.async_wait_durable(
            refuse_outstanding=refuse_outstanding,
            drain_on_cancel=drain_on_cancel,
        )

    async def async_begin(self, mutation: dict[str, Any]) -> str:
        """Persist both series' exact rows and promoted maps before any write."""
        series = mutation.get("series")
        if not isinstance(series, dict) or not series:
            raise ValueError("Statistics mutation has no series rows")
        row_count = 0
        for statistic_id, rows in series.items():
            if not isinstance(rows, list) or not rows:
                raise ValueError(
                    f"Statistics mutation series {statistic_id} has no rows"
                )
            for row in rows:
                if not isinstance(row, (list, tuple)) or len(row) != 3:
                    raise ValueError("Statistics mutation rows must be [start, state, sum]")
            row_count += len(rows)
        if row_count > MAX_PENDING_ROWS:
            raise ValueError(
                f"Statistics mutation has {row_count} rows, above {MAX_PENDING_ROWS}"
            )
        if len(self._data["pending"]) >= MAX_PENDING_MUTATIONS:
            raise ValueError("Too many unfinished statistics mutations")

        mutation_id = uuid.uuid4().hex
        self._data["pending"][mutation_id] = mutation
        self._mark_dirty()
        if not await self.async_wait_durable(drain_on_cancel=True):
            # Keep the mutation in memory: recovery will check durability again
            # and must never replay it before the journal bytes persist.
            raise RuntimeError("Statistics journal is not durable")
        return mutation_id

    async def async_commit(self, mutation_id: str) -> None:
        """Move verified promoted days out of the journal, then clear it durably."""
        mutation = self._data["pending"].pop(mutation_id, None)
        if mutation is None:
            return
        for statistic_id, days in (mutation.get("promoted") or {}).items():
            promoted = self._data["promoted"].setdefault(statistic_id, {})
            for day_iso, record in days.items():
                promoted[day_iso] = {
                    key: record[key] for key in _PROMOTED_KEYS if key in record
                }
            self._trim_promoted(promoted)
        self._mark_dirty()
        try:
            durable = await self.async_wait_durable()
        except asyncio.CancelledError:
            self._data["pending"][mutation_id] = mutation
            self._mark_dirty()
            raise
        except Exception:
            self._data["pending"][mutation_id] = mutation
            self._mark_dirty()
            raise
        if not durable:
            # The recorder rows are verified, but provenance is not durable yet.
            # Re-arm the journal so recovery can complete the commit later.
            self._data["pending"][mutation_id] = mutation
            self._mark_dirty()
            raise RuntimeError("Statistics provenance commit is not durable")

    async def async_discard(self, mutation_id: str) -> None:
        """Drop an uncommitted mutation that wrote nothing to the recorder."""
        mutation = self._data["pending"].pop(mutation_id, None)
        if mutation is None:
            return
        self._mark_dirty()
        try:
            durable = await self.async_wait_durable()
        except asyncio.CancelledError:
            self._data["pending"][mutation_id] = mutation
            self._mark_dirty()
            raise
        if not durable:
            # Keep the uncommitted mutation visible rather than leaving a
            # non-durable in-memory deletion; recovery will re-check durability.
            self._data["pending"][mutation_id] = mutation
            self._mark_dirty()

    async def _async_save(self) -> None:
        """Await durable persistence of the current snapshot (normal callers)."""
        while True:
            if self._save_task is None:
                if self._saved_revision >= self._revision:
                    return
                self._start_save()
            task = self._save_task
            target = self._save_target
            try:
                await asyncio.wait({task})
            except asyncio.CancelledError:
                # A cancelled await does not cancel executor/file I/O. Drain it
                # while the caller still holds the entry lock, bounded.
                try:
                    async with asyncio.timeout(STORE_SAVE_DRAIN_TIMEOUT):
                        await asyncio.wait({task})
                except (TimeoutError, asyncio.CancelledError):
                    _LOGGER.error(
                        "Statistics store save still running after cancellation; "
                        "recovery will refuse until it is durable"
                    )
                if task.done():
                    try:
                        task.exception()
                    except Exception:
                        pass
                raise
            try:
                await task
            except Exception:
                if self._save_task is task:
                    self._save_task = None
                raise
            if self._save_task is task:
                self._save_task = None
            self._saved_revision = max(self._saved_revision, target)
            if self._saved_revision >= self._revision:
                return

    @staticmethod
    def _trim_promoted(promoted: dict[str, Any]) -> None:
        excess = len(promoted) - MAX_PROMOTED_DAYS
        if excess <= 0:
            return
        for key in sorted(promoted)[:excess]:
            promoted.pop(key, None)

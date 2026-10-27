"""Physical fault-point substrate and semantic barrier inventory for statistics tests.

Provides a named semantic barrier inventory covering Store write/readback,
recorder import and commit barriers for both consumption and cost series,
and awaited operations in recording and recovery.

Also provides PhysicalDurabilitySubstrate and StatsFaultHarness to ensure
faults target physical disk durability (SQLite database and HA Store JSON)
rather than in-memory mocks.

Label-to-boundary map (production is read-only; HA 2026.10.2):
* STORE_WRITE_PENDING / STORE_WRITE_COMMIT: Store._write_data(wrapper), on
  the executor immediately before its atomic JSON write. wrapper.data.pending
  selects pending versus cleared/provenance write. Memory already changed;
  disk still has the preceding snapshot. async_discard also clears pending.
* STORE_READBACK: StatisticsStateStore._async_verify_persisted(snapshot),
  AFTER Store.async_save returned, immediately before its real disk read.
  It is not the initial load or a warm Store cache read.
* RECORDER_IMPORT_{CONSUMPTION,COST}: immediately before the corresponding
  synchronous async_add_external_statistics queue dispatch. Cost-first buffers
  consumption until the cost dispatch; it never bypasses the real importer.
* RECORDER_COMMIT_{CONSUMPTION,COST}: on the recorder worker at each separate
  ImportStatisticsTask.run entry. HA calls import_statistics -> session_scope
  -> SQL writes and commit, separately per series. These are pre-transaction
  fault boundaries, not claims of SQL COMMIT having completed. A failed task is
  omitted and its exception delivered after queue drain; the other task runs.
* RECORDER_COMMIT_BARRIER and BEFORE/AFTER_RECORDER_COMMIT: the shared
  coordinator _async_wait_for_recorder_commit await, NOT a per-series commit.
* RECORDER_READBACK_{CONSUMPTION,COST}: before each _async_get_series_with_sums
  await in _async_verify_mutation (recording and recovery).
* BEFORE/AFTER_STORE_LOAD: StatisticsStateStore.async_load await, including
  its loaded-cache fast path; physical post-save verification is separate.
* BEFORE/AFTER_RECOVER_PENDING: coordinator._async_recover_pending await.
* BEFORE/AFTER_BASELINE_READS: EACH of the four production baseline awaits,
  in source order: _async_get_last_stat_before consumption, cost, then
  _async_get_stats_from consumption, cost. No prior read escapes these gates.
* BEFORE/AFTER_JOURNAL_SAVE, JOURNAL_COMMIT, JOURNAL_DISCARD: respectively
  async_begin, async_commit, async_discard awaits. Commit labels also apply in
  recovery; discard is reached after journaling when the owner retires.
* BEFORE/AFTER_RECORDER_IMPORT: synchronous dispatch visit counters only;
  async pause/cancel/timeout actions are explicitly inapplicable there.
* BEFORE/AFTER_MUTATION_VERIFY: _async_verify_mutation await in either path.
* BEFORE/AFTER_RECOVERY_DURABILITY_WAIT, RECOVERY_VERIFY, RECOVERY_REPLAY,
  RECOVERY_COMMIT: the corresponding async_wait_durable, _async_verify_mutation,
  _async_replay_mutation and async_commit awaits ONLY inside recovery. An empty
  recovery still awaits durability, but does not verify/replay/commit.

Live boundary tests inspect disk at write/readback gates, prior-read arrival,
separate physical series transactions, and discard. Inventory counts alone are
not evidence that the adapter reaches those production boundaries.

"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import CancelledError as WorkerCancelledError
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any
from unittest.mock import patch

from homeassistant.components.recorder import Recorder, get_instance
from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.components.recorder.tasks import ImportStatisticsTask
from homeassistant.core import HomeAssistant
from homeassistant.helpers import recorder as recorder_helper
from homeassistant.helpers.recorder import DATA_INSTANCE, DATA_RECORDER
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_recorder_block_till_done,
)

from custom_components.pseg import coordinator as coord_mod
from custom_components.pseg.const import DOMAIN
from custom_components.pseg.coordinator import (
    PsegDataUpdateCoordinator,
)

_LOGGER = logging.getLogger(__name__)

# Default timeout bound for any held/stalled barrier (must be <= 10.0s)
DEFAULT_BARRIER_TIMEOUT = 10.0

# -----------------------------------------------------------------------------
# Named Semantic Barriers
# -----------------------------------------------------------------------------

# Physical Store Barriers
STORE_READBACK = "store_readback"
STORE_WRITE_PENDING = "store_write_pending"
STORE_WRITE_COMMIT = "store_write_commit"

# Per-Series Recorder Import & Commit Barriers
RECORDER_IMPORT_CONSUMPTION = "recorder_import_consumption"
RECORDER_IMPORT_COST = "recorder_import_cost"
RECORDER_COMMIT_CONSUMPTION = "recorder_commit_consumption"
RECORDER_COMMIT_COST = "recorder_commit_cost"
RECORDER_COMMIT_BARRIER = "recorder_commit_barrier"
RECORDER_READBACK_CONSUMPTION = "recorder_readback_consumption"
RECORDER_READBACK_COST = "recorder_readback_cost"

# Awaited Operations in Recording (_async_record_statistics_locked)
BEFORE_STORE_LOAD = "before_store_load"
AFTER_STORE_LOAD = "after_store_load"
BEFORE_RECOVER_PENDING = "before_recover_pending"
AFTER_RECOVER_PENDING = "after_recover_pending"
BEFORE_BASELINE_READS = "before_baseline_reads"
AFTER_BASELINE_READS = "after_baseline_reads"
BEFORE_JOURNAL_SAVE = "before_journal_save"
AFTER_JOURNAL_SAVE = "after_journal_save"
BEFORE_RECORDER_IMPORT = "before_recorder_import"
AFTER_RECORDER_IMPORT = "after_recorder_import"
BEFORE_RECORDER_COMMIT = "before_recorder_commit"
AFTER_RECORDER_COMMIT = "after_recorder_commit"
BEFORE_MUTATION_VERIFY = "before_mutation_verify"
AFTER_MUTATION_VERIFY = "after_mutation_verify"
BEFORE_JOURNAL_COMMIT = "before_journal_commit"
AFTER_JOURNAL_COMMIT = "after_journal_commit"
BEFORE_JOURNAL_DISCARD = "before_journal_discard"
AFTER_JOURNAL_DISCARD = "after_journal_discard"

# Awaited Operations in Recovery (_async_recover_pending)
BEFORE_RECOVERY_DURABILITY_WAIT = "before_recovery_durability_wait"
AFTER_RECOVERY_DURABILITY_WAIT = "after_recovery_durability_wait"
BEFORE_RECOVERY_VERIFY = "before_recovery_verify"
AFTER_RECOVERY_VERIFY = "after_recovery_verify"
BEFORE_RECOVERY_REPLAY = "before_recovery_replay"
AFTER_RECOVERY_REPLAY = "after_recovery_replay"
BEFORE_RECOVERY_COMMIT = "before_recovery_commit"
AFTER_RECOVERY_COMMIT = "after_recovery_commit"


@dataclass(frozen=True)
class BarrierDescriptor:
    """Descriptor defining the semantic role of an inventoried barrier."""

    name: str
    category: str  # "store", "recorder", "awaited_recording", "awaited_recovery"
    series: str  # "consumption", "cost", "both", "none"
    phase: str  # "recording", "recovery", "storage", "verification"
    description: str


BARRIER_INVENTORY: dict[str, BarrierDescriptor] = {
    # Store operations
    STORE_READBACK: BarrierDescriptor(
        STORE_READBACK,
        "store",
        "none",
        "storage",
        "Physical post-save verification readback of statistics Store JSON from disk",
    ),
    STORE_WRITE_PENDING: BarrierDescriptor(
        STORE_WRITE_PENDING,
        "store",
        "both",
        "storage",
        "Physical atomic write of pending statistics journal mutation to disk",
    ),
    STORE_WRITE_COMMIT: BarrierDescriptor(
        STORE_WRITE_COMMIT,
        "store",
        "both",
        "storage",
        "Physical atomic write committing journal mutation to promoted state on disk",
    ),
    # Recorder per-series operations
    RECORDER_IMPORT_CONSUMPTION: BarrierDescriptor(
        RECORDER_IMPORT_CONSUMPTION,
        "recorder",
        "consumption",
        "recording",
        "Queue external statistics import task for energy consumption series",
    ),
    RECORDER_IMPORT_COST: BarrierDescriptor(
        RECORDER_IMPORT_COST,
        "recorder",
        "cost",
        "recording",
        "Queue external statistics import task for energy cost series",
    ),
    RECORDER_COMMIT_CONSUMPTION: BarrierDescriptor(
        RECORDER_COMMIT_CONSUMPTION,
        "recorder",
        "consumption",
        "recording",
        "Commit barrier for energy consumption series",
    ),
    RECORDER_COMMIT_COST: BarrierDescriptor(
        RECORDER_COMMIT_COST,
        "recorder",
        "cost",
        "recording",
        "Commit barrier for energy cost series",
    ),
    RECORDER_COMMIT_BARRIER: BarrierDescriptor(
        RECORDER_COMMIT_BARRIER,
        "recorder",
        "both",
        "recording",
        "Recorder synchronization barrier waiting for queued imports to commit to database",
    ),
    RECORDER_READBACK_CONSUMPTION: BarrierDescriptor(
        RECORDER_READBACK_CONSUMPTION,
        "recorder",
        "consumption",
        "verification",
        "Recorder query verifying persisted rows and cumulative sums for consumption series",
    ),
    RECORDER_READBACK_COST: BarrierDescriptor(
        RECORDER_READBACK_COST,
        "recorder",
        "cost",
        "verification",
        "Recorder query verifying persisted rows and cumulative sums for cost series",
    ),
    # Recording awaited operations
    BEFORE_STORE_LOAD: BarrierDescriptor(
        BEFORE_STORE_LOAD,
        "awaited_recording",
        "none",
        "recording",
        "Before awaiting store.async_load() in recording",
    ),
    AFTER_STORE_LOAD: BarrierDescriptor(
        AFTER_STORE_LOAD,
        "awaited_recording",
        "none",
        "recording",
        "After store.async_load() completes in recording",
    ),
    BEFORE_RECOVER_PENDING: BarrierDescriptor(
        BEFORE_RECOVER_PENDING,
        "awaited_recording",
        "both",
        "recording",
        "Before awaiting _async_recover_pending() in recording",
    ),
    AFTER_RECOVER_PENDING: BarrierDescriptor(
        AFTER_RECOVER_PENDING,
        "awaited_recording",
        "both",
        "recording",
        "After _async_recover_pending() completes in recording",
    ),
    BEFORE_BASELINE_READS: BarrierDescriptor(
        BEFORE_BASELINE_READS,
        "awaited_recording",
        "both",
        "recording",
        "Before awaiting prior and existing baseline stats queries from recorder",
    ),
    AFTER_BASELINE_READS: BarrierDescriptor(
        AFTER_BASELINE_READS,
        "awaited_recording",
        "both",
        "recording",
        "After baseline stats queries complete",
    ),
    BEFORE_JOURNAL_SAVE: BarrierDescriptor(
        BEFORE_JOURNAL_SAVE,
        "awaited_recording",
        "both",
        "recording",
        "Before awaiting journal mutation begin and async_wait_durable",
    ),
    AFTER_JOURNAL_SAVE: BarrierDescriptor(
        AFTER_JOURNAL_SAVE,
        "awaited_recording",
        "both",
        "recording",
        "After journal mutation is durable on disk",
    ),
    BEFORE_RECORDER_IMPORT: BarrierDescriptor(
        BEFORE_RECORDER_IMPORT,
        "awaited_recording",
        "both",
        "recording",
        "Before calling async_add_external_statistics for both series",
    ),
    AFTER_RECORDER_IMPORT: BarrierDescriptor(
        AFTER_RECORDER_IMPORT,
        "awaited_recording",
        "both",
        "recording",
        "After calling async_add_external_statistics for both series",
    ),
    BEFORE_RECORDER_COMMIT: BarrierDescriptor(
        BEFORE_RECORDER_COMMIT,
        "awaited_recording",
        "both",
        "recording",
        "Before awaiting _async_wait_for_recorder_commit in recording",
    ),
    AFTER_RECORDER_COMMIT: BarrierDescriptor(
        AFTER_RECORDER_COMMIT,
        "awaited_recording",
        "both",
        "recording",
        "After _async_wait_for_recorder_commit completes in recording",
    ),
    BEFORE_MUTATION_VERIFY: BarrierDescriptor(
        BEFORE_MUTATION_VERIFY,
        "awaited_recording",
        "both",
        "recording",
        "Before awaiting _async_verify_mutation in recording",
    ),
    AFTER_MUTATION_VERIFY: BarrierDescriptor(
        AFTER_MUTATION_VERIFY,
        "awaited_recording",
        "both",
        "recording",
        "After _async_verify_mutation completes in recording",
    ),
    BEFORE_JOURNAL_COMMIT: BarrierDescriptor(
        BEFORE_JOURNAL_COMMIT,
        "awaited_recording",
        "both",
        "recording",
        "Before awaiting store.async_commit in recording",
    ),
    AFTER_JOURNAL_COMMIT: BarrierDescriptor(
        AFTER_JOURNAL_COMMIT,
        "awaited_recording",
        "both",
        "recording",
        "After store.async_commit completes in recording",
    ),
    # Recovery awaited operations
    BEFORE_RECOVERY_DURABILITY_WAIT: BarrierDescriptor(
        BEFORE_RECOVERY_DURABILITY_WAIT,
        "awaited_recovery",
        "none",
        "recovery",
        "Before awaiting store durability check in recovery",
    ),
    AFTER_RECOVERY_DURABILITY_WAIT: BarrierDescriptor(
        AFTER_RECOVERY_DURABILITY_WAIT,
        "awaited_recovery",
        "none",
        "recovery",
        "After store durability check completes in recovery",
    ),
    BEFORE_RECOVERY_VERIFY: BarrierDescriptor(
        BEFORE_RECOVERY_VERIFY,
        "awaited_recovery",
        "both",
        "recovery",
        "Before awaiting mutation verification in recovery",
    ),
    AFTER_RECOVERY_VERIFY: BarrierDescriptor(
        AFTER_RECOVERY_VERIFY,
        "awaited_recovery",
        "both",
        "recovery",
        "After mutation verification completes in recovery",
    ),
    BEFORE_RECOVERY_REPLAY: BarrierDescriptor(
        BEFORE_RECOVERY_REPLAY,
        "awaited_recovery",
        "both",
        "recovery",
        "Before awaiting mutation replay in recovery",
    ),
    AFTER_RECOVERY_REPLAY: BarrierDescriptor(
        AFTER_RECOVERY_REPLAY,
        "awaited_recovery",
        "both",
        "recovery",
        "After mutation replay completes in recovery",
    ),
    BEFORE_RECOVERY_COMMIT: BarrierDescriptor(
        BEFORE_RECOVERY_COMMIT,
        "awaited_recovery",
        "both",
        "recovery",
        "Before awaiting store.async_commit in recovery",
    ),
    AFTER_RECOVERY_COMMIT: BarrierDescriptor(
        AFTER_RECOVERY_COMMIT,
        "awaited_recovery",
        "both",
        "recovery",
        "After store.async_commit completes in recovery",
    ),
}


for _name, _description in (
    (BEFORE_JOURNAL_DISCARD, "Before awaiting async_discard of a durable unimported journal"),
    (AFTER_JOURNAL_DISCARD, "After awaiting async_discard of a durable unimported journal"),
):
    BARRIER_INVENTORY[_name] = BarrierDescriptor(
        _name, "awaited_recording", "both", "recording", _description
    )


def audit_barrier_inventory() -> dict[str, Any]:
    """Audit the completeness of the named semantic barrier inventory."""
    categories = {desc.category for desc in BARRIER_INVENTORY.values()}
    assert "store" in categories, "Missing store barrier category"
    assert "recorder" in categories, "Missing recorder barrier category"
    assert "awaited_recording" in categories, "Missing awaited_recording barrier category"
    assert "awaited_recovery" in categories, "Missing awaited_recovery barrier category"

    store_barriers = [k for k, v in BARRIER_INVENTORY.items() if v.category == "store"]
    assert STORE_READBACK in store_barriers
    assert STORE_WRITE_PENDING in store_barriers
    assert STORE_WRITE_COMMIT in store_barriers

    consumption_barriers = [k for k, v in BARRIER_INVENTORY.items() if v.series == "consumption"]
    cost_barriers = [k for k, v in BARRIER_INVENTORY.items() if v.series == "cost"]
    assert RECORDER_IMPORT_CONSUMPTION in consumption_barriers
    assert RECORDER_COMMIT_CONSUMPTION in consumption_barriers
    assert RECORDER_READBACK_CONSUMPTION in consumption_barriers
    assert RECORDER_IMPORT_COST in cost_barriers
    assert RECORDER_COMMIT_COST in cost_barriers
    assert RECORDER_READBACK_COST in cost_barriers

    assert RECORDER_COMMIT_BARRIER in BARRIER_INVENTORY

    awaited_recording = [
        k for k, v in BARRIER_INVENTORY.items() if v.category == "awaited_recording"
    ]
    before_rec = [k for k in awaited_recording if k.startswith("before_")]
    for b in before_rec:
        expected_after = "after_" + b.removeprefix("before_")
        assert expected_after in awaited_recording, f"Missing matching after barrier for {b}"

    awaited_recovery = [k for k, v in BARRIER_INVENTORY.items() if v.category == "awaited_recovery"]
    before_recov = [k for k in awaited_recovery if k.startswith("before_")]
    for b in before_recov:
        expected_after = "after_" + b.removeprefix("before_")
        assert expected_after in awaited_recovery, f"Missing matching after barrier for {b}"

    return {
        "total_barriers": len(BARRIER_INVENTORY),
        "categories": sorted(categories),
        "consumption_barriers": sorted(consumption_barriers),
        "cost_barriers": sorted(cost_barriers),
        "store_barriers": sorted(store_barriers),
    }


# -----------------------------------------------------------------------------
# Physical Durability Substrate
# -----------------------------------------------------------------------------


class _Client:
    price_per_kwh = 0.25

    def attach_renewal_admission(self, admission, runtime=None, token=None) -> None:
        self.admission = admission

    def set_expected_meter_ids(self, meter_ids) -> None:
        self.expected_meter_ids = frozenset(meter_ids)

    def pending_confirmed_snapshot(self):
        return None

    def clear_confirmed_snapshot(self, snapshot_id) -> None:
        self.cleared_snapshot = snapshot_id


class PhysicalDurabilitySubstrate:
    """Manages physical SQLite database and on-disk HA Store files.

    Guarantees that test faults interact with physical storage durability
    rather than in-memory mocks. Survives cold reconstruction across fresh
    coordinator instances reusing the exact same database and store paths.
    """

    def __init__(self, base_dir: Path | str, entry_id: str = "m1") -> None:
        self.base_dir = Path(base_dir)
        self.entry_id = entry_id
        self.db_file = self.base_dir / "fault_recorder.db"
        self.db_url = f"sqlite:///{self.db_file}"
        self.store_dir = self.base_dir / ".storage"
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.store_file = self.store_dir / f"pseg.statistics.{entry_id}"
        self._initial_db_size = 0

    def create_coordinator(
        self,
        hass: HomeAssistant,
        entry: MockConfigEntry | None = None,
        client: Any = None,
    ) -> PsegDataUpdateCoordinator:
        """Create a coordinator attached to the physical on-disk store file."""
        if entry is None:
            entry = MockConfigEntry(
                domain=DOMAIN,
                version=2,
                unique_id=self.entry_id,
                data={},
            )
            entry.add_to_hass(hass)

        coord = PsegDataUpdateCoordinator(
            hass,
            client or _Client(),
            {},
            config_entry=entry,
        )
        coord._stats_state._store.__dict__["path"] = str(self.store_file)
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coord
        return coord

    def read_store_bytes(self) -> bytes:
        """Read the raw physical bytes of the Store file on disk."""
        return self.store_file.read_bytes()

    def read_store_json(self) -> dict[str, Any]:
        """Parse and return the physical JSON Store file from disk."""
        return json.loads(self.store_file.read_text(encoding="utf-8"))

    def tamper_store_disk(self, mutator: Callable[[dict[str, Any]], None]) -> None:
        """Directly mutate the on-disk Store JSON without touching warm coordinator memory."""
        data = self.read_store_json()
        mutator(data)
        self.store_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def tamper_warm_memory(
        self,
        coord: PsegDataUpdateCoordinator,
        mutator: Callable[[dict[str, Any]], None],
    ) -> None:
        """Directly mutate warm coordinator in-memory data without modifying disk bytes."""
        mutator(coord._stats_state._data)

    def verify_db_file(self) -> None:
        """Verify that the SQLite database file exists and contains valid tables."""
        assert self.db_file.exists(), f"Database file {self.db_file} does not exist"
        size = self.db_file.stat().st_size
        assert size > 0, f"Database file {self.db_file} is empty (0 bytes)"
        with sqlite3.connect(str(self.db_file)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cursor.fetchall()]
            assert "statistics" in tables or "statistics_meta" in tables, (
                f"SQLite DB missing statistics tables, found: {tables}"
            )

    async def reopen_recorder(
        self,
        hass: HomeAssistant,
        db_url: str | None = None,
    ) -> Recorder:
        """Stop current recorder instance and reopen a new one pointing to the database."""
        target_url = db_url or self.db_url
        old_inst = get_instance(hass)
        if old_inst is not None and old_inst.is_alive():
            await old_inst._async_shutdown(None)
        get_instance.cache_clear()
        hass.data[DATA_RECORDER] = recorder_helper.RecorderData()

        new_inst = Recorder(
            hass=hass,
            auto_purge=False,
            auto_repack=False,
            keep_days=365,
            commit_interval=0,
            uri=target_url,
            db_max_retries=10,
            db_retry_wait=3,
            entity_filter=None,
            exclude_event_types=set(),
        )
        hass.data[DATA_INSTANCE] = new_inst
        new_inst.async_initialize()
        new_inst.async_register()
        new_inst.start()
        await new_inst.async_db_ready
        await async_recorder_block_till_done(hass)
        return new_inst

    async def query_recorder_rows(
        self, hass: HomeAssistant, statistic_id: str
    ) -> list[tuple[datetime, float, float]]:
        """Query the real recorder via statistics_during_period to verify physical rows."""
        rows = await hass.async_add_executor_job(
            statistics_during_period,
            hass,
            datetime(2020, 1, 1, tzinfo=UTC),
            None,
            {statistic_id},
            "hour",
            None,
            {"sum", "state"},
        )
        return sorted(
            (
                datetime.fromtimestamp(r["start"], UTC),
                float(r["state"]),
                float(r["sum"]),
            )
            for r in rows.get(statistic_id, [])
        )

    async def cold_reconstruct(
        self,
        old_coord: PsegDataUpdateCoordinator,
        hass: HomeAssistant,
        reopen_db: bool = True,
    ) -> PsegDataUpdateCoordinator:
        """Cold restart: build a fresh coordinator that reuses the SAME Store and SQLite DB.

        Proves:
        1. Store file path on disk is identical.
        2. SQLite DB path is identical.
        3. Real recorder queries execute against the physical database.
        4. No warm cache is reused.
        """
        entry = old_coord.config_entry
        assert entry is not None

        # Verify physical files exist before tear-down
        self.verify_db_file()
        assert self.store_file.exists()
        persisted_store_bytes = self.read_store_bytes()

        # Stop old coordinator and purge old in-memory runtime
        old_coord.stop_keepalive()
        hass.data.get(f"{DOMAIN}_statistics_runtimes", {}).pop(entry.entry_id, None)

        # Build fresh coordinator context
        cold = PsegDataUpdateCoordinator(
            hass,
            _Client(),
            {},
            config_entry=entry,
        )
        cold._stats_state._store.__dict__["path"] = str(self.store_file)
        # Invalidate internal cache manager if any
        if hasattr(cold._stats_state._store, "_manager"):
            cold._stats_state._store._manager.async_invalidate(cold._stats_state._store.key)

        hass.data[DOMAIN][entry.entry_id] = cold

        # Prove identical paths
        assert cold._stats_state._store.path == str(self.store_file)

        # Reopen recorder against the same database file if requested
        if reopen_db:
            old_recorder = get_instance(hass)
            new_recorder = await self.reopen_recorder(hass)
            assert new_recorder is not old_recorder
            assert new_recorder.db_url == self.db_url
        else:
            recorder_inst = get_instance(hass)
            assert recorder_inst.db_url == self.db_url

        # Prove no warm cache was reused
        assert not cold._stats_state._loaded

        # Load store from disk
        await cold._stats_state.async_load()
        assert cold._stats_state._loaded

        # Prove loaded bytes correspond to persisted disk content
        assert self.store_file.read_bytes() == persisted_store_bytes, (
            "Store bytes changed during cold restart!"
        )

        # Prove loaded data equals persisted disk JSON data
        disk_json = self.read_store_json()
        disk_data = disk_json.get("data", disk_json)
        assert cold._stats_state._data == disk_data, (
            "Cold reconstructed stats state does not match on-disk JSON data"
        )
        assert cold._stats_state._data.get("promoted") or cold._stats_state._data.get("pending"), (
            "Cold reconstructed state is empty!"
        )

        return cold


# -----------------------------------------------------------------------------
# Fault Harness & Barrier Controller
# -----------------------------------------------------------------------------


@dataclass
class _BarrierAction:
    kind: str  # "pause", "hold", "fail", "retire", "cancel", "intercept"
    exception: Exception | None = None
    event: asyncio.Event = None  # type: ignore[assignment]
    timeout: float = DEFAULT_BARRIER_TIMEOUT
    hook: Callable[[Any], Any] | None = None
    one_shot: bool = False


class StatsFaultHarness:
    """Test-local adapter mapping statistics recording and recovery seams to named barriers.

    Provides controls for pause, resume, hold (stalled with timeout bound),
    cancellation, coordinator retirement, and failure injection.
    """

    def __init__(
        self,
        coord: PsegDataUpdateCoordinator | None = None,
        substrate: PhysicalDurabilitySubstrate | None = None,
        series_order: str = "consumption_first",
    ) -> None:
        self.coord = coord
        self.substrate = substrate
        self.series_order = series_order
        self._actions: dict[str, _BarrierAction] = {}
        self._hit_counts: dict[str, int] = {}
        self._fired_counts: dict[str, int] = {}
        self._patches: list[Any] = []
        self._installed = False
        self._in_recovery = False
        self._arrivals: dict[str, asyncio.Event] = {}
        self._waiters: dict[str, list[_BarrierAction]] = {}
        self._worker_errors: list[BaseException] = []
        self._buffered_stats: tuple[Any, Any, Any] | None = None

    def hits(self, barrier_name: str) -> int:
        """Return the number of times the named barrier was hit."""
        return self._hit_counts.get(barrier_name, 0)

    def fired(self, barrier_name: str) -> int:
        """Return the number of times an action at this barrier was actually fired."""
        return self._fired_counts.get(barrier_name, 0)

    def fail_once(self, barrier_name: str, exception: Exception) -> None:
        """Inject an exception once when the barrier is reached, then pass through."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        self._actions[barrier_name] = _BarrierAction(
            kind="fail", exception=exception, one_shot=True
        )

    def cancel_once(self, barrier_name: str) -> None:
        """Raise asyncio.CancelledError once at the barrier, then pass through."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        self._actions[barrier_name] = _BarrierAction(kind="cancel", one_shot=True)

    def retire_once(self, barrier_name: str) -> None:
        """Retire the coordinator once at the barrier, then pass through."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        self._actions[barrier_name] = _BarrierAction(kind="retire", one_shot=True)

    def pause_once(self, barrier_name: str) -> None:
        """Pause execution once at the barrier until resumed, then pass through."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        event = asyncio.Event()
        self._arrivals[barrier_name] = asyncio.Event()
        self._actions[barrier_name] = _BarrierAction(kind="pause", event=event, one_shot=True)

    def pause(self, barrier_name: str) -> None:
        """Pause execution when the barrier is reached until resumed."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        event = asyncio.Event()
        self._arrivals[barrier_name] = asyncio.Event()
        self._actions[barrier_name] = _BarrierAction(kind="pause", event=event)

    def resume(self, barrier_name: str) -> None:
        """Resume a paused barrier."""
        action = self._actions.get(barrier_name)
        if action and action.event:
            action.event.set()
        for waiter in self._waiters.get(barrier_name, ()):
            waiter.event.set()

    async def wait_until_reached(self, barrier_name: str) -> None:
        """Wait for an observed arrival without ordering sleeps."""
        event = self._arrivals.setdefault(barrier_name, asyncio.Event())
        try:
            await asyncio.wait_for(event.wait(), DEFAULT_BARRIER_TIMEOUT)
        except TimeoutError as err:
            raise AssertionError(f"Barrier {barrier_name} was not reached within 10s") from err

    def hold(self, barrier_name: str, timeout: float = DEFAULT_BARRIER_TIMEOUT) -> None:
        """Hold execution at the barrier with a bounded timeout (fails within <= 10.0s)."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        timeout = min(timeout, DEFAULT_BARRIER_TIMEOUT)
        event = asyncio.Event()
        self._actions[barrier_name] = _BarrierAction(kind="hold", event=event, timeout=timeout)

    def fail(self, barrier_name: str, exception: Exception) -> None:
        """Inject an exception when the barrier is reached."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        self._actions[barrier_name] = _BarrierAction(kind="fail", exception=exception)

    def cancel(self, barrier_name: str) -> None:
        """Raise asyncio.CancelledError at the barrier to test abort/rollback."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        self._actions[barrier_name] = _BarrierAction(kind="cancel")

    def retire(self, barrier_name: str) -> None:
        """Simulate coordinator retirement at the barrier by stopping keepalive/coord."""
        assert barrier_name in BARRIER_INVENTORY, f"Unknown barrier name: {barrier_name}"
        self._actions[barrier_name] = _BarrierAction(kind="retire")

    async def _dispatch(self, barrier_name: str, context: Any = None) -> None:
        """Internal hook invoked at seam points."""
        self._hit_counts[barrier_name] = self._hit_counts.get(barrier_name, 0) + 1
        self._arrivals.setdefault(barrier_name, asyncio.Event()).set()
        action = self._actions.get(barrier_name)
        if not action:
            return

        if action.one_shot:
            self._actions.pop(barrier_name, None)
        self._fired_counts[barrier_name] = self._fired_counts.get(barrier_name, 0) + 1

        if action.kind in ("pause", "hold"):
            self._waiters.setdefault(barrier_name, []).append(action)
            try:
                await asyncio.wait_for(action.event.wait(), timeout=action.timeout)
            except TimeoutError as err:
                raise TimeoutError(f"Barrier {barrier_name} stalled and timed out") from err
            finally:
                self._waiters[barrier_name].remove(action)
                action.event.set()
        elif action.kind == "fail":
            assert action.exception is not None
            raise action.exception
        elif action.kind == "cancel":
            raise asyncio.CancelledError(f"Barrier {barrier_name} injected cancellation")
        elif action.kind == "retire":
            if self.coord:
                self.coord.stop_keepalive()

    def install(self, coord: PsegDataUpdateCoordinator) -> None:
        """Attach fault hooks to coordinator and its internal statistics runtime."""
        self.coord = coord
        loop = asyncio.get_running_loop()

        def dispatch_from_worker(barrier, context=None):
            future = asyncio.run_coroutine_threadsafe(self._dispatch(barrier, context), loop)
            try:
                future.result(timeout=DEFAULT_BARRIER_TIMEOUT + 1)
            except WorkerCancelledError as err:
                raise asyncio.CancelledError(f"Barrier {barrier} injected cancellation") from err
            finally:
                if not future.done():
                    future.cancel()

        # The actual Store executor write, after async_begin/commit changed memory.
        original_write = coord._stats_state._store._write_data

        def physical_write(wrapper):
            barrier = STORE_WRITE_PENDING if wrapper["data"]["pending"] else STORE_WRITE_COMMIT
            dispatch_from_worker(barrier, wrapper)
            return original_write(wrapper)

        p = patch.object(coord._stats_state._store, "_write_data", physical_write)
        p.start()
        self._patches.append(p)

        original_readback = coord._stats_state._async_verify_persisted

        async def physical_readback(snapshot):
            await self._dispatch(STORE_READBACK, snapshot)
            return await original_readback(snapshot)

        p = patch.object(coord._stats_state, "_async_verify_persisted", physical_readback)
        p.start()
        self._patches.append(p)

        # Hook Store load
        orig_load = coord._stats_state.async_load

        async def hooked_load():
            await self._dispatch(BEFORE_STORE_LOAD)
            res = await orig_load()
            await self._dispatch(AFTER_STORE_LOAD)
            return res

        p = patch.object(coord._stats_state, "async_load", hooked_load)
        p.start()
        self._patches.append(p)

        # Hook Store begin (pending write)
        orig_begin = coord._stats_state.async_begin

        async def hooked_begin(mutation):
            await self._dispatch(BEFORE_JOURNAL_SAVE, mutation)
            res = await orig_begin(mutation)
            await self._dispatch(AFTER_JOURNAL_SAVE, mutation)
            return res

        p = patch.object(coord._stats_state, "async_begin", hooked_begin)
        p.start()
        self._patches.append(p)

        # Hook Store commit (committed write)
        orig_commit = coord._stats_state.async_commit

        async def hooked_commit(mutation_id):
            await self._dispatch(BEFORE_JOURNAL_COMMIT, mutation_id)
            if self._in_recovery:
                await self._dispatch(BEFORE_RECOVERY_COMMIT, mutation_id)
            res = await orig_commit(mutation_id)
            if self._in_recovery:
                await self._dispatch(AFTER_RECOVERY_COMMIT, mutation_id)
            await self._dispatch(AFTER_JOURNAL_COMMIT, mutation_id)
            return res

        p = patch.object(coord._stats_state, "async_commit", hooked_commit)
        p.start()
        self._patches.append(p)

        # Hook recover pending
        orig_recover = coord._async_recover_pending

        async def hooked_recover():
            await self._dispatch(BEFORE_RECOVER_PENDING)
            self._in_recovery = True
            try:
                res = await orig_recover()
            finally:
                self._in_recovery = False
            await self._dispatch(AFTER_RECOVER_PENDING)
            return res

        p = patch.object(coord, "_async_recover_pending", hooked_recover)
        p.start()
        self._patches.append(p)

        # Hook durability wait in recovery
        orig_wait_durable = coord._stats_state.async_wait_durable

        async def hooked_wait_durable(*args, **kwargs):
            if self._in_recovery:
                await self._dispatch(BEFORE_RECOVERY_DURABILITY_WAIT)
            res = await orig_wait_durable(*args, **kwargs)
            if self._in_recovery:
                await self._dispatch(AFTER_RECOVERY_DURABILITY_WAIT)
            return res

        p = patch.object(coord._stats_state, "async_wait_durable", hooked_wait_durable)
        p.start()
        self._patches.append(p)

        # Hook replay in recovery
        orig_replay = coord._async_replay_mutation

        async def hooked_replay(mutation):
            await self._dispatch(BEFORE_RECOVERY_REPLAY, mutation)
            res = await orig_replay(mutation)
            await self._dispatch(AFTER_RECOVERY_REPLAY, mutation)
            return res

        p = patch.object(coord, "_async_replay_mutation", hooked_replay)
        p.start()
        self._patches.append(p)

        # All four baseline awaits: prior consumption/cost, then existing consumption/cost.
        def baseline_wrapper(original):
            async def wrapped(*args, **kwargs):
                await self._dispatch(BEFORE_BASELINE_READS)
                result = await original(*args, **kwargs)
                await self._dispatch(AFTER_BASELINE_READS)
                return result

            return wrapped

        for name in ("_async_get_last_stat_before", "_async_get_stats_from"):
            p = patch.object(coord_mod, name, baseline_wrapper(getattr(coord_mod, name)))
            p.start()
            self._patches.append(p)

        original_discard = coord._stats_state.async_discard

        async def discard(mutation_id):
            await self._dispatch(BEFORE_JOURNAL_DISCARD, mutation_id)
            result = await original_discard(mutation_id)
            await self._dispatch(AFTER_JOURNAL_DISCARD, mutation_id)
            return result

        p = patch.object(coord._stats_state, "async_discard", discard)
        p.start()
        self._patches.append(p)

        if not self._installed:
            # Hook async_add_external_statistics (per-series imports)
            orig_add_stats = coord_mod.async_add_external_statistics

            def _sync_import_barrier(barrier: str, meta: Any, st: Any) -> None:
                self._hit_counts[barrier] = self._hit_counts.get(barrier, 0) + 1
                act = self._actions.get(barrier)
                if act and act.kind == "fail":
                    if act.one_shot:
                        self._actions.pop(barrier, None)
                    self._fired_counts[barrier] = self._fired_counts.get(barrier, 0) + 1
                    assert act.exception is not None
                    raise act.exception

            def hooked_add_stats(hass_arg, metadata, stats):
                stat_id = metadata.get("statistic_id", "")
                is_consumption = stat_id.endswith("_energy_consumption")
                is_cost = stat_id.endswith("_energy_cost")

                self._hit_counts[BEFORE_RECORDER_IMPORT] = (
                    self._hit_counts.get(BEFORE_RECORDER_IMPORT, 0) + 1
                )

                if self.series_order == "cost_first" and is_consumption:
                    # Buffer consumption and wait for cost to import first
                    self._buffered_stats = (hass_arg, metadata, stats)
                    return None

                barrier = RECORDER_IMPORT_CONSUMPTION if is_consumption else RECORDER_IMPORT_COST
                _sync_import_barrier(barrier, metadata, stats)
                res = orig_add_stats(hass_arg, metadata, stats)
                self._hit_counts[AFTER_RECORDER_IMPORT] = (
                    self._hit_counts.get(AFTER_RECORDER_IMPORT, 0) + 1
                )

                if self.series_order == "cost_first" and is_cost and self._buffered_stats:
                    # Flush buffered consumption second
                    b_hass, b_meta, b_stats = self._buffered_stats
                    self._buffered_stats = None
                    _sync_import_barrier(RECORDER_IMPORT_CONSUMPTION, b_meta, b_stats)
                    orig_add_stats(b_hass, b_meta, b_stats)
                    self._hit_counts[AFTER_RECORDER_IMPORT] = (
                        self._hit_counts.get(AFTER_RECORDER_IMPORT, 0) + 1
                    )

                return res

            p2 = patch.object(coord_mod, "async_add_external_statistics", hooked_add_stats)
            p2.start()
            self._patches.append(p2)

            # Each task owns a separate import_statistics/session_scope transaction.
            original_run = ImportStatisticsTask.run

            def run_import(task, instance):
                statistic_id = task.metadata["statistic_id"]
                if not statistic_id.startswith("pseg:"):
                    return original_run(task, instance)
                barrier = (
                    RECORDER_COMMIT_CONSUMPTION
                    if statistic_id.endswith("_energy_consumption")
                    else RECORDER_COMMIT_COST
                )
                try:
                    dispatch_from_worker(barrier, statistic_id)
                except BaseException as err:
                    # Preserve HA's worker; report failure after the queue drains.
                    self._worker_errors.append(err)
                    return None
                return original_run(task, instance)

            p = patch.object(ImportStatisticsTask, "run", run_import)
            p.start()
            self._patches.append(p)

            # Hook recorder commit wait
            orig_wait_commit = coord_mod._async_wait_for_recorder_commit

            async def hooked_wait_commit(hass_arg):
                await self._dispatch(BEFORE_RECORDER_COMMIT)
                await self._dispatch(RECORDER_COMMIT_BARRIER)
                res = await orig_wait_commit(hass_arg)
                if self._worker_errors:
                    raise self._worker_errors.pop(0)
                await self._dispatch(AFTER_RECORDER_COMMIT)
                return res

            p3 = patch.object(coord_mod, "_async_wait_for_recorder_commit", hooked_wait_commit)
            p3.start()
            self._patches.append(p3)

        # Hook mutation verify
        orig_verify = coord._async_verify_mutation

        async def hooked_verify(mutation):
            await self._dispatch(BEFORE_MUTATION_VERIFY, mutation)
            if self._in_recovery:
                await self._dispatch(BEFORE_RECOVERY_VERIFY, mutation)
            res = await orig_verify(mutation)
            await self._dispatch(AFTER_MUTATION_VERIFY, mutation)
            if self._in_recovery:
                await self._dispatch(AFTER_RECOVERY_VERIFY, mutation)
            return res

        p = patch.object(coord, "_async_verify_mutation", hooked_verify)
        p.start()
        self._patches.append(p)

        # Hook per-series readback in verify
        orig_get_series = coord_mod._async_get_series_with_sums

        async def hooked_get_series(hass_arg, stat_id, start):
            if stat_id.endswith("_energy_consumption"):
                await self._dispatch(RECORDER_READBACK_CONSUMPTION, (stat_id, start))
            elif stat_id.endswith("_energy_cost"):
                await self._dispatch(RECORDER_READBACK_COST, (stat_id, start))
            return await orig_get_series(hass_arg, stat_id, start)

        p4 = patch.object(coord_mod, "_async_get_series_with_sums", hooked_get_series)
        p4.start()
        self._patches.append(p4)

        self._installed = True

    def uninstall(self) -> None:
        """Remove all active patches and wrappers."""
        for p in reversed(self._patches):
            p.stop()
        self._patches.clear()
        self._installed = False

    async def cleanup(self) -> None:
        """Resume any held barriers and clean up pending tasks to prevent resource leaks."""
        # Release all waiting events so tasks do not hang
        for barrier in self._waiters:
            self.resume(barrier)
        for action in self._actions.values():
            if action.event and not action.event.is_set():
                action.event.set()

        self.uninstall()
        self._actions.clear()

        # Drain pending test tasks
        loop = asyncio.get_running_loop()
        curr = asyncio.current_task()
        pending = [
            t
            for t in asyncio.all_tasks(loop)
            if t is not curr and not t.done() and "test" in (t.get_name() or "")
        ]
        if pending:
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def __aenter__(self) -> StatsFaultHarness:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.cleanup()

"""Golden synthetic statistics Store schema pin (P3-05 S4).

One synthetic Store document is fixed as a literal here and in
``tests/fixtures/statistics_store_synthetic.json``; the real production Store
class must load it, keep it, promote its journal and write the same wrapper back
under the installed Home Assistant. Both recorders series (``pseg:..._consumption``
and ``pseg:..._cost``) are asserted literally, and the key prefix, version and
minor version are pinned against the real ``Store`` instance rather than copied
constants.

Scope: persistence compatibility only. Null-values, wrong-type rows and the
parser's NY-wall semantics are covered by the other statistics modules.
"""

from __future__ import annotations

from datetime import date
import json
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant

from custom_components.pseg.statistics_state import STORAGE_VERSION, StatisticsStateStore

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "statistics_store_synthetic.json"

ENTRY_ID = "0123456789abcdef0123456789abcdef"
KEY = f"pseg.statistics.{ENTRY_ID}"
CONSUMPTION_ID = "pseg:m1_energy_consumption"
COST_ID = "pseg:m1_energy_cost"
MUTATION_ID = "9f2c1a7b5d4e4c8fa1b2c3d4e5f60718"
PROMOTED_KEYS = ("total_kwh", "total_cost", "daily_kwh", "daily_cost", "promoted_at")

PROMOTED_DAY_18 = {
    "total_kwh": 24.0,
    "total_cost": 6.0,
    "daily_kwh": 24.0,
    "daily_cost": 6.0,
    "promoted_at": "2026-10-25T12:00:00+00:00",
}
PROMOTED_DAY_20 = {
    "total_kwh": 2.75,
    "total_cost": 0.6875,
    "daily_kwh": 2.75,
    "daily_cost": 0.69,
    "promoted_at": "2026-10-25T12:05:00+00:00",
}

# The journal entry a daily->hourly promotion leaves behind before any recorder
# write: both series' complete rows plus the promoted provenance, keyed by date.
JOURNAL_MUTATION = {
    "created_at": "2026-10-25T12:05:00+00:00",
    "first_start": "2026-10-20T04:00:00+00:00",
    "series": {
        CONSUMPTION_ID: [
            ["2026-10-20T04:00:00+00:00", 1.25, 31.25],
            ["2026-10-20T05:00:00+00:00", 1.5, 32.75],
        ],
        COST_ID: [
            ["2026-10-20T04:00:00+00:00", 0.3125, 7.8125],
            ["2026-10-20T05:00:00+00:00", 0.375, 8.1875],
        ],
    },
    "promoted": {
        CONSUMPTION_ID: {"2026-10-20": PROMOTED_DAY_20},
        COST_ID: {"2026-10-20": PROMOTED_DAY_20},
    },
}

JOURNAL_DATA = {
    "version": 2,
    "promoted": {
        CONSUMPTION_ID: {"2026-10-18": PROMOTED_DAY_18},
        COST_ID: {"2026-10-18": PROMOTED_DAY_18},
    },
    "pending": {MUTATION_ID: JOURNAL_MUTATION},
}

COMMITTED_DATA = {
    "version": 2,
    "promoted": {
        CONSUMPTION_ID: {
            "2026-10-18": PROMOTED_DAY_18,
            "2026-10-20": PROMOTED_DAY_20,
        },
        COST_ID: {
            "2026-10-18": PROMOTED_DAY_18,
            "2026-10-20": PROMOTED_DAY_20,
        },
    },
    "pending": {},
}

# The exact Home Assistant Store wrapper: version, minor_version, key and data.
GOLDEN_DOCUMENT = {
    "version": 2,
    "minor_version": 1,
    "key": KEY,
    "data": JOURNAL_DATA,
}


def _golden() -> dict[str, Any]:
    """Return the checked-in golden document."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _store(hass: HomeAssistant, tmp_path: Path) -> tuple[StatisticsStateStore, Path]:
    """Create a real Store instance redirected at a temporary on-disk file."""
    path = tmp_path / ".storage" / f"pseg.statistics.{ENTRY_ID}"
    path.parent.mkdir(parents=True, exist_ok=True)
    store = StatisticsStateStore(hass, ENTRY_ID)
    # Store caches its path at construction; redirect before the first read/write.
    store._store.__dict__["path"] = str(path)
    assert store._store.path == str(path)
    return store, path


def _read(path: Path) -> dict[str, Any]:
    """Read one persisted Store wrapper."""
    return json.loads(path.read_text(encoding="utf-8"))


def test_golden_fixture_pins_the_literal_schema() -> None:
    """The fixture file and the literal expectations in this module must agree."""
    assert _golden() == GOLDEN_DOCUMENT
    # Store key prefix and schema versions are pinned literally.
    assert GOLDEN_DOCUMENT["key"] == f"pseg.statistics.{ENTRY_ID}"
    assert GOLDEN_DOCUMENT["key"].startswith("pseg.statistics.")
    assert GOLDEN_DOCUMENT["version"] == 2
    assert GOLDEN_DOCUMENT["minor_version"] == 1
    assert GOLDEN_DOCUMENT["data"]["version"] == 2

    # Journal shape: exactly one mutation, keyed by an opaque 32-hex id, naming
    # both series with [start, state, cumulative sum] rows.
    pending = GOLDEN_DOCUMENT["data"]["pending"]
    assert list(pending) == [MUTATION_ID]
    assert len(MUTATION_ID) == 32 and int(MUTATION_ID, 16) >= 0
    mutation = pending[MUTATION_ID]
    assert sorted(mutation) == ["created_at", "first_start", "promoted", "series"]
    assert set(mutation["series"]) == {CONSUMPTION_ID, COST_ID}
    assert mutation["series"][CONSUMPTION_ID][0] == [
        "2026-10-20T04:00:00+00:00",
        1.25,
        31.25,
    ]
    assert mutation["series"][COST_ID][0] == ["2026-10-20T04:00:00+00:00", 0.3125, 7.8125]
    for rows in mutation["series"].values():
        for row in rows:
            assert [type(part).__name__ for part in row] == ["str", "float", "float"]
            assert row[0].endswith("+00:00")

    # Promotion shape: statistic id -> ISO day -> the five provenance fields.
    assert set(mutation["promoted"]) == {CONSUMPTION_ID, COST_ID}
    assert mutation["promoted"][COST_ID]["2026-10-20"] == PROMOTED_DAY_20
    assert tuple(PROMOTED_DAY_20) == PROMOTED_KEYS
    assert GOLDEN_DOCUMENT["data"]["promoted"][CONSUMPTION_ID]["2026-10-18"] == (PROMOTED_DAY_18)


async def test_real_store_pins_key_prefix_version_and_load(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    """The installed HA Store instance must produce the pinned key/version."""
    store, path = _store(hass, tmp_path)
    assert store._store.key == KEY
    assert store._store.key.startswith("pseg.statistics.")
    assert store._store.version == STORAGE_VERSION == 2
    assert store._store.minor_version == 1

    path.write_bytes(FIXTURE.read_bytes())
    await store.async_load()

    assert store._load_failed is False
    assert store._data == JOURNAL_DATA
    assert store.has_pending() is True
    assert store.pending_mutations() == {MUTATION_ID: JOURNAL_MUTATION}
    assert store.promoted(CONSUMPTION_ID) == {"2026-10-18": PROMOTED_DAY_18}
    assert store.promoted(COST_ID) == {"2026-10-18": PROMOTED_DAY_18}
    # pending_days covers journal days only (committed days are not pending) and
    # sees the ISO day plus both series' canonical row starts.
    assert store.pending_days() == {date(2026, 10, 20)}
    assert store.pending_days(CONSUMPTION_ID) == {date(2026, 10, 20)}
    assert store.pending_days(COST_ID) == {date(2026, 10, 20)}


async def test_begin_writes_the_golden_document_byte_for_byte(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    """Empty journal + this mutation must produce the golden wrapper exactly."""
    store, path = _store(hass, tmp_path)
    promoted_only = {
        "version": 2,
        "minor_version": 1,
        "key": KEY,
        "data": {"version": 2, "promoted": JOURNAL_DATA["promoted"], "pending": {}},
    }
    path.write_text(json.dumps(promoted_only), encoding="utf-8")
    await store.async_load()
    assert store._data["pending"] == {}

    await store.async_begin(JOURNAL_MUTATION)

    written = _read(path)
    assert written["version"] == 2
    assert written["minor_version"] == 1
    assert written["key"] == KEY
    pending = written["data"]["pending"]
    assert len(pending) == 1
    (mutation_id,) = pending
    assert len(mutation_id) == 32
    assert written["data"]["promoted"] == JOURNAL_DATA["promoted"]
    # Normalize only the random uuid to compare with the pinned document.
    normalized = {
        **written,
        "data": {**written["data"], "pending": {MUTATION_ID: pending[mutation_id]}},
    }
    assert normalized == GOLDEN_DOCUMENT
    assert pending[mutation_id] == JOURNAL_MUTATION
    assert pending[mutation_id]["series"][CONSUMPTION_ID][1] == [
        "2026-10-20T05:00:00+00:00",
        1.5,
        32.75,
    ]
    assert pending[mutation_id]["series"][COST_ID][1] == [
        "2026-10-20T05:00:00+00:00",
        0.375,
        8.1875,
    ]


async def test_commit_moves_journal_to_promoted_with_pinned_shape(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    """A verified commit clears the journal and writes the committed shape."""
    store, path = _store(hass, tmp_path)
    path.write_bytes(FIXTURE.read_bytes())
    await store.async_load()

    await store.async_commit(MUTATION_ID)

    written = _read(path)
    assert written == {
        "version": 2,
        "minor_version": 1,
        "key": KEY,
        "data": COMMITTED_DATA,
    }
    assert written["data"]["pending"] == {}
    assert written["data"]["promoted"][CONSUMPTION_ID]["2026-10-20"] == PROMOTED_DAY_20
    assert written["data"]["promoted"][COST_ID]["2026-10-20"] == PROMOTED_DAY_20
    for days in written["data"]["promoted"].values():
        for record in days.values():
            assert tuple(record) == PROMOTED_KEYS


async def test_cold_reload_of_committed_store_matches_disk(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    """A fresh instance loading the same file sees the committed literal state."""
    store, path = _store(hass, tmp_path)
    path.write_bytes(FIXTURE.read_bytes())
    await store.async_load()
    await store.async_commit(MUTATION_ID)

    cold = StatisticsStateStore(hass, ENTRY_ID)
    cold._store.__dict__["path"] = str(path)
    assert cold._store.key == KEY
    await cold.async_load()

    assert cold._load_failed is False
    assert cold._data == COMMITTED_DATA
    assert cold._data == _read(path)["data"]
    assert cold.has_pending() is False
    assert cold.pending_mutations() == {}
    assert cold.pending_days() == set()
    assert cold.promoted(COST_ID) == {
        "2026-10-18": PROMOTED_DAY_18,
        "2026-10-20": PROMOTED_DAY_20,
    }

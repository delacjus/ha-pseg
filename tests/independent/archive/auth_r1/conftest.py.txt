"""Pytest fixtures for PSE&G integration tests."""

import pytest

# Fix Python 3.14 inspect.signature annotation issue in HA 2026.10.2 recorder migration
try:
    import homeassistant.components.recorder.core
    import homeassistant.components.recorder.migration

    homeassistant.components.recorder.migration.Recorder = (
        homeassistant.components.recorder.core.Recorder
    )
except Exception:
    pass

# Python 3.14 evaluates annotations lazily; helpers.recorder only imports Session under
# TYPE_CHECKING, so recorder-backed tests (recorder_mock) fail resolving it. Bind it.
try:
    import homeassistant.helpers.recorder as _helpers_recorder
    from sqlalchemy.orm import Session as _SqlaSession

    _helpers_recorder.Session = _SqlaSession
except Exception:
    pass


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable custom integrations for all tests."""
    yield


@pytest.fixture(autouse=True)
def _real_pseg_statistics_writes(tmp_path, hass_storage, monkeypatch):
    """Give every PSE&G statistics Store an isolated real per-test path and writer.

    The HA harness mocks Store._async_write_data globally; route only our key
    through Store._write_data so Store.async_save's real swallow handler is
    exercised. Direct assignment (not monkeypatch) keeps the harness mock's
    autospec teardown intact.
    """
    from pathlib import Path as _Path

    from homeassistant.helpers import storage

    from custom_components.pseg.statistics_state import StatisticsStateStore

    original_init = StatisticsStateStore.__init__

    def _init(self, hass, entry_id):
        original_init(self, hass, entry_id)
        safe_entry = str(entry_id).replace("/", "_")
        self._store.__dict__["path"] = str(
            _Path(tmp_path) / f"pseg-statistics-{safe_entry}.json"
        )

    monkeypatch.setattr(StatisticsStateStore, "__init__", _init)
    original_write = storage.Store._async_write_data

    async def routed(store_obj, data):
        if store_obj.key.startswith("pseg.statistics."):
            await store_obj.hass.async_add_executor_job(
                store_obj._write_data, data
            )
            return
        await original_write(store_obj, data)

    storage.Store._async_write_data = routed
    try:
        yield
    finally:
        storage.Store._async_write_data = original_write

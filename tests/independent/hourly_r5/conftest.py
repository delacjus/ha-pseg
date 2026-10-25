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
def _real_pseg_statistics_writes():
    """No-op override of root fixture to prevent double-wrapping Store._async_write_data."""
    yield


@pytest.fixture(autouse=True)
def physical_statistics_store(tmp_path, hass_storage, monkeypatch):
    """Relocate the store and undo harness writer interception.

    Store.async_save and its real WriteError handler stay untouched.
    """
    from homeassistant.helpers.storage import Store

    from custom_components.pseg.statistics_state import StatisticsStateStore

    init = StatisticsStateStore.__init__

    def located(self, hass, entry_id):
        init(self, hass, entry_id)
        self._store.__dict__["path"] = str(tmp_path / ("store-" + str(entry_id) + ".json"))

    monkeypatch.setattr(StatisticsStateStore, "__init__", located)
    original = Store._async_write_data

    async def physical(store, wrapper):
        if store.key.startswith("pseg.statistics."):
            await store.hass.async_add_executor_job(store._write_data, wrapper)
        else:
            await original(store, wrapper)

    Store._async_write_data = physical
    try:
        yield
    finally:
        Store._async_write_data = original

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

from homeassistant.helpers import storage
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)
from sqlalchemy.exc import SQLAlchemyError

from tests.independent.hourly_r5.test_independent_hourly_r5 import (
    COST_ID,
    Coordinator,
    PsegStatisticsError,
    _Client,
    _daily_with,
    _day_rows,
    _hourly,
    _recs,
    _rows,
    entry_for,
    restart_runtime,
    rs,
)

pytestmark = pytest.mark.independent


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock, enable_custom_integrations):
    yield

@pytest.mark.parametrize('hourly_mode', [False, True])
async def test_real_store_physical_failure_refuses_before_recorder(hass, tmp_path, hourly_mode):
    entry = entry_for(hass)
    old = Coordinator(hass, _Client(), {}, config_entry=entry)
    state_store = old._stats_state
    store = state_store._store
    disk = Path(store.path)
    blocked = tmp_path / 'is-directory'
    blocked.mkdir()
    fault = {'enabled': False, 'failures': 0}

    # Restore the production executor path bypassed by pytest's mock_storage.
    # Keep production Store.async_save/_async_handle_write_data/error handling.
    async def physical_async_write(data):
        await hass.async_add_executor_job(store._write_data, data)

    def physical_prepared_write(mode, payload):
        try:
            storage.write_utf8_file_atomic(str(blocked if fault['enabled'] else disk), payload, False, mode=mode)
        except storage.WriteError:
            fault['failures'] += 1
            raise

    daily = _daily_with(_recs('2026-10-01', 2), '2026-10-02', 24)
    corrected = _daily_with(daily, '2026-10-01', 20)
    real_import = rs.import_statistics
    def fail_cost(instance, metadata, stats, table):
        if metadata['statistic_id'] == COST_ID:
            raise SQLAlchemyError('R4 actual recorder cost failure')
        return real_import(instance, metadata, stats, table)

    with patch.object(store, '_async_write_data', physical_async_write), patch.object(store, '_write_prepared_data', physical_prepared_write):
        await old.async_record_statistics(daily, meter_id='m1')
        baseline_bytes = disk.read_bytes()
        assert not json.loads(baseline_bytes)['data']['pending']
        fault['enabled'] = True
        with patch.object(rs, 'import_statistics', fail_cost):
            with pytest.raises(PsegStatisticsError):
                await asyncio.wait_for(old.async_record_statistics(corrected, meter_id='m1', hourly_records=_hourly('2026-10-02') if hourly_mode else [], hourly_granularity='hourly'), 5)
        await async_wait_recording_done(hass)
        before_cold = (_day_rows(await _rows(hass), '2026-10-01')[0][1], _day_rows(await _rows(hass, COST_ID), '2026-10-01')[0][1])
        crash_bytes = disk.read_bytes()
        assert fault['failures'] >= 1
        assert crash_bytes == baseline_bytes
        print('physical write failures', fault['failures'], 'recorder before cold', before_cold, 'revision falsely durable', state_store._saved_revision == state_store._revision, 'disk pending', bool(json.loads(crash_bytes)['data']['pending']))

    cold = restart_runtime(hass, entry, old)
    await cold._stats_state.async_load()
    assert cold._stats_state._data == json.loads(crash_bytes)['data']
    await cold.async_record_statistics(_recs('2026-10-02', 1, 24), meter_id='m1')
    after_cold = (_day_rows(await _rows(hass), '2026-10-01')[0][1], _day_rows(await _rows(hass, COST_ID), '2026-10-01')[0][1])
    print('recorder after cold', after_cold)
    assert before_cold == (10, 2.5), 'Physical journal write failed: recorder mutation must be refused'
    assert after_cold == (10, 2.5)

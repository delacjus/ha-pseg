import asyncio
import copy
import json
from pathlib import Path
import threading
from unittest.mock import patch

from homeassistant.helpers import storage
import pytest
from sqlalchemy.exc import SQLAlchemyError

from custom_components.pseg import statistics_state as sm
from tests.independent.hourly_r5.test_independent_hourly_r5 import (
    CONF_STATISTICS_IMPORT_ENABLED,
    CONSUMPTION_ID,
    COST_ID,
    Coordinator,
    PsegStatisticsError,
    _Client,
    _daily_with,
    _day_rows,
    _hourly,
    _recs,
    _rows,
    cm,
    entry_for,
    restart_runtime,
    rs,
)

pytestmark = pytest.mark.independent


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(recorder_mock, enable_custom_integrations):
    yield


@pytest.mark.parametrize('fault', [
    'missing', 'malformed', 'wrong_root', 'version', 'minor_version',
    'key', 'data', 'unreadable', 'read_error',
])
async def test_readback_fault_refuses_before_either_recorder_series(hass, fault):
    entry = entry_for(hass)
    c = Coordinator(hass, _Client(), {}, config_entry=entry)
    await c.async_record_statistics(_recs('2026-10-01', 2), meter_id='m1')
    state = c._stats_state
    disk = Path(state._store.path)
    write = state._store._write_data
    read = sm._read_json_file
    armed = {'read': False}

    def faulty_write(wrapper):
        write(wrapper)
        if fault == 'read_error':
            armed['read'] = True
            return
        if fault == 'missing':
            disk.unlink()
        elif fault == 'unreadable':
            disk.unlink()
            disk.mkdir()
        elif fault == 'malformed':
            disk.write_text('{')
        elif fault == 'wrong_root':
            disk.write_text('[]')
        else:
            bad = json.loads(disk.read_text())
            bad[fault] = {'wrong': 'snapshot'} if fault == 'data' else 'wrong'
            disk.write_text(json.dumps(bad))

    def maybe_read(path):
        if armed['read']:
            raise OSError('synthetic bounded read failure')
        return read(path)

    with patch.object(state._store, '_write_data', faulty_write), patch.object(sm, '_read_json_file', maybe_read), patch.object(cm, 'async_add_external_statistics') as queued:
        with pytest.raises(PsegStatisticsError, match='journal'):
            await asyncio.wait_for(c.async_record_statistics(_recs('2026-10-01', 1, 20), meter_id='m1'), 3)
        queued.assert_not_called()
    assert state.has_pending() and state._saved_revision < state._revision
    assert _day_rows(await _rows(hass), '2026-10-01')[0][1:] == (10, 10)
    assert _day_rows(await _rows(hass, COST_ID), '2026-10-01')[0][1:] == (2.5, 2.5)


@pytest.mark.parametrize('hourly_mode', [False, True])
async def test_actual_write_error_restore_io_partial_recorder_then_real_cold_load(hass, tmp_path, hourly_mode, caplog):
    entry = entry_for(hass)
    c = Coordinator(hass, _Client(), {}, config_entry=entry)
    daily = _daily_with(_recs('2026-10-01', 2), '2026-10-02', 24)
    await c.async_record_statistics(daily, meter_id='m1')
    state = c._stats_state
    disk = Path(state._store.path)
    before = disk.read_bytes()
    corrected = _daily_with(daily, '2026-10-01', 20)
    blocked = tmp_path / 'actual-write-error-directory'
    blocked.mkdir()
    physical_errors = []

    def bad_atomic(mode, payload):
        try:
            storage.write_utf8_file_atomic(str(blocked), payload, False, mode=mode)
        except storage.WriteError as err:
            physical_errors.append(type(err))
            raise

    with patch.object(state._store, '_write_prepared_data', bad_atomic), patch.object(cm, 'async_add_external_statistics') as queued:
        with pytest.raises(PsegStatisticsError, match='journal'):
            await asyncio.wait_for(c.async_record_statistics(corrected, meter_id='m1', hourly_records=_hourly('2026-10-02') if hourly_mode else [], hourly_granularity='hourly'), 3)
        queued.assert_not_called()
    assert physical_errors == [storage.WriteError]
    assert 'Error writing config for pseg.statistics.' in caplog.text
    assert disk.read_bytes() == before and not json.loads(before)['data']['pending']
    assert _day_rows(await _rows(hass), '2026-10-01')[0][1] == 10

    # Restore real I/O, save the retained intent, and fail actual recorder cost SQL.
    original_import = rs.import_statistics
    def cost_failure(instance, metadata, rows, table):
        if metadata['statistic_id'] == COST_ID:
            raise SQLAlchemyError('R5 independent real cost SQL failure')
        return original_import(instance, metadata, rows, table)
    with patch.object(rs, 'import_statistics', cost_failure):
        with pytest.raises(PsegStatisticsError, match='did not persist'):
            await asyncio.wait_for(c.async_record_statistics(_recs('2026-10-02', 1, 24), meter_id='m1'), 4)
    durable = json.loads(disk.read_text())['data']
    assert durable['pending']
    assert all(set(m['series']) == {COST_ID, CONSUMPTION_ID} for m in durable['pending'].values())
    assert _day_rows(await _rows(hass), '2026-10-01')[0][1] == 20
    assert _day_rows(await _rows(hass, COST_ID), '2026-10-01')[0][1] == 2.5

    cold = restart_runtime(hass, entry, c)
    await cold._stats_state.async_load()
    assert cold._stats_state._data == durable
    await asyncio.wait_for(cold.async_record_statistics(_recs('2026-10-02', 1, 24), meter_id='m1'), 4)
    energy, cost = await _rows(hass), await _rows(hass, COST_ID)
    assert _day_rows(energy, '2026-10-01')[0][1:] == (20, 20)
    assert _day_rows(cost, '2026-10-01')[0][1:] == (5, 5)
    assert energy[-1][2] == 44 and cost[-1][2] == 11
    assert not cold._stats_state.has_pending()


@pytest.mark.parametrize('hourly_mode', [False, True])
async def test_nondurable_provenance_commit_rearms_pending_and_real_cold_replays(hass, hourly_mode):
    entry = entry_for(hass)
    c = Coordinator(hass, _Client(), {}, config_entry=entry)
    daily = _daily_with(_recs('2026-10-01', 2), '2026-10-02', 24)
    await c.async_record_statistics(daily, meter_id='m1')
    state = c._stats_state
    disk = Path(state._store.path)
    original = state._store._write_data
    def drop_commit(wrapper):
        if wrapper['data']['pending']:
            original(wrapper)
    with patch.object(state._store, '_write_data', drop_commit):
        with pytest.raises(RuntimeError, match='provenance commit'):
            await asyncio.wait_for(c.async_record_statistics(_daily_with(daily, '2026-10-01', 20), meter_id='m1', hourly_records=_hourly('2026-10-02') if hourly_mode else [], hourly_granularity='hourly'), 4)
    assert state.has_pending() and state._saved_revision < state._revision
    durable = json.loads(disk.read_text())['data']
    assert durable['pending']
    cold = restart_runtime(hass, entry, c)
    await cold._stats_state.async_load()
    assert cold._stats_state._data == durable
    await cold.async_record_statistics(_recs('2026-10-02', 1, 24), meter_id='m1')
    assert (await _rows(hass))[-1][2] == 44
    assert (await _rows(hass, COST_ID))[-1][2] == 11
    assert not cold._stats_state.has_pending()


@pytest.mark.parametrize('control', ['pause', 'retire'])
@pytest.mark.parametrize('phase', ['begin', 'recovery'])
async def test_control_change_during_physical_readback_prevents_queue(hass, control, phase):
    entry = entry_for(hass)
    c = Coordinator(hass, _Client(), {}, config_entry=entry)
    await c.async_record_statistics(_recs('2026-10-01', 2), meter_id='m1')
    state = c._stats_state
    disk = Path(state._store.path)
    corrected = _recs('2026-10-01', 1, 20)
    if phase == 'recovery':
        with patch.object(state._store, '_write_data', lambda _wrapper: None):
            with pytest.raises(PsegStatisticsError):
                await c.async_record_statistics(corrected, meter_id='m1')
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    original_read = sm._read_json_file
    held = {'once': False}
    def held_read(path):
        document = original_read(path)
        if path == str(disk) and document['data']['pending'] and not held['once']:
            held['once'] = True
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(8):
                raise TimeoutError('bounded readback gate')
        return document
    task = None
    try:
        with patch.object(sm, '_read_json_file', held_read), patch.object(cm, 'async_add_external_statistics') as queued:
            task = asyncio.create_task(c.async_record_statistics(corrected, meter_id='m1'))
            await asyncio.wait_for(entered.wait(), 3)
            if control == 'pause':
                hass.config_entries.async_update_entry(entry, options={CONF_STATISTICS_IMPORT_ENABLED: False})
            else:
                c.stop_keepalive()
            release.set()
            await asyncio.wait_for(task, 3)
            queued.assert_not_called()
    finally:
        release.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert _day_rows(await _rows(hass), '2026-10-01')[0][1:] == (10, 10)
    assert _day_rows(await _rows(hass, COST_ID), '2026-10-01')[0][1:] == (2.5, 2.5)
    if phase == 'recovery':
        assert state.has_pending() and json.loads(disk.read_text())['data']['pending']


async def test_late_physical_save_after_actual_drain_never_publishes_newer_revision(hass):
    c = Coordinator(hass, _Client(), {})
    state = c._stats_state
    await state.async_load()
    disk = Path(state._store.path)
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    original_write = state._store._write_data
    seen = []
    def held_write(wrapper):
        seen.append(copy.deepcopy(wrapper['data']))
        if wrapper['data']['marker']['value'] == 'old':
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(12):
                raise TimeoutError('bounded late write')
        original_write(wrapper)
    state._data['marker'] = {'value': 'old'}
    state._mark_dirty()
    task = None
    started = loop.time()
    try:
        with patch.object(state._store, '_write_data', held_write):
            task = asyncio.create_task(state.async_wait_durable(drain_on_cancel=True))
            await asyncio.wait_for(entered.wait(), 3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 7)
            assert loop.time() - started >= 5
            state._data['marker']['value'] = 'new'
            state._mark_dirty()
            assert not await asyncio.wait_for(state.async_wait_durable(refuse_outstanding=True), 1)
            assert state._saved_revision < state._revision
            release.set()
            assert await asyncio.wait_for(state.async_wait_durable(), 3)
    finally:
        release.set()
        async with asyncio.timeout(3):
            async with state._io_lock:
                pass
    assert [snap['marker']['value'] for snap in seen] == ['old', 'new']
    assert json.loads(disk.read_text())['data']['marker']['value'] == 'new'
    assert state._saved_revision == state._revision == 2


async def test_real_readback_timeout_refuses_boundedly_then_recovers(hass):
    entry = entry_for(hass)
    c = Coordinator(hass, _Client(), {}, config_entry=entry)
    await c.async_record_statistics(_recs('2026-10-01', 2), meter_id='m1')
    state = c._stats_state
    disk = Path(state._store.path)
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    original = sm._read_json_file
    held = {'once': False}
    def delayed_read(path):
        wrapper = original(path)
        if path == str(disk) and wrapper['data']['pending'] and not held['once']:
            held['once'] = True
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(12):
                raise TimeoutError('bounded stalled read')
        return wrapper
    started = loop.time()
    try:
        with patch.object(sm, '_read_json_file', delayed_read), patch.object(cm, 'async_add_external_statistics') as queued:
            with pytest.raises(PsegStatisticsError, match='journal'):
                await asyncio.wait_for(c.async_record_statistics(_recs('2026-10-01', 1, 20), meter_id='m1'), 7)
            assert entered.is_set()
            assert 4.9 <= loop.time() - started < 6.5
            queued.assert_not_called()
            assert state._saved_revision < state._revision and state.has_pending()
    finally:
        release.set()
        if state._save_task is not None:
            await asyncio.wait_for(asyncio.gather(state._save_task, return_exceptions=True), 3)
    assert _day_rows(await _rows(hass), '2026-10-01')[0][1] == 10
    # The timed-out read may finish later but cannot authorize recorder mutation.
    # Recovery either consumes its failed task or retries the retained intent.
    try:
        await c.async_record_statistics(_recs('2026-10-02', 1), meter_id='m1')
    except PsegStatisticsError:
        await c.async_record_statistics(_recs('2026-10-02', 1), meter_id='m1')
    assert _day_rows(await _rows(hass), '2026-10-01')[0][1:] == (20, 20)
    assert _day_rows(await _rows(hass, COST_ID), '2026-10-01')[0][1:] == (5, 5)

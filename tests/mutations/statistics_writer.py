"""S5 writer faults against exact production preimages, never the active tree.

Five-field rows use the P1 mutation engine unchanged. COVERAGE records the real
writer function, physical assertion and preserved legacy/independent crosswalk.
The focused detectors live in fault_cases (the only permitted detector addition).
"""

F = "tests/stats_suite/fault_cases.py::"
P = "tests/stats_suite/test_fault_points.py::"
R = "tests/stats_suite/test_reference_model.py::"
S = "tests/stats_suite/test_store_schema.py::"
L = "tests/test_statistics_recorder.py::"
INDEPENDENT = "tests/independent/hourly_r5/test_independent_hourly_guards.py::"

MUTATIONS = [
    (
        "w01-drop-physical-readback", "statistics_state.py",
        "                persisted = await self._hass.async_add_executor_job(\n"
        "                    _read_json_file, path\n                )",
        "                persisted = {\"version\": self._store.version,\n"
        "                             \"minor_version\": self._store.minor_version,\n"
        "                             \"key\": self._store.key, \"data\": snapshot}",
        F + "test_writer_refuses_a_dropped_physical_journal",
    ),
    (
        "w02-skip-second-series-verification", "coordinator.py",
        "        for statistic_id, raw_rows in series.items():\n            intended:",
        "        for statistic_id, raw_rows in list(series.items())[:1]:\n            intended:",
        F + "test_writer_partial_sql_failure_and_cold_replay[normal]",
    ),
    (
        "w03-clear-journal-before-import", "coordinator.py",
        "        consumption_metadata, cost_metadata = _statistic_metadata(clean_meter)\n"
        "        async_add_external_statistics(self.hass, consumption_metadata, consumption_stats)",
        "        consumption_metadata, cost_metadata = _statistic_metadata(clean_meter)\n"
        "        await self._stats_state.async_commit(mutation_id)\n"
        "        async_add_external_statistics(self.hass, consumption_metadata, consumption_stats)",
        P + "test_fast_tier_partial_series_commit_control",
    ),
    (
        "w04-daily-overwrites-promotion", "coordinator.py",
        (
            "            if day in promote or day in protected:",
            "            hourly_consumption,\n            protected,",
            "            hourly_cost,\n            protected,",
        ),
        (
            "            if day in promote:",
            "            hourly_consumption,\n            set(),",
            "            hourly_cost,\n            set(),",
        ),
        R + "test_recorder_no_downgrade_both_series",
    ),
    (
        "w05-bypass-live-pause", "coordinator.py",
        "        if not self.statistics_imports_enabled():\n"
        "            _LOGGER.debug(\"Statistics imports are disabled for this PSE&G entry\")\n"
        "            return False",
        "        if False:\n"
        "            _LOGGER.debug(\"Statistics imports are disabled for this PSE&G entry\")\n"
        "            return False",
        F + "test_writer_control_after_durable_journal[pause]",
    ),
    (
        "w06-bypass-retirement", "coordinator.py",
        "        if self._is_stale() or not self._stats_runtime.is_current(self._stats_token):",
        "        if False:",
        F + "test_writer_control_after_durable_journal[retire]",
    ),
    (
        "w07-miss-recorder-commit-barrier", "coordinator.py",
        "                await _async_wait_for_recorder_commit(self.hass)\n"
        "        except TimeoutError as err:\n            raise PsegStatisticsError(\n"
        "                f\"Recorder did not commit the statistics import",
        "                pass\n"
        "        except TimeoutError as err:\n            raise PsegStatisticsError(\n"
        "                f\"Recorder did not commit the statistics import",
        F + "test_writer_verifies_only_after_physical_commit",
    ),
    (
        "w08-recovery-omits-cost-import", "coordinator.py",
        "            async_add_external_statistics(self.hass, metadata, stats)",
        "            if statistic_id.endswith(\"_energy_consumption\"):\n"
        "                async_add_external_statistics(self.hass, metadata, stats)",
        F + "test_writer_partial_sql_failure_and_cold_replay[normal]",
    ),
    (
        "w09-lose-pending-journal", "statistics_state.py",
        "        mutation_id = uuid.uuid4().hex\n        self._data[\"pending\"][mutation_id] = mutation",
        "        mutation_id = uuid.uuid4().hex\n        self._data[\"pending\"].clear()",
        S + "test_begin_writes_the_golden_document_byte_for_byte",
    ),
    (
        "w10-double-count-repeat-daily-import", "statistics_hourly.py",
        "        by_start[start] = value",
        "        by_start[start] = (by_start.get(start) or 0.0) + value",
        R + "test_recorder_repeat_idempotence_both_series",
    ),
    (
        "w11-corrupt-cumulative-suffix", "statistics_hourly.py",
        "        running += state or 0.0",
        "        running += 2 * (state or 0.0)",
        R + "test_recorder_smoke_comparison_both_series",
    ),
    (
        "w12-ignore-older-correction", "statistics_hourly.py",
        "        by_start[start] = value",
        "        by_start.setdefault(start, value)",
        R + "test_recorder_older_correction_recomputes_suffix_both_series",
    ),
    (
        "w13-reparse-canonical-replay-start", "coordinator.py",
        "                start = datetime.fromisoformat(str(raw_start))\n"
        "                if start.tzinfo is None:",
        "                start = datetime.fromisoformat(str(raw_start))\n"
        "                start = start.replace(tzinfo=dt_util.get_time_zone(\"America/New_York\")).astimezone(UTC)\n"
        "                if start.tzinfo is None:",
        F + "test_writer_partial_sql_failure_and_cold_replay[fall25]",
    ),
]

# Each tuple: production function, physical effect/assertion, related old node.
COVERAGE = {
    "w01-drop-physical-readback": (
        "StatisticsStateStore._async_verify_persisted", "DB unchanged when disk drops pending write",
        INDEPENDENT + "test_readback_fault_refuses_before_either_recorder_series",
    ),
    "w02-skip-second-series-verification": (
        "PsegDataUpdateCoordinator._async_verify_mutation", "disk pending retained with cost DB empty",
        L + "test_recorder_series_failure_retains_journal_until_recovered",
    ),
    "w03-clear-journal-before-import": (
        "PsegDataUpdateCoordinator._async_record_statistics_locked", "disk pending after partial import",
        L + "test_recorder_series_failure_retains_journal_until_recovered",
    ),
    "w04-daily-overwrites-promotion": (
        "PsegDataUpdateCoordinator._async_record_statistics_locked", "both DB series retain hourly states",
        L + "test_partial_hourly_for_promoted_day_keeps_hourly",
    ),
    "w05-bypass-live-pause": (
        "PsegDataUpdateCoordinator._can_mutate_statistics", "both DB series empty after pause",
        L + "test_pause_during_final_read_prevents_write",
    ),
    "w06-bypass-retirement": (
        "PsegDataUpdateCoordinator._can_mutate_statistics", "both DB series empty after retirement",
        L + "test_retired_backfill_cannot_overwrite_new_promotion",
    ),
    "w07-miss-recorder-commit-barrier": (
        "PsegDataUpdateCoordinator._async_record_statistics_locked", "both DB series durable before verify",
        L + "test_import_waits_for_recorder_commit_before_next_baseline",
    ),
    "w08-recovery-omits-cost-import": (
        "PsegDataUpdateCoordinator._async_replay_mutation", "cold cost DB equals independent model",
        L + "test_journal_replays_same_batch_daily_correction",
    ),
    "w09-lose-pending-journal": (
        "StatisticsStateStore.async_begin", "literal pending Store document on disk",
        INDEPENDENT + "test_actual_write_error_restore_io_partial_recorder_then_real_cold_load",
    ),
    "w10-double-count-repeat-daily-import": (
        "merge_series_rows", "repeat DB states and sums equal independent model",
        L + "test_partial_backfill_rechains_newer_rows",
    ),
    "w11-corrupt-cumulative-suffix": (
        "chain_rows", "both DB cumulative sums equal independent model",
        L + "test_partial_backfill_rechains_newer_rows",
    ),
    "w12-ignore-older-correction": (
        "merge_series_rows", "corrected DB states and suffix sums equal independent model",
        L + "test_partial_backfill_rechains_newer_rows",
    ),
    "w13-reparse-canonical-replay-start": (
        "PsegDataUpdateCoordinator._async_replay_mutation", "cold DB retains all 25 canonical UTC starts",
        P + "test_canonical_aware_25_hour_recovery_no_reparsing",
    ),
}

EXCLUDED = {
    "duplicate-queue-submission": (
        "Identical start keys are recorder upserts, so duplicate submission alone has no physical "
        "corruption. w10 instead models additive double-counting on repeat."
    ),
    "partial-sql-error-as-success": (
        "Covered by w02: real recorder import_statistics raises SQLAlchemyError for cost, "
        "HA swallows the task error, and skipping its verification falsely clears disk pending."
    ),
    "raw-hour-start-reparse": (
        "Parser ownership is P3-07; w13 covers the writer replay of persisted canonical starts."
    ),
}

"""Opt-in, offline proof that the auth regression tests detect removed guards.

Run from the repository root with .venv/bin/python tests/auth_guard_mutations.py.
Requires an otherwise idle sole-writer checkout. Each mutation is restored byte
for byte in finally; bounded pytest subprocesses use only synthetic adapters.
"""

from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "custom_components" / "pseg"
R1 = "tests/test_auth_review_regressions.py::"
R2 = "tests/test_auth_review_r2_regressions.py::"
R3 = "tests/test_auth_review_r3_regressions.py::"
R4 = "tests/test_auth_review_r4_regressions.py::"
R5 = "tests/test_auth_review_r5_regressions.py::"
MUTATIONS = [
    (
        "1-entry-shared-admission", "coordinator.py",
        "self._renewal_runtime = renewal_runtime_for(hass, config_entry.entry_id)",
        "self._renewal_runtime = type(renewal_runtime_for(hass, config_entry.entry_id))(config_entry.entry_id)",
        R1 + "test_replacement_uses_live_reservation_instead_of_stale_persisted_copy",
    ),
    (
        "1-immediate-owner-check", "pseg_client.py",
        (
            "if self._renewal_runtime is not None and not self._renewal_runtime.can_dispatch(",
            "        if self._owner_check is not None:\n            self._owner_check()",
        ),
        (
            "if False and self._renewal_runtime is not None and not self._renewal_runtime.can_dispatch(",
            "        if False and self._owner_check is not None:\n            self._owner_check()",
        ),
        R1 + "test_retirement_between_reservation_and_immediate_dispatch_sends_nothing",
    ),
    (
        "2-independent-policy-handoff", "renewal_admission.py",
        "        with self.lock:\n            state = self.admission_dict()",
        "        return\n        with self.lock:\n            state = self.admission_dict()",
        R1 + "test_failed_first_refresh_persists_terminal_admission",
    ),
    (
        "3-poll-identity-proof", "pseg_client.py",
        "self._renew_remember_me_sequence(verify_identity=True)",
        "self._renew_remember_me_sequence(verify_identity=False)",
        R1 + "test_poll_failure_does_not_rearm_unconfirmed_rotation",
    ),
    (
        "4-post-await-retirement", "coordinator.py",
        "await self._async_persist_cookies()\n        self._persist_confirmed_session()\n        if self._is_stale():\n            return",
        "await self._async_persist_cookies()\n        self._persist_confirmed_session()",
        R1 + "test_retired_keepalive_cannot_dismiss_replacement_auth_issue",
    ),
    (
        "5-pre-probe-confirmed-jar", "pseg_client.py",
        "self._restore_session_jar(baseline)\n        return self._renew_local_cookie_session(baseline=baseline)",
        "return self._renew_local_cookie_session(baseline=self._snapshot_session_state())",
        R1 + "test_probe_rotation_is_rolled_back_after_transient_renewal",
    ),
    (
        "6-present-corrupt-refusal", "renewal_admission.py",
        "if not isinstance(raw, dict):\n            return cls(uncertain=True)",
        "if not isinstance(raw, dict):\n            return cls()",
        R1 + "test_uncertain_metadata_refuses",
    ),
    (
        "7-transient-only-retry", "renewal_admission.py",
        "if self.sequences and not self.retry_eligible:",
        "if False and self.sequences and not self.retry_eligible:",
        R1 + "test_success_without_rotation_does_not_authorize_transient_retry",
    ),
    (
        "setup-human-account-proof", "config_flow.py",
        "if not client.has_remember_me:\n                    await self.hass.async_add_executor_job(client.ensure_session)",
        "if True:\n                    await self.hass.async_add_executor_job(client.ensure_session)",
        R1 + "test_fresh_human_remember_cookie_setup_uses_its_account_proof",
    ),
    (
        "8-post-renewal-verified-keep", "pseg_client.py",
        "if resp.status_code != 200 or not self._on_dashboard(resp):\n            if not renewed:\n                self._restore_session_state(baseline)",
        "if resp.status_code != 200 or not self._on_dashboard(resp):\n            if True:\n                self._restore_session_state(baseline)",
        R2 + "test_poll_keeps_the_verified_renewal_after_a_post_renewal_hiccup",
    ),
    (
        "9-post-renewal-token-keep", "pseg_client.py",
        "            if not renewed:\n                self._restore_session_state(baseline)\n            raise PsegTransientError(\"__RequestVerificationToken not found on /Dashboard\")",
        "            self._restore_session_state(baseline)\n            raise PsegTransientError(\"__RequestVerificationToken not found on /Dashboard\")",
        R2 + "test_poll_keeps_the_verified_renewal_after_a_post_renewal_hiccup",
    ),
    (
        "10-cooldown-is-transient", "pseg_client.py",
        "                    if deferred.reason == \"cooldown\":",
        "                    if False and deferred.reason == \"cooldown\":",
        R2 + "test_poll_during_an_earned_retry_cooldown_keeps_the_schedule",
    ),
    (
        "11-uncertain-fails-closed", "pseg_client.py",
        "        if deferred.reason in {\"cooldown\", \"busy\", \"retired\"}:",
        "        if deferred.reason in {\"cooldown\", \"busy\", \"retired\", \"uncertain\"}:",
        R2 + "test_corrupt_budget_prompts_the_normal_reauth_flow",
    ),
    (
        "12-confirmed-generation", "pseg_client.py",
        "                self._mark_session_ok()\n                self._note_confirmed_generation()",
        "                self._mark_session_ok()",
        R2 + "test_confirmed_dashboard_slide_is_not_a_renewal_rotation",
    ),
    (
        "12-confirmed-generation-dedupe", "pseg_client.py",
        "        self._dedupe_domain_variants()\n        self._remember_me_seen = self._remember_me_values()",
        "        self._remember_me_seen = self._remember_me_values()",
        R2 + "test_confirmed_slide_with_a_domain_copy_is_not_a_renewal_rotation",
    ),
    (
        "13-security-step-latch", "pseg_client.py",
        "        if reason == AUTH_REASON_SECURITY_STEP:\n            # A security question/password change can only be answered by a human:\n            # latch it so no later tick retries the form or the cookie renewal.\n            self._security_step_latched = True",
        "        if reason == AUTH_REASON_SECURITY_STEP:\n            # A security question/password change can only be answered by a human:\n            # latch it so no later tick retries the form or the cookie renewal.\n            self._security_step_latched = False",
        R3 + "test_poll_fallback_challenge_survives_reload_and_cold_process[security-security_step-PsegSecurityStepRequired]",
    ),
    (
        "14-confirmed-snapshot-capture", "pseg_client.py",
        (
            "        self._mark_session_ok()\n        self._capture_confirmed_session()\n        _LOGGER.info(\"MyMeter Remember Me renewal successful\")",
            "                if (\n                    snapshot is None\n                    or snapshot[\"cookies\"] != exported",
        ),
        (
            "        self._mark_session_ok()\n        _LOGGER.info(\"MyMeter Remember Me renewal successful\")",
            "                if False and (\n                    snapshot is None\n                    or snapshot[\"cookies\"] != exported",
        ),
        R3 + "test_setup_persists_confirmed_renewal_before_a_later_chart_timeout[False]",
    ),
    (
        "15-confirmed-stop-handoff", "coordinator.py",
        "        self._persist_auth_metadata()\n        self._persist_confirmed_session()\n        self._stopped = True",
        "        self._persist_auth_metadata()\n        self._stopped = True",
        R3 + "test_stop_keepalive_persists_a_confirmed_renewal_before_retiring",
    ),
    (
        "16-confirmed-snapshot-not-live-jar", "coordinator.py",
        "        exported = snapshot[\"cookies\"]",
        "        exported = self.client.export_cookies()",
        R3 + "test_failed_response_poison_cookie_is_never_persisted_or_replayed",
    ),
    (
        "17-confirmed-stale-owner-guard", "coordinator.py",
        "        if not self.config_entry or self._is_stale():\n            return\n        snapshot = self.client.pending_confirmed_snapshot()",
        "        if not self.config_entry:\n            return\n        snapshot = self.client.pending_confirmed_snapshot()",
        R3 + "test_stale_owner_never_overwrites_a_human_replaced_jar",
    ),
    (
        "18-confirmed-partial-jar-guard", "coordinator.py",
        "        if not self._persisted_session_cookies <= session_cookies:\n            _LOGGER.debug(\"Not persisting a partial confirmed cookie jar\")",
        "        if False and not self._persisted_session_cookies <= session_cookies:\n            _LOGGER.debug(\"Not persisting a partial confirmed cookie jar\")",
        R3 + "test_partial_confirmed_snapshot_is_never_persisted",
    ),
    (
        "19-settled-spent-is-exhausted", "renewal_admission.py",
        "            # A settled attempt that earned no retry can never run again, even while\n            # its 15-minute window is still open. Do not promise a later attempt.\n            return \"exhausted\"",
        "            return \"cooldown\"",
        R3 + "test_settled_unchanged_success_is_exhausted_before_its_window_closes",
    ),
    (
        "20-durable-challenge-admission", "pseg_client.py",
        "        if reason in {AUTH_REASON_CAPTCHA_REQUIRED, AUTH_REASON_SECURITY_STEP}:\n            self._record_terminal_admission(reason)",
        "        if False and reason in {AUTH_REASON_CAPTCHA_REQUIRED, AUTH_REASON_SECURITY_STEP}:\n            self._record_terminal_admission(reason)",
        R3 + "test_failed_startup_challenge_is_durable_metadata[captcha]",
    ),
    (
        "21-durable-challenge-no-background-http", "pseg_client.py",
        "        self._refuse_if_captcha_latched()\n        self._refuse_if_security_step_latched()\n        self._refuse_if_terminal_step()\n        previous_in_keepalive = self._in_keepalive",
        "        self._refuse_if_captcha_latched()\n        self._refuse_if_security_step_latched()\n        previous_in_keepalive = self._in_keepalive",
        R3 + "test_poll_fallback_challenge_survives_reload_and_cold_process[security-security_step-PsegSecurityStepRequired]",
    ),
    (
        "22-exhausted-no-password-fallback", "pseg_client.py",
        "                if deferred.reason == \"exhausted\":",
        "                if False and deferred.reason == \"exhausted\":",
        R3 + "test_setup_with_spent_generation_is_an_auth_error_not_a_password_post",
    ),
    (
        "23-optional-hourly-jar-quarantine", "pseg_client.py",
        "        cookies, seen = leg_snapshot\n        self.session.cookies = copy.deepcopy(cookies)\n        self._remember_me_seen = seen",
        "        return",
        R4 + "test_optional_hourly_failed_response_cannot_replace_proof_jar[review_aux-500-/Dashboard/Chart]",
    ),
    (
        "24-optional-hourly-stage-rollback", "pseg_client.py",
        "        except PsegTransientError as err:\n            self._restore_cookie_leg(hourly_leg)",
        "        except PsegTransientError as err:",
        R4 + "test_optional_hourly_setup_200_cookie_is_rolled_back_when_chart_data_fails[empty_data]",
    ),
    (
        "25-persist-confirmed-cookies-guard", "coordinator.py",
        "        if confirmed_cookies is not None and exported != confirmed_cookies:",
        "        if False and confirmed_cookies is not None and exported != confirmed_cookies:",
        R4 + "test_persist_cookies_refuses_unconfirmed_live_jar_mutation_and_keeps_confirmed_snapshot",
    ),
    (
        "26-active-owner-dispatch-guard", "pseg_client.py",
        "            and not runtime.is_active(self._renewal_token)",
        "            and False and not runtime.is_active(self._renewal_token)",
        R4 + "test_real_unload_retires_saved_password_fallback[dashboard-real_unload-False]",
    ),
    (
        "27-remember-me-inflight-owner-guard", "pseg_client.py",
        ("        resp = self._get_dashboard()\n        if verify_identity:\n            self._check_renewal_owner()\n        else:\n            self._check_active_owner()", "        if self._owner_check is not None:\n            self._owner_check()"),
        ("        resp = self._get_dashboard()", "        if False and self._owner_check is not None:\n            self._owner_check()"),
        R4 + "test_real_unload_retires_saved_password_fallback[dashboard-real_unload-True]",
    ),
    (
        "28-login-form-entry-owner-guard", "pseg_client.py",
        ("    def _login_form_token(self) -> str:\n        \"\"\"GET the login page and return its antiforgery token ('' if absent).\"\"\"\n        self._check_active_owner()", "        if self._owner_check is not None:\n            self._owner_check()"),
        ("    def _login_form_token(self) -> str:\n        \"\"\"GET the login page and return its antiforgery token ('' if absent).\"\"\"", "        if False and self._owner_check is not None:\n            self._owner_check()"),
        R4 + "test_real_unload_retires_saved_password_fallback[dashboard-real_unload-False]",
    ),
    (
        "29-login-post-owner-guard", "pseg_client.py",
        ("    def _post_login(self, token: str, captcha_response: str) -> None:\n        \"\"\"POST /Home/Login and classify the reply (raises on any refusal).\"\"\"\n        self._check_active_owner()", "        if self._owner_check is not None:\n            self._owner_check()"),
        ("    def _post_login(self, token: str, captcha_response: str) -> None:\n        \"\"\"POST /Home/Login and classify the reply (raises on any refusal).\"\"\"", "        if False and self._owner_check is not None:\n            self._owner_check()"),
        R4 + "test_real_unload_retires_saved_password_fallback[login_form-real_unload-False]",
    ),
    (
        "30-sso-entry-owner-guard", "pseg_client.py",
        ("        self._check_active_owner()\n        baseline = self._snapshot_session_state()\n        try:\n            return self._renew_sso_locked()", "        if self._owner_check is not None:\n            self._owner_check()"),
        ("        baseline = self._snapshot_session_state()\n        try:\n            return self._renew_sso_locked()", "        if False and self._owner_check is not None:\n            self._owner_check()"),
        R4 + "test_real_unload_retires_sso_fallback[dashboard-real_unload]",
    ),
    (
        "31-sso-post-owner-guard", "pseg_client.py",
        ("        self._check_active_owner()\n        try:\n            post_resp = self.session.post(action_url, data=data, allow_redirects=True, timeout=25)", "        if self._owner_check is not None:\n            self._owner_check()"),
        ("        try:\n            post_resp = self.session.post(action_url, data=data, allow_redirects=True, timeout=25)", "        if False and self._owner_check is not None:\n            self._owner_check()"),
        R4 + "test_real_unload_retires_sso_fallback[saml_form-real_unload]",
    ),
    (
        "32-structural-session-send-owner-guard", "pseg_client.py",
        "        if self._owner_check is not None:\n            self._owner_check()",
        "        if False and self._owner_check is not None:\n            self._owner_check()",
        R5 + "test_saml_redirect_cannot_dispatch_new_post_after_retirement[real_unload]",
    ),
    (
        "33-post-renewal-failed-dashboard-leg-restore", "pseg_client.py",
        "        if resp.status_code != 200 or not self._on_dashboard(resp):\n            if not renewed:\n                self._restore_session_state(baseline)\n            if post_renewal_leg is not None:\n                self._restore_cookie_leg(post_renewal_leg)",
        "        if resp.status_code != 200 or not self._on_dashboard(resp):\n            if not renewed:\n                self._restore_session_state(baseline)",
        R5 + "test_postproof_failed_dashboard_cookie_cannot_be_promoted_by_next_poll[MM_SID-maint]",
    ),
    (
        "34-post-renewal-missing-token-leg-restore", "pseg_client.py",
        "            if post_renewal_leg is not None:\n                self._restore_cookie_leg(post_renewal_leg)\n            if not renewed:\n                self._restore_session_state(baseline)",
        "            if not renewed:\n                self._restore_session_state(baseline)",
        R5 + "test_postproof_failed_dashboard_cookie_cannot_be_promoted_by_next_poll[MM_SID-notoken]",
    ),
    (
        "35-post-renewal-exception-leg-restore", "pseg_client.py",
        "            except Exception:\n                self._restore_cookie_leg(post_renewal_leg)\n                raise",
        "            except Exception:\n                raise",
        R5 + "test_postproof_failed_dashboard_cookie_cannot_be_promoted_by_next_poll[MM_SID-500]",
    ),
    (
        "36-hourly-records-validation-before-confirm", "pseg_client.py",
        "            hourly = self._parse_hourly_chart(hourly_payload)\n            if not self._has_valid_meter_read(\n                hourly[\"hourly_records\"],\n                hourly.get(\"meter_ids\") or [],\n            ):\n                raise PsegTransientError(",
        "            hourly = self._parse_hourly_chart(hourly_payload)\n            if False and not self._has_valid_meter_read(\n                hourly[\"hourly_records\"],\n                hourly.get(\"meter_ids\") or [],\n            ):\n                raise PsegTransientError(",
        R5 + "test_invalid_hourly_200_does_not_replace_proven_whole_jar[MM_SID-empty_meter]",
    ),
    (
        "37-hourly-root-dict-validation", "pseg_client.py",
        (
            "        if not isinstance(data, dict):\n            raise PsegTransientError(\"No chart data returned for hourly statistics.\")",
            "        if not isinstance(data, dict):\n            raise PsegTransientError(\"Malformed JSON root from chart data\")",
        ),
        (
            "        if False and not isinstance(data, dict):\n            raise PsegTransientError(\"No chart data returned for hourly statistics.\")",
            "        if False and not isinstance(data, dict):\n            raise PsegTransientError(\"Malformed JSON root from chart data\")",
        ),
        R5 + "test_invalid_hourly_200_does_not_replace_proven_whole_jar[MM_SID-root_list]",
    ),
    (
        "38-latest-confirmed-checkpoint-publish", "pseg_client.py",
        "                snapshot = self._confirmed_snapshot\n                if (\n                    snapshot is None\n                    or snapshot[\"cookies\"] != exported",
        "                snapshot = self._confirmed_snapshot\n                if False and (\n                    snapshot is None\n                    or snapshot[\"cookies\"] != exported",
        R5 + "test_latest_valid_hourly_jar_survives_cancel_or_stop[MM_SID-cancel_poll-True]",
    ),
    (
        "39-daily-validation-before-confirm", "pseg_client.py",
        "            if self._has_valid_meter_read(\n                result.get(\"history_14d\") or [],\n                result.get(\"meter_ids\") or [],\n            ):",
        "            if True or self._has_valid_meter_read(\n                result.get(\"history_14d\") or [],\n                result.get(\"meter_ids\") or [],\n            ):",
        R5 + "test_daily_leg_requires_valid_meter_read_before_confirming_cookie[MM_SID-empty_meter-False]",
    ),
    (
        "40-history-chunk-acceptance-checkpoint", "pseg_client.py",
        "                        else:\n                            self._note_confirmed_generation()\n                            last_validated_leg = self._snapshot_cookie_leg()",
        "                        else:\n                            last_validated_leg = self._snapshot_cookie_leg()",
        R5 + "test_valid_backfill_chunk_rotation_persisted_on_unload[MM_SID]",
    ),
    (
        "41-history-gap-abort-rollback", "pseg_client.py",
        (
            "                    self._restore_cookie_leg(chunk_leg)\n                    _LOGGER.warning(\"No chart data returned for range %s to %s\", chunk_start_str, chunk_end_str)",
            "                if not had_data:\n                    self._restore_cookie_leg(last_validated_leg)\n                    raise PsegTransientError(",
        ),
        (
            "                    _LOGGER.warning(\"No chart data returned for range %s to %s\", chunk_start_str, chunk_end_str)",
            "                if not had_data:\n                    raise PsegTransientError(",
        ),
        R5 + "test_backfill_invalid_or_empty_chunk_cookie_is_quarantined[MM_SID-abort_null_data]",
    ),
    (
        "42-own-save-owner-predicate", "coordinator.py",
        "        writing = self._jar_writing_target\n        return not (writing is not None and current == writing)",
        "        return True",
        R5 + "test_owner_predicate_true_during_own_write_and_false_on_foreign_replace",
    ),
    (
        "43-atomic-checkpoint-compare-clear", "pseg_client.py",
        "        with self._checkpoint_lock:\n            snapshot = self._confirmed_snapshot\n            if snapshot is not None and snapshot[\"id\"] == snapshot_id:\n                self._confirmed_snapshot = None",
        "        with self._checkpoint_lock:\n            self._confirmed_snapshot = None",
        R5 + "test_checkpoint_lock_synchronizes_publish_and_clear",
    ),
    (
        "44-nested-series-and-ajax-shape-guard", "pseg_client.py",
        (
            "            raw_points = s.get(\"data\")\n            if raw_points is not None and not isinstance(raw_points, list):\n                raise PsegTransientError(\"Malformed meter data series from chart data\")",
            "        ajax_results = data.get(\"AjaxResults\")\n        if ajax_results is not None and not isinstance(ajax_results, list):\n            raise PsegTransientError(f\"Malformed AjaxResults from {context}\")",
            "            except Exception as err:\n                self._restore_cookie_leg(chunk_leg)\n                raise PsegTransientError(\n                    f\"Malformed history chart payload ({type(err).__name__})\"\n                ) from err",
        ),
        (
            "            raw_points = s.get(\"data\")",
            "        ajax_results = data.get(\"AjaxResults\")",
            "            except Exception:\n                raise",
        ),
        R5 + "test_r7b_malformed_nested_chart_shapes_quarantined_across_all_legs[MM_SID-meter_data_integer-backfill]",
    ),
    (
        "45-per-record-contributor-provenance", "pseg_client.py",
        "        contributors = set(_contributing_meter_ids(records))\n        if meter_ids is not None:\n            seen = {str(value) for value in (meter_ids or []) if value}\n            contributors &= seen",
        "        contributors = {str(value) for value in (meter_ids or []) if value}",
        R5 + "test_r7b_known_decoy_series_with_unknown_valid_records_rejected[known_empty_unknown_valid-daily]",
    ),
    (
        "46-rejected-daily-quarantines-result", "pseg_client.py",
        "                else:\n                    result = self._empty_chart_result(result.get(\"last_updated\"))",
        "                else:\n                    pass",
        R5 + "test_r7b_proven_meter_learning_and_rejected_daily_isolation",
    ),
    (
        "47-handoff-finally-baseline-reconcile", "coordinator.py",
        "            try:\n                self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)\n            finally:\n                if self.config_entry.data.get(\"cookies\") == exported:\n                    self._jar_baseline = exported\n                    self._persisted_session_cookies = session_cookies\n                self._jar_writing_target = None",
        "            try:\n                self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)\n            finally:\n                self._jar_writing_target = None\n            if self.config_entry.data.get(\"cookies\") == exported:\n                self._jar_baseline = exported\n                self._persisted_session_cookies = session_cookies",
        R5 + "test_r7b_write_cookie_handoff_reconciles_baseline_across_update_faults[True]",
    ),
    (
        "48-history-chart-envelope-guard", "pseg_client.py",
        "                data = self._validate_chart_envelope(resp3.json())",
        "                data = resp3.json()",
        R5
        + "test_r7b_malformed_nested_chart_shapes_quarantined_across_all_legs"
        "[MM_SID-ajax_results_integer_with_valid_data-backfill]",
    ),
    (
        "49-live-chart-envelope-guard", "pseg_client.py",
        "            return self._validate_chart_envelope(resp3.json())",
        "            return resp3.json()",
        R5
        + "test_r7b_malformed_nested_chart_shapes_quarantined_across_all_legs"
        "[MM_SID-ajax_results_integer_with_valid_data-daily]",
    ),
    (
        "50-renewal-empty-expected-fail-closed", "pseg_client.py",
        "        if require_expected and not expected:\n            return False",
        "        if False:\n            return False",
        R5 + "test_r7b_records_without_per_meter_provenance_never_prove_identity",
    ),
    (
        "51-human-label-identity-only", "pseg_client.py",
        "                if self._allow_label_identity and not self._expected_meter_ids and label_ids:",
        "                if False and self._allow_label_identity and not self._expected_meter_ids and label_ids:",
        R5 + "test_r8_fresh_cookie_setup_survives_lagging_daily_window[label_no_points]",
    ),
    (
        "52-rejected-daily-typed-failure", "coordinator.py",
        "                if data.get(\"identity_confirmed\") is False:",
        "                if False and data.get(\"identity_confirmed\") is False:",
        R5 + "test_r8_rejected_daily_real_refresh_keeps_previous_data",
    ),
    (
        "53-daily-hourly-contributor-union", "pseg_client.py",
        "            merged = list(daily_contributors)\n            merged.extend(value for value in hourly_contributors if value not in merged)\n            result[\"contributing_meter_ids\"] = merged\n            result[\"meter_ids\"] = merged",
        "            result[\"contributing_meter_ids\"] = list(hourly_contributors)\n            result[\"meter_ids\"] = list(hourly_contributors)",
        R5 + "test_r8_daily_successor_learned_when_hourly_omits_it",
    ),
    (
        "54-non-meter-series-skip-order", "pseg_client.py",
        "            match = _METER_SERIES.match(name)\n            if not match:\n                # Unrelated telemetry (e.g. a Temperature series) may carry any\n                # shape: it never feeds the metered leg and must not fail it. Any\n                # shape anomaly is reported by _series_shape_anomalies so the\n                # response cannot confirm the jar.\n                continue\n            raw_points = s.get(\"data\")\n            if raw_points is not None and not isinstance(raw_points, list):\n                raise PsegTransientError(\"Malformed meter data series from chart data\")",
        "            raw_points = s.get(\"data\")\n            if raw_points is not None and not isinstance(raw_points, list):\n                raise PsegTransientError(\"Malformed meter data series from chart data\")\n            match = _METER_SERIES.match(name)\n            if not match:\n                continue",
        R5 + "test_r8_nonlist_nonmeter_telemetry_keeps_metered_leg",
    ),
    (
        "55-parser-only-provenance", "pseg_client.py",
        "    if not isinstance(record, _MeterRecord):\n        return ()\n    return tuple(str(m) for m in record.contributing_meter_ids if m)",
        "    if not isinstance(record, _MeterRecord):\n        raw = record.get(\"meter_ids\") or record.get(\"meter_id\") or ()\n        if isinstance(raw, str):\n            raw = (raw,)\n        return tuple(str(m) for m in raw if m)\n    return tuple(str(m) for m in record.contributing_meter_ids if m)",
        R5 + "test_r7b_records_without_per_meter_provenance_never_prove_identity",
    ),
    (
        "56-anomaly-withholds-cookie-confirmation", "pseg_client.py",
        "                if result.pop(\"payload_anomalies\", 0):\n                    # The readings proved the meter, but an unrelated series broke\n                    # the shape contract: this response must not rotate the jar.\n                    self._restore_cookie_leg(daily_leg)\n                else:\n                    self._note_confirmed_generation()",
        "                result.pop(\"payload_anomalies\", 0)\n                self._note_confirmed_generation()",
        R5 + "test_r8_nonlist_nonmeter_telemetry_keeps_metered_leg",
    ),
    (
        "57-renewal-proof-anomaly-restore", "pseg_client.py",
        "            if parsed.get(\"payload_anomalies\"):\n                # The meter identity IS proven, but an unrelated series broke the\n                # response's shape contract: never adopt, confirm or rotate the\n                # cookie jar from it. Restore the whole proof leg so the prior\n                # Dashboard-proven jar and its observed generation stay in place.\n                self._restore_cookie_leg(proof_leg)",
        "            if False and parsed.get(\"payload_anomalies\"):\n                self._restore_cookie_leg(proof_leg)",
        R5 + "test_r9_renewal_proof_anomaly_never_adopts_cookie[anomaly-MM_RememberMe]",
    ),
]


def main() -> int:
    failed = []
    for label, filename, before, after, test in MUTATIONS:
        path = SOURCE / filename
        original = path.read_bytes()
        text = original.decode()
        befores = (before,) if isinstance(before, str) else before
        afters = (after,) if isinstance(after, str) else after
        mutated = text
        for b, a in zip(befores, afters, strict=True):
            if mutated.count(b) != 1:
                raise RuntimeError(f"{label}: mutation target must occur exactly once")
            mutated = mutated.replace(b, a)
        try:
            path.write_text(mutated)
            with TemporaryDirectory(prefix="pseg-mutation-") as cache:
                result = subprocess.run(
                    [sys.executable, "-B", "-X", f"pycache_prefix={cache}", "-m", "pytest",
                     "-q", "--tb=short", "-p", "no:cacheprovider", test],
                    cwd=ROOT, capture_output=True, text=True, timeout=35,
                )
            # An import error/timeout is not a regression proof: require the intended
            # test node to fail with an assertion.
            red = (
                result.returncode == 1
                and f"FAILED {test}" in result.stdout
                and (
                    "AssertionError" in result.stdout
                    or "DID NOT RAISE" in result.stdout
                    or "E   assert " in result.stdout
                    or "UpdateFailed: Error communicating with PSE&G:" in result.stdout
                    or "UpdateFailed: Transient error communicating with PSE&G:" in result.stdout
                )
            )
            print(f"{label}: {'RED (detected)' if red else 'INVALID / survived'}", flush=True)
            if not red:
                failed.append(label)
                print((result.stdout + result.stderr)[-2500:])
        finally:
            path.write_bytes(original)
        if path.read_bytes() != original:
            raise RuntimeError(f"{label}: source restoration failed")
    print(f"{len(MUTATIONS) - len(failed)}/{len(MUTATIONS)} mutations detected; all source bytes restored")
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())

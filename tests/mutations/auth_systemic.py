"""Preserved auth transformations with exact systemic assertion detectors.

The first section is the immutable 60-transformation historical inventory.
No typed-exception allowances: public typed outcomes are asserted by the cases.
Compound historical rows retain every original replacement; their mapped
assertion detects the resulting observable fault, including structural sends.
"""

ORIGINAL_MUTATIONS = [
    (
        "1-entry-shared-admission",
        "coordinator.py",
        "self._renewal_runtime = renewal_runtime_for(hass, config_entry.entry_id)",
        "self._renewal_runtime = type(renewal_runtime_for(hass, "
        "config_entry.entry_id))(config_entry.entry_id)",
        "tests/systemic/test_auth_systemic_catalog.py::test_replacement_inherits_the_inflight_entry_reservation",
    ),
    (
        "1-immediate-owner-check",
        "pseg_client.py",
        (
            "if self._renewal_runtime is not None and not self._renewal_runtime.can_dispatch(",
            "        if self._owner_check is not None:\n            self._owner_check()",
        ),
        (
            "if False and self._renewal_runtime is not None and not self._renewal_runtime.can_dispatch(",
            "        if False and self._owner_check is not None:\n            self._owner_check()",
        ),
        "tests/systemic/test_auth_systemic_catalog.py::test_uncertain_midsequence_admission_refuses_publication",
    ),
    (
        "2-independent-policy-handoff",
        "renewal_admission.py",
        "        with self.lock:\n            state = self.admission_dict()",
        "        return\n        with self.lock:\n            state = self.admission_dict()",
        "tests/systemic/test_auth_systemic_catalog.py::test_failed_first_setup_preserves_spent_terminal_admission",
    ),
    (
        "3-poll-identity-proof",
        "pseg_client.py",
        "self._renew_remember_me_sequence(verify_identity=True)",
        "self._renew_remember_me_sequence(verify_identity=False)",
        "tests/systemic/test_auth_systemic_catalog.py::test_renewal_requires_known_daily_proof_before_publication",
    ),
    (
        "4-post-await-retirement",
        "coordinator.py",
        "await self._async_persist_cookies()\n"
        "        self._persist_confirmed_session()\n"
        "        if self._is_stale():\n"
        "            return",
        "await self._async_persist_cookies()\n        self._persist_confirmed_session()",
        "tests/systemic/test_auth_systemic_catalog.py::test_retired_keepalive_cannot_dismiss_successor_issue_after_export_await",
    ),
    (
        "5-pre-probe-confirmed-jar",
        "pseg_client.py",
        "self._restore_session_jar(baseline)\n"
        "        return self._renew_local_cookie_session(baseline=baseline)",
        "return self._renew_local_cookie_session(baseline=self._snapshot_session_state())",
        "tests/systemic/test_auth_systemic_catalog.py::test_failed_renewal_preserves_preprobe_jar_and_spent_budget",
    ),
    (
        "6-present-corrupt-refusal",
        "renewal_admission.py",
        "if not isinstance(raw, dict):\n            return cls(uncertain=True)",
        "if not isinstance(raw, dict):\n            return cls()",
        "tests/systemic/test_policy_properties.py::test_literal_metadata_table[None-True-uncertain]",
    ),
    (
        "7-transient-only-retry",
        "renewal_admission.py",
        "if self.sequences and not self.retry_eligible:",
        "if False and self.sequences and not self.retry_eligible:",
        "tests/systemic/test_policy_properties.py::test_literal_spacing_and_rollback[1-False-899-exhausted]",
    ),
    (
        "setup-human-account-proof",
        "config_flow.py",
        "if not client.has_remember_me:\n"
        "                    await self.hass.async_add_executor_job(client.ensure_session)",
        "if True:\n                    await self.hass.async_add_executor_job(client.ensure_session)",
        "tests/systemic/test_auth_systemic_catalog.py::test_fresh_human_cookie_flow_has_its_own_account_proof[valid]",
    ),
    (
        "8-post-renewal-verified-keep",
        "pseg_client.py",
        "if resp.status_code != 200 or not self._on_dashboard(resp):\n"
        "            if not renewed:\n"
        "                self._restore_session_state(baseline)",
        "if resp.status_code != 200 or not self._on_dashboard(resp):\n"
        "            if True:\n"
        "                self._restore_session_state(baseline)",
        "tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[maintenance]",
    ),
    (
        "9-post-renewal-token-keep",
        "pseg_client.py",
        "            if not renewed:\n"
        "                self._restore_session_state(baseline)\n"
        '            raise PsegTransientError("__RequestVerificationToken not found on /Dashboard")',
        "            self._restore_session_state(baseline)\n"
        '            raise PsegTransientError("__RequestVerificationToken not found on /Dashboard")',
        "tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[notoken]",
    ),
    (
        "10-cooldown-is-transient",
        "pseg_client.py",
        '                    if deferred.reason == "cooldown":',
        '                    if False and deferred.reason == "cooldown":',
        "tests/systemic/test_auth_systemic_catalog.py::test_loaded_admission_has_the_correct_public_outcome[cooldown]",
    ),
    (
        "11-uncertain-fails-closed",
        "pseg_client.py",
        '        if deferred.reason in {"cooldown", "busy", "retired"}:',
        '        if deferred.reason in {"cooldown", "busy", "retired", "uncertain"}:',
        "tests/systemic/test_auth_systemic_catalog.py::test_loaded_admission_has_the_correct_public_outcome[uncertain]",
    ),
    (
        "12-confirmed-generation",
        "pseg_client.py",
        "                self._mark_session_ok()\n                self._note_confirmed_generation()",
        "                self._mark_session_ok()",
        "tests/systemic/test_auth_systemic_catalog.py::test_confirmed_remember_slide_is_not_a_second_renewal_generation[host]",
    ),
    (
        "12-confirmed-generation-dedupe",
        "pseg_client.py",
        "        self._dedupe_domain_variants()\n"
        "        self._remember_me_seen = self._remember_me_values()",
        "        self._remember_me_seen = self._remember_me_values()",
        "tests/systemic/test_auth_systemic_catalog.py::test_confirmed_remember_slide_is_not_a_second_renewal_generation[domain-copy]",
    ),
    (
        "13-security-step-latch",
        "pseg_client.py",
        "        if reason == AUTH_REASON_SECURITY_STEP:\n"
        "            # A security question/password change can only be answered by a human:\n"
        "            # latch it so no later tick retries the form or the cookie renewal.\n"
        "            self._security_step_latched = True",
        "        if reason == AUTH_REASON_SECURITY_STEP:\n"
        "            # A security question/password change can only be answered by a human:\n"
        "            # latch it so no later tick retries the form or the cookie renewal.\n"
        "            self._security_step_latched = False",
        "tests/systemic/test_auth_systemic_catalog.py::test_adapter_in_memory_security_step_latch",
    ),
    (
        "14-confirmed-snapshot-capture",
        "pseg_client.py",
        (
            "        self._mark_session_ok()\n"
            "        self._capture_confirmed_session()\n"
            '        _LOGGER.info("MyMeter Remember Me renewal successful")',
            "                if (\n"
            "                    snapshot is None\n"
            '                    or snapshot["cookies"] != exported',
        ),
        (
            "        self._mark_session_ok()\n"
            '        _LOGGER.info("MyMeter Remember Me renewal successful")',
            "                if False and (\n"
            "                    snapshot is None\n"
            '                    or snapshot["cookies"] != exported',
        ),
        "tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[maintenance]",
    ),
    (
        "15-confirmed-stop-handoff",
        "coordinator.py",
        "        self._persist_auth_metadata()\n"
        "        self._persist_confirmed_session()\n"
        "        self._stopped = True",
        "        self._persist_auth_metadata()\n        self._stopped = True",
        "tests/systemic/test_exit_checkpoint.py::test_fast_exit_checkpoint_control[after:fetch_energy_data::stop::no-renewal::MM_RememberMe]",
    ),
    (
        "16-confirmed-snapshot-not-live-jar",
        "coordinator.py",
        '        exported = snapshot["cookies"]',
        "        exported = self.client.export_cookies()",
        "tests/systemic/test_auth_systemic_catalog.py::test_handoff_refuses_unvalidated_or_partial_live_jar[immutable]",
    ),
    (
        "17-confirmed-stale-owner-guard",
        "coordinator.py",
        "        if not self.config_entry or self._is_stale():\n"
        "            return\n"
        "        snapshot = self.client.pending_confirmed_snapshot()",
        "        if not self.config_entry:\n"
        "            return\n"
        "        snapshot = self.client.pending_confirmed_snapshot()",
        "tests/systemic/test_auth_systemic_catalog.py::test_old_checkpoint_cannot_overwrite_human_successor",
    ),
    (
        "18-confirmed-partial-jar-guard",
        "coordinator.py",
        "        if not self._persisted_session_cookies <= session_cookies:\n"
        '            _LOGGER.debug("Not persisting a partial confirmed cookie jar")',
        "        if False and not self._persisted_session_cookies <= session_cookies:\n"
        '            _LOGGER.debug("Not persisting a partial confirmed cookie jar")',
        "tests/systemic/test_auth_systemic_catalog.py::test_handoff_refuses_unvalidated_or_partial_live_jar[partial]",
    ),
    (
        "19-settled-spent-is-exhausted",
        "renewal_admission.py",
        "            # A settled attempt that earned no retry can never run again, even while\n"
        "            # its 15-minute window is still open. Do not promise a later attempt.\n"
        '            return "exhausted"',
        '            return "cooldown"',
        "tests/systemic/test_policy_properties.py::test_literal_spacing_and_rollback[1-False-899-exhausted]",
    ),
    (
        "20-durable-challenge-admission",
        "pseg_client.py",
        "        if reason in {AUTH_REASON_CAPTCHA_REQUIRED, AUTH_REASON_SECURITY_STEP}:\n"
        "            self._record_terminal_admission(reason)",
        "        if False and reason in {AUTH_REASON_CAPTCHA_REQUIRED, AUTH_REASON_SECURITY_STEP}:\n"
        "            self._record_terminal_admission(reason)",
        "tests/systemic/test_auth_systemic_catalog.py::test_login_json_security_step_is_latched_and_durable",
    ),
    (
        "21-durable-challenge-no-background-http",
        "pseg_client.py",
        "        self._refuse_if_captcha_latched()\n"
        "        self._refuse_if_security_step_latched()\n"
        "        self._refuse_if_terminal_step()\n"
        "        previous_in_keepalive = self._in_keepalive",
        "        self._refuse_if_captcha_latched()\n"
        "        self._refuse_if_security_step_latched()\n"
        "        previous_in_keepalive = self._in_keepalive",
        "tests/systemic/test_auth_systemic_catalog.py::test_login_json_security_step_is_latched_and_durable",
    ),
    (
        "22-exhausted-no-password-fallback",
        "pseg_client.py",
        '                if deferred.reason == "exhausted":',
        '                if False and deferred.reason == "exhausted":',
        "tests/systemic/test_auth_systemic_catalog.py::test_loaded_admission_has_the_correct_public_outcome[exhausted]",
    ),
    (
        "23-optional-hourly-jar-quarantine",
        "pseg_client.py",
        "        cookies, seen = leg_snapshot\n"
        "        self.session.cookies = copy.deepcopy(cookies)\n"
        "        self._remember_me_seen = seen",
        "        return",
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[hourly-empty]",
    ),
    (
        "24-optional-hourly-stage-rollback",
        "pseg_client.py",
        "        except PsegTransientError as err:\n            self._restore_cookie_leg(hourly_leg)",
        "        except PsegTransientError as err:",
        "tests/systemic/test_auth_systemic_catalog.py::test_hourly_stage_cookie_is_rolled_back_when_data_fails",
    ),
    (
        "25-persist-confirmed-cookies-guard",
        "coordinator.py",
        "        if confirmed_cookies is not None and exported != confirmed_cookies:",
        "        if False and confirmed_cookies is not None and exported != confirmed_cookies:",
        "tests/systemic/test_auth_systemic_catalog.py::test_handoff_refuses_unvalidated_or_partial_live_jar[unconfirmed]",
    ),
    (
        "26-active-owner-dispatch-guard",
        "pseg_client.py",
        "            and not runtime.is_active(self._renewal_token)",
        "            and False and not runtime.is_active(self._renewal_token)",
        "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_first_poll_unload]",
    ),
    (
        "27-remember-me-inflight-owner-guard",
        "pseg_client.py",
        (
            "        resp = self._get_dashboard()\n"
            "        if verify_identity:\n"
            "            self._check_renewal_owner()\n"
            "        else:\n"
            "            self._check_active_owner()",
            "        if self._owner_check is not None:\n            self._owner_check()",
        ),
        (
            "        resp = self._get_dashboard()",
            "        if False and self._owner_check is not None:\n            self._owner_check()",
        ),
        "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_remember_me_proof_unload]",
    ),
    (
        "28-login-form-entry-owner-guard",
        "pseg_client.py",
        (
            "    def _login_form_token(self) -> str:\n"
            '        """GET the login page and return its antiforgery token (\'\' if absent)."""\n'
            "        self._check_active_owner()",
            "        if self._owner_check is not None:\n            self._owner_check()",
        ),
        (
            "    def _login_form_token(self) -> str:\n"
            '        """GET the login page and return its antiforgery token (\'\' if absent)."""',
            "        if False and self._owner_check is not None:\n            self._owner_check()",
        ),
        "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_login_form_entry_unload]",
    ),
    (
        "29-login-post-owner-guard",
        "pseg_client.py",
        (
            "    def _post_login(self, token: str, captcha_response: str) -> None:\n"
            '        """POST /Home/Login and classify the reply (raises on any refusal)."""\n'
            "        self._check_active_owner()",
            "        if self._owner_check is not None:\n            self._owner_check()",
        ),
        (
            "    def _post_login(self, token: str, captcha_response: str) -> None:\n"
            '        """POST /Home/Login and classify the reply (raises on any refusal)."""',
            "        if False and self._owner_check is not None:\n            self._owner_check()",
        ),
        "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_login_post_unload]",
    ),
    (
        "30-sso-entry-owner-guard",
        "pseg_client.py",
        (
            "        self._check_active_owner()\n"
            "        baseline = self._snapshot_session_state()\n"
            "        try:\n"
            "            return self._renew_sso_locked()",
            "        if self._owner_check is not None:\n            self._owner_check()",
        ),
        (
            "        baseline = self._snapshot_session_state()\n"
            "        try:\n"
            "            return self._renew_sso_locked()",
            "        if False and self._owner_check is not None:\n            self._owner_check()",
        ),
        "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_redirect_boundary_reload]",
    ),
    (
        "31-sso-post-owner-guard",
        "pseg_client.py",
        (
            "        self._check_active_owner()\n"
            "        try:\n"
            "            post_resp = self.session.post(action_url, data=data, allow_redirects=True, "
            "timeout=25)",
            "        if self._owner_check is not None:\n            self._owner_check()",
        ),
        (
            "        try:\n"
            "            post_resp = self.session.post(action_url, data=data, allow_redirects=True, "
            "timeout=25)",
            "        if False and self._owner_check is not None:\n            self._owner_check()",
        ),
        "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_sso_post_unload]",
    ),
    (
        "32-structural-session-send-owner-guard",
        "pseg_client.py",
        "        if self._owner_check is not None:\n            self._owner_check()",
        "        if False and self._owner_check is not None:\n            self._owner_check()",
        "tests/systemic/test_dispatch_fence.py::test_fast_dispatch_fence_representative[fast_stage_transition_handoff]",
    ),
    (
        "33-post-renewal-failed-dashboard-leg-restore",
        "pseg_client.py",
        "        if resp.status_code != 200 or not self._on_dashboard(resp):\n"
        "            if not renewed:\n"
        "                self._restore_session_state(baseline)\n"
        "            if post_renewal_leg is not None:\n"
        "                self._restore_cookie_leg(post_renewal_leg)",
        "        if resp.status_code != 200 or not self._on_dashboard(resp):\n"
        "            if not renewed:\n"
        "                self._restore_session_state(baseline)",
        "tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[maintenance]",
    ),
    (
        "34-post-renewal-missing-token-leg-restore",
        "pseg_client.py",
        "            if post_renewal_leg is not None:\n"
        "                self._restore_cookie_leg(post_renewal_leg)\n"
        "            if not renewed:\n"
        "                self._restore_session_state(baseline)",
        "            if not renewed:\n                self._restore_session_state(baseline)",
        "tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[notoken]",
    ),
    (
        "35-post-renewal-exception-leg-restore",
        "pseg_client.py",
        "            except Exception:\n"
        "                self._restore_cookie_leg(post_renewal_leg)\n"
        "                raise",
        "            except Exception:\n                raise",
        "tests/systemic/test_auth_systemic_catalog.py::test_postrenewal_dashboard_failure_keeps_verified_checkpoint[503]",
    ),
    (
        "36-hourly-records-validation-before-confirm",
        "pseg_client.py",
        "            hourly = self._parse_hourly_chart(hourly_payload)\n"
        "            if not self._has_valid_meter_read(\n"
        '                hourly["hourly_records"],\n'
        '                hourly.get("meter_ids") or [],\n'
        "            ):\n"
        "                raise PsegTransientError(",
        "            hourly = self._parse_hourly_chart(hourly_payload)\n"
        "            if False and not self._has_valid_meter_read(\n"
        '                hourly["hourly_records"],\n'
        '                hourly.get("meter_ids") or [],\n'
        "            ):\n"
        "                raise PsegTransientError(",
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[hourly-empty]",
    ),
    (
        "37-hourly-root-dict-validation",
        "pseg_client.py",
        (
            "        if not isinstance(data, dict):\n"
            '            raise PsegTransientError("No chart data returned for hourly statistics.")',
            "        if not isinstance(data, dict):\n"
            '            raise PsegTransientError("Malformed JSON root from chart data")',
        ),
        (
            "        if False and not isinstance(data, dict):\n"
            '            raise PsegTransientError("No chart data returned for hourly statistics.")',
            "        if False and not isinstance(data, dict):\n"
            '            raise PsegTransientError("Malformed JSON root from chart data")',
        ),
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[hourly-root]",
    ),
    (
        "38-latest-confirmed-checkpoint-publish",
        "pseg_client.py",
        "                snapshot = self._confirmed_snapshot\n"
        "                if (\n"
        "                    snapshot is None\n"
        '                    or snapshot["cookies"] != exported',
        "                snapshot = self._confirmed_snapshot\n"
        "                if False and (\n"
        "                    snapshot is None\n"
        '                    or snapshot["cookies"] != exported',
        "tests/systemic/test_auth_systemic_catalog.py::test_checkpoint_ack_cannot_clear_a_newer_publication",
    ),
    (
        "39-daily-validation-before-confirm",
        "pseg_client.py",
        "            if self._has_valid_meter_read(\n"
        '                result.get("history_14d") or [],\n'
        '                result.get("meter_ids") or [],\n'
        "            ):",
        "            if True or self._has_valid_meter_read(\n"
        '                result.get("history_14d") or [],\n'
        '                result.get("meter_ids") or [],\n'
        "            ):",
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-empty]",
    ),
    (
        "40-history-chunk-acceptance-checkpoint",
        "pseg_client.py",
        "                        else:\n"
        "                            self._note_confirmed_generation()\n"
        "                            last_validated_leg = self._snapshot_cookie_leg()",
        "                        else:\n"
        "                            last_validated_leg = self._snapshot_cookie_leg()",
        "tests/systemic/test_auth_systemic_catalog.py::test_valid_history_chunk_publishes_immutable_checkpoint",
    ),
    (
        "41-history-gap-abort-rollback",
        "pseg_client.py",
        (
            "                    self._restore_cookie_leg(chunk_leg)\n"
            '                    _LOGGER.warning("No chart data returned for range %s to %s", '
            "chunk_start_str, chunk_end_str)",
            "                if not had_data:\n"
            "                    self._restore_cookie_leg(last_validated_leg)\n"
            "                    raise PsegTransientError(",
        ),
        (
            '                    _LOGGER.warning("No chart data returned for range %s to %s", '
            "chunk_start_str, chunk_end_str)",
            "                if not had_data:\n                    raise PsegTransientError(",
        ),
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[backfill-null]",
    ),
    (
        "42-own-save-owner-predicate",
        "coordinator.py",
        "        writing = self._jar_writing_target\n"
        "        return not (writing is not None and current == writing)",
        "        return True",
        "tests/systemic/test_auth_systemic_catalog.py::test_owner_stays_active_inside_own_physical_assignment",
    ),
    (
        "43-atomic-checkpoint-compare-clear",
        "pseg_client.py",
        "        with self._checkpoint_lock:\n"
        "            snapshot = self._confirmed_snapshot\n"
        '            if snapshot is not None and snapshot["id"] == snapshot_id:\n'
        "                self._confirmed_snapshot = None",
        "        with self._checkpoint_lock:\n            self._confirmed_snapshot = None",
        "tests/systemic/test_auth_systemic_catalog.py::test_checkpoint_ack_cannot_clear_a_newer_publication",
    ),
    (
        "44-nested-series-and-ajax-shape-guard",
        "pseg_client.py",
        (
            '            raw_points = s.get("data")\n'
            "            if raw_points is not None and not isinstance(raw_points, list):\n"
            '                raise PsegTransientError("Malformed meter data series from chart data")',
            '        ajax_results = data.get("AjaxResults")\n'
            "        if ajax_results is not None and not isinstance(ajax_results, list):\n"
            '            raise PsegTransientError(f"Malformed AjaxResults from {context}")',
            "            except Exception as err:\n"
            "                self._restore_cookie_leg(chunk_leg)\n"
            "                raise PsegTransientError(\n"
            '                    f"Malformed history chart payload ({type(err).__name__})"\n'
            "                ) from err",
        ),
        (
            '            raw_points = s.get("data")',
            '        ajax_results = data.get("AjaxResults")',
            "            except Exception:\n                raise",
        ),
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[backfill-nested]",
    ),
    (
        "45-per-record-contributor-provenance",
        "pseg_client.py",
        "        contributors = set(_contributing_meter_ids(records))\n"
        "        if meter_ids is not None:\n"
        "            seen = {str(value) for value in (meter_ids or []) if value}\n"
        "            contributors &= seen",
        "        contributors = {str(value) for value in (meter_ids or []) if value}",
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-foreign]",
    ),
    (
        "46-rejected-daily-quarantines-result",
        "pseg_client.py",
        "                else:\n"
        '                    result = self._empty_chart_result(result.get("last_updated"))',
        "                else:\n                    pass",
        "tests/systemic/test_auth_systemic_catalog.py::test_rejected_daily_result_contains_no_foreign_readings",
    ),
    (
        "47-handoff-finally-baseline-reconcile",
        "coordinator.py",
        "            try:\n"
        "                self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)\n"
        "            finally:\n"
        '                if self.config_entry.data.get("cookies") == exported:\n'
        "                    self._jar_baseline = exported\n"
        "                    self._persisted_session_cookies = session_cookies\n"
        "                self._jar_writing_target = None",
        "            try:\n"
        "                self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)\n"
        "            finally:\n"
        "                self._jar_writing_target = None\n"
        '            if self.config_entry.data.get("cookies") == exported:\n'
        "                self._jar_baseline = exported\n"
        "                self._persisted_session_cookies = session_cookies",
        "tests/systemic/test_auth_systemic_catalog.py::test_handoff_callback_fault_preserves_physical_owner[after]",
    ),
    (
        "48-history-chart-envelope-guard",
        "pseg_client.py",
        "                data = self._validate_chart_envelope(resp3.json())",
        "                data = resp3.json()",
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[backfill-ajax]",
    ),
    (
        "49-live-chart-envelope-guard",
        "pseg_client.py",
        "            return self._validate_chart_envelope(resp3.json())",
        "            return resp3.json()",
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-ajax]",
    ),
    (
        "50-renewal-empty-expected-fail-closed",
        "pseg_client.py",
        "        if require_expected and not expected:\n            return False",
        "        if False:\n            return False",
        "tests/systemic/test_auth_systemic_catalog.py::test_adapter_parser_provenance_and_empty_renewal_identity",
    ),
    (
        "51-human-label-identity-only",
        "pseg_client.py",
        "                if self._allow_label_identity and not self._expected_meter_ids and label_ids:",
        "                if False and self._allow_label_identity and not self._expected_meter_ids and "
        "label_ids:",
        "tests/systemic/test_auth_systemic_catalog.py::test_fresh_human_cookie_flow_has_its_own_account_proof[label-only]",
    ),
    (
        "52-rejected-daily-typed-failure",
        "coordinator.py",
        '                if data.get("identity_confirmed") is False:',
        '                if False and data.get("identity_confirmed") is False:',
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-empty]",
    ),
    (
        "53-daily-hourly-contributor-union",
        "pseg_client.py",
        "            merged = list(daily_contributors)\n"
        "            merged.extend(value for value in hourly_contributors if value not in merged)\n"
        '            result["contributing_meter_ids"] = merged\n'
        '            result["meter_ids"] = merged',
        '            result["contributing_meter_ids"] = list(hourly_contributors)\n'
        '            result["meter_ids"] = list(hourly_contributors)',
        "tests/systemic/test_auth_systemic_catalog.py::test_daily_successor_is_learned_when_hourly_omits_it",
    ),
    (
        "54-non-meter-series-skip-order",
        "pseg_client.py",
        "            match = _METER_SERIES.match(name)\n"
        "            if not match:\n"
        "                # Unrelated telemetry (e.g. a Temperature series) may carry any\n"
        "                # shape: it never feeds the metered leg and must not fail it. Any\n"
        "                # shape anomaly is reported by _series_shape_anomalies so the\n"
        "                # response cannot confirm the jar.\n"
        "                continue\n"
        '            raw_points = s.get("data")\n'
        "            if raw_points is not None and not isinstance(raw_points, list):\n"
        '                raise PsegTransientError("Malformed meter data series from chart data")',
        '            raw_points = s.get("data")\n'
        "            if raw_points is not None and not isinstance(raw_points, list):\n"
        '                raise PsegTransientError("Malformed meter data series from chart data")\n'
        "            match = _METER_SERIES.match(name)\n"
        "            if not match:\n"
        "                continue",
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-telemetry]",
    ),
    (
        "55-parser-only-provenance",
        "pseg_client.py",
        "    if not isinstance(record, _MeterRecord):\n"
        "        return ()\n"
        "    return tuple(str(m) for m in record.contributing_meter_ids if m)",
        "    if not isinstance(record, _MeterRecord):\n"
        '        raw = record.get("meter_ids") or record.get("meter_id") or ()\n'
        "        if isinstance(raw, str):\n"
        "            raw = (raw,)\n"
        "        return tuple(str(m) for m in raw if m)\n"
        "    return tuple(str(m) for m in record.contributing_meter_ids if m)",
        "tests/systemic/test_auth_systemic_catalog.py::test_adapter_parser_provenance_and_empty_renewal_identity",
    ),
    (
        "56-anomaly-withholds-cookie-confirmation",
        "pseg_client.py",
        '                if result.pop("payload_anomalies", 0):\n'
        "                    # The readings proved the meter, but an unrelated series broke\n"
        "                    # the shape contract: this response must not rotate the jar.\n"
        "                    self._restore_cookie_leg(daily_leg)\n"
        "                else:\n"
        "                    self._note_confirmed_generation()",
        '                result.pop("payload_anomalies", 0)\n'
        "                self._note_confirmed_generation()",
        "tests/systemic/test_auth_systemic_catalog.py::test_focused_chart_response_contract[daily-telemetry]",
    ),
    (
        "57-renewal-proof-anomaly-restore",
        "pseg_client.py",
        '            if parsed.get("payload_anomalies"):\n'
        "                # The meter identity IS proven, but an unrelated series broke the\n"
        "                # response's shape contract: never adopt, confirm or rotate the\n"
        "                # cookie jar from it. Restore the whole proof leg so the prior\n"
        "                # Dashboard-proven jar and its observed generation stay in place.\n"
        "                self._restore_cookie_leg(proof_leg)",
        '            if False and parsed.get("payload_anomalies"):\n'
        "                self._restore_cookie_leg(proof_leg)",
        "tests/systemic/test_auth_systemic_catalog.py::test_renewal_anomalous_proof_never_adopts_response_cookies",
    ),
]

# New faults: deliberately excluded from the historical sixty.
NEW_MUTATIONS = [
    (
        "new-persist-auth-metadata-noop",
        "coordinator.py",
        "    def _persist_auth_metadata(self) -> None:\n"
        '        """Persist the non-secret renewal budget next to the cookies (no reload)."""\n'
        "        if not self.config_entry or self._is_stale():\n"
        "            return\n"
        "        self._renewal_runtime.persist(self.hass, self.config_entry)",
        "    def _persist_auth_metadata(self) -> None:\n"
        '        """Persist the non-secret renewal budget next to the cookies (no reload)."""\n'
        "        return",
        "tests/systemic/test_auth_systemic_catalog.py::test_adapter_exit_persists_policy_state",
    )
]

# Rows whose only faithful detector is an adapter-level private seam. They are NOT
# counted as systemic detections; each keeps its exact mapped assertion below, a
# written reason, and the catalog test asserts this exact set. Everything else is a
# systemic row whose detector must be observable dispatch, HA state, persistence or
# rows.
ADAPTER_LEVEL_LABELS = frozenset(
    {
        "13-security-step-latch",
        "50-renewal-empty-expected-fail-closed",
        "55-parser-only-provenance",
        "new-persist-auth-metadata-noop",
    }
)

ADAPTER_LEVEL_REASONS = {
    "13-security-step-latch": (
        "Masked by the durable terminal admission that the same _mark_auth_failure "
        "records: every automatic path (poll fallback, keepalive, cookie renewal) "
        "consults _refuse_if_terminal_step and raises the same typed refusal, so the "
        "in-memory flag changes no dispatch, persistence or HA state. Its only "
        "latch-only reader (login_local) is the human sign-in that must rearm, so no "
        "automatic observable effect exists."
    ),
    "50-renewal-empty-expected-fail-closed": (
        "Masked by the renewal entry point: _confirm_meter_identity raises before any "
        "chart read when the entry has no known meter identity, so require_expected "
        "is never reached with an empty expected set in a real lifecycle. No public "
        "dispatch, persistence or HA state distinguishes the guard."
    ),
    "55-parser-only-provenance": (
        "Masked by the parser: every record in history_14d/daily/hourly lists is "
        "built as the parser's _MeterRecord, so a plain dict/serialized copy never "
        "reaches provenance in a real lifecycle. The guard is defence in depth with "
        "no observable dispatch, persistence or HA state."
    ),
    "new-persist-auth-metadata-noop": (
        "Masked by the renewal runtime's own scheduled persist callback: every "
        "policy change queues hass.loop.call_soon_threadsafe(persist, ...), which the "
        "event loop delivers before any observable read, so a no-op exit call leaves "
        "entry.data unchanged only when loop delivery is impossible. Faithfully "
        "modelling that window needs a loop-independent call, which is adapter-level."
    ),
}

ADAPTER_LEVEL_DETECTORS = {
    "13-security-step-latch": (
        "tests/systemic/test_auth_systemic_catalog.py"
        "::test_adapter_in_memory_security_step_latch"
    ),
    "50-renewal-empty-expected-fail-closed": (
        "tests/systemic/test_auth_systemic_catalog.py"
        "::test_adapter_parser_provenance_and_empty_renewal_identity"
    ),
    "55-parser-only-provenance": (
        "tests/systemic/test_auth_systemic_catalog.py"
        "::test_adapter_parser_provenance_and_empty_renewal_identity"
    ),
    "new-persist-auth-metadata-noop": (
        "tests/systemic/test_auth_systemic_catalog.py::test_adapter_exit_persists_policy_state"
    ),
}

ADAPTER_LEVEL_MUTATIONS = tuple(
    row for row in (*ORIGINAL_MUTATIONS, *NEW_MUTATIONS) if row[0] in ADAPTER_LEVEL_LABELS
)

SYSTEMIC_MUTATIONS = tuple(
    row for row in ORIGINAL_MUTATIONS if row[0] not in ADAPTER_LEVEL_LABELS
)

MUTATIONS = SYSTEMIC_MUTATIONS + tuple(
    row for row in NEW_MUTATIONS if row[0] not in ADAPTER_LEVEL_LABELS
)

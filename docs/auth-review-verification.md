# Offline authentication regression verification

Audience: the maintainer reviewing the auth patch before committing or deploying.
These checks exercise fake HTTP adapters and Home Assistant test fixtures only.
They do not establish that the vendor will accept a real Remember Me cookie.

## Preconditions

Use the repository's `.venv` with its installed test dependencies. Run from the
repository root. Keep the checkout idle with one writer. The mutation
runner (`tools/release_check.py mutation` or `tools/mutation_check.py`) executes
each mutant in a fresh, disposable copy created by `tools/_snapshot.py`; source
files are never modified in place. Each pytest child has a 35-second timeout.
The legacy `tests/auth_guard_mutations.py` entry point is a safe compatibility wrapper
around the same copy-only engine.

## Run the checks

```sh
timeout 90 .venv/bin/python -m pytest -q --tb=short -p no:cacheprovider
timeout 15 .venv/bin/ruff check . --no-cache
timeout 15 node --require ./tests/support/node_offline.cjs --test tests/test_node_offline.js tests/test_captcha_helper.js tests/test_captcha_extension.js
timeout 600 .venv/bin/python tools/release_check.py mutation --source . --python .venv/bin/python
timeout 5 git diff --check
```

Or run the unified release verification suite:

```sh
.venv/bin/python tools/release_check.py all --source . --python .venv/bin/python
```

The mutation runner's sixty children are each bounded independently (35
seconds per child). Stop if a mutation reports `INVALID / survived`; a test import
error is not a valid proof. The runner requires the exact guard text and refuses
to mutate an ambiguous match. Because the runner operates strictly in isolated
snapshots, the source checkout is never modified.

Observed on the R9 candidate on 2026-10-24: 740 Python tests passed (647 pre-R7B
+ 75 R7B, 11 R8 and 6 R9 cases in `tests/test_auth_review_r5_regressions.py` + 1
concurrent multi-entry setup case in `tests/test_session_lifecycle.py`), Ruff
passed, 41 Node tests passed, and all sixty mutations were detected with source
bytes restored. The original independent R1 scratch file remained unchanged and
passed all 15 cases; the independent R2 scratch set passed all 29; the R3 review
probes passed all 29; the R4 final lifecycle probes passed all 29; the independent
R5 auth lifecycle probes passed all 58; the independent R6 auth lifecycle probes
passed all 48; the independent R7B boundary probes pass 28 of their original 29
(the one return-vs-typed-failure expectation was superseded by R8-2 and is covered
by the reviewer-approved adapted copy, 29/29); the independent R8 probe set passed
all 22 unchanged; the independent R9 probe set passed all 8 (7 passed / 1 failed
before this round); and the preserved R5 physical-storage set passed all 60.

### Promoted independent probe suites

These probes have been formally promoted to repo-owned, hermetic test suites under
`tests/independent/`, backed by provenance manifests in `tests/independent/*/provenance.json`
and validated by `tools/probe_provenance.py`. They run using standard pytest or
via the `independent` profile in `tools/release_check.py`:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/independent
.venv/bin/python tools/release_check.py independent --source . --python .venv/bin/python
.venv/bin/python tools/probe_provenance.py verify --root tests/independent
```

Individual promoted suites can be run directly:

```sh
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r1
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r2
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r3
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r4
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/hourly_r5
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r5
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r6
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r7b
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r8
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/auth_r9
.venv/bin/python -m pytest -q -p no:cacheprovider tests/independent/nywall
```

## What each regression proves

1. **Reload overlap:** actual entry setup/unload/replacement parks the old Dashboard
   probe before reservation and holds the new client's real renewal request. The
   retired client sends no renewal. Extra tests assert a replacement uses the same
   live policy even before its queued metadata save, and that retirement between
   reservation and immediate dispatch sends nothing.
2. **Failed startup:** actual first refresh rejects the Remember Me cookie. The
   entry retains its reservation and terminal outcome before a subsequent reload.
   A separate test makes the metadata handoff fail and confirms a replacement
   refuses renewal. Policy handoff is independent of cookie export/confirmation.
3. **Poll identity proof:** a real poll receives a rotated cookie, then its DAILY
   chart proof times out. No counter, confirmed jar or generation rearm is published.
   Another test substitutes a mismatching expected meter with the same result.
4. **Retired repair cleanup:** an old cookie export is blocked while the replacement
   creates its own repair issue. Releasing the export cannot dismiss that issue.
5. **Pre-probe rollback:** the initial expiry response itself rotates the Remember
   Me cookie; the renewal times out. Both poll and keepalive restore the jar from
   before that response and retain the spent slot, cooldown and first failure.
6. **Malformed metadata:** present null, invalid structures, booleans/negative
   counters and invalid or naive clocks refuse admission. Only an absent key is
   fresh. Human repair preserves a known future clock or starts a conservative
   cooldown when no clock can be trusted.
7. **Transient-only retry:** success without cookie rotation does not earn another
   attempt after 16 minutes. Pending/unknown outcomes do not earn one either.
   Actual transient eligibility survives serialization and reload, and the retry
   consumes the second and final slot.

`tests/test_auth_review_regressions.py` retains all R1 assertions and fault timing;
its HTTP adapters are independent, without requests_mock's global serialization.
`tests/test_renewal_admission.py` exercises strict parsing, cooldown, human repair
and outcome persistence. The nine R1 guard mutations cover every R1 finding, with
two separate checks for shared admission and immediate dispatch ownership, plus the
fresh human setup compatibility check. A fresh cookie-paste flow has no saved
entry identity yet; it retains the existing forced renewal followed by account
extraction before committing, instead of attempting an admitted poll first.

## R2 regressions

`tests/test_auth_review_r2_regressions.py` adds twenty synthetic cases for the
five independent R2 findings, and the mutation runner adds eight R2 guards
(17 mutations in total):

1. **Verified renewal survives a later hiccup.** The poll's expiry probe, a
   Dashboard-plus-DAILY renewal, then a maintenance page, HTTP 404, HTTP 429 or a
   Dashboard without the antiforgery token. The renewed jar, confirmed flag,
   renewal counter and generation (rotated and unrotated) are kept; only a failure
   that happens before any renewal restores the pre-probe baseline. The same check
   covers the saved-login and Okta SSO fallbacks.
2. **A pending retry is not an auth failure.** A real coordinator's keepalive earns
   its transient retry, then the poll runs inside the 15-minute window: the poll
   returns a transient error, keeps `_unsub_refresh`, opens no reauth flow, and the
   later earned retry still succeeds. A real entry whose persisted retry is still
   in cooldown ends in `SETUP_RETRY`, not a terminal auth error.
3. **Corrupt budget fails closed behind the normal prompt.** A real coordinator with
   unreadable stored metadata sends no renewal HTTP, keeps the stored bytes
   untouched and raises the normal reauth flow and repair issue.
4. **Only a renewal's rotation counts.** A confirmed dashboard response that slides
   `MM_RememberMe` does not rearm the next unrotated renewal; a real rotation during
   a verified renewal still starts one new generation, keeps the global gap and
   grants only that generation's initial attempt.
5. **A security step latches automatic attempts.** After MyMeter asks for a security
   question, the keepalive, the poll's cookie renewal and the automatic password
   fallback all send nothing; a completed human sign-in clears the latch. A saved
   login still provides the permitted fallback for a cookie generation that is
   merely inside its cooldown. R3 makes the CAPTCHA/security terminal durable
   across reload and cold process; see the R3 section below.

The promoted R2 probe suite (`tests/independent/auth_r2/`, 29 cases across
`test_independent_auth_r2.py` and `test_independent_auth_r2_extra.py`) passes. One control's *exception expectation* was
adapted to the corrected policy: a human rearm's conservative 15-minute gap is a
pending retry (`PsegTransientError`, no failure reason) rather than a second
re-authentication demand (`PsegOktaSessionExpired`). Its generation and cooldown
assertions are unchanged.

The separate preserved R5 physical-storage tests (`tests/independent/hourly_r5/`,
60 cases across `test_independent_hourly_r5.py`, `test_independent_hourly_physical_failure.py`,
and `test_independent_hourly_guards.py`) passed all 60 cases, including real Store write failures,
cold replay and timeouts. The real
Store error boundary is unchanged. `statistics_hourly.py`, `statistics_state.py`
and `manifest.json` are byte-identical to reviewed hourly base `2285845`. Of the 25
coordinator statistics/journal/backfill functions, 24 have identical ASTs to
`2285845`; only `async_backfill_history` changed, and its sole AST difference is
the auth-only handoff:

```diff
     async with self._update_lock:
-        records = await self.hass.async_add_executor_job(self.client.fetch_history_range, start_date_str, end_date_str, 90)
+        try:
+            records = await self.hass.async_add_executor_job(self.client.fetch_history_range, start_date_str, end_date_str, 90)
+        finally:
+            self._persist_auth_metadata()
+            self._persist_confirmed_session()
         if not records:
```

No statistics, journal, promotion or reconciliation statement changed.

## R3 regressions

`tests/test_auth_review_r3_regressions.py` adds twenty-two synthetic cases for the
three independent R3 findings, and the mutation runner adds nine R3 guards (25
mutations in total):

1. **A confirmed renewal's jar is durable on every exit.** Actual entry setup and
   reload, a runtime poll, `stop_keepalive` and `async_backfill_history` each
   confirm a renewal (Dashboard plus DAILY meter proof) and then fail later. The
   saved jar is the renewed one for both rotated and unrotated generations, and
   the budget is saved in the same entry update. A separate test gives the later
   maintenance response its own `Set-Cookie`, proves the live jar holds it, and
   proves neither the saved jar nor the reloaded probe does. Another replaces the
   entry jar as a human reauth would: the old owner's snapshot cannot overwrite it,
   and a half-empty snapshot is refused.
2. **A spent generation is auth, not a fake wait.** A settled attempt with no
   earned retry is `exhausted` inside and outside its window; an in-flight
   reservation, a human-rearmed generation and an earned retry remain a transient
   cooldown. Real poll and keepalive paths ask for re-authentication immediately,
   a spent startup is `SETUP_ERROR` with no password POST, and an earned retry
   still yields `SETUP_RETRY`.
3. **CAPTCHA and security are durable terminal admissions.** The poll's permitted
   password fallback records the challenge in the shared admission, so a reload
   and a simulated cold process send no background HTTP and no password POST. A
   failed startup persists it too. An ordinary Dashboard success does not clear
   it; a completed human rearm clears it while keeping the 15-minute clock. The
   strict parser still rejects unknown terminal values and malformed counters; a
   known terminal reason with zero spent sequences is now accepted so a challenge
   seen before any renewal can be stored.

The independent R3 probe set (`tests/independent/auth_r3/test_independent_auth_r3.py`,
29 cases) changed from 6 failed/23 passed before this round to 29 passed. It was
not edited. One existing R2 builder assertion changed with the N2 policy: a
settled unrotated renewal's budget is now `exhausted` inside its window instead of
`cooldown` (original:
`assert client._renewal_admission.blocked_reason(datetime.now(UTC)) == "cooldown"`).
The R2 probes were unchanged and remained green.

## R4 regressions

`tests/test_auth_review_r4_regressions.py` adds thirty-eight synthetic cases for
the two independent R4 findings plus controls, and the mutation runner adds nine
R4 guards (34 mutations in total):

1. **Whole-jar quarantine on failed optional and post-confirmation chart stages.**
   Each chart/read stage (`_fetch_chart_json`, `_confirm_meter_identity`, the
   authoritative daily chart leg, the optional hourly chart leg, and each
   `fetch_history_range` chunk) snapshots the live `self.session.cookies` jar and
   `_remember_me_seen` before the first request of the stage and restores both on
   any HTTP/network/decode/auth failure (`429`, `500`, `401`/`403`, login HTML
   redirect, malformed JSON, or `series: []`), including when `POST /Dashboard/Chart`
   returns `200 OK` with `Set-Cookie` and `GET /Dashboard/ChartData` subsequently
   fails. For `200 OK` payloads with empty, unrelated or wholly invalid meter
   points on the daily leg and on history backfill chunks, see the R6 section
   below. A successful optional hourly leg adopts confirmed cookies through
   `_note_confirmed_generation()`. In `coordinator._async_persist_cookies()`,
   live-jar exports that diverge from `client.confirmed_cookies()` are refused and
   never overwrite `entry.data["cookies"]` or clear `pending_confirmed_snapshot()`.
2. **Active entry ownership checks across all automatic fallbacks and credential
   POSTs.** `PsegClient._check_active_owner()` verifies `runtime.is_active(token)`
   under the shared entry `RLock` before every automatic entrypoint (`ensure_session`,
   `_get_verification_token`, `fetch_energy_data`, `fetch_history_range`,
   `keepalive`, `_keepalive_local`, `_renew`, `_login_form_token`, `renew_sso`) and
   immediately before `POST /Home/Login` (`_post_login`) and the SAML ACS POST
   (`_renew_sso_locked`) after any preceding form GET returns, as well as after each
   in-flight GET in `_renew_remember_me_sequence`. Both actual Home Assistant entry
   unload and a completed human sign-in handoff with unchanged cookie values retire
   the old token and block any in-flight poll from dispatching a login form GET,
   password POST, SAML SignIn GET, or SAML ACS POST. Fresh unattached `PsegClient`
   instances in interactive config flows remain unaffected.

The independent R4 probe set (`tests/independent/auth_r4/test_independent_auth_r4.py`,
29 cases) changed from 22 failed/7 passed before this round to 29 passed without
editing the probe file.

## R5 and R6 regressions

`tests/test_auth_review_r5_regressions.py` contains 196 synthetic cases in total
(59 R5, 45 R6, 75 R7B, 11 R8, 6 R9 — see the R7B, R8 and R9 sections below), and
the mutation runner includes 60 guards in total (46 prior + 7 R7B + 6 R8 + 1 R9):

1. **Structural active-owner boundary on every HTTP hop (`AllowlistedSession.send`).**
   `AllowlistedSession` runs the client's `_check_active_owner` callback before
   every outbound request and every automatic `requests` redirect hop (such as an
   HTTP 307 redirect on SAML ACS `POST` or a `POST /Dashboard/Chart` to
   `GET /Dashboard/ChartData` transition), without holding the entry runtime lock
   across network I/O. Unattached interactive config-flow clients remain unaffected.
2. **Post-renewal Dashboard checkpoint restoration.** After a verified renewal
   (Dashboard plus matching DAILY meter proof), `_get_verification_token` snapshots
   the confirmed post-renewal cookie leg (`cookies` and `_remember_me_seen`) before
   fetching the subsequent `/Dashboard` page and restores that post-renewal
   checkpoint on any maintenance, missing-token, 4xx, 5xx, logged-out or exception
   outcome. Failed post-renewal response cookies never remain live to be promoted
   by the next healthy poll, and the dead pre-renewal jar is never restored.
3. **Shared meter-read validation and strict shape guards across daily, hourly,
   and history chunks (`_has_valid_meter_read`, R5-C / R6-F1 / R6-N2).**
   `_parse_chart_data`, `_parse_hourly_chart` and `fetch_history_range` reject
   non-dict JSON roots (such as `[]`) and non-list `series` values as
   `PsegTransientError` inside their cookie-quarantine handlers. Before any chart
   read confirms its response cookies (`_note_confirmed_generation()`),
   `_has_valid_meter_read(records, meter_ids)` requires at least one valid parsed
   record AND at least one `Meter #N` series that matches `self._expected_meter_ids`
   whenever expected meters are configured on the client (multi-meter / meter-swap
   payloads remain valid when at least one series in the payload belongs to the
   entry's known meter set; fresh unattached manual config flows with no saved
   entry identity accept any valid `Meter #N` series with `>= 1` valid record).
   On the authoritative daily leg, an empty, unrelated-series or wholly invalid
   `200 OK` chart response rolls back `daily_leg` (jar and `_remember_me_seen`)
   without calling `_note_confirmed_generation()`, while still returning the
   parsed empty sensor model when no exception is raised. On the optional hourly
   leg, `_parse_hourly_chart` returns the seen `meter_ids` alongside
   `hourly_records`; when `_has_valid_meter_read` is False, `fetch_energy_data`
   raises `PsegTransientError`, rolls back `hourly_leg`, and falls back cleanly
   to the authoritative daily series (whose daily cross-check still gates
   statistics promotion).
4. **Per-chunk history validation, checkpointing, and gap-abort rollback (R6-F2).**
   In `fetch_history_range`, every chunk snapshots `chunk_leg` before
   `POST /Dashboard/Chart`. A chunk whose `Data` is `null`/`{}` (without a login
   redirect) or whose series fails `_has_valid_meter_read` restores `chunk_leg`
   immediately and records `had_data=False`, so edge-empty chunks remain normal
   missing history without accepting or keeping their `Set-Cookie` headers. A
   chunk that passes `_has_valid_meter_read` calls `_note_confirmed_generation()`
   (publishing the latest immutable `_confirmed_snapshot` and `_confirmed_cookies`)
   and updates `last_validated_leg`. If a later empty chunk between populated
   chunks triggers the hole-abort `PsegTransientError`, `fetch_history_range`
   restores `last_validated_leg`, preserving cookie rotations from earlier
   validated chunks while discarding any later unvalidated response cookies.
   Because `coordinator.async_backfill_history` runs `_persist_auth_metadata()`
   and `_persist_confirmed_session()` in its `finally` block, every backfill exit
   (completion, hole abort, HTTP error, cancellation or unload) persists the
   latest validated checkpoint alongside settled admission under active ownership.
5. **Own-cookie-write ownership continuity and atomic checkpoint lock
   (R6-F3 / R6-N1).** `coordinator._write_cookie_handoff` records the target jar in
   `_jar_writing_target` around `hass.config_entries.async_update_entry` and
   updates `_jar_baseline` before clearing `_jar_writing_target`, so
   `_jar_replaced()` and `runtime.is_active(token)` remain `True` for the
   coordinator's own cookie writes while still retiring immediately if a foreign
   human reauth/reconfigure replaces `entry.data["cookies"]`. Inside `PsegClient`,
   a dedicated `_checkpoint_lock` (`threading.Lock`) serializes `_confirmed_snapshot`
   and `_confirmed_cookies` publication, reads and `clear_confirmed_snapshot`
   compare-and-clear without taking the network `RLock` on the event loop.

The independent R5 probe set (`tests/independent/auth_r5/test_independent_auth_r5.py`,
58 cases) and the independent R6 probe sets (`tests/independent/auth_r6/`,
48 cases total across `test_independent_auth_r6.py`, `test_independent_auth_r6_extra.py`,
`test_independent_auth_r6_flows.py`, and `test_independent_auth_r6_race.py`) all pass without
editing any probe file.

## R7B regressions

`tests/test_auth_review_r5_regressions.py` now holds 196 synthetic cases (59 R5,
45 R6, 75 R7B, 11 R8, 6 R9) and the mutation runner 60 guards (46 prior + 7 R7B +
6 R8 + 1 R9).
The four R7B findings and the one release-check test correction are covered by:

1. **Whole-leg chart quarantine (`pseg_client._validate_chart_envelope`,
   `_fetch_chart_json`, `fetch_history_range`).** The root-object and
   `AjaxResults`-is-a-list checks run inside the leg's own rollback handler for
   the daily, hourly and history legs alike, and `fetch_history_range` wraps the
   entire per-chunk leg (both requests, JSON decode, envelope validation, series
   merge, per-meter validation, record aggregation and confirmation) in one
   `try`. Any exception, including an unexpected parser `TypeError`/`ValueError`,
   restores that chunk's whole pre-leg jar and observed Remember Me generation
   before a typed `PsegTransientError` (or the existing auth/retired/transient
   error) propagates; parser messages are replaced by the exception type name, so
   no raw payload text reaches a log. Earlier validated chunk checkpoints and the
   edge/mid-range gap rules are unchanged; the table test asserts the quarantined
   cookie is never dispatched by the next keepalive, two healthy polls or a cold
   client built from the persisted jar, and the cold-restart test additionally runs
   a fresh coordinator on that jar and asserts neither a dispatch nor a re-persist.
2. **Per-record meter provenance (`_MeterRecord`, `_contributing_meter_ids`,
   `_has_valid_meter_read`).** Parsed daily and hourly records carry the meter ids
   that contributed a valid point to that record. Validation requires at least one
   valid record whose contributors intersect the expected/known set; a known meter
   label with an empty or wholly invalid series plus an unknown meter with the only
   valid record is rejected for DAILY, hourly, backfill and renewal, while a
   known-valid record next to an unknown-valid successor still passes and may teach
   the successor. `require_expected=True` (renewal identity proof) fails closed when
   the entry has no known identity at all. A fresh, manually configured flow with no
   saved identity still accepts real contributing meter records.
3. **No publication or learning from a rejected DAILY leg (completed by R8-2).**
   A failed daily identity check returns `_empty_chart_result(...)`
   (`identity_confirmed: False`, no meter ids, no history) after rolling the jar
   back, and the coordinator now raises a typed `UpdateFailed` BEFORE any
   publication, statistics import, meter learning, success clock or `connected`
   status. `coordinator.data`, `_last_valid_data` and `last_successful_update` keep
   the previous valid values, sensors keep their last numeric/date states, the
   connection-status sensor reads `error`, one value-free warning is logged, and
   the poll stays scheduled (no `ConfigEntryAuthFailed`). A later reload therefore
   cannot treat the unknown meter as trusted. Only identity-accepted legs may
   extend `CONF_KNOWN_METER_IDS`, and the reload/repeated-response authorization
   path is asserted end to end.
4. **Own-write baseline reconciliation (`coordinator._write_cookie_handoff`).**
   The `finally` block re-reads `entry.data["cookies"]` and adopts the exported jar
   as `_jar_baseline` whenever the actual entry data still equals this own write
   target, even when Home Assistant's listener/save callback raised after the
   assignment. A pre-assignment failure keeps the old baseline, a foreign
   human/reconfigure replacement still retires the owner immediately, and
   `_jar_writing_target` is still cleared so the own-write window is unchanged.

**Entity-id test correction (not a production change).** The long-standing
`tests/test_session_lifecycle.py::test_second_account_gets_suffixed_entity_ids`
failure was diagnosed as Home Assistant setting up every config entry of the domain
concurrently on first component setup: whichever account's executor refresh
returned first registered the base entity ids. The test now adds the second entry
only after the first entry's setup has completed, and a new deterministic
event-gated test adds both entries before setup, forces the second account's fetch
to finish first, and asserts both entries load with eight unique registry entities
each, disjoint entity ids, and the correct entry/device association without
assuming which account wins the base ids. No production naming, statistics key or
migration logic changed; `README.md` now qualifies the base-id claim as
first-registered rather than first-configured.



## R8 regressions

The R8 review found one release-blocking human-recovery regression introduced by
the R7B quarantine work, one inaccurate "no publication" claim, and three nits.
`tests/test_auth_review_r5_regressions.py` covers them with 11 cases and the
mutation runner with six guards (51-56).

1. **Human identity on a lagging DAILY window (`PsegClient.enable_label_identity_discovery`,
   `fetch_energy_data`).** A fresh cookie sign-in or reauth asks for a one-day
   DAILY window; when the vendor has not published that day's usage yet, the
   response lists `Meter #N` with an empty series or `y: null` points. Only an
   unattached (no expected meter ids) interactive config-flow client, whose flag
   only `_async_validate_and_extract_meter` sets, may then name the account from
   those labels. That DAILY read publishes no readings or statistics, reports
   `identity_confirmed: False` with `identity_source: meter_label`, rolls that leg
   back, and never adopts, confirms or checkpoints the label response's cookies.
   The attached automatic client keeps the strict valid-known-contributor gate; the
   existing account-mismatch guard still aborts a foreign account's reauth. A
   HOURLY response in the same unattached read is a separate, independently
   validated leg: when it carries valid points it may confirm its own response
   cookie and be saved with the new entry, exactly as any fresh manual
   valid-result read does (valid points, never labels). The window is not widened
   and no `MaintainMaxDate` vendor behaviour is assumed.
2. **Rejected DAILY is a typed failure, never a placeholder (`coordinator._async_update_data`).**
   See R7B item 3 above: `identity_confirmed False` raises `UpdateFailed` before any
   success/publication/learning/statistics work, so a real
   `DataUpdateCoordinator.async_refresh()` keeps the previous data and sensors,
   reports `last_update_success False` with status `error`, and keeps the poll
   scheduled. A valid hourly leg cannot carry the poll to success on its own.
3. **Daily/hourly contributor union (N1).** `result.update(hourly)` used to replace
   the daily-proven meter ids, so a valid successor named only by the DAILY leg was
   not learned while the hourly leg was valid. The parsers' validated contributor
   lists are now unioned behind the known-contributor gate (never a raw series
   label); a lagging human-flow label identity is never narrowed by the hourly leg,
   and an invalid unknown meter is still never learned.
4. **Non-meter telemetry no longer fails the metered leg (N2).** The `data`-shape
   check now runs only for `Meter #N` series, so an unrelated Temperature series
   with non-list data cannot fail a valid meter read. A malformed *meter* series is
   still a typed failure with whole-leg rollback, and a response that contains any
   such unrelated anomaly is never used to confirm or rotate the cookie jar. That
   holds for every chart reader, including the renewal identity proof (R9): the read
   may still prove identity, but it restores its whole leg, so its cookie and
   observed generation are discarded and a genuine rotation can never be credited
   to it.
5. **Parser-built provenance only (N3).** `_record_contributing_meters` accepts only
   `_MeterRecord` instances produced by the parsers; a plain dict's own
   `meter_id`/`meter_ids` field or a serialized copy is data, not proof. Provenance
   is validated before the model is exported, so downstream JSON/statistics use is
   unchanged.

## R9 regression

The R9 review found that the R8 non-meter anomaly rule had not reached the renewal
identity proof, the one chart reader that previously ignored
`payload_anomalies`.

`_confirm_meter_identity` still requires a valid contributing record from a known
meter (the proof itself is unchanged), but when the proof response carries an
unrelated series shape anomaly it now restores the whole proof leg before
returning. The identity is proven, yet that response's `Set-Cookie` and observed
Remember Me generation are discarded, the prior Dashboard-proven jar stays in
place, and `_detect_remember_me_rotation` can no longer credit a rotation to it, so
the shared admission stays spent (one sequence, no rearm) instead of refreshing the
budget from a contract-violating response. The table in
`tests/test_auth_review_r5_regressions.py` covers `MM_SID`, `MM_RememberMe` and an
auxiliary cookie plus a clean control: the anomalous cases never persist, dispatch
or checkpoint the marked cookie through keepalive, two polls and a cold client,
while the clean control still adopts the cookie (and rearms only on a genuine
Remember Me rotation). No extra HTTP, no status change and no other production
method is touched.

## Limits, review and rollback

The result is a verified offline builder candidate. A separate fresh adversarial
review must precede the parent's commit and any deployment. This work made no
HA/vendor calls and did not deploy or restart anything. The manifest stays at
unpublished 1.5.0.

The admission runtime survives ordinary reload and failed setup. Entry metadata
is handed to Home Assistant on reservations/outcomes and failure exits; a
confirmed renewal's jar is written in the same entry update, and a failed or
uncertain handoff refuses further renewal. A CAPTCHA or security step is durable
in that shared admission; a plain refused Remember Me cookie remains the existing
terminal reason and may still use the plan-permitted saved-login fallback on a
cooldown, while a spent generation with no retry does not. Home Assistant's disk
save is still best effort. Abrupt process/disk failure can lose a recent save;
crash durability and live vendor renewal remain unverified.

If auth must be rolled back after approval/deployment, restore the auth baseline
from reviewed hourly commit `2285845` through the normal reviewed deployment
procedure. Retain all hourly rows, provenance and pending journals. Never clear
statistics or reinstall the old 1.4.2 daily importer after hourly writes. See the
[hourly rollback runbook](hourly-statistics.md) for the import kill switch.

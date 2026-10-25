# NY-Wall Independent Test Provenance & Assertion Crosswalk

## Provenance Overview

This directory promotes historical review assertion scripts from the America/New_York wall-clock parser reviews (R1 and R2) into portable, deterministic pytest suites.

- **Group**: `nywall`
- **Status**: `active`
- **Reviewer KBs**:
  - R1 Review: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62` (Codex FIX review uncovering unsafe label fallbacks)
  - R2 Review: `8f4541f2-63e1-4666-bbef-2fd86c1686a0` (Codex SHIP review verifying closed defects)
  - Proven Contract KB: `5e0c2b1a-7f3d-4a91-9c2e-20261025a001`
- **Original Source Files**:
  1. `/tmp/pseg-review-nywall-r1/probe.py` (Archived at `tests/independent/archive/nywall/r1_probe.py.txt`, SHA-256 `bcc76c9f3c2a24699db4a6116d82e1f2f8926218f0828941c50465b6a0ff191d`)
  2. `/tmp/pseg-review-nywall-r2/probe.py` (Archived at `tests/independent/archive/nywall/r2_probe.py.txt`, SHA-256 `d244c6dfbc4448fc30260ad62781fcbf91881bd169097192da91b7d81991f69b`)
- **Promoted Modules**:
  - `tests/independent/nywall/test_independent_nywall_contract.py` (15 test cases)
  - `tests/independent/nywall/test_independent_nywall_labels.py` (34 test cases)
  - `tests/independent/nywall/conftest.py` (Shared fixtures: `uninitialized_client`, `base_day`, `point_factory`, `base_varying_points`, `base_varying_total`)
  - `tests/independent/nywall/provenance.json` (Integrity metadata pinning 49 collected tests)

## Transformation & Supersession Rules

1. **R1 Obsolete-by-Design Unsafe Acceptances -> Rejections**:
   In `r1_probe.py.txt`, the probe temporarily asserted that four unsafe label gate inputs (`bare_same_end`, `aware_missing_end`, `date_start_wrong_aware_end`, and `basic_aware_wrong_start`) were accepted by the new parser (`assert all(r['interval_ok'] for r in new['hourly_records'])`).
   In R2 and released v1.6.0, these defects were closed; each interval must be rejected (`assert not any(r['interval_ok'] for r in records)`). These cases are preserved as explicit rejection controls.
2. **R1 Fallback Aware Reason Supersession**:
   In `r1_probe.py.txt`, `fallback_25_aware` asserted `expected_reason == "label_mismatch"`. In R2 and v1.6.0, ambiguity precedence ensures that ambiguous wall hours reject with `dst_ambiguous` before aware label validation executes. The assertion is promoted to expect `dst_ambiguous`.
3. **Declared Expectations (No AST / Git at Runtime)**:
   The historical scripts executed `git show HEAD` and parsed source code via Python's `ast` module. The promoted tests replace runtime AST/git introspection with explicit declared value expectations (`DECLARED_INCOMPLETE_REASONS`) and direct comparisons.
4. **Isolated Captcha Placeholder Formatting**:
   The R2 captcha control tested `strings.json` and `translations/en.json` formatting. Promoted as an isolated synthetic control without invoking config flows or Home Assistant runtime services.

---

## Assertion Crosswalk Table

| Original Script | Original Scenario / Assertion | Promoted Pytest Case ID | Expected Outcome / Rationale | Status |
|---|---|---|---|---|
| `r1_probe.py.txt` | `run('contract_EDT', BASE, {DAY: TOTAL}, 1)` | `test_independent_nywall_contract.py::test_contract_edt_baseline` | 24 EDT hours promote (complete=True, reason=None, UTC 04:00Z..next 03:00Z) | Preserved |
| `r1_probe.py.txt` | `run('EDT_x_shift_+4h', pts, {DAY: TOTAL}, 0)` | `test_independent_nywall_contract.py::test_contract_edt_x_shift[shift_+4h]` | Shift +4h fails validation (complete=False) | Preserved |
| `r1_probe.py.txt` | `run('EDT_x_shift_-4h', pts, {DAY: TOTAL}, 0)` | `test_independent_nywall_contract.py::test_contract_edt_x_shift[shift_-4h]` | Shift -4h fails validation (complete=False) | Preserved |
| `r1_probe.py.txt` | `run('contract_EST', [...], {est: 18}, 1)` | `test_independent_nywall_contract.py::test_contract_est_baseline` | 24 EST hours promote (complete=True, reason=None, UTC 05:00Z..next 04:00Z) | Preserved |
| `r1_probe.py.txt` | `run('fallback_25_duplicate_01', [...], {fall: 25}, 0, 'dst_ambiguous')` | `test_independent_nywall_contract.py::test_fallback_25_duplicate_01` | 25 points with duplicate 01:00 reject with dst_ambiguous | Preserved |
| `r1_probe.py.txt` | `run('fallback_24_distinct', [...], {fall: 24}, 0, 'dst_ambiguous')` | `test_independent_nywall_contract.py::test_fallback_24_distinct` | 24 distinct points reject with dst_ambiguous | Preserved |
| `r1_probe.py.txt` | `run('fallback_25_aware', [...], {fall: 25}, 0, 'label_mismatch')` | `test_independent_nywall_contract.py::test_fallback_25_aware_dst_ambiguous` | Ambiguity precedence takes priority over aware labels -> dst_ambiguous | Adapted (R1 obsolete) |
| `r1_probe.py.txt` | `run('spring_valid_23', [...], {spring: 23}, 1)` | `test_independent_nywall_contract.py::test_spring_valid_23_hours` | Valid 23-hour spring forward day promotes (complete=True) | Preserved |
| `r1_probe.py.txt` | `run('spring_nonexistent_02', [...], {spring: 24}, 0, 'sum_mismatch')` | `test_independent_nywall_contract.py::test_spring_nonexistent_02_gap_rejected` | Nonexistent 02:00 gap hour rejected (sum_mismatch, invalid_points=1) | Preserved |
| `r1_probe.py.txt` | `run('true_UTC_three_days_correct_labels', ...)` | `test_independent_nywall_contract.py::test_true_utc_three_days_rejected` | True-UTC shifted timestamps reject across all 3 days | Preserved |
| `r1_probe.py.txt` | `ALL_2026_CONVERSIONS` (365 days) | `test_independent_nywall_contract.py::test_all_2026_wall_calendar_conversions` (+ `test_declared_calendar_oracle_sanity`) | 365 days: 8,758 ok, 1 nonexistent, 1 ambiguous, fold 1 missing on 11-01; every wall hour, `expected_hour_starts` and `ny_day_bounds` compared to DECLARED 2026 transition dates (03-08, 11-01), not production helpers | Strengthened (parent, Codex P1-08 R1 MAJOR) |
| `r1_probe.py.txt` | `REASON_CLOSURE` (AST walk) | `test_independent_nywall_contract.py::test_reason_closure_observed` | Real parser+validator driven through 8 rejection paths; each emitted reason equals its declared value and lies in the declared closed set | Strengthened: observed, not listed (parent, Codex P1-08 R1 MAJOR) |
| `r1_probe.py.txt` | `run('start_wrong_date', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[start_wrong_date]` | start='10/16/2026' -> complete=False, label_mismatch | Preserved |
| `r1_probe.py.txt` | `run('end_wrong_date', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[end_wrong_date]` | end='10/17/2026' -> complete=False, interval_end_mismatch | Preserved |
| `r1_probe.py.txt` | `run('end_next_date', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[end_next_date]` | end='10/16/2026' -> complete=True (allowed date-only convention) | Preserved |
| `r1_probe.py.txt` | `run('end_unparseable', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[end_unparseable]` | end='garbage' -> complete=False, timestamp_semantics_unverified | Preserved |
| `r1_probe.py.txt` | `run('date_start_aware_wrong_end', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[date_start_aware_wrong_end]` | date start + aware noon end -> timestamp_semantics_unverified | Preserved |
| `r1_probe.py.txt` | `run('naive_zero_length_interval', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[naive_zero_length_interval]` | start=end naive datetime -> timestamp_semantics_unverified | Preserved |
| `r1_probe.py.txt` | `run('aware_start_missing_end', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[aware_start_missing_end]` | aware start + missing end -> timestamp_semantics_unverified | Preserved |
| `r1_probe.py.txt` | `run('aware_start_naive_zero_length_end', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[aware_start_naive_zero_length_end]` | aware start + naive end -> timestamp_semantics_unverified | Preserved |
| `r1_probe.py.txt` | `run('ISO_basic_wrong_start_hour', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[ISO_basic_wrong_start_hour]` | naive ISO basic 2026-10-15T230000 -> timestamp_semantics_unverified | Preserved |
| `r1_probe.py.txt` | `run('ISO_basic_aware_wrong_start_hour', ...)` | `test_independent_nywall_labels.py::test_r1_label_transform[ISO_basic_aware_wrong_start_hour]` | aware ISO basic 20261015T230000-0400 -> label_mismatch | Preserved |
| `r1_probe.py.txt` | `run('mixed_series_valid', ...)` | `test_independent_nywall_labels.py::test_r1_mixed_series[valid]` | alternating aware and date-only valid labels -> complete=True | Preserved |
| `r1_probe.py.txt` | `run('mixed_series_wrong_aware_end', ...)` | `test_independent_nywall_labels.py::test_r1_mixed_series[wrong_aware_end]` | alternating with wrong aware end -> timestamp_semantics_unverified | Preserved |
| `r1_probe.py.txt` | `run('mixed_series_aware_zero_length', ...)` | `test_independent_nywall_labels.py::test_r1_mixed_series[aware_zero_length]` | alternating with 0-length aware interval -> interval_end_mismatch | Preserved |
| `r1_probe.py.txt` | `OLD_GATE bare_same_end` (accepted in R1) | `test_independent_nywall_labels.py::test_r1_unsafe_acceptance_rejected[bare_same_end]` | bare equal clocks reject (not any interval_ok) | Adapted (R1 obsolete) |
| `r1_probe.py.txt` | `OLD_GATE aware_missing_end` (accepted in R1) | `test_independent_nywall_labels.py::test_r1_unsafe_acceptance_rejected[aware_missing_end]` | aware start with missing end rejects (not any interval_ok) | Adapted (R1 obsolete) |
| `r1_probe.py.txt` | `OLD_GATE date_start_wrong_aware_end` (accepted in R1) | `test_independent_nywall_labels.py::test_r1_unsafe_acceptance_rejected[date_start_wrong_aware_end]` | date start with aware noon end rejects (not any interval_ok) | Adapted (R1 obsolete) |
| `r1_probe.py.txt` | `OLD_GATE basic_aware_wrong_start` (accepted in R1) | `test_independent_nywall_labels.py::test_r1_unsafe_acceptance_rejected[basic_aware_wrong_start]` | basic aware wrong start rejects (not any interval_ok) | Adapted (R1 obsolete) |
| `r2_probe.py.txt` | `R2_iso_date_only_end` | `test_independent_nywall_labels.py::test_r2_adversarial_label[iso_date_only_end]` | ISO date-only end '2026-10-15' -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_end_surrounding_text` | `test_independent_nywall_labels.py::test_r2_adversarial_label[end_surrounding_text]` | text surrounding date -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_end_missing_zero` | `test_independent_nywall_labels.py::test_r2_adversarial_label[end_missing_zero]` | end='1/15/2026' -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_start_missing_zero` | `test_independent_nywall_labels.py::test_r2_adversarial_label[start_missing_zero]` | start='1/15/2026' -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_previous_start_same_end` | `test_independent_nywall_labels.py::test_r2_adversarial_label[previous_start_same_end]` | start='10/14/2026', end='10/15/2026' -> label_mismatch | Preserved |
| `r2_probe.py.txt` | `R2_missing_both_labels` | `test_independent_nywall_labels.py::test_r2_adversarial_label[missing_both_labels]` | start=None, end=None -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_end_basic_naive_datetime` | `test_independent_nywall_labels.py::test_r2_adversarial_label[end_basic_naive_datetime]` | end='20261015T230000' -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_start_basic_aware_wrong` | `test_independent_nywall_labels.py::test_r2_adversarial_label[start_basic_aware_wrong]` | start='20261015T230000-0400' -> label_mismatch | Preserved |
| `r2_probe.py.txt` | `R2_single_digit_month_start` | `test_independent_nywall_labels.py::test_r2_single_digit_month[start]` | start='1/05/2026' on 2026-01-05 -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_single_digit_month_end` | `test_independent_nywall_labels.py::test_r2_single_digit_month[end]` | end='1/05/2026' on 2026-01-05 -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_MIXED missing_labels reversed=False` | `test_independent_nywall_labels.py::test_r2_mixed_meter_overlap[missing_labels-normal]` | Meter #1 valid, Meter #2 missing labels -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_MIXED missing_labels reversed=True` | `test_independent_nywall_labels.py::test_r2_mixed_meter_overlap[missing_labels-reversed]` | Meter #2 missing labels, Meter #1 valid -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_MIXED wrong_aware_end reversed=False` | `test_independent_nywall_labels.py::test_r2_mixed_meter_overlap[wrong_aware_end-normal]` | Meter #1 valid, Meter #2 wrong aware end -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_MIXED wrong_aware_end reversed=True` | `test_independent_nywall_labels.py::test_r2_mixed_meter_overlap[wrong_aware_end-reversed]` | Meter #2 wrong aware end, Meter #1 valid -> timestamp_semantics_unverified | Preserved |
| `r2_probe.py.txt` | `R2_matching_aware` | `test_independent_nywall_labels.py::test_r2_positive_controls[matching_aware]` | Full-day aware start + 1h end -> complete=True | Preserved |
| `r2_probe.py.txt` | `R2_strict_next_date_end` | `test_independent_nywall_labels.py::test_r2_positive_controls[strict_next_date_end]` | start='10/15/2026', end='10/16/2026' -> complete=True | Preserved |
| `r2_probe.py.txt` | `R2_surrounding_whitespace` | `test_independent_nywall_labels.py::test_r2_positive_controls[surrounding_whitespace]` | start=' 10/15/2026 ', end='\n10/15/2026\t' -> complete=True | Preserved |
| `r2_probe.py.txt` | `CAPTCHA user` | `test_independent_nywall_contract.py::test_captcha_placeholder_formatting[user]` | all 4 placeholders rendered in strings & translations | Preserved (isolated synthetic) |
| `r2_probe.py.txt` | `CAPTCHA reauth_confirm` | `test_independent_nywall_contract.py::test_captcha_placeholder_formatting[reauth_confirm]` | all 4 placeholders rendered in strings & translations | Preserved (isolated synthetic) |
| `r2_probe.py.txt` | `CAPTCHA reconfigure` | `test_independent_nywall_contract.py::test_captcha_placeholder_formatting[reconfigure]` | all 4 placeholders rendered in strings & translations | Preserved (isolated synthetic) |

Total mapped cases: **49**.

## Scope notes

- Captcha control is FORMAT-ONLY: it renders the `config.step.captcha.description` string from `strings.json` and `translations/en.json` with all four placeholders. The original R2 probe also asserted the flow `step_id`; that needs a config flow and is out of scope for this isolated control (covered by tests/test_config_flow.py). The three origin parameters exercise the same string, so they document origin coverage, not three independent checks.
- Tests are marked `independent` by module-level `pytestmark`; the directory conftest holds fixtures only.

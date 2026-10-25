# Hourly R5 Physical Storage & Recorder Probes Provenance

## Group Overview
- **Group Name**: `hourly_r5`
- **Status**: `active`
- **Reviewer KB Reference**: `7a31c9d4-2e8b-4f6a-b1d0-20261025a002`
- **Expected Collection Count**: 60 test items (39 in `test_independent_hourly_r5.py`, 2 in `test_independent_hourly_physical_failure.py`, 19 in `test_independent_hourly_guards.py`)

## Sources and Integrity Manifest

| Archived Source Path | Original Path | SHA-256 Digest | Role | Collect |
|---|---|---|---|---|
| `hourly_r5/conftest.py.txt` | `/tmp/pseg-independent-r5/conftest.py` | `262d018fe57a51272d90343468df8a89e006987a1061cb242c4c488f2bed42c0` | conftest | false |
| `hourly_r5/test_independent.py.txt` | `/tmp/pseg-independent-r5/test_independent.py` | `c3805bf723ba0d231d0f2d76447f236e4a0b9ef87dafe97b21f5e5d13c44e07c` | probe | false |
| `hourly_r5/test_physical_failure.py.txt` | `/tmp/pseg-independent-r5/test_physical_failure.py` | `e39c6205611344a3ac5219ca8a136a7af7077857330d09f7d76e073a5f80eb5f` | probe | false |
| `hourly_r5/test_r5.py.txt` | `/tmp/pseg-independent-r5/test_r5.py` | `75425590f63ed080adff85866fc6db4e6cf86582519c2c4e71690b37fc909355` | probe | false |

## Promoted File Inventory

1. `__init__.py`: Package marker for `tests.independent.hourly_r5`.
2. `conftest.py`: Local fixtures providing `physical_statistics_store` and overriding root `_real_pseg_statistics_writes` by fixture name to prevent double-wrapping `Store._async_write_data`.
3. `test_independent_hourly_r5.py`: Promoted independent recorder and storage lifecycle probes (39 test cases).
4. `test_independent_hourly_physical_failure.py`: Promoted physical storage failure injection probes (2 test cases).
5. `test_independent_hourly_guards.py`: Promoted boundary and transition guard probes (19 test cases).

## Transformation Rationale
1. **Verbatim AST Preservation**: Assertion ASTs, parameter tables, and fault injection matrices are preserved verbatim from the archived source probes.
2. **Import Normalization**:
   - `test_statistics_recorder` helper imports normalized to `from tests.test_statistics_recorder import ...`.
   - Inter-module probe imports in `test_independent_hourly_physical_failure.py` and `test_independent_hourly_guards.py` updated from `from test_independent import ...` to `from tests.independent.hourly_r5.test_independent_hourly_r5 import ...`.
3. **Root Fixture Name Override**:
   - The root conftest fixture `_real_pseg_statistics_writes` is overridden by name as a no-op in local `conftest.py`. This ensures only `physical_statistics_store` wraps `Store._async_write_data` and manages the local `tmp_path` storage target, avoiding dual-wrapping interference.

## v1.6.0 contract supersession: `test_interval_evidence_all_day_lengths` (parent-approved)

The archived probe asserted the pre-1.6.0 rule `result.complete is (labels == 'aware_valid')`
with `x` as true UTC. Under the shipped v1.6.0 contract (`00ba6b3`; contract KB
`5e0c2b1a-7f3d-4a91-9c2e-20261025a001`; Codex reviews `0ce46ae2` FIX -> `8f4541f2` SHIP)
that rule is obsolete, so this one test is deliberately changed:

- **Input (all 12 cases):** `x` is the America/New_York wall-clock hour start encoded as
  UTC ms. The builder's first draft adapted `x` only for `aware_valid`; the other label
  variants then failed solely from a 4-5 h timestamp shift (`unexpected_start`), passing
  vacuously. Every variant now gets a contract-correct `x`, so a rejection is caused by
  its labels.
- **Assertion:** replaced by a declared `(complete, reason)` table `V160_EXPECTED`:
  strict `MM/DD/YYYY` date-only pairs and aware pairs promote on the spring (23 h) and a
  normal day; the fall-back day 2026-11-01 never promotes (`dst_ambiguous` for consistent
  labels; `label_mismatch` when labels contradict, because `validate_hourly_day` reports
  `label_mismatch` before any interval reason); `bare_clock` and `end_stamped` never promote.
- Every other test in this group is AST-unchanged from the archive.

Tests are marked `independent` via module-level `pytestmark`; the directory conftest holds fixtures only.

Other promotion edits are import/format-only (parent AST audit): an unused `_hourly_chart` import dropped and imports reordered in two `test_independent_hourly_r5.py` functions, and the `physical_statistics_store` conftest fixture reformatted (comment kept as docstring). No other test body differs from the archive.

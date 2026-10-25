# Independent Probe Provenance and Archive

## Overview
This directory preserves legacy review probes and standalone assertion scripts for the `ha-pseg` integration in an inert archive layout. Volatile probe files from `/tmp` review sessions are stored byte-exact under `tests/independent/archive/<group>/*.py.txt` to prevent loss when temporary directories are purged.

## Integrity and Provenance Invariants
1. **Byte-Exact Inert Storage**: Original source files are archived as noncollectable `*.py.txt` files. They cannot be executed, imported, or collected directly by `pytest`.
2. **Deterministic Manifest**: `tests/independent/archive/manifest.json` pins each archived file's relative path, original absolute path, full SHA-256 digest, byte count, and expected prefix from the plan inventory.
3. **Automated Verification**: `tools/probe_provenance.py` verifies that all archived files exist, hashes match, no unmanifested files exist in archive, and no unregistered `test_*.py` files exist in active test directories.
4. **Promotion Contract (P1-05 through P1-08)**: When probes are promoted to active pytest suites, assertion ASTs and parameter domains must be preserved verbatim (except explicitly documented and reviewed supersessions such as C5 and R7B). Promoted suites declare their transformations and complete file hashes (tests, conftest, helpers, `__init__.py`) in a local `provenance.json` using source tuples:
```json
{
  "group": "auth_r1", "status": "active", "reviewer_kb": "0ce46ae2-76f1-4f59-8b73-e744c48e3f62",
  "sources": [{"original_path": "/tmp/pseg-auth-review-r1/test_adversarial.py", "original_sha256": "251976e0b083a7da93c6e2256d66c0de81ea0432557ed984a1c7c30608865c82", "archived_path": "auth_r1/test_adversarial.py.txt", "archived_sha256": "251976e0b083a7da93c6e2256d66c0de81ea0432557ed984a1c7c30608865c82", "role": "probe", "collect": false},
              {"original_path": "/tmp/pseg-auth-review-r1/conftest.py", "original_sha256": "88fbd609ef7b2b0026e303f4d844642153ebf3a47131ddfecca325f2f13e2934", "archived_path": "auth_r1/conftest.py.txt", "archived_sha256": "88fbd609ef7b2b0026e303f4d844642153ebf3a47131ddfecca325f2f13e2934", "role": "conftest", "collect": false}],
  "expected_collection": 15, "transformation_rationale": ["Preserve verbatim AST; normalize imports to tests.independent"],
  "promoted_files": [{"relative_path": "test_independent_auth_r1.py", "sha256": "251976e0b083a7da93c6e2256d66c0de81ea0432557ed984a1c7c30608865c82"}, {"relative_path": "conftest.py", "sha256": "88fbd609ef7b2b0026e303f4d844642153ebf3a47131ddfecca325f2f13e2934"}, {"relative_path": "__init__.py", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]
}
```
   `sources` must list EVERY archived file of the group (tests, conftest, `.orig`, adapted copies); verify fails on an uncovered archive file.
5. **Scope: Python files only.** `promoted_files` coverage is enforced for `*.py` files. Non-Python data that can change test results (JSON/text fixtures, golden files) is NOT verified automatically: a promoted group that uses such files MUST register each one in `promoted_files` with its sha256, and its reviewer must check that they are registered.
6. **Privacy and Safety**: No real secrets, tokens, credentials, or real meter/account identifiers are preserved. Only synthetic fixtures and documented legacy synthetic names are retained.

## Surviving Probe Inventory

| Group | Archive Path | Original Path | Expected Prefix | Historical Cases / Description |
|---|---|---|---|---|
| `auth_r1` | `auth_r1/test_adversarial.py.txt` | `/tmp/pseg-auth-review-r1/test_adversarial.py` | `251976e0` | 15 cases; adversarial session/credential boundaries |
| `auth_r1` | `auth_r1/conftest.py.txt` | `/tmp/pseg-auth-review-r1/conftest.py` | - | Small conftest fixture definitions |
| `auth_r2` | `auth_r2/test_r2_adversarial.py.txt` | `/tmp/pseg-auth-review-r2-opus/test_r2_adversarial.py` | `c8c901ae` | 24 cases; R2 adversarial flow probes |
| `auth_r2` | `auth_r2/test_r2_extra.py.txt` | `/tmp/pseg-auth-review-r2-opus/test_r2_extra.py` | `d9bcb1cf` | 5 cases; R2 extra probes (29 total across R2) |
| `auth_r2` | `auth_r2/test_r2_adversarial.py.orig.txt` | `/tmp/pseg-auth-review-r2-opus/test_r2_adversarial.py.orig` | - | Preserves C5 expectation history before adaptation |
| `auth_r2` | `auth_r2/conftest.py.txt` | `/tmp/pseg-auth-review-r2-opus/conftest.py` | - | Small conftest fixture definitions |
| `auth_r3` | `auth_r3/test_r3_probes.py.txt` | `/tmp/pseg-auth-review-r3-opus/probes/test_r3_probes.py` | `d15abd37` | 29 cases; R3 lifecycle and regression probes |
| `auth_r3` | `auth_r3/conftest.py.txt` | `/tmp/pseg-auth-review-r3-opus/probes/conftest.py` | - | Small conftest fixture definitions |
| `auth_r4` | `auth_r4/test_final_lifecycle.py.txt` | `/tmp/pseg-auth-final-review-20261023/probes/test_final_lifecycle.py` | `ae8dd501` | 29 cases; final lifecycle and keepalive probes |
| `hourly_r5` | `hourly_r5/test_independent.py.txt` | `/tmp/pseg-independent-r5/test_independent.py` | `c3805bf7` | 32 cases; independent hourly recorder/Store probes |
| `hourly_r5` | `hourly_r5/test_physical_failure.py.txt` | `/tmp/pseg-independent-r5/test_physical_failure.py` | `e39c6205` | 5 cases; physical storage failure injection probes |
| `hourly_r5` | `hourly_r5/test_r5.py.txt` | `/tmp/pseg-independent-r5/test_r5.py` | `75425590` | 23 cases; R5 boundary/transition probes (60 total across group) |
| `hourly_r5` | `hourly_r5/conftest.py.txt` | `/tmp/pseg-independent-r5/conftest.py` | `262d018f` | Hourly R5 conftest fixtures |
| `auth_r5` | `auth_r5/test_r5_boundaries.py.txt` | `/tmp/pseg-auth-review-r5-20261023/test_r5_boundaries.py` | `c3de33d7` | 58 cases; auth boundary and renewal probes |
| `auth_r6` | `auth_r6/test_r6_probes.py.txt` | `/tmp/pseg-auth-review-r6-20261023/test_r6_probes.py` | - | 24 cases; auth R6 envelope & contributor probes |
| `auth_r6` | `auth_r6/test_r6_extra.py.txt` | `/tmp/pseg-auth-review-r6-20261023/test_r6_extra.py` | - | 6 cases; auth R6 extra probes |
| `auth_r6` | `auth_r6/test_r6_flows.py.txt` | `/tmp/pseg-auth-review-r6-20261023/test_r6_flows.py` | - | 13 cases; auth R6 flow probes |
| `auth_r6` | `auth_r6/test_r6_race.py.txt` | `/tmp/pseg-auth-review-r6-20261023/test_r6_race.py` | - | 5 cases; auth R6 race probes (48 total across group) |
| `auth_r7b` | `auth_r7b/test_r7b_boundaries.py.txt` | `/tmp/pseg-auth-review-r7b-20261023/test_r7b_boundaries.py` | `cad14c01` | Original 28/29 boundary tests |
| `auth_r7b` | `auth_r7b/test_r7b_boundaries_adapted.py.txt` | `/tmp/pseg-auth-review-r9-20261024/r7b-adapted/test_r7b_boundaries_adapted.py` | `177e0748` | Approved adapted 29/29 target |
| `auth_r8` | `auth_r8/test_r8_probes.py.txt` | `/tmp/pseg-auth-review-r8-20261024/test_r8_probes.py` | `4f7a4ee6` | 22 cases; auth R8 probes |
| `auth_r9` | `auth_r9/test_r9_probes.py.txt` | `/tmp/pseg-auth-review-r9-20261024/test_r9_probes.py` | `bb9924b1` | 8 cases; auth R9 probes |
| `nywall` | `nywall/r1_probe.py.txt` | `/tmp/pseg-review-nywall-r1/probe.py` | `bcc76c9f` | Standalone assertion script (historical baseline) |
| `nywall` | `nywall/r2_probe.py.txt` | `/tmp/pseg-review-nywall-r2/probe.py` | `d244c6df` | Standalone assertion script (adapted baseline) |

## Verification CLI
To verify the provenance archive and all promoted manifests:
```bash
python tools/probe_provenance.py verify --root tests/independent
```

To re-run probe capture from the source specification:
```bash
python tools/probe_provenance.py capture --spec tests/independent/probe_sources.json --dest tests/independent/archive
```

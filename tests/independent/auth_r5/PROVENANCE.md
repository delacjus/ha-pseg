# Auth R5 Independent Probes Provenance

## Group Overview
- **Group Name**: `auth_r5`
- **Status**: active
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`
- **Expected Collection**: 58 cases

## Source Probes
- `auth_r5/test_r5_boundaries.py.txt`
  - Original Path: `/tmp/pseg-auth-review-r5-20261023/test_r5_boundaries.py`
  - SHA-256: `c3de33d7f7c9026051ba5a6de64f294201c8e9c56d99673d6ad7e943b30a9c8c`
  - Role: probe (historical 58 cases)

## Transformation Rationale
- Assertion ASTs and parameter domains preserved verbatim.
- Helper imports normalized from legacy bare import to `tests.test_auth_review_r3_regressions`.
- Applies `independent` marker to all probes via `conftest.py`.

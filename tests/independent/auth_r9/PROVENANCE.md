# Auth R9 Independent Probes Provenance

## Group Overview
- **Group Name**: `auth_r9`
- **Status**: active
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`
- **Approved Supersession KB**: `a4b7e2d9-51c6-4f38-8b02-20261024a4b7`
- **Expected Collection**: 8 cases

## Source Probes
- `auth_r9/test_r9_probes.py.txt`
  - Original Path: `/tmp/pseg-auth-review-r9-20261024/test_r9_probes.py`
  - SHA-256: `bb9924b11541c8978a1bc90624ac951be474c9e60162ff910497fbe0cd5624d7`
  - Role: probe (historical 8 cases)

## Transformation Rationale
- Assertion ASTs and parameter domains preserved verbatim.
- Helper imports normalized from `test_r6_probes` to `tests.independent.auth_r6.test_independent_auth_r6`.
- Applies `independent` marker to all probes via `conftest.py`.

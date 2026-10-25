# Auth R8 Independent Probes Provenance

## Group Overview
- **Group Name**: `auth_r8`
- **Status**: active
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`
- **Expected Collection**: 22 cases

## Source Probes
- `auth_r8/test_r8_probes.py.txt`
  - Original Path: `/tmp/pseg-auth-review-r8-20261024/test_r8_probes.py`
  - SHA-256: `4f7a4ee6b63d4fe7882e4f2948433828f15c6b148711136216a9c76ca9298fd7`
  - Role: probe (historical 22 cases)

## Transformation Rationale
- Assertion ASTs and parameter domains preserved verbatim.
- No helper import changes required.
- Applies `independent` marker to all probes via `conftest.py`.

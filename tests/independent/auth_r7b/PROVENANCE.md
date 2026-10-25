# Auth R7B Independent Probes Provenance

## Group Overview
- **Group Name**: `auth_r7b`
- **Status**: active
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`
- **Approved Supersession KB**: `a4b7e2d9-51c6-4f38-8b02-20261024a4b7`
- **Expected Collection**: 29 cases

## Source Probes
- `auth_r7b/test_r7b_boundaries.py.txt` (original cad14c01..., historically 28/29, preserved inert)
- `auth_r7b/test_r7b_boundaries_adapted.py.txt` (adapted 177e0748..., approved 29/29 target, collected)

## Transformation Rationale
- Promotes the reviewer-approved adapted copy (177e0748) where one return-vs-typed-UpdateFailed expectation was superseded in R8/R9.
- Archive preserves both original (cad14c01) and adapted sources; only the adapted probe is collected.
- Assertion ASTs and parameter domains preserved verbatim from adapted source.
- Imports from `test_r6_probes` resolved through `tests.independent.auth_r6.test_independent_auth_r6`.
- Applies `independent` marker to all probes via `conftest.py`.

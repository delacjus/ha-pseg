# Auth R6 Independent Probes Provenance

## Group Overview
- **Group Name**: `auth_r6`
- **Status**: active
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`
- **Expected Collection**: 48 cases (24 probes, 6 extra, 13 flows, 5 race)

## Source Probes
- `auth_r6/test_r6_probes.py.txt` (24 cases, sha256 `7e28cd47...`)
- `auth_r6/test_r6_extra.py.txt` (6 cases, sha256 `100448df...`)
- `auth_r6/test_r6_flows.py.txt` (13 cases, sha256 `bb4ee828...`)
- `auth_r6/test_r6_race.py.txt` (5 cases, sha256 `fb2ec3e1...`)

## Transformation Rationale
- Assertion ASTs and parameter domains preserved verbatim across all four probe files.
- Internal helper imports updated from `test_r6_probes` to stable `tests.independent.auth_r6.test_independent_auth_r6`.
- Applies `independent` marker to all probes via `conftest.py`.

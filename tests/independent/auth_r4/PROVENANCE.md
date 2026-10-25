# Provenance: auth_r4

## Summary
Group auth_r4 preserves 29 independent final lifecycle probes covering whole-jar quarantine during failed optional hourly fetch, coordinator stop handoffs, and retirement of saved credentials.

- **Status**: active
- **Expected Collection**: 29
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`

## Sources
| Archived Path | Original Path | SHA-256 | Role |
|---|---|---|---|
| `auth_r4/test_final_lifecycle.py.txt` | `/tmp/pseg-auth-final-review-20261023/probes/test_final_lifecycle.py` | `ae8dd501d013...` | probe |

## Promoted Files
| Relative Path | SHA-256 |
|---|---|
| `__init__.py` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `conftest.py` | `73907f13038a547b2060bb483706c795db09b653c5ea7307a4d3e22bea8e8eaf` |
| `test_independent_auth_r4.py` | `dccc18af0a7800b43f000fe4a96f2d21024da961e4ed142d709967e01a0c2199` |

## Transformation Rationale
- Promote inert probe to active independent test suite
- Preserve assertion ASTs and parameter domains verbatim
- Normalize regressions import to stable tests.test_auth_review_r3_regressions package path
- Apply independent test marker via conftest and module pytestmark
- Inherit root custom integration and statistics fixtures


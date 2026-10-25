# Provenance: auth_r3

## Summary
Group auth_r3 preserves 29 independent review probes covering coordinator lifecycle, timeout jar preservation, human rearm gaps, and password fallback safeguards.

- **Status**: active
- **Expected Collection**: 29
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`

## Sources
| Archived Path | Original Path | SHA-256 | Role |
|---|---|---|---|
| `auth_r3/test_r3_probes.py.txt` | `/tmp/pseg-auth-review-r3-opus/probes/test_r3_probes.py` | `d15abd37e1bd...` | probe |
| `auth_r3/conftest.py.txt` | `/tmp/pseg-auth-review-r3-opus/probes/conftest.py` | `88fbd609ef7b...` | conftest |

## Promoted Files
| Relative Path | SHA-256 |
|---|---|
| `__init__.py` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `conftest.py` | `2240ed6b37504b6f368a0a8711d112c2fd6c31fbcf6e668ae62546f89cdfdd7a` |
| `test_independent_auth_r3.py` | `52bc0bfe6c667bd7fa676683e5080e35a2b760b1976a1bb1db6c3cf2ef85e96c` |

## Transformation Rationale
- Promote inert probe to active independent test suite
- Preserve assertion ASTs and parameter domains verbatim
- Apply independent test marker via conftest and module pytestmark
- Inherit root custom integration and statistics fixtures


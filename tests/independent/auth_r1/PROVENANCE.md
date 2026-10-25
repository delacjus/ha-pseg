# Provenance: auth_r1

## Summary
Group auth_r1 preserves 15 independent adversarial review probes for PSE&G authentication lifecycle, transient renewal failures, and token rotation.

- **Status**: active
- **Expected Collection**: 15
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`

## Sources
| Archived Path | Original Path | SHA-256 | Role |
|---|---|---|---|
| `auth_r1/test_adversarial.py.txt` | `/tmp/pseg-auth-review-r1/test_adversarial.py` | `251976e0b083...` | probe |
| `auth_r1/conftest.py.txt` | `/tmp/pseg-auth-review-r1/conftest.py` | `88fbd609ef7b...` | conftest |

## Promoted Files
| Relative Path | SHA-256 |
|---|---|
| `__init__.py` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `conftest.py` | `aee46e33d7b0f91b5744d6a043abe01baa957acfc36473ba0749d12e0dbc081f` |
| `test_independent_auth_r1.py` | `56872d5bc4d8d755473bcd1d041b80e6893c11f9d567009e76957b25cad7125a` |

## Transformation Rationale
- Promote inert probe to active independent test suite
- Preserve assertion ASTs and parameter domains verbatim
- Apply independent test marker via conftest and module pytestmark
- Inherit root custom integration and statistics fixtures


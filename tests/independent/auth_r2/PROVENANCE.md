# Provenance: auth_r2

## Summary
Group auth_r2 preserves 29 independent review probes (26 in test_independent_auth_r2.py, 3 in test_independent_auth_r2_extra.py) covering adversarial cookie renewals, admission cooldowns, and human rearm transitions.

- **Status**: active
- **Expected Collection**: 29
- **Reviewer KB**: `0ce46ae2-76f1-4f59-8b73-e744c48e3f62`

## Sources
| Archived Path | Original Path | SHA-256 | Role |
|---|---|---|---|
| `auth_r2/test_r2_adversarial.py.txt` | `/tmp/pseg-auth-review-r2-opus/test_r2_adversarial.py` | `c8c901aefe7f...` | probe |
| `auth_r2/test_r2_extra.py.txt` | `/tmp/pseg-auth-review-r2-opus/test_r2_extra.py` | `d9bcb1cf71f1...` | probe |
| `auth_r2/test_r2_adversarial.py.orig.txt` | `/tmp/pseg-auth-review-r2-opus/test_r2_adversarial.py.orig` | `46ffaf1032f8...` | historical_orig |
| `auth_r2/conftest.py.txt` | `/tmp/pseg-auth-review-r2-opus/conftest.py` | `88fbd609ef7b...` | conftest |

## Promoted Files
| Relative Path | SHA-256 |
|---|---|
| `__init__.py` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `conftest.py` | `ba7fe5d00ca5b0298ef2fbb11b5f8ae79075519177a13405ae1f94d20fbe4976` |
| `test_independent_auth_r2.py` | `6148a7f8fdfe33af2f87707ffa9df63519cde66d617f09c7dfa52c5b21bd6c0b` |
| `test_independent_auth_r2_extra.py` | `c34a09de377e5895913738d726578bd31e30c5eab7b18de05635106febdb6437` |

## Transformation Rationale
- Promote inert probes to active independent test suite
- Preserve assertion ASTs and parameter domains verbatim
- Preserve C5 expectation history documented in PROVENANCE.md and test_r2_adversarial.py.orig.txt
- Normalize cross-test import to stable tests.independent.auth_r2 package path
- Apply independent test marker via conftest and module pytestmark
- Inherit root custom integration and statistics fixtures

### C5 Expectation History
In `test_r2_adversarial.py.orig.txt` (line 462), `test_c5_human_rearm_preserves_reserved_gap_and_defers_replacement_poll` originally expected:
```python
with pytest.raises(PsegOktaSessionExpired):
    await hass.async_add_executor_job(new_client.ensure_session)
assert new_client.auth_reason is not None
```
In adapted `test_r2_adversarial.py.txt` and promoted `test_independent_auth_r2.py`:
```python
with pytest.raises(PsegTransientError):
    await hass.async_add_executor_job(new_client.ensure_session)
# The human rearm's conservative global gap is a PENDING retry, not a second
# re-auth demand: no new failure is recorded and no slot is spent.
assert new_client.auth_reason is None
```
**Rationale**: The human rearm's conservative global gap represents a PENDING retry rather than a second re-auth demand. Under this contract, no new failure is recorded and no slot is spent, yielding `PsegTransientError` and `new_client.auth_reason is None`. Both original bytes (`.orig.txt`) and adapted bytes (`.py.txt`) are retained in the archive to preserve this provenance.


# Local Testing and Release Verification

This repository provides reproducible local release validation and testing tooling
driven by `tools/release_check.py`. All profile runs execute in fresh, isolated,
disposable filesystem snapshots created by `tools/_snapshot.py`, preventing any
modifications, bytecode generation, or cache pollution from touching the source tree.

## Prerequisites and Environment

Install the pinned test dependencies from `requirements_test.txt` into a Python 3.14 virtual environment:

```sh
export PSEG_TEST_PYTHON=/home/tacoriffic/ha-pseg/.venv/bin/python
export PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 RUFF_NO_CACHE=true
```

Node.js 22 is required for Node test suites and offline security guard verification.

## Release Check Profiles

Run release checks from the repository root:

```sh
"$PSEG_TEST_PYTHON" -B tools/release_check.py fast --source . --python "$PSEG_TEST_PYTHON"
"$PSEG_TEST_PYTHON" -B tools/release_check.py node --source . --python "$PSEG_TEST_PYTHON"
"$PSEG_TEST_PYTHON" -B tools/release_check.py independent --source . --python "$PSEG_TEST_PYTHON"
"$PSEG_TEST_PYTHON" -B tools/release_check.py mutation --source . --python "$PSEG_TEST_PYTHON"
"$PSEG_TEST_PYTHON" -B tools/release_check.py all --source . --python "$PSEG_TEST_PYTHON"
```

### Profile Descriptions

- **`fast`**: Runs `ruff check .` and all collected Python test suites, excluding those marked `slow`, `nightly`, or `quarantine`. Promoted independent suites remain included in `fast`.
- **`node`**: Verifies Node.js offline guards and tests using the offline preload (`tests/support/node_offline.cjs`) across `tests/test_node_offline.js`, `tests/test_captcha_helper.js`, and `tests/test_captcha_extension.js`.
- **`independent`**: Runs the promoted independent probe suites (`-m independent`) in isolation.
- **`mutation`**: Runs all 60 authentication guard mutations in fresh per-mutant copies using `tools/mutation_check.py` against `tests/mutations/auth_guards.py`.
- **`all`**: Runs `fast`, `node`, `independent`, and `mutation` sequentially in fresh disposable copies.
- **Reserved Profiles**: `slow`, `nightly`, `replay`, and `stats-baseline` are reserved for future test tiers and fail clearly until implemented.

## Execution Options

- **`--repeat N`**: Executes the specified profile `N` times sequentially, creating a fresh snapshot and distinct evidence directory for each iteration to detect flakes or nondeterminism:
  ```sh
  "$PSEG_TEST_PYTHON" -B tools/release_check.py independent --source . --python "$PSEG_TEST_PYTHON" --repeat 2
  ```
- **`--paths-from FILE`**: Explicitly includes new, reviewed untracked suite files (one relative path per line or snapshot JSON list) in the snapshot before staging or committing:
  ```sh
  "$PSEG_TEST_PYTHON" -B tools/release_check.py fast --source . --python "$PSEG_TEST_PYTHON" --paths-from /path/to/paths.txt
  ```
  All tracked regular suite files are included automatically. Arbitrary untracked files, symlink escapes, and excluded categories (`.git`, `.venv`, caches, logs, credentials) are rejected by the snapshot contract.
- **`--timeout SECONDS`**: Configures per-child process timeout (default: 600s).
- **`--source PATH`**: Specifies source repository or snapshot root (default: `.`).
- **`--python PATH`**: Specifies the Python interpreter (defaults to `$PSEG_TEST_PYTHON` or `sys.executable`).

## Snapshot Isolation and Evidence Directory

Each iteration creates a temporary directory under `/tmp/pseg-release-*`:
- **`source/`**: The clean snapshot copy of the repository.
- **`runtime/<profile>/output.log`**: Subprocess stdout/stderr logs.
- **`mutation-runtime/output.log`**: Detailed mutation engine results.

Children run with copy-local `PYTHONPATH`, temporary directories (`TMPDIR`), pytest basetemp, and cache directories (`XDG_CACHE_HOME`). Python bytecode writes and Ruff caching are disabled.

Evidence directories remain available after the run for inspection and debugging. Remove them when no longer needed.

## Reading Results

`tools/release_check.py` outputs structured JSON lines to stdout:

1. **Iteration and evidence location**:
   ```json
   {"repeat": 1, "evidence": "/tmp/pseg-release-d7640g5d"}
   ```
2. **Initial source state**:
   ```json
   {"source_before": {"head": "...", "sha256": "...", "status": ""}}
   ```
3. **Snapshot manifest**:
   ```json
   {"copy": "/tmp/pseg-release-.../source", "files": 176, "manifest": "..."}
   ```
4. **Child execution records**:
   ```json
   {"child": "fast-pytest", "counts": {"passed": 1385}, "empty_suite": false, "log": "...", "ok": true, "returncode": 0, "timeout": false}
   ```
5. **Final source state and integrity assertion**:
   ```json
   {"source_after": {"head": "...", "sha256": "...", "status": ""}, "source_unchanged": true}
   ```

### Exit Codes

- **`0`**: Success. All tests passed, all mutations were detected, and source integrity verified unchanged before and after.
- **`1`**: Failure. A test child failed, an unexpected mutant survived, or source changed during execution.
- **`2`**: Invalid specification, missing interpreter, collection error, or timeout.

## Mutation Testing Tools

In addition to `tools/release_check.py mutation`, you can run the mutation engine directly:

```sh
"$PSEG_TEST_PYTHON" -B tools/mutation_check.py --source . --python "$PSEG_TEST_PYTHON" --table tests/mutations/auth_guards.py --json
"$PSEG_TEST_PYTHON" -B tests/auth_guard_mutations.py
```

Filter to a single mutant label for quick diagnosis:

```sh
"$PSEG_TEST_PYTHON" -B tools/mutation_check.py --source . --python "$PSEG_TEST_PYTHON" --table tests/mutations/auth_guards.py --only 1-entry-shared-admission --json
```

## Contract Testing Suites

- **`tests/test_cost_contract.py`**: Offline pure contract test suite freezing the
  PSE&G portal dollar contract (`UsageType: "2"`) and non-authoritative request seam.
  It enforces preservation of the 13 canonical Chart form fields, verifies the current
  production consumption request baseline, enumerates the 8 non-authoritative evidence
  statuses, validates authoritative meter matching (rejecting upstream `series[0]` and
  unauthoritative discovery), verifies that zero is a valid numeric observation
  (rejecting upstream zero-to-estimate substitution), and quarantines booleans, NaN/Inf,
  negative credits, duplicates, and non-USD units.

## Freeze and Snapshot Utilities

The underlying snapshot engine in `tools/_snapshot.py` is accessible directly via `release_check`:

- **Freeze candidate manifest**:
  ```sh
  "$PSEG_TEST_PYTHON" -B tools/release_check.py freeze --source . --json
  ```
- **Create an independent snapshot copy**:
  ```sh
  "$PSEG_TEST_PYTHON" -B tools/release_check.py snapshot --source . --dest /path/to/destination
  ```

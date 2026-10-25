# Local release checks

For maintainers with the pinned development dependencies installed (see
`requirements_test.txt`), run from the repository root:

```sh
export PSEG_TEST_PYTHON=/absolute/path/to/venv/bin/python
export PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 RUFF_NO_CACHE=true
"$PSEG_TEST_PYTHON" -B tools/release_check.py fast --source . --python "$PSEG_TEST_PYTHON"
"$PSEG_TEST_PYTHON" -B tools/release_check.py node --source . --python "$PSEG_TEST_PYTHON"
"$PSEG_TEST_PYTHON" -B tools/release_check.py independent --source . --python "$PSEG_TEST_PYTHON" --repeat 2
```

`fast` runs `ruff check .` and every Python test except those marked `slow`,
`nightly`, or `quarantine`. Tests marked `independent` remain in `fast`;
`independent` also runs them separately with `-m independent`. `node` requires
Node on PATH and runs the offline preload with `tests/test_node_offline.js`,
`tests/test_captcha_helper.js`, and `tests/test_captcha_extension.js`.

Each repeat creates a fresh external snapshot using `tools/_snapshot.py`, retaining
tracked edits. Explicitly include reviewed untracked suite files with
`--paths-from /absolute/path/to/paths.txt` (one relative file path per line, or the
snapshot helper's JSON list format). All tracked eligible files are still included.
For example, list `tests/new_suite/test_example.py` to test that new file before
staging it. Arbitrary untracked inputs, excluded files, symlinks, and escaping paths
are rejected by the snapshot contract.

Children run from the copy with copy-local import paths, temporary directories,
pytest basetemp, and cache locations. Bytecode, pytest cache, and Ruff cache writes
are disabled. Every run prints its evidence directory, manifest aggregate, child
counts/exits/log paths, and source HEAD/status/hash before and after. A changed
source, failed child, missing executable, empty suite, or timeout returns nonzero.
The per-child timeout defaults to 600 seconds; override it with `--timeout SECONDS`.
Evidence (including successful runs) remains under the printed `/tmp/pseg-release-*`
directory for inspection; remove that directory when it is no longer needed.
This is a local release helper with the same threat model as `_snapshot.py`, not a
sandbox against a hostile process with your user permissions.

`mutation` runs all 60 auth guard mutations through `tools/mutation_check.py`
in fresh copies. `all` runs `fast`, `node`, `independent`, and `mutation`.
Future `slow`, `nightly`, `replay`, and `stats-baseline` profiles fail clearly
until implemented.

```sh
"$PSEG_TEST_PYTHON" -B tools/release_check.py mutation --source . --python "$PSEG_TEST_PYTHON"
"$PSEG_TEST_PYTHON" -B tools/mutation_check.py --source . --python "$PSEG_TEST_PYTHON" --table tests/mutations/auth_guards.py --json
"$PSEG_TEST_PYTHON" -B tests/auth_guard_mutations.py
```

The compatibility command uses the same copy-only engine and honors
`PSEG_TEST_PYTHON` (default: the current interpreter). Mutation engine exits are
0 for all detected, 1 for survivors, and 2 for invalid specifications or runs;
the release profile returns nonzero on either failure. Row-specific expected
exceptions are declared in the catalog; collection/setup errors never count as
detections. The frozen `tests/mutations/auth_guards_original.json` fixture was
extracted from `git show 804451d:tests/auth_guard_mutations.py` when writing the
catalog tests; runtime tests require no git history.

The existing `freeze --source . --json` and
`snapshot --source . --dest /absolute/nonexistent/directory` subcommands remain
available; both accept `--paths-from`.

"""Runnable mutation table for the reviewed ADAPTER_LEVEL rows (P2-10).

The historical transformations live once, in :mod:`tests.mutations.auth_systemic`
(``ORIGINAL_MUTATIONS`` plus ``NEW_MUTATIONS``). Four of those rows have no
faithful systemic detector: their only observable difference is in-process state,
so the systemic table excludes them and this table owns them instead. Each row
keeps its reviewed reason below, and the catalog meta-test asserts this exact set
plus the partition 57 systemic + 4 adapter-level = 60 preserved + 1 new.

Run it directly, without any shim::

    $PSEG_TEST_PYTHON -B tools/mutation_check.py --source . \\
        --python "$PSEG_TEST_PYTHON" \\
        --table tests/mutations/auth_systemic_adapter.py --json

These rows are NOT systemic detections; their mapped ``test_adapter_*`` nodes
assert a production seam, and every reason explains what masks the row from any
public dispatch, persistence or HA-state observation.
"""

from tests.mutations.auth_systemic import (
    ADAPTER_LEVEL_LABELS,
    ADAPTER_LEVEL_MUTATIONS,
    ADAPTER_LEVEL_REASONS,
)

#: The four adapter-level rows (13, 50, 55 and the new persist fault), verbatim.
ROWS = ADAPTER_LEVEL_MUTATIONS

#: Reviewed reason each row's only faithful detector is an adapter-level seam.
REASONS = ADAPTER_LEVEL_REASONS

#: The exact reviewed adapter-level label set.
LABELS = ADAPTER_LEVEL_LABELS

#: Table name published for the reviewed label set and reasons.
MUTATIONS = ROWS

__all__ = ["LABELS", "MUTATIONS", "REASONS", "ROWS"]

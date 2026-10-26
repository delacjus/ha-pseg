"""A/B/C/D family replay proof (P2-11).

The R4 dirty-freeze bytes were not recovered in P1, so the required fallback is
four *independently detected* family faults rather than a claimed historical
replay. Each family reuses reviewed transformations from
:mod:`tests.mutations.auth_systemic` byte-for-byte (never copied by hand) and
maps them to a systemic assertion node that observes the public contract:

* A - per-hop / ChartData dispatch fence (I1);
* B - two-poll cookie poison, observed only through the shared follow-on (I3);
* C - invalid-200 / root validation (I10), with two transformations: the
  typed-root half (row 37) and the invalid-200-never-confirms half (row 36);
* D - latest exit checkpoint on the stop path (I5).

The table is standalone evidence: replay labels and detectors are separate from
the P2-10 catalog, and ``tests/test_replay_check.py`` proves every preimage and
replacement still equals its named source row, and that each declared reach maps
to an assertion literal the detector node really contains.
"""

from __future__ import annotations

from pathlib import Path
import runpy

_SOURCE = runpy.run_path(
    str(Path(__file__).with_name("auth_systemic.py")), run_name="__auth_systemic_source__"
)
_SOURCE_ROWS = {
    row[0]: row for row in (*_SOURCE["ORIGINAL_MUTATIONS"], *_SOURCE["NEW_MUTATIONS"])
}

FAMILIES = (
    {
        "family": "A",
        "title": "per-hop / ChartData dispatch fence",
        "source_row": "32-structural-session-send-owner-guard",
        "label": "replay-A-chartdata-dispatch-fence",
        "detector": (
            "tests/systemic/test_dispatch_fence.py"
            "::test_fast_dispatch_fence_representative[fast_stage_transition_handoff]"
        ),
    },
    {
        "family": "B",
        "title": "two-poll cookie poison",
        "source_row": "23-optional-hourly-jar-quarantine",
        "label": "replay-B-two-poll-cookie-poison",
        "detector": (
            "tests/systemic/test_response_corpus.py"
            "::test_post_proof_poison_is_caught_only_by_the_follow_on"
        ),
    },
    {
        "family": "C",
        "title": "invalid-200 / root validation (typed root)",
        "source_row": "37-hourly-root-dict-validation",
        "label": "replay-C-invalid-200-root-validation",
        "detector": (
            "tests/systemic/test_auth_systemic_catalog.py"
            "::test_focused_chart_response_contract[hourly-root]"
        ),
    },
    {
        "family": "C",
        "title": "invalid-200 / root validation (quarantined cookies)",
        "source_row": "36-hourly-records-validation-before-confirm",
        "label": "replay-C-invalid-200-quarantine",
        "detector": (
            "tests/systemic/test_auth_systemic_catalog.py"
            "::test_focused_chart_response_contract[hourly-empty]"
        ),
    },
    {
        "family": "D",
        "title": "latest exit checkpoint",
        "source_row": "15-confirmed-stop-handoff",
        "label": "replay-D-latest-exit-checkpoint",
        "detector": (
            "tests/systemic/test_exit_checkpoint.py"
            "::test_fast_exit_checkpoint_control"
            "[after:fetch_energy_data::stop::no-renewal::MM_RememberMe]"
        ),
    },
)


def _replay_row(family: dict[str, str]) -> dict[str, object]:
    """Project one named source row onto the family's systemic detector."""
    source = _SOURCE_ROWS[family["source_row"]]
    return {
        "label": family["label"],
        "filename": source[1],
        "before": source[2],
        "after": source[3],
        "test": [family["detector"]],
    }


MUTATIONS = tuple(_replay_row(family) for family in FAMILIES)

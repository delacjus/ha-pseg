"""Scoped v1.6.0 statistics baseline guard: comparison, approvals, fail-closed.

The tool under test parses sources with ``ast`` only, works from the manifest plus
an explicit source tree (no git, no imports of the inspected modules), and must
never turn an unreviewed change green or claim whole-file/module identity.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

from tools import stats_baseline

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "tests" / "fixtures" / "statistics_baseline_v1_6_0.json"
MODULE_PATH = "pkg/mod.py"

MODULE = (
    '"""Synthetic statistics module."""\n'
    "\n"
    "VALUE = 7\n"
    "\n"
    "\n"
    "def selected(value):\n"
    "    return value + 1\n"
    "\n"
    "\n"
    "def unselected(value):\n"
    "    return value - 1\n"
)


def write_source(tmp_path: Path, module: str = MODULE) -> Path:
    """Write a synthetic source tree with one module."""
    root = tmp_path / "source"
    (root / "pkg").mkdir(parents=True, exist_ok=True)
    (root / "pkg" / "mod.py").write_text(module, encoding="utf-8")
    return root


def manifest_for(
    source: Path,
    surfaces: list[dict[str, object]] | None = None,
    **extra: object,
) -> dict[str, object]:
    """Build a manifest whose baseline digests match ``source``."""
    if surfaces is None:
        surfaces = [
            {"group": "writer_state", "path": MODULE_PATH, "kind": "function", "name": "selected"},
            {"group": "writer_state", "path": MODULE_PATH, "kind": "assignment", "name": "VALUE"},
        ]
    rows = []
    for surface in surfaces:
        digest, detail = stats_baseline.extract_digest(
            source, str(surface["path"]), str(surface["kind"]), str(surface["name"])
        )
        assert detail == "ok", (surface, detail)
        file_digest = stats_baseline.file_digest(source, str(surface["path"]))
        rows.append(
            {
                "group": surface.get("group", "writer_state"),
                "path": surface["path"],
                "kind": surface["kind"],
                "name": surface["name"],
                "sha256": digest,
                "baseline_file_sha256": file_digest,
                "approved_deltas": surface.get("approved_deltas", []),
            }
        )
    document: dict[str, object] = {
        "schema": 1,
        "baseline": {"commit": "0" * 40, "tag": "synthetic"},
        "normalization": {"digest": "sha256", "line_endings": "LF"},
        "surfaces": rows,
    }
    document.update(extra)
    return document


def write_manifest(tmp_path: Path, document: dict[str, object]) -> Path:
    """Persist one manifest document."""
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def compare(tmp_path: Path, source: Path, **extra: object) -> tuple[int, dict]:
    """Run the tool against a freshly built manifest for ``source``."""
    manifest = write_manifest(tmp_path, manifest_for(source, **extra))
    return stats_baseline.run(manifest, source)


def test_normalization_is_exactly_the_declared_rules(tmp_path: Path) -> None:
    """Normalization: LF endings, rstripped lines, no edge blank lines only."""
    messy = "\r\n\r\ndef selected(value):   \r\n    return value + 1\t\r\n\r\n"
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text(messy, encoding="utf-8", newline="")
    expected_text = "def selected(value):\n    return value + 1"
    assert stats_baseline.normalize_segment(messy) == expected_text
    digest, detail = stats_baseline.extract_digest(tmp_path, MODULE_PATH, "function", "selected")
    assert detail == "ok"
    assert digest == hashlib.sha256(expected_text.encode("utf-8")).hexdigest()


def test_assignment_surfaces_digest_the_normalized_statement(tmp_path: Path) -> None:
    """A constant's normalized assignment text is digested, not its value."""
    module = "VALUE = 7\nOTHER = 1\n"
    source = write_source(tmp_path, module)
    digest, detail = stats_baseline.extract_digest(source, MODULE_PATH, "assignment", "VALUE")
    assert detail == "ok"
    assert digest == hashlib.sha256(b"VALUE = 7").hexdigest()
    assert stats_baseline.extract_digest(source, MODULE_PATH, "function", "VALUE")[1] == (
        "surface_kind_mismatch"
    )


def test_equal_scoped_report_claims_no_whole_file_identity(tmp_path: Path) -> None:
    """Every selected surface equal, exit 0, and the scope is explicitly narrow."""
    source = write_source(tmp_path)
    code, report = compare(tmp_path, source)

    assert code == 0
    assert report["ok"] is True
    assert report["scope"] == stats_baseline.SCOPE == "selected-surfaces-only"
    assert report["blanket_module_or_file_identity_claimed"] is False
    assert report["surfaces_total"] == 2
    assert {row["status"] for row in report["surfaces"]} == {"equal"}
    assert report["unreviewed"] == report["approved_expected_delta"] == 0
    (file_row,) = report["informational_file_digests"]
    assert file_row["path"] == MODULE_PATH
    assert file_row["file_identity_claimed"] is False
    assert file_row["file_digest_changed"] is False
    assert file_row["selected_surfaces_equal"] is True
    assert file_row["file_digest_is_informational_only"] is True


def test_unselected_change_is_informational_not_a_failure(tmp_path: Path) -> None:
    """Shared-file drift outside the selected surfaces: no failure, no equal claim."""
    source = write_source(tmp_path)
    document = manifest_for(source)
    manifest = write_manifest(tmp_path, document)

    changed = MODULE.replace("    return value - 1\n", "    return value - 2\n")
    (source / "pkg" / "mod.py").write_text(changed, encoding="utf-8")

    code, report = stats_baseline.run(manifest, source)
    assert code == 0
    assert {row["status"] for row in report["surfaces"]} == {"equal"}
    (file_row,) = report["informational_file_digests"]
    assert file_row["file_digest_changed"] is True
    assert file_row["selected_surfaces_equal"] is True
    assert file_row["file_identity_claimed"] is False
    assert report["blanket_module_or_file_identity_claimed"] is False
    assert report["unreviewed"] == 0


def test_selected_change_is_unreviewed_and_nonzero(tmp_path: Path) -> None:
    """A changed selected body fails the profile and names the surface."""
    source = write_source(tmp_path)
    manifest = write_manifest(tmp_path, manifest_for(source))

    (source / "pkg" / "mod.py").write_text(
        MODULE.replace("    return value + 1\n", "    return value + 2\n"), encoding="utf-8"
    )

    code, report = stats_baseline.run(manifest, source)
    assert code == 1
    assert report["ok"] is False
    (row,) = report["unreviewed_changes"]
    assert row["name"] == "selected"
    assert row["status"] == "unreviewed-change"
    assert row["observed_sha256"] != row["baseline_sha256"]
    assert "UNREVIEWED" in "\n".join(stats_baseline._summary(report))


@pytest.mark.parametrize(
    "changed",
    [
        pytest.param(MODULE.replace("    return value + 1\n", "    return 1\n"), id="body"),
        pytest.param(
            MODULE.replace(
                "def selected(value):\n",
                'def selected(value):\n    """Added docstring."""\n',
            ),
            id="docstring",
        ),
        pytest.param(MODULE.replace("    return value + 1", "    return value + 1 "), id="ws"),
    ],
)
def test_selected_drift_never_passes_silently(tmp_path: Path, changed: str) -> None:
    """Changing any normalized byte of the selected segment fails the profile."""
    source = write_source(tmp_path)
    manifest = write_manifest(tmp_path, manifest_for(source))
    (source / "pkg" / "mod.py").write_text(changed, encoding="utf-8")
    code, report = stats_baseline.run(manifest, source)
    if changed == MODULE.replace("    return value + 1", "    return value + 1 "):
        # Trailing whitespace is normalized away, so this control stays equal.
        assert code == 0
        assert report["equal"] == 2
        return
    assert code == 1
    assert [row["name"] for row in report["unreviewed_changes"]] == ["selected"]


def test_approved_expected_delta_requires_named_evidence_and_reviewer(
    tmp_path: Path,
) -> None:
    """A reviewed old->new approval is green; incomplete approvals stay unreviewed."""
    source = write_source(tmp_path)
    changed = MODULE.replace("    return value + 1\n", "    return value + 3\n")
    (source / "pkg" / "mod.py").write_text(changed, encoding="utf-8")
    new_digest, detail = stats_baseline.extract_digest(source, MODULE_PATH, "function", "selected")
    assert detail == "ok"

    base_module = write_source(tmp_path / "baseline", MODULE)
    base_surfaces = [
        {"group": "writer_state", "path": MODULE_PATH, "kind": "function", "name": "selected"},
        {"group": "writer_state", "path": MODULE_PATH, "kind": "assignment", "name": "VALUE"},
    ]
    baseline = manifest_for(base_module, base_surfaces)
    baseline_row = baseline["surfaces"][0]
    assert baseline_row["name"] == "selected"

    approval = {
        "old_sha256": baseline_row["sha256"],
        "new_sha256": new_digest,
        "evidence": "synthetic delta: returns value + 3",
        "reviewer": "synthetic reviewer",
    }

    def run_with(entry: dict[str, object]) -> tuple[int, dict]:
        document = manifest_for(base_module, base_surfaces)
        document["surfaces"][0]["approved_deltas"] = [entry]
        return stats_baseline.run(write_manifest(tmp_path, document), source)

    code, report = run_with(approval)
    assert code == 0
    assert report["ok"] is True
    assert report["approved_expected_delta"] == 1
    (row,) = report["approved_deltas"]
    assert row["status"] == "approved-expected-delta"
    assert row["approval"] == approval

    for incomplete in (
        {**approval, "reviewer": ""},
        {**approval, "evidence": "   "},
        {key: value for key, value in approval.items() if key != "reviewer"},
    ):
        code, report = run_with(incomplete)
        assert code == 1
        assert report["unreviewed"] == 1
        assert report["approved_expected_delta"] == 0

    wrong_old = {**approval, "old_sha256": "f" * 64}
    code, report = run_with(wrong_old)
    assert code == 1
    assert report["unreviewed"] == 1


def test_missing_and_ambiguous_surfaces_fail_closed(tmp_path: Path) -> None:
    """A vanished file, a vanished function and a duplicate name are unreviewed."""
    source = write_source(tmp_path)
    manifest = write_manifest(tmp_path, manifest_for(source))

    (source / "pkg" / "mod.py").write_text("VALUE = 7\n", encoding="utf-8")
    code, report = stats_baseline.run(manifest, source)
    assert code == 1
    details = {row["name"]: row["detail"] for row in report["unreviewed_changes"]}
    assert details["selected"] == "surface_missing"

    duplicate = "VALUE = 7\n\ndef selected(v):\n    return v\n\ndef selected(v):\n    return v\n"
    source = write_source(tmp_path / "dupe", duplicate)
    ambiguous = {
        "schema": 1,
        "surfaces": [
            {
                "group": "writer_state",
                "path": MODULE_PATH,
                "kind": "function",
                "name": "selected",
                "sha256": "0" * 64,
            }
        ],
    }
    manifest = write_manifest(tmp_path, ambiguous)
    code, report = stats_baseline.run(manifest, source)
    assert code == 1
    assert {row["detail"] for row in report["unreviewed_changes"]} == {"surface_ambiguous"}

    (source / "pkg" / "mod.py").unlink()
    code, report = stats_baseline.run(manifest, source)
    assert code == 1
    assert {row["detail"] for row in report["unreviewed_changes"]} == {"file_missing"}


@pytest.mark.parametrize(
    ("document", "error"),
    [
        (None, "manifest_missing"),
        ("{not json", "manifest_unparseable"),
        ({"schema": 99, "surfaces": []}, "manifest_schema_unsupported"),
        ({"schema": 1, "surfaces": []}, "manifest_invalid"),
        (
            {
                "schema": 1,
                "surfaces": [
                    {
                        "group": "g",
                        "path": "p.py",
                        "kind": "function",
                        "name": "f",
                        "sha256": "0" * 64,
                    },
                    {
                        "group": "g",
                        "path": "p.py",
                        "kind": "function",
                        "name": "f",
                        "sha256": "1" * 64,
                    },
                ],
            },
            "manifest_invalid",
        ),
    ],
)
def test_malformed_manifests_fail_closed(tmp_path: Path, document: object, error: str) -> None:
    """Manifest problems are nonzero with a fixed code, never a green run."""
    source = write_source(tmp_path)
    path = tmp_path / "manifest.json"
    if document is not None:
        path.write_text(
            document if isinstance(document, str) else json.dumps(document),
            encoding="utf-8",
        )
    code, report = stats_baseline.run(path, source)
    assert code == 1
    assert report["ok"] is False
    assert report["error"] == error


def test_runtime_needs_no_git_and_never_imports_the_inspected_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Parsing only: no git, no subprocess, no execution of the inspected module."""
    poison = (
        '"""Poison: executing this module would leave a marker and exit."""\n'
        "from pathlib import Path\n"
        'Path("EXECUTED").write_text("yes")\n'
        "raise SystemExit(3)\n"
        "\n"
        "\n"
        "def selected(value):\n"
        "    return value + 1\n"
    )
    source = write_source(tmp_path)
    (source / "pkg" / "poison.py").write_text(poison, encoding="utf-8")
    manifest = write_manifest(
        tmp_path,
        manifest_for(
            source,
            [
                {
                    "group": "writer_state",
                    "path": MODULE_PATH,
                    "kind": "function",
                    "name": "selected",
                },
                {
                    "group": "writer_state",
                    "path": "pkg/poison.py",
                    "kind": "function",
                    "name": "selected",
                },
            ],
        ),
    )
    assert not (source / ".git").exists()

    def no_subprocess(*args: object, **kwargs: object) -> None:
        raise AssertionError("stats_baseline must not spawn processes")

    monkeypatch.setattr("subprocess.run", no_subprocess, raising=False)
    monkeypatch.setattr("subprocess.Popen", no_subprocess, raising=False)
    assert not hasattr(stats_baseline, "subprocess")

    code, report = stats_baseline.run(manifest, source)
    assert code == 0
    assert report["surfaces_total"] == 2
    assert report["equal"] == 2
    assert not (source / "EXECUTED").exists()
    assert "poison" not in sys.modules


def test_checked_in_manifest_pins_v1_6_0_provenance_and_separates_parser() -> None:
    """The reviewed manifest states its commit, normalization and approvals."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest["schema"] == stats_baseline.MANIFEST_SCHEMA == 1
    assert manifest["baseline"]["commit"] == "00ba6b33bdf73e3d9524ae3b3307aa44c007f9eb"
    assert manifest["baseline"]["tag"] == "v1.6.0"
    assert "00ba6b3" in manifest["baseline"]["extraction_command"]
    for key in (
        "encoding",
        "segment",
        "line_endings",
        "trailing_whitespace",
        "edges",
        "digest",
        "assignment_surfaces",
        "method_surfaces",
        "scope",
    ):
        assert manifest["normalization"][key]
    assert "ast.get_source_segment" in manifest["normalization"]["segment"]
    assert "declared surfaces only" in manifest["normalization"]["scope"]

    surfaces = manifest["surfaces"]
    assert len(surfaces) == 20
    groups = {surface["group"] for surface in surfaces}
    assert groups == {"writer_state", "parser_v1_6_0"}
    paths = {surface["path"] for surface in surfaces}
    assert paths == {
        "custom_components/pseg/statistics_state.py",
        "custom_components/pseg/coordinator.py",
        "custom_components/pseg/statistics_hourly.py",
        "custom_components/pseg/pseg_client.py",
    }
    for surface in surfaces:
        assert len(surface["sha256"]) == 64
        int(surface["sha256"], 16)
        assert surface["extraction"]["commit"] == manifest["baseline"]["commit"]
        assert surface["extraction"]["sha256"] == surface["sha256"]
        assert surface["extraction"]["function"] == surface["name"]
        assert surface["extraction"]["source"].startswith("git show 00ba6b33")

    writer = [surface for surface in surfaces if surface["group"] == "writer_state"]
    parser = [surface for surface in surfaces if surface["group"] == "parser_v1_6_0"]
    assert writer and parser
    # The known v1.6.0 parser change stays with the parser surfaces only.
    assert all("v1_6_0_change" not in surface for surface in writer)
    assert all(surface["approved_deltas"] == [] for surface in writer)
    changes = {
        surface["name"]: surface["v1_6_0_change"]
        for surface in parser
        if "v1_6_0_change" in surface
    }
    assert set(changes) == {
        "STATISTICS_INCOMPLETE_REASONS",
        "ny_wall_ms_to_utc",
        "parse_date_only_label",
        "HOURLY_X_CONTRACT",
        "PsegClient._parse_hourly_chart",
    }
    assert {entry["change"] for entry in changes.values()} == {"modified", "added"}
    for entry in changes.values():
        assert entry["new_sha256"]
        assert entry["evidence"] and entry["reviewer"]
        if entry["change"] == "added":
            assert entry["old_sha256"] is None
        else:
            assert len(entry["old_sha256"]) == 64
            assert entry["old_sha256"] != entry["new_sha256"]


def test_repo_at_head_is_equal_to_the_reviewed_baseline() -> None:
    """The live tree (v1.6.0 onward) has no unreviewed drift and no false claim."""
    code, report = stats_baseline.run(MANIFEST_PATH, REPO_ROOT)
    assert code == 0, report["unreviewed_changes"]
    assert report["surfaces_total"] == 20
    assert report["equal"] == 20
    assert report["unreviewed"] == 0
    assert report["approved_expected_delta"] == 0
    assert len(report["known_v1_6_0_parser_changes"]) == 5
    assert report["blanket_module_or_file_identity_claimed"] is False


def test_cli_prints_structured_report_and_scoped_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """exit code plus machine report on stdout and a scoped summary on stderr."""
    source = write_source(tmp_path)
    manifest = write_manifest(tmp_path, manifest_for(source))
    (source / "pkg" / "mod.py").write_text(
        MODULE.replace("    return value + 1\n", "    return value + 9\n"), encoding="utf-8"
    )
    code = stats_baseline.main(["--manifest", str(manifest), "--source", str(source)])
    captured = capsys.readouterr()
    assert code == 1
    report = json.loads(captured.out)
    assert report["scope"] == "selected-surfaces-only"
    assert report["unreviewed"] == 1
    summary = captured.err
    assert "selected surfaces" in summary
    assert "UNREVIEWED" in summary
    assert "pkg/mod.py::selected" in summary

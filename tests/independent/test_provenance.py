"""Tests for probe capture, archive integrity, and provenance verification."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any

import pytest

from tools.probe_provenance import (
    capture,
    compute_file_sha256,
    main,
    verify,
)

INDEPENDENT_ROOT = Path(__file__).parent
ARCHIVE_DIR = INDEPENDENT_ROOT / "archive"
SPEC_FILE = INDEPENDENT_ROOT / "probe_sources.json"


def test_all_24_probe_sources_inventory_represented() -> None:
    """Verify that all 24 inventory probe files are listed in probe_sources.json."""
    assert SPEC_FILE.is_file(), f"Specification file missing: {SPEC_FILE}"
    spec = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
    sources = spec.get("sources", [])
    assert len(sources) == 24, f"Expected 24 probe sources in spec, found {len(sources)}"

    manifest_path = ARCHIVE_DIR / "manifest.json"
    assert manifest_path.is_file(), f"Manifest missing: {manifest_path}"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files", [])
    assert len(files) == 24, f"Expected 24 archived files in manifest, found {len(files)}"


def test_archived_files_match_spec_sha256() -> None:
    """Verify that all archived files on disk match their declared SHA-256."""
    manifest_path = ARCHIVE_DIR / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest.get("files", []):
        rel = entry["relative_path"]
        arch_file = ARCHIVE_DIR / rel
        assert arch_file.is_file(), f"Archived file missing: {arch_file}"
        digest = compute_file_sha256(arch_file)
        assert digest == entry["sha256"], f"Digest mismatch for {rel}"


def test_no_archived_files_are_collectable() -> None:
    """Verify no archived file can be collected by pytest as a Python test."""
    for item in ARCHIVE_DIR.rglob("*"):
        if item.is_file() and item.name != "manifest.json":
            assert item.name.endswith(".txt"), f"Archived file does not end in .txt: {item}"
            assert not (item.name.startswith("test_") and item.name.endswith(".py")), (
                f"Archived file has active pytest naming: {item}"
            )


def test_verify_passes_on_worktree() -> None:
    """Verify that verify() passes cleanly on the worktree root."""
    is_valid, messages = verify(INDEPENDENT_ROOT)
    assert is_valid is True, f"Verification failed with: {messages}"
    assert len(messages) > 0
    assert "Provenance verification PASSED" in messages[0]


def test_verify_fails_on_altered_archived_byte(tmp_path: Path) -> None:
    """Negative proof: altering one byte in an archived file fails verification."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    target = temp_root / "archive" / "auth_r1" / "test_adversarial.py.txt"
    data = bytearray(target.read_bytes())
    data[0] = data[0] ^ 0xFF
    target.write_bytes(bytes(data))

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("SHA-256 mismatch" in err and "test_adversarial.py.txt" in err for err in errors)


def test_verify_fails_on_missing_archived_file(tmp_path: Path) -> None:
    """Negative proof: deleting a registered archived file fails verification."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    target = temp_root / "archive" / "hourly_r5" / "test_r5.py.txt"
    target.unlink()

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("Archived file missing on disk" in err and "test_r5.py.txt" in err for err in errors)


def test_verify_fails_on_unregistered_collected_test(tmp_path: Path) -> None:
    """Negative proof: adding an unmanifested test_*.py fails verification."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    rogue_test = temp_root / "auth_r1" / "test_rogue_unregistered.py"
    rogue_test.write_text("def test_rogue(): pass\n", encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any(
        "Unregistered test file detected" in err and "test_rogue_unregistered.py" in err
        for err in errors
    )


def test_verify_fails_on_active_fixture_hash_mismatch(tmp_path: Path) -> None:
    """Negative proof: active promoted file hash mismatch fails verification."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    _, prov_file, meta = _make_valid_group(temp_root, "auth_r1")
    meta["promoted_files"][0]["sha256"] = "0" * 64
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("Promoted file hash mismatch" in err for err in errors)


def test_capture_with_synthetic_sources_idempotence_and_refusal(tmp_path: Path) -> None:
    """Verify capture() succeeds idempotently on synthetic sources but refuses on differing bytes."""
    src_dir = tmp_path / "sources"
    src_dir.mkdir()
    probe_src = src_dir / "probe1.py"
    probe_bytes = b"def test_synthetic(): pass\n"
    probe_src.write_bytes(probe_bytes)
    probe_sha = hashlib.sha256(probe_bytes).hexdigest()

    conftest_src = src_dir / "conftest.py"
    conftest_bytes = b"# synthetic conftest\n"
    conftest_src.write_bytes(conftest_bytes)

    synthetic_spec = tmp_path / "synthetic_sources.json"
    synthetic_spec.write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "sources": [
                    {
                        "group": "synth_group",
                        "archive_relpath": "synth_group/probe1.py.txt",
                        "original_path": str(probe_src),
                        "expected_sha256_prefix": probe_sha[:8],
                        "historical_cases": 1,
                        "status": "inert",
                        "role": "probe",
                        "collect": False,
                        "reviewer_kb": "0ce46ae2-76f1-4f59-8b73-e744c48e3f62",
                        "description": "Synthetic test probe",
                    },
                    {
                        "group": "synth_group",
                        "archive_relpath": "synth_group/conftest.py.txt",
                        "original_path": str(conftest_src),
                        "expected_sha256_prefix": None,
                        "historical_cases": 0,
                        "status": "inert",
                        "role": "conftest",
                        "collect": False,
                        "reviewer_kb": "0ce46ae2-76f1-4f59-8b73-e744c48e3f62",
                        "description": "Synthetic conftest",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    dest = tmp_path / "archive_dest"
    manifest1 = capture(synthetic_spec, dest)
    assert manifest1["file_count"] == 2

    # Idempotent re-run
    manifest2 = capture(synthetic_spec, dest)
    assert manifest2["aggregate_sha256"] == manifest1["aggregate_sha256"]

    # Tamper with one file
    tampered_file = dest / "synth_group" / "probe1.py.txt"
    tampered_bytes = b"tampered differing bytes\n"
    tampered_file.write_bytes(tampered_bytes)

    # Re-run must fail with RuntimeError and leave the file byte-identical
    with pytest.raises(
        RuntimeError, match="Destination file already exists with differing content"
    ):
        capture(synthetic_spec, dest)

    assert tampered_file.read_bytes() == tampered_bytes


def test_verify_independent_of_original_paths(tmp_path: Path) -> None:
    """Prove verification succeeds when original paths in spec do not exist."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)

    # Modify probe_sources.json to point to nonexistent paths
    spec_path = temp_root / "probe_sources.json"
    spec_data = json.loads(spec_path.read_text(encoding="utf-8"))
    for item in spec_data.get("sources", []):
        filename = Path(item["original_path"]).name
        item["original_path"] = f"/nonexistent/probe/path/{filename}"
    spec_path.write_text(json.dumps(spec_data, indent=2), encoding="utf-8")

    is_valid, messages = verify(temp_root)
    assert is_valid is True, f"Verification failed with: {messages}"
    assert len(messages) > 0
    assert "Provenance verification PASSED" in messages[0]


def _make_valid_group(
    temp_root: Path, group_name: str = "auth_r1"
) -> tuple[Path, Path, dict[str, Any]]:
    """Create a valid promoted group with provenance.json for testing.

    The copied tree may already hold this group's real promoted suite (P1-05+);
    start from an empty group directory so the synthetic metadata is complete.
    """
    grp = temp_root / group_name
    if grp.exists():
        shutil.rmtree(grp)
    grp.mkdir(parents=True)
    promoted_file = grp / "test_promoted.py"
    promoted_file.write_text("def test_ok(): pass\n", encoding="utf-8")
    promoted_hash = compute_file_sha256(promoted_file)

    init_file = grp / "__init__.py"
    if not init_file.exists():
        init_file.write_text("", encoding="utf-8")
    init_hash = compute_file_sha256(init_file)

    arch_file1 = temp_root / "archive" / group_name / "test_adversarial.py.txt"
    arch_hash1 = compute_file_sha256(arch_file1)
    arch_file2 = temp_root / "archive" / group_name / "conftest.py.txt"
    arch_hash2 = compute_file_sha256(arch_file2)

    meta = {
        "group": group_name,
        "status": "active",
        "reviewer_kb": "0ce46ae2-76f1-4f59-8b73-e744c48e3f62",
        "expected_collection": 1,
        "transformation_rationale": ["Synthetic adaptation of test probes"],
        "sources": [
            {
                "original_path": "/tmp/pseg-auth-review-r1/test_adversarial.py",
                "original_sha256": arch_hash1,
                "archived_path": f"{group_name}/test_adversarial.py.txt",
                "archived_sha256": arch_hash1,
                "role": "probe",
                "collect": False,
            },
            {
                "original_path": "/tmp/pseg-auth-review-r1/conftest.py",
                "original_sha256": arch_hash2,
                "archived_path": f"{group_name}/conftest.py.txt",
                "archived_sha256": arch_hash2,
                "role": "conftest",
                "collect": False,
            },
        ],
        "promoted_files": [
            {
                "relative_path": "test_promoted.py",
                "sha256": promoted_hash,
            },
            {
                "relative_path": "__init__.py",
                "sha256": init_hash,
            },
        ],
    }
    prov_file = grp / "provenance.json"
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return grp, prov_file, meta


@pytest.mark.parametrize(
    ("mutator", "expected_error_substr"),
    [
        (lambda m: m.pop("sources"), "Missing required field 'sources'"),
        (lambda m: m.update({"sources": []}), "must be a non-empty list"),
        (lambda m: m["sources"][0].pop("original_path"), "Missing required field 'original_path'"),
        (
            lambda m: m["sources"][0].update({"original_path": "relative/path/test.py"}),
            "must be an absolute path",
        ),
        (
            lambda m: m["sources"][0].pop("original_sha256"),
            "Missing required field 'original_sha256'",
        ),
        (
            lambda m: m["sources"][0].update({"original_sha256": "invalid_hex"}),
            "must be a 64-character hex SHA-256",
        ),
        (lambda m: m["sources"][0].pop("archived_path"), "Missing required field 'archived_path'"),
        (
            lambda m: m["sources"][0].pop("archived_sha256"),
            "Missing required field 'archived_sha256'",
        ),
        (
            lambda m: m["sources"][0].update({"archived_sha256": "bad_hex"}),
            "must be a 64-character hex SHA-256",
        ),
        (lambda m: m.pop("reviewer_kb"), "Missing required field 'reviewer_kb'"),
        (lambda m: m.update({"reviewer_kb": "   "}), "must be a non-empty string"),
        (
            lambda m: m.pop("expected_collection"),
            "Missing required field 'expected_collection'",
        ),
        (lambda m: m.update({"expected_collection": -1}), "must be >= 0"),
        (
            lambda m: m.update({"expected_collection": "invalid_str"}),
            "must be an integer count or 'not-collected'",
        ),
        (lambda m: m.pop("status"), "Missing required field 'status'"),
        (lambda m: m.update({"status": "unknown"}), "must be 'inert' or 'active'"),
        (
            lambda m: m.pop("transformation_rationale"),
            "Missing required field 'transformation_rationale'",
        ),
        (lambda m: m.update({"transformation_rationale": ""}), "cannot be empty"),
        (lambda m: m.update({"group": "wrong_group"}), "Group mismatch"),
        (lambda m: m["promoted_files"][0].pop("sha256"), "missing required 'sha256'"),
        (
            lambda m: m["promoted_files"][0].update({"sha256": "bad"}),
            "must be a 64-character hex SHA-256",
        ),
        (
            lambda m: m["promoted_files"][0].update({"sha256": "f" * 64}),
            "Promoted file hash mismatch",
        ),
        (
            lambda m: m["promoted_files"][0].update({"relative_path": "nonexistent.py"}),
            "Promoted file missing",
        ),
    ],
)
def test_verify_fails_on_missing_or_malformed_metadata(
    tmp_path: Path,
    mutator: Callable[[dict[str, Any]], None],
    expected_error_substr: str,
) -> None:
    """Negative proof: missing or malformed required provenance fields fail verification."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    _, prov_file, meta = _make_valid_group(temp_root)
    mutator(meta)
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any(expected_error_substr in err for err in errors), (
        f"Expected '{expected_error_substr}' in {errors}"
    )


def test_verify_fails_on_forged_original_hash(tmp_path: Path) -> None:
    """Negative proof: forged original_sha256 differing from archive/manifest fails."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    _, prov_file, meta = _make_valid_group(temp_root)
    meta["sources"][0]["original_sha256"] = "0" * 64
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("Original SHA-256 does not match" in err for err in errors)


def test_verify_fails_on_forged_original_path(tmp_path: Path) -> None:
    """Negative proof: forged original_path differing from manifest records fails."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    _, prov_file, meta = _make_valid_group(temp_root)
    meta["sources"][0]["original_path"] = "/forged/unrelated.py"
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("Original path mismatch" in err for err in errors)


def test_verify_fails_on_nonexistent_archive_in_tuple(tmp_path: Path) -> None:
    """Negative proof: source tuple pointing to nonexistent archive file fails."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    _, prov_file, meta = _make_valid_group(temp_root)
    meta["sources"][0]["archived_path"] = "auth_r1/nonexistent.py.txt"
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("missing on disk" in err for err in errors)


def test_verify_fails_on_uncovered_archive_file(tmp_path: Path) -> None:
    """Negative proof: archive file under archive/<group>/ omitted from source tuples fails."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    _, prov_file, meta = _make_valid_group(temp_root)
    # Remove second tuple (conftest.py.txt)
    meta["sources"].pop(1)
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("not covered by source tuples" in err and "conftest.py.txt" in err for err in errors)


def test_verify_fails_on_duplicated_source_tuple(tmp_path: Path) -> None:
    """Negative proof: multiple source tuples referencing the same archive file fails."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    _, prov_file, meta = _make_valid_group(temp_root)
    # Duplicate the first tuple
    meta["sources"].append(dict(meta["sources"][0]))
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("Duplicated source tuple" in err for err in errors)


def test_verify_fails_on_unlisted_helper_in_active_group(tmp_path: Path) -> None:
    """Negative proof: unlisted helper.py in active group directory fails verification."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    grp, _, _ = _make_valid_group(temp_root)

    helper_file = grp / "helper.py"
    helper_file.write_text("HELPER_VAR = 1\n", encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("Unlisted python file(s)" in err and "helper.py" in err for err in errors)


def test_verify_fails_on_changed_conftest_with_omitted_hash(tmp_path: Path) -> None:
    """Negative proof: changed conftest.py whose sha256 is omitted from metadata fails."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    grp, prov_file, meta = _make_valid_group(temp_root)

    conftest_file = grp / "conftest.py"
    conftest_file.write_text("# altered conftest\n", encoding="utf-8")

    # List conftest.py in promoted_files without sha256
    meta["promoted_files"].append({"relative_path": "conftest.py"})
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("missing required 'sha256'" in err and "conftest.py" in err for err in errors)


def test_verify_fails_on_inert_group_with_collectable_test(tmp_path: Path) -> None:
    """Negative proof: inert group containing a collectable test_*.py fails verification."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    grp, prov_file, meta = _make_valid_group(temp_root)

    # Set status to inert
    meta["status"] = "inert"
    meta["expected_collection"] = "not-collected"
    meta.pop("transformation_rationale", None)
    meta.pop("promoted_files", None)
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # grp contains test_promoted.py
    is_valid, errors = verify(temp_root)
    assert is_valid is False
    assert any("contains collectable test file" in err for err in errors)


def test_verify_inert_status_without_collectable_test_passes(tmp_path: Path) -> None:
    """Verify inert status passes when no collectable tests are in group directory."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    grp, prov_file, meta = _make_valid_group(temp_root)
    (grp / "test_promoted.py").unlink()

    meta["status"] = "inert"
    meta["expected_collection"] = "not-collected"
    meta.pop("transformation_rationale", None)
    meta.pop("promoted_files", None)
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, messages = verify(temp_root)
    assert is_valid is True, f"Verification failed with: {messages}"


def test_verify_active_group_allowlist_reasoned_exemption(tmp_path: Path) -> None:
    """Verify active group passes with explicit reasoned allowlist for package initializer."""
    temp_root = tmp_path / "independent"
    shutil.copytree(INDEPENDENT_ROOT, temp_root)
    _, prov_file, meta = _make_valid_group(temp_root)

    # Remove __init__.py from promoted_files and add to allowlist with reason
    meta["promoted_files"] = [
        pf for pf in meta["promoted_files"] if pf["relative_path"] != "__init__.py"
    ]
    meta["allowlist"] = [
        {"path": "__init__.py", "reason": "empty shared package initializer"}
    ]
    prov_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    is_valid, messages = verify(temp_root)
    assert is_valid is True, f"Verification failed with: {messages}"


def test_capture_differing_file_left_byte_identical_and_command_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify differing file is left byte-identical and capture command exits nonzero."""
    src_dir = tmp_path / "sources"
    src_dir.mkdir()
    probe_src = src_dir / "probe.py"
    probe_bytes = b"original probe content\n"
    probe_src.write_bytes(probe_bytes)

    spec_path = tmp_path / "spec.json"
    spec_path.write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "sources": [
                    {
                        "group": "grp",
                        "archive_relpath": "grp/probe.py.txt",
                        "original_path": str(probe_src),
                        "expected_sha256_prefix": hashlib.sha256(probe_bytes).hexdigest()[:8],
                        "historical_cases": 1,
                        "status": "inert",
                        "role": "probe",
                        "collect": False,
                        "reviewer_kb": "00000000-0000-0000-0000-000000000000",
                        "description": "Probe",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    dest_dir = tmp_path / "archive"
    dest_dir.mkdir()
    dest_file = dest_dir / "grp" / "probe.py.txt"
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    differing_bytes = b"pre-existing differing evidence\n"
    dest_file.write_bytes(differing_bytes)

    # Call main() via CLI argument simulation
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "probe_provenance.py",
            "capture",
            "--spec",
            str(spec_path),
            "--dest",
            str(dest_dir),
        ],
    )
    exit_code = main()
    assert exit_code != 0
    # Destination file must be left byte-identical
    assert dest_file.read_bytes() == differing_bytes
    captured_err = capsys.readouterr().err
    assert "Destination file already exists with differing content" in captured_err

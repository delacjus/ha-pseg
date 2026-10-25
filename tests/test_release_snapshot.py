"""Tests for the safe snapshot and freeze substrate (P1-01)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from tools._snapshot import (
    MANIFEST_NAME,
    CleanupRefused,
    SnapshotError,
    compute_digest,
    freeze,
    load_manifest,
    snapshot,
)
from tools.release_check import main as cli_main


def _run_git(repo: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip()


def _init_git_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    _run_git(path, "init", "-b", "main")
    _run_git(path, "config", "user.name", "Test Runner")
    _run_git(path, "config", "user.email", "test@example.com")
    # Commit an initial file
    (path / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    _run_git(path, "add", "pyproject.toml")
    _run_git(path, "commit", "-m", "initial commit")
    return _run_git(path, "rev-parse", "HEAD")


# --------------------------------------------------------------------------- Golden Digest


def test_golden_digest_literal() -> None:
    """Small NUL-delimited golden input produces literal independently calculated expected digest."""
    # Golden 1: single file
    files_single = {"a.txt": b"hello\n"}
    # b"a.txt\x00hello\n\x00"
    digest_single = compute_digest(files_single)
    expected_single = hashlib.sha256(b"a.txt\x00hello\n\x00").hexdigest()
    assert expected_single == "ee6dd56c81a8a8eda8f6695867dd7615f814f64145d8464773885fd6872bca8a"
    assert digest_single == expected_single

    # Golden 2: multiple files with directory components
    files_multi = {
        "a.txt": b"hello\n",
        "sub/b.txt": b"world\n",
    }
    # Sorted order: "a.txt", "sub/b.txt"
    # b"a.txt\x00hello\n\x00sub/b.txt\x00world\n\x00"
    digest_multi = compute_digest(files_multi)
    expected_multi = hashlib.sha256(b"a.txt\x00hello\n\x00sub/b.txt\x00world\n\x00").hexdigest()
    assert expected_multi == "e180a05e2ccd32e376a72b5b6ea5b7cf76eed63d5f8b985d5095d36dc2e28c82"
    assert digest_multi == expected_multi


# --------------------------------------------------------------------------- Freeze & Snapshot


def test_freeze_deterministic(tmp_path: Path) -> None:
    """Running freeze twice on an unchanged worktree produces identical manifest."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_example.py").write_text("def test_one(): pass\n", encoding="utf-8")
    _run_git(repo, "add", "tests/test_example.py")
    _run_git(repo, "commit", "-m", "add test")

    m1 = freeze(repo)
    m2 = freeze(repo)

    assert m1["head"] == m2["head"]
    assert m1["sha256"] == m2["sha256"]
    assert m1["count"] == m2["count"] == 2
    assert m1["paths"] == m2["paths"]


def test_snapshot_clean_copy_and_independence(tmp_path: Path) -> None:
    """snapshot creates clean copy, no .git/.venv, and modifying copy does not alter source."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "tests").mkdir()
    test_file = repo / "tests" / "test_foo.py"
    test_content = b"def test_foo(): assert True\n"
    test_file.write_bytes(test_content)
    _run_git(repo, "add", "tests/test_foo.py")
    _run_git(repo, "commit", "-m", "add test")
    expected_head = _run_git(repo, "rev-parse", "HEAD")

    dest = tmp_path / "copy_dest"
    res = snapshot(source=repo, dest=dest)

    assert res["count"] == 2
    assert res["head"] == expected_head
    assert (dest / MANIFEST_NAME).is_file()
    assert not (dest / ".git").exists()
    assert not (dest / ".venv").exists()
    assert (dest / "tests" / "test_foo.py").read_bytes() == test_content

    # Modifying one copied byte does not alter source and changes copy hash
    (dest / "tests" / "test_foo.py").write_bytes(b"def test_foo(): assert False\n")
    assert test_file.read_bytes() == test_content

    # Manifest verification of modified copy fails
    with pytest.raises(SnapshotError) as exc_info:
        freeze(dest)
    assert exc_info.value.code == "file_hash_mismatch"


def test_snapshot_from_manifest_copy(tmp_path: Path) -> None:
    """snapshot supports validated snapshot-manifest inputs without git."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_a.py").write_text("pass\n", encoding="utf-8")
    _run_git(repo, "add", "tests/test_a.py")
    _run_git(repo, "commit", "-m", "add a")

    first_copy = tmp_path / "snapshot_1"
    res1 = snapshot(source=repo, dest=first_copy)
    assert not (first_copy / ".git").exists()

    manifest_data = load_manifest(first_copy / MANIFEST_NAME)
    assert manifest_data["aggregate"] == res1["sha256"]

    # Create second copy from first copy (git-free)
    second_copy = tmp_path / "snapshot_2"
    res2 = snapshot(source=first_copy, dest=second_copy)

    assert res2["head"] == res1["head"]
    assert res2["sha256"] == res1["sha256"]
    assert res2["count"] == res1["count"]
    assert (second_copy / "tests" / "test_a.py").read_text(encoding="utf-8") == "pass\n"


def test_manifest_bad_aggregate_rejected(tmp_path: Path) -> None:
    """A manifest whose aggregate is invalid/mismatched (e.g. 64 zeros) is refused."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    snap_dest = tmp_path / "snap"
    snapshot(source=repo, dest=snap_dest)

    manifest_path = snap_dest / MANIFEST_NAME
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    doc["sha256"] = "0" * 64
    doc["aggregate_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    with pytest.raises(SnapshotError) as exc_info:
        freeze(source=snap_dest)
    assert exc_info.value.code == "manifest_aggregate_mismatch"

    copy_dest = tmp_path / "copy_from_bad"
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=snap_dest, dest=copy_dest)
    assert exc_info.value.code == "manifest_aggregate_mismatch"
    assert not copy_dest.exists()


def test_manifest_exclusions_rejected(tmp_path: Path) -> None:
    """A manifest naming excluded paths (.env, .venv/x, logs/x.log, *.jar, captures, __pycache__) is refused."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    snap_dest = tmp_path / "snap_creds"
    snapshot(source=repo, dest=snap_dest)

    for bad_path in (
        ".env",
        ".venv/test.txt",
        "logs/run.log",
        "app.jar",
        "traffic.pcap",
        "__pycache__/bad.pyc",
    ):
        target = snap_dest / bad_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"data\n")

        manifest_path = snap_dest / MANIFEST_NAME
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        doc["paths"].append({"path": bad_path, "sha256": "a" * 64})
        doc["count"] = len(doc["paths"])
        manifest_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")

        with pytest.raises(SnapshotError) as exc_info:
            snapshot(source=snap_dest, dest=tmp_path / f"out_{bad_path.replace('/', '_')}")
        assert exc_info.value.code == "excluded_path_in_manifest"



# --------------------------------------------------------------------------- Exclusions & Untracked


def test_exclusions_applied(tmp_path: Path) -> None:
    """Excluded dirs/files (.git, .venv, caches, captures, storage, logs, creds) are excluded."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    # Create excluded directories and files
    (repo / ".venv").mkdir()
    (repo / ".venv" / "pyvenv.cfg").write_text("home = /bin\n", encoding="utf-8")

    (repo / "tests").mkdir()
    (repo / "tests" / "__pycache__").mkdir()
    (repo / "tests" / "__pycache__" / "test_foo.cpython-314.pyc").write_bytes(b"bytecode")
    (repo / "tests" / "test_real.py").write_text("def test_real(): pass\n", encoding="utf-8")

    (repo / ".pytest_cache").mkdir()
    (repo / ".pytest_cache" / "v").write_text("cache", encoding="utf-8")

    (repo / "logs").mkdir()
    (repo / "logs" / "run.log").write_text("log output", encoding="utf-8")
    (repo / "app.log").write_text("log file", encoding="utf-8")

    (repo / ".env").write_text("SECRET_KEY=123", encoding="utf-8")
    (repo / "id_ed25519").write_text("PRIVATE KEY", encoding="utf-8")
    (repo / "capture.har").write_text("capture data", encoding="utf-8")
    (repo / "local_storage.db").write_bytes(b"sqlite data")
    (repo / "bundle.jar").write_bytes(b"PK\x03\x04")

    _run_git(repo, "add", "tests/test_real.py")
    _run_git(repo, "commit", "-m", "add test_real")

    dest = tmp_path / "copy_clean"
    res = snapshot(source=repo, dest=dest)

    copied_paths = {p["path"] for p in res["paths"]}
    assert "pyproject.toml" in copied_paths
    assert "tests/test_real.py" in copied_paths

    # Verify nothing excluded made it into snapshot
    assert not (dest / ".git").exists()
    assert not (dest / ".venv").exists()
    assert not (dest / "tests" / "__pycache__").exists()
    assert not (dest / ".pytest_cache").exists()
    assert not (dest / "logs").exists()
    assert not (dest / "app.log").exists()
    assert not (dest / ".env").exists()
    assert not (dest / "id_ed25519").exists()
    assert not (dest / "capture.har").exists()
    assert not (dest / "local_storage.db").exists()
    assert not (dest / "bundle.jar").exists()


def test_reject_arbitrary_untracked_input(tmp_path: Path) -> None:
    """Arbitrary untracked files with unallowed suffixes listed in --paths-from are rejected."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    (repo / "arbitrary.bin").write_bytes(b"binary data")
    paths_file = tmp_path / "paths.txt"
    paths_file.write_text("arbitrary.bin\n", encoding="utf-8")

    with pytest.raises(SnapshotError) as exc_info:
        freeze(repo, paths_from=paths_file)
    assert exc_info.value.code == "arbitrary_file_rejected"

    dest = tmp_path / "dest_failed"
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest, paths_from=paths_file)
    assert exc_info.value.code == "arbitrary_file_rejected"
    assert not dest.exists()


def test_allow_reviewed_untracked_suite_input(tmp_path: Path) -> None:
    """Reviewed new suite paths are included when explicitly listed in --paths-from, preserving baseline."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    (repo / "tools").mkdir()
    (repo / "tools" / "release_check.py").write_text("# tool\n", encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_snapshot.py").write_text("# test\n", encoding="utf-8")
    (repo / "requirements_test.txt").write_text("pytest\n", encoding="utf-8")

    paths_file = tmp_path / "suite_paths.txt"
    paths_file.write_text(
        "tools/release_check.py\ntests/test_snapshot.py\nrequirements_test.txt\n",
        encoding="utf-8",
    )

    manifest = freeze(repo, paths_from=paths_file)
    paths = {p["path"] for p in manifest["paths"]}
    assert "tools/release_check.py" in paths
    assert "tests/test_snapshot.py" in paths
    assert "requirements_test.txt" in paths
    assert "pyproject.toml" in paths


def test_untracked_file_not_auto_included(tmp_path: Path) -> None:
    """Untracked files are NOT auto-included in freeze or snapshot without --paths-from."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    (repo / "tests").mkdir()
    (repo / "tests" / "unreviewed.py").write_text("# untracked\n", encoding="utf-8")

    manifest = freeze(repo)
    paths = {p["path"] for p in manifest["paths"]}
    assert "pyproject.toml" in paths
    assert "tests/unreviewed.py" not in paths

    dest = tmp_path / "copy_clean"
    res = snapshot(source=repo, dest=dest)
    copied = {p["path"] for p in res["paths"]}
    assert "pyproject.toml" in copied
    assert "tests/unreviewed.py" not in copied
    assert not (dest / "tests" / "unreviewed.py").exists()


def test_paths_from_p1_04_shape(tmp_path: Path) -> None:
    """A tree shaped like P1-04 (tests/independent/archive/x/y.py.txt plus manifest.json) works via --paths-from."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    archive_dir = repo / "tests" / "independent" / "archive" / "x"
    archive_dir.mkdir(parents=True)
    archive_file = archive_dir / "y.py.txt"
    archive_file.write_text("# archived python test\n", encoding="utf-8")

    manifest_file = repo / "manifest.json"
    manifest_file.write_text('{"archive": true}\n', encoding="utf-8")

    paths_list = tmp_path / "paths_p1_04.txt"
    paths_list.write_text(
        "tests/independent/archive/x/y.py.txt\nmanifest.json\n",
        encoding="utf-8",
    )

    dest = tmp_path / "snapshot_p1_04"
    res = snapshot(source=repo, dest=dest, paths_from=paths_list)

    copied = {p["path"] for p in res["paths"]}
    assert "pyproject.toml" in copied
    assert "tests/independent/archive/x/y.py.txt" in copied
    assert "manifest.json" in copied

    assert (dest / "tests" / "independent" / "archive" / "x" / "y.py.txt").read_text(encoding="utf-8") == "# archived python test\n"
    assert (dest / "manifest.json").read_text(encoding="utf-8") == '{"archive": true}\n'


# --------------------------------------------------------------------------- Negative Proofs


def test_refusal_destination_reuse(tmp_path: Path) -> None:
    """Destination reuse (existing dir, file, or dangling symlink) is refused before writes."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    existing_dir = tmp_path / "existing_dir"
    existing_dir.mkdir()
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=existing_dir)
    assert exc_info.value.code == "out_exists"

    existing_file = tmp_path / "existing_file.txt"
    existing_file.write_text("already here", encoding="utf-8")
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=existing_file)
    assert exc_info.value.code == "out_exists"

    # Dangling symlink
    dangling = tmp_path / "dangling_symlink"
    os.symlink(tmp_path / "nonexistent", dangling)
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dangling)
    assert exc_info.value.code == "out_exists"


def test_refusal_source_output_alias(tmp_path: Path) -> None:
    """Destination inside source or identical to source is refused before writes."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    # Identical
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=repo)
    assert exc_info.value.code == "source_output_alias"

    # Inside source
    inside_dest = repo / "sub_snapshot"
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=inside_dest)
    assert exc_info.value.code == "source_output_alias"


def test_sibling_prefix_path_allowed(tmp_path: Path) -> None:
    """Destination with sibling prefix (e.g. repo-sibling) is allowed and not treated as alias."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    sibling_dest = tmp_path / "repo-sibling"
    res = snapshot(source=repo, dest=sibling_dest)
    assert sibling_dest.is_dir()
    assert res["count"] >= 1


def test_worktree_git_pointer_handling(tmp_path: Path) -> None:
    """Git worktree with .git file pointer resolves HEAD and excludes .git."""
    base_repo = tmp_path / "base_repo"
    _init_git_repo(base_repo)

    wt = tmp_path / "wt"
    _run_git(base_repo, "worktree", "add", str(wt), "-b", "feature-wt")

    assert (wt / ".git").is_file()  # Worktree pointer

    dest = tmp_path / "wt_snapshot"
    res = snapshot(source=wt, dest=dest)

    assert not (dest / ".git").exists()
    assert res["count"] >= 1
    assert res["head"] == _run_git(wt, "rev-parse", "HEAD")


def test_refusal_unknown_or_missing_path(tmp_path: Path) -> None:
    """--paths-from with a missing path refuses before writes."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    paths_file = tmp_path / "paths.txt"
    paths_file.write_text("pyproject.toml\nnonexistent.py\n", encoding="utf-8")

    with pytest.raises(SnapshotError) as exc_info:
        freeze(source=repo, paths_from=paths_file)
    assert exc_info.value.code in ("source_missing", "missing_path")

    dest = tmp_path / "dest_should_not_exist"
    with pytest.raises(SnapshotError):
        snapshot(source=repo, dest=dest, paths_from=paths_file)
    assert not dest.exists()


def test_refusal_symlink_in_source(tmp_path: Path) -> None:
    """Symlink in source paths is refused."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    target_file = tmp_path / "outside.txt"
    target_file.write_text("secret", encoding="utf-8")

    symlink_path = repo / "tests"
    symlink_path.mkdir(exist_ok=True)
    os.symlink(target_file, repo / "tests" / "test_sym.py")
    _run_git(repo, "add", "tests/test_sym.py")

    with pytest.raises(SnapshotError) as exc_info:
        freeze(source=repo)
    assert exc_info.value.code == "source_symlink"


def test_interrupted_copy_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Failure during snapshot creation cleans up destination and leaves source untouched."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_a.py").write_text("pass\n", encoding="utf-8")
    _run_git(repo, "add", "tests/test_a.py")
    _run_git(repo, "commit", "-m", "add test")

    dest = tmp_path / "interrupted_dest"

    # Simulate write failure midway
    import tools._snapshot as snap_mod

    orig_write = snap_mod._write_file

    def faulting_write(*args, **kwargs):
        if "test_a.py" in str(args):
            raise OSError("simulated disk fault")
        return orig_write(*args, **kwargs)

    monkeypatch.setattr(snap_mod, "_write_file", faulting_write)

    with pytest.raises(SnapshotError):
        snapshot(source=repo, dest=dest)

    # Destination should be completely cleaned up
    assert not dest.exists()
    # Source untouched
    assert (repo / "tests" / "test_a.py").read_text(encoding="utf-8") == "pass\n"


def test_refusal_destination_parent_symlink_into_source(tmp_path: Path) -> None:
    """Destination whose parent is a symlink into source is refused before any write."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    parent_link = tmp_path / "parent_link"
    parent_link.symlink_to(repo, target_is_directory=True)

    dest = parent_link / "snapshot_copy"

    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)
    assert exc_info.value.code == "source_output_alias"
    assert not (repo / "snapshot_copy").exists()


def test_cleanup_mid_copy_preserves_sibling_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulated failure mid-copy removes only created destination; sibling sentinel file survives."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    (repo / "tests").mkdir()
    (repo / "tests" / "test_a.py").write_text("def test_a(): pass\n", encoding="utf-8")
    _run_git(repo, "add", "tests/test_a.py")
    _run_git(repo, "commit", "-m", "add test_a")

    parent_dir = tmp_path / "parent_dest"
    parent_dir.mkdir()
    sentinel = parent_dir / "sentinel.txt"
    sentinel.write_text("sibling sentinel must survive\n", encoding="utf-8")

    dest = parent_dir / "failed_copy"

    import tools._snapshot as snap_mod
    orig_write = snap_mod._write_file

    def faulting_write(*args, **kwargs):
        if "test_a.py" in str(args):
            raise OSError("simulated disk fault mid-copy")
        return orig_write(*args, **kwargs)

    monkeypatch.setattr(snap_mod, "_write_file", faulting_write)

    with pytest.raises(SnapshotError):
        snapshot(source=repo, dest=dest)

    assert not dest.exists()
    assert sentinel.exists()
    assert sentinel.read_text(encoding="utf-8") == "sibling sentinel must survive\n"


def test_cleanup_refused_exception() -> None:
    """Test CleanupRefused exception instantiation."""
    err = CleanupRefused()
    assert isinstance(err, Exception)


# --------------------------------------------------------------------------- CLI Acceptance


def test_cli_freeze_and_snapshot(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """CLI subcommands freeze --source . --json and snapshot --source . --dest ..."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    # Freeze CLI
    exit_code = cli_main(["freeze", "--source", str(repo), "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["tool"] == "release_check"
    assert doc["count"] >= 1
    assert "sha256" in doc

    # Snapshot CLI
    dest = tmp_path / "cli_snapshot"
    exit_code = cli_main(["snapshot", "--source", str(repo), "--dest", str(dest)])
    assert exit_code == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["ok"] is True
    assert (dest / MANIFEST_NAME).is_file()

    # Re-run on existing dest fails
    exit_code = cli_main(["snapshot", "--source", str(repo), "--dest", str(dest)])
    assert exit_code == 1
    captured = capsys.readouterr()
    err = json.loads(captured.err)
    assert err["ok"] is False
    assert err["error"] == "out_exists"


def test_invariant_a_final_containment_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant A: held destination root fd path mismatch at final check fails snapshot."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    parent = tmp_path / "parent"
    parent.mkdir()
    dest = parent / "copy"
    other_parent = tmp_path / "other_parent"

    import tools._snapshot as snap_mod

    orig_read = snap_mod._read_rel

    def move_to_other_parent(root_fd, rel, code, limit):
        ans = orig_read(root_fd, rel, code, limit)
        if code == "readback_failed" and not other_parent.exists():
            parent.rename(other_parent)
        return ans

    monkeypatch.setattr(snap_mod, "_read_rel", move_to_other_parent)

    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)

    assert exc_info.value.code == "out_replaced"


def test_invariant_b_relocated_file_into_source_fails_source_tree_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant B: file relocated/added into source tree causes source_tree_changed failure."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    dest = tmp_path / "dest"

    import tools._snapshot as snap_mod

    orig_verify = snap_mod._verify_archive

    def inject_relocation(*args, **kwargs):
        orig_verify(*args, **kwargs)
        (repo / "relocated_into_source.txt").write_text("rogue entry\n", encoding="utf-8")

    monkeypatch.setattr(snap_mod, "_verify_archive", inject_relocation)

    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)

    assert exc_info.value.code == "source_tree_changed"
    assert "relocated_into_source.txt" in exc_info.value.context["paths"]
    assert exc_info.value.context["path"] == "relocated_into_source.txt"


def test_invariant_c_cleanup_swap_preserves_foreign_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant C: swapping destination directory during cleanup does not delete foreign files."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "sub").mkdir()
    (repo / "sub" / "a.txt").write_text("original\n", encoding="utf-8")
    _run_git(repo, "add", "sub/a.txt")
    _run_git(repo, "commit", "-m", "add sub/a.txt")

    dest = tmp_path / "dest"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "a.txt").write_text("foreign must survive\n", encoding="utf-8")
    held = tmp_path / "held"

    import tools._snapshot as snap_mod

    orig_verify = snap_mod._verify_archive

    def fail_verify(*args, **kwargs):
        orig_verify(*args, **kwargs)
        raise SnapshotError("synthetic_failure")

    orig_unlink = snap_mod._unlink_at

    def swap_unlink(root_fd, rel):
        if rel == "sub/a.txt":
            (dest / "sub").rename(held)
            foreign.rename(dest / "sub")
        return orig_unlink(root_fd, rel)

    monkeypatch.setattr(snap_mod, "_verify_archive", fail_verify)
    monkeypatch.setattr(snap_mod, "_unlink_at", swap_unlink)

    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)

    assert exc_info.value.code == "synthetic_failure"
    # Foreign file was not deleted
    assert (dest / "sub" / "a.txt").exists()
    assert (dest / "sub" / "a.txt").read_text(encoding="utf-8") == "foreign must survive\n"
    # Owned relocated file survived
    assert (held / "a.txt").exists()
    assert "sub/a.txt" in exc_info.value.context.get("retained_paths", [])
    assert "sub/a.txt" in str(exc_info.value)


def test_invariant_c_cleanup_relocate_preserves_relocated_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant C: relocating directory during parent open does not delete relocated files."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "sub").mkdir()
    (repo / "sub" / "a.txt").write_text("original\n", encoding="utf-8")
    _run_git(repo, "add", "sub/a.txt")
    _run_git(repo, "commit", "-m", "add sub/a.txt")

    dest = tmp_path / "dest"
    held = tmp_path / "held"

    import tools._snapshot as snap_mod

    orig_verify = snap_mod._verify_archive

    def fail_verify(*args, **kwargs):
        orig_verify(*args, **kwargs)
        raise SnapshotError("synthetic_failure")

    orig_open_parent = snap_mod._open_rel_parent

    def relocate_open(root_fd, rel, code):
        ans = orig_open_parent(root_fd, rel, code)
        if code == "cleanup_failed" and rel == "sub/a.txt":
            (dest / "sub").rename(held)
        return ans

    monkeypatch.setattr(snap_mod, "_verify_archive", fail_verify)
    monkeypatch.setattr(snap_mod, "_open_rel_parent", relocate_open)

    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)

    assert exc_info.value.code == "synthetic_failure"
    # Relocated file outside destination survived
    assert (held / "a.txt").exists()
    assert "sub/a.txt" in exc_info.value.context.get("retained_paths", [])
    assert str(held / "a.txt") in exc_info.value.context.get("retained_paths", [])
    assert "sub/a.txt" in str(exc_info.value)
    assert str(held / "a.txt") in str(exc_info.value)


def test_invariant_a_relocation_during_source_scan_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant A: destination relocation during end-of-run source-tree walk (B) fails."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "a.txt").write_text("original\n", encoding="utf-8")
    _run_git(repo, "add", "a.txt")
    _run_git(repo, "commit", "-m", "add a.txt")

    parent = tmp_path / "parent"
    parent.mkdir()
    dest = parent / "copy"
    moved = tmp_path / "moved_parent"

    import tools._snapshot as snap_mod

    orig_find = snap_mod._find_new_source_entries
    events: list[str] = []

    def relocate_during_b(source: str, initial_entries: dict) -> list[str]:
        res = orig_find(source, initial_entries)
        if not events:
            parent.rename(moved)
            events.append("relocated_during_b")
        return res

    monkeypatch.setattr(snap_mod, "_find_new_source_entries", relocate_during_b)

    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)

    assert exc_info.value.code == "out_replaced"
    assert not dest.exists()


def test_invariant_c_cleanup_refusal_names_retained_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When cleanup refuses, the raised failure names the retained owned paths."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "pkg").mkdir()
    (repo / "pkg" / "mod.py").write_text("print('hello')\n", encoding="utf-8")
    _run_git(repo, "add", "pkg/mod.py")
    _run_git(repo, "commit", "-m", "add pkg/mod.py")

    dest = tmp_path / "dest"
    held = tmp_path / "held"

    import tools._snapshot as snap_mod

    orig_verify = snap_mod._verify_archive

    def fail_verify(*args, **kwargs):
        orig_verify(*args, **kwargs)
        raise SnapshotError("synthetic_failure")

    orig_open_parent = snap_mod._open_rel_parent

    def relocate_open(root_fd, rel, code):
        ans = orig_open_parent(root_fd, rel, code)
        if code == "cleanup_failed" and rel == "pkg/mod.py":
            (dest / "pkg").rename(held)
        return ans

    monkeypatch.setattr(snap_mod, "_verify_archive", fail_verify)
    monkeypatch.setattr(snap_mod, "_open_rel_parent", relocate_open)

    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)

    assert exc_info.value.code == "synthetic_failure"
    retained = exc_info.value.context.get("retained_paths", [])
    assert "pkg/mod.py" in retained
    assert str(held / "mod.py") in retained
    assert "pkg/mod.py" in str(exc_info.value)
    assert str(held / "mod.py") in str(exc_info.value)


def test_invariant_b_excluded_cache_writes_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unrelated writes into excluded directories (__pycache__, .pytest_cache, .venv) mid-run succeed."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "a.txt").write_text("original\n", encoding="utf-8")
    _run_git(repo, "add", "a.txt")
    _run_git(repo, "commit", "-m", "add a.txt")

    (repo / "__pycache__").mkdir()
    (repo / ".pytest_cache").mkdir()
    (repo / ".venv").mkdir()

    import tools._snapshot as snap_mod

    orig_verify = snap_mod._verify_archive

    def add_excluded_cache_files(*args, **kwargs):
        orig_verify(*args, **kwargs)
        (repo / "__pycache__" / "unrelated.cpython-314.pyc").write_bytes(b"cache")
        (repo / ".pytest_cache" / "nodeids").write_bytes(b"cache")
        (repo / ".venv" / "new.py").write_bytes(b"cache")

    monkeypatch.setattr(snap_mod, "_verify_archive", add_excluded_cache_files)

    dest = tmp_path / "dest"
    snapshot(source=repo, dest=dest)
    assert dest.exists()
    assert (dest / "a.txt").read_text(encoding="utf-8") == "original\n"
    assert not (dest / "__pycache__").exists()
    assert not (dest / ".pytest_cache").exists()
    assert not (dest / ".venv").exists()


def test_invariant_b_non_excluded_file_write_fails_source_tree_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new non-excluded file created mid-run fails with source_tree_changed."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "a.txt").write_text("original\n", encoding="utf-8")
    _run_git(repo, "add", "a.txt")
    _run_git(repo, "commit", "-m", "add a.txt")

    import tools._snapshot as snap_mod

    orig_verify = snap_mod._verify_archive

    def add_non_excluded_file(*args, **kwargs):
        orig_verify(*args, **kwargs)
        (repo / "intruder.txt").write_text("intruder\n", encoding="utf-8")

    monkeypatch.setattr(snap_mod, "_verify_archive", add_non_excluded_file)

    dest = tmp_path / "dest"
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)

    assert exc_info.value.code == "source_tree_changed"
    assert "intruder.txt" in exc_info.value.context.get("paths", [])
    assert exc_info.value.context.get("path") == "intruder.txt"


def test_invariant_b_early_failure_names_new_source_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An injected collection failure plus a new source entry fails and names the new entry."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "a.txt").write_text("original\n", encoding="utf-8")
    _run_git(repo, "add", "a.txt")
    _run_git(repo, "commit", "-m", "add a.txt")

    import tools._snapshot as snap_mod

    def early_collect_failure(*args, **kwargs):
        (repo / "unexpected-new.txt").write_text("new entry\n", encoding="utf-8")
        raise SnapshotError("synthetic_collect_failure")

    monkeypatch.setattr(snap_mod, "_collect", early_collect_failure)

    dest = tmp_path / "dest"
    with pytest.raises(SnapshotError) as exc_info:
        snapshot(source=repo, dest=dest)

    assert exc_info.value.code == "source_tree_changed"
    assert "unexpected-new.txt" in exc_info.value.context.get("paths", [])
    assert exc_info.value.context.get("path") == "unexpected-new.txt"

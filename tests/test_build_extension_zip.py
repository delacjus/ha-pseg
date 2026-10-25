"""Tests for tools/build_extension_zip.py."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import zipfile

from custom_components.pseg.captcha_helper import (
    EXTENSION_MEMBERS,
    build_extension_archive,
)
from tools.build_extension_zip import (
    EXTENSION_ZIP_FILENAME,
    build_archive_from_files,
    build_extension_assets,
    extract_extension_members,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "build_extension_zip.py"


def test_byte_identical_to_build_extension_archive(tmp_path: Path) -> None:
    """Verify generated zip is byte-identical to build_extension_archive()."""
    zip_path, sha_path = build_extension_assets(REPO_ROOT, tmp_path)

    expected_bytes = build_extension_archive()
    assert expected_bytes is not None
    actual_bytes = zip_path.read_bytes()

    assert actual_bytes == expected_bytes

    frontend_dir = REPO_ROOT / "custom_components" / "pseg" / "frontend"
    fallback_bytes = build_archive_from_files(frontend_dir, EXTENSION_MEMBERS)
    assert fallback_bytes == expected_bytes


def test_members_and_zip_metadata(tmp_path: Path) -> None:
    """Verify exactly the three members exist flat at archive root with fixed metadata."""
    zip_path, _ = build_extension_assets(REPO_ROOT, tmp_path)

    with zipfile.ZipFile(zip_path, "r") as archive:
        infolist = archive.infolist()
        names = [info.filename for info in infolist]

        assert names == ["manifest.json", "service-worker.js", "pseg-captcha-helper.js"]
        assert "pseg-energy-card.js" not in names

        for info in infolist:
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert info.compress_type == zipfile.ZIP_DEFLATED
            assert info.external_attr == 0o644 << 16


def test_deterministic_across_two_runs(tmp_path: Path) -> None:
    """Verify repeated runs produce byte-identical archives and checksums."""
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"

    zip1, sha1 = build_extension_assets(REPO_ROOT, out1)
    zip2, sha2 = build_extension_assets(REPO_ROOT, out2)

    assert zip1.read_bytes() == zip2.read_bytes()
    assert sha1.read_text(encoding="utf-8") == sha2.read_text(encoding="utf-8")


def test_sha256_checksum_file(tmp_path: Path) -> None:
    """Verify .sha256 file format matches sha256sum expectation."""
    zip_path, sha_path = build_extension_assets(REPO_ROOT, tmp_path)

    zip_bytes = zip_path.read_bytes()
    expected_hash = hashlib.sha256(zip_bytes).hexdigest()
    expected_content = f"{expected_hash}  {EXTENSION_ZIP_FILENAME}\n"

    assert sha_path.read_text(encoding="utf-8") == expected_content


def test_ast_extraction() -> None:
    """Verify AST extraction extracts the exact EXTENSION_MEMBERS."""
    helper_file = REPO_ROOT / "custom_components" / "pseg" / "captcha_helper.py"
    extracted = extract_extension_members(helper_file)
    assert extracted == EXTENSION_MEMBERS


def test_missing_member_fails_nonzero(tmp_path: Path) -> None:
    """Verify CLI exits nonzero when an extension member is missing."""
    mock_repo = tmp_path / "mock_repo"
    mock_frontend = mock_repo / "custom_components" / "pseg" / "frontend"
    mock_frontend.mkdir(parents=True)

    # Copy only manifest.json and service-worker.js, omit pseg-captcha-helper.js
    real_frontend = REPO_ROOT / "custom_components" / "pseg" / "frontend"
    (mock_frontend / "manifest.json").write_bytes((real_frontend / "manifest.json").read_bytes())
    (mock_frontend / "service-worker.js").write_bytes((real_frontend / "service-worker.js").read_bytes())

    # Copy captcha_helper.py so AST extraction works
    real_helper = REPO_ROOT / "custom_components" / "pseg" / "captcha_helper.py"
    (mock_repo / "custom_components" / "pseg" / "captcha_helper.py").write_text(
        real_helper.read_text(encoding="utf-8"), encoding="utf-8"
    )

    out_dir = tmp_path / "out"
    cmd = [
        sys.executable,
        "-B",
        str(TOOL_PATH),
        "--source",
        str(mock_repo),
        "--out",
        str(out_dir),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert proc.returncode != 0
    assert "Missing extension member" in proc.stderr
    assert not (out_dir / EXTENSION_ZIP_FILENAME).exists()


def test_cli_execution_success(tmp_path: Path) -> None:
    """Verify full CLI execution writes both expected files and exits 0."""
    out_dir = tmp_path / "cli_out"
    cmd = [
        sys.executable,
        "-B",
        str(TOOL_PATH),
        "--source",
        str(REPO_ROOT),
        "--out",
        str(out_dir),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert proc.returncode == 0
    assert (out_dir / EXTENSION_ZIP_FILENAME).is_file()
    assert (out_dir / f"{EXTENSION_ZIP_FILENAME}.sha256").is_file()

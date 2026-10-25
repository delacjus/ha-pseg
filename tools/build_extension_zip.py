#!/usr/bin/env python3
"""Build deterministic PSE&G CAPTCHA helper extension archive and sha256 checksum.

Writes pseg-captcha-helper-extension.zip and
pseg-captcha-helper-extension.zip.sha256 to the specified output directory.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
from pathlib import Path
import sys
import zipfile

EXTENSION_ZIP_FILENAME = "pseg-captcha-helper-extension.zip"


def extract_extension_members(helper_file: Path) -> tuple[str, ...]:
    """Extract EXTENSION_MEMBERS tuple via AST from captcha_helper.py."""
    try:
        content = helper_file.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(helper_file))
    except Exception as err:
        raise RuntimeError(f"Failed to parse {helper_file}: {err}") from err

    for node in tree.body:
        value = None
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "EXTENSION_MEMBERS":
                    value = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "EXTENSION_MEMBERS":
                value = node.value

        if value and isinstance(value, (ast.Tuple, ast.List)):
            members = tuple(
                elt.value
                for elt in value.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            )
            if members:
                return members

    raise RuntimeError(f"EXTENSION_MEMBERS definition not found in {helper_file}")


def build_archive_from_files(frontend_dir: Path, members: tuple[str, ...]) -> bytes:
    """Build deterministic extension ZIP from member files."""
    missing: list[str] = []
    member_data: dict[str, bytes] = {}

    for name in members:
        path = frontend_dir / name
        if not path.is_file():
            missing.append(name)
        else:
            try:
                member_data[name] = path.read_bytes()
            except OSError as err:
                raise RuntimeError(f"Error reading {path}: {err}") from err

    if missing:
        raise FileNotFoundError(f"Missing extension member(s): {", ".join(missing)}")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, member_data[name])

    return buffer.getvalue()


def build_extension_archive_bytes(source_root: Path) -> tuple[str, bytes]:
    """Obtain extension archive bytes and filename, preferring production import."""
    frontend_dir = source_root / "custom_components" / "pseg" / "frontend"
    helper_file = source_root / "custom_components" / "pseg" / "captcha_helper.py"

    if not helper_file.is_file():
        raise FileNotFoundError(f"captcha_helper.py not found at {helper_file}")
    if not frontend_dir.is_dir():
        raise FileNotFoundError(f"frontend directory not found at {frontend_dir}")

    members: tuple[str, ...] | None = None
    filename = EXTENSION_ZIP_FILENAME

    # Try importing from the integration directly if homeassistant is in sys.path / env.
    source_str = str(source_root.resolve())
    if source_str not in sys.path:
        sys.path.insert(0, source_str)

    try:
        from custom_components.pseg.captcha_helper import (
            EXTENSION_DIR as PROD_DIR,
            EXTENSION_MEMBERS as PROD_MEMBERS,
            EXTENSION_ZIP_FILENAME as PROD_FILENAME,
            build_extension_archive as prod_build_archive,
        )

        members = PROD_MEMBERS
        filename = PROD_FILENAME

        missing = [m for m in members if not (frontend_dir / m).is_file()]
        if missing:
            raise FileNotFoundError(f"Missing extension member(s): {", ".join(missing)}")

        if PROD_DIR.resolve() == frontend_dir.resolve():
            archive = prod_build_archive()
            if archive is None:
                raise FileNotFoundError("build_extension_archive returned None")
            return filename, archive
    except (ImportError, ModuleNotFoundError):
        pass

    if members is None:
        members = extract_extension_members(helper_file)

    archive = build_archive_from_files(frontend_dir, members)
    return filename, archive


def build_extension_assets(source_root: Path, out_dir: Path) -> tuple[Path, Path]:
    """Build the ZIP archive and .sha256 file into out_dir."""
    filename, archive_bytes = build_extension_archive_bytes(source_root)

    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / filename
    sha_path = out_dir / f"{filename}.sha256"

    zip_path.write_bytes(archive_bytes)
    sha256_hex = hashlib.sha256(archive_bytes).hexdigest()
    sha_path.write_text(f"{sha256_hex}  {filename}\n", encoding="utf-8")

    return zip_path, sha_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build deterministic PSE&G CAPTCHA helper extension archive and sha256 checksum."
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output directory to place extension zip and sha256 file",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help="Repository root (defaults to parent of tools/ directory)",
    )
    args = parser.parse_args()

    source_root = args.source
    if source_root is None:
        source_root = Path(__file__).resolve().parent.parent

    try:
        zip_path, sha_path = build_extension_assets(source_root, args.out)
    except Exception as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    print(f"Wrote archive:  {zip_path}")
    print(f"Wrote checksum: {sha_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

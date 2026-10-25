"""Probe provenance capture and verification tool.

Preserves review probes and assertion scripts as byte-exact inert archives under
tests/independent/archive/<group>/*.py.txt and validates integrity and provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

VALID_STATUSES = {"inert", "active"}


def compute_sha256(data: bytes) -> str:
    """Compute sha256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(path: Path) -> str:
    """Compute sha256 hex digest of file contents."""
    return compute_sha256(path.read_bytes())


def compute_aggregate_sha256(files: list[dict[str, Any]]) -> str:
    """Compute aggregate sha256 over sorted relative paths and file sha256s."""
    hasher = hashlib.sha256()
    for item in sorted(files, key=lambda x: x["relative_path"]):
        rp = item["relative_path"]
        sh = item["sha256"]
        entry_str = f"{rp}\0{sh}\0"
        hasher.update(entry_str.encode("utf-8"))
    return hasher.hexdigest()


def is_valid_sha256(val: Any) -> bool:
    """Check if value is a 64-character hex SHA-256 string."""
    return (
        isinstance(val, str) and len(val) == 64 and all(c in "0123456789abcdefABCDEF" for c in val)
    )


def is_valid_absolute_path(val: Any) -> bool:
    """Check if value is a non-empty absolute path string."""
    return isinstance(val, str) and bool(val.strip()) and Path(val).is_absolute()


def capture(spec_path: Path, dest_dir: Path) -> dict[str, Any]:
    """Capture probe files into inert archive according to spec.

    Args:
        spec_path: Path to probe_sources.json specification.
        dest_dir: Destination directory (e.g. tests/independent/archive).

    Returns:
        Manifest dictionary.
    """
    if not spec_path.is_file():
        raise FileNotFoundError(f"Spec file not found: {spec_path}")

    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    sources = spec.get("sources", [])
    if not sources:
        raise ValueError(f"No sources defined in spec: {spec_path}")

    dest_dir.mkdir(parents=True, exist_ok=True)
    manifest_entries: list[dict[str, Any]] = []

    for src in sources:
        orig_path_str = src["original_path"]
        orig_path = Path(orig_path_str)
        rel_dest = src["archive_relpath"]
        expected_prefix = src.get("expected_sha256_prefix")

        if not orig_path.exists():
            raise FileNotFoundError(
                f"Missing original probe file: {orig_path_str} (group: {src.get('group')})"
            )
        if not orig_path.is_file():
            raise ValueError(f"Source path is not a regular file: {orig_path_str}")

        raw_bytes = orig_path.read_bytes()
        digest = compute_sha256(raw_bytes)

        if expected_prefix and not digest.startswith(expected_prefix):
            raise ValueError(
                f"SHA-256 prefix mismatch for {orig_path_str}: "
                f"got {digest[: len(expected_prefix)]}, expected {expected_prefix}"
            )

        target_file = dest_dir / rel_dest
        target_file.parent.mkdir(parents=True, exist_ok=True)

        if target_file.exists():
            existing_bytes = target_file.read_bytes()
            if existing_bytes != raw_bytes:
                raise RuntimeError(
                    f"Destination file already exists with differing content: {target_file}"
                )
            # If existing_bytes == raw_bytes, verified idempotent no-op
        else:
            target_file.write_bytes(raw_bytes)

        entry = {
            "group": src["group"],
            "relative_path": rel_dest,
            "original_path": orig_path_str,
            "sha256": digest,
            "size_bytes": len(raw_bytes),
            "expected_sha256_prefix": expected_prefix,
            "prefix_matches": (digest.startswith(expected_prefix) if expected_prefix else True),
            "historical_cases": src.get("historical_cases"),
            "role": src.get("role", "probe"),
            "collect": src.get("collect", False),
            "status": "inert",
            "reviewer_kb": src.get("reviewer_kb"),
            "description": src.get("description", ""),
        }
        manifest_entries.append(entry)

    manifest_entries.sort(key=lambda x: x["relative_path"])
    aggregate_hash = compute_aggregate_sha256(manifest_entries)

    manifest = {
        "version": "1.0.0",
        "spec_file": str(spec_path),
        "file_count": len(manifest_entries),
        "aggregate_sha256": aggregate_hash,
        "files": manifest_entries,
    }

    manifest_path = dest_dir / "manifest.json"
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    if manifest_path.exists():
        if manifest_path.read_bytes() != manifest_bytes:
            raise RuntimeError(f"Manifest already exists with differing content: {manifest_path}")
    else:
        manifest_path.write_bytes(manifest_bytes)

    return manifest


def _validate_provenance_group(
    item: Path,
    archive_dir: Path,
    errors: list[str],
    messages: list[str],
    promoted_test_files: set[str],
    manifest_map: dict[str, dict[str, Any]],
) -> None:
    group_provenance_file = item / "provenance.json"
    if not group_provenance_file.is_file():
        return

    try:
        grp_meta = json.loads(group_provenance_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(f"Failed to parse JSON in {group_provenance_file}: {exc}")
        return

    if not isinstance(grp_meta, dict):
        errors.append(f"Root of {group_provenance_file} must be a JSON object")
        return

    # Check group name matches directory
    declared_group = grp_meta.get("group")
    if declared_group != item.name:
        errors.append(
            f"Group mismatch in {group_provenance_file}: declares '{declared_group}', directory is '{item.name}'"
        )

    # Status: mandatory and type-checked in {"inert", "active"}
    status = grp_meta.get("status")
    if status is None:
        errors.append(f"Missing required field 'status' in {group_provenance_file}")
    elif status not in VALID_STATUSES:
        errors.append(
            f"Field 'status' must be 'inert' or 'active' in {group_provenance_file}: got '{status}'"
        )

    # Build and validate list of source tuples
    # Primary schema: 'sources' (or 'original_sources') list of source tuple dicts
    # Each tuple: {original_path, original_sha256, archived_path, archived_sha256, role, collect}
    raw_sources = grp_meta.get("sources")
    if raw_sources is None:
        raw_sources = grp_meta.get("original_sources")

    source_tuples: list[dict[str, Any]] = []

    if raw_sources is not None:
        if not isinstance(raw_sources, list) or len(raw_sources) == 0:
            errors.append(
                f"Field 'sources' must be a non-empty list in {group_provenance_file}"
            )
        else:
            source_tuples.extend(raw_sources)
        # If singular fields are also present, include them if distinct
        if any(k in grp_meta for k in ("original_path", "original_sha256", "archived_path", "archived_sha256")):
            for f in ["original_path", "original_sha256", "archived_path", "archived_sha256"]:
                if f not in grp_meta:
                    errors.append(f"Missing required field '{f}' in {group_provenance_file}")
            singular_tuple = {
                "original_path": grp_meta.get("original_path"),
                "original_sha256": grp_meta.get("original_sha256"),
                "archived_path": grp_meta.get("archived_path"),
                "archived_sha256": grp_meta.get("archived_sha256"),
                "role": grp_meta.get("role", "probe"),
                "collect": grp_meta.get("collect", False),
            }
            if not any(
                isinstance(t, dict) and t.get("archived_path") == singular_tuple["archived_path"]
                for t in source_tuples
            ):
                source_tuples.insert(0, singular_tuple)
    else:
        # No 'sources' list: if singular fields are used, check them; otherwise 'sources' is missing
        if "original_path" in grp_meta:
            for f in ["original_path", "original_sha256", "archived_path", "archived_sha256"]:
                if f not in grp_meta:
                    errors.append(f"Missing required field '{f}' in {group_provenance_file}")
            singular_tuple = {
                "original_path": grp_meta.get("original_path"),
                "original_sha256": grp_meta.get("original_sha256"),
                "archived_path": grp_meta.get("archived_path"),
                "archived_sha256": grp_meta.get("archived_sha256"),
                "role": grp_meta.get("role", "probe"),
                "collect": grp_meta.get("collect", False),
            }
            source_tuples.append(singular_tuple)
        else:
            errors.append(f"Missing required field 'sources' in {group_provenance_file}")

    covered_archived_files: set[str] = set()

    for idx, st in enumerate(source_tuples):
        if not isinstance(st, dict):
            errors.append(
                f"Source tuple at index {idx} in {group_provenance_file} must be a dict: got {st}"
            )
            continue

        orig_path = st.get("original_path")
        if orig_path is None:
            errors.append(f"Missing required field 'original_path' in source tuple {idx} of {group_provenance_file}")
        elif not is_valid_absolute_path(orig_path):
            errors.append(
                f"Field 'original_path' must be an absolute path in source tuple {idx} of {group_provenance_file}: got '{orig_path}'"
            )

        orig_sha = st.get("original_sha256")
        if orig_sha is None:
            errors.append(f"Missing required field 'original_sha256' in source tuple {idx} of {group_provenance_file}")
        elif not is_valid_sha256(orig_sha):
            errors.append(
                f"Field 'original_sha256' must be a 64-character hex SHA-256 in source tuple {idx} of {group_provenance_file}: got '{orig_sha}'"
            )

        arch_path = st.get("archived_path")
        clean_arch = None
        if arch_path is None:
            errors.append(f"Missing required field 'archived_path' in source tuple {idx} of {group_provenance_file}")
        elif not isinstance(arch_path, str) or not arch_path.strip():
            errors.append(
                f"Field 'archived_path' must be a non-empty string in source tuple {idx} of {group_provenance_file}"
            )
        else:
            clean_arch = arch_path.removeprefix("archive/").strip("/")
            if not clean_arch.startswith(f"{item.name}/"):
                # If relative to group directory, resolve under group
                alt_clean = f"{item.name}/{clean_arch}"
                if (archive_dir / alt_clean).exists() or alt_clean in manifest_map:
                    clean_arch = alt_clean

        arch_sha = st.get("archived_sha256")
        if arch_sha is None:
            errors.append(f"Missing required field 'archived_sha256' in source tuple {idx} of {group_provenance_file}")
        elif not is_valid_sha256(arch_sha):
            errors.append(
                f"Field 'archived_sha256' must be a 64-character hex SHA-256 in source tuple {idx} of {group_provenance_file}: got '{arch_sha}'"
            )

        role = st.get("role")
        if role is not None and (not isinstance(role, str) or not role.strip()):
            errors.append(f"Field 'role' must be a non-empty string in source tuple {idx} of {group_provenance_file}")

        collect = st.get("collect")
        if collect is not None and not isinstance(collect, bool):
            errors.append(f"Field 'collect' must be a boolean in source tuple {idx} of {group_provenance_file}: got '{collect}'")

        if clean_arch:
            target_arch_file = archive_dir / clean_arch
            if not target_arch_file.exists() or not target_arch_file.is_file():
                errors.append(
                    f"Archived file referenced in {group_provenance_file} missing on disk: {target_arch_file}"
                )
            else:
                # (a) match every tuple's archived_sha256 against archive file bytes
                actual_arch_hash = compute_file_sha256(target_arch_file)
                if arch_sha and actual_arch_hash != arch_sha:
                    errors.append(
                        f"Archived file hash mismatch for {target_arch_file}: got {actual_arch_hash}, metadata declares {arch_sha}"
                    )

                # (b) match original_sha256 against archived_sha256 and manifest record
                if orig_sha and arch_sha and orig_sha != arch_sha:
                    errors.append(
                        f"Original SHA-256 does not match archived SHA-256 for {clean_arch}: {orig_sha} != {arch_sha} (archive must be byte-exact copy)"
                    )

                manifest_entry = manifest_map.get(clean_arch)
                if manifest_entry is None:
                    errors.append(
                        f"Archived file not recorded in archive manifest: {clean_arch}"
                    )
                else:
                    if orig_sha and manifest_entry.get("sha256") != orig_sha:
                        errors.append(
                            f"Original SHA-256 does not match archive manifest entry for {clean_arch}: declared {orig_sha}, manifest has {manifest_entry.get('sha256')}"
                        )
                    if orig_path and manifest_entry.get("original_path") != orig_path:
                        errors.append(
                            f"Original path mismatch for {clean_arch}: declared '{orig_path}', manifest records '{manifest_entry.get('original_path')}'"
                        )

            # (c) Check duplicated source tuple
            if clean_arch in covered_archived_files:
                errors.append(
                    f"Duplicated source tuple for archived file in {group_provenance_file}: {clean_arch}"
                )
            else:
                covered_archived_files.add(clean_arch)

    # (c) require every archived file under archive/<group>/ to be covered by exactly one tuple
    group_archive_dir = archive_dir / item.name
    existing_archived_files: set[str] = set()
    if group_archive_dir.is_dir():
        for f in group_archive_dir.rglob("*"):
            if f.is_file() and f.name != "manifest.json":
                existing_archived_files.add(str(f.relative_to(archive_dir)))

    uncovered_archive_files = existing_archived_files - covered_archived_files
    if uncovered_archive_files:
        errors.append(
            f"Archived file(s) under archive/{item.name} not covered by source tuples in {group_provenance_file}: {sorted(uncovered_archive_files)}"
        )

    # Reviewer KB id: mandatory non-empty string
    reviewer_kb = grp_meta.get("reviewer_kb")
    if reviewer_kb is None:
        errors.append(f"Missing required field 'reviewer_kb' in {group_provenance_file}")
    elif not isinstance(reviewer_kb, str) or not reviewer_kb.strip():
        errors.append(f"Field 'reviewer_kb' must be a non-empty string in {group_provenance_file}")

    # Expected collection count: mandatory (int >= 0 or 'not-collected' for inert)
    exp_collection = grp_meta.get("expected_collection")
    if exp_collection is None:
        exp_collection = grp_meta.get("historical_cases")
    if exp_collection is None:
        errors.append(f"Missing required field 'expected_collection' in {group_provenance_file}")
    else:
        if isinstance(exp_collection, int) and not isinstance(exp_collection, bool):
            if exp_collection < 0:
                errors.append(
                    f"Field 'expected_collection' must be >= 0 in {group_provenance_file}: got {exp_collection}"
                )
            if status == "inert" and exp_collection != 0:
                errors.append(
                    f"Inert status in {group_provenance_file} must have expected_collection 0 or 'not-collected', got {exp_collection}"
                )
        elif isinstance(exp_collection, str) and exp_collection.lower() == "not-collected":
            if status == "active":
                errors.append(
                    f"Active status in {group_provenance_file} cannot have expected_collection 'not-collected'"
                )
        else:
            errors.append(
                f"Field 'expected_collection' must be an integer count or 'not-collected' in {group_provenance_file}: got '{exp_collection}'"
            )

    # Inert group enforcement: must not contain collectable test files
    if status == "inert":
        collectable_tests = [
            str(p.relative_to(item))
            for p in item.rglob("*.py")
            if p.is_file() and (p.name.startswith("test_") or p.name.endswith("_test.py"))
        ]
        if collectable_tests:
            errors.append(
                f"Inert group {item.name} contains collectable test file(s): {sorted(collectable_tests)}. Inert groups must contain no collectable tests."
            )

    # Transformation rationale: required when status is active
    transformations = grp_meta.get("transformation_rationale")
    if transformations is None:
        transformations = grp_meta.get("transformations")
    if status == "active":
        if transformations is None:
            errors.append(
                f"Missing required field 'transformation_rationale' for active status in {group_provenance_file}"
            )
        elif isinstance(transformations, (str, list)) and len(transformations) == 0:
            errors.append(
                f"Field 'transformation_rationale' in {group_provenance_file} cannot be empty"
            )
        elif isinstance(transformations, list):
            if not all(isinstance(t, str) and t.strip() for t in transformations):
                errors.append(
                    f"Field 'transformation_rationale' in {group_provenance_file} contains empty or non-string entries"
                )
            else:
                messages.append(
                    f"Group {item.name}: transformations declared: {'; '.join(transformations)}"
                )
        elif isinstance(transformations, str):
            if not transformations.strip():
                errors.append(
                    f"Field 'transformation_rationale' in {group_provenance_file} cannot be empty"
                )
            else:
                messages.append(f"Group {item.name}: transformations declared: {transformations}")
        else:
            errors.append(
                f"Field 'transformation_rationale' in {group_provenance_file} must be string or list of strings"
            )

    # Promoted files: complete coverage required for ACTIVE groups
    # EVERY *.py file under item (tests, conftest.py, helpers, __init__.py) must be listed with its sha256
    # (or in explicit allowlist with reason)
    promoted_files = grp_meta.get("promoted_files")
    if status == "active" and (
        promoted_files is None or not isinstance(promoted_files, list) or len(promoted_files) == 0
    ):
        errors.append(
            f"Active status requires non-empty 'promoted_files' list in {group_provenance_file}"
        )

    covered_py_files: set[str] = set()

    # Check allowlist if present
    allowlist = grp_meta.get("allowlist", [])
    if allowlist:
        if not isinstance(allowlist, list):
            errors.append(f"Field 'allowlist' in {group_provenance_file} must be a list")
        else:
            for al in allowlist:
                if not isinstance(al, dict):
                    errors.append(f"Allowlist entry in {group_provenance_file} must be a dict: got {al}")
                    continue
                al_path = al.get("path")
                al_reason = al.get("reason")
                if not al_path or not isinstance(al_path, str):
                    errors.append(f"Allowlist entry in {group_provenance_file} missing string 'path'")
                elif not al_reason or not isinstance(al_reason, str) or not al_reason.strip():
                    errors.append(
                        f"Allowlist entry for '{al_path}' in {group_provenance_file} missing reasoned string 'reason'"
                    )
                else:
                    covered_py_files.add(al_path)

    if promoted_files is not None:
        if not isinstance(promoted_files, list):
            errors.append(f"'promoted_files' must be a list in {group_provenance_file}")
        else:
            for pf in promoted_files:
                if not isinstance(pf, dict):
                    errors.append(
                        f"Entry in 'promoted_files' must be a dict in {group_provenance_file}: got {pf}"
                    )
                    continue
                pf_rel = pf.get("relative_path")
                if not pf_rel or not isinstance(pf_rel, str):
                    errors.append(
                        f"Promoted file entry missing relative_path in {group_provenance_file}"
                    )
                    continue
                covered_py_files.add(pf_rel)
                pf_path = item / pf_rel
                promoted_test_files.add(str(pf_path.resolve()))
                if not pf_path.exists():
                    errors.append(f"Promoted file missing: {pf_path}")
                    continue

                pf_sha = pf.get("sha256")
                if pf_sha is None:
                    errors.append(
                        f"Promoted file entry missing required 'sha256': {pf_rel} in {group_provenance_file}"
                    )
                elif not is_valid_sha256(pf_sha):
                    errors.append(
                        f"Promoted file 'sha256' must be a 64-character hex SHA-256 in {group_provenance_file}: got '{pf_sha}'"
                    )
                else:
                    pf_hash = compute_file_sha256(pf_path)
                    if pf_hash != pf_sha:
                        errors.append(
                            f"Promoted file hash mismatch for {pf_path}: got {pf_hash}, declared {pf_sha}"
                        )

    # For active groups, verify complete coverage of all *.py files in the group directory
    if status == "active":
        all_group_py_files = {
            str(p.relative_to(item)) for p in item.rglob("*.py") if p.is_file()
        }
        unlisted_py = all_group_py_files - covered_py_files
        if unlisted_py:
            errors.append(
                f"Unlisted python file(s) in active group {item.name}: {sorted(unlisted_py)}. "
                "Every *.py file must be listed in promoted_files with its sha256 (or in allowlist with reason)."
            )


def verify(root_dir: Path) -> tuple[bool, list[str]]:
    """Verify archive integrity, provenance metadata, and absence of unregistered tests.

    Args:
        root_dir: Root directory of independent tests (e.g. tests/independent).

    Returns:
        Tuple of (is_valid, list of messages/errors).
    """
    errors: list[str] = []
    messages: list[str] = []

    archive_dir = root_dir / "archive"
    manifest_path = archive_dir / "manifest.json"

    if not manifest_path.is_file():
        errors.append(f"Archive manifest not found: {manifest_path}")
        return False, errors

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(f"Failed to parse manifest JSON: {exc}")
        return False, errors

    files_list = manifest.get("files", [])
    if not files_list:
        errors.append("Manifest contains no files")

    manifest_relpaths = set()
    manifest_map: dict[str, dict[str, Any]] = {}
    for entry in files_list:
        rel_path = entry.get("relative_path")
        if not rel_path:
            errors.append(f"Manifest entry missing relative_path: {entry}")
            continue
        manifest_relpaths.add(rel_path)
        manifest_map[rel_path] = entry

        orig_path = entry.get("original_path")
        if not orig_path:
            errors.append(f"Manifest entry missing original_path: {rel_path}")
        elif not is_valid_absolute_path(orig_path):
            errors.append(f"Manifest entry original_path must be absolute: {orig_path}")

        entry_sha = entry.get("sha256")
        if not entry_sha:
            errors.append(f"Manifest entry missing sha256: {rel_path}")
        elif not is_valid_sha256(entry_sha):
            errors.append(f"Manifest entry sha256 must be 64-char hex: {entry_sha}")

        if not entry.get("reviewer_kb"):
            errors.append(f"Manifest entry missing reviewer_kb: {rel_path}")

        status = entry.get("status")
        if status not in VALID_STATUSES:
            errors.append(f"Manifest entry invalid status: {status} in {rel_path}")

        target_path = archive_dir / rel_path
        if not target_path.exists():
            errors.append(f"Archived file missing on disk: {target_path}")
            continue
        if not target_path.is_file():
            errors.append(f"Archived path is not a regular file: {target_path}")
            continue

        raw_bytes = target_path.read_bytes()
        digest = compute_sha256(raw_bytes)
        expected_digest = entry.get("sha256")
        if digest != expected_digest:
            errors.append(
                f"SHA-256 mismatch for {rel_path}: got {digest}, manifest expects {expected_digest}"
            )

        expected_size = entry.get("size_bytes")
        if len(raw_bytes) != expected_size:
            errors.append(
                f"Size mismatch for {rel_path}: got {len(raw_bytes)}, manifest expects {expected_size}"
            )

        prefix = entry.get("expected_sha256_prefix")
        if prefix and not digest.startswith(prefix):
            errors.append(f"Prefix mismatch for {rel_path}: {digest} does not start with {prefix}")

        # Check non-collectable extension: must end with .txt or not be a python test
        if target_path.suffix == ".py" or (
            target_path.name.startswith("test_") and target_path.suffix == ".py"
        ):
            errors.append(
                f"Archived file {rel_path} has active python test naming; must end with .txt"
            )

    # Check for unmanifested files in archive
    for path in archive_dir.rglob("*"):
        if path.is_file() and path.name != "manifest.json":
            rel = str(path.relative_to(archive_dir))
            if rel not in manifest_relpaths:
                errors.append(f"Unmanifested file found in archive: {rel}")

    # Check aggregate hash
    expected_aggregate = manifest.get("aggregate_sha256")
    actual_aggregate = compute_aggregate_sha256(files_list)
    if expected_aggregate != actual_aggregate:
        errors.append(
            f"Aggregate SHA-256 mismatch: manifest {expected_aggregate}, computed {actual_aggregate}"
        )

    # Discover and validate per-group provenance.json files
    promoted_test_files: set[str] = set()
    for item in sorted(root_dir.iterdir()):
        if item.is_dir() and item.name != "archive" and not item.name.startswith("."):
            _validate_provenance_group(
                item, archive_dir, errors, messages, promoted_test_files, manifest_map
            )

    # Verify no unregistered python test files in root_dir (except test_provenance.py and registered promoted files)
    for py_file in root_dir.rglob("*.py"):
        if py_file.name.startswith("test_") or py_file.name.endswith("_test.py"):
            resolved = str(py_file.resolve())
            if py_file == (root_dir / "test_provenance.py"):
                continue
            if resolved not in promoted_test_files:
                errors.append(f"Unregistered test file detected: {py_file.relative_to(root_dir)}")

    is_valid = len(errors) == 0
    if is_valid:
        messages.insert(
            0,
            f"Provenance verification PASSED: {len(manifest_relpaths)} archived files verified, "
            f"aggregate sha256: {actual_aggregate[:16]}...",
        )
    return is_valid, errors if errors else messages


def main() -> int:
    """CLI entrypoint for capture and verify."""
    parser = argparse.ArgumentParser(description="Probe provenance capture and verification")
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture", help="Capture probes into archive")
    capture_parser.add_argument(
        "--spec", required=True, type=Path, help="Path to probe_sources.json"
    )
    capture_parser.add_argument(
        "--dest", required=True, type=Path, help="Destination archive directory"
    )

    verify_parser = subparsers.add_parser("verify", help="Verify archive and provenance")
    verify_parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Root directory (e.g. tests/independent)",
    )

    args = parser.parse_args()

    if args.command == "capture":
        try:
            manifest = capture(args.spec, args.dest)
            print(f"Captured {manifest['file_count']} files to {args.dest}")
            print(f"Aggregate SHA-256: {manifest['aggregate_sha256']}")
            return 0
        except (
            RuntimeError,
            ValueError,
            FileNotFoundError,
            json.JSONDecodeError,
            OSError,
        ) as exc:
            print(f"Error during capture: {exc}", file=sys.stderr)
            return 1

    elif args.command == "verify":
        valid, msgs = verify(args.root)
        for msg in msgs:
            print(msg)
        return 0 if valid else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())

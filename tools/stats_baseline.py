#!/usr/bin/env python3
"""Scoped v1.6.0 baseline guard for the PSE&G statistics surfaces.

The manifest under ``tests/fixtures/`` pins the exact bytes of a declared subset
of statistics writer/state/parser functions and module constants as of commit
``00ba6b3`` (v1.6.0). Selected surfaces only: this tool never claims that a whole
module, a file or the integration is unchanged.

Comparison rule per surface:

* ``equal`` - the normalized segment is the manifested baseline segment;
* ``approved-expected-delta`` - the segment matches the ``new_sha256`` of a
  recorded approval whose ``old_sha256`` is the manifested baseline and whose
  behavioural ``evidence`` and ``reviewer`` are stated;
* ``unreviewed-change`` - anything else, including a missing file, a missing or
  ambiguous surface, and an unparseable module. This is a nonzero exit.

The tool reads the manifest plus the explicit ``--source`` tree only. It never
runs git, never imports or executes the inspected modules (``ast`` parsing only)
and never rewrites the manifest, so a change cannot be green by regeneration.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

MANIFEST_SCHEMA = 1
DEFAULT_MANIFEST = "tests/fixtures/statistics_baseline_v1_6_0.json"
SCOPE = "selected-surfaces-only"

STATUS_EQUAL = "equal"
STATUS_APPROVED = "approved-expected-delta"
STATUS_UNREVIEWED = "unreviewed-change"

FUNCTION_KINDS = ("function", "method")
SURFACE_KINDS = (*FUNCTION_KINDS, "assignment")


class ManifestError(Exception):
    """The manifest is missing, unreadable or structurally unusable."""

    def __init__(self, code: str, **context: Any) -> None:
        """Store a fixed public code plus context."""
        super().__init__(code)
        self.code = code
        self.context = context


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #


def normalize_segment(segment: str) -> str:
    """Normalize one extracted source segment exactly as declared in the manifest.

    Declared transformations, in order, and nothing else:

    1. CRLF and lone CR line endings become LF;
    2. each line has trailing whitespace removed (``rstrip()``);
    3. leading and trailing blank lines are removed;
    4. the result is joined with LF and has no trailing newline.
    """
    text = segment.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def digest_segment(segment: str) -> str:
    """Return the sha256 hex digest of the normalized segment bytes."""
    return hashlib.sha256(normalize_segment(segment).encode("utf-8")).hexdigest()


def _module_nodes(tree: ast.Module, name: str) -> list[ast.AST]:
    """Return module-level nodes matching a bare surface name."""
    if "." in name:
        class_name, _, attribute = name.partition(".")
        matches: list[ast.AST] = []
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                matches.extend(
                    child
                    for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name == attribute
                )
        return matches
    matches = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            matches.append(node)
        elif isinstance(node, ast.Assign):
            targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if targets == [name]:
                matches.append(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                matches.append(node)
    return matches


def extract_digest(source_root: Path, path: str, kind: str, name: str) -> tuple[str | None, str]:
    """Return ``(sha256, detail)`` for one declared surface, parsed with ast only."""
    file_path = source_root / path
    if not file_path.is_file():
        return None, "file_missing"
    try:
        source = file_path.read_bytes().decode("utf-8")
    except OSError:
        return None, "file_unreadable"
    except UnicodeDecodeError:
        return None, "file_unreadable"
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return None, "file_unparseable"
    except ValueError:
        return None, "file_unparseable"
    nodes = _module_nodes(tree, name)
    if not nodes:
        return None, "surface_missing"
    if len(nodes) > 1:
        return None, "surface_ambiguous"
    if kind not in FUNCTION_KINDS and not isinstance(nodes[0], (ast.Assign, ast.AnnAssign)):
        return None, "surface_kind_mismatch"
    if kind in FUNCTION_KINDS and not isinstance(nodes[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None, "surface_kind_mismatch"
    segment = ast.get_source_segment(source, nodes[0], padded=False)
    if segment is None:
        return None, "segment_unavailable"
    return digest_segment(segment), "ok"


def file_digest(source_root: Path, path: str) -> str | None:
    """Return the informational whole-file sha256, or None when unreadable."""
    file_path = source_root / path
    try:
        return hashlib.sha256(file_path.read_bytes()).hexdigest()
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Manifest handling
# --------------------------------------------------------------------------- #


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and structurally validate the baseline manifest."""
    try:
        raw = path.read_bytes()
    except OSError:
        raise ManifestError("manifest_missing", path=str(path)) from None
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise ManifestError("manifest_unparseable", path=str(path)) from None
    except ValueError:
        raise ManifestError("manifest_unparseable", path=str(path)) from None
    if not isinstance(manifest, dict):
        raise ManifestError("manifest_invalid", path=str(path))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ManifestError("manifest_schema_unsupported", schema=manifest.get("schema"))
    surfaces = manifest.get("surfaces")
    if not isinstance(surfaces, list) or not surfaces:
        raise ManifestError("manifest_invalid", reason="no_surfaces")
    seen: set[tuple[str, str, str]] = set()
    for surface in surfaces:
        if not isinstance(surface, dict):
            raise ManifestError("manifest_invalid", reason="surface_not_object")
        for key in ("group", "path", "kind", "name", "sha256"):
            if not isinstance(surface.get(key), str) or not surface.get(key):
                raise ManifestError("manifest_invalid", reason=f"surface_{key}")
        if surface["kind"] not in SURFACE_KINDS:
            raise ManifestError("manifest_invalid", reason="surface_kind")
        if not isinstance(surface.get("approved_deltas", []), list):
            raise ManifestError("manifest_invalid", reason="approved_deltas")
        identity = (surface["path"], surface["kind"], surface["name"])
        if identity in seen:
            raise ManifestError("manifest_invalid", reason="duplicate_surface")
        seen.add(identity)
    manifest["_digest"] = hashlib.sha256(raw).hexdigest()
    return manifest


def _approval(surface: dict[str, Any], observed: str) -> dict[str, Any] | None:
    """Return the reviewed approval covering ``observed`` for this surface."""
    for approval in surface.get("approved_deltas", []):
        if not isinstance(approval, dict):
            continue
        evidence = approval.get("evidence")
        reviewer = approval.get("reviewer")
        if not isinstance(evidence, str) or not evidence.strip():
            continue
        if not isinstance(reviewer, str) or not reviewer.strip():
            continue
        if approval.get("old_sha256") != surface["sha256"]:
            continue
        if approval.get("new_sha256") != observed:
            continue
        return {
            "old_sha256": approval["old_sha256"],
            "new_sha256": approval["new_sha256"],
            "evidence": evidence,
            "reviewer": reviewer,
        }
    return None


def compare(manifest: dict[str, Any], source_root: Path) -> dict[str, Any]:
    """Compare every manifested surface against the source tree."""
    rows: list[dict[str, Any]] = []
    for surface in manifest["surfaces"]:
        observed, detail = extract_digest(
            source_root, surface["path"], surface["kind"], surface["name"]
        )
        baseline = surface["sha256"]
        approval = None
        if observed is None:
            status = STATUS_UNREVIEWED
        elif observed == baseline:
            status = STATUS_EQUAL
        else:
            approval = _approval(surface, observed)
            status = STATUS_APPROVED if approval is not None else STATUS_UNREVIEWED
        row: dict[str, Any] = {
            "group": surface["group"],
            "path": surface["path"],
            "kind": surface["kind"],
            "name": surface["name"],
            "baseline_sha256": baseline,
            "observed_sha256": observed,
            "status": status,
            "detail": detail,
        }
        if surface.get("v1_6_0_change"):
            row["v1_6_0_change"] = surface["v1_6_0_change"]
        if approval is not None:
            row["approval"] = approval
        rows.append(row)

    groups: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = groups.setdefault(
            row["group"],
            {status: 0 for status in (STATUS_EQUAL, STATUS_APPROVED, STATUS_UNREVIEWED)},
        )
        bucket[row["status"]] += 1

    # Whole-file digests are provenance only: they are never used to claim that
    # unselected code in the same file is unchanged.
    files: dict[str, dict[str, Any]] = {}
    for surface in manifest["surfaces"]:
        path = surface["path"]
        entry = files.setdefault(
            path,
            {
                "path": path,
                "baseline_file_sha256": surface.get("baseline_file_sha256"),
                "observed_file_sha256": file_digest(source_root, path),
                "selected_surface_count": 0,
                "selected_surfaces_equal": True,
                "file_identity_claimed": False,
            },
        )
        entry["selected_surface_count"] += 1
        row = next(
            item
            for item in rows
            if item["path"] == path
            and item["kind"] == surface["kind"]
            and item["name"] == surface["name"]
        )
        if row["status"] != STATUS_EQUAL:
            entry["selected_surfaces_equal"] = False
    for entry in files.values():
        baseline = entry["baseline_file_sha256"]
        entry["file_digest_changed"] = (
            baseline is not None and entry["observed_file_sha256"] != baseline
        )
        entry["file_digest_is_informational_only"] = True

    unreviewed = [row for row in rows if row["status"] == STATUS_UNREVIEWED]
    approved = [row for row in rows if row["status"] == STATUS_APPROVED]
    known_parser_changes = [
        {
            "path": row["path"],
            "name": row["name"],
            "change": row["v1_6_0_change"].get("change"),
            "old_sha256": row["v1_6_0_change"].get("old_sha256"),
            "new_sha256": row["v1_6_0_change"].get("new_sha256"),
            "evidence": row["v1_6_0_change"].get("evidence"),
            "reviewer": row["v1_6_0_change"].get("reviewer"),
        }
        for row in rows
        if row.get("v1_6_0_change")
    ]
    return {
        "tool": "stats_baseline",
        "ok": not unreviewed,
        "scope": SCOPE,
        "blanket_module_or_file_identity_claimed": False,
        "baseline": manifest.get("baseline", {}),
        "manifest_digest": manifest["_digest"],
        "normalization": manifest.get("normalization", {}),
        "surfaces_total": len(rows),
        "equal": sum(1 for row in rows if row["status"] == STATUS_EQUAL),
        "approved_expected_delta": len(approved),
        "unreviewed": len(unreviewed),
        "groups": groups,
        "known_v1_6_0_parser_changes": known_parser_changes,
        "surfaces": rows,
        "approved_deltas": approved,
        "unreviewed_changes": unreviewed,
        "informational_file_digests": sorted(files.values(), key=lambda item: item["path"]),
    }


def run(manifest_path: Path, source_root: Path) -> tuple[int, dict[str, Any]]:
    """Run one comparison; return the exit code and the structured report."""
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as err:
        return 1, {"tool": "stats_baseline", "ok": False, "error": err.code, **err.context}
    if not source_root.is_dir():
        return 1, {
            "tool": "stats_baseline",
            "ok": False,
            "error": "source_not_directory",
            "source": str(source_root),
        }
    report = compare(manifest, source_root)
    return (0 if report["ok"] else 1), report


def _summary(report: dict[str, Any]) -> list[str]:
    """Render the human-facing summary lines (never the machine report)."""
    if report.get("error"):
        return [f"stats-baseline: {report['error']}"]
    baseline = report["baseline"]
    lines = [
        f"stats-baseline: {baseline.get('tag', '?')} @ {baseline.get('commit', '?')[:12]} "
        f"({report['surfaces_total']} selected surfaces, scope={report['scope']})"
    ]
    for group, counts in sorted(report["groups"].items()):
        lines.append(
            f"  {group}: equal={counts.get(STATUS_EQUAL, 0)} "
            f"approved={counts.get(STATUS_APPROVED, 0)} "
            f"unreviewed={counts.get(STATUS_UNREVIEWED, 0)}"
        )
    for row in report["unreviewed_changes"]:
        lines.append(
            f"  UNREVIEWED {row['path']}::{row['name']} ({row['kind']}, {row['detail']}) "
            f"baseline={row['baseline_sha256']} observed={row['observed_sha256']}"
        )
    for row in report["approved_deltas"]:
        lines.append(
            f"  APPROVED {row['path']}::{row['name']} {row['approval']['old_sha256'][:12]} -> "
            f"{row['approval']['new_sha256'][:12]} ({row['approval']['reviewer']})"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: structured report on stdout, summary on stderr."""
    parser = argparse.ArgumentParser(
        prog="stats_baseline",
        description="Compare selected statistics surfaces with the v1.6.0 baseline manifest",
    )
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--source", default=".", help="Tree holding the manifested paths")
    parser.add_argument("--json", action="store_true", help="Emit the report as indented JSON")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2
    code, report = run(Path(args.manifest), Path(args.source))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(json.dumps(report, sort_keys=True))
    print("\n".join(_summary(report)), file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""ha-pseg release check and snapshot tooling.

Currently implements freeze and snapshot subcommands (P1-01).
Additional profiles (fast, node, independent, mutation, all) arrive in P1-09.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_TOOLS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TOOLS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools._snapshot import (  # noqa: E402
    CleanupRefused,
    SnapshotError,
    freeze,
    snapshot,
)


def _emit_error(code: str, **context: object) -> None:
    payload = {"ok": False, "error": code, **context}
    print(json.dumps(payload, sort_keys=True), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="release_check",
        description="ha-pseg release and validation runner",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # freeze
    freeze_parser = subparsers.add_parser("freeze", help="Freeze candidate manifest")
    freeze_parser.add_argument(
        "--source", default=".", help="Source path (git worktree or snapshot)"
    )
    freeze_parser.add_argument("--json", action="store_true", help="Emit manifest JSON")
    freeze_parser.add_argument(
        "--paths-from",
        default=None,
        help="Explicit file containing paths to include",
    )

    # snapshot
    snapshot_parser = subparsers.add_parser(
        "snapshot", help="Create independent safe snapshot"
    )
    snapshot_parser.add_argument(
        "--source", default=".", help="Source path (git worktree or snapshot)"
    )
    snapshot_parser.add_argument(
        "--dest", required=True, help="Destination directory (must not exist)"
    )
    snapshot_parser.add_argument(
        "--paths-from",
        default=None,
        help="Explicit file containing paths to include",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        if args.subcommand == "freeze":
            manifest = freeze(source=args.source, paths_from=args.paths_from)
            if args.json:
                print(json.dumps(manifest, indent=2, sort_keys=True))
            else:
                print(
                    f"Frozen {manifest['count']} files; "
                    f"head={manifest['head']} aggregate={manifest['sha256']}"
                )
            return 0
        elif args.subcommand == "snapshot":
            res = snapshot(
                source=args.source, dest=args.dest, paths_from=args.paths_from
            )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "files": res["count"],
                        "sha256": res["sha256"],
                        "head": res["head"],
                        "dest": res.get("dest", args.dest),
                    },
                    sort_keys=True,
                )
            )
            return 0
        else:
            _emit_error("unknown_subcommand", subcommand=args.subcommand)
            return 1
    except SnapshotError as err:
        _emit_error(err.code, **err.context)
        return 1
    except CleanupRefused:
        _emit_error("cleanup_refused")
        return 1
    except OSError:
        _emit_error("io_error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

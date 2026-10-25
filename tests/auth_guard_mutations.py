"""Compatibility entry point for the copy-only auth mutation engine."""

import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.mutation_check import main as mutation_main  # noqa: E402


def main() -> int:
    return mutation_main([
        "--source", str(ROOT),
        "--python", os.environ.get("PSEG_TEST_PYTHON", sys.executable),
        "--table", str(ROOT / "tests/mutations/auth_guards.py"),
        *sys.argv[1:],
    ])


if __name__ == "__main__":
    raise SystemExit(main())

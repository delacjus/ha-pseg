"""Run the energy card's Node tests as part of the pytest suite."""

import shutil
import subprocess
import unittest
from pathlib import Path

CARD_TESTS = Path(__file__).parent / "test_energy_card.js"


@unittest.skipIf(shutil.which("node") is None, "Node.js is not installed")
class TestEnergyCard(unittest.TestCase):
    def test_card(self):
        result = subprocess.run(
            ["node", "--test", str(CARD_TESTS)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

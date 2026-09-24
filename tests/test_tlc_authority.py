import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.check_tlc_authority import (
    DEFAULT_JAR,
    PINNED_SHA256,
    build_command,
    validate_refinement_fixture,
)

ROOT = Path(__file__).parents[1]


class TLCAuthorityTests(unittest.TestCase):
    def test_pinned_local_artifact_and_exact_command(self):
        digest = hashlib.sha256(DEFAULT_JAR.read_bytes()).hexdigest()
        self.assertEqual(digest, PINNED_SHA256)
        command = build_command(
            DEFAULT_JAR,
            ROOT / "formal/authority/AuthorityInteraction.tla",
            ROOT / "formal/authority/AuthorityInteraction.cfg",
        )
        self.assertEqual(command[1:5], ["-cp", str(DEFAULT_JAR), "tlc2.TLC", "-config"])
        self.assertEqual(command[-2:], [str(ROOT / "formal/authority/AuthorityInteraction.cfg"), str(ROOT / "formal/authority/AuthorityInteraction.tla")])

    def test_missing_jar_fails_closed_without_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "scripts/check_tlc_authority.py", "--jar", str(Path(directory) / "missing.jar")],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL CLOSED", result.stderr)

    def test_positive_and_hostile_fixture_bindings(self):
        positive = json.loads((ROOT / "specifications/fixtures/authority-interaction-ar0099-v1.json").read_text())
        hostile = json.loads((ROOT / "specifications/fixtures/authority-interaction-ar0099-hostile-v1.json").read_text())
        self.assertEqual(positive["refinement_target"]["protocol"], "awr-authority-interaction-model")
        self.assertEqual(positive["offline"]["network"], "disabled")
        self.assertGreaterEqual(len(positive["positive_paths"]), 4)
        self.assertGreaterEqual(len(hostile["counterexamples"]), 10)
        self.assertTrue(all(case["expected"] in {"rejected", "blocked"} for case in hostile["counterexamples"]))
        validate_refinement_fixture()


if __name__ == "__main__":
    unittest.main()

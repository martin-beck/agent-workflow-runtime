import tempfile
import unittest
from pathlib import Path

from awr_cli.qualification import run_concurrent


class QualificationTests(unittest.TestCase):
    def test_isolated_projects_run_concurrently(self):
        with tempfile.TemporaryDirectory() as root:
            result = run_concurrent(Path(root), 3)
            self.assertEqual(result["status"], "qualified")
            self.assertTrue(result["parallel"])
            self.assertEqual([item["status"] for item in result["projects"]], ["accepted"] * 3)
            self.assertEqual(len({item["artifact_digest"] for item in result["projects"]}), 3)
            self.assertEqual(len({item["scheduler"] for item in result["projects"]}), 3)

    def test_count_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "count"):
            run_concurrent(Path(tempfile.mkdtemp()), 1)


if __name__ == "__main__":
    unittest.main()

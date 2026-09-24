import json
import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError
from awr_cli.project_bootstrap import bootstrap
from awr_cli.project_registry import list_projects, register


class ProjectRegistryTests(unittest.TestCase):
    def test_registers_two_projects_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); home = root / "runtime"
            bootstrap("alpha-system", "example-org", root / "alpha", root / "alpha-state")
            bootstrap("beta-system", "example-org", root / "beta", root / "beta-state")
            self.assertEqual(register("alpha-system", root / "alpha", root / "alpha-state", home)["status"], "registered")
            self.assertEqual(register("alpha-system", root / "alpha", root / "alpha-state", home)["status"], "already_registered")
            self.assertEqual(register("beta-system", root / "beta", root / "beta-state", home)["count"], 2)
            self.assertEqual([item["name"] for item in list_projects(home)["projects"]], ["alpha-system", "beta-system"])

    def test_cross_project_binding_conflict_and_missing_binding_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); home = root / "runtime"
            bootstrap("alpha-system", "example-org", root / "alpha", root / "alpha-state")
            register("alpha-system", root / "alpha", root / "alpha-state", home)
            bootstrap("alpha-system", "example-org", root / "alpha-two", root / "alpha-two-state")
            with self.assertRaisesRegex(CliError, "conflict"):
                register("alpha-system", root / "alpha-two", root / "alpha-two-state", home)
            with self.assertRaisesRegex(CliError, "invalid"):
                register("beta-system", root / "missing", root / "missing-state", home)

    def test_corrupt_registry_does_not_get_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); home = root / "runtime"; home.mkdir()
            (home / "projects.json").write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(CliError, "corrupt"):
                list_projects(home)
            self.assertEqual((home / "projects.json").read_text(), "{broken")


if __name__ == "__main__":
    unittest.main()

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from awr_cli.existing_project_setup import setup_existing
from awr_cli.cli import CliError


class ExistingProjectSetupTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        return subprocess.run(["git", "-C", str(root), *args], check=True, text=True,
                              stdout=subprocess.PIPE).stdout.strip()

    def repo(self, root: Path) -> Path:
        project = root / "existing-project"
        project.mkdir()
        self.git(root, "init", "-b", "main", str(project))
        (project / "README.md").write_text("existing\n")
        self.git(project, "add", "README.md")
        self.git(project, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "initial")
        return project

    def test_setup_adopts_existing_git_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); project = self.repo(root); home = root / "awr-home"
            first = setup_existing(project, home=home)
            self.assertEqual(first["status"], "ready")
            self.assertTrue((project / ".awr-project-binding.json").exists())
            self.assertTrue((project / ".awr" / "workflow-graph.json").exists())
            second = setup_existing(project, home=home)
            self.assertEqual(second["registry"]["status"], "already_registered")
            self.assertEqual(json.loads((project / ".awr" / "state" / "agent-workflow-state.json").read_text())["lifecycle"], "ready")

    def test_dirty_existing_project_requires_explicit_opt_in_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); project = self.repo(root); home = root / "awr-home"
            (project / "README.md").write_text("changed\n")
            with self.assertRaisesRegex(CliError, "dirty"):
                setup_existing(project, home=home)
            result = setup_existing(project, home=home, allow_dirty=True)
            self.assertTrue(result["git_dirty"])
            self.assertEqual((project / "README.md").read_text(), "changed\n")

    def test_non_git_and_managed_conflict_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); project = root / "plain"; project.mkdir(); (project / "file").write_text("x")
            with self.assertRaisesRegex(CliError, "not_a_git"):
                setup_existing(project, home=root / "home")
            project = self.repo(root); (project / ".awr-project-binding.json").write_text("{}")
            with self.assertRaisesRegex(CliError, "managed_file_conflict"):
                setup_existing(project, home=root / "home2")

    def test_start_runs_the_initial_controlled_local_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); project = self.repo(root)
            result = setup_existing(project, home=root / "home", start=True)
            self.assertEqual(result["started"]["tasks"]["AR-9001"], "completed")
            self.assertTrue((project / ".awr" / "run" / "run.json").exists())


if __name__ == "__main__":
    unittest.main()

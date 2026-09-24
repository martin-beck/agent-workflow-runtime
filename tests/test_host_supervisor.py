import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError
from awr_cli.host_supervisor import HostSupervisor


class HostSupervisorTests(unittest.TestCase):
    def test_bounded_success_and_allowlisted_environment(self):
        with tempfile.TemporaryDirectory() as root:
            worktree = Path(root) / "project"; worktree.mkdir()
            result = HostSupervisor(Path(root)).run(["python3", "-c", "print('ok')"], worktree, env={"AWR_TEST": "yes"}, allowed_env=["AWR_TEST"], require_network_disabled=False)
            self.assertEqual(result["status"], "ok")
            self.assertIn("ok", result["stdout"])
            self.assertTrue(result["controls"]["worktree_boundary"])

    def test_timeout_kills_process_group(self):
        with tempfile.TemporaryDirectory() as root:
            worktree = Path(root) / "project"; worktree.mkdir()
            result = HostSupervisor(Path(root)).run(["python3", "-c", "import time; time.sleep(10)"], worktree, timeout_seconds=0.05, require_network_disabled=False)
            self.assertEqual(result["status"], "timeout")
            self.assertTrue(result["controls"]["process_group_cleanup"])

    def test_escape_and_unallowlisted_environment_fail_closed(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            with self.assertRaisesRegex(CliError, "escape"):
                HostSupervisor(Path(root)).run(["true"], Path(outside), require_network_disabled=False)
            worktree = Path(root) / "project"; worktree.mkdir()
            with self.assertRaisesRegex(CliError, "allowlisted"):
                HostSupervisor(Path(root)).run(["true"], worktree, env={"SECRET": "x"}, require_network_disabled=False)

    def test_network_requirement_is_explicitly_unsupported(self):
        with tempfile.TemporaryDirectory() as root:
            worktree = Path(root) / "project"; worktree.mkdir()
            with self.assertRaisesRegex(CliError, "network"):
                HostSupervisor(Path(root)).run(["true"], worktree)


if __name__ == "__main__":
    unittest.main()

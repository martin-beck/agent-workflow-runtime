import tempfile
import unittest
from pathlib import Path

from awr_cli.agent_session import AgentSession, fake_digest
from awr_cli.cli import CliError


class AgentSessionTests(unittest.TestCase):
    def test_two_adapters_share_lifecycle_without_provider(self):
        with tempfile.TemporaryDirectory() as root:
            worktree = Path(root) / "project"; worktree.mkdir()
            command = ["python3", "-c", "print('deterministic')"]
            first = AgentSession(Path(root), "SES-FAKE-A", "fake-alpha").run(command, worktree, input_digest=fake_digest("input"))
            second = AgentSession(Path(root), "SES-FAKE-B", "fake-beta").run(command, worktree, input_digest=fake_digest("input"))
            self.assertEqual(first["status"], "completed")
            self.assertEqual(second["status"], "completed")
            self.assertEqual(first["result"]["stdout"], second["result"]["stdout"])
            self.assertEqual([event["kind"] for event in first["events"]], ["session_admitted", "session_started", "session_terminal"])

    def test_invalid_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            worktree = Path(root) / "project"; worktree.mkdir()
            with self.assertRaisesRegex(CliError, "digest"):
                AgentSession(Path(root), "SES-FAKE-A", "fake-alpha").run(["true"], worktree, input_digest="bad")


if __name__ == "__main__":
    unittest.main()

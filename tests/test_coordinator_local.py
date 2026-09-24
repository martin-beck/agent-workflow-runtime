import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError
from awr_cli.coordinator_local import LocalCoordinator


class LocalCoordinatorTests(unittest.TestCase):
    def test_init_claim_heartbeat_and_terminal_reconciliation(self):
        with tempfile.TemporaryDirectory() as root:
            store = LocalCoordinator(Path(root) / "state" / "coordinator.json")
            digest = "sha256:" + "a" * 64
            first = store.init("AR-0113", digest, "sha256:" + "b" * 64, "SES-LOCAL-1")
            self.assertEqual(first["task"]["status"], "open")
            claimed = store.claim("WRK-LOCAL-1", 1)
            self.assertEqual(claimed["task"]["lease"], "LSE-00000001")
            store.heartbeat("WRK-LOCAL-1", "LSE-00000001", 2)
            done = store.complete("WRK-LOCAL-1", "LSE-00000001", 2)
            self.assertEqual(done["task"]["status"], "done")

    def test_stale_crossed_duplicate_and_corrupt_operations_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "state.json"; store = LocalCoordinator(path)
            store.init("AR-0113", "sha256:" + "a" * 64, "sha256:" + "b" * 64, "SES-LOCAL-1")
            with self.assertRaisesRegex(CliError, "stale"):
                store.claim("WRK-LOCAL-1", 2)
            store.claim("WRK-LOCAL-1", 1)
            with self.assertRaisesRegex(CliError, "fence"):
                store.complete("WRK-OTHER", "LSE-00000001", 2)
            with self.assertRaisesRegex(CliError, "not_claimable"):
                store.claim("WRK-OTHER", 2)
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(CliError, "corrupt"):
                store.snapshot()


if __name__ == "__main__":
    unittest.main()

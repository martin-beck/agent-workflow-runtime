import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError
from awr_cli.scheduler_local import LocalScheduler


class LocalSchedulerTests(unittest.TestCase):
    def test_dependency_dispatch_completion_and_restart(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "scheduler.json"; scheduler = LocalScheduler(path)
            scheduler.submit("JOB-A", "alpha", priority=10); scheduler.submit("JOB-B", "alpha", dependencies=["JOB-A"], priority=100)
            lease = scheduler.dispatch("WRK-ONE")["job"]["lease"]; scheduler.complete("JOB-A", "WRK-ONE", lease["id"])
            lease = LocalScheduler(path).dispatch("WRK-TWO")["job"]["lease"]; view = LocalScheduler(path).complete("JOB-B", "WRK-TWO", lease["id"])
            self.assertEqual(view["jobs"]["JOB-B"]["state"], "done")

    def test_capacity_fence_retry_and_missing_dependency_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            scheduler = LocalScheduler(Path(root) / "scheduler.json", max_concurrency=1)
            with self.assertRaisesRegex(CliError, "dependency"):
                scheduler.submit("JOB-B", "alpha", dependencies=["JOB-X"])
            scheduler.submit("JOB-A", "alpha", retry_limit=1)
            lease = scheduler.dispatch("WRK-ONE")["job"]["lease"]
            with self.assertRaisesRegex(CliError, "capacity"):
                scheduler.dispatch("WRK-TWO")
            with self.assertRaisesRegex(CliError, "fence"):
                scheduler.complete("JOB-A", "WRK-TWO", lease["id"])
            scheduler.complete("JOB-A", "WRK-ONE", lease["id"], status="failed")
            self.assertEqual(scheduler.dispatch("WRK-ONE")["job"]["attempts"], 2)


if __name__ == "__main__":
    unittest.main()

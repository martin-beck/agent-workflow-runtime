import unittest
from pathlib import Path

from scripts.check_durable_scheduler import load, validate, validate_spec
from scripts.durable_scheduler import Job, Resources, Scheduler, SchedulerError

ROOT = Path(__file__).parents[1]


class DurableSchedulerTests(unittest.TestCase):
    def test_canonical_fixture(self):
        spec = load(ROOT / "specifications/durable-scheduler-v1.json")
        fixture = load(ROOT / "specifications/fixtures/durable-scheduler-ar0062-v1.json")
        validate_spec(spec, 1)
        result = validate(fixture)
        self.assertEqual(result["states"]["JOB-B"], "succeeded")
        self.assertFalse(result["execute"])

    def setUp(self):
        self.scheduler = Scheduler(Resources(2, 2, 2), max_concurrency=2, max_queued=2, lease_seconds=3, tenant_limits={"a": 1}, aging_quantum=2)
        self.scheduler.admit("ADMIT-A", Job("A", priority=90, tenant="a", resources=Resources(1, 1, 1), max_attempts=2))
        self.scheduler.admit("ADMIT-B", Job("B", priority=10, tenant="b", resources=Resources(1, 1, 1), max_attempts=1))

    def test_dependency_release_backpressure_and_resource_reservation(self):
        self.scheduler.admit("ADMIT-C", Job("C", priority=50, tenant="b"))
        self.assertEqual(self.scheduler.release_dependencies(0), ["A", "B"])
        self.scheduler.admit("ADMIT-D", Job("D"))
        self.assertEqual(self.scheduler.jobs["D"].state, "submitted")
        lease = self.scheduler.dispatch("DISPATCH-A", "worker-a", 0)
        self.assertEqual(lease.job_id, "A")
        self.assertEqual(self.scheduler.available, Resources(1, 1, 1))
        second = self.scheduler.dispatch("DISPATCH-B", "worker-b", 0)
        self.assertEqual(second.job_id, "C")
        self.assertEqual(self.scheduler.available, Resources(0, 0, 0))

    def test_lease_fencing_expiry_retry_checkpoint_and_idempotency(self):
        self.scheduler.release_dependencies(0)
        lease = self.scheduler.dispatch("DISPATCH", "worker-a", 0)
        self.scheduler.checkpoint("CHECKPOINT", "A", "worker-a", lease.lease_id, "sha256:" + "a" * 64, 1)
        replay = self.scheduler.dispatch("DISPATCH", "worker-a", 0)
        self.assertEqual(replay, lease)
        with self.assertRaises(SchedulerError):
            self.scheduler.heartbeat("STALE", "A", "worker-a", lease.lease_id, 3)
        self.scheduler.expire(3)
        self.assertEqual(self.scheduler.jobs["A"].state, "queued")
        new_lease = self.scheduler.dispatch("DISPATCH-NEW", "worker-b", 3)
        self.assertEqual(new_lease.fence, 2)
        self.scheduler.fail("FAIL", "A", "worker-b", new_lease.lease_id, "worker_lost", 4)
        with self.assertRaises(SchedulerError):
            self.scheduler.fail("FAIL", "A", "worker-b", new_lease.lease_id, "other", 4)

    def test_aging_starvation_prevention_and_terminal_reconciliation(self):
        self.scheduler.release_dependencies(0)
        self.scheduler.jobs["B"].queued_at = 0
        self.scheduler.now = 100
        self.assertEqual(self.scheduler.dispatch("FAIR", "worker", 100).job_id, "A")
        self.scheduler.complete("DONE", "A", "worker", "LSE-A-1", 100)
        self.assertEqual(self.scheduler.dispatch("FAIR-B", "worker", 100).job_id, "B")

    def test_hostile_unknown_dependency_cancel_and_conflicting_replay(self):
        with self.assertRaises(SchedulerError):
            self.scheduler.admit("BAD", Job("bad", dependencies=("missing",)))
        self.scheduler.release_dependencies(0)
        self.scheduler.request_cancel("CANCEL", "B", 0)
        self.assertEqual(self.scheduler.jobs["B"].state, "cancelled")
        with self.assertRaises(SchedulerError):
            self.scheduler.request_cancel("CANCEL", "A", 1)


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.check_lease_service import check, check_spec, load
from scripts.lease_service import (
    LeaseBinding,
    LeaseError,
    LeaseService,
    LocalCoordinatorFake,
    UnknownLeaseOutcome,
    run_interleaving,
)

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/lease-service-v1.json"
FIXTURE = ROOT / "specifications/fixtures/lease-service-ar0082-v1.json"


class LeaseServiceTests(unittest.TestCase):
    def setUp(self):
        self.binding = LeaseBinding("AR-0082", "agent-workflow-runtime", "agent-workflow-runtime-0082")
        self.fake = LocalCoordinatorFake(self.binding)
        self.service = LeaseService(self.fake, self.binding)

    def test_spec_fixture_and_checker(self):
        spec, fixture = load(SPEC), load(FIXTURE)
        check_spec(spec)
        result = check(spec, fixture, 3)
        self.assertEqual((result["operations"], result["counterexamples"], result["fence"]), (5, 2, 3))

    def test_cas_and_no_double_owner_under_competing_acquire(self):
        first = self.service.acquire("OP-AR0082-A", expected_revision=1, owner_id="WRK-A", lease_id="LSE-A", now=1, expires=4)
        self.assertEqual((first["owner_id"], first["fence"]), ("WRK-A", 1))
        with self.assertRaises(LeaseError) as error:
            self.service.acquire("OP-AR0082-B", expected_revision=1, owner_id="WRK-B", lease_id="LSE-B", now=1, expires=4)
        self.assertEqual(str(error.exception), "stale_cas_revision")
        self.assertEqual(self.fake.owner_id, "WRK-A")

    def test_heartbeat_requires_strict_monotonic_time_and_expiry(self):
        self.service.acquire("OP-AR0082-A", expected_revision=1, owner_id="WRK-A", lease_id="LSE-A", now=1, expires=4)
        with self.assertRaises(LeaseError):
            self.service.heartbeat("OP-AR0082-H0", expected_revision=2, owner_id="WRK-A", lease_id="LSE-A", fence=1, now=1, expires=5)
        with self.assertRaises(LeaseError):
            self.service.heartbeat("OP-AR0082-H1", expected_revision=2, owner_id="WRK-A", lease_id="LSE-A", fence=1, now=2, expires=4)
        good = self.service.heartbeat("OP-AR0082-H2", expected_revision=2, owner_id="WRK-A", lease_id="LSE-A", fence=1, now=2, expires=6)
        self.assertEqual(good["task_revision"], 3)

    def test_handoff_and_expiry_recovery_increase_fence_and_fence_old_owner(self):
        self.service.acquire("OP-AR0082-A", expected_revision=1, owner_id="WRK-A", lease_id="LSE-A", now=1, expires=3)
        handoff = self.service.handoff("OP-AR0082-X", expected_revision=2, owner_id="WRK-A", lease_id="LSE-A", fence=1, new_owner_id="WRK-B", new_lease_id="LSE-B", now=2, expires=5)
        self.assertEqual(handoff["fence"], 2)
        with self.assertRaises(LeaseError):
            self.service.heartbeat("OP-AR0082-OLD", expected_revision=3, owner_id="WRK-A", lease_id="LSE-A", fence=1, now=3, expires=7)
        recovered = self.service.recover_expired("OP-AR0082-REC", expected_revision=3, owner_id="WRK-B", lease_id="LSE-B", fence=2, new_owner_id="WRK-C", new_lease_id="LSE-C", now=5, expires=8)
        self.assertEqual((recovered["owner_id"], recovered["fence"]), ("WRK-C", 3))

    def test_recovery_before_expiry_and_release_after_expiry_reject(self):
        self.service.acquire("OP-AR0082-A", expected_revision=1, owner_id="WRK-A", lease_id="LSE-A", now=1, expires=4)
        with self.assertRaises(LeaseError) as error:
            self.service.recover_expired("OP-AR0082-EARLY", expected_revision=2, owner_id="WRK-A", lease_id="LSE-A", fence=1, new_owner_id="WRK-B", new_lease_id="LSE-B", now=3, expires=7)
        self.assertEqual(str(error.exception), "lease_not_expired")
        with self.assertRaises(LeaseError) as error:
            self.service.release("OP-AR0082-LATE", expected_revision=2, owner_id="WRK-A", lease_id="LSE-A", fence=1, now=4)
        self.assertEqual(str(error.exception), "lease_expired")

    def test_ambiguous_delayed_and_identical_replay_are_safe(self):
        self.fake.inject("ambiguous_after_commit")
        with self.assertRaises(UnknownLeaseOutcome):
            self.service.acquire("OP-AR0082-A", expected_revision=1, owner_id="WRK-A", lease_id="LSE-A", now=1, expires=4)
        replay = self.service.acquire("OP-AR0082-A", expected_revision=1, owner_id="WRK-A", lease_id="LSE-A", now=1, expires=4)
        self.assertEqual(replay["task_revision"], 2)
        self.fake.inject("delay_response")
        with self.assertRaises(UnknownLeaseOutcome):
            self.service.heartbeat("OP-AR0082-H", expected_revision=2, owner_id="WRK-A", lease_id="LSE-A", fence=1, now=2, expires=6)
        self.assertEqual(self.fake.deliver_delayed()["task_revision"], 3)

    def test_changed_replay_and_crossed_binding_fail_closed(self):
        request = {"task_id": "AR-0082", "project_key": "agent-workflow-runtime", "worktree_key": "agent-workflow-runtime-0082", "operation": "acquire", "operation_id": "OP-AR0082-R", "expected_revision": 1, "now": 1, "owner_id": "WRK-A", "lease_id": "LSE-A", "new_expires": 4}
        self.fake.apply(request)
        changed = dict(request, new_expires=5)
        with self.assertRaises(LeaseError) as error:
            self.fake.apply(changed)
        self.assertEqual(str(error.exception), "changed_replay")
        with self.assertRaises(LeaseError) as error:
            self.fake.apply(dict(request, operation_id="OP-AR0082-CROSS", task_id="AR-0099"))
        self.assertEqual(str(error.exception), "crossed_binding")

    def test_deterministic_eight_worker_round_robin_has_one_owner(self):
        evidence = run_interleaving(self.fake, [f"WRK-{letter}" for letter in "ABCDEFGH"], rounds=5)
        self.assertEqual(len(evidence), 40)
        self.assertLessEqual(sum(item["result"] == "accepted" for item in evidence), 5)
        self.assertIsNone(self.fake.owner_id)
        self.assertEqual(self.fake.fence, 1)

    def test_fixture_counterexample_cannot_be_removed_or_accepted(self):
        fixture = load(FIXTURE)
        hostile = copy.deepcopy(fixture)
        hostile["counterexamples"] = []
        result = check(load(SPEC), hostile, 3)
        self.assertEqual(result["counterexamples"], 0)
        hostile["operations"][1]["response"]["fence"] = 99
        with self.assertRaises(LeaseError):
            check(load(SPEC), hostile, 3)


if __name__ == "__main__":
    unittest.main()

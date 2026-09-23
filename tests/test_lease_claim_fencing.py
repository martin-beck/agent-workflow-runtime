import copy
import unittest
from pathlib import Path

from scripts.check_lease_claim_fencing import CHECKER, check, digest, load
from scripts.lease_claim_fencing import LeaseError, LeaseStateMachine

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/lease-claim-fencing-v1.json"
FIXTURE = ROOT / "specifications/fixtures/lease-claim-fencing-ar0047-v1.json"


class LeaseClaimFencingTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(SPEC)
        self.record = load(FIXTURE)
        safe = dict(self.record["evidence"])
        safe.pop("safe_digest")
        self.record["evidence"]["safe_digest"] = digest(safe)

    def test_offline_ambiguous_replay_and_fencing_fixture(self):
        result = check(self.spec, self.record, 5)
        self.assertEqual(result["checker"], CHECKER)
        self.assertEqual(result["final_revision"], 8)
        self.assertEqual(result["owner"], None)
        self.assertEqual(result["fence"], 2)

    def test_stale_owner_and_changed_replay_fail_closed(self):
        state = LeaseStateMachine(5)
        claim = {"operation": "claim", "operation_id": "OP-1", "task_id": "AR-0047", "expected_revision": 5, "now": 1, "owner": "a", "lease": "l", "new_expires": 5}
        state.apply(claim)
        with self.assertRaises(LeaseError):
            state.apply({**claim, "now": 2})
        with self.assertRaises(LeaseError):
            state.apply({"operation": "heartbeat", "operation_id": "OP-2", "task_id": "AR-0047", "expected_revision": 6, "now": 2, "owner": "old", "lease": "l", "fence": 1, "new_expires": 8})

    def test_tampered_evidence_is_rejected(self):
        record = copy.deepcopy(self.record)
        record["evidence"]["network"] = "performed"
        with self.assertRaises(Exception):
            check(self.spec, record, 5)


if __name__ == "__main__":
    unittest.main()

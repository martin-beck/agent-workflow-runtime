import copy
import unittest
from pathlib import Path

from scripts.awq_evidence_transport import LocalAWQFake, TransportError, digest, project, validate_record
from scripts.check_awq_evidence_transport import check, load

ROOT = Path(__file__).parents[1]


class AWQEvidenceTransportTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(ROOT / "specifications/awq-evidence-transport-v1.json")
        self.record = load(ROOT / "specifications/fixtures/awq-evidence-transport-ar0052-v1.json")
        self.evidence = load(ROOT / "specifications/fixtures/awq-evidence-transport-evidence-ar0052-v1.json")

    def test_fixture_is_revision_bound_and_non_authorizing(self):
        result = check(self.spec, self.record, self.evidence, 5)
        self.assertEqual("accepted", result["status"])
        self.assertEqual("unverified", result["live_verification"])
        self.assertEqual("not_decided_by_runtime", project(self.record)["quality_status"])

    def test_acceptance_rejection_and_blocking_are_independent_awq_observations(self):
        for status in ("rejected", "blocked"):
            record = copy.deepcopy(self.record)
            record["gate"].update(status=status, ack_id=None)
            record["submission"]["state"] = status
            self.assertEqual(status, validate_record(record, 5)["status"])

    def test_stale_duplicate_private_and_self_approval_fail_closed(self):
        cases = []
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 4; cases.append(stale)
        duplicate = copy.deepcopy(self.record); duplicate["evidence"][1]["evidence_digest"] = duplicate["evidence"][0]["evidence_digest"]; cases.append(duplicate)
        private = copy.deepcopy(self.record); private["session"]["id"] = "SES-private-token"; cases.append(private)
        self_approval = copy.deepcopy(self.record); self_approval["gate"]["authority"] = "runtime"; cases.append(self_approval)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(TransportError): validate_record(candidate, 5)

    def test_local_fake_retries_idempotently_and_does_not_guess_unknown(self):
        binding = {key: self.record[key] for key in ("task", "project", "worktree", "session")}
        fake = LocalAWQFake(binding, [{"status": "accepted", "ack_id": "ACK-AR0052"}])
        request = {"binding": binding, "operation_id": "OP-AR0052-SUBMIT", "attempt": 2}
        first = fake.submit(request)
        self.assertEqual(first, fake.submit(request))
        changed = dict(request, evidence_digest="sha256:" + "9" * 64)
        with self.assertRaisesRegex(TransportError, "changed replay"): fake.submit(changed)
        unknown = LocalAWQFake(binding, [])
        self.assertEqual("unknown_outcome", unknown.submit(request)["status"])

    def test_interrupted_acceptance_requires_awq_acknowledgement(self):
        record = copy.deepcopy(self.record)
        record["submission"]["acknowledged"] = False
        with self.assertRaisesRegex(TransportError, "acknowledgement"): validate_record(record, 5)


if __name__ == "__main__":
    unittest.main()

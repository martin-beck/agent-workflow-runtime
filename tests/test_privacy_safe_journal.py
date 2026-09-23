import copy
import unittest
from pathlib import Path

from scripts.privacy_safe_journal import Journal, JournalError, canonical_bytes, public_projection, sha256, validate_journal
from scripts.check_privacy_safe_journal import load, validate_spec

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/privacy-safe-journal-v1.json"
TRACE = ROOT / "specifications/fixtures/journal-ar0008-v1.json"
EVIDENCE = ROOT / "specifications/fixtures/journal-evidence-ar0008-v1.json"


class PrivacySafeJournalTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(SPEC)
        self.trace = load(TRACE)

    def reject(self, trace=None, revision=5, anchor=None):
        with self.assertRaises(JournalError):
            validate_journal(trace or self.trace, revision, **({"anchor": anchor} if anchor else {}))

    def test_fixture_and_exact_evidence_bind_revision_and_spec(self):
        validate_spec(self.spec)
        result = validate_journal(self.trace, 5)
        self.assertEqual(result["head_digest"], self.trace[-1]["record_digest"])
        evidence = load(EVIDENCE)
        self.assertEqual(evidence["task_revision"], 5)
        self.assertEqual(evidence["specification_digest"], sha256(canonical_bytes(self.spec)))
        self.assertEqual(evidence["journal_digest"], sha256(canonical_bytes(self.trace)))

    def test_redaction_projection_retention_and_replay(self):
        journal = Journal("AR-0008", 5, "SES-AR0008-TEST", max_records=2)
        first = journal.append(record_id="JR-ONE", operation_id="OP-ONE", event_type="session_started", disposition="started", payload={"ok": "yes", "password": "do-not-store", "nested": {"private_path": "/home/user/file"}})
        self.assertNotIn("password", first["payload"])
        self.assertEqual(first, journal.append(record_id="JR-DIFFERENT", operation_id="OP-ONE", event_type="session_started", disposition="started", payload={"ok": "yes", "password": "do-not-store", "nested": {"private_path": "/home/user/file"}}))
        journal.append(record_id="JR-TWO", operation_id="OP-TWO", event_type="test_result", disposition="passed", payload={"count": 1})
        journal.append(record_id="JR-THREE", operation_id="OP-THREE", event_type="completed", disposition="completed", payload={"result": "ok"})
        self.assertEqual([item["sequence"] for item in journal.records], [2, 3])
        validate_journal(journal.records, 5, anchor=first["record_digest"])
        projection = public_projection(journal.records, 5, sha256(canonical_bytes(self.spec)))
        self.assertNotIn("payload", projection)
        self.assertEqual(projection["count"], 2)

    def test_hostile_tampering_replay_stale_malformed_and_privacy(self):
        tampered = copy.deepcopy(self.trace); tampered[1]["payload"]["count"] = 99; self.reject(tampered)
        replay = copy.deepcopy(self.trace); replay[2]["operation_id"] = replay[1]["operation_id"]; self.reject(replay)
        stale = copy.deepcopy(self.trace); stale[0]["task"]["revision"] = 4; self.reject(stale)
        unknown = copy.deepcopy(self.trace); unknown[0]["payload"]["extra"] = {"token": "secret"}; self.reject(unknown)
        malformed = copy.deepcopy(self.trace); malformed[0]["task"] = "AR-0008"; self.reject(malformed)
        private = copy.deepcopy(self.trace); private[0]["payload"]["raw_output"] = "password=leak"; self.reject(private)

    def test_interruption_and_terminal_fence(self):
        journal = Journal("AR-0008", 5, "SES-AR0008-INT")
        journal.append(record_id="JR-INT-START", operation_id="OP-INT-START", event_type="session_started", disposition="started", payload={})
        journal.append(record_id="JR-INT", operation_id="OP-INT", event_type="interrupted", disposition="failed", payload={})
        with self.assertRaises(JournalError):
            journal.append(record_id="JR-AFTER", operation_id="OP-AFTER", event_type="test_result", disposition="passed", payload={})


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.check_session_events import EventError, canonical_bytes, load_json, sha256, validate_trace


ROOT = Path(__file__).parents[1]
TRACE_PATH = ROOT / "specifications" / "fixtures" / "session-trace-ar0002-v1.json"
EVIDENCE_PATH = ROOT / "specifications" / "fixtures" / "protocol-evidence-ar0002-v1.json"
SPEC_PATH = ROOT / "specifications" / "session-event-protocol-v1.json"


def reseal(trace):
    for event in trace:
        unsigned = dict(event)
        unsigned.pop("event_digest")
        event["event_digest"] = sha256(canonical_bytes(unsigned))
    return trace


class SessionEventTests(unittest.TestCase):
    def setUp(self):
        self.trace = load_json(TRACE_PATH)

    def assert_rejected(self, trace=None, revision=5):
        with self.assertRaises(EventError):
            validate_trace(trace or self.trace, revision)

    def test_valid_trace_and_exact_digest_fixture(self):
        result = validate_trace(self.trace, 5)
        self.assertEqual(result["terminal"], "completed")
        self.assertEqual(result["events"], 3)
        self.assertEqual(self.trace[0]["event_digest"], "sha256:19216d79d532ceaa2a14007de58f8e1fa5b92c165ab6d68404337f2e8c8c3efc")

    def test_evidence_fixture_binds_revision_spec_and_trace(self):
        evidence = load_json(EVIDENCE_PATH)
        specification = load_json(SPEC_PATH)
        self.assertEqual(evidence["task"]["revision"], 5)
        self.assertEqual(evidence["specification"]["sha256"], sha256(canonical_bytes(specification)))
        self.assertEqual(evidence["trace"]["trace_digest"], sha256(canonical_bytes(self.trace)))

    def test_malformed_event_and_invalid_ids(self):
        malformed = copy.deepcopy(self.trace)
        del malformed[0]["session"]
        self.assert_rejected(malformed)
        invalid = copy.deepcopy(self.trace)
        invalid[1]["event_id"] = "bad-id"
        self.assert_rejected(invalid)
        non_string = copy.deepcopy(self.trace)
        non_string[1]["event_type"] = ["checkpointed"]
        self.assert_rejected(non_string)

    def test_stale_revision_and_cross_binding(self):
        self.assert_rejected(revision=4)
        stale = copy.deepcopy(self.trace)
        stale[1]["task"]["revision"] = 4
        self.assert_rejected(stale)
        worktree = copy.deepcopy(self.trace)
        worktree[1]["session"]["worktree_key"] = "other-worktree"
        self.assert_rejected(reseal(worktree))
        session = copy.deepcopy(self.trace)
        session[2]["correlation"]["session_id"] = "SES-OTHER"
        self.assert_rejected(reseal(session))

    def test_duplicate_and_replayed_material(self):
        duplicate_id = copy.deepcopy(self.trace)
        duplicate_id[2]["event_id"] = duplicate_id[1]["event_id"]
        self.assert_rejected(reseal(duplicate_id))
        duplicate_digest = copy.deepcopy(self.trace)
        duplicate_digest[2]["event_digest"] = duplicate_digest[1]["event_digest"]
        self.assert_rejected(duplicate_digest)
        duplicate_evidence = copy.deepcopy(self.trace)
        duplicate_evidence[2]["evidence_digest"] = duplicate_evidence[1]["evidence_digest"]
        self.assert_rejected(reseal(duplicate_evidence))

    def test_invalid_ordering_and_terminal_fence(self):
        sequence = copy.deepcopy(self.trace)
        sequence[2]["sequence"] = 4
        self.assert_rejected(reseal(sequence))
        parent = copy.deepcopy(self.trace)
        parent[2]["correlation"]["parent_event_id"] = parent[0]["event_id"]
        self.assert_rejected(reseal(parent))
        after_terminal = copy.deepcopy(self.trace)
        after_terminal.append(copy.deepcopy(after_terminal[1]))
        after_terminal[-1]["sequence"] = 4
        after_terminal[-1]["event_id"] = "EV-AR0002-AFTER"
        after_terminal[-1]["correlation"]["parent_event_id"] = after_terminal[2]["event_id"]
        self.assert_rejected(reseal(after_terminal))

    def test_privacy_and_unsupported_compatibility(self):
        private = copy.deepcopy(self.trace)
        private[1]["private_path"] = "/home/not-public"
        self.assert_rejected(private)
        unsupported = copy.deepcopy(self.trace)
        unsupported[0]["protocol"]["version"] = "2.0.0"
        self.assert_rejected(unsupported)
        unknown = copy.deepcopy(self.trace)
        unknown[0]["raw_output"] = "bounded-looking output"
        self.assert_rejected(unknown)


if __name__ == "__main__":
    unittest.main()

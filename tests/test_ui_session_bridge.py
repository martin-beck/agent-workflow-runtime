import copy
import unittest
from pathlib import Path

from scripts.ui_session_bridge import BridgeError, binding_digest, trace_digest, validate_bridge


ROOT = Path(__file__).parents[1]
RECORD = ROOT / "specifications/fixtures/ui-session-trace-ar0011-v1.json"


class UiSessionBridgeTests(unittest.TestCase):
    def setUp(self):
        import json
        self.record = json.loads(RECORD.read_text(encoding="utf-8"))
        self.record["resume"]["prior_trace_digest"] = trace_digest(self.record)
        self.record["resume"]["binding_digest"] = binding_digest(self.record)

    def reject(self, record=None, revision=1):
        with self.assertRaises(BridgeError):
            validate_bridge(record or self.record, revision)

    def test_positive_safe_exit_is_resumable_and_exactly_bound(self):
        result = validate_bridge(self.record)
        self.assertEqual(result["final"], "safe_exit")
        self.assertTrue(result["resumable"])

    def test_stale_and_cross_binding(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 2; self.reject(stale)
        project = copy.deepcopy(self.record); project["project"]["revision"] = "b" * 40; self.reject(project)
        lease = copy.deepcopy(self.record); lease["lease"]["id"] = "LSE-OTHER"; self.reject(lease)
        session = copy.deepcopy(self.record); session["session"]["id"] = "SES-OTHER"; self.reject(session)

    def test_replay_unknown_private_and_bounded_events(self):
        replay = copy.deepcopy(self.record); replay["events"][1]["evidence_digest"] = replay["events"][0]["evidence_digest"]; self.reject(replay)
        unknown = copy.deepcopy(self.record); unknown["events"][0]["extra"] = "bad"; self.reject(unknown)
        private = copy.deepcopy(self.record); private["events"][1]["prompt"] = "not allowed"; self.reject(private)
        too_many = copy.deepcopy(self.record); too_many["events"] *= 11; self.reject(too_many)

    def test_invalid_final_event_and_resume_tampering(self):
        invalid = copy.deepcopy(self.record); invalid["final_event"]["reason"] = "session_completed"; self.reject(invalid)
        missing_checkpoint = copy.deepcopy(self.record); missing_checkpoint["resume"]["checkpoint_event_id"] = "UI-AR0011-RENDER"; self.reject(missing_checkpoint)
        changed = copy.deepcopy(self.record); changed["events"][1]["event_id"] = "UI-AR0011-OTHER"; self.reject(changed)
        completed = copy.deepcopy(self.record); completed["final_event"] = {"event_id": "UI-AR0011-DONE", "sequence": 4, "event_type": "completed", "disposition": "completed", "reason": "session_completed", "evidence_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555"}; completed["resume"] = None; validate_bridge(completed)


if __name__ == "__main__":
    unittest.main()

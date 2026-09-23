import copy
import hashlib
import json
import unittest
from pathlib import Path

from scripts.check_supervisor import SupervisorCheckError, canonical_bytes, load_json, validate_spec, validate_trace
from scripts.supervisor import SupervisorError, SupervisorState

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/supervisor-lifecycle-v1.json"
TRACE = ROOT / "specifications/fixtures/supervisor-trace-ar0005-v1.json"


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.trace = load_json(TRACE)

    def reject(self, trace=None, revision=5):
        with self.assertRaises(SupervisorCheckError):
            validate_trace(trace or self.trace, self.spec, revision)

    def test_valid_handoff_cancellation_and_spec_digest(self):
        validate_spec(self.spec)
        result = validate_trace(self.trace, self.spec, 5)
        self.assertEqual(result["final"], "closed")
        self.assertEqual(result["worker"], "WRK-AR0005-B")
        expected = "sha256:" + hashlib.sha256(canonical_bytes(self.spec)).hexdigest()
        self.assertEqual(self.trace["evidence"]["specification_digest"], expected)

    def test_stale_revision_replay_unknown_fields_and_privacy_reject(self):
        self.reject(revision=4)
        stale = copy.deepcopy(self.trace)
        stale["task"]["revision"] = 4
        self.reject(stale)
        replay = copy.deepcopy(self.trace)
        replay["actions"][2]["id"] = replay["actions"][1]["id"]
        self.reject(replay)
        unknown = copy.deepcopy(self.trace)
        unknown["actions"][0]["unbounded"] = True
        self.reject(unknown)
        private = copy.deepcopy(self.trace)
        private["evidence"]["token"] = "forbidden"
        self.reject(private)

    def test_wrong_worker_expired_heartbeat_and_invalid_transition_reject(self):
        wrong = copy.deepcopy(self.trace)
        wrong["actions"][1]["worker"] = "WRK-OTHER"
        self.reject(wrong)
        expired = copy.deepcopy(self.trace)
        expired["actions"][1]["time"] = 120
        self.reject(expired)
        transition = copy.deepcopy(self.trace)
        transition["actions"][5]["operation"] = "resume"
        self.reject(transition)

    def test_stale_recovery_fences_old_worker_and_requires_expiry(self):
        state = SupervisorState(5, "SES-RECOVERY", "WRK-OLD", "LSE-OLD", 10)
        with self.assertRaises(SupervisorError):
            state.action("stale_recover", worker="WRK-OLD", lease="LSE-OLD", now=9, new_worker="WRK-NEW", new_lease="LSE-NEW", new_expiry=20)
        self.assertEqual(state.action("stale_recover", worker="WRK-OLD", lease="LSE-OLD", now=10, new_worker="WRK-NEW", new_lease="LSE-NEW", new_expiry=20), "recovered")
        with self.assertRaises(SupervisorError):
            state.action("heartbeat", worker="WRK-OLD", lease="LSE-OLD", now=11, new_expiry=30)
        self.assertEqual(state.action("resume", worker="WRK-NEW", lease="LSE-NEW", now=11), "active")


if __name__ == "__main__":
    unittest.main()

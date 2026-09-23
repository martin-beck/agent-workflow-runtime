import copy
import unittest
from pathlib import Path

from scripts.check_supervisor_runtime import CheckError, load_json, validate_spec, validate_trace
from scripts.supervisor_runtime import SupervisorAdmission, SupervisorRuntime, SupervisorRuntimeError


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/supervisor-runtime-v1.json"
TRACE = ROOT / "specifications/fixtures/supervisor-runtime-ar0018-v1.json"


class SupervisorRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.trace = load_json(TRACE)

    def reject(self, trace=None, revision=1):
        with self.assertRaises(CheckError):
            validate_trace(trace or self.trace, self.spec, revision)

    def test_positive_revision_bound_cancellation_and_evidence(self):
        validate_spec(self.spec)
        result = validate_trace(self.trace, self.spec, 1)
        self.assertEqual(result, {"protocol": "awr-supervisor-runtime@1.0.0", "task_revision": 1, "actions": 4, "final": "closed"})

    def test_hostile_stale_replay_lease_authority_terminal_and_privacy(self):
        stale = copy.deepcopy(self.trace); stale["task"]["revision"] = 2; self.reject(stale)
        replay = copy.deepcopy(self.trace); replay["actions"][1]["id"] = replay["actions"][0]["id"]; self.reject(replay)
        lease = copy.deepcopy(self.trace); lease["actions"][1]["new_expiry"] = 110; self.reject(lease)
        authority = copy.deepcopy(self.trace); authority["actions"][2]["worker"] = "WRK-OTHER"; self.reject(authority)
        terminal = copy.deepcopy(self.trace); terminal["actions"].append(copy.deepcopy(terminal["actions"][-1])); terminal["actions"][-1]["id"] = "ACT-AFTER"; terminal["actions"][-1]["sequence"] = 5; self.reject(terminal)
        privacy = copy.deepcopy(self.trace); privacy["evidence"]["token"] = "bad"; self.reject(privacy)

    def test_recovery_requires_expiry_and_fences_old_worker(self):
        admission = SupervisorAdmission("AR-0018", 1, "agent-workflow-runtime", "a" * 40, "agent-workflow-runtime-0018", "a" * 40, "sha256:" + "a" * 64, "SES-AR0018-RECOVERY", "WRK-OLD", "LSE-OLD", 10)
        runtime = SupervisorRuntime(admission)
        runtime.apply("ACT-START", "start", worker="WRK-OLD", lease="LSE-OLD", now=1)
        with self.assertRaises(SupervisorRuntimeError):
            runtime.apply("ACT-RECOVER-EARLY", "stale_recover", worker="WRK-OLD", lease="LSE-OLD", now=9, new_worker="WRK-NEW", new_lease="LSE-NEW", new_expiry=20)
        self.assertEqual(runtime.apply("ACT-RECOVER", "stale_recover", worker="WRK-OLD", lease="LSE-OLD", now=10, new_worker="WRK-NEW", new_lease="LSE-NEW", new_expiry=20), "recovered")
        with self.assertRaises(SupervisorRuntimeError):
            runtime.apply("ACT-OLD", "resume", worker="WRK-OLD", lease="LSE-OLD", now=11)
        self.assertEqual(runtime.apply("ACT-RESUME", "resume", worker="WRK-NEW", lease="LSE-NEW", now=11), "active")
        self.assertEqual(runtime.apply("ACT-COMPLETE", "complete", worker="WRK-NEW", lease="LSE-NEW", now=12), "closed")


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.check_runtime_model import CheckError, load_json, validate_spec, validate_trace
from scripts.runtime_model import RuntimeModelError, RuntimeState

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/runtime-model-v1.json"
TRACE = ROOT / "specifications/fixtures/runtime-trace-ar0014-v1.json"


class RuntimeModelTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.trace = load_json(TRACE)

    def reject(self, trace):
        with self.assertRaises(CheckError):
            validate_trace(trace, self.spec, 1)

    def test_positive_corpus_covers_full_runtime_model(self):
        validate_spec(self.spec)
        result = validate_trace(self.trace, self.spec, 1)
        self.assertEqual(result["final"], "completed")
        self.assertEqual(result["actions"], 13)

    def test_hostile_stale_replay_authority_privacy_and_terminal(self):
        stale = copy.deepcopy(self.trace); stale["task"]["revision"] = 0; self.reject(stale)
        replay = copy.deepcopy(self.trace); replay["actions"][1]["event_id"] = replay["actions"][0]["event_id"]; self.reject(replay)
        authority = copy.deepcopy(self.trace); authority["actions"][4]["authority"] = "runtime"; self.reject(authority)
        privacy = copy.deepcopy(self.trace); privacy["evidence"]["prompt"] = "private"; self.reject(privacy)
        terminal = copy.deepcopy(self.trace); terminal["actions"][12]["operation"] = "execute"; self.reject(terminal)

    def test_hostile_oracle_publication_and_recovery_invariants(self):
        oracle = copy.deepcopy(self.trace); oracle["actions"][5]["payload"]["decision"] = "approved_by_runtime"; self.reject(oracle)
        publication = copy.deepcopy(self.trace); publication["actions"][10]["payload"]["merge_status"] = "merged"; self.reject(publication)
        recovery = copy.deepcopy(self.trace); recovery["actions"][9]["payload"]["checkpoint_digest"] = "sha256:" + "9" * 64; self.reject(recovery)

    def test_model_fences_old_worker_after_recovery(self):
        state = RuntimeState(1, "SES-AR0014-X", "sha256:" + "a" * 64, "WRK-A", "LSE-A")
        common = {"task_revision": 1, "session_id": "SES-AR0014-X", "worktree_digest": "sha256:" + "a" * 64, "worker_id": "WRK-A", "lease_id": "LSE-A"}
        actions = [("admit", "coordinator", {"revision": 1, "worktree_digest": common["worktree_digest"]}), ("claim", "coordinator", {"claim_digest": "sha256:" + "b" * 64}), ("start", "runtime", {"session_id": common["session_id"]}), ("execute", "runtime", {"operation_digest": "sha256:" + "c" * 64}), ("checkpoint", "runtime", {"checkpoint_digest": "sha256:" + "f" * 64, "operation_digest": "sha256:" + "c" * 64}), ("interrupt", "runtime", {"reason_digest": "sha256:" + "1" * 64})]
        for operation, authority, payload in actions:
            state.apply({**common, "event_id": operation, "operation": operation, "authority": authority, "state": state.state, "payload": payload})
        state.apply({**common, "event_id": "recover", "operation": "recover", "authority": "coordinator", "state": "interrupted", "payload": {"new_worker": "WRK-B", "new_lease": "LSE-B", "checkpoint_digest": "sha256:" + "f" * 64}})
        with self.assertRaises(RuntimeModelError):
            state.apply({**common, "event_id": "old", "operation": "resume", "authority": "runtime", "state": "recovering", "payload": {"checkpoint_digest": "sha256:" + "f" * 64}})


if __name__ == "__main__":
    unittest.main()

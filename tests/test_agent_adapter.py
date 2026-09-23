import copy
import unittest
from pathlib import Path

from scripts.agent_adapter import AdapterError, ReferenceAdapter, canonical_bytes, sha256
from scripts.check_agent_adapter import ContractError, load_json, validate_spec, validate_trace


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications" / "agent-adapter-lifecycle-v1.json"
TRACE = ROOT / "specifications" / "fixtures" / "adapter-trace-ar0003-v1.json"
EVIDENCE = ROOT / "specifications" / "fixtures" / "adapter-evidence-ar0003-v1.json"


class AgentAdapterTests(unittest.TestCase):
    def setUp(self):
        self.trace = load_json(TRACE)
        self.adapter = ReferenceAdapter(expected_revision=5)
        self.task = {"id": "AR-0003", "revision": 5}
        self.session = {"id": "SES-AR0003-REFERENCE", "worktree_key": "agent-workflow-runtime-0003", "worktree_digest": "sha256:" + "1" * 64}

    def test_spec_and_positive_trace(self):
        specification = load_json(SPEC)
        validate_spec(specification)
        result = validate_trace(self.trace)
        self.assertEqual(result["terminal_state"], "terminated")
        evidence = load_json(EVIDENCE)
        self.assertEqual(evidence["task"]["revision"], 5)
        self.assertEqual(evidence["specification"]["sha256"], sha256(canonical_bytes(specification)))
        self.assertEqual(evidence["trace"]["sha256"], sha256(canonical_bytes(self.trace)))

    def test_reference_adapter_positive_lifecycle_and_capability_digest(self):
        self.adapter.discover()
        report = self.adapter.capabilities()
        body = {key: report[key] for key in ("adapter", "capabilities", "limits")}
        self.assertEqual(report["digest"], sha256(canonical_bytes(body)))
        self.adapter.start(self.task, self.session)
        self.adapter.interact("sha256:" + "2" * 64)
        self.assertEqual(self.adapter.terminate("interrupted")["state"], "terminated")

    def test_hostile_unauthorized_and_terminal_transitions(self):
        with self.assertRaises(AdapterError):
            self.adapter.start(self.task, self.session)
        self.adapter.discover()
        with self.assertRaises(AdapterError):
            self.adapter.interact("sha256:" + "2" * 64)
        self.adapter.start(self.task, self.session)
        self.adapter.fail("provider_unavailable")
        with self.assertRaises(AdapterError):
            self.adapter.terminate()

    def test_hostile_stale_revision_malformed_and_privacy_input(self):
        self.adapter.discover()
        stale = {"id": "AR-0003", "revision": 4}
        with self.assertRaises(AdapterError):
            self.adapter.start(stale, self.session)
        private = dict(self.session, private_path="/home/not-public")
        with self.assertRaises(AdapterError):
            self.adapter.start(self.task, private)
        self.assertEqual(self.adapter.start(self.task, self.session)["state"], "started")

    def test_checker_rejects_replay_unknown_privacy_and_terminal_followup(self):
        malformed = copy.deepcopy(self.trace)
        malformed[1]["unknown"] = True
        with self.assertRaises(ContractError):
            validate_trace(malformed)
        stale = copy.deepcopy(self.trace)
        stale[2]["task"]["revision"] = 4
        with self.assertRaises(ContractError):
            validate_trace(stale)
        private = copy.deepcopy(self.trace)
        private[0]["raw_output"] = "not allowed"
        with self.assertRaises(ContractError):
            validate_trace(private)
        after = copy.deepcopy(self.trace)
        after.append(copy.deepcopy(after[-1]))
        after[-1]["sequence"] = 5
        with self.assertRaises(ContractError):
            validate_trace(after)


if __name__ == "__main__":
    unittest.main()

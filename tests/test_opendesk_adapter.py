import copy
import unittest
from pathlib import Path

from scripts.check_opendesk_adapter import ContractError, load_json, validate_capability_report, validate_spec, validate_trace
from scripts.opendesk_adapter import AdapterError, OpenDeskStyleAdapter, canonical_bytes, sha256


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications" / "opendesk-adapter-v1.json"
TRACE = ROOT / "specifications" / "fixtures" / "opendesk-trace-ar0017-v1.json"


class OpenDeskAdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = OpenDeskStyleAdapter(capabilities=("conversation",), expected_revision=5)
        self.task = {"id": "AR-0017", "revision": 5}
        self.session = {"id": "SES-AR0017-TEST", "worktree_key": "agent-workflow-runtime-0017", "worktree_digest": sha256(b"worktree")}

    def test_spec_and_trace_are_revision_bound(self):
        specification = load_json(SPEC)
        validate_spec(specification)
        result = validate_trace(load_json(TRACE))
        self.assertEqual(result["terminal_state"], "terminated")
        self.assertEqual(specification["task"], self.task)
        self.assertEqual(sha256(canonical_bytes(specification))[0:7], "sha256:")

    def test_unsupported_capability_is_explicit_and_non_mutating(self):
        self.adapter.discover()
        self.adapter.start(self.task, self.session)
        before = self.adapter.state
        result = self.adapter.request("tool_use", "sha256:" + "1" * 64)
        self.assertEqual(result["disposition"], "unsupported_capability")
        self.assertFalse(result["execute"])
        self.assertEqual(result["state_after"], before)
        self.assertEqual(self.adapter.state, before)

    def test_supported_request_is_still_offline(self):
        self.adapter.discover()
        report = self.adapter.capabilities()
        validate_capability_report({key: report[key] for key in ("adapter", "capabilities", "limits", "digest")})
        self.adapter.start(self.task, self.session)
        result = self.adapter.request("conversation", "sha256:" + "2" * 64)
        self.assertEqual(result["disposition"], "accepted")
        self.assertFalse(result["execute"])

    def test_hostile_unknown_capability_stale_revision_and_private_binding(self):
        self.adapter.discover()
        with self.assertRaises(AdapterError):
            self.adapter.start({"id": "AR-0017", "revision": 4}, self.session)
        self.adapter.start(self.task, self.session)
        with self.assertRaises(AdapterError):
            self.adapter.request("launch_provider", "sha256:" + "1" * 64)
        with self.assertRaises(AdapterError):
            OpenDeskStyleAdapter(capabilities=("launch_provider",))
        with self.assertRaises(AdapterError):
            OpenDeskStyleAdapter().start(self.task, dict(self.session, private_path="/home/private"))

    def test_hostile_checker_rejects_state_change_unknown_fields_payload_and_replay(self):
        trace = load_json(TRACE)
        hostile = copy.deepcopy(trace)
        hostile[2]["state_after"] = "ready"
        with self.assertRaises(ContractError):
            validate_trace(hostile)
        hostile = copy.deepcopy(trace)
        hostile[2]["capability"] = "launch_provider"
        with self.assertRaises(ContractError):
            validate_trace(hostile)
        hostile = copy.deepcopy(trace)
        hostile[3]["unknown"] = True
        with self.assertRaises(ContractError):
            validate_trace(hostile)
        hostile = copy.deepcopy(trace)
        hostile[3]["request_digest"] = "prompt text"
        with self.assertRaises(ContractError):
            validate_trace(hostile)
        self.adapter = OpenDeskStyleAdapter()
        self.adapter.discover()
        report = self.adapter.capabilities()
        report["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ContractError):
            validate_capability_report(report)
        hostile = copy.deepcopy(trace)
        hostile.append(copy.deepcopy(hostile[-1]))
        hostile[-1]["sequence"] = 6
        with self.assertRaises(ContractError):
            validate_trace(hostile)


if __name__ == "__main__":
    unittest.main()

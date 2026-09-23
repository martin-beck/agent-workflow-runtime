import copy
import json
import unittest
from pathlib import Path

from scripts.check_production_provider_adapters import ContractError, load_json, validate, validate_spec
from scripts.provider_adapters import AdapterError, CodexAdapter, FakeTransport, OpenCodeAdapter, OpenDeskAdapter, PROFILES, run_script, sha256


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/production-provider-adapters-v1.json"
FIXTURE = ROOT / "specifications/fixtures/production-provider-adapters-ar0050-v1.json"


class ProductionProviderAdapterTests(unittest.TestCase):
    def setUp(self):
        self.record = load_json(FIXTURE)
        self.session = {"id": "SES-AR0050-TEST", "worktree_key": "agent-workflow-runtime-0050", "worktree_digest": sha256(b"test")}
        self.task = {"id": "AR-0050", "revision": 5}

    def test_spec_fixture_and_all_independent_adapters_are_offline(self):
        validate_spec(load_json(SPEC))
        result = validate(self.record)
        self.assertEqual(result["provider"], "not_performed")
        self.assertEqual(set(self.record["adapters"]), set(PROFILES))
        self.assertTrue(all(event.get("raw_output_absent") is not False for trace in self.record["adapters"].values() for event in trace))

    def test_discovery_negotiation_correlation_stream_and_model_identity(self):
        for adapter_type in (CodexAdapter, OpenCodeAdapter, OpenDeskAdapter):
            adapter = adapter_type(FakeTransport())
            discovery = adapter.discover()
            self.assertEqual(discovery["model"], PROFILES[adapter.profile.adapter_id].model)
            negotiated = adapter.negotiate(self.task, self.session, list(adapter.profile.capabilities))
            request = adapter.request("REQ-AR0050-1", sha256(b"request"))
            stream = adapter.stream("REQ-AR0050-1")
            self.assertEqual(negotiated["state_after"], "negotiated")
            self.assertEqual(request["request_id"], stream["request_id"])
            self.assertEqual([frame["sequence"] for frame in stream["frames"]], [1, 2, 3])

    def test_tool_and_file_policy_is_nonexecuting_and_provider_limits_are_enforced(self):
        adapter = OpenDeskAdapter(); adapter.discover(); adapter.negotiate(self.task, self.session, list(adapter.profile.capabilities))
        denied_tool = adapter.request("REQ-AR0050-1", sha256(b"one"), tool="edit")
        self.assertEqual(denied_tool["disposition"], "tool_denied")
        self.assertFalse(denied_tool["execute"])
        with self.assertRaises(AdapterError):
            adapter.stream("REQ-AR0050-1")
        adapter = OpenDeskAdapter(); adapter.discover(); adapter.negotiate(self.task, self.session, list(adapter.profile.capabilities)); adapter.request("REQ-AR0050-2", sha256(b"two"), file="write")
        self.assertEqual(adapter.state, "negotiated")
        adapter.request("REQ-AR0050-3", sha256(b"three"))
        with self.assertRaises(AdapterError):
            adapter.stream("REQ-AR0050-3", frame_count=5)

    def test_interruption_resume_errors_and_correlation_fail_closed(self):
        adapter = CodexAdapter(); adapter.discover(); adapter.negotiate(self.task, self.session, list(adapter.profile.capabilities)); adapter.request("REQ-AR0050-1", sha256(b"request"))
        interruption = adapter.interrupt("REQ-AR0050-1")
        with self.assertRaises(AdapterError):
            adapter.resume("REQ-AR0050-1", sha256(b"wrong-checkpoint"))
        adapter.resume("REQ-AR0050-1", interruption["checkpoint_digest"])
        error = adapter.error("REQ-AR0050-1", "provider_timeout")
        self.assertFalse(error["success"])
        with self.assertRaises(AdapterError):
            adapter.close("REQ-AR0050-1")

    def test_hostile_fixture_revision_privacy_digest_replay_and_execution_claims(self):
        mutations = []
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 4; mutations.append(stale)
        private = copy.deepcopy(self.record); private["adapters"]["codex"][1]["prompt"] = "raw"; mutations.append(private)
        tampered = copy.deepcopy(self.record); tampered["adapters"]["opencode"][2]["event_digest"] = sha256(b"tampered"); mutations.append(tampered)
        execution = copy.deepcopy(self.record); execution["execution"]["network"] = "enabled"; mutations.append(execution)
        duplicate = copy.deepcopy(self.record); duplicate["adapters"]["opendesk"].append(copy.deepcopy(duplicate["adapters"]["opendesk"][0])); mutations.append(duplicate)
        for hostile in mutations:
            with self.assertRaises(ContractError):
                validate(hostile)


if __name__ == "__main__":
    unittest.main()

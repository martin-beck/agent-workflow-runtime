import copy
import unittest
from pathlib import Path

from scripts.provider_adapter_protocol import AdapterProtocol, ProtocolError, sha256
from scripts.check_provider_adapter_protocol import ContractError, load_json, validate_spec, validate_trace

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/provider-adapter-protocol-v1.json"
TRACE = ROOT / "specifications/fixtures/provider-adapter-trace-ar0063-v1.json"

class ProviderAdapterProtocolTests(unittest.TestCase):
    def setUp(self):
        self.adapter = AdapterProtocol(advertised=("request", "stream", "tool", "file_read", "file_write", "interrupt", "checkpoint", "resume"))
        self.task = {"id": "AR-0063", "revision": 5}
        self.session = {"id": "SES-AR0063-TEST", "worktree_key": "agent-workflow-runtime-0063", "worktree_digest": sha256(b"worktree")}

    def test_spec_fixture_and_positive_lifecycle(self):
        validate_spec(load_json(SPEC))
        self.assertEqual(validate_trace(load_json(TRACE))["terminal_state"], "closed")
        self.adapter.admit(self.task, self.session); self.adapter.discover(); self.adapter.negotiate(["request", "stream"])
        self.adapter.request("request", sha256(b"request")); self.adapter.stream("open"); self.adapter.stream("chunk", sha256(b"chunk")); self.adapter.stream("end")
        self.adapter.interrupt(); self.adapter.checkpoint(sha256(b"checkpoint")); self.adapter.resume(sha256(b"checkpoint")); self.assertEqual(self.adapter.close()["state_after"], "closed")

    def test_router_unsupported_is_explicit_and_non_mutating(self):
        self.adapter.admit(self.task, self.session); self.adapter.discover(); self.adapter.negotiate(["request"])
        before = (self.adapter.state, self.adapter.sequence)
        outcome = self.adapter.request("stream", sha256(b"x"))
        self.assertEqual(outcome["disposition"], "unsupported")
        self.assertEqual((self.adapter.state, self.adapter.sequence), (before[0], before[1] + 1))
        self.assertFalse(outcome["execute"])

    def test_secret_references_and_hostile_payloads(self):
        self.adapter.admit(self.task, self.session); self.adapter.discover(); self.adapter.negotiate(["tool", "file_read"])
        self.assertEqual(self.adapter.tool_or_file("tool", "secret-ref:oauth")["disposition"], "accepted")
        with self.assertRaises(ProtocolError): self.adapter.tool_or_file("tool", "actual-secret")
        with self.assertRaises(ProtocolError): self.adapter.request("request", "prompt text")
        with self.assertRaises(ProtocolError): self.adapter.admit({"id":"AR-0063","revision":4}, self.session)

    def test_checkpoint_fencing_terminal_and_privacy_replay(self):
        self.adapter.admit(self.task, self.session); self.adapter.discover(); self.adapter.negotiate(["interrupt", "checkpoint", "resume"])
        self.adapter.interrupt(); digest = sha256(b"cp"); self.adapter.checkpoint(digest)
        with self.assertRaises(ProtocolError): self.adapter.resume(sha256(b"other"))
        self.adapter.resume(digest); self.adapter.close()
        with self.assertRaises(ProtocolError): self.adapter.request("request", sha256(b"late"))
        hostile = copy.deepcopy(load_json(TRACE)); hostile[0]["private_path"] = "/home/user/x"
        with self.assertRaises(ContractError): validate_trace(hostile)
        hostile = copy.deepcopy(load_json(TRACE)); hostile[-1]["state_after"] = "active"
        with self.assertRaises(ContractError): validate_trace(hostile)

if __name__ == "__main__": unittest.main()

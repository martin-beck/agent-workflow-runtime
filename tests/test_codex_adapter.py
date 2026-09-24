import copy
import unittest
from pathlib import Path

from scripts.codex_adapter import AdapterError, CodexStyleAdapter, canonical_bytes, sha256
from scripts.check_codex_adapter import ContractError, load_json, validate_spec, validate_trace


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/codex-style-adapter-v1.json"
TRACE = ROOT / "specifications/fixtures/codex-replay-ar0015-v1.json"
EVIDENCE = ROOT / "specifications/fixtures/codex-evidence-ar0015-v1.json"


class CodexAdapterTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.trace = load_json(TRACE)
        self.adapter = CodexStyleAdapter(expected_revision=5)
        self.task = {"id": "AR-0015", "revision": 5}
        self.session = {"id": "SES-AR0015-OFFLINE", "worktree_key": "agent-workflow-runtime-0015", "worktree_digest": "sha256:" + "1" * 64}

    def test_spec_fixture_and_evidence_are_revision_and_digest_bound(self):
        validate_spec(self.spec)
        self.assertEqual(validate_trace(self.trace)["terminal_state"], "closed")
        evidence = load_json(EVIDENCE)
        self.assertEqual(evidence["task"]["revision"], 5)
        self.assertEqual(evidence["specification"]["sha256"], sha256(canonical_bytes(self.spec)))
        self.assertEqual(evidence["trace"]["sha256"], sha256(canonical_bytes(self.trace)))

    def test_positive_discovery_capability_and_turn_lifecycle(self):
        self.adapter.discover()
        report = self.adapter.capabilities()
        body = {key: report[key] for key in ("adapter", "capabilities", "limits")}
        self.assertEqual(report["digest"], sha256(canonical_bytes(body)))
        self.assertEqual(self.adapter.start(self.task, self.session)["state"], "active")
        self.assertEqual(self.adapter.turn("sha256:" + "2" * 64)["turn"], 1)
        self.assertEqual(self.adapter.close()["disposition"], "completed")

    def test_hostile_provider_seam_stale_revision_private_binding_and_bad_reference(self):
        with self.assertRaises(AdapterError):
            self.adapter.start(self.task, self.session)
        self.adapter.discover()
        with self.assertRaises(AdapterError):
            self.adapter.start({"id": "AR-0015", "revision": 4}, self.session)
        with self.assertRaises(AdapterError):
            self.adapter.start(self.task, dict(self.session, private_path="/home/user/x"))
        self.adapter.start(self.task, self.session)
        with self.assertRaises(AdapterError):
            self.adapter.turn("not-a-digest")
        with self.assertRaises(AdapterError):
            self.adapter.turn("sha256:" + "2" * 64 + "x")

    def test_hostile_checker_rejects_unknown_privacy_replay_stale_and_terminal_records(self):
        for mutate in (
            lambda t: t[1].update(unknown=True),
            lambda t: t[2]["task"].update(revision=4),
            lambda t: t[0].update(prompt="do this"),
        ):
            hostile = copy.deepcopy(self.trace)
            mutate(hostile)
            with self.assertRaises(ContractError):
                validate_trace(hostile)
        hostile = copy.deepcopy(self.trace)
        hostile.append(copy.deepcopy(hostile[-1]))
        hostile[-1]["sequence"] = 5
        with self.assertRaises(ContractError):
            validate_trace(hostile)


if __name__ == "__main__":
    unittest.main()

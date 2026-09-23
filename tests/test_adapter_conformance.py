import copy
import unittest
from pathlib import Path

from scripts.adapter_conformance import ConformanceError, capability_mismatch, replay, validate_record
from scripts.check_adapter_conformance import load_json, validate_fixture, validate_spec

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/adapter-conformance-v1.json"
FIXTURE = ROOT / "specifications/fixtures/adapter-conformance-ar0022-v1.json"


class AdapterConformanceTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.record = load_json(FIXTURE)

    def test_positive_spec_record_and_deterministic_replay(self):
        validate_spec(self.spec)
        result = validate_fixture(self.record)
        self.assertEqual(result["adapters"], ["codex-style", "opencode-style", "opendesk-style"])
        self.assertEqual(result["mismatch"], "capability_mismatch")
        for events in self.record["replays"].values():
            self.assertEqual(replay(events), replay(copy.deepcopy(events)))

    def test_mismatch_is_explicit_nonexecuting_and_nonmutating(self):
        reports = list(self.record["capabilities"].values())
        before = copy.deepcopy(reports)
        result = capability_mismatch(reports, ["tool_use", "conversation"])
        self.assertEqual(result["disposition"], "capability_mismatch")
        self.assertFalse(result["execute"])
        self.assertEqual(reports, before)
        self.assertEqual(result["missing"]["tool_use"], ["codex-style", "opendesk-style"])

    def test_hostile_stale_unknown_private_digest_and_cross_binding(self):
        mutations = []
        stale = copy.deepcopy(self.record)
        stale["task"]["revision"] = 2
        mutations.append(stale)
        unknown = copy.deepcopy(self.record)
        unknown["replays"]["codex-style"][0]["prompt"] = "must not enter contract"
        mutations.append(unknown)
        private = copy.deepcopy(self.record)
        private["replays"]["opencode-style"][0]["session"]["worktree_key"] = "/home/private"
        mutations.append(private)
        tampered = copy.deepcopy(self.record)
        tampered["replays"]["opendesk-style"][1]["event_digest"] = "sha256:" + "0" * 64
        mutations.append(tampered)
        crossed = copy.deepcopy(self.record)
        crossed["replays"]["codex-style"][1]["adapter"]["id"] = "opencode-style"
        mutations.append(crossed)
        for hostile in mutations:
            with self.assertRaises(ConformanceError):
                validate_record(hostile)

    def test_hostile_replay_terminal_duplicate_and_mismatch_tamper(self):
        terminal = copy.deepcopy(self.record)
        terminal["replays"]["codex-style"][1]["event_type"] = "tool_call"
        with self.assertRaises(ConformanceError):
            validate_record(terminal)
        duplicate = copy.deepcopy(self.record)
        duplicate["replays"]["opendesk-style"].append(copy.deepcopy(duplicate["replays"]["opendesk-style"][1]))
        duplicate["replays"]["opendesk-style"][-1]["sequence"] = 3
        with self.assertRaises(ConformanceError):
            validate_record(duplicate)
        mismatch = copy.deepcopy(self.record)
        mismatch["mismatch_report"]["execute"] = True
        with self.assertRaises(ConformanceError):
            validate_record(mismatch)


if __name__ == "__main__":
    unittest.main()

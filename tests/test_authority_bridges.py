import copy
import unittest
from pathlib import Path

from scripts.authority_bridges import (
    AuthorityBridge,
    BridgeError,
    LocalAuthorityFake,
    validate_binding,
    validate_record,
)
from scripts.check_authority_bridges import check, load, validate_spec

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/authority-bridges-v1.json"
FIXTURE = ROOT / "specifications/fixtures/authority-bridges-ar0088-v1.json"


def binding():
    return {
        "task": {"id": "AR-0088", "revision": 3},
        "project": {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64},
        "worktree": {
            "key": "agent-workflow-runtime-0088",
            "digest": "sha256:" + "2" * 64,
        },
        "lease": {
            "id": "LSE-AR0088-TEST",
            "worker_id": "WRK-AR0088-TEST",
            "digest": "sha256:" + "3" * 64,
        },
        "session": {"id": "SES-AR0088-TEST"},
    }


class AuthorityBridgeTests(unittest.TestCase):
    def setUp(self):
        self.binding = binding()
        self.fakes = {
            "awq": LocalAuthorityFake("awq", ["pending", "accepted"]),
            "awg": LocalAuthorityFake("awg", ["timeout", "requires_ui"]),
            "ui": LocalAuthorityFake("ui", ["pending", "approved"]),
        }
        self.bridge = AuthorityBridge(self.binding, self.fakes)

    def test_concurrent_pending_resume_and_authoritative_awq_resolution(self):
        first = self.bridge.request(
            "awq", "REQ-AWQ-A", "evidence", {"evidence": "a"}, operation_id="OP-AWQ-A"
        )
        second = self.bridge.request(
            "awq", "REQ-AWQ-B", "evidence", {"evidence": "b"}, operation_id="OP-AWQ-B"
        )
        self.assertEqual(first["status"], "pending")
        self.assertEqual(second["status"], "accepted")
        self.assertEqual(self.bridge.resume("OP-AWQ-A")["status"], "pending")
        self.fakes["awq"].respond("OP-AWQ-A", "accepted")
        result = self.bridge.observe("OP-AWQ-A")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["resumed"], 1)

    def test_timeout_retry_and_resume_are_explicit(self):
        result = self.bridge.request(
            "awg",
            "REQ-AWG-TIMEOUT",
            "discussion",
            {"topic": "x"},
            operation_id="OP-AWG-TIMEOUT",
            max_attempts=2,
        )
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(self.bridge.resume("OP-AWG-TIMEOUT")["status"], "timeout")
        self.assertEqual(self.bridge.retry("OP-AWG-TIMEOUT")["status"], "requires_ui")
        with self.assertRaises(BridgeError):
            self.bridge.retry("OP-AWG-TIMEOUT")

    def test_unknown_retry_exhaustion_is_blocked(self):
        fake = LocalAuthorityFake("awg", ["unknown", "unknown"])
        bridge = AuthorityBridge(
            self.binding,
            {
                "awq": LocalAuthorityFake("awq"),
                "awg": fake,
                "ui": LocalAuthorityFake("ui"),
            },
        )
        self.assertEqual(
            bridge.request(
                "awg",
                "REQ-UNKNOWN",
                "discussion",
                {"topic": "x"},
                operation_id="OP-UNKNOWN",
                max_attempts=2,
            )["status"],
            "unknown",
        )
        self.assertEqual(bridge.retry("OP-UNKNOWN")["status"], "unknown")
        self.assertEqual(bridge.retry("OP-UNKNOWN")["status"], "blocked")
        with self.assertRaises(BridgeError):
            bridge.finalize_change("OP-UNKNOWN", "OP-MISSING")

    def test_rejection_is_terminal_and_cannot_be_retried(self):
        fake = LocalAuthorityFake("awq", ["rejected", "accepted"])
        bridge = AuthorityBridge(
            self.binding,
            {
                "awq": fake,
                "awg": LocalAuthorityFake("awg"),
                "ui": LocalAuthorityFake("ui"),
            },
        )
        self.assertEqual(
            bridge.request(
                "awq",
                "REQ-REJECT",
                "evidence",
                {"evidence": "x"},
                operation_id="OP-REJECT",
            )["status"],
            "rejected",
        )
        with self.assertRaises(BridgeError):
            bridge.retry("OP-REJECT")

    def test_required_change_must_route_awg_then_ui(self):
        awg = self.bridge.request(
            "awg",
            "REQ-CHANGE-AWG",
            "discussion",
            {"change": "spec"},
            operation_id="OP-CHANGE-AWG",
            change_kind="specification_change",
        )
        self.assertEqual(awg["status"], "timeout")
        awg = self.bridge.retry("OP-CHANGE-AWG")
        self.assertEqual(awg["status"], "requires_ui")
        ui = self.bridge.request(
            "ui",
            "REQ-CHANGE-UI",
            "human_gate",
            {"change": "spec"},
            operation_id="OP-CHANGE-UI",
            change_kind="specification_change",
        )
        self.assertEqual(ui["status"], "pending")
        with self.assertRaises(BridgeError):
            self.bridge.finalize_change("OP-CHANGE-AWG", "OP-CHANGE-UI")
        self.fakes["ui"].respond("OP-CHANGE-UI", "approved")
        self.assertEqual(self.bridge.observe("OP-CHANGE-UI")["status"], "approved")
        authorized = self.bridge.finalize_change("OP-CHANGE-AWG", "OP-CHANGE-UI")
        self.assertEqual(authorized["status"], "authorized")

    def test_runtime_cannot_manufacture_authority_or_cross_bind(self):
        with self.assertRaises(BridgeError):
            self.bridge.request(
                "awq", "REQ-BAD", "discussion", {"x": 1}, operation_id="OP-BAD"
            )
        stale = copy.deepcopy(self.binding)
        stale["task"]["revision"] = 4
        with self.assertRaises(BridgeError):
            validate_binding(stale)
        crossed = copy.deepcopy(self.binding)
        crossed["lease"]["id"] = "LSE/OTHER"
        with self.assertRaises(BridgeError):
            validate_binding(crossed)


class AuthorityBridgeContractTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(SPEC)
        self.record = load(FIXTURE)
        self.evidence = {
            "checker": "awr-authority-bridges-checker/1.0.0",
            "task_revision": 3,
            "specification_digest": "",
            "record_digest": "",
            "result": {},
        }
        from scripts.authority_bridges import canonical, digest

        result = validate_record(self.record)
        self.evidence["specification_digest"] = digest(canonical(self.spec))
        self.evidence["record_digest"] = digest(self.record)
        self.evidence["result"] = result
        self.evidence["evidence_digest"] = digest(self.evidence)

    def test_machine_contract_and_fixture(self):
        self.assertEqual(
            validate_spec(self.spec)["protocol"]["id"], "awr-authority-bridges"
        )
        self.assertEqual(
            check(self.spec, self.record, self.evidence, 3)["change_status"],
            "authorized",
        )
        self.assertEqual(validate_record(self.record)["pending"], 2)

    def reject(self, record):
        with self.assertRaises(BridgeError):
            validate_record(record)

    def test_hostile_stale_replay_private_and_fail_open_mutations(self):
        stale = copy.deepcopy(self.record)
        stale["binding"]["task"]["revision"] = 4
        self.reject(stale)
        crossed = copy.deepcopy(self.record)
        crossed["operations"][0]["binding_digest"] = "sha256:" + "9" * 64
        self.reject(crossed)
        replay = copy.deepcopy(self.record)
        replay["operations"][1]["operation_id"] = replay["operations"][0][
            "operation_id"
        ]
        self.reject(replay)
        private = copy.deepcopy(self.record)
        private["operations"][0]["request_id"] = "REQ-PROMPT"
        self.reject(private)
        manufactured = copy.deepcopy(self.record)
        manufactured["change_control"]["status"] = "authorized"
        manufactured["operations"][2]["status"] = "approved"
        self.reject(manufactured)
        fail_open = copy.deepcopy(self.record)
        fail_open["operations"][4]["status"] = "approved"
        self.reject(fail_open)


if __name__ == "__main__":
    unittest.main()

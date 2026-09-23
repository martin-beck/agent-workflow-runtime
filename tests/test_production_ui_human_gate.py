import copy
import unittest
from pathlib import Path

from scripts.production_ui_human_gate import SessionError, final_digest, input_digest, persist_final_event, rendering_inputs, sha256, validate
from scripts.check_production_ui_human_gate import check, load


ROOT = Path(__file__).parents[1]


class ProductionUiHumanGateTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(ROOT / "specifications/production-ui-human-gate-v1.json")
        self.record = load(ROOT / "specifications/fixtures/production-ui-human-gate-ar0054-v1.json")

    def reject(self, mutate):
        changed = copy.deepcopy(self.record)
        mutate(changed)
        with self.assertRaises(SessionError):
            validate(changed, 5)

    def reseal_decision(self, decision, *, human_present=True, reason=None):
        changed = copy.deepcopy(self.record)
        changed["events"][2]["decision"] = decision
        changed["events"][2]["human_present"] = human_present
        changed["final_event"]["decision"] = decision
        changed["final_event"]["reason"] = reason or ("human_selected" if decision in {"approve", "reject", "clarify"} else "session_expired" if decision == "timeout" else "user_cancelled")
        changed["persistence"]["event_digest"] = final_digest(changed["final_event"])
        return changed

    def test_positive_private_session_render_and_idempotent_persistence_are_offline(self):
        result = validate(self.record, 5)
        self.assertEqual(result["decision"], "approve")
        self.assertEqual(result["persistence"], "not_performed")
        self.assertEqual(result["live_ui"], "not_performed")
        self.assertEqual(rendering_inputs(self.record)["input_digest"], self.record["render"]["input_digest"])
        self.assertEqual(persist_final_event(self.record)["event_digest"], self.record["persistence"]["event_digest"])

    def test_approve_reject_clarify_timeout_and_cancel_have_distinct_semantics(self):
        for decision in ("approve", "reject", "clarify", "cancel"):
            result = validate(self.reseal_decision(decision), 5)
            self.assertEqual(result["decision"], decision)
        timeout = self.reseal_decision("timeout", human_present=False)
        self.assertEqual(validate(timeout, 5)["decision"], "timeout")

    def test_stale_tampered_duplicate_replacement_and_missing_presence_fail_closed(self):
        self.reject(lambda r: r["task"].update(revision=4))
        self.reject(lambda r: r["render"].update(input_digest=sha256({"tampered": True})))
        self.reject(lambda r: r["events"].__setitem__(2, copy.deepcopy(r["events"][1])))
        self.reject(lambda r: r["session"].update(generation=2))
        self.reject(lambda r: r["events"][2].update(human_present=False))
        self.reject(lambda r: r["final_event"].update(decision="approve", reason="human_selected", input_event_id="EVT-OTHER"))

    def test_privacy_timeout_cancellation_and_persistence_tampering_fail_closed(self):
        self.reject(lambda r: r["private_session"].update(file_mode="0644"))
        self.reject(lambda r: r["request"].update(prompt="do this"))
        self.reject(lambda r: r["persistence"].update(status="persisted"))
        self.reject(lambda r: r["persistence"].update(event_digest="sha256:" + "d" * 64))
        self.reject(lambda r: r["final_event"].update(reason="session_expired"))

    def test_checker_evidence_is_deterministic_and_rejects_wrong_revision(self):
        result = validate(self.record, 5)
        evidence = {"checker": "awr-production-ui-human-gate-checker/1.0.0", "task_revision": 5, "specification_digest": sha256(load(ROOT / "specifications/production-ui-human-gate-v1.json")), "record_digest": sha256(self.record), "result": result, "persistence": persist_final_event(self.record), "live_verification": "unverified"}
        self.assertEqual(check(self.spec, self.record, evidence, 5)["decision"], "approve")
        with self.assertRaises(SessionError):
            validate(self.record, 4)


if __name__ == "__main__":
    unittest.main()

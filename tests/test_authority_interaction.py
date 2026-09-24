import copy
import json
import unittest
from pathlib import Path

from scripts.authority_interaction_model import (
    AuthorityModelError,
    InteractionModel,
    bounded_model_check,
    refine_event,
)
from scripts.check_authority_interaction import (
    CheckError,
    check_corpus,
    validate_spec,
    validate_trace,
)

ROOT = Path(__file__).parents[1]
SPEC = json.loads((ROOT / "specifications/authority-interaction-v1.json").read_text())
POSITIVE = json.loads((ROOT / "specifications/fixtures/authority-interaction-ar0098-v1.json").read_text())
DIGEST = "sha256:" + "0" * 64


class AuthorityInteractionTests(unittest.TestCase):
    def reject(self, trace):
        with self.assertRaises(CheckError):
            validate_trace(trace, SPEC)

    def test_positive_two_job_interleaving_and_ui_change_control(self):
        validate_spec(SPEC)
        result = validate_trace(POSITIVE, SPEC)
        self.assertEqual(result["states"], {"JOB-A": "completed", "JOB-B": "completed"})
        self.assertEqual(result["actions"], 20)

    def test_skip_awc_lease_and_awq_acceptance(self):
        trace = copy.deepcopy(POSITIVE)
        trace["actions"] = trace["actions"][:2] + [copy.deepcopy(trace["actions"][4])]
        trace["actions"][-1].update(sequence=3)
        self.reject(trace)
        trace = copy.deepcopy(POSITIVE)
        trace["actions"] = trace["actions"][:5] + [copy.deepcopy(trace["actions"][17])]
        trace["actions"][-1].update(sequence=6, job_id="JOB-A", lease_id="LSE-A", action_id="skip-quality")
        self.reject(trace)

    def test_skip_awg_and_ui_decisions_is_rejected(self):
        trace = copy.deepcopy(POSITIVE)
        trace["actions"] = trace["actions"][:13] + [copy.deepcopy(trace["actions"][17])]
        trace["actions"][-1].update(sequence=14, job_id="JOB-A", lease_id="LSE-A", action_id="skip-awg")
        self.reject(trace)
        trace = copy.deepcopy(POSITIVE)
        trace["actions"] = trace["actions"][:15] + [copy.deepcopy(trace["actions"][17])]
        trace["actions"][-1].update(sequence=16, job_id="JOB-A", lease_id="LSE-A", action_id="skip-ui")
        self.reject(trace)

    def test_direct_awg_or_ui_mutation_and_llm_authorship_fail_closed(self):
        trace = copy.deepcopy(POSITIVE)
        trace["actions"][14]["authority"] = "awr"
        self.reject(trace)
        trace = copy.deepcopy(POSITIVE)
        trace["actions"][16]["authority"] = "awr"
        trace["actions"][16]["payload"]["source"] = "awr"
        self.reject(trace)
        trace = copy.deepcopy(POSITIVE)
        trace["actions"][14]["payload"]["source"] = "llm"
        self.reject(trace)

    def test_unresolved_repair_escalation_is_blocked_until_ui(self):
        model = InteractionModel(); model.add_job("JOB-R")
        actions = []
        def add(operation, authority, payload, lease=""):
            actions.append({"action_id": f"R-{len(actions)}", "sequence": len(actions) + 1, "job_id": "JOB-R", "authority": authority, "operation": operation, "task_revision": model.jobs["JOB-R"].revision, "lease_id": lease, "payload": payload})
            model.apply(actions[-1])
        add("admit", "awc", {"admitted": True, "revision": 1, "admission_digest": DIGEST})
        add("lease", "awc", {"new_lease_id": "LSE-R", "lease_digest": DIGEST})
        add("dispatch", "awr", {"admission_digest": DIGEST, "dispatch_digest": DIGEST}, "LSE-R")
        add("start", "awr", {"start_digest": DIGEST}, "LSE-R")
        add("evidence", "awr", {"evidence_digest": DIGEST}, "LSE-R")
        add("quality_accept", "awq", {"evidence_digest": DIGEST, "result": "accepted", "source": "awq"}, "LSE-R")
        add("repair_escalate", "awr", {"repair_digest": DIGEST, "reason": "bounded_repair_exhausted", "bounded_attempts": 2}, "LSE-R")
        add("guidance_decide", "awg", {"decision_digest": DIGEST, "decision": "requires_ui", "source": "awg"}, "LSE-R")
        self.assertEqual(model.jobs["JOB-R"].state, "ui_pending")
        blocked = copy.deepcopy(actions[-1])
        blocked.update(action_id="direct-resume", sequence=9, authority="awr", operation="continue", payload={"quality_digest": DIGEST})
        with self.assertRaises(AuthorityModelError):
            model.apply(blocked)
        expired = copy.deepcopy(actions[-1])
        expired.update(action_id="expired", sequence=9, authority="ui", operation="ui_decide", payload={"decision_digest": None, "decision": "unresolved", "outcome": "expired", "source": "ui"})
        model.apply(expired)
        self.assertEqual(model.jobs["JOB-R"].state, "blocked")

    def test_stale_replay_crossed_revision_and_recovery_fence(self):
        trace = copy.deepcopy(POSITIVE)
        trace["actions"][19]["task_revision"] = 0
        self.reject(trace)
        trace = copy.deepcopy(POSITIVE)
        trace["actions"][19]["action_id"] = trace["actions"][18]["action_id"]
        self.reject(trace)
        model = InteractionModel(); model.add_job("JOB-C")
        common = lambda operation, authority, payload, lease="": {"action_id": f"C-{len(model.event_ids)}", "sequence": len(model.event_ids)+1, "job_id": "JOB-C", "authority": authority, "operation": operation, "task_revision": model.jobs["JOB-C"].revision, "lease_id": lease, "payload": payload}
        model.apply(common("admit", "awc", {"admitted": True, "revision": 1, "admission_digest": DIGEST}))
        model.apply(common("lease", "awc", {"new_lease_id": "LSE-C", "lease_digest": DIGEST}))
        model.apply(common("dispatch", "awr", {"admission_digest": DIGEST, "dispatch_digest": DIGEST}, "LSE-C"))
        model.apply(common("start", "awr", {"start_digest": DIGEST}, "LSE-C"))
        model.apply(common("checkpoint", "awr", {"checkpoint_digest": DIGEST}, "LSE-C"))
        model.apply(common("crash", "awr", {"checkpoint_digest": DIGEST, "reason": "worker_lost"}, "LSE-C"))
        model.apply(common("recover", "awc", {"checkpoint_digest": DIGEST, "new_lease_id": "LSE-C-R", "new_revision": 2}, "LSE-C"))
        stale = common("dispatch", "awr", {"admission_digest": DIGEST, "dispatch_digest": DIGEST}, "LSE-C")
        stale["task_revision"] = 1
        with self.assertRaises(AuthorityModelError): model.apply(stale)

    def test_bounded_interleaving_and_refinement_map(self):
        result = bounded_model_check(4)
        self.assertGreater(result["states"], 1)
        self.assertGreater(result["accepted_edges"], 0)
        self.assertEqual(refine_event("running"), "dispatch")
        with self.assertRaises(AuthorityModelError): refine_event("untrusted-agent-output")

    def test_hostile_corpus_contract_accepts_fail_closed_cases(self):
        blocked = copy.deepcopy(POSITIVE)
        blocked["jobs"] = ["JOB-A"]
        blocked["actions"] = [copy.deepcopy(action) for action in POSITIVE["actions"] if action["job_id"] == "JOB-A"][:8]
        for sequence, action in enumerate(blocked["actions"], 1): action["sequence"] = sequence
        expired = copy.deepcopy(POSITIVE["actions"][16])
        expired.update(sequence=9, action_id="expired", authority="ui", operation="ui_decide", payload={"decision_digest": None, "decision": "unresolved", "outcome": "expired", "source": "ui"})
        blocked["actions"].append(expired)
        blocked["expected"] = {"JOB-A": "blocked"}
        cases = [{"name": "expired-ui", "expectation": "blocked", "trace": blocked}]
        self.assertEqual(check_corpus(SPEC, POSITIVE, cases)["hostile_blocked"], 1)


if __name__ == "__main__":
    unittest.main()

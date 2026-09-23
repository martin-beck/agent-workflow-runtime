import copy
import unittest
from pathlib import Path

from scripts.awg_decision_integration import DecisionError, digest, project, validate
from scripts.check_awg_decision_integration import check, load

ROOT = Path(__file__).parents[1]


class AwgDecisionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(ROOT / "specifications/awg-decision-integration-v1.json")
        self.record = load(ROOT / "specifications/fixtures/awg-decision-integration-ar0053-v1.json")
        self.record["request"]["binding_digest"] = digest({key: self.record[key] for key in ("task", "project", "worktree", "session")})
        self.record["response"]["binding_digest"] = digest({key: self.record[key] for key in ("task", "project", "worktree", "session", "request")})
        self.record["consumption"]["binding_digest"] = self.record["response"]["binding_digest"]

    def test_decision_and_guidance_are_consumed_only_when_awg_bound(self):
        result = validate(self.record, 5)
        self.assertEqual(result["consumption"], "applied")
        self.assertEqual(project(self.record, digest(self.spec))["selected_alternative_id"], "ALT-WORKFLOW")

    def reject(self, mutation):
        changed = copy.deepcopy(self.record)
        mutation(changed)
        with self.assertRaises(DecisionError):
            validate(changed, 5)

    def test_stale_conflicting_expired_and_replayed_inputs_block_or_fail(self):
        self.reject(lambda r: r["task"].update(revision=4))
        self.reject(lambda r: r["response"].update(decision_status="conflicting", decision_digest=None, selected_alternative_id=None))
        expired = copy.deepcopy(self.record)
        expired["response"].update(decision_status="expired", status="received", decision_digest=None, selected_alternative_id=None, observed_at=200)
        expired["consumption"].update(status="blocked_unresolved", decision_digest=None, selected_alternative_id=None, guidance_digests=[])
        self.assertEqual(validate(expired, 5)["consumption"], "blocked_unresolved")
        self.reject(lambda r: r["alternatives"][1].update(evidence_digest=r["alternatives"][0]["evidence_digest"]))

    def test_runtime_cannot_author_or_silently_choose(self):
        self.reject(lambda r: r["response"].update(source="runtime"))
        self.reject(lambda r: r["consumption"].update(selected_alternative_id="ALT-PROVIDER"))
        self.reject(lambda r: r["response"].update(guidance=[{"id": "GUIDE-LOCAL", "digest": "sha256:" + "9" * 64}]))

    def test_interrupted_transport_is_observed_without_implying_live_awg(self):
        self.assertEqual(validate(self.record, 5)["live_verification"], "unverified")
        self.reject(lambda r: r["transport"].update(network="performed"))

    def test_checker_evidence_is_deterministic(self):
        evidence = {"checker": "awr-awg-decision-integration-checker/1.0.0", "task_revision": 5, "record_digest": digest(self.record), "projection": project(self.record, digest(self.spec)), "live_verification": "unverified"}
        self.assertEqual(check(self.spec, self.record, evidence, 5)["decision_status"], "decided")


if __name__ == "__main__":
    unittest.main()

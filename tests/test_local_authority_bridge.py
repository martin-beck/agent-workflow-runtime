import copy
import unittest

from scripts.local_authority_bridge import (
    AuthorityBridgeError, digest, request_envelope, response_envelope,
    validate_exchange,
)
from scripts.check_local_authority_bridge import check


class LocalAuthorityBridgeTests(unittest.TestCase):
    def setUp(self):
        self.request = request_envelope(
            "awg", "OP-LOCAL-TEST", 9, digest({"question": "digest-only"}),
            task_id="AR-LOCAL-1", requested_kind="observation",
        )
        self.response = response_envelope(self.request, "requires_ui")

    def test_all_four_authorities_have_deterministic_offline_envelopes(self):
        first = check()
        self.assertEqual(first, check())
        self.assertEqual(first["authorities"], 4)
        self.assertEqual(first["network"], "disabled")
        self.assertEqual(first["durable_state"], "not_performed")

    def test_positive_revision_bound_exchange_is_observation_only(self):
        result = validate_exchange(self.request, self.response, expected_revision=9, required_authorities={"awg"})
        self.assertEqual(result["outcome"], "requires_ui")
        self.assertEqual(result["authority_state"], "observed_only")
        self.assertEqual(result["durable_state"], "not_performed")

    def reject(self, request=None, response=None, **kwargs):
        with self.assertRaises(AuthorityBridgeError):
            validate_exchange(request or self.request, response or self.response, expected_revision=9, **kwargs)

    def test_stale_revision_missing_authority_and_crossed_authority_fail_closed(self):
        stale = copy.deepcopy(self.response)
        stale["task_revision"] = 8
        self.reject(response=stale, required_authorities={"awg"})
        missing = copy.deepcopy(self.request)
        del missing["authority"]
        self.reject(request=missing, required_authorities={"awg"})
        wrong = copy.deepcopy(self.response)
        wrong["authority"] = "awq"
        self.reject(response=wrong, required_authorities={"awg"})
        self.reject(required_authorities={"awq"})

    def test_ambiguous_malformed_and_unbound_responses_fail_closed(self):
        for outcome in ("unknown", "ambiguous", "indeterminate"):
            response = response_envelope(self.request, outcome)
            self.reject(response=response, required_authorities={"awg"})
        bad_digest = copy.deepcopy(self.response)
        bad_digest["request_digest"] = digest("other request")
        self.reject(response=bad_digest, required_authorities={"awg"})
        bad_operation = copy.deepcopy(self.response)
        bad_operation["operation_id"] = "OP-OTHER"
        self.reject(response=bad_operation, required_authorities={"awg"})

    def test_autonomous_worker_cannot_author_decisions_tests_or_specifications(self):
        for kind in ("decision", "test", "specification"):
            with self.subTest(kind=kind), self.assertRaises(AuthorityBridgeError):
                request_envelope(
                    "awg", "OP-WORKER-" + kind.upper(), 9, digest(kind),
                    task_id="AR-LOCAL-1", actor="autonomous_worker", requested_kind=kind,
                )

    def test_worker_evidence_and_human_decision_requests_are_not_inferred(self):
        evidence = request_envelope(
            "awq", "OP-WORKER-EVIDENCE", 9, digest("evidence"),
            task_id="AR-LOCAL-1", actor="autonomous_worker", requested_kind="evidence",
        )
        self.assertEqual(validate_exchange(evidence, response_envelope(evidence, "accepted"), expected_revision=9, required_authorities={"awq"})["outcome"], "accepted")
        human = request_envelope(
            "ui", "OP-HUMAN-DECISION", 9, digest("choice-reference"),
            task_id="AR-LOCAL-1", actor="human", requested_kind="decision",
        )
        self.assertEqual(validate_exchange(human, response_envelope(human, "approved"), expected_revision=9, required_authorities={"ui"})["outcome"], "approved")


if __name__ == "__main__":
    unittest.main()


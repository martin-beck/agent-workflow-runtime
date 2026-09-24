import copy
import unittest
from pathlib import Path

from scripts.check_coordinator_client import check_record, check_spec, load
from scripts.coordinator_client import (
    CoordinatorBinding,
    CoordinatorClient,
    CoordinatorClientError,
    CoordinatorRejected,
    InProcessCoordinator,
    UnknownOutcome,
    digest,
)

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/coordinator-client-v1.json"
FIXTURE = ROOT / "specifications/fixtures/coordinator-client-ar0081-v1.json"


class CoordinatorClientTests(unittest.TestCase):
    def setUp(self):
        self.server = InProcessCoordinator()
        self.binding = CoordinatorBinding(
            "AR-0081",
            "agent-workflow-runtime",
            "agent-workflow-runtime-0081",
            "SES-AR0081-TEST",
            "WRK-AR0081-TEST",
            "LSE-AR0081-TEST",
            "AUTH-AR0081",
        )
        self.client = CoordinatorClient(self.server, self.binding)

    def test_spec_fixture_and_typed_read_write(self):
        spec, fixture = load(SPEC), load(FIXTURE)
        check_spec(spec)
        result = check_record(fixture, spec, 3)
        self.assertEqual(result["operations"], 3)
        read = self.client.read_revision(
            "OP-AR0081-READ", "CORR-AR0081-READ", expected_revision=1
        )
        self.assertEqual(
            (read.task_id, read.revision, read.event_count), ("AR-0081", 1, 0)
        )
        write = self.client.write_event(
            "OP-AR0081-WRITE",
            "CORR-AR0081-WRITE",
            expected_revision=1,
            event_kind="checkpoint",
            event_digest=digest({"checkpoint": 1}),
        )
        self.assertEqual((write.revision, write.event_count), (2, 1))

    def test_cas_stale_concurrent_write_fails_closed(self):
        first = self.client.write_event(
            "OP-AR0081-A",
            "CORR-AR0081-A",
            expected_revision=1,
            event_kind="checkpoint",
            event_digest=digest("a"),
        )
        self.assertEqual(first.revision, 2)
        with self.assertRaises(CoordinatorRejected) as error:
            self.client.write_event(
                "OP-AR0081-B",
                "CORR-AR0081-B",
                expected_revision=1,
                event_kind="checkpoint",
                event_digest=digest("b"),
            )
        self.assertEqual(error.exception.code, "stale_revision")
        self.assertEqual(len(self.server.events), 1)

    def test_retry_policy_is_bounded_and_only_retries_transport_faults(self):
        self.server.inject("unavailable", "deadline_exceeded")
        read = self.client.read_revision(
            "OP-AR0081-RETRY", "CORR-AR0081-RETRY", expected_revision=1
        )
        self.assertEqual(read.revision, 1)
        self.server.inject("unavailable", "unavailable", "unavailable")
        with self.assertRaises(CoordinatorRejected) as error:
            self.client.read_revision(
                "OP-AR0081-EXHAUST", "CORR-AR0081-EXHAUST", expected_revision=1
            )
        self.assertEqual(error.exception.code, "unavailable")

    def test_ambiguous_write_never_becomes_local_success_and_identical_retry_reconciles(
        self,
    ):
        event_digest = digest("ambiguous")
        self.server.inject("ambiguous_after_commit")
        with self.assertRaises(UnknownOutcome) as error:
            self.client.write_event(
                "OP-AR0081-AMB",
                "CORR-AR0081-AMB",
                expected_revision=1,
                event_kind="checkpoint",
                event_digest=event_digest,
            )
        self.assertEqual(
            (error.exception.operation_id, error.exception.correlation_id),
            ("OP-AR0081-AMB", "CORR-AR0081-AMB"),
        )
        self.assertEqual(len(self.server.events), 1)
        recovered = self.client.write_event(
            "OP-AR0081-AMB",
            "CORR-AR0081-AMB",
            expected_revision=1,
            event_kind="checkpoint",
            event_digest=event_digest,
        )
        self.assertEqual(recovered.revision, 2)
        self.assertEqual(len(self.server.events), 1)

    def test_hostile_correlation_auth_response_and_private_payloads(self):
        self.server.inject("malformed_response")
        with self.assertRaises(CoordinatorClientError) as error:
            self.client.read_revision(
                "OP-AR0081-MALFORMED", "CORR-AR0081-MALFORMED", expected_revision=1
            )
        self.assertEqual(str(error.exception), "response_correlation_mismatch")
        request = {
            "protocol": {"id": "awr-coordinator-client", "version": "1.0.0"},
            **self.binding.as_dict(),
            "operation": "read_revision",
            "operation_id": "OP-AR0081-PRIVATE",
            "correlation_id": "CORR-AR0081-PRIVATE",
            "expected_revision": 1,
            "timeout_ms": 1000,
            "attempt": 1,
            "auth_proof_digest": digest(
                {
                    "auth_reference": "AUTH-AR0081",
                    "correlation_id": "CORR-AR0081-PRIVATE",
                }
            ),
            "prompt": "private transcript",
        }
        with self.assertRaises(CoordinatorRejected) as error:
            self.server.exchange(request)
        self.assertEqual(error.exception.code, "privacy_or_operation_violation")

    def test_changed_replay_and_bounds_are_rejected(self):
        event_digest = digest("same")
        request = {
            "protocol": {"id": "awr-coordinator-client", "version": "1.0.0"},
            **self.binding.as_dict(),
            "operation": "write_event",
            "operation_id": "OP-AR0081-REPLAY",
            "correlation_id": "CORR-AR0081-REPLAY",
            "expected_revision": 1,
            "timeout_ms": 1000,
            "attempt": 1,
            "event_kind": "checkpoint",
            "event_digest": event_digest,
            "auth_proof_digest": digest(
                {
                    "auth_reference": "AUTH-AR0081",
                    "correlation_id": "CORR-AR0081-REPLAY",
                }
            ),
        }
        self.server.exchange(request)
        changed = copy.deepcopy(request)
        changed["event_digest"] = digest("changed")
        with self.assertRaises(CoordinatorRejected) as error:
            self.server.exchange(changed)
        self.assertEqual(error.exception.code, "changed_replay")
        with self.assertRaises(CoordinatorClientError):
            self.client.read_revision(
                "OP-AR0081-BOUNDS",
                "CORR-AR0081-BOUNDS",
                expected_revision=1,
                timeout_ms=0,
            )


if __name__ == "__main__":
    unittest.main()

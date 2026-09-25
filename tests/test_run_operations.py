# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.run_operations import RunOperations, RunOperationsError, digest


def binding():
    return {"run_id": "RUN-0138-1", "task_id": "AR-0138", "task_revision": 3,
            "project": "agent-workflow-runtime", "worktree_key": "agent-workflow-runtime-0138",
            "worktree_digest": digest("tree"), "graph_digest": digest("graph"), "owner": "WRK-0138",
            "session_id": "SES-0138-1", "lease_id": "LSE-0138-1", "lease_fence": 1,
            "lease_expires_at": 2000, "event_budget": 30, "accounting_budget": 100}


def observed(state, *, coordinator="running", checkpoint=None, authority=None, failure=""):
    return {"runtime_state": state, "coordinator_state": coordinator, "worker_id": "WRK-0138", "session_id": "SES-0138-1",
            "lease_id": "LSE-0138-1", "lease_fence": 1, "checkpoint_digest": checkpoint,
            "authority_observations": authority or {}, "failure_code": failure}


class RunOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "run-operations.json"
        self.now = 1000
        self.board = RunOperations(self.path, clock=lambda: self.now)
        self.board.start(binding(), "OP-START")

    def tearDown(self):
        self.temp.cleanup()

    def apply(self, command, op, **kwargs):
        revision = self.board.status("RUN-0138-1")["revision"]
        return self.board.apply(command, run_id="RUN-0138-1", operation_id=op, expected_revision=revision, lease_id="LSE-0138-1", lease_fence=1, **kwargs)

    def test_start_status_and_follow_are_durable_and_board_readable(self):
        status = self.board.status("RUN-0138-1")
        self.assertEqual((status["status"], status["events"], status["provider"], status["credentials"]), ("starting", 1, "not_performed", "not_inspected"))
        self.assertEqual([event["action"] for event in self.board.follow("RUN-0138-1")], ["start"])
        self.assertEqual(self.board.follow("RUN-0138-1", 1), [])
        with self.assertRaisesRegex(RunOperationsError, "run_not_found"):
            self.board.status("RUN-OTHER")

    def test_observation_accounting_and_artifact_digest_conserve(self):
        self.apply("observe", "OP-OBS-1", observation=observed("running"), accounting_delta=17,
                   artifacts=[{"artifact_id": "ART-1", "digest": digest("artifact")}])
        evidence = self.board.export_evidence("RUN-0138-1")
        RunOperations.validate_export(evidence)
        self.assertEqual(evidence["accounting"], {"budget": 100, "consumed": 17, "remaining": 83})
        self.assertEqual(evidence["artifacts"][0]["digest"], digest("artifact"))

    def test_interrupt_resume_and_checkpoint_recovery_are_fenced(self):
        self.apply("observe", "OP-OBS-1", observation=observed("running"))
        self.apply("interrupt", "OP-INT", observation={})
        self.assertEqual(self.board.status("RUN-0138-1")["status"], "interrupt_requested")
        checkpoint = digest("checkpoint")
        self.apply("observe", "OP-INT-ACK", observation=observed("interrupted", checkpoint=checkpoint))
        self.apply("resume", "OP-RESUME", observation={"checkpoint_digest": checkpoint})
        self.assertEqual(self.board.status("RUN-0138-1")["status"], "resume_requested")
        self.apply("observe", "OP-RESUMED", observation=observed("running"))
        self.apply("observe", "OP-INT-2", observation=observed("interrupted", checkpoint=checkpoint))
        self.now = 2001
        recovered = self.apply("recover", "OP-RECOVER", observation={"checkpoint_digest": checkpoint,
                "new_worker_id": "WRK-0138-2", "new_lease_id": "LSE-0138-2", "new_lease_fence": 2,
                "new_lease_expires_at": 3000, "runtime_state": "running"})
        self.assertEqual((recovered["status"], recovered["lease_id"], recovered["lease_fence"]), ("running", "LSE-0138-2", 2))
        reopened = RunOperations(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.status("RUN-0138-1")["owner"], "WRK-0138-2")
        self.assertEqual(reopened.follow("RUN-0138-1")[-1]["recovery_binding"]["lease_id"], "LSE-0138-2")

    def test_cancel_remains_requested_until_confirmed(self):
        self.apply("observe", "OP-OBS-1", observation=observed("running"))
        pending = self.apply("cancel", "OP-CANCEL", observation={})
        self.assertEqual(pending["status"], "cancel_requested")
        with self.assertRaisesRegex(RunOperationsError, "cancellation_unconfirmed"):
            self.apply("observe", "OP-CANCEL-FAKE", observation=observed("cancelled", coordinator="running"))

    def test_diagnose_reports_failure_without_promoting_it(self):
        self.apply("observe", "OP-OBS-1", observation=observed("running"))
        before = self.board.status("RUN-0138-1")
        report = self.board.diagnose("RUN-0138-1")
        self.assertEqual(report["classification"], "healthy_or_in_progress")
        self.assertEqual(self.board.status("RUN-0138-1"), before)
        self.assertEqual(self.board.status("RUN-0138-1")["status"], "running")

    def test_stale_revision_lease_replay_cross_run_and_ambiguous_success_reject(self):
        for args, message in [
            ({"expected_revision": 0}, "stale_revision"),
            ({"lease_id": "LSE-OTHER"}, "stale_lease"),
        ]:
            with self.assertRaisesRegex(RunOperationsError, message):
                self.board.apply("interrupt", run_id="RUN-0138-1", operation_id="OP-HOSTILE-" + message.upper().replace("_", "-"), expected_revision=args.get("expected_revision", 1),
                                 lease_id=args.get("lease_id", "LSE-0138-1"), lease_fence=1)
        with self.assertRaisesRegex(RunOperationsError, "run_binding_mismatch"):
            self.board.apply("interrupt", run_id="RUN-OTHER", operation_id="OP-CROSS-RUN", expected_revision=1,
                             lease_id="LSE-0138-1", lease_fence=1)
        with self.assertRaisesRegex(RunOperationsError, "observation_binding_mismatch"):
            self.apply("observe", "OP-WRONG-WORKER", observation={**observed("running"), "worker_id": "WRK-OTHER"})
        with self.assertRaisesRegex(RunOperationsError, "run_already_exists"):
            self.board.start(binding(), "OP-SECOND-START")
        with self.assertRaisesRegex(RunOperationsError, "unverified_lifecycle_transition"):
            self.apply("observe", "OP-SKIP-RUN", observation=observed("accepted", coordinator="done", authority={"awq": "accepted", "awg": "approved", "ui": "completed"}))
        self.apply("observe", "OP-OBS-1", observation=observed("running"))
        with self.assertRaisesRegex(RunOperationsError, "success_evidence_incomplete"):
            self.apply("observe", "OP-FAKE-SUCCESS", observation=observed("accepted", coordinator="unknown"))
        with self.assertRaisesRegex(RunOperationsError, "operation_replay"):
            self.apply("interrupt", "OP-OBS-1", observation={})

    def test_redaction_event_budget_and_accounting_budget_fail_closed(self):
        with self.assertRaisesRegex(RunOperationsError, "observation_invalid"):
            self.apply("observe", "OP-SECRET", observation={"prompt": "private"})
        with self.assertRaisesRegex(RunOperationsError, "accounting_budget_exceeded"):
            self.apply("observe", "OP-OVER", observation=observed("running"), accounting_delta=101)
        value = json.loads(self.path.read_text())
        value["binding"]["event_budget"] = 1
        self.path.write_text(json.dumps(value))
        with self.assertRaisesRegex(RunOperationsError, "event_budget_exceeded"):
            self.board.apply("observe", run_id="RUN-0138-1", operation_id="OP-OVER-EVENT", expected_revision=1,
                             observation=observed("running"),
                             lease_id="LSE-0138-1", lease_fence=1)

    def test_restart_and_export_tampering_are_detected(self):
        self.apply("observe", "OP-OBS-1", observation=observed("running"), accounting_delta=4)
        reopened = RunOperations(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.status("RUN-0138-1"), self.board.status("RUN-0138-1"))
        record = reopened.export_evidence("RUN-0138-1")
        damaged = copy.deepcopy(record); damaged["events"][0]["state_after"] = "accepted"
        with self.assertRaisesRegex(RunOperationsError, "export_integrity_failure"):
            reopened.validate_export(damaged)
        raw = json.loads(self.path.read_text()); raw["events"][0]["action"] = "cancel"
        self.path.write_text(json.dumps(raw))
        with self.assertRaisesRegex(RunOperationsError, "journal_integrity_failure"):
            reopened.status("RUN-0138-1")

    def test_expired_lease_rejects_commands_until_checkpoint_recovery(self):
        self.apply("observe", "OP-OBS-1", observation=observed("running"))
        checkpoint = digest("checkpoint-expiry")
        self.apply("observe", "OP-INTERRUPT", observation=observed("interrupted", checkpoint=checkpoint))
        self.now = 2000
        with self.assertRaisesRegex(RunOperationsError, "lease_still_active"):
            self.apply("recover", "OP-RECOVER-EARLY", observation={"checkpoint_digest": checkpoint,
                "new_worker_id": "WRK-0138-2", "new_lease_id": "LSE-0138-2", "new_lease_fence": 2,
                "new_lease_expires_at": 3000, "runtime_state": "running"})
        self.now = 2001
        recovered = self.apply("recover", "OP-RECOVER-EXPIRED", observation={"checkpoint_digest": checkpoint,
            "new_worker_id": "WRK-0138-2", "new_lease_id": "LSE-0138-2", "new_lease_fence": 2,
            "new_lease_expires_at": 3000, "runtime_state": "running"})
        self.assertEqual(recovered["status"], "running")

    def test_acceptance_requires_complete_authority_evidence_from_running(self):
        self.apply("observe", "OP-OBS-1", observation=observed("running"))
        accepted = observed("accepted", coordinator="done", authority={"awq": "accepted", "awg": "approved", "ui": "completed"})
        self.apply("observe", "OP-ACCEPT", observation=accepted)
        self.assertEqual(self.board.status("RUN-0138-1")["status"], "accepted")


if __name__ == "__main__":
    unittest.main()

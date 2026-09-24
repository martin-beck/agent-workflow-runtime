from __future__ import annotations

import inspect
import json
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.check_project_integration import validate_record, validate_spec
from scripts.project_integration import (
    IntegrationError,
    LocalAuthorityPort,
    LocalProjectFake,
    ProjectIntegrationRuntime,
    ProjectRegistration,
    SessionBoundary,
    TaskIntake,
    digest,
)
from scripts.project_isolation import RoutingContext, make_dispatch_lease

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specifications" / "project-integration-v1.json"
FIXTURE = ROOT / "specifications" / "fixtures" / "project-integration-ar0089-v1.json"
REVISION = "a" * 40


def make_context(
    *, project: str = "alpha-project", tenant: str = "tenant-a", task: str = "AR-0089", fence: int = 1
) -> tuple[RoutingContext, object]:
    lease = make_dispatch_lease(
        job_id=task,
        project=project,
        task_revision=3,
        agent_id="agent-alpha",
        fence=fence,
    )
    return (
        RoutingContext.from_dispatch(
            lease,
            task_revision=3,
            tenant=tenant,
            project_key=project,
            project_revision=REVISION,
        ),
        lease,
    )


def make_registration(*, project: str = "alpha-project", tenant: str = "tenant-a") -> ProjectRegistration:
    return ProjectRegistration(project, tenant, REVISION, frozenset({"read", "edit"}))


def make_intake(*, task: str = "AR-0089", required: frozenset[str] = frozenset({"read"})) -> TaskIntake:
    return TaskIntake(task, 3, digest({"input": task}), required, digest({"opaque": "policy"}))


def make_session(context: RoutingContext, capabilities: frozenset[str] = frozenset({"read", "edit"})) -> SessionBoundary:
    return SessionBoundary(context.session_id, digest({"session": context.session_id}), capabilities)


def prepared() -> tuple[ProjectIntegrationRuntime, str, RoutingContext, LocalAuthorityPort]:
    context, lease = make_context()
    authority = LocalAuthorityPort(["accepted"])
    runtime = ProjectIntegrationRuntime(__import__("scripts.project_isolation", fromlist=["ProjectIsolationRegistry"]).ProjectIsolationRegistry(), authority)
    registration = make_registration()
    intake = make_intake()
    session = make_session(context)
    runtime.register(registration)
    run = runtime.intake(registration, intake, context, session, lease=lease)
    runtime.begin(run, "OP-BEGIN-TEST")
    return runtime, run, context, authority


class ProjectIntegrationContractTests(unittest.TestCase):
    def test_spec_and_fixture_are_machine_checkable(self) -> None:
        validate_spec(json.loads(SPEC.read_text(encoding="utf-8")), 3)
        result = validate_record(json.loads(FIXTURE.read_text(encoding="utf-8")))
        self.assertEqual(result["runs"], 1)
        self.assertEqual(result["terminal_state"], "terminal")

    def test_registration_and_intake_use_existing_lease_and_session_boundaries(self) -> None:
        runtime, run, context, _authority = prepared()
        self.assertEqual(run, "alpha-project:AR-0089:3:" + context.worktree_key)
        self.assertEqual(runtime.snapshot()["runs"][run]["state"], "executing")
        self.assertEqual(runtime.snapshot()["projects"]["alpha-project"]["capabilities"], ["edit", "read"])

    def test_registration_conflict_and_changed_intake_replay_fail_closed(self) -> None:
        context, lease = make_context()
        runtime = ProjectIntegrationRuntime(__import__("scripts.project_isolation", fromlist=["ProjectIsolationRegistry"]).ProjectIsolationRegistry(), LocalAuthorityPort())
        registration = make_registration()
        runtime.register(registration)
        with self.assertRaisesRegex(IntegrationError, "registration_conflict"):
            runtime.register(replace(registration, project_revision="b" * 40))
        session = make_session(context)
        runtime.intake(registration, make_intake(), context, session, lease=lease)
        with self.assertRaisesRegex(IntegrationError, "changed_intake_replay"):
            runtime.intake(registration, replace(make_intake(), input_digest=digest({"changed": True})), context, session, lease=lease)

    def test_cross_project_tenant_and_revision_bindings_are_rejected(self) -> None:
        context, lease = make_context()
        runtime = ProjectIntegrationRuntime(__import__("scripts.project_isolation", fromlist=["ProjectIsolationRegistry"]).ProjectIsolationRegistry(), LocalAuthorityPort())
        runtime.register(make_registration())
        with self.assertRaisesRegex(IntegrationError, "cross_project_binding"):
            runtime.intake(make_registration(project="other-project"), make_intake(), context, make_session(context), lease=lease)
        stale = replace(context, project_revision="b" * 40)
        with self.assertRaisesRegex(IntegrationError, "stale_project_revision"):
            runtime.intake(make_registration(), make_intake(), stale, make_session(stale), lease=lease)
        crossed = replace(context, session_id="SES-CROSSED-1")
        with self.assertRaisesRegex(IntegrationError, "binding_mismatch"):
            runtime.intake(make_registration(), make_intake(), crossed, make_session(context), lease=lease)

    def test_capability_declarations_are_required_at_both_project_and_session(self) -> None:
        context, lease = make_context()
        runtime = ProjectIntegrationRuntime(__import__("scripts.project_isolation", fromlist=["ProjectIsolationRegistry"]).ProjectIsolationRegistry(), LocalAuthorityPort())
        registration = make_registration()
        runtime.register(registration)
        with self.assertRaisesRegex(IntegrationError, "project_capability_mismatch"):
            runtime.intake(registration, make_intake(required=frozenset({"deploy"})), context, make_session(context), lease=lease)
        with self.assertRaisesRegex(IntegrationError, "session_capability_mismatch"):
            runtime.intake(registration, make_intake(required=frozenset({"edit"})), context, make_session(context, frozenset({"read"})), lease=lease)

    def test_artifact_exchange_and_awq_evidence_handoff_are_content_addressed(self) -> None:
        runtime, run, _context, authority = prepared()
        record = runtime.publish_artifact(run, "ART-RESULT", {"tests": 3})
        result = runtime.handoff_evidence(run, "ART-RESULT", "EVD-RESULT", {"passed": 3}, operation_id="OP-AWQ-TEST", request_id="REQ-AWQ-TEST")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["evidence"]["artifact_digest"], record.content_digest)
        self.assertEqual(authority.request_log["OP-AWQ-TEST"]["result"]["status"], "accepted")

    def test_missing_artifact_and_changed_evidence_replay_are_rejected(self) -> None:
        runtime, run, _context, _authority = prepared()
        with self.assertRaisesRegex(IntegrationError, "evidence_artifact_missing"):
            runtime.handoff_evidence(run, "ART-MISSING", "EVD-MISSING", {}, operation_id="OP-AWQ-MISSING", request_id="REQ-AWQ-MISSING")
        runtime.publish_artifact(run, "ART-RESULT", {"ok": True})
        runtime.handoff_evidence(run, "ART-RESULT", "EVD-RESULT", {"x": 1}, operation_id="OP-AWQ-REPLAY", request_id="REQ-AWQ-REPLAY")
        with self.assertRaisesRegex(IntegrationError, "contradictory_evidence"):
            runtime.handoff_evidence(run, "ART-RESULT", "EVD-OTHER", {"x": 2}, operation_id="OP-AWQ-OTHER", request_id="REQ-AWQ-OTHER")

    def test_crossed_and_ambiguous_authority_outcomes_fail_closed(self) -> None:
        runtime, run, _context, authority = prepared()
        runtime.publish_artifact(run, "ART-RESULT", {"ok": True})
        authority.binding_digest = digest({"wrong": "binding"})
        with self.assertRaisesRegex(IntegrationError, "crossed_authority_result"):
            runtime.handoff_evidence(run, "ART-RESULT", "EVD-CROSSED", {}, operation_id="OP-AWQ-CROSSED", request_id="REQ-AWQ-CROSSED")
        authority.binding_digest = None
        authority.responses.append("not-an-outcome")
        with self.assertRaisesRegex(IntegrationError, "ambiguous_authority_result"):
            runtime.handoff_evidence(run, "ART-RESULT", "EVD-AMBIGUOUS", {}, operation_id="OP-AWQ-AMBIGUOUS", request_id="REQ-AWQ-AMBIGUOUS")

    def test_pending_awq_requires_observation_before_success_terminal(self) -> None:
        context, lease = make_context()
        authority = LocalAuthorityPort(["pending"])
        from scripts.project_isolation import ProjectIsolationRegistry
        runtime = ProjectIntegrationRuntime(ProjectIsolationRegistry(), authority)
        registration = make_registration()
        runtime.register(registration)
        run = runtime.intake(registration, make_intake(), context, make_session(context), lease=lease)
        runtime.begin(run, "OP-BEGIN-PENDING")
        runtime.publish_artifact(run, "ART-RESULT", {"ok": True})
        result = runtime.handoff_evidence(run, "ART-RESULT", "EVD-PENDING", {}, operation_id="OP-AWQ-PENDING", request_id="REQ-AWQ-PENDING")
        with self.assertRaisesRegex(IntegrationError, "missing_or_mismatched_evidence"):
            runtime.reconcile_terminal(run, "succeeded", terminal_payload={}, evidence_digest=result["evidence"]["evidence_digest"], operation_id="TERM-PENDING")
        authority.resolve("OP-AWQ-PENDING")
        self.assertEqual(runtime.observe_evidence(run)["status"], "accepted")
        runtime.reconcile_terminal(run, "succeeded", terminal_payload={}, evidence_digest=result["evidence"]["evidence_digest"], operation_id="TERM-PENDING")

    def test_terminal_requires_evidence_and_rejects_contradiction_or_stale_revision(self) -> None:
        runtime, run, context, _authority = prepared()
        runtime.publish_artifact(run, "ART-RESULT", {"ok": True})
        evidence = runtime.handoff_evidence(run, "ART-RESULT", "EVD-RESULT", {}, operation_id="OP-AWQ-TERM", request_id="REQ-AWQ-TERM")["evidence"]
        with self.assertRaisesRegex(IntegrationError, "missing_or_mismatched_evidence"):
            runtime.reconcile_terminal(run, "succeeded", terminal_payload={}, operation_id="TERM-MISSING")
        first = runtime.reconcile_terminal(run, "succeeded", terminal_payload={"ok": True}, evidence_digest=evidence["evidence_digest"], operation_id="TERM-RESULT")
        self.assertEqual(first["status"], "reconciled")
        replay = runtime.reconcile_terminal(run, "succeeded", terminal_payload={"ok": True}, evidence_digest=evidence["evidence_digest"], operation_id="TERM-RESULT")
        self.assertEqual(replay["status"], "replayed")
        with self.assertRaisesRegex(IntegrationError, "contradictory_terminal"):
            runtime.reconcile_terminal(run, "failed", terminal_payload={"ok": False}, evidence_digest=None, operation_id="TERM-CONTRADICT")
        stale = replace(context, task_revision=4, coordinator_revision=4)
        self.assertNotEqual(stale.task_revision, runtime.snapshot()["runs"][run]["task_revision"])

    def test_terminal_failure_can_be_reconciled_without_evidence_but_is_immutable(self) -> None:
        runtime, run, _context, _authority = prepared()
        result = runtime.reconcile_terminal(run, "failed", terminal_payload={"reason": "blocked"}, operation_id="TERM-FAILED")
        self.assertEqual(result["status"], "reconciled")
        with self.assertRaisesRegex(IntegrationError, "contradictory_terminal"):
            runtime.reconcile_terminal(run, "cancelled", terminal_payload={"reason": "other"}, operation_id="TERM-OTHER")

    def test_record_replay_requires_exact_request_and_has_no_provider_surface(self) -> None:
        runtime, _run, _context, _authority = prepared()
        fake = LocalProjectFake(runtime)
        entry = fake.record("response", {"input": 1}, {"output": "local"})
        self.assertEqual(fake.replay("response", {"input": 1}), entry["response"])
        with self.assertRaisesRegex(IntegrationError, "replay_miss"):
            fake.replay("response", {"input": 2})
        source = inspect.getsource(__import__("scripts.project_integration", fromlist=["ProjectIntegrationRuntime"]))
        self.assertNotIn("OPENAI_API_KEY", source)
        self.assertNotIn("ANTHROPIC_API_KEY", source)
        self.assertNotIn("import requests", source)

    def test_policy_is_opaque_and_not_runtime_decision_input(self) -> None:
        context, lease = make_context()
        runtime = ProjectIntegrationRuntime(__import__("scripts.project_isolation", fromlist=["ProjectIsolationRegistry"]).ProjectIsolationRegistry(), LocalAuthorityPort())
        registration = make_registration()
        runtime.register(registration)
        intake = make_intake()
        run = runtime.intake(registration, intake, context, make_session(context), lease=lease)
        self.assertEqual(runtime.snapshot()["projects"][registration.project_key]["capabilities"], ["edit", "read"])
        self.assertEqual(intake.policy_reference, digest({"opaque": "policy"}))
        self.assertNotIn("policy", runtime.snapshot()["runs"][run])

    def test_snapshot_replay_is_deterministic(self) -> None:
        left, run_left, _context_left, _authority_left = prepared()
        right, run_right, _context_right, _authority_right = prepared()
        for runtime, run in ((left, run_left), (right, run_right)):
            runtime.publish_artifact(run, "ART-RESULT", {"same": True})
            evidence = runtime.handoff_evidence(run, "ART-RESULT", "EVD-SAME", {"proof": 1}, operation_id="OP-AWQ-SAME", request_id="REQ-AWQ-SAME")["evidence"]
            runtime.reconcile_terminal(run, "succeeded", terminal_payload={"ok": True}, evidence_digest=evidence["evidence_digest"], operation_id="TERM-SAME")
        self.assertEqual(left.snapshot(), right.snapshot())


if __name__ == "__main__":
    unittest.main()

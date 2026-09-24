from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.check_project_isolation import validate_record, validate_spec
from scripts.fair_scheduler import (
    AgentSlot,
    FairScheduler,
    JobSpec,
    Resources,
)
from scripts.fair_scheduler import digest as scheduler_digest
from scripts.project_isolation import (
    IsolationError,
    LocalProjectFake,
    ProjectIsolationRegistry,
    RoutingContext,
    UnknownCleanupOutcome,
    digest,
    make_dispatch_lease,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specifications" / "multi-project-isolation-v1.json"
FIXTURE = (
    ROOT / "specifications" / "fixtures" / "multi-project-isolation-ar0087-v1.json"
)

REV_A = "a" * 40
REV_B = "b" * 40


def context(
    *,
    project: str = "project-one",
    tenant: str = "tenant-a",
    task: str = "AR-0087",
    fence: int = 1,
    worktree: str | None = None,
) -> RoutingContext:
    lease = make_dispatch_lease(
        job_id=task,
        project=project,
        task_revision=3,
        agent_id=f"agent-{project.split('-')[-1]}",
        fence=fence,
    )
    if worktree is not None:
        lease = replace(lease, worktree_key=worktree)
    return RoutingContext.from_dispatch(
        lease,
        task_revision=3,
        tenant=tenant,
        project_key=project,
        project_revision=REV_A if project == "project-one" else REV_B,
    )


def registry_with(*contexts: RoutingContext) -> ProjectIsolationRegistry:
    registry = ProjectIsolationRegistry()
    for item in contexts:
        registry.register_project(
            item.project_key,
            tenant=item.tenant,
            project_revision=item.project_revision,
        )
    for item in contexts:
        registry.allocate_worktree(item)
    return registry


class ProjectIsolationTests(unittest.TestCase):
    def test_spec_and_fixture_are_machine_checkable(self) -> None:
        spec = __import__("json").loads(SPEC.read_text(encoding="utf-8"))
        record = __import__("json").loads(FIXTURE.read_text(encoding="utf-8"))
        validate_spec(spec, 3)
        result = validate_record(record)
        self.assertEqual(result["projects"], 2)
        self.assertEqual(
            result["final_worktree_states"],
            {"project-one": "cleaned", "project-two": "active"},
        )

    def test_real_ar0086_dispatch_lease_is_consumed_without_new_lease_authority(
        self,
    ) -> None:
        scheduler = FairScheduler(
            Resources(cpu=2, memory=2, disk=2), max_concurrency=2, authority_revision=3
        )
        profile = AgentSlot(
            "agent-a",
            scheduler_digest({"profile": "a"}),
            capabilities=frozenset({"read", "edit"}),
            capacity=Resources(cpu=2, memory=2, disk=2),
        )
        scheduler.register_agent(profile)
        scheduler.admit(
            "OP-ADMIT-0087",
            JobSpec(
                "JOB-0087",
                "tenant-a",
                "project-one",
                required_capabilities=frozenset({"edit"}),
                coordinator_revision=3,
            ),
        )
        lease = scheduler.dispatch("OP-DISPATCH-0087", now=0)
        self.assertIsNotNone(lease)
        item = RoutingContext.from_dispatch(
            lease,
            task_revision=3,
            tenant="tenant-a",
            project_key="project-one",
            project_revision=REV_A,
        )
        registry = registry_with(item)
        self.assertEqual(
            registry.snapshot()["worktrees"]["project-one-0087"]["state"], "active"
        )
        self.assertEqual(
            registry.snapshot()["worktrees"]["project-one-0087"]["fence"], lease.fence
        )

    def test_two_projects_are_isolated_and_have_distinct_opaque_paths(self) -> None:
        first, second = (
            context(),
            context(project="project-two", worktree="WT-PROJECT-TWO-0087-1"),
        )
        registry = registry_with(first, second)
        fake = LocalProjectFake(registry)
        first_record = fake.publish_json(
            first, "ART-BUILD", {"project": "one", "value": 1}
        )
        second_record = fake.publish_json(
            second, "ART-BUILD", {"project": "two", "value": 2}
        )
        self.assertNotEqual(first_record.content_digest, second_record.content_digest)
        snapshot = registry.snapshot()
        self.assertEqual(
            snapshot["worktrees"][first.worktree_key]["path_token"],
            "wt://project-one/" + first.worktree_key,
        )
        self.assertEqual(
            snapshot["worktrees"][second.worktree_key]["path_token"],
            "wt://project-two/" + second.worktree_key,
        )
        with self.assertRaisesRegex(IsolationError, "artifact_not_routable"):
            registry.read_artifact(first, "ART-MISSING")
        crossed = replace(first, worktree_key=second.worktree_key)
        with self.assertRaisesRegex(IsolationError, "cross_project_or_revision"):
            registry.read_artifact(crossed, "ART-BUILD")

    def test_same_project_artifact_replay_is_idempotent_but_mutation_is_rejected(
        self,
    ) -> None:
        item = context()
        registry = registry_with(item)
        first = registry.put_artifact(item, "ART-RESULT", {"ok": True})
        replay = registry.put_artifact(item, "ART-RESULT", {"ok": True})
        self.assertEqual(first, replay)
        with self.assertRaisesRegex(
            IsolationError, "artifact_rewrite_or_digest_mismatch"
        ):
            registry.put_artifact(item, "ART-RESULT", {"ok": False})
        record, payload = registry.read_artifact(item, "ART-RESULT")
        self.assertEqual(
            record.provenance_digest,
            digest(
                {
                    "artifact_id": "ART-RESULT",
                    "context": item.as_dict(),
                    "content_digest": digest({"ok": True}),
                }
            ),
        )
        self.assertEqual(payload, {"ok": True})

    def test_storage_tampering_is_detected_by_content_digest_on_read(self) -> None:
        item = context()
        registry = registry_with(item)
        record = registry.put_artifact(item, "ART-TAMPER", {"safe": True})
        registry._payloads[(item.project_key, item.worktree_key, "ART-TAMPER")] = {
            "safe": False
        }
        with self.assertRaisesRegex(IsolationError, "artifact_content_digest_mismatch"):
            registry.read_artifact(item, "ART-TAMPER")
        with self.assertRaisesRegex(IsolationError, "artifact_content_digest_mismatch"):
            registry.allow_dependency(
                "project-one",
                "project-one",
                "ART-TAMPER",
                source_worktree_key=item.worktree_key,
                content_digest=record.content_digest,
                provenance_digest=record.provenance_digest,
            )

    def test_dependency_inputs_require_explicit_same_tenant_grant(self) -> None:
        producer = context(project="project-one")
        consumer = context(project="project-two", worktree="WT-PROJECT-TWO-0087-1")
        other_tenant = context(
            project="project-three",
            tenant="tenant-b",
            worktree="WT-PROJECT-THREE-0087-1",
        )
        registry = registry_with(producer, consumer, other_tenant)
        source = registry.put_artifact(producer, "ART-API", {"schema": 1})
        with self.assertRaisesRegex(IsolationError, "dependency_not_granted"):
            registry.read_dependency(consumer, "project-one", "ART-API")
        registry.allow_dependency(
            "project-two",
            "project-one",
            "ART-API",
            source_worktree_key=producer.worktree_key,
            content_digest=source.content_digest,
            provenance_digest=source.provenance_digest,
        )
        record, payload = registry.read_dependency(consumer, "project-one", "ART-API")
        self.assertEqual((record.project_key, payload), ("project-one", {"schema": 1}))
        with self.assertRaisesRegex(IsolationError, "cross_tenant_dependency"):
            registry.allow_dependency(
                "project-three",
                "project-one",
                "ART-API",
                source_worktree_key=producer.worktree_key,
                content_digest=source.content_digest,
                provenance_digest=source.provenance_digest,
            )
        with self.assertRaisesRegex(IsolationError, "cross_tenant_dependency"):
            registry.read_dependency(other_tenant, "project-one", "ART-API")

    def test_revision_lease_and_project_crossing_fail_closed(self) -> None:
        item = context()
        registry = registry_with(item)
        stale_revision = replace(item, task_revision=4, coordinator_revision=4)
        with self.assertRaisesRegex(IsolationError, "cross_project_or_revision"):
            registry.put_artifact(stale_revision, "ART-STALE", {"x": 1})
        wrong_project_revision = replace(item, project_revision=REV_B)
        with self.assertRaisesRegex(IsolationError, "cross_project_or_revision"):
            registry.put_artifact(wrong_project_revision, "ART-CROSSED", {"x": 1})
        wrong_worker = replace(item, worker_id="agent-other")
        with self.assertRaisesRegex(
            IsolationError, "stale_or_crossed_worktree_binding"
        ):
            registry.put_artifact(wrong_worker, "ART-CROSSED", {"x": 1})

    def test_worktree_collision_and_registration_conflict_are_rejected(self) -> None:
        item = context()
        registry = ProjectIsolationRegistry()
        registry.register_project(
            "project-one", tenant="tenant-a", project_revision=REV_A
        )
        registry.allocate_worktree(item)
        collision = context(project="project-one", fence=2, worktree=item.worktree_key)
        with self.assertRaisesRegex(IsolationError, "worktree_collision"):
            registry.allocate_worktree(collision)
        with self.assertRaisesRegex(IsolationError, "project_registration_conflict"):
            registry.register_project(
                "project-one", tenant="tenant-b", project_revision=REV_A
            )

    def test_interrupted_cleanup_requires_new_fence_and_preserves_artifacts(
        self,
    ) -> None:
        item = context()
        registry = registry_with(item)
        registry.put_artifact(item, "ART-BEFORE-CLEANUP", {"kept": True})
        with self.assertRaisesRegex(UnknownCleanupOutcome, "cleanup_response_lost"):
            registry.cleanup_worktree(item, "OP-CLEANUP-0087", interrupted=True)
        self.assertEqual(
            registry.snapshot()["worktrees"][item.worktree_key]["state"],
            "cleanup_pending",
        )
        with self.assertRaisesRegex(IsolationError, "recovery_requires_new_fence"):
            registry.recover_cleanup(item, "OP-RECOVER-OLD")
        recovered = replace(
            item,
            worker_id="agent-recovered",
            lease_id="LSE-RECOVERED-2",
            session_id="SES-RECOVERED-2",
            fence=2,
        )
        self.assertEqual(
            registry.recover_cleanup(recovered, "OP-RECOVER-0087")["disposition"],
            "recovered_cleaned",
        )
        with self.assertRaisesRegex(IsolationError, "worktree_not_active"):
            registry.read_artifact(recovered, "ART-BEFORE-CLEANUP")
        self.assertEqual(
            registry.snapshot()["worktrees"][item.worktree_key]["state"], "cleaned"
        )

    def test_cleanup_replay_and_conflicting_replay_are_fenced(self) -> None:
        item = context()
        registry = registry_with(item)
        result = registry.cleanup_worktree(item, "OP-CLEANUP-REPLAY")
        self.assertEqual(registry.cleanup_worktree(item, "OP-CLEANUP-REPLAY"), result)
        with self.assertRaisesRegex(IsolationError, "idempotency_conflict"):
            registry.cleanup_worktree(item, "OP-CLEANUP-REPLAY", interrupted=True)

    def test_payload_is_copied_and_concurrent_interleaving_is_deterministic(
        self,
    ) -> None:
        first, second = (
            context(),
            context(project="project-two", worktree="WT-PROJECT-TWO-0087-1"),
        )
        left = registry_with(first, second)
        right = registry_with(first, second)
        payload = {"items": ["a", "b"]}
        left.put_artifact(first, "ART-ONE", payload)
        payload["items"].append("mutated")
        right.put_artifact(first, "ART-ONE", {"items": ["a", "b"]})
        left.put_artifact(second, "ART-TWO", {"from": "two"})
        right.put_artifact(second, "ART-TWO", {"from": "two"})
        self.assertEqual(left.snapshot(), right.snapshot())

    def test_unknown_or_malformed_bindings_never_allocate(self) -> None:
        registry = ProjectIsolationRegistry()
        bad = copy.copy(context())
        bad = replace(bad, tenant="tenant-bad!")
        with self.assertRaisesRegex(IsolationError, "invalid_tenant"):
            registry.allocate_worktree(bad)
        self.assertEqual(registry.snapshot()["worktrees"], {})


if __name__ == "__main__":
    unittest.main()

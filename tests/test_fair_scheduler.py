import unittest
from pathlib import Path

from scripts.check_fair_scheduler import load, validate, validate_spec
from scripts.fair_scheduler import (
    AgentSlot,
    FairScheduler,
    JobSpec,
    Resources,
    SchedulingError,
    digest,
)

ROOT = Path(__file__).parents[1]
REGISTRY = "sha256:" + "a" * 64
PROFILE_A = "sha256:" + "1" * 64
PROFILE_B = "sha256:" + "2" * 64


def agent(name, profile=PROFILE_A, capabilities=("coding", "review"), maximum=1):
    return AgentSlot(
        name,
        profile,
        frozenset(capabilities),
        Resources(2, 2, 2),
        maximum,
        REGISTRY,
    )


def job(name, tenant="tenant-a", project="project-a", **overrides):
    values = {
        "job_id": name,
        "tenant": tenant,
        "project": project,
        "resources": Resources(1, 1, 1),
        "coordinator_revision": 7,
        "registry_digest": REGISTRY,
    }
    values.update(overrides)
    return JobSpec(**values)


def scheduler(**overrides):
    values = {
        "capacity": Resources(4, 4, 4),
        "max_concurrency": 2,
        "max_queued": 32,
        "lease_seconds": 4,
        "aging_quantum": 2,
        "tenant_quotas": {"tenant-a": 8, "tenant-b": 8},
        "project_quotas": {"project-a": 8, "project-b": 8},
        "agent_quotas": {"agent-a": 1, "agent-b": 1},
        "authority_revision": 7,
        "registry_digest": REGISTRY,
    }
    values.update(overrides)
    result = FairScheduler(**values)
    result.register_agent(agent("agent-a", PROFILE_A))
    result.register_agent(agent("agent-b", PROFILE_B))
    return result


class FairSchedulerTests(unittest.TestCase):
    def test_machine_checked_fixture_and_contract(self):
        spec = load(ROOT / "specifications/fair-scheduler-v1.json")
        fixture = load(ROOT / "specifications/fixtures/fair-scheduler-ar0086-v1.json")
        validate_spec(spec, 3)
        result = validate(fixture)
        self.assertEqual(result["states"], {"JOB-A": "succeeded", "JOB-B": "succeeded", "JOB-C": "succeeded"})
        self.assertEqual(result["fence"], 4)
        self.assertFalse(result["execute"])

    def test_dependency_dag_readiness_and_terminal_propagation(self):
        s = scheduler()
        s.admit("OP-A", job("JOB-A"))
        s.admit("OP-B", job("JOB-B", dependencies=("JOB-A",)))
        lease = s.dispatch("OP-D0", now=0, agent_id="agent-a")
        self.assertEqual(lease.job_id, "JOB-A")
        s.complete("OP-C-A", job_id="JOB-A", lease=lease, now=1)
        child = s.dispatch("OP-D2", now=1)
        self.assertEqual(child.job_id, "JOB-B")
        s.complete("OP-C-B", job_id="JOB-B", lease=child, now=2)
        self.assertEqual({item.state for item in s.jobs.values()}, {"succeeded"})

        failed = scheduler()
        failed.admit("OP-X", job("JOB-X", max_attempts=1))
        failed.admit("OP-Y", job("JOB-Y", dependencies=("JOB-X",)))
        xlease = failed.dispatch("OP-X-D", now=0)
        failed.fail("OP-X-F", job_id="JOB-X", lease=xlease, reason="permanent", now=1)
        self.assertIsNone(failed.dispatch("OP-Y-D", now=1))
        self.assertEqual(failed.jobs["JOB-Y"].state, "failed")

    def test_unknown_dependency_cycle_and_authority_fencing_are_fail_closed(self):
        s = scheduler()
        with self.assertRaises(SchedulingError):
            s.admit("OP-UNKNOWN", job("JOB-A", dependencies=("JOB-MISSING",)))
        s.admit("OP-A", job("JOB-A"))
        s.admit("OP-B", job("JOB-B", dependencies=("JOB-A",)))
        with self.assertRaises(SchedulingError):
            s.admit("OP-CYCLE", job("JOB-C", dependencies=("JOB-B", "JOB-C")))
        with self.assertRaises(SchedulingError):
            s.admit("OP-STALE", job("JOB-STALE", coordinator_revision=8))
        with self.assertRaises(SchedulingError):
            s.admit("OP-REGISTRY", job("JOB-REGISTRY", registry_digest="sha256:" + "b" * 64))

    def test_tenant_project_backpressure_and_global_admission(self):
        s = scheduler(max_queued=2, tenant_quotas={"tenant-a": 1, "tenant-b": 2}, project_quotas={"project-a": 2})
        s.admit("OP-1", job("JOB-A", priority=80))
        with self.assertRaisesRegex(SchedulingError, "tenant_backpressure"):
            s.admit("OP-2", job("JOB-B"))
        s.admit("OP-3", job("JOB-C", tenant="tenant-b", eligible_agents=frozenset({"agent-b"})))
        with self.assertRaisesRegex(SchedulingError, "backpressure_active_job_limit"):
            s.admit("OP-4", job("JOB-D", tenant="tenant-b"))
        lease = s.dispatch("OP-D", now=0)
        s.complete("OP-C", job_id="JOB-A", lease=lease, now=1)
        self.assertEqual(s.jobs["JOB-C"].state, "queued")

    def test_resource_reservations_and_agent_quotas_never_overcommit(self):
        s = scheduler(max_concurrency=4, agent_quotas={"agent-a": 1, "agent-b": 1})
        s.admit("OP-A", job("JOB-A", resources=Resources(2, 2, 2), eligible_agents=frozenset({"agent-a"})))
        s.admit("OP-B", job("JOB-B", resources=Resources(2, 2, 2), eligible_agents=frozenset({"agent-a"})))
        first = s.dispatch("OP-D-A", now=0, agent_id="agent-a")
        self.assertEqual(first.agent_id, "agent-a")
        self.assertIsNone(s.dispatch("OP-D-B", now=0, agent_id="agent-a"))
        self.assertEqual(s.available, Resources(2, 2, 2))
        s.admit("OP-C", job("JOB-C", tenant="tenant-b", project="project-b", eligible_agents=frozenset({"agent-b"})))
        second = s.dispatch("OP-D-C", now=0, agent_id="agent-b")
        self.assertEqual(second.agent_id, "agent-b")
        self.assertEqual(s.available, Resources(1, 1, 1))

    def test_capability_and_profile_preflight_boundaries(self):
        s = scheduler()
        with self.assertRaises(SchedulingError):
            s.register_agent(agent("agent-a"))
        s.admit("OP-CAP", job("JOB-CAP", required_capabilities=frozenset({"gpu"})))
        self.assertIsNone(s.dispatch("OP-CAP-D", now=0))
        s.admit("OP-OK", job("JOB-OK", required_capabilities=frozenset({"review"}), eligible_agents=frozenset({"agent-b"})))
        lease = s.dispatch("OP-OK-D", now=0)
        self.assertEqual(lease.profile_digest, PROFILE_B)
        self.assertTrue(lease.session_id.startswith("SES-"))
        self.assertEqual(lease.coordinator_revision, 7)

    def test_aging_and_virtual_service_bound_progress_many_tenants(self):
        s = scheduler(max_concurrency=1, aging_quantum=2, tenant_quotas={"tenant-a": 20, "tenant-b": 20}, project_quotas={"project-a": 20, "project-b": 20})
        for index in range(10):
            s.admit("OP-A" + str(index), job(f"JOB-A{index}", tenant="tenant-a", project="project-a", priority=100 if index else 0, eligible_agents=frozenset({"agent-a"})))
        s.admit("OP-B", job("JOB-B", tenant="tenant-b", project="project-b", priority=0, eligible_agents=frozenset({"agent-a"})))
        completed = []
        for tick in range(40):
            lease = s.dispatch("OP-FAIR" + str(tick), now=tick, agent_id="agent-a")
            if lease is None:
                continue
            completed.append(lease.job_id)
            s.complete("OP-DONE" + str(tick), job_id=lease.job_id, lease=lease, now=tick)
            if "JOB-B" in completed:
                break
        self.assertIn("JOB-B", completed)
        self.assertLess(completed.index("JOB-B"), 20)

    def test_retry_budget_backoff_and_expiry_are_bounded(self):
        s = scheduler()
        s.admit("OP-R", job("JOB-R", max_attempts=3, retry_budget=2, retry_backoff=2, eligible_agents=frozenset({"agent-a"})))
        first = s.dispatch("OP-R-D1", now=0, agent_id="agent-a")
        self.assertEqual(s.fail("OP-R-F1", job_id="JOB-R", lease=first, reason="worker_lost", now=1), "queued")
        self.assertIsNone(s.dispatch("OP-R-D2", now=2, agent_id="agent-a"))
        second = s.dispatch("OP-R-D3", now=3, agent_id="agent-a")
        self.assertEqual(second.fence, 2)
        s.advance(7)  # inclusive expiry; consumes the second retry budget
        self.assertEqual(s.jobs["JOB-R"].state, "queued")
        third = s.dispatch("OP-R-D4", now=11, agent_id="agent-a")
        self.assertEqual(third.fence, 3)
        self.assertEqual(s.fail("OP-R-F3", job_id="JOB-R", lease=third, reason="worker_lost", now=12), "failed")
        self.assertEqual(s.jobs["JOB-R"].retries_used, 2)

    def test_cancellation_has_priority_and_stale_claims_cannot_mutate(self):
        s = scheduler()
        s.admit("OP-C", job("JOB-C", eligible_agents=frozenset({"agent-a"})))
        lease = s.dispatch("OP-C-D", now=0, agent_id="agent-a")
        self.assertEqual(s.request_cancel("OP-CANCEL", job_id="JOB-C", now=1), "cancelling")
        with self.assertRaisesRegex(SchedulingError, "cancellation_in_progress"):
            s.heartbeat("OP-HB", job_id="JOB-C", lease=lease, now=1)
        s.acknowledge_cancel("OP-ACK", job_id="JOB-C", lease=lease, now=2)
        self.assertEqual(s.jobs["JOB-C"].state, "cancelled")
        with self.assertRaises(SchedulingError):
            s.complete("OP-STALE", job_id="JOB-C", lease=lease, now=2)

    def test_idempotency_conflict_and_deterministic_replay(self):
        s = scheduler()
        s.admit("OP-A", job("JOB-A"))
        first = s.dispatch("OP-D", now=0)
        self.assertEqual(s.dispatch("OP-D", now=0), first)
        with self.assertRaisesRegex(SchedulingError, "idempotency_conflict"):
            s.dispatch("OP-D", now=1)

        def run():
            other = scheduler()
            other.admit("OP-A", job("JOB-A"))
            lease = other.dispatch("OP-D", now=0)
            other.complete("OP-C", job_id="JOB-A", lease=lease, now=1)
            return other.snapshot()

        self.assertEqual(run(), run())
        self.assertEqual(digest(run()), digest(run()))

    def test_virtual_time_cannot_move_backwards(self):
        s = scheduler()
        s.advance(10)
        with self.assertRaises(SchedulingError):
            s.advance(9)


if __name__ == "__main__":
    unittest.main()

import tempfile
import threading
import unittest
from pathlib import Path

from awr_cli.agent_registry import AdapterProfile, AdapterRegistry, RegistryError, deterministic_fake_adapters, deterministic_fake_profiles
from awr_cli.agent_session import AgentSession, fake_digest
from awr_cli.cli import CliError
from awr_cli.scheduler_local import LocalScheduler


class DurableAgentRegistryTests(unittest.TestCase):
    def test_atomic_revisioned_registration_and_two_heterogeneous_fakes(self):
        alpha_adapter, beta_adapter = deterministic_fake_adapters()
        request = "sha256:" + "a" * 64
        self.assertEqual(alpha_adapter.respond(request)["style"], "stream")
        self.assertEqual(beta_adapter.respond(request)["style"], "checkpointed")
        with tempfile.TemporaryDirectory() as directory:
            registry = AdapterRegistry(Path(directory) / "agents.json")
            alpha, beta = deterministic_fake_profiles()[:2]
            self.assertEqual(registry.register(alpha, expected_revision=0), 1)
            self.assertEqual(registry.register(beta, expected_revision=1), 2)
            self.assertNotEqual(alpha.capabilities, beta.capabilities)
            self.assertEqual(registry.negotiate("fake-beta", ["checkpoint"])['status'], "accepted")

    def test_duplicate_stale_unsupported_and_unsafe_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AdapterRegistry(Path(directory) / "agents.json")
            alpha = deterministic_fake_profiles()[0]
            registry.register(alpha)
            with self.assertRaisesRegex(RegistryError, "duplicate"):
                registry.register(alpha)
            with self.assertRaisesRegex(RegistryError, "stale"):
                registry.register(AdapterProfile("fake-gamma", "1.0.0", ("gamma",), frozenset({"request"}), ("start", "request"), {"max_request_bytes": 64}), expected_revision=0)
            with self.assertRaisesRegex(RegistryError, "unsupported"):
                registry.negotiate("fake-alpha", ["checkpoint"])
            with self.assertRaisesRegex(RegistryError, "unsafe"):
                AdapterProfile("unsafe-agent", "1.0.0", ("sh -c 'bad'",), frozenset({"request"}), ("start", "request"), {"max_request_bytes": 64}).validate()

    def test_concurrent_duplicate_registration_has_one_winner(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AdapterRegistry(Path(directory) / "agents.json")
            profile = deterministic_fake_profiles()[0]
            outcomes = []
            def attempt():
                try:
                    outcomes.append(registry.register(profile))
                except RegistryError as exc:
                    outcomes.append(str(exc))
            threads = [threading.Thread(target=attempt) for _ in range(8)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(outcomes.count(1), 1)
            self.assertEqual(registry.revision, 1)

    def test_session_and_scheduler_admission_use_the_same_registry_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AdapterRegistry(Path(directory) / "agents.json")
            for profile in deterministic_fake_profiles(): registry.register(profile)
            root = Path(directory) / "root"; root.mkdir()
            worktree = root / "worktree"; worktree.mkdir()
            session = AgentSession(root, "SES-REGISTRY-A", "fake-alpha", registry=registry)
            result = session.run(["python3", "-c", "print('deterministic')"], worktree, input_digest=fake_digest("input"))
            self.assertEqual(result["status"], "completed")
            scheduler = LocalScheduler(Path(directory) / "scheduler.json", registry=registry)
            scheduler.submit("JOB-REGISTRY", "project", adapter_id="fake-beta", capabilities=["checkpoint"])
            self.assertEqual(scheduler.dispatch("WRK-REGISTRY")["job"]["adapter_id"], "fake-beta")

    def test_session_rejects_unsupported_capability_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); worktree = root / "worktree"; worktree.mkdir()
            with self.assertRaisesRegex(CliError, "unsupported"):
                AgentSession(root, "SES-REGISTRY-B", "fake-alpha").run(["false"], worktree, input_digest=fake_digest("input"), capabilities=["checkpoint"])


if __name__ == "__main__":
    unittest.main()

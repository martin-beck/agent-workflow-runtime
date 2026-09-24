from __future__ import annotations

import copy
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scripts.agent_registry import AgentRegistry
from scripts.agent_sessions import AdapterError, AdapterSession, SessionBinding, digest
from scripts.check_agent_sessions import validate
from scripts.local_supervisor import Lease, LocalSupervisor, SupervisorPolicy

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_SPEC = ROOT / "specifications" / "agent-registry-v1.json"
SESSION_SPEC = ROOT / "specifications" / "agent-session-v1.json"
SESSION_FIXTURE = ROOT / "specifications" / "fixtures" / "agent-session-ar0085-v1.json"
HELPER = ROOT / "tests" / "helpers" / "agent_session_helper.py"


def make_registry() -> AgentRegistry:
    return AgentRegistry(json.loads(REGISTRY_SPEC.read_text(encoding="utf-8")))


def make_session(registry: AgentRegistry, state: Path, profile: str, suffix: str = "A") -> AdapterSession:
    supervisor = LocalSupervisor(
        SupervisorPolicy(ROOT, Path(sys.executable), (HELPER,)), state_dir=state
    )
    return AdapterSession(
        registry,
        supervisor,
        profile_id=profile,
        binding=SessionBinding(
            f"SES-0085-{suffix}", "agent-workflow-runtime-0085", digest({"worktree": "fixture"})
        ),
        lease=Lease("WRK-0085", f"LSE-{suffix}", time.monotonic() + 30),
        helper=HELPER,
    )


class AgentSessionTests(unittest.TestCase):
    def test_checker_accepts_fixture_and_rejects_tampering(self) -> None:
        spec = json.loads(SESSION_SPEC.read_text(encoding="utf-8"))
        fixture = json.loads(SESSION_FIXTURE.read_text(encoding="utf-8"))
        result = validate(spec, fixture, 3)
        self.assertEqual(result["profiles"], 4)
        hostile = copy.deepcopy(fixture)
        hostile["execution"]["provider"] = "verified"
        with self.assertRaises(ValueError):
            validate(spec, hostile, 3)

    def test_all_four_profiles_share_the_real_supervised_lifecycle(self) -> None:
        registry = make_registry()
        digest_value = digest({"request": "deterministic", "case": "all-profiles"})
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            sessions = [
                make_session(registry, state, profile, str(index))
                for index, profile in enumerate(registry.profiles, 1)
            ]
            for session in sessions:
                self.assertEqual(session.start()["event_type"], "session_started")
                self.assertEqual(session.request(digest_value)["disposition"], "accepted")
                chunks = session.stream(digest_value, count=1)
                self.assertEqual(len(chunks), 1)
                self.assertEqual(chunks[0]["event_type"], "stream_chunk")
                self.assertEqual(session.close()["event_type"], "closed")
                self.assertEqual(session.state, "closed")
                self.assertEqual(len(session.events), 4)
                self.assertEqual(
                    [event["sequence"] for event in session.events], [1, 2, 3, 4]
                )
                for event in session.events:
                    self.assertTrue(event["event_digest"].startswith("sha256:"))
                    self.assertEqual(event["correlation"]["session_id"], session.binding.session_id)

    def test_interruption_resume_and_close_are_checkpoint_fenced(self) -> None:
        registry = make_registry()
        request_digest = digest({"request": "interrupt"})
        with tempfile.TemporaryDirectory() as directory:
            session = make_session(registry, Path(directory), "generic-mock-agent")
            session.start()
            interrupted = session.interrupt(request_digest)
            checkpoint = interrupted["details"]["checkpoint_digest"]
            self.assertEqual(session.state, "interrupted")
            with self.assertRaises(AdapterError) as wrong:
                session.resume(digest({"wrong": True}))
            self.assertEqual(wrong.exception.code, "fence_mismatch")
            resumed = session.resume(checkpoint)
            self.assertEqual(resumed["event_type"], "resumed")
            self.assertEqual(session.close()["disposition"], "completed")
            self.assertEqual(session.state, "closed")

    def test_capability_mismatch_never_launches_a_process_or_changes_state(self) -> None:
        registry = make_registry()
        with tempfile.TemporaryDirectory() as directory:
            session = make_session(registry, Path(directory), "opendesk-agent")
            session.start()
            before = (session.state, len(session.events))
            with self.assertRaises(AdapterError) as blocked:
                session.request(digest({"request": "tool"}), capability="tool_use")
            self.assertEqual(blocked.exception.code, "capability_mismatch")
            self.assertEqual((session.state, len(session.events)), before)
            session.close()

    def test_stale_and_expired_leases_are_normalized_before_execution(self) -> None:
        registry = make_registry()
        with tempfile.TemporaryDirectory() as directory:
            session = make_session(registry, Path(directory), "generic-mock-agent")
            with self.assertRaises(AdapterError) as stale:
                session.start(lease=Lease("WRK-OTHER", "LSE-OTHER", time.monotonic() + 30))
            self.assertEqual(stale.exception.code, "stale_lease")
            expired = make_session(registry, Path(directory), "generic-mock-agent", "B")
            expired.lease = Lease("WRK-0085", "LSE-B", time.monotonic() - 1)
            with self.assertRaises(AdapterError) as old:
                expired.start()
            self.assertEqual(old.exception.code, "expired_lease")

    def test_payload_and_event_budgets_fail_closed(self) -> None:
        registry = make_registry()
        with tempfile.TemporaryDirectory() as directory:
            session = make_session(registry, Path(directory), "opendesk-agent")
            session.start()
            with self.assertRaises(AdapterError) as too_large:
                session.request("x" * 4096, capability="read")
            self.assertEqual(too_large.exception.code, "payload_too_large")
            session.close()

    def test_event_digests_and_replay_are_deterministic(self) -> None:
        registry = make_registry()
        value = digest({"request": "replay"})
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = make_session(registry, Path(first_dir), "generic-mock-agent", "C")
            second = make_session(registry, Path(second_dir), "generic-mock-agent", "C")
            for session in (first, second):
                session.start()
                session.request(value)
                session.close()
            self.assertEqual(first.events, second.events)
            for event in first.events:
                unsigned = {key: value for key, value in event.items() if key != "event_digest"}
                self.assertEqual(event["event_digest"], digest(unsigned))

    def test_invalid_state_and_unknown_profile_are_normalized(self) -> None:
        registry = make_registry()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AdapterError) as unknown:
                make_session(registry, Path(directory), "missing-agent")
            self.assertEqual(unknown.exception.code, "unknown_profile")
            session = make_session(registry, Path(directory), "generic-mock-agent")
            with self.assertRaises(AdapterError) as invalid:
                session.request(digest({"request": "before-start"}))
            self.assertEqual(invalid.exception.code, "invalid_state")


if __name__ == "__main__":
    unittest.main()

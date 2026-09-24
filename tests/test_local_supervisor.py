from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.check_local_supervisor import validate
from scripts.local_supervisor import (
    Budget,
    Lease,
    LocalSupervisor,
    SupervisorError,
    SupervisorPolicy,
    redact,
)

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tests" / "helpers" / "supervisor_helper.py"


def policy() -> SupervisorPolicy:
    return SupervisorPolicy(ROOT, Path(sys.executable), (HELPER,))


def command(mode: str, value: str = "") -> list[str]:
    result = [sys.executable, str(HELPER), mode]
    if value:
        result.append(value)
    return result


class LocalSupervisorTests(unittest.TestCase):
    def supervisor(self) -> tuple[LocalSupervisor, tempfile.TemporaryDirectory[str]]:
        state = tempfile.TemporaryDirectory()
        return LocalSupervisor(policy(), state_dir=Path(state.name)), state

    def test_success_is_real_bounded_repository_helper(self) -> None:
        supervisor, state = self.supervisor()
        try:
            result = supervisor.run(
                "RUN-SUCCESS",
                command("success"),
                lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                budget=Budget(timeout_ms=1_000),
            )
            self.assertEqual(result.disposition, "completed")
            self.assertEqual(result.stdout.strip(), "helper-ok")
            self.assertTrue(result.process_tree_clean)
            self.assertTrue(result.cleaned)
            self.assertEqual(list(Path(state.name).iterdir()), [])
        finally:
            state.cleanup()

    def test_timeout_kills_process_group_and_cleans_record(self) -> None:
        supervisor, state = self.supervisor()
        try:
            result = supervisor.run(
                "RUN-TIMEOUT",
                command("sleep", "5"),
                lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                budget=Budget(timeout_ms=100),
            )
            self.assertEqual(result.disposition, "timed_out")
            self.assertTrue(result.process_tree_clean)
            self.assertTrue(result.cleaned)
        finally:
            state.cleanup()

    def test_cancellation_is_fenced_and_kills_descendant_tree(self) -> None:
        supervisor, state = self.supervisor()
        try:
            lease = Lease("WRK-A", "LSE-A", time.monotonic() + 10)
            handle = supervisor.launch(
                "RUN-CANCEL",
                command("child", "5"),
                lease=lease,
                budget=Budget(timeout_ms=3_000),
            )
            time.sleep(0.05)
            with self.assertRaises(SupervisorError):
                handle.cancel(
                    Lease("WRK-B", "LSE-B", lease.expires_at), now=time.monotonic()
                )
            result = handle.cancel(lease, now=time.monotonic())
            self.assertEqual(result.disposition, "cancelled")
            self.assertTrue(result.process_tree_clean)
        finally:
            state.cleanup()

    def test_output_is_capped_and_redacted(self) -> None:
        supervisor, state = self.supervisor()
        try:
            result = supervisor.run(
                "RUN-OUTPUT",
                command("output", "100000"),
                lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                budget=Budget(timeout_ms=1_000, output_bytes=128),
            )
            self.assertEqual(result.disposition, "output_overflow")
            self.assertLessEqual(result.output_bytes, 128)
            self.assertNotIn("TOPSECRET", result.stdout)
            self.assertIn("REDACTED", result.stdout)
        finally:
            state.cleanup()

    def test_environment_is_not_inherited_and_private_names_are_rejected(self) -> None:
        supervisor, state = self.supervisor()
        try:
            result = supervisor.run(
                "RUN-ENV",
                command("env"),
                lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                budget=Budget(timeout_ms=1_000),
            )
            self.assertEqual(result.disposition, "completed")
            self.assertEqual(result.stdout.strip(), "HOME= TOKEN=")
            with self.assertRaises(SupervisorError):
                supervisor.launch(
                    "RUN-PRIVATE",
                    command("success"),
                    lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                    budget=Budget(),
                    environment={"TOKEN": "not-allowed"},
                )
        finally:
            state.cleanup()

    def test_safe_environment_values_do_not_corrupt_structured_output(self) -> None:
        supervisor, state = self.supervisor()
        try:
            result = supervisor.run(
                "RUN-JSON",
                command("json"),
                lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                budget=Budget(timeout_ms=1_000),
            )
            self.assertEqual(json.loads(result.stdout), {"value": 1, "status": "ok"})
        finally:
            state.cleanup()

    def test_only_explicit_redaction_values_are_applied(self) -> None:
        supervisor, state = self.supervisor()
        try:
            result = supervisor.run(
                "RUN-EXPLICIT-REDACTION",
                command("value", "PRIVATE-VALUE"),
                lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                budget=Budget(timeout_ms=1_000),
                redaction_values=("PRIVATE-VALUE",),
            )
            self.assertEqual(result.stdout.strip(), "REDACTED")
        finally:
            state.cleanup()

    def test_stale_lease_is_rejected_before_spawn_and_on_cancel(self) -> None:
        supervisor, state = self.supervisor()
        try:
            with self.assertRaises(SupervisorError):
                supervisor.launch(
                    "RUN-STALE",
                    command("success"),
                    lease=Lease("WRK-A", "LSE-A", 1),
                    budget=Budget(),
                    now=2,
                )
            lease = Lease("WRK-A", "LSE-A", time.monotonic() + 10)
            handle = supervisor.launch(
                "RUN-FENCE",
                command("sleep", "2"),
                lease=lease,
                budget=Budget(timeout_ms=3_000),
            )
            with self.assertRaises(SupervisorError):
                handle.cancel(
                    Lease("WRK-A", "LSE-OLD", lease.expires_at), now=time.monotonic()
                )
            handle.cancel(lease, now=time.monotonic())
        finally:
            state.cleanup()

    def test_exact_worktree_and_allowlisted_helper_are_enforced(self) -> None:
        supervisor, state = self.supervisor()
        try:
            with self.assertRaises(SupervisorError):
                supervisor.launch(
                    "RUN-ESCAPE",
                    [sys.executable, "/etc/hosts", "success"],
                    lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                    budget=Budget(),
                )
            outside = Path(tempfile.gettempdir()) / "awr-0083-outside-helper.py"
            outside.write_text("print('outside')\n", encoding="utf-8")
            try:
                with self.assertRaises(SupervisorError):
                    supervisor.launch(
                        "RUN-OUTSIDE",
                        [sys.executable, str(outside), "success"],
                        lease=Lease("WRK-A", "LSE-A", time.monotonic() + 10),
                        budget=Budget(),
                    )
            finally:
                outside.unlink()
        finally:
            state.cleanup()

    def test_unsupported_host_control_fails_closed(self) -> None:
        with self.assertRaises(SupervisorError):
            LocalSupervisor(replace(policy(), required_controls=("landlock",)))

    def test_crash_recovery_requires_expired_old_lease_and_fences_replacement(
        self,
    ) -> None:
        state = tempfile.TemporaryDirectory()
        try:
            lease = Lease("WRK-A", "LSE-A", time.monotonic() + 0.1)
            supervisor = LocalSupervisor(policy(), state_dir=Path(state.name))
            handle = supervisor.launch(
                "RUN-RECOVER", command("success"), lease=lease, budget=Budget()
            )
            handle.process.wait(timeout=2)
            assert (
                handle.process.stdout is not None and handle.process.stderr is not None
            )
            handle.process.stdout.close()
            handle.process.stderr.close()
            with self.assertRaises(SupervisorError):
                supervisor.recover(
                    "RUN-RECOVER",
                    replacement_lease=Lease("WRK-B", "LSE-B", time.monotonic() + 10),
                    now=time.monotonic(),
                )
            time.sleep(0.15)
            recovered = supervisor.recover(
                "RUN-RECOVER",
                replacement_lease=Lease("WRK-B", "LSE-B", time.monotonic() + 10),
                now=time.monotonic(),
            )
            self.assertEqual(recovered["disposition"], "recovered")
            self.assertFalse((Path(state.name) / "RUN-RECOVER.json").exists())
        finally:
            state.cleanup()

    def test_redactor_handles_label_and_bearer_forms(self) -> None:
        value = redact("token=abc password: xyz Bearer qqq")
        self.assertEqual(value, "token=REDACTED password: REDACTED Bearer REDACTED")

    def test_machine_checker_accepts_fixture_and_rejects_revision_drift(self) -> None:
        import json

        spec = json.loads(
            (ROOT / "specifications" / "local-supervisor-v1.json").read_text(
                encoding="utf-8"
            )
        )
        fixture = json.loads(
            (
                ROOT / "specifications" / "fixtures" / "local-supervisor-ar0083-v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(validate(spec, fixture, 3)["cases"], 6)
        with self.assertRaises(ValueError):
            validate(spec, fixture, 4)


if __name__ == "__main__":
    unittest.main()

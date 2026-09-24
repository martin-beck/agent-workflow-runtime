import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError
from awr_cli.observability import AuditJournal


class ObservabilityTests(unittest.TestCase):
    def test_append_status_and_chain_are_deterministic(self):
        with tempfile.TemporaryDirectory() as root:
            journal = AuditJournal(Path(root))
            first = journal.append(event_id="EVT-ONE", task_id="AR-0107", task_revision=1, category="runtime", status="started", detail="local mock")
            second = journal.append(event_id="EVT-TWO", task_id="AR-0107", task_revision=1, category="runtime", status="finished", detail="passed")
            self.assertNotEqual(first["record_digest"], second["record_digest"])
            self.assertEqual(journal.status()["records"], 2)
            self.assertEqual(journal.status()["payloads"], "digest_only")

    def test_private_oversized_and_invalid_events_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            journal = AuditJournal(Path(root))
            for detail in ("token=secret", "x" * 4097):
                with self.assertRaisesRegex(CliError, "private_or_oversized"):
                    journal.append(event_id="EVT-ONE", task_id="AR-0107", task_revision=1, category="runtime", status="started", detail=detail)
            with self.assertRaisesRegex(CliError, "binding"):
                journal.append(event_id="BAD", task_id="AR-0107", task_revision=1, category="runtime", status="started")

    def test_tampered_chain_is_rejected_without_repair(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root); journal = AuditJournal(home)
            journal.append(event_id="EVT-ONE", task_id="AR-0107", task_revision=1, category="runtime", status="started")
            path = home / "audit.jsonl"; path.write_text(path.read_text().replace('"status":"started"', '"status":"tampered"'), encoding="utf-8")
            with self.assertRaisesRegex(CliError, "chain_invalid"):
                AuditJournal(home).status()


if __name__ == "__main__":
    unittest.main()

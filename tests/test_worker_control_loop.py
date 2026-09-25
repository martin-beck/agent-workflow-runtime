import copy
import tempfile
import unittest
from pathlib import Path

from scripts.worker_control_loop import (
    DENIED, SPECIFICATION_DIGEST, TEST_CONTRACT_DIGEST, ControlLoopError,
    DecisionJournal, FakeAuthority, Proposal, WorkerControlLoop, check, digest,
    fake_loop,
)


class WorkerControlLoopTests(unittest.TestCase):
    def proposal(self, **changes):
        values = dict(
            task_id="AR-0135", revision=2, proposal="apply bounded worker change",
            specification_digest=SPECIFICATION_DIGEST, test_digest=TEST_CONTRACT_DIGEST,
            evidence_digest=digest({"test_result": "passed", "change": "bounded"}),
        )
        values.update(changes)
        return Proposal(**values)

    def test_executable_loop_requires_all_durable_gates_and_replays_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = DecisionJournal(Path(directory) / "decisions.jsonl")
            loop = fake_loop(journal=journal)
            proposal = self.proposal()
            result = loop.run(proposal)
            self.assertEqual(check(result, proposal, journal)["decisions"], 3)
            self.assertEqual([item["decision"]["authority"] for item in journal.entries[0:3]], ["awq", "awg", "ui"])
            self.assertEqual(result["decisions"][1]["guidance_digest"], digest({
                "binding": proposal.binding(), "guidance": "local-fake-guidance-v1"
            }))
            self.assertEqual(len(DecisionJournal(Path(directory) / "decisions.jsonl").entries), 3)

    def test_skipped_or_reordered_gates_are_rejected(self):
        proposal = self.proposal()
        for names in (("awg", "ui", "ui"), ("awq", "ui", "awg"), ("ui", "awg", "awq")):
            authorities = tuple(FakeAuthority(name) for name in names)
            loop = WorkerControlLoop(*authorities, DecisionJournal())
            with self.subTest(authorities=[a.name for a in authorities]), self.assertRaises(ControlLoopError):
                loop.run(proposal)
        record = fake_loop().run(proposal)
        hostile = copy.deepcopy(record)
        hostile["decisions"].pop(1)
        with self.assertRaises(ControlLoopError):
            check(hostile, proposal, DecisionJournal())

    def test_worker_specification_test_decision_and_acceptance_edits_are_denied(self):
        for forbidden in DENIED:
            with self.subTest(forbidden=forbidden), self.assertRaisesRegex(ControlLoopError, "worker_changed"):
                fake_loop().run(self.proposal(worker_changes=(forbidden,)))
        for field in ("specification_digest", "test_digest"):
            with self.subTest(field=field), self.assertRaisesRegex(ControlLoopError, "changed"):
                fake_loop().run(self.proposal(**{field: digest("worker changed baseline")}))

    def test_stale_awq_awg_or_ui_decisions_are_rejected(self):
        proposal = self.proposal()
        for authority in ("awq", "awg", "ui"):
            fakes = [FakeAuthority(name) for name in ("awq", "awg", "ui")]
            fakes[("awq", "awg", "ui").index(authority)].alter["task_revision"] = 1
            with self.subTest(authority=authority), self.assertRaisesRegex(ControlLoopError, "binding"):
                WorkerControlLoop(*fakes, DecisionJournal()).run(proposal)

    def test_rejection_and_cancellation_are_terminal_and_durable(self):
        proposal = self.proposal()
        rejected = fake_loop(("rejected", "approved", "approved"))
        result = rejected.run(proposal)
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual([d["authority"] for d in result["decisions"]], ["awq"])
        cancelled = fake_loop(("approved", "approved", "cancelled"))
        result = cancelled.run(proposal)
        self.assertEqual(result["outcome"], "cancelled")
        self.assertEqual([d["authority"] for d in result["decisions"]], ["awq", "awg", "ui"])

    def test_blocked_work_requires_awg_escalation_and_ui_resolution(self):
        proposal = self.proposal(blocked=True)
        with self.assertRaisesRegex(ControlLoopError, "not_escalated"):
            fake_loop().run(proposal)
        escalated = fake_loop(("approved", "escalated", "cancelled"))
        result = escalated.run(proposal)
        self.assertEqual(result["outcome"], "cancelled")
        self.assertTrue(result["decisions"][1]["escalation"])
        self.assertEqual(result["decisions"][2]["authority"], "ui")

    def test_ambiguous_or_non_durable_authority_answers_fail_closed(self):
        proposal = self.proposal()
        for alteration in ({"outcome": "unknown"}, {"durable": False}):
            fakes = [FakeAuthority(name) for name in ("awq", "awg", "ui")]
            fakes[0].alter.update(alteration)
            with self.subTest(alteration=alteration), self.assertRaises(ControlLoopError):
                WorkerControlLoop(*fakes, DecisionJournal()).run(proposal)

    def test_journal_tampering_is_detected_on_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decisions.jsonl"
            journal = DecisionJournal(path)
            fake_loop(journal=journal).run(self.proposal())
            raw = path.read_text().replace('"outcome":"approved"', '"outcome":"rejected"', 1)
            path.write_text(raw)
            with self.assertRaisesRegex(ControlLoopError, "journal_corrupt"):
                DecisionJournal(path)


if __name__ == "__main__":
    unittest.main()

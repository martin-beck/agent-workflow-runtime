import copy
import json
import unittest
from pathlib import Path

from scripts.cross_agent_accounting import AccountingError, AgentLedger, compare, replay

ROOT = Path(__file__).parents[1]
FIX = ROOT / "specifications/fixtures/cross-agent-accounting-ar0090-v1.json"


class CrossAgentAccountingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIX.read_text())

    def test_fixture_replays_and_compares_two_agents(self):
        self.assertEqual(compare(self.fixture["runs"]), self.fixture["expected"])
        self.assertEqual(replay(self.fixture["runs"][0])["usage"]["tokens"], 5)

    def test_digest_chain_and_budget_are_enforced(self):
        r = self.fixture["runs"][0]
        l = AgentLedger(
            r["job_id"],
            r["lease_id"],
            r["session_id"],
            r["agent_id"],
            r["benchmark_digest"],
            r["budget"],
        )
        l.append(
            "EV-X-1",
            "completion",
            {"seconds": 2, "tokens": 5},
            r["events"][0]["evidence_digest"],
        )
        with self.assertRaisesRegex(AccountingError, "replayed_event"):
            l.append(
                "EV-X-1",
                "completion",
                {"seconds": 1, "tokens": 1},
                r["events"][0]["evidence_digest"],
            )
        with self.assertRaisesRegex(AccountingError, "budget_exceeded"):
            l.append(
                "EV-X-2",
                "completion",
                {"seconds": 9, "tokens": 1},
                r["events"][0]["evidence_digest"],
            )

    def test_privacy_and_ambiguity_fail_closed(self):
        r = copy.deepcopy(self.fixture["runs"][0])
        r["events"][0]["kind"] = "raw transcript secret"
        with self.assertRaises(AccountingError):
            replay(r)

    def test_comparison_requires_same_benchmark_and_configuration(self):
        r = copy.deepcopy(self.fixture["runs"][1])
        r["benchmark_digest"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(AccountingError, "non_comparable_runs"):
            compare([self.fixture["runs"][0], r])

    def test_one_agent_is_not_a_comparison(self):
        with self.assertRaisesRegex(AccountingError, "comparison_requires_two_agents"):
            compare([self.fixture["runs"][0]])


if __name__ == "__main__":
    unittest.main()

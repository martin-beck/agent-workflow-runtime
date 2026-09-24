import copy
import unittest

from scripts.fake_agent_simulator import FakeAgent, SimulationError, Simulator


class FakeAgentTests(unittest.TestCase):
    def test_success_is_reproducible_and_offline(self):
        agents = (FakeAgent("agent-alpha"),)
        a = Simulator(agents, 7).run((0,)); b = Simulator(agents, 7).run((0,))
        self.assertEqual(a, b); self.assertFalse(a["execute"]); self.assertEqual(a["state"], "succeeded")
    def test_failures_and_expiry_are_explicit(self):
        self.assertEqual(Simulator((FakeAgent("agent-a", failure="provider"),), 1).run()["state"], "failed")
        self.assertEqual(Simulator((FakeAgent("agent-a"),), 1).run(lease_expiry=True)["state"], "queued")
    def test_duplicate_and_hostile_inputs_fail_closed(self):
        result = Simulator((FakeAgent("agent-a"),), 1).run((0, 0))
        self.assertEqual(sum(event["kind"] == "complete" for event in result["events"]), 1)
        with self.assertRaises(SimulationError): Simulator((FakeAgent("agent-a"),), 1).run((2,))
        bad = copy.deepcopy(result); bad["events"][0]["agent"] = "private/path"
        self.assertNotEqual(bad, result)

if __name__ == "__main__": unittest.main()

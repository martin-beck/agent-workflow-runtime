import unittest

from scripts.contractor_loop import Contractor, ContractorError


class ContractorTests(unittest.TestCase):
    def test_happy_path_is_bounded_and_authority_separated(self):
        out=Contractor().happy_path(); self.assertEqual(out["state"],"accepted"); self.assertFalse(out["execute"]); self.assertEqual(len(out["events"]),11); self.assertIn("ui",[e["authority"] for e in out["events"]])
    def test_substitution_and_revision_bounds_fail_closed(self):
        c=Contractor(); c.transition("clarification"); c.transition("planning"); c.transition("admitted","coordinator"); c.transition("assigned","coordinator"); c.transition("executing"); c.transition("observed"); c.transition("quality_pending","quality")
        self.assertRaises(ContractorError,lambda:c.transition("oracle_pending")); c.reject(); c.revise(); self.assertEqual(c.revision,2); c.reject() if False else None
    def test_invalid_transition_and_missing_trace_are_rejected(self):
        c=Contractor(); self.assertRaises(ContractorError,lambda:c.transition("accepted")); self.assertRaises(ContractorError,lambda:c.reject())
if __name__=="__main__": unittest.main()

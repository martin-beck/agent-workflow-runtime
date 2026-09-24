import unittest

from scripts.contractor_runtime import LocalContractorRuntime, WorkflowError


class RuntimeTests(unittest.TestCase):
    def test_success_path_is_authority_separated(self):
        r=LocalContractorRuntime(); out=r.run_success(); self.assertEqual(out["state"],"accepted"); self.assertFalse(out["execute"]); self.assertEqual([e["authority"] for e in out["events"]], ["scheduler","scheduler","runtime","runtime","quality","guidance","ui","coordinator"])
    def test_bounded_revision_and_terminal_fence(self):
        r=LocalContractorRuntime(); r._move("scheduled","scheduler"); r._move("assigned","scheduler"); r._move("executing","runtime"); r._move("observed","runtime"); r._move("quality_pending","quality"); r.reject_and_revise(); self.assertEqual(r.attempt,1); self.assertRaises(WorkflowError,lambda:r._move("accepted","runtime"))
if __name__=="__main__": unittest.main()

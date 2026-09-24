import unittest

from scripts.adapter_transport import Transport, TransportError


class TransportTests(unittest.TestCase):
    def test_bounded_lifecycle_and_opaque_frames(self):
        t=Transport(); t.admit("SES-A","agent-workflow-runtime-0073","LSE-A",["request"]); t.receive("start",{"request_digest":"sha256:"+"a"*64}); t.receive("close",{"reason":"done"}); self.assertEqual(t.state,"closed"); self.assertFalse(t.export()["execute"])
    def test_private_missing_and_over_budget_frames_fail_closed(self):
        t=Transport(); t.admit("SES-A","agent-workflow-runtime-0073","LSE-A",["request"]); self.assertRaises(TransportError,lambda:t.receive("start",{})); self.assertRaises(TransportError,lambda:t.receive("start",{"token":"secret","request_digest":"sha256:"+"a"*64}))
if __name__=="__main__": unittest.main()

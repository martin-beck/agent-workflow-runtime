import unittest

from scripts.codex_adapter import AdapterError, CodexAdapter


class CodexTests(unittest.TestCase):
    def test_offline_lifecycle(self):
        a=CodexAdapter(); a.admit("SES-A","LSE-A"); a.request("sha256:"+"a"*64); a.interrupt(); a.close(); self.assertEqual(a.state,"closed"); self.assertFalse(a.export()["execute"])
    def test_bad_binding_and_order_fail(self):
        a=CodexAdapter(); self.assertRaises(AdapterError,a.close); self.assertRaises(AdapterError,lambda:a.admit("private","LSE-A"))
if __name__=="__main__": unittest.main()

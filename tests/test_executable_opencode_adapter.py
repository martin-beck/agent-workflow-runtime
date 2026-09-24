import unittest

from scripts.executable_opencode_adapter import (
    ExecutableOpenCodeAdapter,
    OpenCodeAdapterError,
)


class OpenCodeTests(unittest.TestCase):
    def test_offline_lifecycle(self):
        a=ExecutableOpenCodeAdapter(); a.admit("SES-A","LSE-A"); a.request("sha256:"+"a"*64); a.interrupt(); a.close(); self.assertEqual(a.state,"closed"); self.assertFalse(a.export()["execute"])
    def test_bad_binding_and_order_fail(self):
        a=ExecutableOpenCodeAdapter(); self.assertRaises(OpenCodeAdapterError,a.close); self.assertRaises(OpenCodeAdapterError,lambda:a.admit("private","LSE-A"))
if __name__=="__main__": unittest.main()

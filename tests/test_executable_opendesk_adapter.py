import unittest

from scripts.executable_opendesk_adapter import (
    ExecutableOpenDeskAdapter,
    OpenDeskAdapterError,
)


class OpenDeskTests(unittest.TestCase):
    def test_offline_lifecycle_and_unsupported_capability(self):
        a=ExecutableOpenDeskAdapter(); a.admit("SES-A","LSE-A"); self.assertFalse(a.unsupported("stream")["state_change"]); a.request("sha256:"+"a"*64); a.interrupt(); a.close(); self.assertEqual(a.state,"closed")
    def test_unknown_capability_fails(self):
        a=ExecutableOpenDeskAdapter(); self.assertRaises(OpenDeskAdapterError,lambda:a.unsupported("unknown"))
if __name__=="__main__": unittest.main()

import copy
import unittest

from scripts.runtime_kernel import KernelError, RuntimeKernel


class RuntimeKernelTests(unittest.TestCase):
    def test_idempotency_accounting_and_restart(self):
        kernel=RuntimeKernel(); first=kernel.record("OP-AR0069-1","admit",usage={"seconds":1,"tokens":2}); self.assertEqual(first,kernel.record("OP-AR0069-1","admit",usage={"seconds":1,"tokens":2})); self.assertEqual(kernel.store.usage["events"],1); recovered=RuntimeKernel.recover(kernel.snapshot()); self.assertEqual(recovered.store.usage,kernel.store.usage)
    def test_changed_replay_privacy_binding_and_corrupt_snapshot_fail_closed(self):
        kernel=RuntimeKernel(); kernel.record("OP-AR0069-1","admit")
        self.assertRaises(KernelError,lambda:kernel.record("OP-AR0069-1","admit",payload={"token":"secret"}))
        self.assertRaises(KernelError,lambda:kernel.record("OP-AR0069-1","admit",lease_id="LSE-OTHER"))
        bad=copy.deepcopy(kernel.snapshot()); bad["store"]["events"][0]["event_digest"]="sha256:"+"f"*64; self.assertRaises(KernelError,lambda:RuntimeKernel.recover(bad))
    def test_terminal_state_and_no_execution(self):
        kernel=RuntimeKernel(); kernel.record("OP-AR0069-1","admit"); kernel.record("OP-AR0069-2","complete"); self.assertEqual(kernel.snapshot()["state"],"terminal"); self.assertFalse(kernel.snapshot()["execute"])
if __name__ == "__main__": unittest.main()

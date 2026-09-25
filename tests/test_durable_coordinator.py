import tempfile
import unittest
from pathlib import Path

from scripts.durable_coordinator import AuthorityError, DurableFakeCoordinator


class DurableCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "authority.json"
        self.now = [10.0]
        self.coordinator = DurableFakeCoordinator(self.path, clock=lambda: self.now[0], lease_seconds=5)
        self.coordinator.initialize("AR-0133", 7, "sha256:" + "a" * 64, "sha256:" + "b" * 64)

    def tearDown(self): self.temp.cleanup()

    def start(self):
        claimed = self.coordinator.claim("AR-0133", 7, "WRK-AR0133-1", "OP-AR0133-CLAIM")
        lease = self.coordinator.acquire_lease("AR-0133", claimed["revision"], "WRK-AR0133-1", "SES-AR0133-1", "OP-AR0133-LEASE")
        return lease["revision"], lease["lease"]

    def test_revision_cas_conflict_and_duplicate_operation_are_idempotent(self):
        receipt = self.coordinator.claim("AR-0133", 7, "WRK-AR0133-1", "OP-AR0133-CLAIM")
        again = self.coordinator.claim("AR-0133", 7, "WRK-AR0133-1", "OP-AR0133-CLAIM")
        self.assertEqual(receipt, again)
        with self.assertRaisesRegex(AuthorityError, "cas_conflict"):
            self.coordinator.acquire_lease("AR-0133", 7, "WRK-AR0133-1", "SES-AR0133-1", "OP-AR0133-STALE")
        with self.assertRaisesRegex(AuthorityError, "operation_id_conflict"):
            self.coordinator.claim("AR-0133", 7, "WRK-AR0133-OTHER", "OP-AR0133-CLAIM")

    def test_expiry_fences_session_event_and_old_worker(self):
        revision, lease = self.start()
        self.now[0] = 15.0
        with self.assertRaisesRegex(AuthorityError, "lease_expired_or_fenced"):
            self.coordinator.append_session_event("AR-0133", revision, lease, "SES-AR0133-1", "session_started", "sha256:" + "c" * 64, "OP-AR0133-EVENT")

    def test_ambiguous_durable_write_recovers_by_same_operation_after_restart(self):
        self.coordinator.ambiguous_once = True
        with self.assertRaisesRegex(AuthorityError, "unknown_outcome"):
            self.coordinator.claim("AR-0133", 7, "WRK-AR0133-1", "OP-AR0133-CLAIM")
        restarted = DurableFakeCoordinator(self.path, clock=lambda: self.now[0], lease_seconds=5)
        recovered = restarted.claim("AR-0133", 7, "WRK-AR0133-1", "OP-AR0133-CLAIM")
        self.assertEqual(recovered["revision"], 8)
        self.assertEqual(len(__import__("json").loads(self.path.read_text())["events"]), 1)


if __name__ == "__main__": unittest.main()

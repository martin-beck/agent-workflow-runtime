import copy
import json
import unittest
from pathlib import Path

from scripts.check_session_bootstrap import BootstrapError, load, validate_record
from scripts.session_bootstrap import Admission, SessionBootstrap

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/session-bootstrap-v1.json"
FIXTURE = ROOT / "specifications/fixtures/session-bootstrap-ar0030-v1.json"


class SessionBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(SPEC)
        self.record = load(FIXTURE)

    def test_fixture_is_accepted_and_offline_only(self):
        result = validate_record(self.record, self.spec, 5)
        self.assertEqual(result["final"], "interrupted")
        self.assertEqual(result["live_verification"], "unverified")

    def test_checker_rejects_stale_crossed_replay_and_private_payload(self):
        for mutation in (
            lambda r: r["admission"].update(task_revision=4),
            lambda r: r["actions"][1].update(owner_id="WRK-OTHER"),
            lambda r: r["actions"].append(copy.deepcopy(r["actions"][-1])),
            lambda r: r["actions"][0].update(token="private"),
        ):
            record = copy.deepcopy(self.record)
            mutation(record)
            with self.assertRaises(BootstrapError):
                validate_record(record, self.spec, 5)

    def test_runtime_fences_expiry_and_exact_identity(self):
        admission = Admission("AR-0030", 5, "agent-workflow-runtime", "sha256:" + "1" * 64,
                              "agent-workflow-runtime-0030", "sha256:" + "2" * 64,
                              "SES-AR0030-X", "WRK-AR0030-X", "LSE-AR0030-X", 10)
        runtime = SessionBootstrap(admission)
        kwargs = dict(task_revision=5, project_key=admission.project_key,
                      project_revision=admission.project_revision, worktree_key=admission.worktree_key,
                      worktree_digest=admission.worktree_digest, session_id=admission.session_id,
                      owner_id=admission.owner_id, lease_id=admission.lease_id, now=1)
        self.assertEqual(runtime.apply("ACT-BOOT", "bootstrap", **kwargs), "active")
        with self.assertRaises(Exception):
            runtime.apply("ACT-OLD", "checkpoint", **{**kwargs, "now": 10,
                           "evidence_digest": "sha256:" + "3" * 64})
        with self.assertRaises(Exception):
            runtime.apply("ACT-CROSSED", "checkpoint", **{**kwargs, "now": 2,
                           "owner_id": "WRK-OTHER", "evidence_digest": "sha256:" + "3" * 64})


if __name__ == "__main__":
    unittest.main()

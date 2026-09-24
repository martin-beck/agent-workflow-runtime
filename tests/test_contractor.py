import tempfile
import unittest
from pathlib import Path

from awr_cli.authority_gates import AuthorityGates
from awr_cli.contractor import LocalContractor
from awr_cli.scheduler_local import LocalScheduler
from scripts.local_authority_transport import LocalAuthorityClient, LocalAuthorityEndpoint


class ContractorTests(unittest.TestCase):
    def test_closed_loop_accepts_fake_artifact_and_accounts(self):
        with tempfile.TemporaryDirectory() as root:
            endpoints = {
                "coordinator": LocalAuthorityEndpoint("coordinator", ["observed"]),
                "awq": LocalAuthorityEndpoint("awq", ["accepted", "accepted"]),
                "awg": LocalAuthorityEndpoint("awg", ["requires_ui", "requires_ui"]),
                "ui": LocalAuthorityEndpoint("ui", ["approved", "approved"]),
            }
            result = LocalContractor(LocalScheduler(Path(root) / "scheduler.json"), AuthorityGates(LocalAuthorityClient(endpoints)), Path(root)).execute(
                job_id="JOB-CONTRACT", task="AR-CONTRACT-1", revision=3, worker="WRK-ONE", session_id="SES-CONTRACT-1", adapter="fake-agent", argv=["python3", "-c", "print('artifact')"], cwd=Path(root)
            )
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(result["terminal"]["jobs"]["JOB-CONTRACT"]["state"], "done")
            self.assertEqual(result["accounting"]["provider_cost"], "not_performed")


if __name__ == "__main__":
    unittest.main()

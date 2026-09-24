import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from awr_cli.agent_registry import AdapterRegistry
from awr_cli.local_llm_mock import LocalMockWorkflow, MockRequest, compare_agents
from awr_cli.authority_gates import AuthorityGates
from awr_cli.project_bootstrap import bootstrap
from awr_cli.scheduler_local import LocalScheduler
from scripts.local_authority_transport import LocalAuthorityClient, LocalAuthorityEndpoint


class FinalPlatformAcceptanceTests(unittest.TestCase):
    def test_two_new_projects_use_registered_agents_and_complete_workflow(self):
        def run(index: int):
            root = Path(tempfile.mkdtemp())
            project, state = root / "project", root / "state"
            created = bootstrap(f"complex-{index}", "board", project, state)
            self.assertEqual(created["status"], "created")
            registry = AdapterRegistry.memory_with_fakes()
            endpoints = {
                name: LocalAuthorityEndpoint(name, outcomes)
                for name, outcomes in {
                    "coordinator": ["observed"], "awq": ["accepted", "accepted"],
                    "awg": ["requires_ui", "requires_ui"], "ui": ["approved", "approved"],
                }.items()
            }
            workflow = LocalMockWorkflow(LocalScheduler(state / "scheduler.json", registry=registry), AuthorityGates(LocalAuthorityClient(endpoints)), registry)
            request = MockRequest(f"REQ-FINAL-{index}", f"SES-FINAL-{index}", f"AR-{1280 + index:04d}", 1, "fake-alpha", ({"role": "user", "content": "same board input"},))
            result = workflow.run(job_id=f"JOB-FINAL-{index}", task=request.task, revision=1, worker=f"WRK-FINAL-{index}", session_id=request.session_id, lease_id="LSE-00000001", request=request, budget={"seconds": 1, "tokens": 128, "events": 1})
            comparison = compare_agents(request, ["fake-alpha", "fake-beta"], registry=registry)
            return result["status"], result["terminal"]["jobs"][f"JOB-FINAL-{index}"]["state"], comparison["comparable"], result["accounting"]["usage"]["events"]

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, (1, 2)))
        self.assertEqual(results, [("accepted", "done", True, 1), ("accepted", "done", True, 1)])


if __name__ == "__main__":
    unittest.main()

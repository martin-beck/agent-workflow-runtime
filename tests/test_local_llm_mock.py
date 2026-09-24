import copy
import tempfile
import unittest
from pathlib import Path

from awr_cli.agent_registry import AdapterRegistry
from awr_cli.authority_gates import AuthorityGates
from awr_cli.local_llm_mock import (DeterministicLocalLLM, LocalMockWorkflow,
                                    MockProtocolError, MockRequest,
                                    compare_agents, digest, record_exchange,
                                    replay_exchange)
from awr_cli.scheduler_local import LocalScheduler
from scripts.local_authority_transport import LocalAuthorityClient, LocalAuthorityEndpoint


class LocalLLMMockTests(unittest.TestCase):
    def setUp(self):
        self.registry = AdapterRegistry.memory_with_fakes()
        self.request = MockRequest("REQ-MOCK-1", "SES-MOCK-1", "AR-0129", 1, "fake-alpha", ({"role": "user", "content": "same benchmark input"},))

    def test_request_is_deterministic_and_stream_is_ordered(self):
        model = DeterministicLocalLLM(self.registry, "fake-alpha")
        self.assertEqual(model.request(self.request), model.request(self.request))
        frames = list(model.stream(self.request))
        self.assertEqual([f["sequence"] for f in frames], list(range(1, len(frames) + 1)))
        self.assertEqual(frames[-1]["finish_reason"], "stop")

    def test_record_replay_is_digest_only_and_detects_mismatch(self):
        model = DeterministicLocalLLM(self.registry, "fake-alpha")
        response = model.request(self.request)
        record = record_exchange(self.request, response, list(model.stream(self.request)), registry_revision=response["registry_revision"], profile_digest=response["profile_digest"], authority_digest=digest({"gate": "observed"}), lease_id="LEASE-MOCK-1")
        self.assertNotIn("same benchmark input", str(record))
        self.assertTrue(replay_exchange(record, self.request, registry=self.registry)["replayed"])
        altered = copy.deepcopy(record); altered["response_digest"] = digest("tampered")
        with self.assertRaisesRegex(MockProtocolError, "record_digest_mismatch"):
            replay_exchange(altered, self.request, registry=self.registry)
        changed = MockRequest(**{**self.request.__dict__, "messages": ({"role": "user", "content": "changed"},)})
        with self.assertRaisesRegex(MockProtocolError, "replay_mismatch"):
            replay_exchange(record, changed, registry=self.registry)

    def test_two_agents_compare_exact_same_input(self):
        result = compare_agents(self.request, ["fake-alpha", "fake-beta"], registry=self.registry)
        self.assertTrue(result["comparable"])
        self.assertEqual({run["input_digest"] for run in result["runs"]}, {self.request.input_digest})
        with self.assertRaisesRegex(MockProtocolError, "comparison_requires_two_agents"):
            compare_agents(self.request, ["fake-alpha"], registry=self.registry)

    def test_workflow_uses_scheduler_authorities_and_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            scheduler = LocalScheduler(Path(directory) / "scheduler.json", registry=self.registry)
            client = LocalAuthorityClient({name: LocalAuthorityEndpoint(name, outcomes) for name, outcomes in {"coordinator": ["observed"], "awq": ["accepted", "accepted"], "awg": ["requires_ui", "requires_ui"], "ui": ["approved", "approved"]}.items()})
            workflow = LocalMockWorkflow(scheduler, AuthorityGates(client), self.registry)
            result = workflow.run(job_id="JOB-MOCK-1", task="AR-0129", revision=1, worker="WRK-MOCK-1", session_id="SES-MOCK-1", lease_id="LSE-00000001", request=self.request, budget={"seconds": 1, "tokens": 64, "events": 1})
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(result["terminal"]["jobs"]["JOB-MOCK-1"]["state"], "done")
            self.assertEqual(result["accounting"]["usage"]["events"], 1)
            self.assertEqual(result["record"]["network"], "disabled")

    def test_unsupported_stream_fails_before_execution(self):
        request = MockRequest(**{**self.request.__dict__, "adapter_id": "fake-beta"})
        with self.assertRaisesRegex(MockProtocolError, "unsupported"):
            DeterministicLocalLLM(self.registry, "fake-beta").request(request)


if __name__ == "__main__":
    unittest.main()

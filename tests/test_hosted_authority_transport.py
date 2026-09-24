import unittest

from awr_cli.authority_gates import AuthorityGates
from scripts.hosted_authority_transport import (
    AmbiguousAuthorityOutcome,
    DeterministicHostedServer,
    HostedAuthorityClient,
    HostedExchange,
    HostedTransportError,
)
from scripts.local_authority_bridge import AuthorityBridgeError
from scripts.local_authority_transport import make_request


def hosted(outcomes):
    return HostedAuthorityClient({name: DeterministicHostedServer(name, values) for name, values in outcomes.items()})


class HostedAuthorityTransportTests(unittest.TestCase):
    def test_mandatory_order_uses_all_four_hosted_observation_adapters(self):
        client = hosted({
            "coordinator": ["observed"], "awq": ["accepted"],
            "awg": ["requires_ui"], "ui": ["approved"],
        })
        result = AuthorityGates(client).admit(task="AR-HOST-1", revision=4)
        self.assertEqual(result["mandatory_order"], ["coordinator", "awq", "awg", "ui"])
        self.assertEqual([item["authority"] for item in result["trace"]], result["mandatory_order"])
        self.assertEqual(result["authority_state"], "observed_only")

    def test_revision_and_required_authority_are_checked_before_server(self):
        server = DeterministicHostedServer("ui", ["approved"])
        client = HostedAuthorityClient({"ui": server})
        request = make_request("ui", "OP-STALE", 3)
        with self.assertRaisesRegex(HostedTransportError, "stale"):
            client.exchange(request, expected_revision=4, required_authority="ui")
        with self.assertRaisesRegex(HostedTransportError, "required"):
            client.exchange(request, expected_revision=3, required_authority="awg")
        self.assertEqual(server.requests, [])

    def test_correlation_mismatch_is_rejected(self):
        def crossed(envelope):
            return HostedExchange(envelope["request"] | {"operation_id": "OP-CROSSED"}, "OTHER", 1, 100)

        client = HostedAuthorityClient({"awq": crossed})
        with self.assertRaisesRegex(HostedTransportError, "correlation"):
            client.exchange(make_request("awq", "OP-CORRELATION", 2), expected_revision=2, required_authority="awq")

    def test_transient_transport_retries_are_bounded(self):
        server = DeterministicHostedServer("awq", ["accepted"], failures=["reset", "unavailable"])
        client = HostedAuthorityClient({"awq": server}, max_attempts=3)
        result = client.exchange(make_request("awq", "OP-RETRY", 2), expected_revision=2, required_authority="awq")
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual([item["attempt"] for item in server.requests], [1, 2, 3])

    def test_ambiguous_outcome_is_not_retried_or_promoted(self):
        server = DeterministicHostedServer("awg", ["unknown", "approved"])
        client = HostedAuthorityClient({"awg": server}, max_attempts=3)
        with self.assertRaises(AmbiguousAuthorityOutcome):
            client.exchange(make_request("awg", "OP-AMBIGUOUS", 2), expected_revision=2, required_authority="awg")
        self.assertEqual(len(server.requests), 1)

    def test_deadline_is_enforced_after_fake_server_delay(self):
        server = DeterministicHostedServer("ui", ["approved"], delay_ms=20)
        client = HostedAuthorityClient({"ui": server}, deadline_ms=5, max_attempts=1)
        with self.assertRaisesRegex(HostedTransportError, "deadline"):
            client.exchange(make_request("ui", "OP-DEADLINE", 2), expected_revision=2, required_authority="ui")

    def test_response_revision_and_digest_remain_contract_validated(self):
        def stale(envelope):
            request = envelope["request"]
            response = DeterministicHostedServer("coordinator", ["observed"])(envelope).response
            response["task_revision"] = request["task_revision"] - 1
            return HostedExchange(response, envelope["correlation_id"], envelope["attempt"], envelope["deadline_ms"])

        client = HostedAuthorityClient({"coordinator": stale})
        with self.assertRaisesRegex(AuthorityBridgeError, "stale"):
            client.exchange(make_request("coordinator", "OP-STALE-RESPONSE", 3), expected_revision=3, required_authority="coordinator")


if __name__ == "__main__":
    unittest.main()

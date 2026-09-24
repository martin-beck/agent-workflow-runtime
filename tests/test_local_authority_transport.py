import copy
import unittest

from scripts.local_authority_bridge import AuthorityBridgeError
from scripts.local_authority_transport import LocalAuthorityClient, LocalAuthorityEndpoint, LocalAuthorityProcessEndpoint, demo_client, make_request


class LocalAuthorityTransportTests(unittest.TestCase):
    def test_four_authority_exchange_is_real_in_process_request_response(self):
        client = demo_client()
        outcomes = []
        for authority, expected in (("coordinator", "observed"), ("awq", "accepted"), ("awg", "requires_ui"), ("ui", "approved")):
            outcomes.append(client.exchange(make_request(authority, "OP-" + authority.upper(), 9), expected_revision=9, required_authority=authority)["outcome"])
        self.assertEqual(outcomes, ["observed", "accepted", "requires_ui", "approved"])
        self.assertEqual([len(endpoint.requests) for endpoint in client.endpoints.values()], [1, 1, 1, 1])

    def test_transient_unknown_is_bounded_and_then_resolved(self):
        endpoint = LocalAuthorityEndpoint("awq", ["unknown", "accepted"])
        client = LocalAuthorityClient({"awq": endpoint}, max_attempts=2)
        result = client.exchange(make_request("awq", "OP-RETRY", 2), expected_revision=2, required_authority="awq")
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(len(endpoint.requests), 2)

    def test_unknown_exhaustion_remains_blocking(self):
        endpoint = LocalAuthorityEndpoint("awg", ["unknown", "unknown"])
        client = LocalAuthorityClient({"awg": endpoint}, max_attempts=2)
        with self.assertRaisesRegex(AuthorityBridgeError, "ambiguous"):
            client.exchange(make_request("awg", "OP-BLOCK", 2), expected_revision=2, required_authority="awg")

    def test_local_os_process_endpoint_exchanges_events_without_network(self):
        endpoint = LocalAuthorityProcessEndpoint("awq", ["accepted"])
        try:
            client = LocalAuthorityClient({"awq": endpoint})
            result = client.exchange(make_request("awq", "OP-PROCESS", 3), expected_revision=3, required_authority="awq")
            self.assertEqual(result["outcome"], "accepted")
        finally:
            endpoint.close()

    def test_stale_crossed_and_replayed_requests_fail_closed(self):
        client = demo_client()
        request = make_request("ui", "OP-STALE", 4)
        with self.assertRaisesRegex(AuthorityBridgeError, "stale"):
            client.exchange(request, expected_revision=5, required_authority="ui")
        with self.assertRaisesRegex(AuthorityBridgeError, "required"):
            client.exchange(request, expected_revision=4, required_authority="awg")
        self.assertEqual(client.exchange(request, expected_revision=4, required_authority="ui")["outcome"], "approved")
        self.assertEqual(client.exchange(request, expected_revision=4, required_authority="ui")["outcome"], "approved")
        self.assertEqual(len(client.endpoints["ui"].requests), 2)


if __name__ == "__main__":
    unittest.main()

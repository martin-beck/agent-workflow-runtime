import unittest

from awr_cli.authority_gates import AuthorityGates
from scripts.local_authority_bridge import AuthorityBridgeError
from scripts.local_authority_transport import LocalAuthorityClient, LocalAuthorityEndpoint
from scripts.hosted_authority_transport import DeterministicHostedServer, HostedAuthorityClient


def client(outcomes):
    return LocalAuthorityClient({name: LocalAuthorityEndpoint(name, values) for name, values in outcomes.items()})


class AuthorityGateTests(unittest.TestCase):
    def test_all_gates_are_executed_in_order(self):
        result = AuthorityGates(client({"coordinator": ["observed"], "awq": ["accepted"], "awg": ["requires_ui"], "ui": ["approved"]})).admit(task="AR-GATE-1", revision=3)
        self.assertEqual(result["mandatory_order"], ["coordinator", "awq", "awg", "ui"])
        self.assertEqual([item["authority"] for item in result["trace"]], result["mandatory_order"])

    def test_quality_rejection_cannot_skip_to_guidance_or_ui(self):
        endpoints = {"coordinator": LocalAuthorityEndpoint("coordinator", ["observed"]), "awq": LocalAuthorityEndpoint("awq", ["rejected"]), "awg": LocalAuthorityEndpoint("awg", ["approved"]), "ui": LocalAuthorityEndpoint("ui", ["approved"])}
        with self.assertRaisesRegex(AuthorityBridgeError, "awq"):
            AuthorityGates(LocalAuthorityClient(endpoints)).admit(task="AR-GATE-1", revision=3)
        self.assertEqual(endpoints["awg"].requests, [])
        self.assertEqual(endpoints["ui"].requests, [])

    def test_invalid_revision_is_rejected_before_any_gate(self):
        gates = AuthorityGates(client({"coordinator": ["observed"], "awq": ["accepted"], "awg": ["approved"], "ui": ["approved"]}))
        with self.assertRaisesRegex(AuthorityBridgeError, "revision"):
            gates.admit(task="AR-GATE-1", revision=0)

    def test_hosted_shaped_transport_is_wired_through_all_gates(self):
        endpoints = {
            name: DeterministicHostedServer(name, values)
            for name, values in {
                "coordinator": ["observed"], "awq": ["accepted"], "awg": ["requires_ui"], "ui": ["approved"]
            }.items()
        }
        result = AuthorityGates(HostedAuthorityClient(endpoints)).admit(task="AR-GATE-1", revision=3)
        self.assertEqual(result["status"], "admitted")
        self.assertEqual([event["authority"] for event in result["trace"]], ["coordinator", "awq", "awg", "ui"])


if __name__ == "__main__":
    unittest.main()

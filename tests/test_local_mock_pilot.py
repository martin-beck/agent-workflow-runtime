import copy
import unittest

from scripts.local_mock_pilot import LocalLLMMock, LocalMockError, run, validate


class LocalMockPilotTests(unittest.TestCase):
    def test_local_end_to_end_is_deterministic_and_never_external(self):
        first = run(7)
        second = run(7)
        self.assertEqual(first, second)
        self.assertTrue(first["local_execution"])
        self.assertEqual(first["external_provider"], "not_performed")
        self.assertEqual(first["network"], "disabled")
        self.assertEqual(first["credentials"], "not_supplied")

    def test_mock_rejects_provider_shaped_or_malformed_requests(self):
        mock = LocalLLMMock()
        with self.assertRaises(LocalMockError):
            mock.complete({"model": "real/provider", "messages": [], "request_id": "REQ-MOCK-1"})
        with self.assertRaises(LocalMockError):
            mock.complete({"model": "mock/benchmark-v1", "messages": [], "request_id": "bad"})

    def test_fixture_tampering_fails_closed(self):
        from scripts.local_mock_pilot import digest
        record = {"seed": 1, "expected_digest": digest(run(1))}
        validate(record)
        tampered = copy.deepcopy(record)
        tampered["expected_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(LocalMockError):
            validate(tampered)


if __name__ == "__main__":
    unittest.main()

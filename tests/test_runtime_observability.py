import copy
import json
import unittest
from pathlib import Path

from scripts.runtime_observability import ObservabilityError, digest, validate

ROOT = Path(__file__).parents[1]


class RuntimeObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / "specifications/fixtures/runtime-observability-ar0056-v1.json").read_text(encoding="utf-8"))

    def reject(self, mutate):
        changed = copy.deepcopy(self.record)
        mutate(changed)
        with self.assertRaises(ObservabilityError):
            validate(changed, 5)

    def test_complete_offline_trace_reconstructs_audit_and_export(self):
        result = validate(self.record, 5)
        self.assertEqual(result["events"], 12)
        self.assertTrue(result["audit_reconstructed"])
        self.assertEqual(result["export"], "prepared_not_exported")
        self.assertEqual(result["provider"], "not_performed")

    def test_revision_binding_order_clock_and_audit_fail_closed(self):
        self.reject(lambda r: r["task"].update(revision=4))
        self.reject(lambda r: r["events"][3].update(previous_id="EVT-01"))
        self.reject(lambda r: r["events"][4].update(ingested_at=2000))
        self.reject(lambda r: r["audit"][6].update(event_id="EVT-01"))
        self.reject(lambda r: r["events"][2].update(correlation_id="CORR-OTHER"))
        self.reject(lambda r: r["audit"][1].update(previous_digest=digest("genesis")))

    def test_redaction_cardinality_retention_and_execution_boundaries_fail_closed(self):
        self.reject(lambda r: r["events"][1]["attributes"].update(prompt="raw"))
        self.reject(lambda r: r["events"][0].update(correlation_id="CORR-OTHER"))
        self.reject(lambda r: r["retention"].update(raw_payloads=True))
        self.reject(lambda r: r["incident_export"].update(status="exported"))
        self.reject(lambda r: r["incident_export"].update(on_failure="retry_unbounded"))
        self.reject(lambda r: r["boundary"].update(provider="supported"))
        self.reject(lambda r: r["readiness"].update(status="ready"))

    def test_record_digest_and_structured_metric_tampering_fail_closed(self):
        self.reject(lambda r: r["metrics"][0].update(value="2400"))
        self.reject(lambda r: r["metrics"].append(copy.deepcopy(r["metrics"][0])))
        self.reject(lambda r: r["evidence"].update(record_digest=digest(b"tampered")))


if __name__ == "__main__":
    unittest.main()

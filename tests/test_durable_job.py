import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_durable_job import load, main, validate_spec
from scripts.durable_job import JobError, validate

ROOT = Path(__file__).parents[1]


class DurableJobTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(ROOT / "specifications/durable-job-v1.json")
        self.record = load(ROOT / "specifications/fixtures/durable-job-ar0061-v1.json")

    def reject(self, mutation):
        changed = copy.deepcopy(self.record)
        mutation(changed)
        with self.assertRaises(JobError):
            validate(changed)

    def test_canonical_fixture_is_offline_terminal_and_revision_bound(self):
        validate_spec(self.spec, 1)
        result = validate(self.record)
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(result["events"], 6)
        self.assertFalse(result["execute"])
        self.assertEqual(result["durable_state"], "not_performed")

    def test_hostile_bindings_privacy_and_unknown_fields_fail_closed(self):
        mutations = (
            lambda r: r["task"].update(revision=2),
            lambda r: r["events"][2].update(task_revision=2),
            lambda r: r["events"][1].update(previous_digest="sha256:" + "f" * 64),
            lambda r: r["events"][4].update(to="succeeded"),
            lambda r: r["events"][0].update(evidence_digest="sha256:" + "0" * 64),
            lambda r: r["events"].append(copy.deepcopy(r["events"][-1])),
            lambda r: r["job"].update(credentials="secret"),
            lambda r: r["job"]["inputs"].update(payload="private"),
            lambda r: r["job"]["budget"].update(max_attempts=4),
            lambda r: r["job"]["deadline"].update(at="2025-01-01T00:00:00Z"),
            lambda r: r["job"]["retry"].update(max_attempts=4),
            lambda r: r["job"]["tenancy"].update(tenant="other"),
            lambda r: r["job"]["privacy"].update(raw_payload="present"),
            lambda r: r["job"]["human_gates"].update(decision="approved"),
            lambda r: r["job"]["cancellation"].update(ack_required=False),
            lambda r: r["job"]["idempotency"].update(key="other"),
            lambda r: r["job"]["provenance"].update(input_digest="sha256:" + "a" * 64),
            lambda r: r["terminal"].update(execute=True),
            lambda r: r["terminal"].update(provider="performed"),
            lambda r: r["evidence"].update(record_digest="sha256:" + "d" * 64),
            lambda r: r.update(extra="unknown"),
        )
        for mutation in mutations:
            self.reject(mutation)

    def test_all_contract_sections_are_present_and_digest_bound(self):
        expected = {"objective", "inputs", "dependencies", "capabilities", "adapters", "acceptance", "budget", "deadline", "retry", "priority", "tenancy", "privacy", "artifacts", "human_gates", "cancellation", "idempotency", "provenance"}
        self.assertEqual(set(self.record["job"]), expected)
        self.assertEqual(self.record["job"]["provenance"]["contract_digest"], self.record["evidence"]["contract_digest"])

    def test_checker_rejects_changed_schema_and_specification(self):
        changed = copy.deepcopy(self.spec)
        changed["schema_evolution"]["rule"] = "mutable"
        with tempfile.TemporaryDirectory() as directory:
            spec_path = Path(directory) / "spec.json"
            fixture_path = Path(directory) / "fixture.json"
            spec_path.write_text(json.dumps(changed), encoding="utf-8")
            fixture_path.write_text(json.dumps(self.record), encoding="utf-8")
            self.assertEqual(main(["--spec", str(spec_path), "--fixture", str(fixture_path), "--expected-revision", "1"]), 1)


if __name__ == "__main__":
    unittest.main()

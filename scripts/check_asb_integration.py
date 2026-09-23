#!/usr/bin/env python3
"""Check AR-0055 ASB integration evidence without external effects."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from scripts.asb_integration import IntegrationError, validate
except ModuleNotFoundError:
    from asb_integration import IntegrationError, validate


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrationError("malformed JSON") from exc


def validate_spec(spec, expected_revision):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "workflow", "boundaries", "limits", "hostile_qualification", "limitations"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-asb-integration" or spec["version"] != "1.0.0" or spec["normative"] is not True or spec["task"] != {"id": "AR-0055", "revision": expected_revision} or expected_revision != 5:
        raise IntegrationError("unsupported or stale AR-0055 specification")
    if spec["workflow"] != ["setup_init", "add_first_agent", "agent_connection", "preflight_eligibility", "benchmark_run", "extend_identical_configuration", "llm_record_replay", "interrupt_recovery", "comparison"]:
        raise IntegrationError("workflow specification mismatch")
    if spec["boundaries"] != {"execute": False, "provider": "not_performed", "network": "disabled", "llm": "not_performed", "benchmark": "not_performed", "credentials": "references_only", "durable_state": "not_performed", "remote_verification": "unverified"} or spec["limits"] != {"max_events": 16, "max_agents": 8, "max_bytes": 4096, "max_retries": 1}:
        raise IntegrationError("unsafe specification boundary")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        validate_spec(load(args.spec), args.expected_revision)
        result = validate(load(args.fixture), args.expected_revision)
    except (IntegrationError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

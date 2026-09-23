#!/usr/bin/env python3
"""Check AR-0051 deterministic capability and preflight evidence offline."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.agent_capability_preflight import PreflightError, canonical_bytes, preflight, sha256


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = json.loads(args.spec.read_text(encoding="utf-8"))
        record = json.loads(args.record.read_text(encoding="utf-8"))
        required = {"schema_version", "specification_id", "version", "title", "normative", "task", "states", "statuses", "rules", "required_gates", "privacy", "offline_boundary", "hostile_qualification", "limitations"}
        if set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-agent-capability-preflight" or spec["version"] != "1.0.0" or spec["normative"] is not True or spec["task"] != {"id": "AR-0051", "revision": 5}:
            raise PreflightError("unsupported or stale AR-0051 specification")
        if spec["offline_boundary"] != {"provider": "not_performed", "adapter_execution": "not_performed", "network": "disabled", "llm": "not_performed", "credentials": "references_only", "live_support": "unverified", "durable_state": "not_performed"}:
            raise PreflightError("unsafe offline boundary")
        result = preflight(record, args.expected_revision)
    except (OSError, json.JSONDecodeError, PreflightError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": "awr-agent-capability-preflight-checker/1.0.0", "specification_digest": sha256(canonical_bytes(spec)), "record_digest": sha256(canonical_bytes(record))}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

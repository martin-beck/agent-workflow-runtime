#!/usr/bin/env python3
"""Offline checker for the AR-0056 observability contract."""
import argparse, json, sys
from pathlib import Path
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.runtime_observability import ObservabilityError, ALERTS, LIMITS, PROTOCOL, TASK, validate

def load(path):
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise ObservabilityError("malformed JSON") from exc

def validate_spec(spec, revision):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "limits", "retention", "alert_thresholds", "offline_boundary", "required_surfaces", "limitations"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != PROTOCOL["id"] or spec["version"] != "1.0.0" or spec["normative"] is not True or spec["task"] != {"id": "AR-0056", "revision": revision} or revision != 5:
        raise ObservabilityError("unsupported or stale AR-0056 specification")
    if spec["limits"] != LIMITS or spec["alert_thresholds"] != ALERTS or spec["retention"] != {"retention_days": 7, "mode": "digest_only", "raw_payloads": False, "export_max_bytes": 16384} or spec["offline_boundary"] != {"collector": "supplied_observations_only", "provider": "not_performed", "network": "disabled", "llm": "not_performed", "durable_state": "not_performed", "remote_verification": "unverified"}:
        raise ObservabilityError("unsafe specification boundary")

def main(argv=None):
    p = argparse.ArgumentParser(); p.add_argument("--spec", required=True, type=Path); p.add_argument("--record", required=True, type=Path); p.add_argument("--expected-revision", required=True, type=int); a = p.parse_args(argv)
    try: validate_spec(load(a.spec), a.expected_revision); result = validate(load(a.record), a.expected_revision)
    except (ObservabilityError, KeyError, TypeError) as exc: print("REJECT: " + str(exc), file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0
if __name__ == "__main__": raise SystemExit(main())

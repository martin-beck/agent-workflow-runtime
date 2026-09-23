#!/usr/bin/env python3
"""Fail-closed checker for AR-0059; no external effects."""
import argparse, json, sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.production_qualification_chaos import QualificationError, PROTOCOL, TASK, LIMITS, THRESHOLDS, validate, digest

def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError("malformed JSON") from exc

def validate_spec(spec, revision):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "adapters", "asb_workflows", "scenarios", "thresholds", "limits", "authority", "offline_boundary", "privacy", "failure_semantics", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != PROTOCOL["id"] or spec["version"] != PROTOCOL["version"] or spec["normative"] is not True or spec["task"] != TASK or revision != 5:
        raise QualificationError("unsupported or stale AR-0059 specification")
    if spec["adapters"] != ["codex", "opencode", "opendesk"] or spec["limits"] != LIMITS or spec["thresholds"] != THRESHOLDS or spec["offline_boundary"]["execute"] is not False or spec["offline_boundary"]["network"] != "disabled" or not spec["limitations"] or not spec["follow_up"]:
        raise QualificationError("incomplete or unsafe specification")

def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try:
        spec = load(args.spec); record = load(args.fixture); validate_spec(spec, args.expected_revision); result = validate(record)
        if record["evidence"]["specification_digest"] != digest(spec):
            raise QualificationError("specification digest mismatch")
        if validate(json.loads(json.dumps(record, sort_keys=True))) != result:
            raise QualificationError("replay changed result")
    except (QualificationError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline checker for AR-0061; it never executes or persists a job."""
import argparse, json, sys
from pathlib import Path
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.durable_job import JobError, PROTOCOL, TASK, validate, digest

def load(path):
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise JobError("malformed JSON") from exc

def validate_spec(spec, revision):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "schema_evolution", "states", "terminal_states", "authority", "offline_boundary", "privacy", "failure_semantics", "limitations", "follow_up", "required_job_sections"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != PROTOCOL["id"] or spec["version"] != PROTOCOL["version"] or spec["normative"] is not True or spec["task"] != TASK or revision != 1: raise JobError("unsupported or stale specification")
    if spec["states"][:1] != ["submitted"] or spec["terminal_states"] != ["succeeded", "failed", "cancelled"] or spec["offline_boundary"]["execute"] is not False: raise JobError("incomplete or unsafe specification")

def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try:
        spec, record = load(args.spec), load(args.fixture); validate_spec(spec, args.expected_revision); result = validate(record, args.expected_revision)
        if record["evidence"]["contract_digest"] != digest(spec) or validate(record, args.expected_revision) != result: raise JobError("replay changed result")
    except (JobError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0

if __name__ == "__main__": raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed checker for the AR-0060 offline final pilot."""
import argparse, json, sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.final_pilot import FinalPilotError, PROTOCOL, TASK, GATES, validate, digest


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalPilotError("malformed JSON") from exc


def validate_spec(spec, revision):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "gates", "authority", "offline_boundary", "privacy", "failure_semantics", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != PROTOCOL["id"] or spec["version"] != PROTOCOL["version"] or spec["normative"] is not True or spec["task"] != TASK or revision != 5:
        raise FinalPilotError("unsupported or stale specification")
    if spec["gates"] != list(GATES) or spec["offline_boundary"]["execute"] is not False or spec["offline_boundary"]["network"] != "disabled" or not spec["limitations"] or not spec["follow_up"]:
        raise FinalPilotError("incomplete or unsafe specification")


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try:
        spec = load(args.spec); record = load(args.fixture); validate_spec(spec, args.expected_revision); result = validate(record, args.expected_revision)
        if record["evidence"]["specification_digest"] != digest(spec) or validate(record, args.expected_revision) != result or record["evidence"]["record_digest"] != digest({key: value for key, value in record.items() if key != "evidence"}):
            raise FinalPilotError("replay changed result")
    except (FinalPilotError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Check AR-0057 supplied security observations without external effects."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.production_security_hardening import PROTOCOL, SecurityError, canonical, digest, validate

CHECKER = "awr-production-security-hardening-checker/1.0.0"


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record = load(args.spec), load(args.record)
        required = {"schema_version", "specification_id", "version", "title", "normative", "task", "controls", "operations", "privacy", "failure_semantics", "offline_boundary", "follow_up"}
        if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != PROTOCOL["id"] or spec["version"] != "1.0.0" or spec["normative"] is not True or spec["task"] != {"id": "AR-0057", "revision": 5} or args.expected_revision != 5:
            raise SecurityError("unsupported or stale specification")
        result = validate(record, args.expected_revision)
    except (SecurityError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": digest(canonical(spec)), "record_digest": digest(canonical(record))}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

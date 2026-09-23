#!/usr/bin/env python3
"""Fail-closed offline checker for the AR-0011 UI session bridge."""

import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.ui_session_bridge import BridgeError, canonical_bytes, sha256, validate_bridge
except ImportError:
    from ui_session_bridge import BridgeError, canonical_bytes, sha256, validate_bridge

CHECKER = "awr-ui-session-bridge-checker/1.0.0"


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise BridgeError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record, evidence = load_json(args.spec), load_json(args.record), load_json(args.evidence)
        if not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-ui-session-bridge" or spec.get("version") != "1.0.0":
            raise BridgeError("unsupported specification")
        result = validate_bridge(record, args.expected_revision)
        expected_spec = sha256(canonical_bytes(spec))
        expected = {"checker": CHECKER, "task_revision": args.expected_revision, "specification_digest": expected_spec, "record_digest": sha256(canonical_bytes(record)), "result": result}
        if evidence != {**expected, "safe_digest": evidence.get("safe_digest")}:
            raise BridgeError("mismatched evidence envelope")
        if evidence.get("safe_digest") != sha256(canonical_bytes(expected)):
            raise BridgeError("evidence digest mismatch")
    except (BridgeError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": expected_spec}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

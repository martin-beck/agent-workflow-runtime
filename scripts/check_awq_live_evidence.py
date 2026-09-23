#!/usr/bin/env python3
"""Offline checker for the AR-0037 AWQ live-evidence contract."""

import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.awq_live_evidence import EvidenceError, canonical_bytes, project, sha256, validate
except ModuleNotFoundError:
    from awq_live_evidence import EvidenceError, canonical_bytes, project, sha256, validate


CHECKER = "awr-awq-live-evidence-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record, evidence = load(args.spec), load(args.record), load(args.evidence)
        if not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-awq-live-evidence" or spec.get("version") != "1.0.0":
            raise EvidenceError("unsupported specification")
        result = validate(record, args.expected_revision)
        expected_spec = sha256(canonical_bytes(spec))
        expected_projection = project(record, expected_spec)
        expected = {"checker": CHECKER, "task_revision": args.expected_revision, "specification_digest": expected_spec, "record_digest": sha256(canonical_bytes(record)), "projection": expected_projection, "live_verification": "unverified", "safe_digest": evidence.get("safe_digest")}
        if evidence != expected:
            raise EvidenceError("mismatched evidence envelope")
        safe = dict(evidence); safe.pop("safe_digest")
        if not isinstance(evidence.get("safe_digest"), str) or evidence["safe_digest"] != sha256(canonical_bytes(safe)):
            raise EvidenceError("evidence digest mismatch")
        if expected_projection["quality_status"] != "not_decided_by_runtime" or expected_projection["gate_consumption"]["authority"] != "awq":
            raise EvidenceError("runtime manufactured quality authority")
    except (EvidenceError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": expected_spec, "live_verification": "unverified"}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed checker for the offline AR-0039 UI/human-gate fixture."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.ui_live_human_gate import GateError, canonical_bytes, project, sha256, validate
except ModuleNotFoundError:
    from ui_live_human_gate import GateError, canonical_bytes, project, sha256, validate

CHECKER = "awr-ui-live-human-gate-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record, evidence = load(args.spec), load(args.record), load(args.evidence)
        if not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-ui-live-human-gate" or spec.get("version") != "1.0.0":
            raise GateError("unsupported specification")
        result = validate(record, args.expected_revision)
        spec_digest = sha256(canonical_bytes(spec))
        expected = {"checker": CHECKER, "task_revision": args.expected_revision, "specification_digest": spec_digest, "record_digest": sha256(canonical_bytes(record)), "projection": project(record, spec_digest), "live_verification": "unverified"}
        if evidence != {**expected, "evidence_digest": evidence.get("evidence_digest")}:
            raise GateError("mismatched evidence envelope")
        safe = dict(evidence); safe.pop("evidence_digest", None)
        if evidence.get("evidence_digest") != sha256(canonical_bytes(safe)):
            raise GateError("evidence digest mismatch")
        if evidence["projection"]["human_gate"]["guidance_status"] != "not_decided" or evidence["live_verification"] != "unverified":
            raise GateError("authority or live success manufactured")
    except (GateError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": spec_digest, "live_verification": "unverified"}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

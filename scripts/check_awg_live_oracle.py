#!/usr/bin/env python3
"""Fail-closed offline checker for the AR-0038 AWG oracle boundary."""
import argparse, json, sys
from pathlib import Path

try:
    from scripts.awg_live_oracle import OracleError, canonical_bytes, project, sha256, validate
except ModuleNotFoundError:
    from awg_live_oracle import OracleError, canonical_bytes, project, sha256, validate

CHECKER = "awr-awg-live-oracle-checker/1.0.0"

def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise OracleError("malformed JSON") from exc

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record, evidence = load(args.spec), load(args.record), load(args.evidence)
        if not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-awg-live-oracle" or spec.get("version") != "1.0.0":
            raise OracleError("unsupported specification")
        result = validate(record, args.expected_revision)
        spec_digest = sha256(canonical_bytes(spec)); expected_projection = project(record, spec_digest)
        expected = {"checker": CHECKER, "task_revision": args.expected_revision, "specification_digest": spec_digest, "record_digest": sha256(canonical_bytes(record)), "projection": expected_projection, "live_verification": "unverified", "safe_digest": evidence.get("safe_digest")}
        if evidence != expected:
            raise OracleError("mismatched evidence envelope")
        safe = dict(evidence); safe.pop("safe_digest")
        if not isinstance(evidence.get("safe_digest"), str) or evidence["safe_digest"] != sha256(canonical_bytes(safe)):
            raise OracleError("evidence digest mismatch")
        if expected_projection["response"]["decision_status"] != "not_decided" or expected_projection["transport"]["network"] != "not_performed":
            raise OracleError("oracle decision or live success manufactured")
    except (OracleError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": spec_digest, "live_verification": "unverified"}, sort_keys=True, separators=(",", ":"))); return 0

if __name__ == "__main__":
    raise SystemExit(main())

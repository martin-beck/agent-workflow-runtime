#!/usr/bin/env python3
"""Check AR-0021 evidence without Git, CI, providers, or network."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.publication_ci_bridge import BridgeError, canonical_bytes, project, sha256, validate
except ModuleNotFoundError:
    from publication_ci_bridge import BridgeError, canonical_bytes, project, sha256, validate

CHECKER = "awr-publication-ci-bridge-checker/1.0.0"


def load(path):
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
        spec, record, evidence = load(args.spec), load(args.record), load(args.evidence)
        if not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-publication-ci-bridge" or spec.get("version") != "1.0.0":
            raise BridgeError("unsupported specification")
        result = validate(record, args.expected_revision)
        spec_digest = sha256(canonical_bytes(spec))
        expected = {"checker": CHECKER, "task_revision": args.expected_revision, "specification_digest": spec_digest, "record_digest": sha256(canonical_bytes(record)), "projection": project(record, spec_digest), "evidence_digest": evidence.get("evidence_digest")}
        if evidence != expected:
            raise BridgeError("mismatched evidence envelope")
        unsigned = dict(evidence); unsigned.pop("evidence_digest")
        if evidence["evidence_digest"] != sha256(canonical_bytes(unsigned)):
            raise BridgeError("evidence envelope digest mismatch")
    except (BridgeError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": spec_digest}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Check AR-0013 CI and external-observation evidence without side effects."""

import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.ci_observation_adapter import ObservationError, canonical_bytes, project_evidence, sha256, validate_record
except ModuleNotFoundError:
    from ci_observation_adapter import ObservationError, canonical_bytes, project_evidence, sha256, validate_record

CHECKER = "awr-ci-observation-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ObservationError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record, evidence = load(args.spec), load(args.record), load(args.evidence)
        if not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-ci-observation-adapter" or spec.get("version") != "1.0.0":
            raise ObservationError("unsupported specification")
        result = validate_record(record, args.expected_revision)
        spec_digest = sha256(canonical_bytes(spec))
        expected_projection = project_evidence(record, spec_digest)
        expected = {"checker": CHECKER, "task_revision": args.expected_revision, "specification_digest": spec_digest, "record_digest": sha256(canonical_bytes(record)), "projection": expected_projection}
        if evidence != {**expected, "evidence_digest": evidence.get("evidence_digest")}:
            raise ObservationError("mismatched evidence envelope")
        unsigned = dict(evidence); unsigned.pop("evidence_digest")
        if evidence["evidence_digest"] != sha256(canonical_bytes(unsigned)):
            raise ObservationError("evidence envelope digest mismatch")
    except (ObservationError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": spec_digest}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

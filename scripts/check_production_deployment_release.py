#!/usr/bin/env python3
"""Check AR-0058 supplied release observations without external effects."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.production_deployment_release import DeploymentReleaseError, PROTOCOL, canonical, digest, validate

CHECKER = "awr-production-deployment-release-checker/1.0.0"


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeploymentReleaseError("malformed JSON") from exc


def validate_spec(spec, expected_revision=5):
    fields = {"schema_version", "specification_id", "version", "title", "normative", "task", "areas", "states", "invariants", "privacy", "failure_semantics", "offline_boundary", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != fields or spec["schema_version"] != 1 or spec["specification_id"] != PROTOCOL["id"] or spec["version"] != PROTOCOL["version"] or spec["normative"] is not True or spec["task"] != {"id": "AR-0058", "revision": expected_revision} or expected_revision != 5:
        raise DeploymentReleaseError("unsupported or stale specification")
    if spec["areas"] != ["packaging", "deployment", "compatibility", "upgrade", "rollback", "release"] or not spec["invariants"] or not spec["follow_up"]:
        raise DeploymentReleaseError("incomplete specification")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = load(args.spec); record = load(args.record)
        validate_spec(spec, args.expected_revision)
        result = validate(record, args.expected_revision)
        evidence = record["evidence"]
        if evidence["specification_digest"] != digest(canonical(spec)):
            raise DeploymentReleaseError("specification digest mismatch")
    except (DeploymentReleaseError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": digest(canonical(spec)), "record_digest": digest(canonical(record))}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

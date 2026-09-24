#!/usr/bin/env python3
"""Check AR-0080 production integration evidence without external effects."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.production_integration_baseline import IntegrationError, canonical_bytes, digest, validate


CHECKER = "awr-production-integration-baseline-checker/1.0.0"


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrationError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = load(args.spec)
        record = load(args.record)
        result = validate(record, spec, args.expected_revision)
    except (IntegrationError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": digest(canonical_bytes(spec)), "record_digest": digest(canonical_bytes(record))}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

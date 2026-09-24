#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0084 agent registry preflight."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.agent_registry import (
    RegistryError,
    canonical_bytes,
    preflight,
    sha256,
    validate_spec,
)

CHECKER = "awr-agent-registry-checker/1.0.0"


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = load_json(args.spec)
        record = load_json(args.record)
        validate_spec(spec, args.expected_revision)
        result = preflight(record, spec, args.expected_revision)
    except (RegistryError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({
        **result,
        "checker": CHECKER,
        "registry_digest": sha256(canonical_bytes(spec)),
        "record_digest": sha256(canonical_bytes(record)),
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

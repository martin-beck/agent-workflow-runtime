#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0064."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.fake_agent_simulator import SimulationError, validate


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try:
        spec = json.loads(args.spec.read_text(encoding="utf-8")); record = json.loads(args.fixture.read_text(encoding="utf-8"))
        if args.expected_revision != 1 or set(spec) != {"schema_version", "specification_id", "version", "task", "offline", "invariants", "failures"} or spec["task"] != {"id": "AR-0064", "revision": 1} or spec["offline"]["execute"] is not False:
            raise SimulationError("unsupported or unsafe specification")
        print(json.dumps(validate(record), sort_keys=True, separators=(",", ":"))); return 0
    except (OSError, json.JSONDecodeError, KeyError, TypeError, SimulationError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())

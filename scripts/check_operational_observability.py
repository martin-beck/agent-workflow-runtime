#!/usr/bin/env python3
"""Offline contract checker for AR-0091 operational observability."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.operational_observability import OperationalObservabilityError, validate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = json.loads(args.spec.read_text())
        fixture = json.loads(args.fixture.read_text())
        if spec.get("task") != {"id": "AR-0091", "revision": args.expected_revision}:
            raise OperationalObservabilityError("invalid_specification_task")
        if spec.get("offline_boundary", {}).get("network") != "disabled":
            raise OperationalObservabilityError("online_boundary")
        result = validate(fixture, args.expected_revision)
        print(
            json.dumps(
                {"checker": "awr-operational-observability-checker/1.0.0", **result},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        OperationalObservabilityError,
    ) as error:
        print(f"REJECT: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

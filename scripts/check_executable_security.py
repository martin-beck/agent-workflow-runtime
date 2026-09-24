#!/usr/bin/env python3
"""Run the AR-0092 security contract without external effects."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.executable_security import ExecutableSecurityError, validate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = json.loads(args.spec.read_text())
        fixture = json.loads(args.fixture.read_text())
        if (
            spec.get("task") != {"id": "AR-0092", "revision": args.expected_revision}
            or spec.get("offline_boundary", {}).get("network") != "disabled"
        ):
            raise ExecutableSecurityError("invalid_specification")
        print(
            json.dumps(
                validate(fixture, args.expected_revision),
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
        ExecutableSecurityError,
    ) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

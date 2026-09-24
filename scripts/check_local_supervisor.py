#!/usr/bin/env python3
"""Offline checker for the AR-0083 supervisor contract and fixture."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CHECKER = "awr-local-supervisor-checker/1.0.0"
PROTOCOL = {"id": "awr-local-supervisor", "version": "1.0.0"}


class CheckError(ValueError):
    pass


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc
    if not isinstance(value, dict):
        raise CheckError("object required")
    return value


def validate(spec: dict, fixture: dict, expected_revision: int) -> dict[str, object]:
    required_spec = {
        "schema_version",
        "specification_id",
        "version",
        "normative",
        "authority",
        "admission",
        "boundary",
        "lifecycle",
        "privacy",
        "failure_semantics",
        "unsupported_controls",
        "execution",
    }
    if (
        set(spec) != required_spec
        or spec["schema_version"] != 1
        or spec["specification_id"] != PROTOCOL["id"]
        or spec["version"] != PROTOCOL["version"]
        or spec["normative"] is not True
    ):
        raise CheckError("unsupported specification")
    if (
        spec["failure_semantics"] != "fail_closed"
        or spec["unsupported_controls"] != "block admission"
    ):
        raise CheckError("unsafe failure semantics")
    if (
        set(fixture)
        != {"schema_version", "protocol", "task", "cases", "execution", "evidence"}
        or fixture["schema_version"] != 1
        or fixture["protocol"] != PROTOCOL
    ):
        raise CheckError("malformed fixture envelope")
    if fixture["task"] != {"id": "AR-0083", "revision": expected_revision}:
        raise CheckError("wrong task revision")
    cases = fixture["cases"]
    if not isinstance(cases, list) or {
        case.get("name") for case in cases if isinstance(case, dict)
    } != {
        "success",
        "timeout",
        "cancellation",
        "output_overflow",
        "unsupported_control",
        "stale_lease",
    }:
        raise CheckError("required hostile cases are missing")
    if any(
        not isinstance(case, dict)
        or set(case) != {"name", "disposition", "host_controls"}
        for case in cases
    ):
        raise CheckError("malformed case")
    if fixture["execution"] != {
        "mode": "offline_fixture",
        "process": "not_performed",
        "network": "disabled",
        "provider": "not_performed",
    }:
        raise CheckError("external execution claim")
    if fixture["evidence"] != {"checker": CHECKER, "live_verification": "unverified"}:
        raise CheckError("evidence mismatch")
    return {
        "protocol": "awr-local-supervisor@1.0.0",
        "task_revision": expected_revision,
        "cases": len(cases),
        "live_verification": "unverified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        print(
            json.dumps(
                validate(load(args.spec), load(args.fixture), args.expected_revision),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (CheckError, TypeError, KeyError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

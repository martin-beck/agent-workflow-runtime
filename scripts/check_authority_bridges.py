#!/usr/bin/env python3
"""Fail-closed checker for the AR-0088 offline authority bridge contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.authority_bridges import (
    PROTOCOL,
    BridgeError,
    canonical,
    digest,
    validate_record,
)

CHECKER = "awr-authority-bridges-checker/1.0.0"
OFFLINE = {
    "network": "disabled",
    "provider": "not_performed",
    "llm": "not_performed",
    "durable_state": "not_performed",
}
REQUIRED_HOSTILES = {
    "stale_revision",
    "crossed_lease",
    "changed_replay",
    "runtime_manufactured_acceptance",
    "runtime_manufactured_guidance",
    "runtime_manufactured_ui_approval",
    "unresolved_pending_continuation",
    "exhausted_unknown_retry",
    "rejected_change",
    "private_material",
}


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BridgeError("malformed JSON") from exc


def validate_spec(spec: dict) -> dict:
    fields = {
        "schema_version",
        "specification_id",
        "version",
        "title",
        "normative",
        "authorities",
        "states",
        "invariants",
        "required_change_kinds",
        "hostile_cases",
        "offline_boundary",
        "limitations",
    }
    if (
        not isinstance(spec, dict)
        or set(spec) != fields
        or spec["schema_version"] != 1
        or spec["specification_id"] != PROTOCOL["id"]
        or spec["version"] != PROTOCOL["version"]
        or spec["normative"] is not True
    ):
        raise BridgeError("malformed or unsupported specification")
    if set(spec["authorities"]) != {"awq", "awg", "ui", "runtime"} or not all(
        isinstance(value, dict) for value in spec["authorities"].values()
    ):
        raise BridgeError("authority partition incomplete")
    if (
        not set(spec["states"])
        >= {
            "pending",
            "accepted",
            "approved",
            "rejected",
            "unknown",
            "blocked",
            "authorized",
        }
        or not spec["invariants"]
    ):
        raise BridgeError("state or invariant model incomplete")
    if set(spec["required_change_kinds"]) != {
        "refinement",
        "test_change",
        "specification_change",
        "repair_escalation",
    }:
        raise BridgeError("required change kinds incomplete")
    if (
        set(spec["hostile_cases"]) != REQUIRED_HOSTILES
        or spec["offline_boundary"] != OFFLINE
        or not spec["limitations"]
    ):
        raise BridgeError("hostile corpus or offline boundary incomplete")
    runtime = spec["authorities"]["runtime"]
    if (
        set(runtime["may"]) != {"request", "observe", "retry", "resume", "enforce"}
        or "manufacture_human_approval" not in runtime["may_not"]
    ):
        raise BridgeError("runtime authority boundary weakened")
    return {
        "protocol": PROTOCOL,
        "invariants": len(spec["invariants"]),
        "hostile_cases": len(spec["hostile_cases"]),
    }


def check(spec: dict, record: dict, evidence: dict, expected_revision: int) -> dict:
    validate_spec(spec)
    result = validate_record(record, expected_revision=expected_revision)
    spec_digest = digest(canonical(spec))
    expected = {
        "checker": CHECKER,
        "task_revision": expected_revision,
        "specification_digest": spec_digest,
        "record_digest": digest(record),
        "result": result,
    }
    if evidence != {**expected, "evidence_digest": evidence.get("evidence_digest")}:
        raise BridgeError("mismatched evidence envelope")
    unsigned = dict(evidence)
    unsigned.pop("evidence_digest", None)
    if evidence.get("evidence_digest") != digest(unsigned):
        raise BridgeError("evidence digest mismatch")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = check(
            load(args.spec),
            load(args.record),
            load(args.evidence),
            args.expected_revision,
        )
    except (BridgeError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {**result, "checker": CHECKER}, sort_keys=True, separators=(",", ":")
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

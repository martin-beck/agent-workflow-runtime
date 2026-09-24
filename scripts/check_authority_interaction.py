#!/usr/bin/env python3
"""Checker for the AR-0098 offline authority interaction model."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.authority_interaction_model import (
    AuthorityModelError,
    InteractionModel,
    bounded_model_check,
    refine_event,
)

CHECKER = "awr-authority-interaction-checker/1.0.0"
PROTOCOL = {"id": "awr-authority-interaction-model", "version": "1.0.0"}


class CheckError(ValueError):
    """A malformed or unsafe AR-0098 specification/trace."""


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc


def validate_spec(spec: dict) -> dict:
    fields = {"schema_version", "specification_id", "version", "title", "normative", "authorities", "states", "operations", "invariants", "temporal_properties", "refinement_events", "hostile_cases", "offline_boundary", "limitations"}
    if not isinstance(spec, dict) or set(spec) != fields or spec.get("schema_version") != 1 or spec.get("specification_id") != PROTOCOL["id"] or spec.get("version") != PROTOCOL["version"] or spec.get("normative") is not True:
        raise CheckError("malformed or unsupported specification")
    if set(spec["authorities"]) != {"awc", "awr", "awq", "awg", "ui"}:
        raise CheckError("authority partition incomplete")
    if not set(spec["states"]) >= {"new", "leased", "executing", "quality_pending", "oracle_pending", "repair_pending", "ui_pending", "completed", "blocked"}:
        raise CheckError("state model incomplete")
    if not isinstance(spec["operations"], dict) or not spec["operations"] or not spec["invariants"] or not spec["temporal_properties"]:
        raise CheckError("incomplete normative model")
    required_hostiles = {"skipped_awc_lease", "skipped_awq_acceptance", "skipped_awg_decision", "direct_ui_mutation", "unresolved_repair_escalation", "stale_revision", "replay", "crash_recovery"}
    if set(spec["hostile_cases"]) != required_hostiles:
        raise CheckError("hostile corpus incomplete")
    if spec["offline_boundary"] != {"network": "disabled", "provider": "not_performed", "llm": "not_performed", "ui": "not_performed", "durable_state": "not_performed"}:
        raise CheckError("unsafe offline boundary")
    if not isinstance(spec["refinement_events"], dict) or not spec["limitations"]:
        raise CheckError("missing refinement or limitation declaration")
    for event, operation in spec["refinement_events"].items():
        if refine_event(event) != operation:
            raise CheckError("refinement mapping mismatch")
    return {"protocol": PROTOCOL, "invariants": len(spec["invariants"]), "hostile_cases": len(spec["hostile_cases"])}


def validate_trace(trace: dict, spec: dict, *, expected: dict[str, str] | None = None) -> dict:
    validate_spec(spec)
    fields = {"schema_version", "protocol", "task", "jobs", "actions", "expected", "refinement", "offline"}
    if not isinstance(trace, dict) or set(trace) != fields or trace["schema_version"] != 1 or trace["protocol"] != PROTOCOL or trace["task"] != {"id": "AR-0098", "revision": 1}:
        raise CheckError("malformed trace binding")
    jobs = trace["jobs"]
    if not isinstance(jobs, list) or not jobs or len(set(jobs)) != len(jobs) or any(not isinstance(job, str) or not job.startswith("JOB-") for job in jobs):
        raise CheckError("invalid job set")
    if trace["offline"] != spec["offline_boundary"]:
        raise CheckError("offline boundary mismatch")
    model = InteractionModel()
    for job in jobs:
        model.add_job(job)
    actions = trace["actions"]
    if not isinstance(actions, list) or not actions:
        raise CheckError("empty action trace")
    for sequence, action in enumerate(actions, 1):
        if action.get("sequence") != sequence:
            raise CheckError("non-contiguous action sequence")
        try:
            model.apply(action)
        except (AuthorityModelError, KeyError, TypeError) as exc:
            raise CheckError(str(exc)) from exc
        if model.invariants():
            raise CheckError("mandatory authority invariant violated")
    result_expected = expected if expected is not None else trace["expected"]
    if result_expected != trace["expected"] or set(result_expected) != set(jobs):
        raise CheckError("expected state binding mismatch")
    actual = {job_id: job.state for job_id, job in model.jobs.items()}
    if actual != result_expected:
        raise CheckError("final state mismatch")
    if not isinstance(trace["refinement"], list) or any(refine_event(item) != spec["refinement_events"].get(item) for item in trace["refinement"]):
        raise CheckError("unmapped refinement event")
    return {"checker": CHECKER, "jobs": len(jobs), "actions": len(actions), "states": actual}


def check_corpus(spec: dict, positive: dict, hostile: list[dict]) -> dict:
    validate_trace(positive, spec)
    rejected = blocked = 0
    for case in hostile:
        if not isinstance(case, dict) or set(case) != {"name", "expectation", "trace"}:
            raise CheckError("malformed hostile case")
        try:
            result = validate_trace(case["trace"], spec)
        except CheckError:
            if case["expectation"] != "reject":
                raise
            rejected += 1
        else:
            if case["expectation"] != "blocked" or set(result["states"].values()) != {"blocked"}:
                raise CheckError("hostile case was not fail-closed")
            blocked += 1
    return {"positive": 1, "hostile_rejected": rejected, "hostile_blocked": blocked}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--bounded-depth", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        spec = load(args.spec)
        result = validate_trace(load(args.trace), spec)
        result["bounded"] = bounded_model_check(args.bounded_depth)
    except (CheckError, AuthorityModelError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed checker for the AR-0086 scheduler contract and fixture."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.fair_scheduler import (
    AgentSlot,
    FairScheduler,
    JobSpec,
    Resources,
    SchedulingError,
)


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchedulingError("malformed JSON") from exc


def validate_spec(spec: dict, expected_revision: int) -> None:
    required = {
        "schema_version", "specification_id", "version", "normative", "task", "authority_boundaries",
        "policy", "invariants", "offline_boundary", "hostile_qualification", "required_fixture_fields",
    }
    if set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-fair-scheduler" or spec["version"] != "1.0.0" or spec["normative"] is not True:
        raise SchedulingError("unsupported_or_stale_specification")
    if expected_revision != 3 or spec["task"] != {"id": "AR-0086", "revision": 3}:
        raise SchedulingError("unsupported_or_stale_task_revision")
    boundaries = spec["authority_boundaries"]
    if boundaries != {
        "awc": "owns task identity, dependency revisions, claims, leases, and terminal commits",
        "awr": "owns policy evaluation, reservations, dispatch decisions, and bounded retries only",
        "awq": "owns quality acceptance and evidence policy; scheduler cannot approve",
        "awg": "owns guidance and user-decision escalation; scheduler cannot decide",
        "agent_registry": "supplied preflighted profiles are consumed without discovery or mutation",
        "agent_sessions": "dispatch claims are handed to the provider-neutral session boundary",
    }:
        raise SchedulingError("authority_boundary_changed")
    if spec["offline_boundary"] != {
        "execute": False,
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
        "coordinator_write": "not_performed",
        "agent_session": "not_performed",
    }:
        raise SchedulingError("unsafe_offline_boundary")
    if not isinstance(spec["invariants"], list) or len(spec["invariants"]) < 10 or not spec["hostile_qualification"] or not spec["required_fixture_fields"]:
        raise SchedulingError("incomplete_scheduler_contract")


def _resources(value: dict) -> Resources:
    return Resources(**value)


def _agent(value: dict) -> AgentSlot:
    return AgentSlot(
        agent_id=value["agent_id"],
        profile_digest=value["profile_digest"],
        capabilities=frozenset(value["capabilities"]),
        capacity=_resources(value["capacity"]),
        max_concurrency=value.get("max_concurrency", 1),
        registry_digest=value.get("registry_digest", ""),
        preflight_status=value.get("preflight_status", "accepted"),
    )


def _job(value: dict) -> JobSpec:
    fields = dict(value)
    fields["resources"] = _resources(fields.get("resources", {}))
    fields["dependencies"] = tuple(fields.get("dependencies", []))
    fields["required_capabilities"] = frozenset(fields.get("required_capabilities", []))
    fields["eligible_agents"] = frozenset(fields.get("eligible_agents", []))
    fields["retryable"] = frozenset(fields.get("retryable", ["worker_lost", "transient_unavailable", "lease_expired"]))
    return JobSpec(**fields)


def validate(record: dict) -> dict:
    required = {"capacity", "limits", "agents", "jobs", "actions", "expected"}
    if set(record) != required:
        raise SchedulingError("unknown_or_missing_fixture_field")
    scheduler = FairScheduler(_resources(record["capacity"]), **record["limits"])
    for profile in record["agents"]:
        scheduler.register_agent(_agent(profile))
    for value in record["jobs"]:
        scheduler.admit("OP-ADMIT-" + value["job_id"], _job(value))
    leases = {}
    for action in record["actions"]:
        kind = action["kind"]
        if kind == "advance":
            scheduler.advance(action["now"])
        elif kind == "dispatch":
            lease = scheduler.dispatch(action["operation_id"], now=action["now"], agent_id=action.get("agent_id"))
            if lease is not None:
                leases[lease.job_id] = lease
        elif kind in {"complete", "ack_cancel"}:
            lease = leases[action["job_id"]]
            operation = getattr(scheduler, "complete" if kind == "complete" else "acknowledge_cancel")
            operation(action["operation_id"], job_id=action["job_id"], lease=lease, now=action["now"])
        elif kind == "fail":
            lease = leases[action["job_id"]]
            scheduler.fail(action["operation_id"], job_id=action["job_id"], lease=lease, reason=action["reason"], now=action["now"])
        elif kind == "cancel":
            scheduler.request_cancel(action["operation_id"], job_id=action["job_id"], now=action["now"])
        elif kind == "heartbeat":
            lease = leases[action["job_id"]]
            leases[action["job_id"]] = scheduler.heartbeat(action["operation_id"], job_id=action["job_id"], lease=lease, now=action["now"])
        else:
            raise SchedulingError("unknown_action")
    snapshot = scheduler.snapshot()
    actual = {
        "states": {key: value["state"] for key, value in snapshot["jobs"].items()},
        "events": len(snapshot["events"]),
        "available": snapshot["available"],
        "fence": snapshot["fence"],
    }
    if actual != record["expected"]:
        raise SchedulingError("fixture_result_mismatch")
    return {
        "contract": "awr-fair-scheduler@1.0.0",
        "task_revision": 3,
        **actual,
        "execute": False,
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record = load(args.spec), load(args.fixture)
        validate_spec(spec, args.expected_revision)
        result = validate(record)
    except (SchedulingError, KeyError, TypeError, ValueError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

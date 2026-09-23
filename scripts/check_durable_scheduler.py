#!/usr/bin/env python3
"""Offline checker for the AR-0062 scheduler fixture."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.durable_scheduler import Job, Resources, Scheduler, SchedulerError


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchedulerError("malformed JSON") from exc


def validate_spec(spec, revision):
    required = {"schema_version", "specification_id", "version", "normative", "task", "parent", "invariants", "states", "terminal_states", "fairness", "lease", "offline_boundary", "failure_semantics", "limitations", "follow_up", "required_fixture_fields"}
    if set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-durable-fair-scheduler-worker-lease" or spec["version"] != "1.0.0" or spec["normative"] is not True or spec["task"] != {"id": "AR-0062", "revision": 1} or spec["parent"] != {"id": "AR-0061", "revision": 1, "contract": "awr-durable-revision-bound-job"} or revision != 1:
        raise SchedulerError("unsupported or stale specification")
    if spec["offline_boundary"]["execute"] is not False or spec["terminal_states"] != ["succeeded", "failed", "cancelled"]:
        raise SchedulerError("unsafe specification")


def validate(record):
    if set(record) != {"capacity", "limits", "jobs", "operations", "expected"}:
        raise SchedulerError("unknown or missing fixture field")
    capacity = Resources(**record["capacity"])
    limits = record["limits"]
    scheduler = Scheduler(capacity, **limits)
    for item in record["jobs"]:
        item = dict(item)
        resources = Resources(**item.pop("resources", {}))
        for key in ("dependencies",):
            item[key] = tuple(item.get(key, []))
        if "retryable" in item:
            item["retryable"] = frozenset(item["retryable"])
        scheduler.admit("admit-" + item["job_id"], Job(resources=resources, **item))
    for operation in record["operations"]:
        kind = operation["kind"]
        args = dict(operation)
        args.pop("kind")
        if kind == "release":
            scheduler.release_dependencies(**args)
        elif kind == "dispatch":
            scheduler.dispatch(**args)
        elif kind == "complete":
            scheduler.complete(**args)
        elif kind == "fail":
            scheduler.fail(**args)
        elif kind == "expire":
            scheduler.expire(**args)
        elif kind == "cancel":
            scheduler.request_cancel(**args)
        elif kind == "ack_cancel":
            scheduler.acknowledge_cancel(**args)
        else:
            raise SchedulerError("unknown operation")
    actual = {"states": {key: job.state for key, job in sorted(scheduler.jobs.items())}, "events": len(scheduler.events), "available": scheduler.available.__dict__}
    if actual != record["expected"]:
        raise SchedulerError("fixture result mismatch")
    return {"contract": "awr-durable-fair-scheduler-worker-lease@1.0.0", "task_revision": 1, "states": actual["states"], "events": actual["events"], "execute": False, "durable_state": "not_performed", "remote_verification": "unverified"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record = load(args.spec), load(args.fixture)
        validate_spec(spec, args.expected_revision)
        result = validate(record)
    except (SchedulerError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

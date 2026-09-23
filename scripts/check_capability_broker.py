#!/usr/bin/env python3
"""Fail-closed offline checker for the AR-0019 capability broker."""

import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.capability_broker import Admission, Broker, CapabilityBrokerError, digest, privacy
except ModuleNotFoundError:
    from capability_broker import Admission, Broker, CapabilityBrokerError, digest, privacy

CHECKER = "awr-capability-broker-checker/1.0.0"
TOP = {"schema_version", "protocol", "task", "project", "worktree", "session", "grant", "lifecycle", "actions", "evidence"}


class CheckError(ValueError):
    pass


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "normative", "title", "authority", "binding", "capabilities", "enforcement", "lifecycle", "privacy", "limitations"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-capability-broker" or spec["version"] != "1.0.0" or spec["normative"] is not True:
        raise CheckError("unsupported or malformed specification")
    if not isinstance(spec["limitations"], list) or not spec["limitations"] or spec["binding"].get("task_revision") != 1:
        raise CheckError("malformed broker specification")


def validate_trace(trace, spec, expected_revision=1):
    validate_spec(spec)
    if expected_revision != 1 or not isinstance(trace, dict) or set(trace) != TOP or trace["schema_version"] != 1 or trace["protocol"] != {"id": "awr-capability-broker", "version": "1.0.0"}:
        raise CheckError("malformed or stale broker envelope")
    admission = Admission(trace["task"], trace["project"], trace["worktree"], trace["session"], trace["grant"])
    try:
        broker = Broker(admission)
        if trace["lifecycle"] != {"initial": "bound", "final": "active"} or not isinstance(trace["actions"], list) or not trace["actions"]:
            raise CheckError("malformed lifecycle")
        for action in trace["actions"]:
            broker.apply(action)
        if broker.state != "active" or privacy(trace):
            raise CheckError("invalid final or privacy state")
    except (CapabilityBrokerError, KeyError, TypeError) as exc:
        raise CheckError(str(exc)) from exc
    evidence = trace["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"task_revision", "specification_digest", "trace_digest", "action_digest", "action_count", "checker"}:
        raise CheckError("malformed evidence")
    expected = {"task_revision": 1, "specification_digest": digest(spec), "trace_digest": digest({key: trace[key] for key in TOP if key != "evidence"}), "action_digest": broker.result()["action_digest"], "action_count": len(trace["actions"]), "checker": CHECKER}
    if evidence != expected:
        raise CheckError("invalid evidence binding")
    return {"protocol": "awr-capability-broker@1.0.0", "task_revision": 1, "accepted_actions": len(trace["actions"]), "state": broker.state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = validate_trace(load_json(args.trace), load_json(args.spec), args.expected_revision)
    except (CheckError, CapabilityBrokerError, TypeError, KeyError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

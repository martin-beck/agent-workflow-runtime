#!/usr/bin/env python3
"""Fail-closed checker for the offline AR-0031 host enforcement fixture."""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.host_enforcement import Admission, HostEnforcementError, HostRuntime, digest, private

CHECKER = "awr-host-enforcement-checker/1.0.0"
PROTOCOL = {"id": "awr-host-enforcement", "version": "1.0.0"}
SPEC_KEYS = {"schema_version", "specification_id", "version", "normative", "authority", "binding", "lifecycle", "host_policy", "gates", "compatibility", "privacy", "failure_semantics", "limitations"}
TOP_KEYS = {"schema_version", "protocol", "task", "project", "worktree", "admission", "grant", "budgets", "actions", "evidence", "execution"}


class CheckError(ValueError):
    pass


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc


def check_spec(spec):
    if not isinstance(spec, dict) or set(spec) != SPEC_KEYS or spec.get("schema_version") != 1 or spec.get("specification_id") != PROTOCOL["id"] or spec.get("version") != "1.0.0" or spec.get("normative") is not True:
        raise CheckError("unsupported specification")
    if spec["authority"]["coordinator"] != ["task identity", "claims", "revisions", "leases", "durable state"] or spec["failure_semantics"]["mode"] != "fail_closed":
        raise CheckError("authority or fail-closed contract mismatch")


def validate(trace, spec, expected_revision):
    check_spec(spec)
    if not isinstance(trace, dict) or set(trace) != TOP_KEYS or trace["schema_version"] != 1 or trace["protocol"] != PROTOCOL or private(trace):
        raise CheckError("malformed, private, or wrong protocol envelope")
    if trace["task"] != {"id": "AR-0031", "revision": expected_revision}:
        raise CheckError("stale task revision")
    admission = trace["admission"]
    required = {"task_id", "task_revision", "project_key", "project_revision", "worktree_key", "worktree_digest", "session_id", "worker_id", "lease_id", "lease_expires"}
    if set(admission) != required:
        raise CheckError("malformed admission")
    try:
        bound = Admission(**admission).validate()
        runtime = HostRuntime(bound, trace["grant"], trace["budgets"])
    except (HostEnforcementError, TypeError, KeyError) as exc:
        raise CheckError(str(exc)) from exc
    if trace["project"] != {"key": bound.project_key, "revision": bound.project_revision} or trace["worktree"] != {"key": bound.worktree_key, "digest": bound.worktree_digest}:
        raise CheckError("crossed project or worktree binding")
    if trace["execution"] != {"mode": "offline_fixture", "process": "not_performed", "network": "disabled", "coordinator": "not_performed", "live_verification": "unverified"}:
        raise CheckError("external execution claim")
    actions = trace["actions"]
    if not isinstance(actions, list) or not actions:
        raise CheckError("missing action trace")
    for supplied in actions:
        if not isinstance(supplied, dict) or "action_digest" not in supplied:
            raise CheckError("missing action digest")
        claimed = supplied["action_digest"]
        unsigned = dict(supplied); unsigned.pop("action_digest")
        if claimed != digest(unsigned) or supplied.get("sequence") != runtime.sequence + 1:
            raise CheckError("tampered or unordered action")
        try:
            state = runtime.apply(unsigned)
        except (HostEnforcementError, TypeError, KeyError) as exc:
            raise CheckError(str(exc)) from exc
        if supplied.get("state") != state:
            raise CheckError("state evidence mismatch")
    evidence = trace["evidence"]
    expected = {"checker": CHECKER, "task_revision": expected_revision, "specification_digest": digest(spec), "trace_digest": digest(runtime.actions), "final_state": runtime.state, "action_count": len(runtime.actions), "live_verification": "unverified"}
    if evidence != expected:
        raise CheckError("evidence mismatch")
    if runtime.state != "running":
        raise CheckError("fixture must demonstrate fenced recovery to running")
    return {"protocol": "awr-host-enforcement@1.0.0", "task_revision": expected_revision, "actions": len(actions), "final": runtime.state, "live_verification": "unverified"}


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try:
        print(json.dumps(validate(load(args.fixture), load(args.spec), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (CheckError, TypeError, KeyError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

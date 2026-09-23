"""Fail-closed checker for the offline AR-0048 host admission fixture."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.host_admission import Admission, HostAdmissionError, HostRuntime, digest, private
except ModuleNotFoundError:
    from host_admission import Admission, HostAdmissionError, HostRuntime, digest, private

CHECKER = "awr-host-admission-checker/1.0.0"
PROTOCOL = {"id": "awr-host-admission", "version": "1.0.0"}
SPEC_KEYS = {"schema_version", "specification_id", "version", "normative", "authority", "binding", "capability_matrix", "launch_profile", "resource_policy", "lifecycle", "failure_semantics", "offline_boundary", "limitations"}


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise HostAdmissionError("malformed JSON") from exc


def check_spec(spec):
    if not isinstance(spec, dict) or set(spec) != SPEC_KEYS or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-host-admission" or spec.get("version") != "1.0.0" or spec.get("normative") is not True:
        raise HostAdmissionError("unsupported specification")
    if spec["failure_semantics"].get("mode") != "fail_closed" or spec["offline_boundary"].get("network") != "disabled":
        raise HostAdmissionError("unsafe failure or offline boundary")


def check(spec, record, expected_revision=5):
    check_spec(spec)
    required = {"schema_version", "protocol", "task", "project", "worktree", "admission", "host_capabilities", "grant", "profile", "budgets", "actions", "evidence", "execution"}
    if not isinstance(record, dict) or set(record) != required or record["protocol"] != PROTOCOL or record["schema_version"] != 1 or private(record):
        raise HostAdmissionError("malformed, private, or wrong protocol envelope")
    if record["task"] != {"id": "AR-0048", "revision": expected_revision}:
        raise HostAdmissionError("stale task revision")
    admission = Admission(**record["admission"]).validate()
    if record["project"] != {"key": admission.project_key, "revision": admission.project_revision} or record["worktree"] != {"key": admission.worktree_key, "digest": admission.worktree_digest}:
        raise HostAdmissionError("crossed project or worktree binding")
    if record["execution"] != {"mode": "offline_fixture", "process": "not_performed", "network": "disabled", "providers": "not_performed", "coordinator": "not_performed", "live_verification": "unverified"}:
        raise HostAdmissionError("external execution claim")
    runtime = HostRuntime(admission, record["host_capabilities"], record["grant"], record["profile"], record["budgets"])
    for supplied in record["actions"]:
        if not isinstance(supplied, dict) or supplied.get("sequence") != runtime.sequence + 1 or supplied.get("action_digest") != digest({k: v for k, v in supplied.items() if k != "action_digest"}):
            raise HostAdmissionError("tampered or unordered action")
        expected_state = runtime.apply({k: v for k, v in supplied.items() if k not in {"sequence", "state", "action_digest"}})
        if supplied.get("state") != expected_state:
            raise HostAdmissionError("state evidence mismatch")
    evidence = record["evidence"]
    expected = {"checker": CHECKER, "task_revision": expected_revision, "specification_digest": digest(spec), "trace_digest": digest(runtime.actions), "final_state": runtime.state, "action_count": len(runtime.actions), "live_verification": "unverified"}
    if evidence != expected or runtime.state != "running":
        raise HostAdmissionError("evidence mismatch or incomplete recovery")
    return {"checker": CHECKER, "task_revision": expected_revision, "actions": len(runtime.actions), "final_state": runtime.state, "live_verification": "unverified"}


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try:
        print(json.dumps(check(load(args.spec), load(args.fixture), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (HostAdmissionError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

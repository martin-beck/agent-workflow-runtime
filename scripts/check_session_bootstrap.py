#!/usr/bin/env python3
"""Fail-closed checker for the AR-0030 offline session-bootstrap contract."""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.session_bootstrap import Admission, BootstrapError, DIGEST, SessionBootstrap, canonical, digest, private

CHECKER = "awr-session-bootstrap-checker/1.0.0"
PROTOCOL = {"id": "awr-admission-lease-session-bootstrap", "version": "1.0.0"}
ALLOWED_SPEC = {"schema_version", "specification_id", "version", "normative", "authority", "binding", "lifecycle", "gates", "compatibility", "privacy", "failure_semantics", "limitations"}
ALLOWED_RECORD = {"schema_version", "protocol", "task", "project", "worktree", "admission", "gates", "actions", "evidence", "execution"}


def _record_has_private_payload(value):
    """Reject private payloads while allowing the fixed gate vocabulary."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "credentials" and child in {"not_required", "reference_only"}:
                continue
            if re.search(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|personal.?data)", str(key), re.I):
                return True
            if _record_has_private_payload(child):
                return True
        return False
    if isinstance(value, list):
        return any(_record_has_private_payload(child) for child in value)
    return bool(isinstance(value, str) and re.search(r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", value, re.I))


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapError("malformed JSON") from exc


def check_spec(spec):
    if not isinstance(spec, dict) or set(spec) != ALLOWED_SPEC or spec.get("schema_version") != 1 or spec.get("specification_id") != PROTOCOL["id"] or spec.get("version") != "1.0.0" or spec.get("normative") is not True:
        raise BootstrapError("unsupported or unknown specification fields")
    if spec.get("authority", {}).get("coordinator") != ["task identity", "project revision", "claims", "leases", "durable state"]:
        raise BootstrapError("Coordinator authority is not preserved")
    if spec.get("failure_semantics", {}).get("mode") != "fail_closed":
        raise BootstrapError("fail-closed semantics required")
    return True


def _admission(record):
    value = record["admission"]
    required = {"task_id", "task_revision", "project_key", "project_revision", "worktree_key", "worktree_digest", "session_id", "owner_id", "lease_id", "lease_expires", "decision"}
    if set(value) != required or value["decision"] != "admit":
        raise BootstrapError("malformed admission")
    return Admission(**{key: value[key] for key in required if key != "decision"}).validate()


def validate_record(record, spec, expected_revision):
    check_spec(spec)
    if set(record) != ALLOWED_RECORD or record.get("schema_version") != 1 or record.get("protocol") != PROTOCOL:
        raise BootstrapError("malformed record or protocol")
    if _record_has_private_payload(record):
        raise BootstrapError("privacy-bearing record")
    admission = _admission(record)
    if admission.task_id != "AR-0030" or admission.task_revision != expected_revision:
        raise BootstrapError("stale task admission")
    if record["task"] != {"id": admission.task_id, "revision": admission.task_revision}:
        raise BootstrapError("task binding mismatch")
    if record["project"] != {"key": admission.project_key, "revision": admission.project_revision}:
        raise BootstrapError("project binding mismatch")
    if record["worktree"] != {"key": admission.worktree_key, "digest": admission.worktree_digest}:
        raise BootstrapError("worktree binding mismatch")
    if record["execution"] != {"mode": "offline_fixture", "provider": "not_performed", "network": "disabled", "coordinator": "not_performed"}:
        raise BootstrapError("external execution claim")
    gates = record["gates"]
    if gates != {"capability": "declared", "credentials": "not_required", "network": "disabled", "human_approval": "not_required"}:
        raise BootstrapError("invalid gate declaration")
    actions = record["actions"]
    if not isinstance(actions, list) or not actions:
        raise BootstrapError("missing actions")
    runtime = SessionBootstrap(admission)
    allowed = {"action_id", "operation", "sequence", "task_revision", "project_key", "project_revision", "worktree_key", "worktree_digest", "session_id", "owner_id", "lease_id", "time", "state", "evidence_digest", "action_digest"}
    for supplied in actions:
        if set(supplied) - allowed or "evidence_digest" not in supplied and supplied["operation"] in {"checkpoint", "interrupt", "fail"}:
            raise BootstrapError("unknown or incomplete action")
        before = dict(supplied); claimed = before.pop("action_digest", None)
        if claimed != digest(before):
            raise BootstrapError("action digest mismatch")
        state = runtime.apply(supplied["action_id"], supplied["operation"],
                              task_revision=supplied["task_revision"],
                              project_key=supplied["project_key"],
                              project_revision=supplied["project_revision"],
                              worktree_key=supplied["worktree_key"],
                              worktree_digest=supplied["worktree_digest"],
                              session_id=supplied["session_id"], owner_id=supplied["owner_id"],
                              lease_id=supplied["lease_id"], now=supplied["time"],
                              evidence_digest=supplied.get("evidence_digest"))
        if supplied["sequence"] != runtime.sequence or supplied["state"] != state:
            raise BootstrapError("action ordering or state mismatch")
    if runtime.state != "interrupted" or record["evidence"].get("checker") != CHECKER:
        raise BootstrapError("fixture must end at acknowledged interruption")
    evidence = record["evidence"]
    if set(evidence) != {"checker", "specification_digest", "trace_digest", "live_verification"} or evidence["specification_digest"] != digest(spec) or evidence["trace_digest"] != digest(actions) or evidence["live_verification"] != "unverified":
        raise BootstrapError("evidence mismatch")
    return {"protocol": "awr-session-bootstrap@1.0.0", "task_revision": expected_revision, "actions": len(actions), "final": runtime.state, "live_verification": "unverified"}


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try:
        print(json.dumps(validate_record(load(args.fixture), load(args.spec), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (BootstrapError, KeyError, TypeError, AttributeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed offline model for the AR-0061 durable job contract."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-durable-revision-bound-job", "version": "1.0.0"}
TASK = {"id": "AR-0061", "revision": 1}
STATES = ("submitted", "admitted", "queued", "running", "awaiting_human_gate", "checkpointed", "cancelling", "succeeded", "failed", "cancelled")
TERMINAL = {"succeeded", "failed", "cancelled"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|command|network|personal.?data", re.I)
SAFE_KEYS = {"network", "provider", "llm", "live_service", "durable_state", "execute", "status", "verification", "reason"}
SAFE_VALUES = {"network", "provider", "llm", "durable_state", "not_performed", "disabled", "unverified", "not_decided"}


class JobError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return all((str(k) in SAFE_KEYS or not PRIVATE.search(str(k))) and _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or (PRIVATE.search(value) and value not in SAFE_VALUES)))


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise JobError("invalid " + name)


def _exact_keys(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise JobError("invalid " + name)


def _binding(job, key):
    return job[key] == {"id": "AR-0061", "revision": 1} if key == "task" else job[key]


def validate(record, expected_revision=1, expected_worktree="agent-workflow-runtime-0061"):
    required = {"schema_version", "protocol", "task", "project", "worktree", "session", "job", "events", "terminal", "evidence"}
    if not isinstance(record, dict) or set(record) != required or not _safe(record):
        raise JobError("unknown, missing, or privacy-bearing field")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != TASK or expected_revision != 1:
        raise JobError("unsupported or stale task binding")
    if record["project"] != {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64}:
        raise JobError("invalid project binding")
    if record["worktree"] != {"key": expected_worktree, "digest": "sha256:" + "2" * 64}:
        raise JobError("invalid worktree binding")
    _exact_keys(record["session"], {"id"}, "session")
    if not re.fullmatch(r"SES-AR0061-[A-Z0-9-]{1,48}", record["session"]["id"]):
        raise JobError("invalid session binding")
    job = record["job"]
    sections = {"objective", "inputs", "dependencies", "capabilities", "adapters", "acceptance", "budget", "deadline", "retry", "priority", "tenancy", "privacy", "artifacts", "human_gates", "cancellation", "idempotency", "provenance"}
    if set(job) != sections or job["objective"] != {"summary": "validate the durable revision-bound job contract", "digest": "sha256:" + "3" * 64}:
        raise JobError("invalid objective binding")
    if job["inputs"] != {"payload_digest": "sha256:" + "4" * 64, "count": 1} or job["dependencies"] != {"task_ids": [], "digests": []}:
        raise JobError("invalid inputs or dependencies")
    if job["capabilities"] != {"requested": ["read", "edit", "test"], "denied": ["network", "provider", "llm", "durable_state"]}:
        raise JobError("invalid capabilities")
    if job["adapters"] != [{"id": "offline-reference", "version": "1.0.0", "digest": "sha256:" + "5" * 64}]:
        raise JobError("invalid adapters")
    if job["acceptance"] != {"criteria": ["focused_tests_pass", "full_tests_pass"], "criteria_digest": "sha256:" + "6" * 64}:
        raise JobError("invalid acceptance")
    if job["budget"] != {"max_attempts": 3, "max_events": 32, "max_runtime_seconds": 900}:
        raise JobError("invalid budget")
    if job["deadline"] != {"kind": "absolute", "at": "2026-12-31T23:59:59Z"}:
        raise JobError("invalid deadline")
    if job["retry"] != {"policy": "bounded-exponential", "max_attempts": 3, "retryable": ["worker_lost", "transient_unavailable"]}:
        raise JobError("invalid retry policy")
    if job["priority"] != {"class": "normal", "value": 50} or job["tenancy"] != {"tenant": "agent-workflow-runtime", "isolation": "exclusive-worktree"}:
        raise JobError("invalid priority or tenancy")
    if job["privacy"] != {"classification": "public-safe-digest-only", "raw_payload": "forbidden"}:
        raise JobError("invalid privacy policy")
    if job["artifacts"] != {"allowed": ["digest", "test_result", "checkpoint"], "retention": "until-terminal"}:
        raise JobError("invalid artifacts policy")
    if job["human_gates"] != {"required": ["acceptance-review"], "decision": "not_decided", "input_digest": "sha256:" + "7" * 64}:
        raise JobError("invalid human gate")
    if job["cancellation"] != {"mode": "cooperative", "ack_required": True, "deadline_seconds": 30}:
        raise JobError("invalid cancellation policy")
    if job["idempotency"] != {"key": "JOB-AR0061-REFERENCE", "replay": "same_digest_same_result", "conflict": "reject"}:
        raise JobError("invalid idempotency policy")
    if job["provenance"]["input_digest"] != "sha256:" + "4" * 64 or not DIGEST.fullmatch(job["provenance"]["contract_digest"]) or job["provenance"]["parent_revision"] != 1 or set(job["provenance"]) != {"input_digest", "contract_digest", "parent_revision"}:
        raise JobError("invalid provenance binding")
    events = record["events"]
    if not isinstance(events, list) or not events or len(events) > job["budget"]["max_events"]:
        raise JobError("invalid event count")
    allowed = {("submitted", "admitted"), ("admitted", "queued"), ("queued", "running"), ("running", "awaiting_human_gate"), ("awaiting_human_gate", "running"), ("running", "checkpointed"), ("checkpointed", "running"), ("running", "cancelling"), ("cancelling", "cancelled"), ("running", "succeeded"), ("running", "failed"), ("queued", "cancelled"), ("admitted", "cancelled")}
    state = "submitted"; seen = set(); previous = "sha256:" + "0" * 64
    for index, event in enumerate(events, 1):
        fields = {"event_id", "sequence", "from", "to", "task_revision", "session_id", "previous_digest", "evidence_digest"}
        if not isinstance(event, dict) or set(event) != fields or event["sequence"] != index or event["task_revision"] != 1 or event["session_id"] != record["session"]["id"]:
            raise JobError("invalid event binding or sequence")
        if event["event_id"] in seen or (event["from"], event["to"]) not in allowed or event["from"] != state or event["previous_digest"] != previous:
            raise JobError("duplicate, reordered, or invalid transition")
        _digest(event["evidence_digest"], "event evidence digest")
        unsigned = dict(event); unsigned.pop("evidence_digest")
        if event["evidence_digest"] != digest(unsigned):
            raise JobError("tampered event evidence")
        seen.add(event["event_id"]); state = event["to"]; previous = event["evidence_digest"]
    if state not in TERMINAL:
        raise JobError("trace is not terminal")
    terminal = {"state": state, "execute": False, "network": "disabled", "provider": "not_performed", "llm": "not_performed", "live_service": "not_performed", "durable_state": "not_performed", "human_gate": "not_decided", "remote_verification": "unverified"}
    if record["terminal"] != terminal:
        raise JobError("unsafe terminal projection")
    evidence = record["evidence"]
    _exact_keys(evidence, {"checker", "task_revision", "contract_digest", "record_digest"}, "evidence")
    if evidence["checker"] != "awr-durable-revision-bound-job-checker/1.0.0" or evidence["task_revision"] != 1:
        raise JobError("invalid evidence envelope")
    _digest(evidence["contract_digest"], "contract digest"); _digest(evidence["record_digest"], "record digest")
    if job["provenance"]["contract_digest"] != evidence["contract_digest"]:
        raise JobError("provenance contract mismatch")
    if evidence["record_digest"] != digest({k: v for k, v in record.items() if k != "evidence"}):
        raise JobError("record digest mismatch")
    return {"contract": "awr-durable-revision-bound-job@1.0.0", "task_revision": 1, "state": state, "events": len(events), "execute": False, "human_gate": "not_decided", "durable_state": "not_performed", "remote_verification": "unverified"}

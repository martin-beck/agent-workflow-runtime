#!/usr/bin/env python3
"""Deterministic, file-backed offline model for the AR-0029 Coordinator boundary."""

import hashlib
import json
import os
import re
import tempfile
from copy import deepcopy

PROTOCOL = {"id": "awr-coordinator-live-state", "version": "1.0.0"}
GENESIS = "sha256:" + "0" * 64
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDS = {
    "task": re.compile(r"^AR-[0-9]{4}$"), "session": re.compile(r"^SES-[A-Z0-9-]{1,63}$"),
    "owner": re.compile(r"^WRK-[A-Z0-9-]{1,63}$"), "lease": re.compile(r"^LSE-[A-Z0-9-]{1,63}$"),
    "operation": re.compile(r"^OP-[A-Z0-9-]{1,63}$"),
}
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|personal.?data)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)


class CoordinatorError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value) if not isinstance(value, bytes) else value).hexdigest()


def _private(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(k)) or _private(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_private(v) for v in value)
    return isinstance(value, str) and bool(PRIVATE_VALUE.search(value))


def _id(value, kind):
    if not isinstance(value, str) or not IDS[kind].fullmatch(value):
        raise CoordinatorError("invalid " + kind)


class CoordinatorHarness:
    """A local authority-shaped harness; it never contacts or mutates Coordinator."""

    def __init__(self, path=None, *, task_revision=3, now=None):
        self.path = path
        self.now = now
        self.data = self._load() if path and os.path.exists(path) else {
            "schema_version": 1, "protocol": PROTOCOL,
            "task": {"id": "AR-0029", "revision": task_revision, "status": "open", "owner": "", "lease": "", "claim_expires": ""},
            "project": {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64},
            "worktree": {"key": "agent-workflow-runtime-0029", "digest": "sha256:" + "2" * 64},
            "session_id": "", "events": [], "operations": {}, "head_digest": GENESIS,
        }
        self._validate_document()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as stream:
                return json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise CoordinatorError("malformed durable document") from exc

    def _persist(self):
        if not self.path:
            return
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, temporary = tempfile.mkstemp(prefix=".awr-state-", dir=directory, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.data, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def _validate_document(self):
        if self.data.get("schema_version") != 1 or self.data.get("protocol") != PROTOCOL:
            raise CoordinatorError("unsupported document")
        task = self.data.get("task", {})
        if task.get("id") != "AR-0029" or not isinstance(task.get("revision"), int) or task["revision"] < 3:
            raise CoordinatorError("invalid task identity")
        if self.data.get("project", {}).get("key") != "agent-workflow-runtime" or self.data.get("worktree", {}).get("key") != "agent-workflow-runtime-0029":
            raise CoordinatorError("crossed project or worktree")
        previous, seen = GENESIS, set()
        for event in self.data.get("events", []):
            if event.get("previous_digest") != previous or event.get("operation_id") in seen:
                raise CoordinatorError("broken or replayed event chain")
            body = dict(event); actual = body.pop("event_digest", None)
            if actual != digest(body) or _private(event):
                raise CoordinatorError("invalid event digest or privacy")
            previous, seen = actual, seen | {event["operation_id"]}
        if self.data.get("head_digest") != previous:
            raise CoordinatorError("head digest mismatch")

    def _common(self, op, expected_revision, session, owner, lease):
        task = self.data["task"]
        if expected_revision != task["revision"]: raise CoordinatorError("stale revision")
        _id(session, "session"); _id(owner, "owner"); _id(lease, "lease")
        if task["status"] != "in_progress" or task["owner"] != owner or task["lease"] != lease or self.data["session_id"] != session:
            raise CoordinatorError("lease or session fence mismatch")
        if self.now is not None and task["claim_expires"] <= self.now:
            raise CoordinatorError("expired lease")

    def _apply(self, operation_id, kind, body, *, increment=True):
        _id(operation_id, "operation")
        old = self.data["operations"].get(operation_id)
        fingerprint = digest({"kind": kind, **body})
        if old:
            if old["fingerprint"] != fingerprint: raise CoordinatorError("changed replay")
            return deepcopy(old["result"])
        event = {"sequence": len(self.data["events"]) + 1, "operation_id": operation_id, "kind": kind, **body, "previous_digest": self.data["head_digest"]}
        event["event_digest"] = digest(event)
        self.data["events"].append(event); self.data["head_digest"] = event["event_digest"]
        result = {"task_revision": self.data["task"]["revision"], "event_digest": event["event_digest"], "disposition": "accepted"}
        self.data["operations"][operation_id] = {"fingerprint": fingerprint, "result": result}
        if increment: self.data["task"]["revision"] += 1
        self._persist()
        return deepcopy(result)

    def claim(self, operation_id, *, expected_revision, session, owner, lease, claim_expires):
        task = self.data["task"]
        replay_body = {"task_revision": expected_revision, "session_id": session, "owner": owner, "lease": lease, "claim_expires": claim_expires}
        if operation_id in self.data["operations"]:
            return self._apply(operation_id, "claim", replay_body)
        if expected_revision != task["revision"] or task["status"] != "open" or task["owner"] or not isinstance(claim_expires, str) or not claim_expires.endswith("+00:00") or (self.now is not None and claim_expires <= self.now):
            raise CoordinatorError("claim precondition failed")
        _id(session, "session"); _id(owner, "owner"); _id(lease, "lease")
        result = self._apply(operation_id, "claim", replay_body)
        self.data["task"].update(status="in_progress", owner=owner, lease=lease, claim_expires=claim_expires); self.data["session_id"] = session
        self._persist(); return result

    def heartbeat(self, operation_id, *, expected_revision, session, owner, lease, claim_expires):
        self._common("heartbeat", expected_revision, session, owner, lease)
        if not isinstance(claim_expires, str) or not claim_expires.endswith("+00:00"): raise CoordinatorError("invalid lease expiry")
        result = self._apply(operation_id, "heartbeat", {"task_revision": expected_revision, "session_id": session, "owner": owner, "lease": lease, "claim_expires": claim_expires}, increment=False)
        self.data["task"]["claim_expires"] = claim_expires; self._persist(); return result

    def state_event(self, operation_id, *, expected_revision, session, owner, lease, event_type, evidence_digest):
        self._common("state_event", expected_revision, session, owner, lease)
        if event_type not in {"checkpoint", "observation", "interrupted"} or not DIGEST.fullmatch(evidence_digest): raise CoordinatorError("invalid state event")
        return self._apply(operation_id, "state_event", {"task_revision": expected_revision, "session_id": session, "owner": owner, "lease": lease, "event_type": event_type, "evidence_digest": evidence_digest})

    def release(self, operation_id, *, expected_revision, session, owner, lease, status):
        self._common("release", expected_revision, session, owner, lease)
        if status not in {"open", "done", "blocked"}: raise CoordinatorError("unauthorized status")
        result = self._apply(operation_id, "release", {"task_revision": expected_revision, "session_id": session, "owner": owner, "lease": lease, "status": status})
        self.data["task"].update(status=status, owner="", lease="", claim_expires=""); self.data["session_id"] = ""; self._persist(); return result

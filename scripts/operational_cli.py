#!/usr/bin/env python3
"""Offline state model for the AR-0024 operational CLI contract."""

import hashlib
import json
import re

TASK = {"id": "AR-0024", "revision": 3}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|email|personal.?data|raw.?output|executable|shell", re.I)

class OperationalError(ValueError):
    pass

TRANSITIONS = {
    ("new", "setup"): "configured", ("configured", "run"): "running",
    ("running", "observe"): "observed", ("observed", "interrupt"): "interrupted",
    ("interrupted", "resume"): "running", ("observed", "diagnose"): "diagnosed",
    ("running", "diagnose"): "diagnosed", ("diagnosed", "shutdown"): "stopped",
}
PAYLOAD_FIELDS = {
    "setup": {"config_digest", "profile", "timeout_seconds", "max_events", "max_output_bytes", "setup_status"},
    "run": {"run_digest", "run_status"},
    "observe": {"observation_digest", "observation_status"},
    "interrupt": {"checkpoint_digest", "interrupt_status"},
    "resume": {"checkpoint_digest", "resume_status"},
    "diagnose": {"diagnosis_digest", "diagnosis_status"},
    "shutdown": {"shutdown_status", "durable_state", "remote_verification"},
}
AUTHORITIES = {key: "runtime" for key in PAYLOAD_FIELDS}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

def safe(value):
    if isinstance(value, dict):
        return all(not PRIVATE.search(str(k)) and safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 128 or PRIVATE.search(value)))

class OperationalState:
    def __init__(self, revision, project, worktree_digest, session_id):
        self.revision, self.project = revision, project
        self.worktree_digest, self.session_id = worktree_digest, session_id
        self.state, self.checkpoint = "new", None
        self.events, self.evidence = set(), set()

    def apply(self, event):
        required = {"event_id", "sequence", "command", "authority", "state", "next_state", "task_revision", "project", "worktree_digest", "session_id", "invocation", "payload", "evidence_digest", "disposition"}
        if not isinstance(event, dict) or set(event) != required:
            raise OperationalError("malformed command event")
        if event["event_id"] in self.events or event["evidence_digest"] in self.evidence:
            raise OperationalError("replayed event or evidence")
        if event["task_revision"] != self.revision or event["project"] != self.project or event["worktree_digest"] != self.worktree_digest or event["session_id"] != self.session_id:
            raise OperationalError("stale or crossed binding")
        if event["state"] != self.state or event["authority"] != "runtime" or event["disposition"] != "observed":
            raise OperationalError("invalid authority or state observation")
        if not isinstance(event["invocation"], int) or event["invocation"] < 1 or event["invocation"] > 1000 or not DIGEST.fullmatch(event["evidence_digest"]):
            raise OperationalError("invalid invocation or evidence digest")
        payload = event["payload"]
        command = event["command"]
        if command not in PAYLOAD_FIELDS or set(payload) != PAYLOAD_FIELDS[command] or (self.state, command) not in TRANSITIONS or not safe(event):
            raise OperationalError("unknown, unsafe, or unauthorized command")
        for key, value in payload.items():
            if key.endswith("digest") and (not isinstance(value, str) or not DIGEST.fullmatch(value)):
                raise OperationalError("malformed digest")
        self._validate(command, payload)
        if command == "interrupt": self.checkpoint = payload["checkpoint_digest"]
        if command == "resume" and payload["checkpoint_digest"] != self.checkpoint:
            raise OperationalError("checkpoint mismatch")
        self.state = TRANSITIONS[(self.state, command)]
        self.events.add(event["event_id"]); self.evidence.add(event["evidence_digest"])
        return self.state

    def _validate(self, command, payload):
        if command == "setup": valid = payload["profile"] == "offline" and payload["setup_status"] == "configured" and all(isinstance(payload[key], int) and 0 < payload[key] <= limit for key, limit in (("timeout_seconds", 86400), ("max_events", 1000), ("max_output_bytes", 1000000)))
        elif command == "run": valid = payload["run_status"] == "started"
        elif command == "observe": valid = payload["observation_status"] == "observed"
        elif command == "interrupt": valid = payload["interrupt_status"] == "acknowledged"
        elif command == "resume": valid = payload["resume_status"] == "resumed"
        elif command == "diagnose": valid = payload["diagnosis_status"] == "observed"
        else: valid = payload["shutdown_status"] == "acknowledged" and payload["durable_state"] == "not_performed" and payload["remote_verification"] == "unverified"
        if not valid: raise OperationalError("invalid command status")

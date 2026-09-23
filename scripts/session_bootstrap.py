#!/usr/bin/env python3
"""Offline admission, lease, and revision-bound session bootstrap model.

This is an authority-shaped harness only.  It never contacts Coordinator,
starts a worker, opens a provider, or writes durable coordination state.
"""

from dataclasses import dataclass, field
import hashlib
import json
import re


class BootstrapError(ValueError):
    pass


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDS = {
    "task": re.compile(r"^AR-[0-9]{4}$"),
    "session": re.compile(r"^SES-[A-Z0-9-]{1,63}$"),
    "owner": re.compile(r"^WRK-[A-Z0-9-]{1,63}$"),
    "lease": re.compile(r"^LSE-[A-Z0-9-]{1,63}$"),
    "action": re.compile(r"^ACT-[A-Z0-9-]{1,63}$"),
}
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|personal.?data)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)


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


@dataclass(frozen=True)
class Admission:
    task_id: str
    task_revision: int
    project_key: str
    project_revision: str
    worktree_key: str
    worktree_digest: str
    session_id: str
    owner_id: str
    lease_id: str
    lease_expires: int

    def validate(self):
        if not IDS["task"].fullmatch(self.task_id) or not isinstance(self.task_revision, int) or isinstance(self.task_revision, bool) or self.task_revision < 1:
            raise BootstrapError("invalid task binding")
        if not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", self.project_key) or not DIGEST.fullmatch(self.project_revision):
            raise BootstrapError("invalid project binding")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", self.worktree_key) or not DIGEST.fullmatch(self.worktree_digest):
            raise BootstrapError("invalid worktree binding")
        for kind, value in (("session", self.session_id), ("owner", self.owner_id), ("lease", self.lease_id)):
            if not IDS[kind].fullmatch(value):
                raise BootstrapError("invalid " + kind + " binding")
        if not isinstance(self.lease_expires, int) or isinstance(self.lease_expires, bool) or self.lease_expires < 1:
            raise BootstrapError("invalid lease expiry")
        return self


@dataclass
class SessionBootstrap:
    admission: Admission
    now: int = 0
    state: str = "admitted"
    sequence: int = 0
    seen: set = field(default_factory=set)
    actions: list = field(default_factory=list)

    def __post_init__(self):
        self.admission.validate()

    def apply(self, action_id, operation, *, task_revision, project_key, project_revision,
              worktree_key, worktree_digest, session_id, owner_id, lease_id, now,
              evidence_digest=None):
        if not IDS["action"].fullmatch(action_id) or action_id in self.seen:
            raise BootstrapError("malformed or replayed action")
        binding = (task_revision, project_key, project_revision, worktree_key,
                   worktree_digest, session_id, owner_id, lease_id)
        expected = (self.admission.task_revision, self.admission.project_key,
                    self.admission.project_revision, self.admission.worktree_key,
                    self.admission.worktree_digest, self.admission.session_id,
                    self.admission.owner_id, self.admission.lease_id)
        if binding != expected:
            raise BootstrapError("exact admission binding required")
        if not isinstance(now, int) or isinstance(now, bool) or now < self.now:
            raise BootstrapError("non-monotonic time")
        if now >= self.admission.lease_expires:
            raise BootstrapError("lease expired")
        if operation in {"checkpoint", "interrupt", "fail"} and not DIGEST.fullmatch(str(evidence_digest)):
            raise BootstrapError("digest-only evidence required")
        transitions = {
            ("admitted", "bootstrap"): "active",
            ("active", "checkpoint"): "active",
            ("active", "interrupt"): "interrupted",
            ("active", "fail"): "failed",
        }
        target = transitions.get((self.state, operation))
        if target is None:
            raise BootstrapError("invalid bootstrap transition")
        self.state = target
        self.now = now
        self.sequence += 1
        action = {"action_id": action_id, "operation": operation, "sequence": self.sequence,
                  "task_revision": task_revision, "project_key": project_key,
                  "project_revision": project_revision, "worktree_key": worktree_key,
                  "worktree_digest": worktree_digest, "session_id": session_id,
                  "owner_id": owner_id, "lease_id": lease_id, "time": now,
                  "state": self.state}
        if evidence_digest is not None:
            action["evidence_digest"] = evidence_digest
        action["action_digest"] = digest(action)
        self.actions.append(action)
        self.seen.add(action_id)
        return self.state


def private(value):
    return _private(value)

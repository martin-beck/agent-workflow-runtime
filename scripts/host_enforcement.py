#!/usr/bin/env python3
"""Deterministic, offline model for the AR-0031 host enforcement boundary."""

from dataclasses import dataclass, field
import hashlib
import json
import re


class HostEnforcementError(ValueError):
    pass


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = {
    "session": re.compile(r"^SES-[A-Z0-9-]{1,63}$"),
    "worker": re.compile(r"^WRK-[A-Z0-9-]{1,63}$"),
    "lease": re.compile(r"^LSE-[A-Z0-9-]{1,63}$"),
    "action": re.compile(r"^ACT-[A-Z0-9-]{1,63}$"),
}
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|environment", re.I)
SHELL = re.compile(r"[|;&<>`$()]|\n|\r")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _private(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(k)) or _private(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_private(v) for v in value)
    return isinstance(value, str) and bool(PRIVATE.search(value))


def private(value):
    return _private(value)


@dataclass(frozen=True)
class Admission:
    task_id: str
    task_revision: int
    project_key: str
    project_revision: str
    worktree_key: str
    worktree_digest: str
    session_id: str
    worker_id: str
    lease_id: str
    lease_expires: int

    def validate(self):
        if self.task_id != "AR-0031" or not isinstance(self.task_revision, int) or isinstance(self.task_revision, bool) or self.task_revision < 1:
            raise HostEnforcementError("invalid task admission")
        if not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", self.project_key) or not DIGEST.fullmatch(self.project_revision):
            raise HostEnforcementError("invalid project binding")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", self.worktree_key) or not DIGEST.fullmatch(self.worktree_digest):
            raise HostEnforcementError("invalid worktree binding")
        for kind, value in (("session", self.session_id), ("worker", self.worker_id), ("lease", self.lease_id)):
            if not ID[kind].fullmatch(value):
                raise HostEnforcementError("invalid " + kind + " binding")
        if not isinstance(self.lease_expires, int) or isinstance(self.lease_expires, bool) or self.lease_expires < 1:
            raise HostEnforcementError("invalid lease expiry")
        return self


@dataclass
class HostRuntime:
    admission: Admission
    grant: dict
    budgets: dict
    state: str = "admitted"
    now: int = 0
    sequence: int = 0
    seen: set = field(default_factory=set)
    actions: list = field(default_factory=list)

    def __post_init__(self):
        self.admission.validate()
        if set(self.grant) != {"capabilities", "tools"} or not isinstance(self.grant["capabilities"], list) or not isinstance(self.grant["tools"], dict):
            raise HostEnforcementError("malformed capability grant")
        if not set(self.grant["capabilities"]).issubset({"read", "edit", "test"}) or len(set(self.grant["capabilities"])) != len(self.grant["capabilities"]):
            raise HostEnforcementError("invalid capabilities")
        if set(self.budgets) != {"cpu_ms", "memory_mb", "disk_mb", "network_bytes", "processes", "depth", "wall_ms"} or any(not isinstance(v, int) or isinstance(v, bool) or v < (0 if key == "network_bytes" else 1) for key, v in self.budgets.items()):
            raise HostEnforcementError("invalid resource budget")

    def _binding(self, action):
        expected = {"task_revision": self.admission.task_revision, "project_key": self.admission.project_key,
                    "project_revision": self.admission.project_revision, "worktree_key": self.admission.worktree_key,
                    "worktree_digest": self.admission.worktree_digest, "session_id": self.admission.session_id,
                    "worker_id": self.admission.worker_id, "lease_id": self.admission.lease_id}
        if {key: action.get(key) for key in expected} != expected:
            raise HostEnforcementError("exact admission binding required")

    def _command(self, action):
        command = action.get("command")
        if not isinstance(command, list) or not command or len(command) > 8 or any(not isinstance(arg, str) or not arg or len(arg) > 128 or SHELL.search(arg) for arg in command):
            raise HostEnforcementError("bounded argv command required")
        capability = action.get("capability")
        if capability not in self.grant["capabilities"]:
            raise HostEnforcementError("capability not granted")
        tool = action.get("tool")
        if not isinstance(tool, str) or tool not in self.grant["tools"] or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", self.grant["tools"][tool]):
            raise HostEnforcementError("tool not granted with bounded version")

    def apply(self, action):
        if not isinstance(action, dict) or action.get("id") in self.seen or not ID["action"].fullmatch(str(action.get("id"))):
            raise HostEnforcementError("malformed or replayed action")
        self._binding(action)
        if not isinstance(action.get("time"), int) or isinstance(action["time"], bool) or action["time"] < self.now or action["time"] >= self.admission.lease_expires:
            raise HostEnforcementError("expired or non-monotonic lease time")
        operation = action.get("operation")
        if operation in {"start", "started", "resumed"}:
            self._command(action)
            observation = action.get("observation")
            if not isinstance(observation, dict) or set(observation) != {"cpu_ms", "memory_mb", "disk_mb", "network_bytes", "processes", "depth", "wall_ms", "tree_complete", "terminated"}:
                raise HostEnforcementError("complete host observation required")
            if any(not isinstance(observation[k], int) or isinstance(observation[k], bool) or observation[k] < 0 for k in self.budgets) or any(observation[k] > self.budgets[k] for k in self.budgets) or observation["tree_complete"] is not True:
                raise HostEnforcementError("resource or process boundary exceeded")
        if operation == "interrupt" and self.state != "running":
            raise HostEnforcementError("invalid interruption")
        if operation == "ack_interrupt" and (self.state != "interrupting" or action.get("acknowledged") is not True or action.get("terminated") is not True):
            raise HostEnforcementError("interrupt acknowledgement required")
        transitions = {("admitted", "start"): "starting", ("starting", "started"): "running", ("running", "interrupt"): "interrupting", ("interrupting", "ack_interrupt"): "interrupted", ("running", "complete"): "completed", ("running", "timeout"): "timed_out", ("starting", "fail"): "failed", ("running", "fail"): "failed", ("interrupted", "recover"): "recovering", ("failed", "recover"): "recovering", ("timed_out", "recover"): "recovering", ("recovering", "resumed"): "running"}
        target = transitions.get((self.state, operation))
        if target is None:
            raise HostEnforcementError("invalid lifecycle transition")
        if operation == "recover":
            if action.get("new_worker_id") == self.admission.worker_id or action.get("new_lease_id") == self.admission.lease_id or not DIGEST.fullmatch(str(action.get("checkpoint_digest"))):
                raise HostEnforcementError("recovery must fence old lease and use checkpoint")
            self.admission = Admission(self.admission.task_id, self.admission.task_revision, self.admission.project_key, self.admission.project_revision, self.admission.worktree_key, self.admission.worktree_digest, self.admission.session_id, action["new_worker_id"], action["new_lease_id"], action["new_lease_expires"]).validate()
        elif operation == "resumed" and (action.get("worker_id") != self.admission.worker_id or action.get("lease_id") != self.admission.lease_id):
            raise HostEnforcementError("fenced worker cannot resume")
        self.state, self.now = target, action["time"]
        self.sequence += 1
        self.seen.add(action["id"])
        recorded = dict(action); recorded["sequence"] = self.sequence; recorded["state"] = self.state; recorded["action_digest"] = digest(recorded)
        self.actions.append(recorded)
        return self.state

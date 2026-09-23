"""Deterministic offline AR-0048 host admission and enforcement model."""

from dataclasses import dataclass, field
import hashlib
import json
import re


class HostAdmissionError(ValueError):
    pass


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
SHELL = re.compile(r"[|;&<>`$()]|\n|\r")
CAPABILITIES = {"process_launch", "filesystem_isolation", "resource_limits", "process_tree_cleanup", "network_isolation", "cancellation"}
TOOLS = {"read", "edit", "test"}
OBSERVATION_KEYS = {"cpu_ms", "memory_mb", "disk_mb", "network_bytes", "processes", "depth", "wall_ms", "tree_complete", "terminated"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _private(value):
    if isinstance(value, dict):
        return any(re.search(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output", str(k), re.I) or _private(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_private(v) for v in value)
    return isinstance(value, str) and bool(re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I))


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
        if self.task_id != "AR-0048" or self.task_revision != 5:
            raise HostAdmissionError("task revision must be AR-0048 revision 5")
        if not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", self.project_key) or not DIGEST.fullmatch(self.project_revision):
            raise HostAdmissionError("invalid project binding")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", self.worktree_key) or not DIGEST.fullmatch(self.worktree_digest):
            raise HostAdmissionError("invalid worktree binding")
        if any(not isinstance(v, str) or not IDENT.fullmatch(v) for v in (self.session_id, self.worker_id, self.lease_id)):
            raise HostAdmissionError("invalid session, worker, or lease binding")
        if not isinstance(self.lease_expires, int) or isinstance(self.lease_expires, bool) or self.lease_expires < 1:
            raise HostAdmissionError("invalid lease expiry")
        return self


@dataclass
class HostRuntime:
    admission: Admission
    capabilities: dict
    grant: dict
    profile: dict
    budgets: dict
    state: str = "admitted"
    now: int = 0
    sequence: int = 0
    seen: set = field(default_factory=set)
    actions: list = field(default_factory=list)

    def __post_init__(self):
        self.admission.validate()
        if set(self.capabilities) != CAPABILITIES or any(value is not True for value in self.capabilities.values()):
            raise HostAdmissionError("unsupported host capability")
        if set(self.grant) != {"capabilities", "tools"} or not isinstance(self.grant["capabilities"], list) or not isinstance(self.grant["tools"], dict):
            raise HostAdmissionError("malformed least-privilege grant")
        if not self.grant["capabilities"] or not set(self.grant["capabilities"]).issubset(TOOLS) or len(set(self.grant["capabilities"])) != len(self.grant["capabilities"]):
            raise HostAdmissionError("invalid capability grant")
        if set(self.profile) != {"argv_only", "inherit_environment", "privilege_escalation", "network", "filesystem"} or self.profile != {"argv_only": True, "inherit_environment": False, "privilege_escalation": False, "network": "deny", "filesystem": {"read": "worktree", "write": "worktree"}}:
            raise HostAdmissionError("unsafe launch profile")
        if set(self.budgets) != {"cpu_ms", "memory_mb", "disk_mb", "network_bytes", "processes", "depth", "wall_ms"} or any(not isinstance(v, int) or isinstance(v, bool) or v < (0 if k == "network_bytes" else 1) for k, v in self.budgets.items()):
            raise HostAdmissionError("invalid resource budget")

    def _common(self, action):
        expected = {"task_revision": self.admission.task_revision, "project_key": self.admission.project_key, "project_revision": self.admission.project_revision, "worktree_key": self.admission.worktree_key, "worktree_digest": self.admission.worktree_digest, "session_id": self.admission.session_id, "worker_id": self.admission.worker_id, "lease_id": self.admission.lease_id}
        if {key: action.get(key) for key in expected} != expected:
            raise HostAdmissionError("exact admission binding required")
        if not isinstance(action.get("time"), int) or isinstance(action["time"], bool) or action["time"] < self.now or action["time"] >= self.admission.lease_expires:
            raise HostAdmissionError("expired or non-monotonic lease time")

    def _launch(self, action):
        if action.get("capability") not in self.grant["capabilities"]:
            raise HostAdmissionError("capability not granted")
        command = action.get("argv")
        if not isinstance(command, list) or not command or len(command) > 8 or any(not isinstance(arg, str) or not arg or len(arg) > 128 or SHELL.search(arg) for arg in command):
            raise HostAdmissionError("bounded argv required")
        if action.get("tool") not in self.grant["tools"] or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", str(self.grant["tools"].get(action.get("tool"), ""))):
            raise HostAdmissionError("tool version is not granted")
        if action.get("cwd_scope") != "worktree" or action.get("filesystem") != self.profile["filesystem"] or action.get("network") != "deny":
            raise HostAdmissionError("workspace or network boundary missing")
        observation = action.get("observation")
        if not isinstance(observation, dict) or set(observation) != OBSERVATION_KEYS or any(not isinstance(observation[k], int) or isinstance(observation[k], bool) or observation[k] < 0 for k in self.budgets) or any(observation[k] > self.budgets[k] for k in self.budgets) or observation["tree_complete"] is not True:
            raise HostAdmissionError("resource or complete process-tree observation required")

    def apply(self, action):
        if not isinstance(action, dict) or set(action) - {"id", "operation", "time", "task_revision", "project_key", "project_revision", "worktree_key", "worktree_digest", "session_id", "worker_id", "lease_id", "capability", "tool", "argv", "cwd_scope", "filesystem", "network", "observation", "checkpoint_digest", "acknowledged", "terminated", "new_worker_id", "new_lease_id", "new_lease_expires"} or action.get("id") in self.seen or not re.fullmatch(r"ACT-[A-Z0-9-]{1,63}", str(action.get("id"))):
            raise HostAdmissionError("malformed, unknown, or replayed action")
        self._common(action)
        operation = action.get("operation")
        transitions = {("admitted", "launch"): "running", ("running", "cancel"): "cancelling", ("cancelling", "cleanup"): "cancelled", ("cancelled", "checkpoint"): "checkpointed", ("checkpointed", "recover"): "recovering", ("recovering", "resume"): "running"}
        target = transitions.get((self.state, operation))
        if target is None:
            raise HostAdmissionError("invalid lifecycle transition")
        if operation in {"launch", "resume"}:
            self._launch(action)
        if operation == "cleanup" and (action.get("acknowledged") is not True or action.get("terminated") is not True or action.get("observation", {}).get("tree_complete") is not True or action.get("observation", {}).get("terminated") is not True):
            raise HostAdmissionError("complete process-tree cleanup acknowledgement required")
        if operation == "checkpoint" and not DIGEST.fullmatch(str(action.get("checkpoint_digest"))):
            raise HostAdmissionError("verified checkpoint digest required")
        if operation == "recover":
            if action.get("new_worker_id") == self.admission.worker_id or action.get("new_lease_id") == self.admission.lease_id or not isinstance(action.get("new_lease_expires"), int) or action["new_lease_expires"] <= action["time"]:
                raise HostAdmissionError("recovery must fence the old lease")
            self.admission = Admission(self.admission.task_id, 5, self.admission.project_key, self.admission.project_revision, self.admission.worktree_key, self.admission.worktree_digest, self.admission.session_id, action["new_worker_id"], action["new_lease_id"], action["new_lease_expires"]).validate()
        self.state, self.now = target, action["time"]
        self.sequence += 1
        self.seen.add(action["id"])
        recorded = dict(action); recorded.update(sequence=self.sequence, state=self.state); recorded["action_digest"] = digest(recorded)
        self.actions.append(recorded)
        return self.state

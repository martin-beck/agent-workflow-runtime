#!/usr/bin/env python3
"""Offline reference model for the AR-0019 capability broker."""

from dataclasses import dataclass, field
import hashlib
import json
import re


class CapabilityBrokerError(ValueError):
    """A fail-closed grant, binding, privacy, or replay violation."""


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TOOLS = {"read", "edit", "test"}
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", re.I)


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _closed(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CapabilityBrokerError("malformed " + name)
    return value


def _revision(value, name):
    if not isinstance(value, int) or isinstance(value, bool) or value != 1:
        raise CapabilityBrokerError("invalid " + name + " revision")


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise CapabilityBrokerError("malformed " + name + " digest")


def privacy(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(key)) or privacy(child) for key, child in value.items())
    if isinstance(value, list):
        return any(privacy(child) for child in value)
    return isinstance(value, str) and bool(PRIVATE_VALUE.search(value))


@dataclass(frozen=True)
class Admission:
    task: dict
    project: dict
    worktree: dict
    session: dict
    grant: dict

    def validate(self):
        if set(self.task) != {"id", "revision"} or self.task["id"] != "AR-0019":
            raise CapabilityBrokerError("wrong task binding")
        _revision(self.task["revision"], "task")
        if set(self.project) != {"key", "revision"} or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", str(self.project["key"])):
            raise CapabilityBrokerError("malformed project binding")
        if not re.fullmatch(r"[0-9a-f]{40}", str(self.project["revision"])):
            raise CapabilityBrokerError("malformed project revision")
        if set(self.worktree) != {"key", "revision", "digest", "binding"} or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(self.worktree["key"])):
            raise CapabilityBrokerError("malformed worktree binding")
        if not re.fullmatch(r"[0-9a-f]{40}", str(self.worktree["revision"])) or self.worktree["binding"] != "exclusive_supplied":
            raise CapabilityBrokerError("invalid worktree observation")
        _digest(self.worktree["digest"], "worktree")
        if set(self.session) != {"id"} or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", str(self.session["id"])):
            raise CapabilityBrokerError("malformed session binding")
        if set(self.grant) != {"id", "revision", "tools"} or not re.fullmatch(r"GRT-[A-Z0-9-]{1,63}", str(self.grant["id"])):
            raise CapabilityBrokerError("malformed grant")
        _revision(self.grant["revision"], "grant")
        tools = self.grant["tools"]
        if not isinstance(tools, list) or not tools or len({item.get("id") for item in tools if isinstance(item, dict)}) != len(tools):
            raise CapabilityBrokerError("malformed grant tools")
        for tool in tools:
            if not isinstance(tool, dict) or set(tool) != {"id", "version"} or tool["id"] not in TOOLS or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(tool["version"])):
                raise CapabilityBrokerError("invalid granted tool")
        return self

    def identity(self):
        return {"task": self.task, "project": self.project, "worktree": self.worktree, "session": self.session, "grant": self.grant}


@dataclass
class Broker:
    admission: Admission
    state: str = "active"
    seen_ids: set = field(default_factory=set)
    seen_identities: set = field(default_factory=set)
    accepted: list = field(default_factory=list)

    def __post_init__(self):
        self.admission.validate()

    def apply(self, action):
        fields = {"id", "sequence", "task", "project", "worktree", "session", "grant", "tool", "operation", "disposition", "evidence_digest"}
        _closed(action, fields, "action")
        if not re.fullmatch(r"ACT-[A-Z0-9-]{1,63}", str(action["id"])) or action["id"] in self.seen_ids:
            raise CapabilityBrokerError("replayed action")
        if action["sequence"] != len(self.accepted) + 1 or not isinstance(action["sequence"], int) or isinstance(action["sequence"], bool):
            raise CapabilityBrokerError("invalid action sequence")
        _digest(action["evidence_digest"], "action evidence")
        if any(action[name] != getattr(self.admission, name) for name in ("task", "project", "worktree", "session", "grant")):
            raise CapabilityBrokerError("action binding mismatch")
        identity = (action["id"], digest({name: action[name] for name in ("task", "project", "worktree", "session", "grant")}))
        if identity in self.seen_identities:
            raise CapabilityBrokerError("replayed action identity")
        if self.state != "active" or action["operation"] not in {"read", "edit", "test", "close"}:
            raise CapabilityBrokerError("invalid broker operation")
        if action["operation"] != "close":
            if action["tool"] not in {item["id"] for item in self.admission.grant["tools"]} or action["tool"] != action["operation"] or action["disposition"] != "accepted":
                raise CapabilityBrokerError("unauthorized tool")
        elif action["tool"] is not None or action["disposition"] != "closed":
            raise CapabilityBrokerError("invalid close action")
        if action["operation"] == "close":
            self.state = "closed"
        self.seen_ids.add(action["id"])
        self.seen_identities.add(identity)
        self.accepted.append(action)

    def result(self):
        return {"state": self.state, "accepted_actions": len(self.accepted), "action_digest": digest(self.accepted)}

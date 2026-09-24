#!/usr/bin/env python3
"""Deterministic, non-executing fake-agent and interleaving model for AR-0064."""
import hashlib
import json
import re
from dataclasses import dataclass

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|raw.?output", re.IGNORECASE)

class SimulationError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()

def safe(value):
    if isinstance(value, dict):
        return all(not FORBIDDEN.search(str(k)) and safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or FORBIDDEN.search(value)))

@dataclass(frozen=True)
class FakeAgent:
    agent_id: str
    capabilities: tuple = ("request", "interrupt", "checkpoint", "resume")
    failure: str = "none"

    def __post_init__(self):
        if not re.fullmatch(r"agent-[a-z0-9-]{1,31}", self.agent_id) or not self.capabilities:
            raise SimulationError("invalid fake agent")
        if self.failure not in {"none", "provider", "host_loss", "crash", "ui_interrupt", "quality_unavailable"}:
            raise SimulationError("invalid failure injection")

class Simulator:
    """A virtual-clock model; it never starts a process or contacts a service."""
    def __init__(self, agents, seed=7):
        if not agents or len(agents) > 8 or len({a.agent_id for a in agents}) != len(agents):
            raise SimulationError("invalid agent set")
        if not isinstance(seed, int) or seed < 0:
            raise SimulationError("invalid seed")
        self.agents = tuple(agents); self.seed = seed; self.clock = 0; self.events = []; self.claimed = set(); self.state = "queued"

    def _event(self, kind, agent, state, detail):
        if len(self.events) >= 64 or not safe(detail):
            raise SimulationError("event budget or privacy violation")
        item = {"sequence": len(self.events) + 1, "clock": self.clock, "kind": kind, "agent": agent,
                "state": state, "detail_digest": digest(detail), "execute": False}
        item["event_digest"] = digest(item); self.events.append(item); return item

    def run(self, order=(0,), lease_expiry=False):
        for index in order:
            if not isinstance(index, int) or index < 0 or index >= len(self.agents):
                raise SimulationError("invalid interleaving")
            agent = self.agents[index]
            if agent.agent_id in self.claimed:
                self._event("duplicate_rejected", agent.agent_id, self.state, {"reason": "already_claimed"}); continue
            self.claimed.add(agent.agent_id); self.clock += 1
            self._event("dispatch", agent.agent_id, "running", {"seed": self.seed})
            if lease_expiry:
                self.clock += 2; self._event("lease_expired", agent.agent_id, "queued", {"fenced": True}); self.claimed.remove(agent.agent_id); continue
            if agent.failure == "ui_interrupt":
                self._event("interrupt", agent.agent_id, "cancelled", {"acknowledged": True}); self.state = "cancelled"
            elif agent.failure in {"provider", "host_loss", "crash", "quality_unavailable"}:
                self._event("failure", agent.agent_id, "failed", {"class": agent.failure}); self.state = "failed"
            else:
                self._event("complete", agent.agent_id, "succeeded", {"result_digest": digest({"agent": agent.agent_id, "seed": self.seed})}); self.state = "succeeded"
            break
        return self.result()

    def result(self):
        return {"seed": self.seed, "clock": self.clock, "state": self.state, "events": self.events,
                "terminal": self.state in {"succeeded", "failed", "cancelled"}, "execute": False,
                "network": "disabled", "llm": "not_performed"}

def validate(record):
    if not isinstance(record, dict) or set(record) != {"agents", "seed", "order", "lease_expiry", "expected"} or not safe(record):
        raise SimulationError("unknown, missing, or privacy-bearing field")
    agents = tuple(FakeAgent(a["agent_id"], tuple(a["capabilities"]), a["failure"]) for a in record["agents"])
    actual = Simulator(agents, record["seed"]).run(tuple(record["order"]), bool(record["lease_expiry"]))
    if actual != record["expected"]:
        raise SimulationError("deterministic trace mismatch")
    return {"contract": "awr-deterministic-fake-agent-simulator@1.0.0", "events": len(actual["events"]), "state": actual["state"], "execute": False}

#!/usr/bin/env python3
"""Deterministic cross-agent evidence, accounting, replay, and comparison (AR-0090)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^(?:JOB|LEASE|SES|EV|RUN)-[A-Z0-9-]{1,63}$")
PRIVATE = re.compile(
    r"credential|password|secret|token|prompt|transcript|private[_ -]?path|raw[_ -]?output",
    re.IGNORECASE,
)
ZERO = "sha256:" + "0" * 64


class AccountingError(ValueError):
    pass


def canonical(v: Any) -> bytes:
    return json.dumps(
        v, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(v: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(v if isinstance(v, bytes) else canonical(v)).hexdigest()
    )


def safe(v: Any) -> bool:
    if isinstance(v, dict):
        return all(
            (str(k) == "tokens" or not PRIVATE.search(str(k))) and safe(x)
            for k, x in v.items()
        )
    if isinstance(v, list):
        return all(safe(x) for x in v)
    return not (isinstance(v, str) and (len(v) > 256 or PRIVATE.search(v)))


def req_id(v: Any, label: str) -> str:
    if not isinstance(v, str) or not ID.fullmatch(v):
        raise AccountingError("invalid_" + label)
    return v


def req_digest(v: Any, label: str) -> str:
    if not isinstance(v, str) or not DIGEST.fullmatch(v):
        raise AccountingError("invalid_" + label)
    return v


@dataclass
class AgentLedger:
    job_id: str
    lease_id: str
    session_id: str
    agent_id: str
    benchmark_digest: str
    budget: dict[str, int]
    events: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(
        default_factory=lambda: {"seconds": 0, "tokens": 0, "events": 0}
    )

    def __post_init__(self):
        for v, n in (
            (self.job_id, "job_id"),
            (self.lease_id, "lease_id"),
            (self.session_id, "session_id"),
        ):
            req_id(v, n)
        req_digest(self.benchmark_digest, "benchmark_digest")
        if set(self.budget) != {"seconds", "tokens", "events"} or any(
            not isinstance(v, int) or v < 0 for v in self.budget.values()
        ):
            raise AccountingError("invalid_budget")

    def append(
        self,
        event_id: str,
        kind: str,
        usage: dict[str, int],
        evidence_digest: str,
        *,
        revision: int = 3,
    ) -> dict[str, Any]:
        req_id(event_id, "event_id")
        req_digest(evidence_digest, "evidence_digest")
        if any(e["event_id"] == event_id for e in self.events):
            raise AccountingError("replayed_event")
        if set(usage) != {"seconds", "tokens"} or any(
            isinstance(v, bool) or not isinstance(v, int) or v < 0
            for v in usage.values()
        ):
            raise AccountingError("invalid_usage")
        nxt = {
            "seconds": self.usage["seconds"] + usage["seconds"],
            "tokens": self.usage["tokens"] + usage["tokens"],
            "events": len(self.events) + 1,
        }
        if any(nxt[k] > self.budget[k] for k in nxt):
            raise AccountingError("budget_exceeded")
        body = {
            "event_id": event_id,
            "sequence": len(self.events) + 1,
            "job_id": self.job_id,
            "lease_id": self.lease_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "revision": revision,
            "kind": kind,
            "usage": usage,
            "evidence_digest": evidence_digest,
            "previous_digest": self.events[-1]["digest"] if self.events else ZERO,
        }
        if not safe(body):
            raise AccountingError("privacy_violation")
        body["digest"] = digest(body)
        self.events.append(body)
        self.usage = nxt
        return body

    def export(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "lease_id": self.lease_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "benchmark_digest": self.benchmark_digest,
            "budget": self.budget,
            "usage": self.usage,
            "events": self.events,
            "execute": False,
            "provider": "not_performed",
            "network": "disabled",
        }


def replay(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict) or not safe(record):
        raise AccountingError("privacy_or_malformed_record")
    required = {
        "job_id",
        "lease_id",
        "session_id",
        "agent_id",
        "benchmark_digest",
        "budget",
        "events",
        "expected",
    }
    if not required <= set(record):
        raise AccountingError("missing_record_field")
    ledger = AgentLedger(
        record["job_id"],
        record["lease_id"],
        record["session_id"],
        record["agent_id"],
        record["benchmark_digest"],
        record["budget"],
    )
    for e in record["events"]:
        ledger.append(
            e["event_id"],
            e["kind"],
            e["usage"],
            e["evidence_digest"],
            revision=e["revision"],
        )
    actual = ledger.export()
    if actual != record["expected"]:
        raise AccountingError("replay_mismatch")
    return {
        "agent_id": ledger.agent_id,
        "events": len(ledger.events),
        "usage": ledger.usage,
        "replayed": True,
    }


def compare(records: list[dict[str, Any]]) -> dict[str, Any]:
    if len(records) < 2:
        raise AccountingError("comparison_requires_two_agents")
    benchmarks = {r["benchmark_digest"] for r in records}
    configs = {r.get("configuration_digest") for r in records}
    if len(benchmarks) != 1 or len(configs) != 1 or None in configs:
        raise AccountingError("non_comparable_runs")
    results = [replay(r) for r in records]
    return {
        "agents": [r["agent_id"] for r in records],
        "benchmark_digest": records[0]["benchmark_digest"],
        "configuration_digest": records[0]["configuration_digest"],
        "results": results,
        "measurement": "not_performed",
        "comparable": True,
        "execute": False,
    }

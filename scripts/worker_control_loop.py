#!/usr/bin/env python3
"""Executable, fail-closed local reference loop for material worker actions.

Authority implementations here are deterministic test doubles. The controller
requires all three decisions and records them in an append-only local journal;
it does not contact or represent live authorities.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

PROTOCOL = {"id": "awr-worker-control-loop", "version": "1.0.0"}
DENIED = {"specification", "tests", "user_decision", "acceptance_evidence"}
HEX = re.compile(r"^[0-9a-f]{64}$")
SPECIFICATION_PATH = Path(__file__).parents[1] / "specifications" / "worker-control-loop-v1.json"
SPECIFICATION_DIGEST = ""
TEST_CONTRACT_DIGEST = ""


class ControlLoopError(ValueError):
    """A missing, stale, unauthorized, or non-durable control decision."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


SPECIFICATION_DIGEST = digest(SPECIFICATION_PATH.read_bytes()) if SPECIFICATION_PATH.exists() else ""
TEST_CONTRACT_DIGEST = digest({"protected": sorted(DENIED), "gates": ["awq", "awg", "ui"]})


@dataclass(frozen=True)
class Proposal:
    task_id: str
    revision: int
    proposal: str
    specification_digest: str
    test_digest: str
    evidence_digest: str
    material: bool = True
    uncertain: bool = False
    blocked: bool = False
    worker_changes: tuple[str, ...] = ()

    def binding(self) -> dict[str, Any]:
        if not self.task_id or type(self.revision) is not int or self.revision < 1:
            raise ControlLoopError("invalid_task_binding")
        for item in (self.specification_digest, self.test_digest, self.evidence_digest):
            if not isinstance(item, str) or not item.startswith("sha256:") or not HEX.fullmatch(item[7:]):
                raise ControlLoopError("invalid_proposal_digest")
        forbidden = set(self.worker_changes) & DENIED
        if forbidden:
            raise ControlLoopError("worker_changed_protected_input")
        return {
            "task_id": self.task_id, "task_revision": self.revision,
            "proposal_digest": digest(self.proposal),
            "specification_digest": self.specification_digest,
            "test_digest": self.test_digest, "evidence_digest": self.evidence_digest,
        }


class Authority(Protocol):
    name: str

    def decide(self, binding: dict[str, Any], *, escalation: bool) -> dict[str, Any]: ...


@dataclass
class FakeAuthority:
    """Deterministic authority fake; accepted outcomes persist in its journal."""
    name: str
    outcome: str = "approved"
    journal: list[dict[str, Any]] = field(default_factory=list)
    alter: dict[str, Any] = field(default_factory=dict)

    def decide(self, binding: dict[str, Any], *, escalation: bool) -> dict[str, Any]:
        decision = {
            **binding, "authority": self.name, "decision_id": f"DEC-{self.name.upper()}-{len(self.journal)+1:04d}",
            "outcome": self.outcome, "escalation": escalation, "durable": True,
        }
        if self.name == "awg":
            decision["guidance_digest"] = digest({"binding": binding, "guidance": "local-fake-guidance-v1"})
        decision.update(self.alter)
        self.journal.append(decision)
        return decision


class DecisionJournal:
    """Append-only canonical decision journal with a hash-linked event chain."""
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else None
        self.entries: list[dict[str, Any]] = []
        if self.path and self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                self.entries.append(json.loads(line))
            self._verify()

    def _verify(self) -> None:
        previous = "sha256:" + "0" * 64
        for index, entry in enumerate(self.entries, 1):
            body = {k: v for k, v in entry.items() if k != "entry_digest"}
            if entry.get("sequence") != index or entry.get("previous_digest") != previous or entry.get("entry_digest") != digest(body):
                raise ControlLoopError("decision_journal_corrupt")
            previous = entry["entry_digest"]

    def append(self, decision: dict[str, Any]) -> dict[str, Any]:
        previous = self.entries[-1]["entry_digest"] if self.entries else "sha256:" + "0" * 64
        body = {"sequence": len(self.entries) + 1, "previous_digest": previous, "decision": decision}
        entry = {**body, "entry_digest": digest(body)}
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(canonical(entry).decode() + "\n")
        self.entries.append(entry)
        return entry


class WorkerControlLoop:
    def __init__(self, awq: Authority, awg: Authority, ui: Authority, journal: DecisionJournal,
                 *, specification_digest: str = SPECIFICATION_DIGEST,
                 test_digest: str = TEST_CONTRACT_DIGEST):
        self.authorities = (awq, awg, ui)
        self.journal = journal
        self.specification_digest = specification_digest
        self.test_digest = test_digest

    def run(self, proposal: Proposal) -> dict[str, Any]:
        binding = proposal.binding()
        if not proposal.material:
            raise ControlLoopError("non_material_action_out_of_scope")
        if binding["specification_digest"] != self.specification_digest:
            raise ControlLoopError("changed_specification")
        if binding["test_digest"] != self.test_digest:
            raise ControlLoopError("changed_tests")
        if tuple(a.name for a in self.authorities) != ("awq", "awg", "ui"):
            raise ControlLoopError("authority_order_invalid")
        decisions = []
        escalate = proposal.uncertain or proposal.blocked
        for authority in self.authorities:
            decision = authority.decide(binding, escalation=escalate)
            required = {**binding, "authority": authority.name}
            if any(decision.get(k) != v for k, v in required.items()):
                raise ControlLoopError("decision_binding_mismatch")
            if decision.get("durable") is not True or not decision.get("decision_id"):
                raise ControlLoopError("decision_not_durable")
            allowed = {"awq": {"approved", "rejected"}, "awg": {"approved", "rejected", "escalated"}, "ui": {"approved", "rejected", "cancelled"}}[authority.name]
            if decision.get("outcome") not in allowed:
                raise ControlLoopError("decision_outcome_invalid")
            self.journal.append(decision)
            decisions.append(decision)
            if decision["outcome"] == "rejected":
                return self._result(binding, decisions, "rejected")
            if decision["outcome"] == "cancelled":
                return self._result(binding, decisions, "cancelled")
            if decision["outcome"] == "escalated":
                # Escalation requires the UI decision, so continue only to UI.
                continue
        if escalate and decisions[1]["outcome"] != "escalated":
            raise ControlLoopError("blocked_or_uncertain_work_not_escalated")
        return self._result(binding, decisions, "approved")

    def _result(self, binding: dict[str, Any], decisions: list[dict[str, Any]], outcome: str) -> dict[str, Any]:
        return {"protocol": PROTOCOL, **binding, "decisions": decisions, "outcome": outcome,
                "journal_head": self.journal.entries[-1]["entry_digest"],
                "provider": "not_performed", "network": "disabled", "live_authority": "unverified"}


def fake_loop(outcomes: tuple[str, str, str] = ("approved", "approved", "approved"), journal: DecisionJournal | None = None) -> WorkerControlLoop:
    return WorkerControlLoop(*(FakeAuthority(name, outcome) for name, outcome in zip(("awq", "awg", "ui"), outcomes)), journal or DecisionJournal())


def check(result: dict[str, Any], proposal: Proposal, expected_journal: DecisionJournal) -> dict[str, Any]:
    binding = proposal.binding()
    if result.get("protocol") != PROTOCOL or any(result.get(k) != v for k, v in binding.items()):
        raise ControlLoopError("result_binding_mismatch")
    decisions = result.get("decisions")
    if not isinstance(decisions, list) or not decisions:
        raise ControlLoopError("missing_authority_decision")
    names = [d.get("authority") for d in decisions]
    if names != ["awq", "awg", "ui"][:len(names)]:
        raise ControlLoopError("skipped_or_reordered_gate")
    if result.get("outcome") == "approved" and names != ["awq", "awg", "ui"]:
        raise ControlLoopError("incomplete_gate_chain")
    if result.get("journal_head") != expected_journal.entries[-1]["entry_digest"]:
        raise ControlLoopError("decision_not_journaled")
    journal_decisions = [entry["decision"] for entry in expected_journal.entries[-len(decisions):]]
    if decisions != journal_decisions:
        raise ControlLoopError("decision_journal_mismatch")
    outcomes = [item.get("outcome") for item in decisions]
    if result.get("outcome") == "approved" and (outcomes[-1] != "approved" or "rejected" in outcomes or "cancelled" in outcomes):
        raise ControlLoopError("approval_outcome_mismatch")
    if result.get("outcome") == "rejected" and "rejected" not in outcomes:
        raise ControlLoopError("rejection_outcome_mismatch")
    if result.get("outcome") == "cancelled" and outcomes[-1] != "cancelled":
        raise ControlLoopError("cancellation_outcome_mismatch")
    return {"outcome": result["outcome"], "decisions": len(decisions), "journal_head": result["journal_head"]}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", default="AR-0135")
    parser.add_argument("--revision", type=int, default=2)
    args = parser.parse_args()
    sample = Proposal(args.task_id, args.revision, "deterministic local demonstration",
                      SPECIFICATION_DIGEST, TEST_CONTRACT_DIGEST, digest({"test": "passed"}))
    journal = DecisionJournal()
    result = fake_loop(journal=journal).run(sample)
    check(result, sample, journal)
    print(json.dumps(result, sort_keys=True, indent=2))

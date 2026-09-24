"""Deterministic closed-loop contractor over scheduler, sessions, and gates."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Sequence

from .agent_session import AgentSession, fake_digest
from .authority_gates import AuthorityGates
from .scheduler_local import LocalScheduler
from .cli import canonical


class LocalContractor:
    def __init__(self, scheduler: LocalScheduler, gates: AuthorityGates, root: Path):
        self.scheduler, self.gates, self.root = scheduler, gates, root

    def execute(self, *, job_id: str, task: str, revision: int, worker: str, session_id: str, adapter: str, argv: Sequence[str], cwd: Path, sandboxed: bool = False) -> dict[str, Any]:
        self.scheduler.submit(job_id, task)
        lease = self.scheduler.dispatch(worker)["job"]["lease"]
        admission = self.gates.admit(task=task, revision=revision)
        session = AgentSession(self.root, session_id, adapter, sandboxed=sandboxed).run(argv, cwd, input_digest=fake_digest(task))
        artifact_digest = "sha256:" + hashlib.sha256(canonical({"session": session, "task": task, "revision": revision})).hexdigest()
        if session["status"] != "completed":
            self.scheduler.complete(job_id, worker, lease["id"], status="failed")
            return {"status": "rejected", "job_id": job_id, "session": session, "accounting": {"attempts": 1, "artifact_bytes": 0}}
        acceptance = self.gates.accept_artifact(task=task, revision=revision, artifact_digest=artifact_digest)
        terminal = self.scheduler.complete(job_id, worker, lease["id"], status="done")
        accounting = {"attempts": 1, "artifact_bytes": len(artifact_digest), "stdout_bytes": len(session["result"]["stdout"].encode()), "provider_cost": "not_performed", "network": "not_required_but_host_control_unverified"}
        return {"status": "accepted", "job_id": job_id, "admission": admission, "session": session, "artifact_digest": artifact_digest, "acceptance": acceptance, "terminal": terminal, "accounting": accounting}

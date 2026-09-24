"""Concurrent provider-free qualification across isolated project bindings."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .authority_gates import AuthorityGates
from .contractor import LocalContractor
from .scheduler_local import LocalScheduler
from scripts.local_authority_transport import LocalAuthorityClient, LocalAuthorityEndpoint


def _one(root: Path, number: int) -> dict[str, Any]:
    project = root / f"project-{number}"; project.mkdir()
    endpoints = {
        "coordinator": LocalAuthorityEndpoint("coordinator", ["observed"]),
        "awq": LocalAuthorityEndpoint("awq", ["accepted", "accepted"]),
        "awg": LocalAuthorityEndpoint("awg", ["requires_ui", "requires_ui"]),
        "ui": LocalAuthorityEndpoint("ui", ["approved", "approved"]),
    }
    result = LocalContractor(LocalScheduler(project / "scheduler.json"), AuthorityGates(LocalAuthorityClient(endpoints)), root).execute(
        job_id=f"JOB-QUAL-{number}", task=f"AR-QUAL-{number}", revision=3, worker=f"WRK-{number:03d}", session_id=f"SES-QUAL-{number}", adapter="fake-agent", argv=["python3", "-c", f"print('project-{number}')"], cwd=project
    )
    return {"project": str(project), "job_id": result["job_id"], "status": result["status"], "artifact_digest": result["artifact_digest"], "scheduler": result["terminal"]["state_digest"]}


def run_concurrent(root: Path, count: int = 2) -> dict[str, Any]:
    if count < 2 or count > 8:
        raise ValueError("qualification_count_invalid")
    root.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=count) as pool:
        results = list(pool.map(lambda item: _one(root, item), range(count)))
    results.sort(key=lambda item: item["job_id"])
    return {"status": "qualified", "parallel": True, "projects": results, "providers": "not_performed", "network": "not_required_but_host_control_unverified"}

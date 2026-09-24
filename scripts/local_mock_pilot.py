#!/usr/bin/env python3
"""Deterministic local-LLM pilot for AR-0068; never contacts a provider."""
import hashlib
import json
import re
from dataclasses import asdict

from scripts.evidence_accounting import Ledger
from scripts.executable_observability import Observer
from scripts.executable_scheduler import RuntimeScheduler


class LocalMockError(ValueError):
    pass


def digest(value):
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class LocalLLMMock:
    """A LiteLLM-shaped local request/response boundary with deterministic output."""

    backend = "local-deterministic-mock"

    def complete(self, request):
        if set(request) != {"model", "messages", "request_id"}:
            raise LocalMockError("invalid local mock request")
        if not re.fullmatch(r"REQ-[A-Z0-9-]{1,40}", request["request_id"]):
            raise LocalMockError("invalid request binding")
        if request["model"] != "mock/benchmark-v1" or not isinstance(request["messages"], list):
            raise LocalMockError("unsupported local mock request")
        response = {
            "request_id": request["request_id"],
            "backend": self.backend,
            "response_digest": digest(request),
            "usage": {"tokens": 1},
            "network": "disabled",
            "external_provider": "not_performed",
        }
        return response


def run(seed=1):
    if not isinstance(seed, int) or seed < 0:
        raise LocalMockError("invalid deterministic seed")
    scheduler = RuntimeScheduler()
    scheduler.submit("OP-MOCK-1", "JOB-MOCK-1")
    lease = scheduler.dispatch("OP-MOCK-2", "WORKER-MOCK", 0)
    mock = LocalLLMMock()
    response = mock.complete(
        {"model": "mock/benchmark-v1", "messages": [{"role": "user", "content_digest": digest({"seed": seed})}], "request_id": "REQ-MOCK-1"}
    )
    ledger = Ledger("JOB-MOCK-1", "LEASE-MOCK-1", {"seconds": 10, "tokens": 4, "events": 4})
    ledger.append("EV-MOCK-1", "request", "local_mock", {"seconds": 1, "tokens": 1})
    ledger.append("EV-MOCK-2", "response", "local_mock", {"seconds": 1, "tokens": 1})
    observer = Observer(max_events=8)
    observer.observe("job", "JOB-MOCK-1", "running", {"backend": mock.backend})
    observer.observe("adapter", "JOB-MOCK-1", "succeeded", {"response_digest": response["response_digest"]})
    return {
        "seed": seed,
        "job_id": "JOB-MOCK-1",
        "lease": asdict(lease),
        "response": response,
        "accounting": ledger.export(),
        "observability": observer.export(),
        "scheduler": scheduler.snapshot(),
        "local_execution": True,
        "external_provider": "not_performed",
        "network": "disabled",
        "credentials": "not_supplied",
        "remote": "unverified",
    }


def validate(record):
    actual = run(record.get("seed", 1))
    if set(record) != {"seed", "expected_digest"} or record["expected_digest"] != digest(actual):
        raise LocalMockError("local mock pilot fixture mismatch")
    return actual

"""Deterministic, provider-free local LLM request/response protocol."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterator, Sequence

from .agent_registry import AdapterRegistry, RegistryError
from .authority_gates import AuthorityGates
from .scheduler_local import LocalScheduler
from scripts.cross_agent_accounting import AgentLedger


class MockProtocolError(ValueError):
    pass


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^(?:REQ|SES|JOB|LEASE|LSE)-[A-Z0-9-]{3,63}$")
_PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|raw[_ -]?output|private[_ -]?path", re.I)


def _privacy_safe(value: Any) -> bool:
    if isinstance(value, dict):
        return all((key == "tokens" or not _PRIVATE.search(str(key))) and _privacy_safe(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_privacy_safe(item) for item in value)
    return not (isinstance(value, str) and _PRIVATE.search(value))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


@dataclass(frozen=True)
class MockRequest:
    request_id: str
    session_id: str
    task: str
    revision: int
    adapter_id: str
    messages: tuple[dict[str, str], ...]
    max_tokens: int = 64
    stream: bool = True

    def validate(self) -> None:
        if not _ID.fullmatch(self.request_id) or not _ID.fullmatch(self.session_id):
            raise MockProtocolError("request_identity_invalid")
        if not isinstance(self.task, str) or not self.task or len(self.task) > 128 or _PRIVATE.search(self.task):
            raise MockProtocolError("request_task_invalid")
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1:
            raise MockProtocolError("request_revision_invalid")
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", self.adapter_id):
            raise MockProtocolError("request_adapter_invalid")
        if not isinstance(self.messages, tuple) or not 1 <= len(self.messages) <= 16:
            raise MockProtocolError("request_messages_invalid")
        for message in self.messages:
            if set(message) != {"role", "content"} or message["role"] not in {"user", "system", "assistant"} or not isinstance(message["content"], str) or len(message["content"]) > 4096:
                raise MockProtocolError("request_message_invalid")
        if not isinstance(self.max_tokens, int) or isinstance(self.max_tokens, bool) or not 1 <= self.max_tokens <= 256:
            raise MockProtocolError("request_token_bound_invalid")
        if not isinstance(self.stream, bool):
            raise MockProtocolError("request_stream_invalid")

    @property
    def input_digest(self) -> str:
        self.validate()
        return digest({"messages": list(self.messages)})

    @property
    def configuration_digest(self) -> str:
        return digest({"max_tokens": self.max_tokens, "stream": self.stream})


class DeterministicLocalLLM:
    def __init__(self, registry: AdapterRegistry, adapter_id: str):
        self.registry, self.adapter_id = registry, adapter_id
        try:
            self.profile = registry.profile(adapter_id)
        except RegistryError as exc:
            raise MockProtocolError("unknown_adapter") from exc

    def _response(self, request: MockRequest) -> str:
        seed = digest({"input": request.input_digest, "adapter": self.adapter_id, "profile": self.profile.public()["profile_digest"]})[7:]
        words = [seed[index:index + 8] for index in range(0, min(len(seed), request.max_tokens * 2), 8)]
        return f"local-{self.adapter_id}-" + " ".join(words)

    def request(self, request: MockRequest) -> dict[str, Any]:
        request.validate()
        capabilities = ["request"] + (["stream"] if request.stream else [])
        try:
            negotiation = self.registry.negotiate(self.adapter_id, capabilities)
        except RegistryError as exc:
            raise MockProtocolError(f"capability_{exc}") from exc
        content = self._response(request)
        return {"schema_version": 1, "object": "local.mock.response", "request_id": request.request_id, "session_id": request.session_id, "task": request.task, "revision": request.revision, "adapter_id": self.adapter_id, "input_digest": request.input_digest, "content": content, "response_digest": digest({"content": content}), "usage": {"tokens": len(content.split()), "events": 1}, "registry_revision": negotiation["registry_revision"], "profile_digest": negotiation["profile_digest"], "execute": False, "provider": "not_performed", "network": "disabled"}

    def stream(self, request: MockRequest) -> Iterator[dict[str, Any]]:
        response = self.request(request)
        parts = response["content"].split()
        for sequence, part in enumerate(parts, 1):
            yield {"schema_version": 1, "object": "local.mock.chunk", "request_id": request.request_id, "session_id": request.session_id, "revision": request.revision, "sequence": sequence, "delta": part, "delta_digest": digest(part), "finish_reason": None}
        yield {"schema_version": 1, "object": "local.mock.chunk", "request_id": request.request_id, "session_id": request.session_id, "revision": request.revision, "sequence": len(parts) + 1, "delta": "", "delta_digest": digest(""), "finish_reason": "stop"}


def record_exchange(request: MockRequest, response: dict[str, Any], frames: Sequence[dict[str, Any]], *, registry_revision: int, profile_digest: str, authority_digest: str, lease_id: str) -> dict[str, Any]:
    request.validate()
    if not _DIGEST.fullmatch(authority_digest) or not _DIGEST.fullmatch(profile_digest) or not _ID.fullmatch(lease_id):
        raise MockProtocolError("record_binding_invalid")
    if response.get("input_digest") != request.input_digest:
        raise MockProtocolError("response_input_mismatch")
    record = {"schema_version": 1, "request_id": request.request_id, "session_id": request.session_id, "task": request.task, "revision": request.revision, "adapter_id": request.adapter_id, "input_digest": request.input_digest, "configuration_digest": request.configuration_digest, "response_digest": response["response_digest"], "stream_digests": [{key: frame[key] for key in ("sequence", "delta_digest", "finish_reason")} for frame in frames], "registry_revision": registry_revision, "profile_digest": profile_digest, "authority_digest": authority_digest, "lease_id": lease_id, "usage": response["usage"], "execute": False, "provider": "not_performed", "network": "disabled"}
    if not _privacy_safe(record):
        raise MockProtocolError("privacy_violation")
    record["record_digest"] = digest(record)
    return record


def replay_exchange(record: dict[str, Any], request: MockRequest, *, registry: AdapterRegistry) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("schema_version") != 1 or "record_digest" not in record:
        raise MockProtocolError("record_shape_invalid")
    supplied = dict(record); expected = supplied.pop("record_digest")
    if expected != digest(supplied):
        raise MockProtocolError("record_digest_mismatch")
    if supplied.get("input_digest") != request.input_digest or supplied.get("adapter_id") != request.adapter_id or supplied.get("configuration_digest") != request.configuration_digest:
        raise MockProtocolError("replay_mismatch")
    response = DeterministicLocalLLM(registry, request.adapter_id).request(request)
    if response["response_digest"] != supplied.get("response_digest"):
        raise MockProtocolError("replay_response_mismatch")
    return {"replayed": True, "request_id": request.request_id, "response_digest": response["response_digest"], "record_digest": expected, "execute": False, "provider": "not_performed"}


def compare_agents(request: MockRequest, adapters: Sequence[str], *, registry: AdapterRegistry) -> dict[str, Any]:
    if len(adapters) != 2 or adapters[0] == adapters[1]:
        raise MockProtocolError("comparison_requires_two_agents")
    request.validate(); runs = []
    for adapter in adapters:
        # Comparison is response-based; streaming is an optional presentation
        # capability and must not make a heterogeneous pair incomparable.
        run_request = MockRequest(request.request_id, request.session_id, request.task, request.revision, adapter, request.messages, request.max_tokens, False)
        response = DeterministicLocalLLM(registry, adapter).request(run_request)
        runs.append({"adapter_id": adapter, "input_digest": run_request.input_digest, "configuration_digest": request.configuration_digest, "response_digest": response["response_digest"], "usage": response["usage"]})
    return {"schema_version": 1, "comparison": "same_input", "input_digest": request.input_digest, "configuration_digest": request.configuration_digest, "runs": runs, "comparable": True, "measurement": "local_digest_comparison", "execute": False, "provider": "not_performed", "network": "disabled"}


class LocalMockWorkflow:
    def __init__(self, scheduler: LocalScheduler, gates: AuthorityGates, registry: AdapterRegistry):
        self.scheduler, self.gates, self.registry = scheduler, gates, registry

    def run(self, *, job_id: str, task: str, revision: int, worker: str, session_id: str, lease_id: str, request: MockRequest, budget: dict[str, int]) -> dict[str, Any]:
        if request.session_id != session_id or request.revision != revision or request.task != task:
            raise MockProtocolError("workflow_binding_mismatch")
        self.scheduler.submit(job_id, task, adapter_id=request.adapter_id, capabilities=["request"] + (["stream"] if request.stream else []))
        lease = self.scheduler.dispatch(worker)["job"]["lease"]
        if lease["id"] != lease_id:
            raise MockProtocolError("workflow_lease_mismatch")
        admission = self.gates.admit(task=task, revision=revision)
        model = DeterministicLocalLLM(self.registry, request.adapter_id)
        response = model.request(request); frames = list(model.stream(request)) if request.stream else []
        record = record_exchange(request, response, frames, registry_revision=response["registry_revision"], profile_digest=response["profile_digest"], authority_digest=digest(admission["trace"]), lease_id=lease_id)
        ledger = AgentLedger(job_id, lease_id, session_id, request.adapter_id, request.input_digest, budget)
        ledger.append("EV-MOCK-1", "local_mock_response", {"seconds": 0, "tokens": response["usage"]["tokens"]}, digest(record))
        acceptance = self.gates.accept_artifact(task=task, revision=revision, artifact_digest=record["record_digest"])
        terminal = self.scheduler.complete(job_id, worker, lease_id)
        return {"status": "accepted", "admission": admission, "response": response, "record": record, "accounting": ledger.export(), "acceptance": acceptance, "terminal": terminal}


__all__ = ["DeterministicLocalLLM", "LocalMockWorkflow", "MockProtocolError", "MockRequest", "compare_agents", "digest", "record_exchange", "replay_exchange"]

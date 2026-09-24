#!/usr/bin/env python3
"""Deterministic local request/event exchange for authority bridge contracts.

This is an in-process transport harness, not a substitute authority. Endpoint
outcomes are explicitly supplied by the authority fixture; the runtime client
only transports, validates, retries bounded transient outcomes, and projects
observations.
"""

from __future__ import annotations

import multiprocessing
import queue
import time
from dataclasses import dataclass, field
from typing import Iterable

from scripts.local_authority_bridge import (
    AuthorityBridgeError,
    digest,
    request_envelope,
    response_envelope,
    validate_exchange,
)


TRANSIENT = {"unknown", "ambiguous", "indeterminate"}


def _process_server(connection, authority: str, outcomes: list[str]) -> None:
    responses: dict[str, dict] = {}
    while True:
        request = connection.recv()
        if request is None:
            return
        operation_id = request["operation_id"]
        if operation_id in responses:
            connection.send(responses[operation_id])
            continue
        outcome = outcomes.pop(0) if outcomes else "unknown"
        response = response_envelope(request, outcome, authority=authority)
        if outcome not in TRANSIENT:
            responses[operation_id] = response
        connection.send(response)


@dataclass
class LocalAuthorityEndpoint:
    authority: str
    outcomes: list[str]
    requests: list[dict] = field(default_factory=list)
    _responses: dict[str, dict] = field(default_factory=dict)

    def exchange(self, request: dict) -> dict:
        if request.get("authority") != self.authority:
            raise AuthorityBridgeError("endpoint authority mismatch")
        self.requests.append(request)
        operation_id = request["operation_id"]
        if operation_id in self._responses:
            return self._responses[operation_id]
        outcome = self.outcomes.pop(0) if self.outcomes else "unknown"
        response = response_envelope(request, outcome)
        if outcome not in TRANSIENT:
            self._responses[operation_id] = response
        return response


@dataclass
class LocalAuthorityClient:
    endpoints: dict[str, LocalAuthorityEndpoint]
    max_attempts: int = 3

    def exchange(self, request: dict, *, expected_revision: int, required_authority: str) -> dict:
        if required_authority not in self.endpoints or request.get("authority") != required_authority:
            raise AuthorityBridgeError("required local authority unavailable")
        if request.get("task_revision") != expected_revision:
            raise AuthorityBridgeError("stale task revision")
        if not isinstance(self.max_attempts, int) or not 1 <= self.max_attempts <= 5:
            raise AuthorityBridgeError("invalid attempt bound")
        endpoint = self.endpoints[required_authority]
        last: dict | None = None
        for _ in range(self.max_attempts):
            response = endpoint.exchange(request)
            last = response
            if response.get("outcome") in TRANSIENT:
                continue
            return validate_exchange(request, response, expected_revision=expected_revision, required_authorities={required_authority})
        assert last is not None
        return validate_exchange(request, last, expected_revision=expected_revision, required_authorities={required_authority})


class LocalAuthorityProcessEndpoint:
    """A bounded local OS-process endpoint used only by conformance tests."""

    def __init__(self, authority: str, outcomes: Iterable[str], timeout: float = 1.0):
        self.authority = authority
        self.timeout = timeout
        self._parent, child = multiprocessing.Pipe()
        self._process = multiprocessing.Process(target=_process_server, args=(child, authority, list(outcomes)), daemon=True)
        self._process.start()

    def exchange(self, request: dict) -> dict:
        if request.get("authority") != self.authority:
            raise AuthorityBridgeError("endpoint authority mismatch")
        self._parent.send(request)
        if not self._parent.poll(self.timeout):
            raise AuthorityBridgeError("local authority deadline exceeded")
        return self._parent.recv()

    def close(self) -> None:
        if self._process.is_alive():
            self._parent.send(None)
            self._process.join(self.timeout)
        if self._process.is_alive():
            self._process.terminate()
            self._process.join()
        self._parent.close()


def demo_client() -> LocalAuthorityClient:
    return LocalAuthorityClient({
        name: LocalAuthorityEndpoint(name, [outcome])
        for name, outcome in {
            "coordinator": "observed", "awq": "accepted", "awg": "requires_ui", "ui": "approved"
        }.items()
    })


def make_request(authority: str, operation: str, revision: int, task: str = "AR-LOCAL-1") -> dict:
    return request_envelope(authority, operation, revision, digest({"authority": authority, "operation": operation}), task_id=task)

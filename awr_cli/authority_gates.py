"""Mandatory executable AWQ/AWG/UI gate sequence for runtime sessions."""

from __future__ import annotations

import hashlib
from typing import Any

from scripts.local_authority_transport import LocalAuthorityClient, make_request
from scripts.local_authority_bridge import AuthorityBridgeError, request_envelope


class AuthorityGates:
    """Consume authority observations in a fixed, non-skippable order.

    The local endpoints are qualification fixtures, not the production
    authorities. The runtime can consume outcomes but cannot manufacture them.
    """

    def __init__(self, client: LocalAuthorityClient):
        self.client = client

    @staticmethod
    def _request(authority: str, operation: str, revision: int, task: str, payload: str):
        operation_id = "OP-" + hashlib.sha256(f"{task}:{operation}".encode()).hexdigest()[:20].upper()
        return request_envelope(authority, operation_id, revision, payload, task_id=task)

    def admit(self, *, task: str, revision: int) -> dict[str, Any]:
        trace: list[dict[str, Any]] = []

        def ask(authority: str, operation: str, expected: set[str]) -> dict[str, Any]:
            observed = self.client.exchange(
                self._request(authority, operation, revision, task,
                              make_request(authority, operation, revision, task=task)["payload_digest"]),
                expected_revision=revision,
                required_authority=authority,
            )
            trace.append(observed)
            if observed["outcome"] not in expected:
                raise AuthorityBridgeError(f"mandatory_{authority}_gate_not_satisfied")
            return observed

        ask("coordinator", "COORDINATOR-ADMIT", {"observed"})
        ask("awq", "AWQ-EVIDENCE", {"accepted"})
        guidance = ask("awg", "AWG-GUIDANCE", {"approved", "requires_ui"})
        # UI is mandatory even when guidance is already marked approved: this
        # prevents an ambiguous worker interpretation from bypassing the board.
        ui = ask("ui", "UI-DECISION", {"approved"})
        return {
            "status": "admitted",
            "task": task,
            "task_revision": revision,
            "mandatory_order": ["coordinator", "awq", "awg", "ui"],
            "guidance": guidance["outcome"],
            "decision": ui["outcome"],
            "trace": trace,
            "authority_state": "observed_only",
        }

    def accept_artifact(self, *, task: str, revision: int, artifact_digest: str) -> dict[str, Any]:
        """Require post-execution quality, guidance, and human acceptance."""
        trace: list[dict[str, Any]] = []

        def ask(authority: str, operation: str, expected: set[str]) -> dict[str, Any]:
            original = make_request(authority, operation, revision, task=task)
            observed = self.client.exchange(self._request(authority, operation, revision, task,
                                                          original["payload_digest"]), expected_revision=revision, required_authority=authority)
            trace.append(observed)
            if observed["outcome"] not in expected:
                raise AuthorityBridgeError(f"mandatory_{authority}_acceptance_not_satisfied")
            return observed

        ask("awq", "AWQ-ARTIFACT", {"accepted"})
        ask("awg", "AWG-ARTIFACT", {"approved", "requires_ui"})
        decision = ask("ui", "UI-ARTIFACT", {"approved"})
        return {"status": "accepted", "artifact_digest": artifact_digest, "trace": trace, "decision": decision["outcome"], "authority_state": "observed_only"}

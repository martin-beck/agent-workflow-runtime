"""Mandatory executable AWQ/AWG/UI gate sequence for runtime sessions."""

from __future__ import annotations

from typing import Any

from scripts.local_authority_transport import LocalAuthorityClient, make_request
from scripts.local_authority_bridge import AuthorityBridgeError


class AuthorityGates:
    """Consume authority observations in a fixed, non-skippable order.

    The local endpoints are qualification fixtures, not the production
    authorities. The runtime can consume outcomes but cannot manufacture them.
    """

    def __init__(self, client: LocalAuthorityClient):
        self.client = client

    def admit(self, *, task: str, revision: int) -> dict[str, Any]:
        trace: list[dict[str, Any]] = []

        def ask(authority: str, operation: str, expected: set[str]) -> dict[str, Any]:
            observed = self.client.exchange(
                make_request(authority, operation, revision, task=task),
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

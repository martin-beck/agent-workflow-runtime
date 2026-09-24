"""Provider-neutral executable session lifecycle over the local host boundary."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Sequence

from .cli import CliError, canonical
from .host_supervisor import HostSupervisor


SESSION_ID = re.compile(r"^SES-[A-Z0-9-]{3,64}$")


class AgentSession:
    """Execute a deterministic adapter command and normalize its lifecycle."""

    def __init__(self, root: Path, session_id: str, adapter: str, *, sandboxed: bool = False):
        if not SESSION_ID.fullmatch(session_id) or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", adapter):
            raise CliError("session_identity_invalid")
        self.session_id = session_id
        self.adapter = adapter
        self.sandboxed = sandboxed
        self.supervisor = HostSupervisor(root)

    def run(self, argv: Sequence[str], cwd: Path, *, input_digest: str, timeout_seconds: float = 5.0) -> dict[str, Any]:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", input_digest):
            raise CliError("session_input_digest_invalid")
        events: list[dict[str, Any]] = [
            {"kind": "session_admitted", "session_id": self.session_id, "adapter": self.adapter, "input_digest": input_digest},
            {"kind": "session_started", "session_id": self.session_id},
        ]
        if self.sandboxed:
            from scripts.host_sandbox import HostSandbox, SandboxError
            try:
                result = HostSandbox(cwd).run(argv)
            except SandboxError as exc:
                raise CliError("sandbox_admission_failed") from exc
        else:
            result = self.supervisor.run(argv, cwd, timeout_seconds=timeout_seconds, require_network_disabled=False)
        output_digest = "sha256:" + hashlib.sha256(canonical({"stdout": result["stdout"], "stderr": result["stderr"], "returncode": result["returncode"]})).hexdigest()
        terminal = "completed" if result["status"] == "ok" else ("timed_out" if result["status"] == "timeout" else "failed")
        events.append({"kind": "session_terminal", "session_id": self.session_id, "status": terminal, "output_digest": output_digest})
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "adapter": self.adapter,
            "status": terminal,
            "events": events,
            "result": result,
            "network": "not_required_but_host_control_unverified",
            "sandbox": "enforced" if self.sandboxed else "not_required",
        }


def fake_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()

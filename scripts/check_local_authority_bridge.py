#!/usr/bin/env python3
"""Run deterministic, in-memory positive and hostile authority bridge cases."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.local_authority_bridge import (  # noqa: E402
    AUTHORITIES, AuthorityBridgeError, digest, request_envelope,
    response_envelope, validate_exchange,
)


def check() -> dict[str, Any]:
    """Exercise every authority without transport or persistent state."""
    outcomes = {"coordinator": "observed", "awq": "accepted", "awg": "requires_ui", "ui": "approved"}
    observations = []
    for index, authority in enumerate(sorted(AUTHORITIES), 1):
        request = request_envelope(
            authority, f"OP-LOCAL-{index}", 7, digest({"sample": index}),
            task_id="AR-LOCAL-1", requested_kind="evidence" if authority == "awq" else "observation",
        )
        response = response_envelope(request, outcomes[authority])
        observations.append(validate_exchange(request, response, expected_revision=7, required_authorities={authority}))
    return {
        "protocol": "awr-local-authority-bridge@1.0.0",
        "authorities": len(observations), "task_revision": 7,
        "outcomes": [item["outcome"] for item in observations],
        "network": "disabled", "durable_state": "not_performed",
    }


def main() -> int:
    print(json.dumps(check(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


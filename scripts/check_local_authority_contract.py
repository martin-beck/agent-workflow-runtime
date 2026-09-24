#!/usr/bin/env python3
"""Check the versioned local authority bridge contract and fixture corpus."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
AUTHORITIES = {"coordinator", "awq", "awg", "ui"}


def check(spec_path: Path | None = None, positive_path: Path | None = None, hostile_path: Path | None = None) -> dict[str, object]:
    spec = json.loads((spec_path or ROOT / "specifications/local-authority-bridge-v1.json").read_text())
    positive = json.loads((positive_path or ROOT / "specifications/fixtures/local-authority-bridge-positive-v1.json").read_text())
    hostile = json.loads((hostile_path or ROOT / "specifications/fixtures/local-authority-bridge-hostile-v1.json").read_text())
    if spec["schema_version"] != 1 or spec["version"] != "1.0.0" or set(spec["authorities"]) != AUTHORITIES:
        raise ValueError("invalid authority bridge specification")
    required = set(spec["binding"]["required"])
    if not required <= {"task_id", "task_revision", "project_revision", "worktree_digest", "session_id", "operation_id", "payload_digest"}:
        raise ValueError("invalid binding contract")
    if positive["protocol"] != {"id": "awr-local-authority-bridge", "version": "1.0.0"} or positive["task_revision"] < 1:
        raise ValueError("invalid positive fixture")
    for key in ("project_revision", "worktree_digest", "payload_digest"):
        if not DIGEST.fullmatch(positive[key]):
            raise ValueError("positive fixture digest mismatch")
    if len(positive["exchanges"]) != 4 or {item["authority"] for item in positive["exchanges"]} != AUTHORITIES:
        raise ValueError("positive fixture does not cover all authorities")
    if len(hostile) < 5 or not all(item.get("name") for item in hostile):
        raise ValueError("hostile fixture corpus incomplete")
    forbidden = set(spec["request"]["worker_forbidden_kinds"])
    if not forbidden == {"decision", "test", "specification"}:
        raise ValueError("worker mutation prohibition missing")
    return {"protocol": "awr-local-authority-bridge@1.0.0", "authorities": len(AUTHORITIES), "hostile_cases": len(hostile), "network": "disabled", "durable_state": "not_performed"}


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))

#!/usr/bin/env python3
"""Check optional provider/backend boundaries without invoking an adapter."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET = re.compile(r"(?:token|secret|password|api.?key|credential)\s*[:=]", re.I)


def check() -> dict[str, object]:
    spec = json.loads((ROOT / "specifications/optional-provider-boundary-v1.json").read_text())
    positive = json.loads((ROOT / "specifications/fixtures/optional-provider-boundary-positive-v1.json").read_text())
    hostile = json.loads((ROOT / "specifications/fixtures/optional-provider-boundary-hostile-v1.json").read_text())
    if spec["baseline"] != {"credentials": "not_required", "network": "disabled", "provider": "not_performed", "llm": "not_performed"}:
        raise ValueError("unsafe baseline")
    if positive["credential_reference"] is not None or positive["explicit_opt_in"] or positive["execution"] != "deterministic_local_mock" or positive["provider_e2e"] != "unverified" or positive["network"] != "disabled":
        raise ValueError("positive fixture claims external execution")
    if SECRET.search(json.dumps(hostile)) is None or len(hostile) != 5:
        raise ValueError("hostile boundary corpus incomplete")
    if spec["qualification"]["provider_e2e"] != "separate_direct_evidence_required":
        raise ValueError("provider evidence boundary missing")
    return {"status": "qualified_local_boundary", "provider": "not_performed", "network": "disabled", "hostile_cases": len(hostile)}


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))

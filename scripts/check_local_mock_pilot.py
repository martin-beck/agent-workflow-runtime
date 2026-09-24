#!/usr/bin/env python3
"""Checker for the deterministic local-mock pilot contract."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.local_mock_pilot import LocalMockError, validate


ROOT = Path(__file__).resolve().parents[1]


def main():
    spec = json.loads((ROOT / "specifications/local-mock-pilot-v1.json").read_text())
    fixture = json.loads((ROOT / "specifications/fixtures/local-mock-pilot-ar0068-v1.json").read_text())
    if spec["task"] != {"id": "AR-0068", "revision": 9}:
        raise LocalMockError("wrong task binding")
    if spec["boundary"] != {"local_execution": True, "network": "disabled", "external_provider": "not_performed", "credentials": "not_supplied"}:
        raise LocalMockError("unsafe execution boundary")
    validate(fixture)
    print("ok: AR-0068 local mock pilot")


if __name__ == "__main__":
    main()

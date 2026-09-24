#!/usr/bin/env python3
"""Run the deterministic local project workflow or validate a supplied trace."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from awr_cli.cli import CliError, validate_manifest
from scripts.local_project_workflow import WorkflowError, run, validate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--record", type=Path, help="validate this JSON trace instead of generating a local mock trace")
    parser.add_argument("--expected-revision", help="require the exact sha256 project manifest revision")
    args = parser.parse_args(argv)
    try:
        manifest, revision = validate_manifest(args.manifest.read_bytes())
        if args.expected_revision is not None and args.expected_revision != revision:
            raise WorkflowError("stale_project_revision")
        if args.record:
            record = json.loads(args.record.read_text(encoding="utf-8"))
            result = validate(record, revision)
            if record["project"]["name"] != manifest["project"]["name"]:
                raise WorkflowError("project_manifest_mismatch")
        else:
            record = run(args.manifest.read_bytes(), revision)
            result = validate(record, revision)
        print(json.dumps({"result": result, "record": record}, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, json.JSONDecodeError, CliError, WorkflowError) as exc:
        print(f"local-project-workflow: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


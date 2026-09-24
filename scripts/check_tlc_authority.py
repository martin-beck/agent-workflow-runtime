#!/usr/bin/env python3
"""Run the repository-pinned AR-0099 TLC model, fail closed.

This runner is intentionally boring: it never downloads a verifier, invokes a
provider, or falls back to the AR-0098 Python model.  A missing Java runtime,
missing JAR, or digest mismatch is an error, not a skipped check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JAR = ROOT / "formal" / "authority" / "tla2tools.jar"
DEFAULT_MODULE = ROOT / "formal" / "authority" / "AuthorityInteraction.tla"
DEFAULT_CONFIG = ROOT / "formal" / "authority" / "AuthorityInteraction.cfg"
DEFAULT_LIVENESS_CONFIG = ROOT / "formal" / "authority" / "AuthorityInteractionLiveness.cfg"
DEFAULT_CHANGE_CONFIG = ROOT / "formal" / "authority" / "AuthorityInteractionChange.cfg"
DEFAULT_REPAIR_CONFIG = ROOT / "formal" / "authority" / "AuthorityInteractionRepair.cfg"
DEFAULT_FIXTURE = ROOT / "specifications" / "fixtures" / "authority-interaction-ar0099-v1.json"
AR0098_SPEC = ROOT / "specifications" / "authority-interaction-v1.json"
PINNED_SHA256 = "b658b4e504fdf0b721caf7066320f6b6fe5805f4dd2f717d0e47baba4097205e"
SUCCESS_MARKER = "No error has been found"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_command(jar: Path, module: Path, config: Path) -> list[str]:
    java = shutil.which("java")
    if java is None:
        raise RuntimeError("TLC unavailable: java is not installed")
    for label, path in (("TLC JAR", jar), ("TLA module", module), ("TLC config", config)):
        if not path.is_file():
            raise RuntimeError(f"TLC unavailable: {label} is missing: {path}")
    actual = _sha256(jar)
    if actual != PINNED_SHA256:
        raise RuntimeError(
            f"TLC unavailable: JAR SHA-256 mismatch: expected {PINNED_SHA256}, got {actual}"
        )
    return [java, "-cp", str(jar), "tlc2.TLC", "-config", str(config), str(module)]


def validate_refinement_fixture(path: Path = DEFAULT_FIXTURE) -> None:
    """Ensure the TLA scenarios remain bound to the AR-0098 vocabulary."""
    try:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        ar0098 = json.loads(AR0098_SPEC.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"malformed AR-0099 refinement fixture: {exc}") from exc
    if fixture.get("schema_version") != 1 or fixture.get("ar") != "AR-0099":
        raise RuntimeError("AR-0099 refinement fixture binding is invalid")
    target = fixture.get("refinement_target", {})
    if target != {
        "specification": "specifications/authority-interaction-v1.json",
        "protocol": ar0098.get("specification_id"),
        "version": ar0098.get("version"),
    }:
        raise RuntimeError("AR-0099 fixture does not bind the AR-0098 specification")
    operations = set(ar0098.get("operations", {}))
    model_only = {"repair", "guidance"}
    for path_operations in fixture.get("positive_paths", []):
        if not set(path_operations) <= operations | model_only:
            raise RuntimeError("AR-0099 positive path contains an unmapped AR-0098 operation")
    required = {"dispatch", "continue", "request_completion", "commit"}
    if not required <= operations:
        raise RuntimeError("AR-0098 refinement vocabulary is missing a mandatory gate")
    invariants = " ".join(ar0098.get("invariants", []))
    for term in ("refinement", "test-change", "specification-change", "repair"):
        if term not in invariants:
            raise RuntimeError(f"AR-0098 invariant vocabulary missing {term}")
    for key in ("model", "config", "liveness_config", "change_config", "repair_config"):
        if not (ROOT / fixture[key]).is_file():
            raise RuntimeError(f"AR-0099 fixture path is missing: {fixture[key]}")
    if fixture.get("jar_sha256") != PINNED_SHA256:
        raise RuntimeError("AR-0099 fixture JAR pin does not match the runner")


def run_one(jar: Path, module: Path, config: Path) -> int:
    try:
        command = build_command(jar, module, config)
    except RuntimeError as exc:
        print(f"FAIL CLOSED: {exc}", file=sys.stderr)
        return 2
    environment = os.environ.copy()
    environment.pop("TLA_TOOLS_JAR_URL", None)
    with tempfile.TemporaryDirectory(prefix="awr-ar0099-tlc-") as metadir:
        command = [*command[:4], "-metadir", metadir, *command[4:]]
        try:
            completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, env=environment, check=False)
        except OSError as exc:
            print(f"FAIL CLOSED: unable to execute TLC: {exc}", file=sys.stderr)
            return 2
    output = completed.stdout + completed.stderr
    print(output, end="")
    if completed.returncode != 0:
        print(f"FAIL CLOSED: TLC exited with status {completed.returncode}", file=sys.stderr)
        return completed.returncode or 1
    if SUCCESS_MARKER not in output:
        print("FAIL CLOSED: TLC did not emit its success marker", file=sys.stderr)
        return 3
    return 0


def run(jar: Path, module: Path, configs: tuple[Path, ...], fixture: Path = DEFAULT_FIXTURE) -> int:
    try:
        validate_refinement_fixture(fixture)
    except RuntimeError as exc:
        print(f"FAIL CLOSED: {exc}", file=sys.stderr)
        return 2
    for selected_config in configs:
        result = run_one(jar, module, selected_config)
        if result:
            return result
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=Path, default=Path(os.environ.get("TLC_JAR", DEFAULT_JAR)))
    parser.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--liveness-config", type=Path, default=DEFAULT_LIVENESS_CONFIG)
    parser.add_argument("--change-config", type=Path, default=DEFAULT_CHANGE_CONFIG)
    parser.add_argument("--repair-config", type=Path, default=DEFAULT_REPAIR_CONFIG)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args(argv)
    configs = tuple(path.resolve() for path in (args.config, args.liveness_config, args.change_config, args.repair_config))
    return run(args.jar.resolve(), args.module.resolve(), configs, args.fixture.resolve())


if __name__ == "__main__":
    raise SystemExit(main())

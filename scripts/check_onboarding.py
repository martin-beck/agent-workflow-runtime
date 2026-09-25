#!/usr/bin/env python3
"""Check that the provider-free onboarding walkthrough names supported commands."""

from __future__ import annotations

import json
import re
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "docs/getting-started.md"
REQUIRED = ("awr install", "awr project-init", "awr project-register", "awr project-list", "awr local-run", "awr board-acceptance", "awr audit-status", "awr security-check")
FORBIDDEN = re.compile(r"(?:API_KEY|OPENAI_" + r"API_KEY|provider login|connect to|curl https?://)", re.I)


def check(path: Path = DOC) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    missing = [command for command in REQUIRED if command not in text]
    if missing:
        raise ValueError("onboarding command missing: " + ",".join(missing))
    if FORBIDDEN.search(text):
        raise ValueError("onboarding requires external provider or credential")
    if "provider-free" not in text or "does not claim" not in text:
        raise ValueError("onboarding boundary missing")
    return {"status": "qualified", "commands": len(REQUIRED), "provider": "not_performed", "network": "disabled"}


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))

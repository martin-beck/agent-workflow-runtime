#!/usr/bin/env python3
"""Offline fail-closed checker for AR-0008."""
import argparse, hashlib, json, sys
from pathlib import Path
try:
    from scripts.privacy_safe_journal import JournalError, canonical_bytes, sha256, validate_journal
except ModuleNotFoundError:  # Direct execution from the repository's scripts directory.
    from privacy_safe_journal import JournalError, canonical_bytes, sha256, validate_journal

CHECKER = "awr-journal-checker/1.0.0"

def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise JournalError(f"malformed JSON: {exc}") from exc

def validate_spec(spec):
    if not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-privacy-safe-event-journal" or spec.get("version") != "1.0.0":
        raise JournalError("unsupported specification")

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--journal", required=True, type=Path); parser.add_argument("--evidence", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, journal, evidence = load(args.spec), load(args.journal), load(args.evidence)
        validate_spec(spec); result = validate_journal(journal, args.expected_revision)
        expected_spec = sha256(canonical_bytes(spec))
        if evidence != {"checker": CHECKER, "task_revision": args.expected_revision, "specification_digest": expected_spec, "journal_digest": sha256(canonical_bytes(journal)), "safe_digest": evidence["safe_digest"]}:
            raise JournalError("malformed evidence")
        safe = dict(evidence); safe.pop("safe_digest")
        if evidence["safe_digest"] != sha256(canonical_bytes(safe)):
            raise JournalError("evidence digest mismatch")
        if evidence["task_revision"] != args.expected_revision or evidence["journal_digest"] != sha256(canonical_bytes(journal)):
            raise JournalError("stale or mismatched evidence")
    except (JournalError, KeyError, TypeError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr); return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": expected_spec}, sort_keys=True, separators=(",", ":"))); return 0

if __name__ == "__main__":
    raise SystemExit(main())

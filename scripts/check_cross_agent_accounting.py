#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.cross_agent_accounting import AccountingError, compare


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--spec", required=True, type=Path)
    p.add_argument("--fixture", required=True, type=Path)
    p.add_argument("--expected-revision", required=True, type=int)
    a = p.parse_args(argv)
    try:
        s = json.loads(a.spec.read_text())
        f = json.loads(a.fixture.read_text())
        if (
            a.expected_revision != 3
            or s.get("task") != {"id": "AR-0090", "revision": 3}
            or s.get("offline", {}).get("execute") is not False
        ):
            raise AccountingError("invalid_specification")
        if len(f.get("runs", [])) < 2:
            raise AccountingError("fixture_needs_two_runs")
        result = compare(f["runs"])
        expected = f.get("expected")
        if expected != result:
            raise AccountingError("fixture_result_mismatch")
        print(
            json.dumps(
                {"checker": "awr-cross-agent-accounting-checker/1.0.0", **result},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, json.JSONDecodeError, KeyError, TypeError, AccountingError) as e:
        print("REJECT: " + str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

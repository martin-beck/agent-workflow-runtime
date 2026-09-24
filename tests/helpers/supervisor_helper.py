#!/usr/bin/env python3
"""Repository-owned deterministic helper used only by AR-0083 tests."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("success", "sleep", "child", "output", "env", "json", "value", "fail")
    )
    parser.add_argument("value", nargs="?", default="")
    args = parser.parse_args()
    if args.mode == "success":
        print("helper-ok", flush=True)
        return 0
    if args.mode == "sleep":
        time.sleep(float(args.value or "5"))
        print("helper-woke", flush=True)
        return 0
    if args.mode == "child":
        child = subprocess.Popen(
            [sys.executable, __file__, "sleep", "5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"child={child.pid}", flush=True)
        time.sleep(float(args.value or "5"))
        return 0
    if args.mode == "output":
        print("token=TOPSECRET " + ("x" * int(args.value or "100000")), flush=True)
        return 0
    if args.mode == "env":
        print(
            "HOME="
            + os.environ.get("HOME", "")
            + " TOKEN="
            + os.environ.get("TOKEN", ""),
            flush=True,
        )
        return 0
    if args.mode == "json":
        print('{"value":1,"status":"ok"}', flush=True)
        return 0
    if args.mode == "value":
        print(args.value, flush=True)
        return 0
    print("password=FAILURE", file=sys.stderr, flush=True)
    return 7


if __name__ == "__main__":
    raise SystemExit(main())

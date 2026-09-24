#!/usr/bin/env python3
"""Repository-owned deterministic helper for AR-0085 only.

It accepts bounded opaque digests rather than prompts and emits a local
LiteLLM-shaped mock envelope.  The interrupt mode intentionally waits until
the AR-0083 supervisor cancels its process group.
"""

from __future__ import annotations

import argparse
import json
import time


def envelope(profile: str, request_digest: str, ordinal: int, stream: bool) -> dict[str, object]:
    suffix = request_digest.removeprefix("sha256:")[:16]
    return {
        "id": f"local-mock-{suffix}-{ordinal}",
        "object": "chat.completion.chunk" if stream else "chat.completion",
        "model": "local-deterministic-mock",
        "choices": [
            {
                "index": 0,
                "finish_reason": None if stream else "stop",
                "delta": {"content": f"mock:{profile}:{suffix}:{ordinal}"} if stream else {},
                "message": {} if stream else {"role": "assistant", "content": f"mock:{profile}:{suffix}:{ordinal}"},
            }
        ],
        "usage": {"input_units": 0, "output_units": 0, "total_units": 0},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("start", "request", "stream", "interrupt", "resume", "close"))
    parser.add_argument("profile")
    parser.add_argument("request_digest")
    parser.add_argument("ordinal", type=int)
    args = parser.parse_args()
    if args.mode == "interrupt":
        time.sleep(30)
        return 0
    if args.mode == "stream":
        print(json.dumps(envelope(args.profile, args.request_digest, args.ordinal, True), separators=(",", ":")), flush=True)
    else:
        print(json.dumps(envelope(args.profile, args.request_digest, args.ordinal, False), separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

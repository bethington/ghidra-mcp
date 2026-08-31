#!/usr/bin/env python3
"""Simple health probe for the local Ghidra MCP HTTP server.

Checks `check_connection` with retry logic so tasks can verify server readiness
right after deployment/startup.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def _probe(url: str, timeout: float) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        body = response.read(4096).decode("utf-8", "replace")
        return response.status, body


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe Ghidra MCP server health")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8089/check_connection",
        help="Health endpoint URL (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-request timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=10,
        help="Number of attempts before failing (default: %(default)s)",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Delay between attempts in seconds (default: %(default)s)",
    )
    args = parser.parse_args()

    last_error = None
    for attempt in range(1, args.retries + 1):
        try:
            status, body = _probe(args.url, args.timeout)
            print(f"STATUS={status}")
            print(body)
            if status == 200:
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict):
                        state = parsed.get("status") or parsed.get("message") or "ok"
                        print(f"HEALTH={state}")
                except json.JSONDecodeError:
                    pass
                return 0
            last_error = f"Unexpected HTTP status {status}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)

        if attempt < args.retries:
            print(f"Attempt {attempt}/{args.retries} failed: {last_error}")
            time.sleep(args.retry_delay)

    print(f"ERROR={last_error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

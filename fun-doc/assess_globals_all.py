#!/usr/bin/env python3
"""assess_globals_all.py -- re-score globals across every project binary.

The globals assess pass is idempotent and cheap (~15ms per address, measured), so
the honest thing is to run it over everything rather than maintain a cache that
can go stale. It previously DID maintain one -- it skipped any global already
carrying a DOC rung -- and the result was that 2,142 of D2Common's 2,231 globals
were frozen at whatever band they had when first seen. Re-running the sweep after
that gate was removed moved D2Common from "2,060 unscored" to 77% COMPLETE_100:
the work had been done all along, the dashboard just could not see it.

Run this after any bulk globals work, or whenever a Globals bar looks suspiciously
empty. Sequential on purpose -- these all hit one Ghidra HTTP server, and running
them concurrently just queues inside Ghidra while making failures harder to read.

  python assess_globals_all.py                 # every binary
  python assess_globals_all.py --skip D2Common.dll D2Client.dll
  python assess_globals_all.py --only BH.dll
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import conformance_dashboard as cd

SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON = str(SCRIPT_DIR / ".venv" / "Scripts" / "python.exe")
if not Path(PYTHON).exists():          # non-Windows / no venv -> current interpreter
    PYTHON = sys.executable


def _band_line(program):
    try:
        b = cd.glob_bands(program)
        n = b["in_scope"] or 1
        return (b, f"{b['bands']['COMPLETE_100']}/{b['in_scope']} at 100 "
                   f"({100 * b['bands']['COMPLETE_100'] / n:.1f}%), "
                   f"{b['untagged']} unscored")
    except Exception as exc:           # noqa: BLE001 — reporting only
        return None, f"(read failed: {type(exc).__name__})"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip", nargs="*", default=[], help="binary names to skip")
    ap.add_argument("--only", nargs="*", default=[], help="only these binary names")
    ap.add_argument("--timeout", type=int, default=900, help="per-binary seconds")
    args = ap.parse_args(argv)

    binaries = cd.list_binaries()["binaries"]
    if args.only:
        want = {s.lower() for s in args.only}
        binaries = [b for b in binaries if b["name"].lower() in want]
    if args.skip:
        skip = {s.lower() for s in args.skip}
        binaries = [b for b in binaries if b["name"].lower() not in skip]

    print(f"re-scoring globals across {len(binaries)} binaries\n")
    moved, failed, t0 = [], [], time.time()

    for i, b in enumerate(binaries, 1):
        before, before_s = _band_line(b["path"])
        print(f"[{i}/{len(binaries)}] {b['name']}")
        print(f"    before: {before_s}")
        try:
            r = subprocess.run(
                [PYTHON, "-u", str(SCRIPT_DIR / "fun_doc.py"), "--assess",
                 "--assess-globals-only", "--binary", b["path"]],
                cwd=str(SCRIPT_DIR), capture_output=True, text=True,
                timeout=args.timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"    TIMEOUT after {args.timeout}s")
            failed.append((b["name"], "timeout"))
            continue
        if r.returncode != 0:
            tail = (r.stdout or r.stderr or "").strip().splitlines()[-1:] or ["(no output)"]
            print(f"    rc={r.returncode}: {tail[0][:120]}")
            failed.append((b["name"], f"rc={r.returncode}"))
            continue

        after, after_s = _band_line(b["path"])
        print(f"    after : {after_s}")
        if before and after:
            d100 = after["bands"]["COMPLETE_100"] - before["bands"]["COMPLETE_100"]
            dunsc = after["untagged"] - before["untagged"]
            if d100 or dunsc:
                moved.append((b["name"], d100, dunsc))
                print(f"    -> COMPLETE_100 {d100:+d}, unscored {dunsc:+d}")
        print()

    print("=" * 62)
    print(f"done in {time.time() - t0:.0f}s — {len(binaries)} binaries, "
          f"{len(moved)} changed, {len(failed)} failed")
    for name, d100, dunsc in sorted(moved, key=lambda t: -abs(t[1])):
        print(f"  {name:<26} COMPLETE_100 {d100:+6d}   unscored {dunsc:+6d}")
    for name, why in failed:
        print(f"  FAILED {name}: {why}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

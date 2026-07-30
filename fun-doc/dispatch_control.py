#!/usr/bin/env python3
"""dispatch_control.py -- drive D2Debugger's live shadow dispatchers.

The oracle has always exposed mode control (POST /dispatchers/mode for all,
POST /dispatcher/{i}/mode for one), but only through raw HTTP or the in-game
ImGui panel -- so in practice modes got flipped by hand. This is the wrapper,
so an agent or a script can run a CONTROLLED shadow experiment instead of
"shadow everything and hope".

Why controlled matters: shadow mode runs BOTH original and reimpl on every real
call. Applied to all 102 dispatchers at once that includes functions taking
~1M calls/sec, and the patch directory still carries a
`D2Common.dll.CRASHED_114disp_*` artifact from a previous all-at-once change.
Start narrow, widen once it holds.

Shadow mode alone proves NOTHING without a bound reimpl: with the provider
unloaded the thunk returns before the comparison, so hits climb while
divergences and distinct_inputs stay 0. Check `status` first.

Usage:
    python dispatch_control.py status
    python dispatch_control.py enter-game        # any state -> in a saved world
    python dispatch_control.py list [--shadow] [--hot N]
    python dispatch_control.py set-all original|shadow|reimpl
    python dispatch_control.py set NAME_OR_INDEX [...] --mode shadow
    python dispatch_control.py load-provider
    python dispatch_control.py watch [--seconds N] [--interval S]
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request

ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790").rstrip("/")
MODES = ("original", "reimpl", "shadow")


def _req(path, body=None, timeout=15):
    url = f"{ORACLE_URL}/{path.lstrip('/')}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method="POST" if data is not None else "GET",
        headers={"Content-Type": "application/json"} if data is not None else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def dispatchers():
    return _req("/dispatchers").get("dispatchers", []) or []


def resolve(token, ds):
    """Accept a dispatcher index or a (case-insensitive) name."""
    if str(token).isdigit():
        return int(token)
    lowered = str(token).lower()
    for d in ds:
        if d["name"].lower() == lowered:
            return d["index"]
    raise SystemExit(f"no dispatcher named {token!r} (try `list`)")


def cmd_status(_args):
    st = _req("/status")
    ds = dispatchers()
    modes = {}
    for d in ds:
        modes[d.get("modeName")] = modes.get(d.get("modeName"), 0) + 1
    sampler = bool(ds) and "distinct_inputs" in ds[0] and "arg_count" in ds[0]
    print(f"oracle      : {ORACLE_URL}")
    print(f"bridge      : {st.get('bridge')}   dispatchers: {st.get('dispatchers')}")
    print(f"provider    : {st.get('provider')}   reloadSeq: {st.get('reloadSeq')}")
    print(f"modes       : {modes}")
    print(f"sampler     : {'PRESENT' if sampler else 'ABSENT (patch DLL predates it)'}")
    if not sampler:
        print("  -> battletest_promoter will refuse to promote (fails closed).")
    if "not loaded" in str(st.get("provider", "")):
        print("  !! provider NOT loaded: shadow mode counts calls but runs no")
        print("     comparison, so divergences and distinct_inputs stay 0.")


def cmd_list(args):
    ds = dispatchers()
    if args.shadow:
        ds = [d for d in ds if d.get("modeName") == "shadow"]
    ds = sorted(ds, key=lambda d: -d.get("hits", 0))
    if args.hot:
        ds = ds[:args.hot]
    print(f"{'idx':>4}  {'name':<40} {'mode':<9} {'hits':>12} {'div':>6} "
          f"{'distinct':>9} {'argc':>5}")
    for d in ds:
        print(f"{d['index']:>4}  {d['name']:<40} {d.get('modeName',''):<9} "
              f"{d.get('hits',0):>12} {d.get('divergences',0):>6} "
              f"{str(d.get('distinct_inputs','-')):>9} {str(d.get('arg_count','-')):>5}")
    print(f"\n{len(ds)} shown")


def cmd_set_all(args):
    print(_req("/dispatchers/mode", {"mode": args.mode}))


def cmd_set(args):
    ds = dispatchers()
    for token in args.targets:
        i = resolve(token, ds)
        r = _req(f"/dispatcher/{i}/mode", {"mode": args.mode})
        d = r.get("dispatcher", {})
        print(f"  [{i}] {d.get('name', token)} -> {d.get('modeName', r)}")


def cmd_load_provider(_args):
    r = _req("/reimpl/reload", {})
    print(f"provider: {r.get('provider')}  reloadSeq: {r.get('reloadSeq')}")


def _gameplay_moving(seconds=4):
    """Are gameplay dispatchers accruing hits? The only RELIABLE in-world test.

    /status's charSelectReady is False both at the title screen AND in-world, so
    it cannot distinguish "not there yet" from "already playing" -- reading it
    as the former is what left the operator to load the game by hand.
    """
    a = {d["name"]: d.get("hits", 0) for d in dispatchers()}
    if not a:
        return False
    time.sleep(seconds)
    b = {d["name"]: d.get("hits", 0) for d in dispatchers()}
    return sum(1 for n in b if b[n] > a.get(n, 0)) > 0


def cmd_enter_game(args):
    """Get from ANY state to in-world, deterministically.

    States handled: already in-world (no-op), character-select (launch), title
    screen (single-player -> wait for the list -> launch). Every step verifies
    the transition actually happened rather than trusting the action's return
    value -- /action/* reports success when the CALL succeeded, not when the
    game moved, and both exit actions have already been observed returning
    ok:true while nothing changed.
    """
    deadline = time.monotonic() + args.timeout

    if _gameplay_moving(3):
        print("already in-world (gameplay dispatchers accruing hits)")
        return 0

    while time.monotonic() < deadline:
        st = _req("/status")
        if st.get("charSelectReady"):
            r = _req("/action/launch-character",
                     {"confirm": True, "difficulty": args.difficulty, "timeoutMs": 8000})
            print(f"launch-character -> {r.get('ok')} {r.get('error') or ''}")
            # Verify by OUTCOME, not by the action's own say-so.
            for _ in range(int(args.timeout // 4)):
                if _gameplay_moving(4):
                    print("in-world confirmed (hits climbing)")
                    return 0
            print("launch reported ok but no gameplay traffic appeared")
            return 1
        if st.get("charListLoaded") is False and not st.get("charSelectReady"):
            # Title screen (or still loading). Nudge to single-player; harmless
            # and SEH-guarded if we are already past it.
            r = _req("/action/main-menu-singleplayer", {"confirm": True, "timeoutMs": 8000})
            if not r.get("ok"):
                # Expected when already past the title -- keep polling rather
                # than treating it as fatal.
                pass
        time.sleep(2)

    print(f"timed out after {args.timeout}s without reaching a world")
    return 1


def cmd_watch(args):
    """Sample the counters over time -- the only way to tell a live shadow
    comparison from a dispatcher that is merely counting calls."""
    end = time.monotonic() + args.seconds
    first = None
    while True:
        ds = [d for d in dispatchers() if d.get("modeName") == "shadow"]
        active = [d for d in ds if d.get("distinct_inputs", 0) > 0]
        tot_div = sum(d.get("divergences", 0) for d in ds)
        snap = (len(active), sum(d.get("distinct_inputs", 0) for d in ds), tot_div)
        if first is None:
            first = snap
        print(f"  shadow={len(ds):<4} sampling={snap[0]:<4} "
              f"distinct_total={snap[1]:<6} divergences={snap[2]}")
        if time.monotonic() >= end:
            break
        time.sleep(args.interval)
    print(f"\ndelta over {args.seconds}s: sampling {first[0]}->{snap[0]}, "
          f"distinct {first[1]}->{snap[1]}, divergences {first[2]}->{snap[2]}")
    if snap[1] == 0:
        print("NO distinct inputs recorded -- either no reimpl is bound (check "
              "`status`) or the shadowed functions were never called.")


def main():
    ap = argparse.ArgumentParser(description="Drive D2Debugger shadow dispatchers.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status").set_defaults(fn=cmd_status)

    p = sub.add_parser("list")
    p.add_argument("--shadow", action="store_true", help="only shadow-mode entries")
    p.add_argument("--hot", type=int, help="only the N hottest")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("set-all")
    p.add_argument("mode", choices=MODES)
    p.set_defaults(fn=cmd_set_all)

    p = sub.add_parser("set")
    p.add_argument("targets", nargs="+", help="dispatcher names or indices")
    p.add_argument("--mode", choices=MODES, required=True)
    p.set_defaults(fn=cmd_set)

    sub.add_parser("load-provider").set_defaults(fn=cmd_load_provider)

    p = sub.add_parser("enter-game", help="get into a saved single-player world from any state")
    p.add_argument("--difficulty", type=int, default=0, help="0=Normal 1=Nightmare 2=Hell")
    p.add_argument("--timeout", type=int, default=90)
    p.set_defaults(fn=cmd_enter_game)

    p = sub.add_parser("watch")
    p.add_argument("--seconds", type=int, default=30)
    p.add_argument("--interval", type=float, default=5.0)
    p.set_defaults(fn=cmd_watch)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Audit manifest `args` count against the callee's ACTUAL stack cleanup.

Companion to audit_ret_widths.py, and the same lesson one level worse.

ret_bits being wrong costs you FALSE DIVERGENCES -- noisy, misleading, but the
game keeps running. The arg count being wrong on a __stdcall dispatcher costs
you the PROCESS. stdcall is callee-cleans: the real function ends in `RET n`
where n = 4 * argc. The generated thunk is declared with its own argument list
and emits its own `RET n`. If the manifest says 1 arg and the function really
takes 2, the thunk pops 4 bytes where the caller expected 8 to go -- ESP is off
by a dword for the rest of that call chain and the next return dereferences
whatever is now under it. The observed signature is an ACCESS_VIOLATION with
`eip` holding a small nonsense value (0x140 in the 2026-07-30 crash) rather
than any address in any loaded module.

So, exactly as with return width: the DISASSEMBLY is the authority, not
Ghidra's inferred signature. Ghidra's parameter list on an undocumented leaf is
a guess; `RET 0x8` is a fact the compiler emitted.

    RET 0x8   -> 2 args     RET 0x4  -> 1 arg     RET (bare) -> 0 args *
    RET 0xC   -> 3 args     RET 0x10 -> 4 args

  * A bare `RET` means the CALLER cleans, i.e. cdecl -- which for a manifest
    entry declared `stdcall` is itself a mismatch worth reporting.

fastcall is checked too but reads differently: the first two dword args arrive
in ECX/EDX and are NOT on the stack, so the cleanup is 4 * max(0, argc - 2).

Read-only. Prints findings; never edits a manifest.

Usage:
    python -m scripts.audit_stdcall_argc
    python -m scripts.audit_stdcall_argc --program D2Client.dll
    python -m scripts.audit_stdcall_argc --only-new conformance/shadow_manifest.json.bak_preharvest2
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import requests

GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")
D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))

MODULES = {
    "D2Common.dll": (0x6FD50000, D2MOO_REPO / "conformance" / "shadow_manifest.json"),
    "D2Client.dll": (0x6FAB0000, D2MOO_REPO / "conformance" / "shadow_manifest.D2Client.json"),
}

_SESSION = requests.Session()
_RET = re.compile(r"^RET\s*(0x[0-9a-f]+|\d+)?\s*$", re.I)


def _norm(raw):
    return raw if isinstance(raw, int) else int(str(raw), 0)


def _disasm(addr, program):
    try:
        return _SESSION.get(f"{GHIDRA_HTTP}/disassemble_function",
                            params={"address": f"0x{addr:x}", "program": program},
                            timeout=30).json().get("instructions", []) or []
    except Exception:
        return []


def observed_cleanup(ins):
    """Bytes the callee pops on return, or None if the paths disagree/are absent.

    Every return path in a single function must pop the same amount -- the
    calling convention is a property of the function, not of the path. If they
    disagree, the disassembly is being misread (or the range covers two
    functions), so report undetermined rather than pick one.
    """
    pops = set()
    for i in ins:
        m = _RET.match(i.get("instruction", "").strip())
        if m:
            pops.add(int(m.group(1), 0) if m.group(1) else 0)
    if len(pops) != 1:
        return None
    return pops.pop()


def expected_cleanup(callconv, argc):
    """Bytes the callee should pop for this convention and arg count."""
    if callconv == "cdecl":
        return 0                                    # caller cleans
    if callconv == "fastcall":
        return 4 * max(0, argc - 2)                 # first two args in ECX/EDX
    return 4 * argc                                 # stdcall


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--program", default="D2Common.dll", choices=list(MODULES))
    ap.add_argument("--only-new", metavar="BASELINE_MANIFEST",
                    help="only audit entries absent from this baseline (by offset)")
    args = ap.parse_args()

    base, mpath = MODULES[args.program]
    entries = json.loads(mpath.read_text(encoding="utf-8"))["entries"]

    if args.only_new:
        bl = Path(args.only_new)
        if not bl.is_absolute():
            bl = D2MOO_REPO / bl
        seen = {_norm(e["offset"])
                for e in json.loads(bl.read_text(encoding="utf-8"))["entries"]}
        entries = [e for e in entries if _norm(e["offset"]) not in seen]
        print(f"{args.program}: auditing {len(entries)} entries new since "
              f"{Path(args.only_new).name}\n")
    else:
        print(f"{args.program}: auditing {len(entries)} manifest entries "
              f"against actual stack cleanup\n")

    bad, unknown, ok = [], [], 0
    for e in entries:
        # Class B is the void/out-param shape; its thunk still has to get the
        # arg count right, so it is NOT skipped here (unlike the ret-width
        # audit, where there is no return register to compare).
        off = _norm(e["offset"])
        cc = e.get("callconv", "stdcall")
        argc = len(e.get("args", []))
        ins = _disasm(base + off, args.program)
        if not ins:
            unknown.append((e["name"], "no disassembly"))
            continue
        obs = observed_cleanup(ins)
        if obs is None:
            unknown.append((e["name"], "no RET found, or return paths pop different amounts"))
            continue
        exp = expected_cleanup(cc, argc)
        if obs != exp:
            bad.append((e["name"], f"0x{off:x}", cc, argc, exp, obs, obs // 4))
        else:
            ok += 1

    print(f"MATCH: {ok}    MISMATCH: {len(bad)}    UNDETERMINED: {len(unknown)}\n")
    if bad:
        print("MISMATCHES -- each one misbalances ESP on every call (CRASH, not a divergence):")
        for n, off, cc, argc, exp, obs, real in bad:
            print(f"  {n:<44} {off:<9} {cc:<9} manifest argc={argc} "
                  f"(pops {exp}) but RET pops {obs} -> real argc={real}")
    if unknown:
        print(f"\nUNDETERMINED ({len(unknown)}) -- inspect by hand, do not guess:")
        for n, why in unknown[:25]:
            print(f"  {n:<44} {why}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())

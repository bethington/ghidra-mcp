#!/usr/bin/env python3
"""Explain WHY a dispatcher is never called, from its callers -- not from its name.

coverage_gaps.py answers "which functions lack coverage" and suggests an
activity, but that suggestion is INFERENCE FROM THE NAME ("ITEMS_* is probably
reached by handling items"). This answers the same question from EVIDENCE: walk
the call graph and see who actually reaches the function, then check which of
those callers are themselves live right now.

That distinction decides what to do:

  * A caller that IS being hit means the function is reachable from code the
    game is already running, so the gate is a CONDITION inside that caller --
    a specific item type, skill id, monster class or UI state. Worth chasing:
    the path is warm, you just have not met the predicate.
  * NO live caller anywhere up the chain means the whole subtree is cold. No
    amount of item-shuffling will reach it; something structural is missing
    (an unvisited act, an unopened screen, a game mode you are not in).
  * NO callers at all inside D2Common usually means the caller lives in
    ANOTHER MODULE -- D2Client and D2Game call into D2Common constantly, and
    Ghidra's D2Common program cannot see those references. That is a limit of
    this tool, not proof the function is dead.

Read-only. Needs the game running (live hit counts) and Ghidra on :8089.

Usage:
    python -m scripts.trace_triggers                 # every never-called dispatcher
    python -m scripts.trace_triggers --name SKILLS_GetSkillRange
    python -m scripts.trace_triggers --limit 15
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.request
from pathlib import Path

import requests

GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")
ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790").rstrip("/")
D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
MANIFEST = D2MOO_REPO / "conformance" / "shadow_manifest.json"
BASE = 0x6FD50000
PROGRAM = "D2Common.dll"

_S = requests.Session()


def oracle_dispatchers():
    with urllib.request.urlopen(f"{ORACLE_URL}/dispatchers", timeout=15) as r:
        return json.loads(r.read().decode("utf-8", "replace")).get("dispatchers", []) or []


def manifest_offsets():
    out = {}
    try:
        for e in json.loads(MANIFEST.read_text(encoding="utf-8"))["entries"]:
            raw = e["offset"]
            out[e["name"]] = BASE + (raw if isinstance(raw, int) else int(str(raw), 0))
    except Exception:
        pass
    return out


def callers_of(addr):
    """[(name, address)] of functions that call `addr`."""
    try:
        r = _S.get(f"{GHIDRA_HTTP}/get_function_callers",
                   params={"address": f"0x{addr:x}", "program": PROGRAM},
                   timeout=25).json()
    except Exception:
        return []
    out = []
    for c in (r.get("callers") or r.get("functions") or []):
        if isinstance(c, dict) and c.get("name"):
            out.append((c["name"], c.get("address")))
    return out


import re  # noqa: E402

CORRECTED_DEF = D2MOO_REPO / "conformance" / "corrected_defs" / "D2Common.1.13c.corrected.def"

# Every module in the PD2 process that could plausibly call into D2Common and
# is loaded as a Ghidra program. If a function is imported by NONE of these and
# called by nothing inside D2Common, nothing in the loaded set reaches it.
CALLER_PROGRAMS = ("D2Client.dll", "D2Game.dll", "ProjectDiablo.dll",
                   "PD2_EXT.dll", "Storm.dll", "SGD2FreeRes.dll",
                   "SGD2FreeDisplayFix.dll")


def export_ordinals():
    """name -> ordinal, from the corrected .def."""
    out = {}
    try:
        for line in CORRECTED_DEF.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"\s*(\w+)\s+@(\d+)", line)
            if m:
                out[m.group(1)] = int(m.group(2))
    except OSError:
        pass
    return out


def import_names(program):
    """Every import symbol name in `program` (fetched once, reused)."""
    try:
        r = _S.get(f"{GHIDRA_HTTP}/list_imports",
                   params={"program": program, "limit": 6000}, timeout=90).json()
    except Exception:
        return None
    items = r.get("imports") or r.get("items") or []
    return [str(i.get("name", "")) for i in items if isinstance(i, dict)]


def real_callers(addr):
    """Intra-D2Common callers, EXCLUDING the export-table entry.

    get_xrefs_to reports the export as a single `EXTERNAL` reference from
    "Entry Point". That is the symbol being exported, not a call site, and
    counting it makes every exported accessor look referenced.
    """
    try:
        r = _S.get(f"{GHIDRA_HTTP}/get_xrefs_to",
                   params={"address": f"0x{addr:x}", "program": PROGRAM, "limit": 50},
                   timeout=40).json()
    except Exception:
        return []
    out = []
    for x in (r.get("xrefs") or r.get("references") or []):
        if not isinstance(x, dict):
            continue
        if str(x.get("type", "")).upper() == "EXTERNAL":
            continue
        if str(x.get("from_address", "")).lower() == "entry point":
            continue
        out.append(x.get("function") or x.get("from_address"))
    return out


def classify(hits, offs):
    """Split never-called dispatchers into reachable vs unreachable."""
    ords = export_ordinals()
    tables = {}
    for p in CALLER_PROGRAMS:
        names = import_names(p)
        if names is not None:
            tables[p] = names
    print(f"import tables loaded: "
          f"{', '.join(f'{p}={len(v)}' for p, v in tables.items())}\n")

    never = sorted(n for n, h in hits.items() if h == 0)
    reachable, unreachable, unknown = [], [], []
    for name in never:
        addr = offs.get(name)
        if addr is None:
            unknown.append((name, "not in manifest"))
            continue
        inner = real_callers(addr)
        if inner:
            reachable.append((name, f"called inside D2Common by {inner[0]}"))
            continue
        o = ords.get(name)
        pat = re.compile(rf"(?<!\d){o}(?!\d)") if o else None
        importers = []
        for p, names in tables.items():
            for nm in names:
                if nm == name or (pat and pat.search(nm)):
                    importers.append(p)
                    break
        if importers:
            reachable.append((name, f"imported by {', '.join(importers)}"))
        elif o is None:
            unknown.append((name, "no ordinal in the corrected .def -- cannot check imports"))
        else:
            unreachable.append((name, o))
    return reachable, unreachable, unknown


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", help="trace a single function")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--classify", action="store_true",
                    help="split ALL never-called dispatchers into reachable vs "
                         "unreachable, using intra-module xrefs plus every "
                         "loaded module's import table")
    args = ap.parse_args()

    try:
        disp = oracle_dispatchers()
    except OSError as e:
        print(f"oracle unreachable: {e}"); return 2

    hits = {d["name"]: d.get("hits", 0) for d in disp}
    offs = manifest_offsets()

    if args.classify:
        reachable, unreachable, unknown = classify(hits, offs)
        total = len(reachable) + len(unreachable) + len(unknown)
        print(f"NEVER-CALLED DISPATCHERS: {total}\n")
        print(f"  REACHABLE   {len(reachable):>3}  a caller exists -- worth playing for")
        print(f"  UNREACHABLE {len(unreachable):>3}  NO caller in any loaded module")
        print(f"  UNKNOWN     {len(unknown):>3}  could not determine")
        if unreachable:
            print("\nUNREACHABLE -- nothing in the loaded module set calls these, so no")
            print("amount of gameplay will ever exercise them. They cannot promote and")
            print("should not be counted as coverage gaps:\n")
            for n, o in unreachable:
                print(f"   {n:<44} export @{o}")
        if reachable:
            print("\nREACHABLE -- these DO have a caller; the right activity reaches them:\n")
            for n, why in reachable:
                print(f"   {n:<44} {why}")
        if unknown:
            print("\nUNKNOWN:\n")
            for n, why in unknown:
                print(f"   {n:<44} {why}")
        return 0

    if args.name:
        targets = [args.name]
    else:
        targets = sorted(n for n, h in hits.items() if h == 0)[:args.limit]

    warm, cold, external = [], [], []
    for name in targets:
        addr = offs.get(name)
        if addr is None:
            external.append((name, "not in manifest"))
            continue
        cs = callers_of(addr)
        if not cs:
            external.append((name, "no callers inside D2Common -- caller is most "
                                   "likely in D2Client/D2Game, invisible here"))
            continue
        live = [(cn, hits.get(cn, 0)) for cn, _ in cs if hits.get(cn, 0) > 0]
        if live:
            warm.append((name, sorted(live, key=lambda t: -t[1]), len(cs)))
        else:
            cold.append((name, [cn for cn, _ in cs][:6], len(cs)))

    print(f"traced {len(targets)} never-called dispatcher(s)\n")

    if warm:
        print("WARM PATH -- a caller IS running, so the gate is a CONDITION inside it.")
        print("These are the reachable ones; find the predicate and satisfy it.\n")
        for name, live, ncall in warm:
            shown = ", ".join(f"{cn} ({h:,} hits)" for cn, h in live[:3])
            print(f"  {name}")
            print(f"      live caller(s): {shown}    [{ncall} caller(s) total]")

    if cold:
        print("\nCOLD SUBTREE -- no caller is running either. Something structural is")
        print("missing (an area, screen or game mode), not just the right item.\n")
        for name, cs, ncall in cold:
            print(f"  {name}")
            print(f"      callers (none live): {', '.join(cs)}"
                  + (f", +{ncall - len(cs)} more" if ncall > len(cs) else ""))

    if external:
        print("\nCALLER OUTSIDE D2Common (or unknown) -- this tool cannot see it:\n")
        for name, why in external[:20]:
            print(f"  {name:<44} {why}")

    print(f"\nsummary: {len(warm)} warm, {len(cold)} cold, {len(external)} external/unknown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

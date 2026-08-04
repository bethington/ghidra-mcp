"""Corpus sweep: find globals that a neighbouring type application destroyed.

Report-first with a dry-run default, like `crt_sweep.py` and `falsify_sweep.py`
before it -- read the JSON, then `--apply`.

THE BUG THIS SWEEPS UP (fixed 2026-08-03, but the damage is already on disk)

`set_global` cleared its whole extent with the exception swallowed, so applying
a type silently deleted any NAMED global it overlapped -- and still reported
success. Two shapes, both observed in a single PD2_EXT.dll pass:

    FORWARD     byte[256] at 0x10015179 ate g_abUppercaseCharTbl2_end at +1
                float10   at 0x10012e18 ate g_dwPosInfBits            at +8
    CONTAINING  three 4-byte writes inside g_apfnApiSlots destroyed the
                128-byte array they sat in

Each victim had been reported `completed` seconds earlier and was cached clean
for 7 days, so the worker would not revisit it. Worse, `/list_globals` resolves
the CONTAINING data unit, so it reports the EATER's type at the dead address --
the dashboard shows a destroyed global as perfectly typed. That is why this
sweep asks `audit_global` (which uses getDefinedDataAt) rather than reading the
inventory: the inventory cannot see the damage by construction.

WHAT IT REPORTS

    interior    the address sits inside a data unit that starts earlier.
                Ghidra shows the container's type here; the global itself has
                no type at all. `container` names the eater.
    orphaned    untyped with no container -- either never typed, or its data
                was cleared outright (the CONTAINING shape above). Only
                reported when the global was previously cached clean, since
                that combination means something typed it and then it stopped
                being typed.

WHAT IT WRITES (only with --apply)

    NOTHING in Ghidra. Re-typing these needs a judgement call the sweep cannot
    make -- either the container's length is wrong or the interior symbol
    should not exist. All --apply does is FORGET the victims' clean-cache
    entries so the globals worker stops skipping them and re-works them
    normally. That is deliberately the whole write surface.

USAGE

    python fun-doc/scripts/audit_evicted_globals.py --folder /Mods/PD2-S12
    python fun-doc/scripts/audit_evicted_globals.py --program /Mods/PD2-S12/D2Common.dll
    python fun-doc/scripts/audit_evicted_globals.py --folder /Mods/PD2-S12 --apply
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import conformance_dashboard as cd                              # noqa: E402
import fun_doc as fd                                            # noqa: E402

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")


def _audit(program: str, address: str) -> dict | None:
    url = (f"{GHIDRA}/audit_global?program={urllib.parse.quote(program, safe='')}"
           f"&address={address}")
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _global_addresses(program: str) -> list[tuple[str, str, str]]:
    """(address, name, list_globals_type) for every in-image global, deduped by
    address. The type is carried purely so the report can show what the
    inventory CLAIMS versus what audit_global finds."""
    try:
        rng = cd._image_range(program)
        txt = cd._get("/list_globals", program=program, limit=100000)
    except OSError:
        return []
    lo, hi = rng or (cd._IMG_LO, cd._IMG_HI)
    out, seen = [], set()
    for ln in cd._envelope_items(txt, "globals"):
        m = cd._GLOB_LINE.match(str(ln).strip())
        if not m:
            continue
        a = int(m.group("addr"), 16)
        if not (lo <= a < hi) or m.group("name").startswith("Ordinal_"):
            continue
        addr = "0x%08x" % a
        if addr in seen:
            continue
        seen.add(addr)
        out.append((addr, m.group("name"), m.group("type").strip()))
    return out


def sweep_program(program: str, clean_cache: dict, workers: int = 8) -> dict:
    entries = _global_addresses(program)
    findings = []

    def check(entry):
        addr, name, list_type = entry
        audit = _audit(program, addr)
        if not audit:
            return None
        if "untyped" not in (audit.get("issues") or []):
            return None
        interior = bool(audit.get("interior_to_data"))
        was_cached = fd._clean_cache_is_fresh(
            clean_cache, program, addr, axis=fd.GLOBALS_AXIS_TYPE)
        if not interior and not was_cached:
            # Plain never-typed global. Ordinary backlog, not damage.
            return None
        return {
            "address": addr,
            "name": name,
            "kind": "interior" if interior else "orphaned",
            "list_globals_type": list_type,
            "audit_type": audit.get("type"),
            "audit_length": audit.get("length"),
            "container": audit.get("container"),
            # The tell that makes this invisible: the inventory shows a type
            # (the eater's) where audit_global finds none.
            "hidden_from_inventory": not cd._glob_is_untyped(list_type),
            "was_cached_clean": was_cached,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(check, entries):
            if r:
                findings.append(r)

    findings.sort(key=lambda f: f["address"])
    return {
        "program": program,
        "globals_scanned": len(entries),
        "findings": findings,
        "counts": dict(Counter(f["kind"] for f in findings)),
        "hidden_from_inventory": sum(1 for f in findings if f["hidden_from_inventory"]),
        "cached_clean_while_broken": sum(1 for f in findings if f["was_cached_clean"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--program", help="single program path")
    g.add_argument("--folder", help="project folder prefix, e.g. /Mods/PD2-S12")
    ap.add_argument("--apply", action="store_true",
                    help="forget the victims' clean-cache entries so the globals "
                         "worker re-works them. Writes NOTHING to Ghidra.")
    ap.add_argument("--out", help="write the JSON report here")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    if args.program:
        programs = [args.program]
    else:
        prefix = args.folder.rstrip("/") + "/"
        programs = [b["path"] for b in cd.list_binaries()["binaries"]
                    if b["path"].startswith(prefix)]
    if not programs:
        print("no programs matched", file=sys.stderr)
        return 2

    clean_cache = fd._load_globals_clean_cache()
    report = {"programs": [], "totals": {}}
    for p in programs:
        r = sweep_program(p, clean_cache, workers=args.workers)
        report["programs"].append(r)
        flag = ""
        if r["hidden_from_inventory"]:
            flag = f"  ({r['hidden_from_inventory']} invisible to the dashboard)"
        print(f"{p}: {len(r['findings'])} evicted / {r['globals_scanned']} globals "
              f"{r['counts']}{flag}")
        for f in r["findings"][:8]:
            c = f.get("container") or {}
            where = (f" inside {c.get('name') or '?'} @ {c.get('address')} "
                     f"({c.get('type')})" if f["kind"] == "interior" else "")
            print(f"    {f['address']} {f['name']:40} "
                  f"list_globals={f['list_globals_type']!r}{where}")
        if len(r["findings"]) > 8:
            print(f"    ... {len(r['findings']) - 8} more (see the JSON report)")

    tot = Counter()
    for r in report["programs"]:
        tot["findings"] += len(r["findings"])
        tot["scanned"] += r["globals_scanned"]
        tot["hidden"] += r["hidden_from_inventory"]
        tot["cached_clean"] += r["cached_clean_while_broken"]
    report["totals"] = dict(tot)
    print(f"\nTOTAL: {tot['findings']} evicted globals across {len(programs)} "
          f"program(s), {tot['scanned']} globals scanned")
    print(f"  invisible to the dashboard (list_globals shows the eater's type): "
          f"{tot['hidden']}")
    print(f"  cached clean while broken (worker would skip them): {tot['cached_clean']}")

    if args.apply:
        forgotten = 0
        for r in report["programs"]:
            for f in r["findings"]:
                if fd._clean_cache_forget(clean_cache, r["program"], f["address"]):
                    forgotten += 1
        fd._save_globals_clean_cache(clean_cache)
        # Two different numbers, and conflating them would overstate the fix.
        # `forgotten` counts every cache entry removed, most of which had already
        # aged past the TTL and were suppressing nothing. `cached_clean` is the
        # subset that was still ACTIVELY hiding a broken global from the worker.
        print(f"\nAPPLIED: removed {forgotten} clean-cache entries "
              f"({tot['cached_clean']} of them were still within the TTL and "
              f"actively suppressing re-work; the rest had already expired).")
        print(f"  The remaining {tot['findings'] - tot['cached_clean']} findings were "
              f"already worker-eligible — their problem is visibility, not caching.")
    else:
        print("\n(dry run -- re-run with --apply to un-cache these for re-work)")

    out = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "evicted_globals_report.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"report -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

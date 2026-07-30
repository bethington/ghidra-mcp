#!/usr/bin/env python3
"""migrate_doc_map.py -- retire the globals DOC_ ladder from the `Doc` property map.

WHY THIS EXISTS
---------------
Globals used to carry the function DOC ladder (DOC_DRAFT / DOC_REVIEWED /
DOC_VERIFIED) in a per-address string property map called `Doc`. That model was
wrong in three separate ways, all confirmed against the live project on
2026-07-28:

  1. Only DOC_DRAFT ever had a producer. A survey of all 32 project binaries
     found 17,442 `Doc` entries and every single one was DOC_DRAFT. The other two
     rungs read zero on every binary, forever -- DOC_VERIFIED had no reachable
     definition at all, since there is no proof pipeline for a data address.

  2. DOC_DRAFT was a watermark, not a quality signal. The assess pass stamped it
     on any global whose score crossed Target and then skipped anything already
     carrying a rung, so it meant "assess visited this" and it froze 2,142 of
     D2Common's 2,231 globals out of ever being re-scored.

  3. 4,848 of the 17,442 entries (28%) sat at addresses outside the program that
     held them -- D2CMP.dll held 4,049 entries of which only 307 were its own,
     the rest D2Client (0x6fbc/0x6fb8) and rebased-module (0x1003/0x1010)
     addresses. Those are writes that leaked to whatever program was active, the
     known hazard of `/set_property`'s QUERY-sourced `program` parameter.

The map now holds exactly one value, REVIEWED, meaning an independent provider
(or a human, from the inventory row) re-checked the global against its real uses.
This script clears the legacy entries so the new value starts from an honest zero
rather than inheriting 17k claims nobody made.

Completeness lives in the sibling `Complete` band map and is NOT touched here.

USAGE
-----
    python migrate_doc_map.py                    # dry run: survey + snapshot, no writes
    python migrate_doc_map.py --apply            # snapshot, then clear every entry
    python migrate_doc_map.py --binary D2CMP.dll # scope to one program
    python migrate_doc_map.py --apply --strays-only
                                                 # clear ONLY out-of-image entries,
                                                 # keep in-image DOC_DRAFT

A snapshot is always written first, dry run or not, to
`fun-doc/backups/doc_map_<timestamp>.json`. Restore is a plain replay of that
file through /set_property; --restore does it for you.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import quote

import conformance_dashboard as cd

SCRIPT_DIR = Path(__file__).resolve().parent
BACKUP_DIR = SCRIPT_DIR / "backups"


def _survey(program: str) -> dict:
    """Every `Doc` entry for one program, split by whether it belongs here."""
    img = cd._image_range(program)
    entries = cd._prop_map(program, cd.GLOB_DOC_MAP)          # unfiltered, on purpose
    out = {"program": program, "image": None, "entries": entries,
           "in_image": [], "stray": [], "values": {}}
    if img:
        out["image"] = ["0x%08x" % img[0], "0x%08x" % img[1]]
    for addr, value in entries.items():
        out["values"][value] = out["values"].get(value, 0) + 1
        n = int(addr, 16)
        if img and not (img[0] <= n < img[1]):
            out["stray"].append(addr)
        else:
            out["in_image"].append(addr)
    return out


def _clear(program: str, addresses: list, save_every: int = 200) -> tuple:
    """Remove `Doc` at each address. Returns (removed, failed).

    Failures are counted and reported, never swallowed -- a best-effort write-back
    that fails silently is exactly what hid the wrong-binary CONF_ bug for weeks.
    """
    q = "?program=" + quote(program, safe="")
    removed = failed = 0
    for i, addr in enumerate(addresses, 1):
        try:
            cd._post("/remove_property" + q,
                     {"map": cd.GLOB_DOC_MAP, "address": addr, "program": program})
            removed += 1
        except OSError as exc:
            failed += 1
            print(f"    ! {addr}: {type(exc).__name__}: {exc}", flush=True)
        if i % save_every == 0:
            try:
                cd._post("/save_program" + q, {})
            except OSError as exc:
                print(f"    ! checkpoint save failed: {exc}", flush=True)
            print(f"    ... {i}/{len(addresses)}", flush=True)
    try:
        cd._post("/save_program" + q, {})
    except OSError as exc:
        print(f"    ! final save failed — entries cleared in memory only: {exc}",
              flush=True)
    return removed, failed


def _restore(path: Path) -> int:
    """Replay a snapshot back into the `Doc` maps it came from."""
    data = json.loads(path.read_text(encoding="utf-8"))
    total = 0
    for rec in data["binaries"]:
        program, entries = rec["program"], rec["entries"]
        if not entries:
            continue
        q = "?program=" + quote(program, safe="")
        cd._post("/create_property_map" + q,
                 {"name": cd.GLOB_DOC_MAP, "type": "string", "program": program})
        for addr, value in entries.items():
            cd._post("/set_property" + q,
                     {"map": cd.GLOB_DOC_MAP, "address": addr,
                      "value": value, "program": program})
            total += 1
        cd._post("/save_program" + q, {})
        print(f"  restored {len(entries):>6} entries to {program}", flush=True)
    return total


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="actually clear entries (default is a dry-run survey)")
    ap.add_argument("--strays-only", action="store_true",
                    help="clear only out-of-image entries, keep in-image DOC_DRAFT")
    ap.add_argument("--binary", help="limit to one program (name or full path)")
    ap.add_argument("--restore", metavar="SNAPSHOT",
                    help="replay a snapshot json back into Ghidra and exit")
    args = ap.parse_args(argv)

    if args.restore:
        p = Path(args.restore)
        if not p.exists():
            print(f"no such snapshot: {p}", file=sys.stderr)
            return 2
        print(f"restoring from {p}")
        print(f"restored {_restore(p)} entries")
        return 0

    binaries = cd.list_binaries()["binaries"]
    if args.binary:
        want = args.binary.lower()
        binaries = [b for b in binaries
                    if b["name"].lower() == want or b["path"].lower() == want]
        if not binaries:
            print(f"no binary matching {args.binary!r}", file=sys.stderr)
            return 2

    print(f"surveying {len(binaries)} binaries for `{cd.GLOB_DOC_MAP}` entries...\n")
    surveys, tot_in, tot_stray = [], 0, 0
    for b in binaries:
        try:
            s = _survey(b["path"])
        except Exception as exc:                       # noqa: BLE001 — report, continue
            print(f"  {b['name']:<32} ERROR {type(exc).__name__}: {exc}")
            continue
        surveys.append(s)
        tot_in += len(s["in_image"])
        tot_stray += len(s["stray"])
        if s["entries"]:
            vals = " ".join(f"{k}={v}" for k, v in sorted(s["values"].items()))
            print(f"  {b['name']:<32} total={len(s['entries']):<6} "
                  f"in-image={len(s['in_image']):<6} stray={len(s['stray']):<6} {vals}")

    print(f"\nTOTAL  in-image={tot_in}  stray={tot_stray}  "
          f"all={tot_in + tot_stray}")

    BACKUP_DIR.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    snap = BACKUP_DIR / f"doc_map_{stamp}.json"
    snap.write_text(json.dumps(
        {"created": stamp, "map": cd.GLOB_DOC_MAP,
         "binaries": [{"program": s["program"], "image": s["image"],
                       "entries": s["entries"], "stray": s["stray"]}
                      for s in surveys]},
        indent=1), encoding="utf-8")
    print(f"snapshot -> {snap}")

    # NEVER clear a REVIEWED entry. This script retires the LEGACY rung values;
    # REVIEWED is the live trust bit the new review pass writes, and by the time
    # this runs some of them already exist. Deleting them would silently destroy
    # real second-provider verdicts -- the one thing in this map that cannot be
    # recomputed, since re-earning it means paying for the provider calls again.
    def _clearable(survey):
        pool = survey["stray"] if args.strays_only else sorted(survey["entries"])
        return [a for a in pool if survey["entries"].get(a) != cd.GLOB_REVIEWED]

    kept = sum(1 for s in surveys for v in s["entries"].values()
               if v == cd.GLOB_REVIEWED)
    if kept:
        print(f"preserving {kept} {cd.GLOB_REVIEWED} entries (live trust bits)")
    targets = {s["program"]: _clearable(s) for s in surveys}
    n_target = sum(len(v) for v in targets.values())
    what = "stray entries" if args.strays_only else "ALL entries"

    if not args.apply:
        print(f"\nDRY RUN — would clear {n_target} {what} across "
              f"{sum(1 for v in targets.values() if v)} binaries.")
        print(f"re-run with --apply to write. Restore with:\n"
              f"    python migrate_doc_map.py --restore {snap.name}")
        return 0

    print(f"\nclearing {n_target} {what}...")
    removed = failed = 0
    for program, addrs in targets.items():
        if not addrs:
            continue
        print(f"  {program} ({len(addrs)})")
        r, f = _clear(program, addrs)
        removed += r
        failed += f
    print(f"\ndone: removed={removed} failed={failed}")
    if failed:
        print("FAILURES ABOVE — re-run to retry; the snapshot is still valid.")
        return 1
    print(f"snapshot retained at {snap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

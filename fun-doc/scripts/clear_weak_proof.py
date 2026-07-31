#!/usr/bin/env python3
r"""Clear `weak_proof` on rows that live shadow evidence has since vindicated.

THE FLAG
--------
`weak_proof` is set by port_live_prove._degenerate_capture_note when the
ORIGINAL returned the SAME value on every static vector:

    "DEGENERATE CAPTURE: the original returned the SAME value (7) on all 8
     vectors, only 2 distinct object(s) -- a wrong-offset reimpl matches by
     luck. This CONF_LIVE proof is WEAK; re-prove against DIVERSE objects (or
     trust shadow/V2) before promoting or freezing."

It is a well-earned guard, not paranoia. STAT_GetActiveSkillFieldC and
SKILLS_GetActiveSkillAnimData passed 8/8 on idle-town captures and then
diverged ~99% under shadow (2026-07-08). Volume proved nothing; diversity did.

WHY IT NEEDS CLEARING AT ALL
----------------------------
battletest_promoter refuses to promote a weak_proof row outright, and nothing
ever clears the flag -- so those functions are stuck below CONF_BATTLETESTED
permanently, no matter what evidence arrives. Measured 2026-07-31: 37 of 191
deployed dispatchers, including DATATBLS_GetItemStorePage sitting on 9,037
clean shadow hits across 62 distinct live inputs.

The flag's own text names the remedy: "re-prove against DIVERSE objects (or
trust shadow/V2)". Shadow mode IS that re-prove -- real inputs, real objects,
real comparison against the original on every call. And the counterexample is
the proof that it discriminates: shadow is what CAUGHT the wrong-offset
reimpls. A wrong offset cannot agree with the right one across dozens of
genuinely different live objects.

THE BAR, AND WHY IT IS HIGHER THAN NORMAL PROMOTION
---------------------------------------------------
CONF_BATTLETESTED needs 1000 hits / 20 distinct. Clearing a weak_proof asks
for more, because we are overturning a recorded doubt rather than just meeting
a threshold:

    divergences == 0          any disagreement means the doubt was justified
    distinct_inputs >= 40     2x the promotion floor
    hits >= 10000             10x the promotion floor

One residual risk stays and is worth stating plainly: `distinct_inputs` counts
distinct ARGUMENTS, not distinct RETURNS. If the original genuinely returns a
constant across its entire reachable domain, a wrong-offset reimpl that also
reads a constant would agree. That is the same residual the normal gate
accepts, and 40 distinct live objects makes it small -- but it is not zero,
which is why this is an explicit, dry-run-default, auditable operation and not
something the promoter does on its own.

Cleared rows keep an audit trail: `weak_proof_cleared` records the evidence
and `weak_proof_original` preserves the note that was overturned. Nothing is
deleted.

USAGE
    python fun-doc/scripts/clear_weak_proof.py                 # dry run
    python fun-doc/scripts/clear_weak_proof.py --apply
    python fun-doc/scripts/clear_weak_proof.py --min-distinct 60 --min-hits 50000
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import urllib.request
from pathlib import Path

_FUNDOC = Path(__file__).resolve().parent.parent
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

# Deliberately stricter than conf_ladder's promotion floors -- see module docs.
DEFAULT_MIN_DISTINCT = 40
DEFAULT_MIN_HITS = 10_000


def load_dispatchers(oracle_url: str) -> dict:
    """{address_hex_lowercase_no0x: dispatcher} for every hooked dispatcher."""
    import battletest_promoter as btp

    with urllib.request.urlopen(f"{oracle_url}/dispatchers", timeout=30) as r:
        data = json.loads(r.read().decode("utf-8", "replace"))
    out = {}
    for d in data.get("dispatchers", []):
        base = btp.IMAGE_BASES.get(d.get("module"))
        if base is None:
            continue
        out[format(base + d["offset"], "x")] = d
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="write (default: dry run)")
    ap.add_argument("--min-distinct", type=int, default=DEFAULT_MIN_DISTINCT)
    ap.add_argument("--min-hits", type=int, default=DEFAULT_MIN_HITS)
    args = ap.parse_args()

    import battletest_promoter as btp

    registry = Path(btp.PROVEN_REGISTRY)
    rows = btp._load_registry()
    weak = [r for r in rows if r.get("weak_proof")]
    if not weak:
        print("no weak_proof rows -- nothing to do.")
        return 0

    try:
        disp = load_dispatchers(btp.ORACLE_URL)
    except OSError as e:
        print(f"D2Debugger unreachable at {btp.ORACLE_URL}: {e}", file=sys.stderr)
        return 1

    cleared, held = [], []
    for r in weak:
        addr = str(r.get("address", "")).lower().replace("0x", "")
        d = disp.get(addr)
        name = r.get("name") or (d or {}).get("name") or addr
        if d is None:
            held.append((name, "no live dispatcher"))
            continue
        if d.get("modeName") != "shadow":
            held.append((name, f"mode={d.get('modeName')} -- no shadow evidence "
                               f"is being collected"))
            continue
        divs, hits = d.get("divergences", 0), d.get("hits", 0)
        distinct = d.get("distinct_inputs", 0)
        if divs > 0:
            held.append((name, f"{divs} DIVERGENCES -- the doubt was justified"))
            continue
        if distinct < args.min_distinct or hits < args.min_hits:
            held.append((name, f"insufficient: {hits} hits / {distinct} distinct "
                               f"(need {args.min_hits} / {args.min_distinct})"))
            continue
        cleared.append((r, d, name))

    print(f"{len(weak)} weak_proof row(s); {len(cleared)} vindicated by shadow "
          f"evidence, {len(held)} still held\n")
    if cleared:
        print("WOULD CLEAR:" if not args.apply else "CLEARING:")
        for _, d, name in cleared:
            print(f"   {name:<44} {d['hits']:>10} hits  "
                  f"{d['distinct_inputs']:>4} distinct  0 divergences")
    if held:
        print("\nSTILL HELD:")
        for name, why in sorted(held, key=lambda t: t[0])[:40]:
            print(f"   {name:<44} {why}")
        if len(held) > 40:
            print(f"   ... and {len(held) - 40} more")

    if not args.apply:
        print("\nDRY RUN -- re-run with --apply to write.")
        return 0
    if not cleared:
        return 0

    # Back up before rewriting an append-only registry. Cheap insurance on a
    # file that is the mirror of every proof this project has recorded.
    backup = registry.with_suffix(registry.suffix + f".bak_weakclear_{int(time.time())}")
    shutil.copyfile(registry, backup)
    print(f"\nregistry backed up -> {backup.name}")

    by_addr = {str(r.get("address", "")).lower().replace("0x", ""): r for r, _, _ in cleared}
    ev_by_addr = {str(r.get("address", "")).lower().replace("0x", ""): d
                  for r, d, _ in cleared}
    n = 0
    for row in rows:
        a = str(row.get("address", "")).lower().replace("0x", "")
        if a not in by_addr:
            continue
        d = ev_by_addr[a]
        # PRESERVE the overturned note; never silently drop the history of a
        # doubt that was recorded for a real reason.
        row["weak_proof_original"] = row.pop("weak_proof")
        row["weak_proof_cleared"] = {
            "date": time.strftime("%Y-%m-%d"),
            "basis": "live shadow evidence",
            "hits": d.get("hits"),
            "distinct_inputs": d.get("distinct_inputs"),
            "divergences": 0,
            "thresholds": {"min_hits": args.min_hits,
                           "min_distinct": args.min_distinct},
        }
        n += 1

    tmp = registry.with_suffix(registry.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, default=str) + "\n")
    tmp.replace(registry)
    print(f"cleared weak_proof on {n} row(s). battletest_promoter will now "
          f"consider them; run it (or let the watcher's next round) to promote.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

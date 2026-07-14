"""gen_fort_rename_map.py -- generate the D2MOO -> Fortification struct-name mapping table
that drives the source-level rename of the D2MOO repo (PD2-only conversion, phase 2).

Identity between the two vocabularies CANNOT be established structurally alone: size/offset
matching produced provable nonsense (D2MissileStrc "matched" a 92-byte context struct). The
primary key is NAME CORRESPONDENCE -- D2<X>Strc <-> <X> (case-insensitive, plus curated
aliases like D2UnitStrc<->UnitAny) -- then structure decides the disposition:

  * rename_now      -- names correspond AND sizes agree: safe mechanical rename.
  * layout_drift    -- names correspond but sizes differ: SAME runtime concept, different
                       version layout (D2MOO=1.10f heritage, Fortification=1.13c). These are
                       the phase-3 proof-gated adoption backlog: prove the 1.13c layout field
                       by field, adopt it, THEN rename.
  * no_counterpart  -- no Fortification name: D2MOO name IS the unified name (backfill).

Data-table records (D2*Txt/D2*Bin) are excluded: Fortification doesn't define them.

Output: conformance/fort_rename_map.json in the D2MOO repo.
"""
from __future__ import annotations

import json
import sys

import unify_types as ut

OUT = r"C:\Users\benam\source\cpp\D2MOO\conformance\fort_rename_map.json"

# Curated aliases where the community name differs from the D2MOO stem.
ALIASES = {
    "D2UnitStrc": "UnitAny",
    "D2ActiveRoomStrc": "Room1",
    "D2DrlgRoomStrc": "Room2",
    "D2DrlgLevelStrc": "Level",
    "D2DrlgActStrc": "Act",
    "D2DrlgStrc": "ActMisc",
    "D2DynamicPathStrc": "Path",
    "D2DrlgRoomTilesStrc": "RoomTile",
    "D2DrlgPresetUnitStrc": "PresetUnit",
    "D2DrlgCoordsStrc": "CollMap",
    "D2SeedStrc": "RandomSeed",
}


def stem(d2moo_name):
    """D2AutomapCellStrc -> automapcell"""
    n = d2moo_name
    if n.startswith("D2"):
        n = n[2:]
    if n.endswith("Strc"):
        n = n[:-4]
    return n.lower()


def main():
    fort = ut._FortSource().structs()
    moo = ut._D2MOOSource().structs()

    fort_by_lower = {}
    for n in fort:
        fort_by_lower.setdefault(n.lower(), n)

    rows = []
    for n in sorted(moo):
        s = moo[n]
        if not s.get("fields"):
            continue
        if ut._is_datatable(n):
            continue
        target = ALIASES.get(n) or fort_by_lower.get(stem(n))
        entry = {"d2moo": n, "size": s.get("size")}
        if target is None or target not in fort:
            entry["tier"] = "no_counterpart"
        else:
            fsize = fort[target].get("size")
            moo_off = set(s.get("fields", {}))
            foff = set(fort[target].get("fields", {}))
            ov = (len(moo_off & foff) / max(len(moo_off), len(foff))) if moo_off and foff else 0.0
            entry.update(fort=target, fort_size=fsize, overlap=round(ov, 3))
            entry["tier"] = "rename_now" if fsize == s.get("size") else "layout_drift"
        rows.append(entry)

    by_tier = {}
    for r in rows:
        by_tier.setdefault(r["tier"], []).append(r)
    summary = {t: len(v) for t, v in sorted(by_tier.items())}

    moo_names = set(moo)
    collisions = sorted({r["fort"] for r in rows if r.get("fort") and r["fort"] in moo_names})

    out = {
        "generated_by": "gen_fort_rename_map.py",
        "note": "name-correspondence primary key; see module docstring",
        "summary": summary,
        "collisions": collisions,
        "pairs": rows,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print("wrote", OUT)
    print("summary:", json.dumps(summary))
    if collisions:
        print("COLLISIONS:", collisions)
    for t in ("rename_now", "layout_drift"):
        print("\n--", t)
        for r in by_tier.get(t, []):
            print(" %-30s -> %-22s d2moo=%-6s fort=%-6s ov=%s" % (
                r["d2moo"], r["fort"], r["size"], r.get("fort_size"), r.get("overlap")))


if __name__ == "__main__":
    sys.exit(main())

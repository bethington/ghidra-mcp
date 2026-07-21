"""struct_registry.py -- canonical struct registry: concise/community/D2MOO names, a merged
field set (D2MOO + Fortification), and a per-offset PROVABILITY mark (proven by a getter,
size-proven by a stride match, or unverified).

Integrates three sources, all offset-annotated (`... //0xNN`):
  * D2MOO headers          -> the reimplementation's field names/types (d2moo_names)
  * Fortification D2Structs -> the community field names (gap-filling, cross-check)
  * proven candidates       -> which offsets a bit-exact getter actually reads in PD2 (provability)

Naming: the recommended concise name drops the redundant `D2` prefix and `Strc` suffix and uses
the community-standard concept name (UnitAny, Room1, ...), keeping only meaningful tags (Txt/Bin
for data-table records).

Usage:
    python struct_registry.py            # build + readable summary + write struct_registry.json
    python struct_registry.py --struct UnitAny   # full merged field table for one struct
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import d2moo_names as dn

FORT_H = Path(os.environ.get(
    "FORTIFICATION_STRUCTS",
    r"C:\Users\benam\source\cpp\Fortification\Fortification\D2Structs.h"))
CANDIDATES = dn.D2MOO_REPO / "conformance" / "reimpl_provider" / "candidates"
# d2moo_names defaults to D2Common only; the registry wants every module's structs
ALL_INCLUDES = sorted((dn.D2MOO_REPO / "source").glob("*/include"))
_D2_CACHE = None


def _d2_all():
    global _D2_CACHE
    if _D2_CACHE is None:
        _D2_CACHE = dn.load(include_dirs=ALL_INCLUDES)
    return _D2_CACHE

# (D2MOO name candidates, community/Fortification name, recommended concise name)
MARQUEE = [
    (["D2UnitStrc"], "UnitAny", "UnitAny"),
    (["D2InventoryStrc"], "Inventory", "Inventory"),
    (["D2ItemDataStrc"], "ItemData", "ItemData"),
    (["D2PlayerDataStrc"], "PlayerData", "PlayerData"),
    (["D2MonsterDataStrc"], "MonsterData", "MonsterData"),
    (["D2StatListStrc", "D2StatListExStrc"], "StatList", "StatList"),
    (["D2ActiveRoomStrc"], "Room1", "Room1"),
    (["D2DrlgRoomStrc", "D2DrlgLogicalRoomInfoStrc"], "Room2", "Room2"),
    (["D2PresetUnitStrc"], "PresetUnit", "PresetUnit"),
    (["D2DynamicPathStrc", "D2PathStrc"], "Path", "Path"),
    (["D2SkillListStrc","D2SkillStrc"], "Skill", "Skill"),
    (["D2StatStrc", "D2UnitStatStrc"], "Stat", "Stat"),
    (["D2ItemsTxt"], "ItemsTxt", "ItemsTxt"),
    (["D2MonStatsTxt"], "MonStatsTxt", "MonStatsTxt"),
    (["D2SkillsTxt"], "SkillsTxt", "SkillsTxt"),
]

_UNK = re.compile(r"unk|pad|gap|unused|_0x|^_\d", re.I)


def _fort_structs():
    """{name: {'size', 'fields': {off: {name,type,width}}}} from Fortification's D2Structs.h,
    parsed with the same offset-annotated field parser d2moo_names uses."""
    try:
        txt = FORT_H.read_text(encoding="utf-16")
    except (OSError, UnicodeError):
        try:
            txt = FORT_H.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {}
    structs = {}
    dn._parse_file(txt, structs)
    return structs


def _proven():
    """{d2moo_struct: {'offsets': set(int), 'size_proven': bool}} from the proven candidates:
    canonicalize each getter to (struct, read_off); a 'stride == sizeof' resolution size-proves."""
    out = {}
    if not CANDIDATES.is_dir():
        return out
    structs = _d2_all()
    for cpp in sorted(CANDIDATES.glob("*.cpp")):
        try:
            c = dn.canonicalize(cpp.stem, cpp.read_text(encoding="utf-8", errors="replace"), structs)
        except Exception:
            continue
        if not (c.get("ok") and c.get("struct")):
            continue
        rec = out.setdefault(c["struct"], {"offsets": set(), "size_proven": False})
        if c.get("read_off") is not None:
            rec["offsets"].add(c["read_off"])
        # size-proven: a candidate strode this struct's array by exactly its D2MOO sizeof
        try:
            ex = dn._extract_from_candidate(cpp.read_text(encoding="utf-8", errors="replace"))
            if ex.get("stride") and structs.get(c["struct"], {}).get("size") == ex["stride"]:
                rec["size_proven"] = True
        except Exception:
            pass
    return out


def _is_named(fname: str) -> bool:
    return bool(fname) and not _UNK.search(fname)


def build():
    d2 = _d2_all()
    fort = _fort_structs()
    proven = _proven()
    registry = []
    for d2names, community, concise in MARQUEE:
        d2name = next((n for n in d2names if n in d2), None)
        d2s = d2.get(d2name, {}) if d2name else {}
        forts = fort.get(community, {})
        pv = proven.get(d2name, {"offsets": set(), "size_proven": False})
        d2f, ff = d2s.get("fields", {}), forts.get("fields", {})
        offsets = sorted(set(d2f) | set(ff))
        fields = []
        for off in offsets:
            dm, fo = d2f.get(off), ff.get(off)
            is_proven = off in pv["offsets"]
            prov = "proven" if is_proven else "unverified"
            fort_named = bool(fo and _is_named(fo["name"]))
            d2_named = bool(dm and _is_named(dm["name"]))
            # PD2 authority: proof (reads PD2 memory) > Fortification (PD2-native) > D2MOO (1.10f)
            if is_proven:
                pd2_conf = "confirmed"
            elif fort_named and d2_named and fo["name"] != dm["name"]:
                pd2_conf = "conflict"        # Fortification wins for PD2, but flag it
            elif fort_named:
                pd2_conf = "pd2-ref"         # only Fortification names it -> PD2-authoritative
            elif d2_named:
                pd2_conf = "1.10f-only"      # only D2MOO -> uncertain for PD2 (may be version drift)
            else:
                pd2_conf = "unknown"
            # preferred PD2 field name: Fortification (PD2) when it names it, else D2MOO
            pd2_name = (fo["name"] if fort_named else dm["name"] if d2_named else (fo or dm or {}).get("name"))
            fields.append({
                "offset": off, "off_hex": f"0x{off:X}",
                "d2moo": dm["name"] if dm else None, "type": (dm or fo or {}).get("type"),
                "fort": fo["name"] if fo else None, "provability": prov,
                "pd2_conf": pd2_conf, "pd2_name": pd2_name,
                "gapfill": ("fort->d2moo" if (dm and not _is_named(dm["name"]) and fo and _is_named(fo["name"]))
                            else "d2moo->fort" if (fo and not _is_named(fo["name"]) and dm and _is_named(dm["name"]))
                            else None),
            })
        d2size, fsize = d2s.get("size"), forts.get("size")
        registry.append({
            "concise": concise, "community": community, "d2moo": d2name,
            "size_d2moo": d2size, "size_fort": fsize,
            "size_match": (d2size is not None and d2size == fsize),
            "size_proven": pv["size_proven"],
            "fields_total": len(offsets),
            "proven_offsets": len(pv["offsets"]),
            "pd2_confirmed": sum(1 for f in fields if f["pd2_conf"] == "confirmed"),
            "pd2_ref": sum(1 for f in fields if f["pd2_conf"] == "pd2-ref"),
            "pd2_conflict": sum(1 for f in fields if f["pd2_conf"] == "conflict"),
            "only_1_10f": sum(1 for f in fields if f["pd2_conf"] == "1.10f-only"),
            "gapfill_fort_to_d2moo": sum(1 for f in fields if f["gapfill"] == "fort->d2moo"),
            "gapfill_d2moo_to_fort": sum(1 for f in fields if f["gapfill"] == "d2moo->fort"),
            "fields": fields,
        })
    return registry


def _summary(reg):
    L = ["=" * 92,
         "CANONICAL STRUCT REGISTRY -- names, merged fields (D2MOO + Fortification), PD2 provability",
         "=" * 92,
         "PD2 authority per field: confirmed=proven / ref=Fortification(PD2) / "
         "1.10f=D2MOO-only(uncertain) / conflict=disagree(Fort wins)",
         f"{'concise':14} {'D2MOO':22} {'size':>10} {'sz?':4} {'flds':>4} "
         f"{'conf':>4} {'ref':>4} {'1.10f':>5} {'cflct':>5}"]
    for r in reg:
        sz = f"{r['size_d2moo']:#x}" if r["size_d2moo"] else "-"
        szm = ("=" if r["size_match"] else "x") + ("P" if r["size_proven"] else " ")
        L.append(f"{r['concise']:14} {(r['d2moo'] or '(missing)'):22} {sz:>10} {szm:4} "
                 f"{r['fields_total']:>4} {r['pd2_confirmed']:>4} {r['pd2_ref']:>4} "
                 f"{r['only_1_10f']:>5} {r['pd2_conflict']:>5}")
    tc = sum(r["pd2_confirmed"] for r in reg)
    tr = sum(r["pd2_ref"] for r in reg)
    t1 = sum(r["only_1_10f"] for r in reg)
    tx = sum(r["pd2_conflict"] for r in reg)
    tg = sum(r["gapfill_fort_to_d2moo"] + r["gapfill_d2moo_to_fort"] for r in reg)
    L += ["-" * 92,
          f"{len(reg)} structs | PD2 fields: {tc} confirmed(proven) / {tr} Fortification-ref / "
          f"{t1} 1.10f-only(uncertain) / {tx} conflict | {tg} gap-fill candidates",
          "sz? '='=size matches Fortification, 'x'=differs (version drift 1.10f vs PD2)"]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--struct", help="print the full merged field table for one struct (by concise/community name)")
    ap.add_argument("--json", default=None, help="where to write the registry JSON")
    args = ap.parse_args()
    reg = build()
    if args.struct:
        r = next((x for x in reg if args.struct in (x["concise"], x["community"], x["d2moo"])), None)
        if not r:
            print(f"no such struct: {args.struct}"); return 1
        sd = f"{r['size_d2moo']:#x}" if isinstance(r["size_d2moo"], int) else "?"
        sf = f"{r['size_fort']:#x}" if isinstance(r["size_fort"], int) else "?"
        print(f"{r['concise']}  (community: {r['community']}  |  D2MOO: {r['d2moo']}  |  "
              f"size D2MOO {sd} {'==' if r['size_match'] else '!='} Fort {sf}  |  "
              f"{r['proven_offsets']} proven offsets)")
        print(f"{'offset':>7} {'PD2 authority':13} {'PD2 field':24} {'D2MOO field':24} "
              f"{'Fortification':22} type")
        for f in r["fields"]:
            print(f"{f['off_hex']:>7} {f['pd2_conf']:13} {(f['pd2_name'] or '-'):24} "
                  f"{(f['d2moo'] or '-'):24} {(f['fort'] or '-'):22} {f['type'] or ''}")
        return 0
    print(_summary(reg))
    path = args.json or os.path.join(os.environ.get("TEMP", "."), "struct_registry.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, default=lambda o: sorted(o) if isinstance(o, set) else str(o))
    print(f"\nfull registry -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

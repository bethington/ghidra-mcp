"""unify_types.py -- collapse the two loaded vocabularies (D2MOO + Fortification) into ONE set.

Decision: Fortification (PD2-native, the version we prove against) is the base; D2MOO structs
that DUPLICATE a Fortification struct (same size, or exact size+offset signature) are deleted;
D2MOO structs with no Fortification match are KEPT as backfill (data-table records + PD2-absent
concepts). Result: one set of struct names in Ghidra -- community/Fortification names + the D2MOO
backfill -- no duplicates.

    python unify_types.py --plan                 # print keep/delete counts + the delete list
    python unify_types.py --apply [--program P]  # delete duplicates from one program
    python unify_types.py --apply-all            # every open PD2 game binary
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.parse
import urllib.request

import struct_registry as sr

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")


def _sig(s):
    return (s.get("size"), tuple(sorted(s.get("fields", {}))))


def _is_datatable(name):
    """Data-table record (`.txt`/`.bin` compiled row): Fortification is a runtime-struct header
    and defines NONE of these, so they are ALWAYS backfill, never a size-coincidence duplicate."""
    return name.endswith(("Txt", "Bin"))


def plan():
    """(duplicates[list of D2MOO names], backfill[list]). A duplicate matches a Fortification
    struct (exact sig OR size) AND is not a data-table record. Backfill is the rest PLUS the
    transitive D2MOO dependency-closure of that rest: a D2MOO helper struct that a kept struct
    embeds/points to is retained even if it size-matches Fortification, so the kept type graph
    resolves fully (no dangling undefined references)."""
    import d2moo_types as dt
    d2 = sr._d2_all()
    fort = sr._fort_structs()
    fort_sigs = {_sig(s) for s in fort.values() if s.get("fields")}
    fort_sizes = {s.get("size") for s in fort.values() if s.get("fields") and s.get("size")}
    dup_cand, keep = set(), set()
    for n, s in d2.items():
        if not s.get("fields"):
            continue                      # fieldless/forward-decl -> leave alone
        is_dup = (not _is_datatable(n)) and (_sig(s) in fort_sigs or s.get("size") in fort_sizes)
        (dup_cand if is_dup else keep).add(n)
    # pull any dup that a kept struct depends on into keep, transitively (fixpoint)
    defs = {d["name"]: d for d in dt._definitions()}
    changed = True
    while changed:
        changed = False
        for n in list(keep):
            for dep in defs.get(n, {}).get("deps", []):
                if dep in dup_cand:
                    dup_cand.discard(dep); keep.add(dep); changed = True
    return sorted(dup_cand), sorted(keep)


def reload_full_d2moo(targets):
    """Re-import the complete D2MOO header (re-adds every struct, incl. data-table records that a
    prior over-aggressive delete removed). Dependency-safe: emit_header topo-sorts + forward-decls
    the whole set, so subset-dependency gaps can't occur."""
    import d2moo_types as dt
    header, stats = dt.emit_header()
    print(f"re-importing full D2MOO header ({stats['total']} defs) into {len(targets)} binary(ies)...")
    for p in targets:
        res = _post("/import_data_types", {"source": header}, p)
        try:
            added = json.loads(res).get("types_added", "?")
        except Exception:
            added = "?"
        print(f"  {os.path.basename(p):16} +{added}")


MARKER_GROUP, MARKER_OPTION = "Program Information", "PD2.unified.types.version"


def _keep_names():
    """The unified struct name set = Fortification's structs + the D2MOO backfill/closure kept."""
    import fort_types as ft
    _dups, backfill = plan()
    fort_names = set(sr._fort_structs())
    return fort_names | set(backfill)


def unified_marker():
    """Stable marker for 'the ONE unified set is loaded & current'. Changes if either vocabulary's
    contribution changes, so a stale/partial load is detectable in a single option read."""
    import hashlib
    names = sorted(_keep_names())
    h = hashlib.sha1("\n".join(names).encode("utf-8")).hexdigest()[:8]
    return f"uni1:{len(names)}:{h}"


def load_unified(program):
    """Idempotently bring ONE binary to the unified set: import Fortification (base) + full D2MOO,
    then delete the runtime duplicates, then stamp the unified marker. Safe to re-run -- this is
    what the 'Load types' button must call so it can never re-introduce the D2MOO duplicates."""
    import d2moo_types as dt
    import fort_types as ft
    dups, _backfill = plan()
    fort_header = ft.emit_fort_header()[0]
    d2_header = dt.emit_header()[0]
    added = 0
    for hdr in (fort_header, d2_header):
        res = _post("/import_data_types", {"source": hdr}, program)
        try:
            added += json.loads(res).get("types_added", 0)
        except Exception:
            pass
    apply_to(program, dups)
    _post("/set_program_option", {"group": MARKER_GROUP, "name": MARKER_OPTION,
                                  "value": unified_marker()}, program)
    try:
        _post("/save_program", {}, program)
    except Exception:
        pass
    return {"program": program, "added": added, "deleted_dups": len(dups), "marker": unified_marker()}


def _post(path, body, program):
    url = f"{GHIDRA}{path}?program=" + urllib.parse.quote(program, safe="")
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def _get(path, **params):
    url = f"{GHIDRA}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
    with urllib.request.urlopen(url, timeout=60) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _open_programs():
    d = _get("/list_open_programs")
    progs = d if isinstance(d, list) else d.get("programs", d.get("open_programs", []))
    out = [(p if isinstance(p, str) else (p.get("path") or p.get("name"))) for p in progs]
    return sorted({p for p in out if p and p.startswith("/Mods/") and p.endswith(".dll")})


def apply_to(program, dups):
    """Delete each duplicate; a few passes handle the type-graph reference ordering."""
    remaining = list(dups)
    deleted = 0
    for _pass in range(4):
        still = []
        for name in remaining:
            r = _post("/delete_data_type", {"type_name": name}, program)
            if "deleted successfully" in r or "not found" in r.lower():
                deleted += 1 if "deleted successfully" in r else 0
            else:
                still.append(name)
        remaining = still
        if not remaining:
            break
    return {"program": program, "deleted": deleted, "left": len(remaining)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--apply-all", action="store_true")
    ap.add_argument("--restore", action="store_true",
                    help="reload full D2MOO header then re-delete only true (non-datatable) dups")
    ap.add_argument("--stamp-all", action="store_true",
                    help="stamp the unified marker + save on every open binary (persist current state)")
    ap.add_argument("--load-unified", action="store_true",
                    help="idempotent full unified load (Fortification + D2MOO backfill) on every open binary")
    ap.add_argument("--program", default="/Mods/PD2-S12/D2Common.dll")
    args = ap.parse_args()
    dups, backfill = plan()
    if args.plan:
        print(f"Fortification = base. D2MOO structs: {len(dups)} DELETE (duplicate), "
              f"{len(backfill)} KEEP (backfill, no PD2 twin)")
        print(f"\nKEEP / backfill ({len(backfill)}):")
        print("  " + ", ".join(backfill))
        print(f"\nDELETE / duplicates ({len(dups)}):")
        print("  " + ", ".join(dups))
        return 0
    if args.stamp_all:
        marker = unified_marker()
        print(f"stamping unified marker {marker} + saving...")
        for p in _open_programs():
            _post("/set_program_option", {"group": MARKER_GROUP, "name": MARKER_OPTION, "value": marker}, p)
            try:
                _post("/save_program", {}, p)
            except Exception:
                pass
            print(f"  {os.path.basename(p):16} marked + saved")
        return 0
    if args.load_unified:
        for p in _open_programs():
            r = load_unified(p)
            print(f"  {os.path.basename(p):16} +{r['added']} imported, {r['deleted_dups']} dups removed, marked")
        return 0
    targets = _open_programs() if (args.apply_all or args.restore) else [args.program]
    if args.restore:
        reload_full_d2moo(targets)
        print()
    print(f"deleting {len(dups)} duplicate D2MOO structs from {len(targets)} binary(ies)...")
    for p in targets:
        r = apply_to(p, dups)
        print(f"  {os.path.basename(p):16} deleted {r['deleted']}, {r['left']} left")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

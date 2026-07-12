"""unify_types.py -- the Diablo II / Project Diablo 2 PROFILE of the generic type_unifier engine.

Collapses the two loaded vocabularies into ONE set in the PD2 game binaries:
  * PRIMARY  = Fortification's PD2-native structs (community names: UnitAny, Room1, ItemData, ...)
  * SECONDARY= D2MOO's canonical headers (D2*Strc / D2*Txt); backfills what Fortification lacks
    (data-table records + internal helpers), and its runtime duplicates of Fortification are deleted.

All the app-specific choices live here; the dedup/closure/delete/marker engine is type_unifier.py.
This module keeps the public API (plan / load_unified / unified_marker / MARKER_GROUP / MARKER_OPTION)
that web.py's request_load_types and conformance_dashboard's types_status depend on, so wiring an
entirely different application means writing a sibling profile, not touching the engine or callers.

    python unify_types.py --plan          # keep/delete counts + lists
    python unify_types.py --apply-all     # delete duplicates from every open binary
    python unify_types.py --restore       # reload full D2MOO then re-delete the corrected dups
    python unify_types.py --stamp-all     # stamp unified marker + save on every open binary
    python unify_types.py --load-unified  # idempotent full unified load on every open binary
"""
from __future__ import annotations

import argparse
import os

import type_unifier as tu
import struct_registry as sr
import d2moo_types as dt
import fort_types as ft


# ---- the two D2 vocabularies as TypeSources --------------------------------------------------
class _FortSource(tu.TypeSource):
    """PRIMARY: Fortification's PD2 runtime structs (the version the conformance oracle proves)."""
    def structs(self):
        return sr._fort_structs()

    def emit_header(self):
        return ft.emit_fort_header()[0]


class _D2MOOSource(tu.TypeSource):
    """SECONDARY: D2MOO's canonical headers -- every module's structs, with a dep graph for closure."""
    def __init__(self):
        self._defs = None

    def _definitions(self):
        if self._defs is None:
            self._defs = {d["name"]: d for d in dt._definitions()}
        return self._defs

    def structs(self):
        return sr._d2_all()

    def emit_header(self):
        return dt.emit_header()[0]

    def deps(self, name):
        return self._definitions().get(name, {}).get("deps", ())


def _is_datatable(name):
    """Data-table record (`.txt`/`.bin` compiled row): Fortification is a runtime-struct header and
    defines NONE of these, so they are ALWAYS backfill, never a size-coincidence duplicate."""
    return name.endswith(("Txt", "Bin"))


def _pd2_programs(paths):
    """The PD2 game binaries loaded in Ghidra (mod DLLs under /Mods/)."""
    return sorted({p for p in paths if p.startswith("/Mods/") and p.endswith(".dll")})


# The configured engine instance -- swapping applications = a different Unifier here.
UNIFIER = tu.Unifier(
    primary=_FortSource(),
    secondary=_D2MOOSource(),
    never_dedup=_is_datatable,
    program_selector=_pd2_programs,
    marker_group="Program Information",
    marker_option="PD2.unified.types.version",
)

# ---- public API preserved for web.py / conformance_dashboard (thin passthroughs) -------------
MARKER_GROUP = UNIFIER.marker_group
MARKER_OPTION = UNIFIER.marker_option


def plan():
    return UNIFIER.plan()


def unified_marker():
    return UNIFIER.unified_marker()


def load_unified(program):
    return UNIFIER.load_unified(program)


# ---- CLI -------------------------------------------------------------------------------------
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

    dups, backfill = UNIFIER.plan()
    if args.plan:
        print(f"Fortification = base. D2MOO structs: {len(dups)} DELETE (duplicate), "
              f"{len(backfill)} KEEP (backfill, no PD2 twin)")
        print(f"\nKEEP / backfill ({len(backfill)}):\n  " + ", ".join(backfill))
        print(f"\nDELETE / duplicates ({len(dups)}):\n  " + ", ".join(dups))
        return 0
    if args.stamp_all:
        marker = UNIFIER.unified_marker()
        print(f"stamping unified marker {marker} + saving...")
        for p in UNIFIER.open_programs():
            UNIFIER.stamp(p); UNIFIER.save(p)
            print(f"  {os.path.basename(p):16} marked + saved")
        return 0
    if args.load_unified:
        for p in UNIFIER.open_programs():
            r = UNIFIER.load_unified(p)
            print(f"  {os.path.basename(p):16} +{r['added']} imported, {r['deleted_dups']} dups removed, marked")
        return 0

    targets = UNIFIER.open_programs() if (args.apply_all or args.restore) else [args.program]
    if args.restore:
        print(f"re-importing full D2MOO header into {len(targets)} binary(ies), then deleting {len(dups)} dups...")
        for p in targets:
            r = UNIFIER.restore(p)
            print(f"  {os.path.basename(p):16} +{r['added']} re-imported, deleted {r['deleted']}, {r['left']} left")
        return 0
    print(f"deleting {len(dups)} duplicate D2MOO structs from {len(targets)} binary(ies)...")
    for p in targets:
        r = UNIFIER.delete_dups(p, dups)
        print(f"  {os.path.basename(p):16} deleted {r['deleted']}, {r['left']} left")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

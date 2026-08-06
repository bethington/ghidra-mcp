"""Graph-based scope: what does this binary actually DO, as opposed to what did
the toolchain link into it.

THE PROBLEM THIS EXISTS TO SOLVE

Every scope mechanism that came before this one keys on a NAME or on BYTES:

    scope_tag_library.py   name/symbol regex ("NAME/SYMBOL EVIDENCE ONLY")
    crt_identify.py        relocation-masked byte match against a real .lib
    doc_lint fid_bookmarks Ghidra's Function ID analyzer

Each is precise and each has the same blind spot, measured on PD2_EXT.dll
2026-08-04: after all three ran, 147 functions were still "in scope" and 143 of
them were MSVC runtime. Four were authored.

They missed because:

  * the binary links the UCRT (`__acrt_*`, `__scrt_*`, VS2015+), and the FID
    databases are VS2003/VC6-era, so they predate it by a decade;
  * the survivors had ALREADY BEEN RENAMED by documentation workers, to
    `UNIT_GetUnitFlags2` (really a PEB+0x68 NtGlobalFlag read),
    `MEMMGR_DetectSimdCapabilities` (really `__isa_available_init`),
    `STRING_*`, `DATATBLS_*`. A name-based classifier cannot catch CRT code
    wearing a game name -- the bad name is the OUTPUT of the mistake, so it
    cannot be the INPUT to detecting it.

REFERENCES SURVIVE RENAMING. NAMES DO NOT. That is the whole idea here, and it
is the same reason the globals rule keys on referrers rather than on `g_*`.

THE RULE

A function is library-owned iff EVERY function that references it is library
code -- applied transitively to a fixed point. One authored referrer keeps it.
Direct mirror of `library_scope.library_globals`, one level up.

Edges come from `/get_bulk_xrefs`, counting BOTH `CALL` and `DATA` references,
each attributed to its containing function. Not from `/get_full_call_graph`:
that endpoint is measurably incomplete -- `__CxxFrameHandler3` has 7
`UNCONDITIONAL_CALL` xrefs and reports zero call-graph edges. DATA references
matter as much as calls: `CompareUint`'s only referrer is a `DATA` ref from
`expand_argument_wildcards` handing it to `qsort`, which is invisible to a call
graph and decisive here.

EVERY WAY OF BEING UNSURE KEEPS A FUNCTION IN SCOPE

    zero references        -> stays (cannot be proven library-owned)
    unreadable references  -> stays (unknown is not library)
    a referrer we cannot   -> stays (it might be authored)
      attribute to a function

WHAT PROTECTS AUTHORED CODE

Exports and entry points are never swept. That is structural, so it survives
renaming. It is also NOT SUFFICIENT, and the module is honest about that:
`PD2EXT_InstallBootstrapHook` is authored, is not an export, and its only
referrer is the CRT's `DllMain` -- so "every referrer is library" is true of it,
as it is of EVERY mod entry point by construction. Nothing in the graph can tell
it apart from a CRT helper the identification lanes missed.

That is why the sweep is REVIEW-GATED on first run rather than auto-applied
(and why `--apply` is not the default). The review is not ceremony; it is the
only backstop for the one case the structure provably cannot catch.

MARKING

Swept functions get `SCOPE_EXCLUDED`, deliberately NOT `LIB_CRT`. A `LIB_*` tag
is a claim backed by a matched artifact -- that is what makes the identification
lanes worth trusting -- and an inference must not be able to forge one. A swept
function is also not necessarily CRT: it may be third-party, or authored and
unreachable. The tag records what we actually know. The `Scope` property carries
the reason, the same map `scope_tag_library` and the globals lane already use.
"""

from __future__ import annotations

import collections
import datetime as _dt
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import library_scope as ls                                       # noqa: E402
import call_graph as _cg                                         # noqa: E402

# The inference tag. Separate from KNOWN_LIB_TAGS on purpose -- see MARKING.
SCOPE_EXCLUDED = "SCOPE_EXCLUDED"

# Consumers must exclude on this too. Kept here so there is one place to read
# when wiring a new consumer, rather than a literal scattered across modules.
ALL_EXCLUDING_TAGS = ls.KNOWN_LIB_TAGS + (SCOPE_EXCLUDED,)


# EmptyGraph and function_referrers now live in call_graph, because
# documentation ordering needs the SAME graph pointed the other way (callees
# before callers). Two builders answering "what references what" is the shape
# of most defects in this codebase; there is one, and both consumers import it.
# Re-exported here so this module's own API is unchanged.
EmptyGraph = _cg.EmptyGraph
function_referrers = _cg.function_referrers


@dataclass
class ScopeReport:
    program: str
    binary: str = ""
    total: int = 0
    seed_library: int = 0
    swept: List[dict] = field(default_factory=list)
    protected: List[dict] = field(default_factory=list)
    in_scope: List[dict] = field(default_factory=list)
    rounds: int = 0
    edges: int = 0
    unreferenced: int = 0

    def to_json(self) -> dict:
        return {
            "program": self.program, "binary": self.binary,
            "total": self.total, "seed_library": self.seed_library,
            "swept": self.swept, "swept_count": len(self.swept),
            "protected_count": len(self.protected),
            "in_scope": self.in_scope, "in_scope_count": len(self.in_scope),
            "rounds": self.rounds, "edges": self.edges,
            "unreferenced": self.unreferenced,
        }


# --------------------------------------------------------------------------
# references
# --------------------------------------------------------------------------

# Where the C runtime hands control to code the AUTHOR wrote. These are the
# only doors between the two worlds, and they are enumerable because the CRT is
# the same CRT everywhere: the DllMain dispatchers, the static-initializer
# table walkers, the process entry shims, and the atexit/TLS callback invokers.
#
# A function called from one of these, that no identification lane claimed, is
# an AUTHORED ENTRY POINT by construction -- there is no other reason for the
# CRT to be calling it.
#
# Without this, a single boundary mistake CASCADES and deletes the whole
# authored subtree. Measured on PD2_EXT.dll: `dllmain_dispatch` calls
# `PD2EXT_InstallBootstrapHook`, whose only referrer it is, so the hook was
# swept; that made it "library", which swept `PD2EXT_InstallGameAndFogHooks`,
# which swept `PD2EXT_RemoveLastPathComponent`. Three of the binary's four
# authored functions, gone, from one wrong verdict -- and a human reviewing 119
# swept entries has to spot exactly those three.
_CRT_HANDOFF = (
    "dllmain_dispatch", "dllmain_raw",          # -> the user's DllMain
    "_initterm", "initterm_e",                  # -> static initializers
    "execute_onexit_table",                     # -> atexit-registered user code
    "scrt_common_main",                         # -> the user's main/WinMain
    "maincrtstartup", "winmaincrtstartup",
    "tls_callback",                             # -> user TLS callbacks
)

# Names that CONTAIN a handoff token but are CRT-internal plumbing, not a door
# to user code. Without these the rule over-protects badly: on PD2_EXT it kept
# 16 CRT functions in scope (`FLS_CleanupCurrentThread`, `GAME_InitCommandLine`,
# `MEMMGR_DetectSimdCapabilities`) purely because `__scrt_dllmain_after_initialize_c`
# or `CRT_DllMainProcessAttach` called them. Over-protecting is the SAFE
# direction -- it leaves CRT in scope rather than deleting authored code -- but
# it is still wrong, and these three prefixes are the whole difference.
_CRT_INTERNAL = ("scrt_dllmain_", "dllmain_crt_", "dllmainprocess")


def _is_crt_handoff(name: str) -> bool:
    """Does this function hand control from the CRT to code the author wrote?"""
    n = (name or "").lower()
    if any(k in n for k in _CRT_INTERNAL):
        return False
    return any(k in n for k in _CRT_HANDOFF)


def protected_addresses(program: str,
                        referrers: Optional[Dict[str, Set[str]]] = None,
                        names: Optional[Dict[str, str]] = None,
                        library: Optional[Set[str]] = None) -> Dict[str, str]:
    """{addr -> why} for functions the sweep may never touch.

    Three structural sources, all rename-proof:
      * exports
      * entry points
      * anything the CRT hands control to that no lane identified as library
        (see _CRT_HANDOFF -- this is what stops the cascade)
    """
    out: Dict[str, str] = {}
    if referrers is not None and names is not None:
        lib = library or set()
        for addr, refs in referrers.items():
            if addr in lib:
                continue                       # positively identified; not ours
            for r in refs:
                if r != "?unattributed" and _is_crt_handoff(names.get(r, "")):
                    out[addr] = f"called by CRT handoff {names.get(r, r)}"
                    break
    try:
        for x in ls._items(ls._get("/list_exports", program=program, limit=5000),
                           "exports"):
            a = x.get("address") if isinstance(x, dict) else None
            if a:
                out[ls.norm_addr(a)] = "export"
    except Exception as e:                                       # noqa: BLE001
        print(f"  ! list_exports failed for {program}: {e}", flush=True)
    try:
        for x in ls._items(ls._get("/get_entry_points", program=program),
                           "entry_points"):
            a = x.get("address") if isinstance(x, dict) else x
            if a:
                out[ls.norm_addr(a)] = "entry point"
    except Exception as e:                                       # noqa: BLE001
        print(f"  ! get_entry_points failed for {program}: {e}", flush=True)
    return out


# --------------------------------------------------------------------------
# the sweep
# --------------------------------------------------------------------------

def sweep_program(program: str, extra_seeds: Optional[Iterable[str]] = None
                  ) -> ScopeReport:
    """Compute the scope verdict for one program. Writes NOTHING."""
    rep = ScopeReport(program=program, binary=os.path.basename(program))
    fns = {ls.norm_addr(f["address"]): (f.get("name") or "")
           for f in ls._items(ls._get("/list_functions", program=program,
                                      limit=200000), "functions")}
    rep.total = len(fns)
    if not fns:
        return rep

    ranges = ls._function_ranges(program)
    referrers = function_referrers(program, list(fns), ranges)
    rep.edges = sum(len(v) for v in referrers.values())
    rep.unreferenced = sum(1 for a in fns if not referrers.get(a))

    lib = set(ls.existing_lib_tags(program))
    for a in (extra_seeds or ()):
        lib.add(ls.norm_addr(a))
    rep.seed_library = len(lib)

    # Protection is computed AFTER the seed library is known: the CRT-handoff
    # rule only protects functions no lane identified, so a CRT helper that
    # DllMain legitimately calls is still sweepable.
    protected = protected_addresses(program, referrers=referrers,
                                    names=fns, library=lib)
    rep.protected = [{"address": a, "name": fns.get(a, ""), "why": w}
                     for a, w in sorted(protected.items()) if a in fns]

    seeded = set(lib)
    swept_reason: Dict[str, List[str]] = {}
    added, rounds = 1, 0
    while added:
        added, rounds = 0, rounds + 1
        for a in fns:
            if a in lib or a in protected:
                continue
            refs = referrers.get(a)
            # No referrers, or an unattributable one, or any referrer outside
            # the library set -> stays in scope. Every uncertainty keeps it.
            if not refs or "?unattributed" in refs:
                continue
            if refs <= lib:
                lib.add(a)
                swept_reason[a] = sorted(refs)
                added += 1
    rep.rounds = rounds

    for a in sorted(swept_reason):
        rep.swept.append({
            "address": a, "name": fns.get(a, ""),
            "referrers": [{"address": r, "name": fns.get(r, "")}
                          for r in swept_reason[a][:8]],
            "referrer_count": len(swept_reason[a]),
            "reason": "all %d referrer(s) are library code" % len(swept_reason[a]),
        })
    rep.in_scope = [{"address": a, "name": fns[a]}
                    for a in sorted(fns) if a not in lib]
    return rep


# --------------------------------------------------------------------------
# the writer
# --------------------------------------------------------------------------

def apply_scope(rep: ScopeReport) -> dict:
    """Write SCOPE_EXCLUDED + the `Scope` reason for every swept function.

    Goes through `library_scope._checked_post`, which treats an `error` in a
    200 body as a failure. Without that, a corpus apply reported "tagged 5462"
    while Ghidra's tag count did not move by one.
    """
    stats = {"tagged": 0, "failed": 0}
    if not rep.swept:
        return stats
    try:
        ls._post("/create_property_map", rep.program,
                 {"name": ls.SCOPE_MAP, "type": "string"})
    except Exception:                                            # noqa: BLE001
        pass                                   # already exists is the normal case
    for s in rep.swept:
        try:
            ls._checked_post("/add_function_tag", rep.program,
                             {"function": s["address"], "tags": SCOPE_EXCLUDED})
            ls._checked_post("/set_property", rep.program,
                             {"map": ls.SCOPE_MAP, "address": s["address"],
                              "value": SCOPE_EXCLUDED})
            ls._checked_post("/set_bookmark", rep.program, {
                "address": s["address"], "category": "Library Scope",
                "comment": f"{SCOPE_EXCLUDED}: {s['reason']}"})
            stats["tagged"] += 1
        except Exception as e:                                   # noqa: BLE001
            print(f"  ! scope tag failed {s['address']} ({s['name']}): {e}",
                  flush=True)
            stats["failed"] += 1
    return stats

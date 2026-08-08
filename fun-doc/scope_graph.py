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
unreachable. The tag records what we actually know, and a durable bookmark
carries the referrer reason (it survives a rename, as FID's do).

NOT the `Scope` property map, which the globals lane uses: every reader of that
map treats an entry as a DATA address, and the globals panel takes the map's
SIZE as its hidden-globals count. See `apply_scope`.
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
import scope_tags as _st                                         # noqa: E402

# The inference tag. Separate from KNOWN_LIB_TAGS on purpose -- see MARKING.
# Declared in scope_tags, where every consumer reads it from; re-exported for
# this module's own callers and tests.
SCOPE_EXCLUDED = _st.SCOPE_EXCLUDED
ALL_EXCLUDING_TAGS = _st.ALL_EXCLUDING_TAGS


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
# the controls
# --------------------------------------------------------------------------

#: Benchmark.dll is the only binary in the corpus with ground truth: 9 functions
#: whose C source we wrote. Shared with `library_scope`, same authored list.
BENCHMARK_BINARY = ls.BENCHMARK_BINARY

#: The binary where the cascade was MEASURED (2026-08-04). Its four authored
#: functions form a chain each of whose only referrer is the one above it, rooted
#: at the CRT's DllMain -- so it is the one place a live sweep can demonstrate
#: that the boundary guard still works. The offline test proves the logic against
#: a mocked graph; only this proves it against a real one.
CASCADE_CONTROL_BINARY = "PD2_EXT.dll"

#: The chain, top to bottom. A name-based control is fine where a name-based
#: CLASSIFIER is not: when this fires, a human reads it.
CASCADE_CONTROL_AUTHORED = (
    "PD2EXT_LoadModAfterGameDataInit",
    "PD2EXT_InstallBootstrapHook",
    "PD2EXT_InstallGameAndFogHooks",
    "PD2EXT_RemoveLastPathComponent",
)


def benchmark_gate(reports: Sequence[ScopeReport]) -> Tuple[bool, List[str]]:
    """(passed, violations). Sweeping an authored Benchmark.dll function fails.

    Deliberately no override parameter, exactly as `library_scope.benchmark_gate`
    has none: a control you can wave through is not a control.
    """
    authored = ls.benchmark_authored_functions()
    if not authored:
        return True, []
    bad: List[str] = []
    for rep in reports:
        if rep.binary != BENCHMARK_BINARY:
            continue
        for s in rep.swept:
            if s.get("name") in authored:
                bad.append(f"{s['name']} @ {s['address']} swept -- {s.get('reason', '')}")
    return (not bad), bad


def cascade_control(reports: Sequence[ScopeReport]
                    ) -> Tuple[bool, bool, List[str]]:
    """(passed, exercised, violations) for the PD2_EXT authored chain.

    `exercised` is the half that matters most. A sweep that returns NOTHING
    passes a "was anything authored swept?" check while being completely dead --
    the same trap the CRT detector's control has (claim nothing, pass the
    positive control), which is why that one is paired with a mirror test. Here
    the mirror is built in: the control only counts as exercised if the four
    authored names were actually FOUND in the program, so an empty or failed
    sweep reports "not exercised" rather than "passed".
    """
    violations: List[str] = []
    exercised = False
    for rep in reports:
        if rep.binary != CASCADE_CONTROL_BINARY:
            continue
        seen = {s["name"] for s in rep.swept}
        seen |= {x["name"] for x in rep.in_scope}
        seen |= {p["name"] for p in rep.protected}
        found = [n for n in CASCADE_CONTROL_AUTHORED if n in seen]
        if len(found) < len(CASCADE_CONTROL_AUTHORED):
            missing = [n for n in CASCADE_CONTROL_AUTHORED if n not in seen]
            print(f"  ! cascade control NOT exercised on {rep.binary}: "
                  f"{len(missing)} authored function(s) not found "
                  f"({', '.join(missing[:4])}). Renamed, or the sweep read "
                  f"nothing.", flush=True)
            continue
        exercised = True
        swept_names = {s["name"] for s in rep.swept}
        for n in CASCADE_CONTROL_AUTHORED:
            if n in swept_names:
                violations.append(
                    f"{n} swept on {rep.binary} -- the CRT-handoff guard is not "
                    f"holding, and this is the head of a 3-function cascade")
    return (not violations), exercised, violations


def gate_report(reports: Sequence[ScopeReport]) -> dict:
    """Both controls, as one JSON-able block. The CLI refuses to apply on any
    failure, and refuses on a control that never ran unless told to acknowledge
    it -- an unexercised control is not a passing one."""
    b_passed, b_bad = benchmark_gate(reports)
    c_passed, c_exercised, c_bad = cascade_control(reports)
    swept_benchmark = any(r.binary == BENCHMARK_BINARY for r in reports)
    return {
        "passed": bool(b_passed and c_passed),
        "benchmark": {"passed": b_passed, "exercised": swept_benchmark,
                      "violations": b_bad},
        "cascade": {"passed": c_passed, "exercised": c_exercised,
                    "violations": c_bad},
        "violations": b_bad + c_bad,
    }


# --------------------------------------------------------------------------
# drift: the reviewed set must be the written set
# --------------------------------------------------------------------------

def swept_index(reports: Sequence[ScopeReport]) -> Dict[str, Set[str]]:
    """{program -> set(addresses swept)}. The unit the review is about."""
    return {r.program: {s["address"] for s in r.swept} for r in reports}


def saved_swept_index(saved: dict) -> Dict[str, Set[str]]:
    """Same shape, read back out of a report JSON written by the sweep."""
    out: Dict[str, Set[str]] = {}
    for p in (saved or {}).get("programs") or []:
        prog = p.get("program")
        if not prog:
            continue
        out[prog] = {s.get("address") for s in (p.get("swept") or [])
                     if isinstance(s, dict) and s.get("address")}
    return out


def report_drift(saved: dict, fresh: Sequence[ScopeReport]) -> List[str]:
    """Human-readable differences between a reviewed report and a fresh sweep.

    `--apply` writes the addresses in the FILE, but only after checking the
    binary still produces them. Without this the review is decorative: the graph
    is recomputed from live Ghidra state, so a rename, a re-analysis or another
    lane's tags landing in between can move the verdict, and the operator would
    be approving one set while a different set got written.

    Empty list means the report is still an accurate description of the binary.
    """
    old, new = saved_swept_index(saved), swept_index(fresh)
    out: List[str] = []
    for prog in sorted(set(old) | set(new)):
        if prog not in old:
            out.append(f"{prog}: not in the reviewed report at all "
                       f"({len(new[prog])} swept now)")
            continue
        if prog not in new:
            out.append(f"{prog}: in the reviewed report but not in this sweep")
            continue
        added = sorted(new[prog] - old[prog])
        gone = sorted(old[prog] - new[prog])
        if added:
            out.append(f"{prog}: {len(added)} address(es) swept now that were "
                       f"not in the report ({', '.join(added[:6])})")
        if gone:
            out.append(f"{prog}: {len(gone)} address(es) in the report are no "
                       f"longer swept ({', '.join(gone[:6])})")
    return out


# --------------------------------------------------------------------------
# the writer
# --------------------------------------------------------------------------

def apply_scope(rep: ScopeReport) -> dict:
    """Write the SCOPE_EXCLUDED tag + a durable bookmark for every swept function.

    The bookmark matters as much as the tag: like FID's, it SURVIVES a later
    rename, so an overwritten verdict stays recoverable rather than merely
    detectable -- and it is where the referrer reason lives.

    Deliberately NOT the `Scope` property map, even though the globals lane and
    this module's own MARKING note reach for it. Every reader of that map in this
    repo treats an entry as a DATA address: `conformance_dashboard`'s globals
    panel takes `len(_scope_excluded_globals(program))` as its hidden-globals
    count, so writing 119 function addresses into the map would have inflated
    that number by 119 and told the operator a binary's globals were being
    excluded when nothing of the sort had happened. The map is for globals; a
    function's durable record is its tag and its bookmark.

    Goes through `library_scope._checked_post`, which treats an `error` in a
    200 body as a failure. Without that, a corpus apply reported "tagged 5462"
    while Ghidra's tag count did not move by one.
    """
    stats = {"tagged": 0, "failed": 0}
    if not rep.swept:
        return stats
    for s in rep.swept:
        try:
            ls._checked_post("/add_function_tag", rep.program,
                             {"function": s["address"], "tags": SCOPE_EXCLUDED})
            ls._checked_post("/set_bookmark", rep.program, {
                "address": s["address"], "category": "Library Scope",
                "comment": f"{SCOPE_EXCLUDED}: {s['reason']}"})
            stats["tagged"] += 1
        except Exception as e:                                   # noqa: BLE001
            print(f"  ! scope tag failed {s['address']} ({s['name']}): {e}",
                  flush=True)
            stats["failed"] += 1
    return stats


def existing_scope_tags(program: str) -> Set[str]:
    """Addresses already carrying SCOPE_EXCLUDED in Ghidra.

    Deliberately NOT unioned into the sweep's SEED SET. Within one run the
    fixed-point iteration is bounded and the whole of it lands in a report a human
    reads; across runs, seeding from a previous inference would let one wrong
    verdict become the premise for the next, compounding silently with nothing to
    review. Seeds stay proof-only (`ls.existing_lib_tags`), which also makes the
    sweep deterministic -- re-running produces the same set, which is exactly what
    the `--apply` drift check depends on.

    What this IS for: reconciling the SQL flag with the durable tag.
    """
    out: Set[str] = set()
    for tag in _st.INFERRED_TAGS:
        try:
            res = ls._get("/search_functions_by_tag", program=program, tag=tag,
                          limit=200000)
        except Exception as e:                                   # noqa: BLE001
            print(f"  ! cannot read {tag} on {program}: {e}", flush=True)
            continue
        for f in ls._items(res, "functions"):
            if isinstance(f, dict) and f.get("address"):
                out.add(ls.norm_addr(f["address"]))
    return out


def sync_scope_excluded_flags(reports: Sequence[ScopeReport]) -> dict:
    """Mirror the durable SCOPE_EXCLUDED tag into `functions_workflow`.

    The selector reads the COLUMN, not the tag, so a tag written without this is
    inert -- the exact 681-function gap measured on D2Client.dll, where 1,020
    LIB_* tags faced 339 flagged rows and the difference was still being handed to
    workers.

    PER-FUNCTION via `update_function_state`, never load_state + mutate +
    save_state. The bulk path is a read-modify-write over every row in the binary,
    so a Doc worker finishing a function between our load and our save loses its
    entire result. This sweep is explicitly something you might run while the
    fleet is working.

    Verdicts UNION the durable tags, computed BEFORE the empty check, for the
    same reason `library_scope.sync_library_code_flags` does it: syncing only
    this run's finds leaves every pre-existing verdict unflagged, and an
    empty-check ahead of the union makes a reconcile pass over an already-swept
    program report 0 updated and do nothing at all.
    """
    try:
        import fun_doc                                           # noqa: PLC0415
    except Exception as e:                                       # noqa: BLE001
        print(f"  ! cannot import fun_doc to sync flags: {e}", flush=True)
        return {"updated": 0, "missing": 0, "failed": 0, "error": str(e)}

    now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    stats = {"updated": 0, "missing": 0, "failed": 0}
    for rep in reports:
        reasons = {s["address"]: s.get("reason") or "all referrers are library code"
                   for s in rep.swept}
        for addr in existing_scope_tags(rep.program):
            reasons.setdefault(addr, "pre-existing SCOPE_EXCLUDED tag (durable)")
        if not reasons:
            continue
        try:
            state = fun_doc.load_state(binary_name=rep.binary)
            if not state:
                state = fun_doc.load_state()
        except Exception as e:                                   # noqa: BLE001
            print(f"  ! load_state failed for {rep.binary}: {e}", flush=True)
            continue
        # Read-only use of the loaded state: it supplies the key and the existing
        # record, and is never handed back to save_state.
        by_addr = {}
        for key, f in (state or {}).get("functions", {}).items():
            if f.get("program") != rep.program:
                continue
            by_addr[ls.norm_addr(f.get("address"))] = (key, f)

        for addr, reason in reasons.items():
            hit = by_addr.get(addr)
            if not hit:
                stats["missing"] += 1
                continue
            key, existing = hit
            if existing.get("scope_excluded"):
                continue                       # already flagged; nothing to write
            patch = dict(existing)
            patch["scope_excluded"] = True
            patch["scope_excluded_at"] = now
            patch["scope_excluded_reasons"] = [reason]
            try:
                fun_doc.update_function_state(key, patch)
                stats["updated"] += 1
            except Exception as e:                               # noqa: BLE001
                print(f"  ! flag write failed {rep.binary} {addr}: {e}", flush=True)
                stats["failed"] += 1
    return stats

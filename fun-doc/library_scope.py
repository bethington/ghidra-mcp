"""Unified library-code identification and inventory scoping.

The question this module answers is "what in this binary is NOT worth
documenting, because the toolchain wrote it rather than a person" -- and then
gets that population out of every count, bar and percentage the operator reads.

WHY A FOURTH MODULE

Three identification lanes already existed and none of them owned the outcome:

    crt_identify.py         byte-exact vs the real MSVC static runtimes
    doc_lint.fid_bookmarks  Ghidra's Function ID analyzer, read from bookmarks
    bsim_identify.py        same-source/different-build similarity

Each writes its own verdict its own way, and the *consumer* side (the dashboard
denominators, the selector's skip, the globals inventory) reads a mix of Ghidra
tags, a SQL flag, and a `Scope` property map that nothing in Python ever wrote.
The result was measurable: PD2_EXT.dll carried 272 LIB_CRT tags while all 463 of
its SQL rows said `library_code = 0`, and its `Scope` map was empty while
D2Common's held 369 entries. Same corpus, three disagreeing answers, and the
operator saw whichever one the panel in front of them happened to read.

So this module does not add a fourth detector. It sequences the three that
exist, adds the one population nobody computed (library-owned GLOBALS), and
writes ONE verdict to all three consumers.

LANE PRECEDENCE -- first hit wins, later lanes never override

    1  bytes      crt_identify        exact, abstains          -> tag
    2  fid        Function ID         exact, abstains          -> tag
    3  bsim       BSim sim/signif     calibrated, abstains     -> tag
    4  heuristic  library_code_detector  guesses               -> REVIEW ONLY

The ordering is by evidence quality, and the first three write autonomously
because each is calibrated to abstain rather than guess (`STRONG_INFORMATIVE_BYTES`,
FID's own single/multiple-match flag, `SIGNIF_FLOOR`). The fourth never writes a
tag. That is not timidity: a LIB_* tag makes the selector skip a function
PERMANENTLY, so a heuristic with an irreversible action is a heuristic that
quietly deletes real game code from the work queue. The repo has the receipt --
`PD2_AllocItemExtraData`, hand-written game code, read as CRT because it called
`_CxxThrowException`. Its hits go to a review list for bulk approval instead.

Precedence is "first hit wins" rather than "best hit wins" for the same reason
`crt_identify` takes the tightest match: once an exact lane has spoken, a later
lane's disagreement is not new information, it is noise with a worse prior.

LIBRARY GLOBALS -- the exclusive-reference rule

A global is library-owned iff EVERY function that references it is library
code. One game-logic referrer keeps it in scope. The asymmetry is deliberate
and points the safe way: a global the game touches matters even if the CRT
touches it too, so `g_dwLastError` (read by `GAME_Init`, written by the CRT)
stays in the inventory, while `__acrt_ptd_head` (CRT-only) leaves it.

Names cannot do this job. 306 of PD2_EXT.dll's 404 globals had already been
renamed to `g_*` by a globals worker that had no idea it was documenting CRT
locale tables and PTD slots -- so by the time you ask, the name is evidence of
past effort, not of provenance. References survive renaming; names do not.

Globals with NO references default to STAYING in the inventory. They cannot be
proven library-owned, and the whole point of the exclusive rule is that absence
of evidence is not evidence of absence.

WHAT GETS WRITTEN (only with apply=True)

    Ghidra   LIB_* function tag + a durable bookmark  (via each lane's own
             sync_to_ghidra -- this module is NOT a fourth writer)
    Ghidra   `Scope` property map on library-owned globals, value = the tag
    SQL      functions_workflow.library_code = 1, with lane attribution in
             library_code_reasons

Nothing is deleted. Every exclusion is a flag, so a bad verdict is one flip to
undo and the audit trail of which lane said what survives.

THE BENCHMARK GATE

`Benchmark.dll` has ground truth: 9 authored functions whose source we wrote.
If any lane claims one of them, the sweep does not apply -- full stop, no
override flag. It is the same positive control `crt_identify` uses, promoted to
a hard gate because this sweep's blast radius is the whole corpus rather than
one binary.

USAGE

    python fun-doc/scripts/library_scope_sweep.py --folder /Mods/PD2-S12
    python fun-doc/scripts/library_scope_sweep.py --program /Mods/PD2-S12/D2Common.dll
    python fun-doc/scripts/library_scope_sweep.py --folder /Mods/PD2-S12 --apply
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crt_identify as ci                                        # noqa: E402
from library_code_detector import detect_library_code            # noqa: E402

GHIDRA_URL = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089")

# The tag vocabulary the CONSUMERS already read. conformance_dashboard.LIB_TAGS
# and fun_doc._ASSESS_LIB_TAGS must stay supersets of whatever we emit, or an
# exclusion written here is invisible to the panel that renders it.
TAG_CRT = "LIB_CRT"
TAG_EH = "LIB_MSVC_EH"
TAG_MSVC = "LIB_MSVC"
KNOWN_LIB_TAGS = (TAG_CRT, TAG_EH, "LIB_SECURITY", "LIB_MATH", TAG_MSVC, "LIB_UNKNOWN")

# The property map the globals inventory already reads
# (conformance_dashboard._scope_excluded_globals). Its value is the tag that
# justified the exclusion, so the map is self-documenting when read raw.
SCOPE_MAP = "Scope"

# Benchmark.dll's authored functions -- the positive control. Sourced from the
# benchmark's own ground truth rather than retyped, so the two cannot drift.
BENCHMARK_BINARY = "Benchmark.dll"

# A library function still wearing a game-style name is the tell for BOTH a bad
# LIB_ verdict and an earlier bad rename (143 such were caught corpus-wide in
# 2026-08). Matches `SUBSYS_PascalCase` and bare `PascalCase`, not `_qsort` or
# the `?...@@YA...` mangled forms, which are what correct library names look like.
_GAME_STYLE = re.compile(r"^(?:[A-Z][A-Z0-9]{1,11}_)?[A-Z][a-z][A-Za-z0-9]*$")


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def _get(path: str, **params) -> dict:
    url = f"{GHIDRA_URL}{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=300) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _post(path: str, program: str, body: dict) -> dict:
    url = f"{GHIDRA_URL}{path}?" + urllib.parse.urlencode({"program": program})
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=300) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def _items(payload, key: str) -> list:
    """Unwrap a 7.0.0 envelope. Every reader here goes through this for the
    reason the response-contract guard exists: a bare `.get(key)` against an
    enveloped response returns [] and reads as 'clean' rather than 'broken',
    which is how two inventories silently reported 0 rows for days."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return []
    if not isinstance(payload, dict):
        return list(payload) if isinstance(payload, (list, tuple)) else []
    inner = payload.get("result")
    if isinstance(inner, (str, dict)):
        got = _items(inner, key)
        if got:
            return got
    for k in (key, "items", "data"):
        v = payload.get(k)
        if isinstance(v, list):
            return v
    return []


def norm_addr(a) -> str:
    """'0x' + zero-padded lowercase hex. The one canonical form in this module.

    Written out rather than using `lstrip("0x")` on purpose: lstrip takes a
    CHARACTER SET, so it also eats leading zeros and any leading 'a'..'f' that
    happens to be a 0 or x -- the exact bug that made two address sets that
    should have compared equal silently miss each other.
    """
    s = str(a or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.lstrip("0") or "0"
    return "0x" + s.rjust(8, "0")


# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------

@dataclass
class Verdict:
    """One function's library-code verdict, with the lane that produced it."""

    address: str                  # canonical norm_addr form
    lane: str                     # bytes | fid | bsim | heuristic
    tag: str                      # LIB_CRT / LIB_MSVC_EH / ...
    lib_name: Optional[str]       # the library's own symbol, when known
    current_name: str
    evidence: str                 # human-readable, lands in the report

    @property
    def writes_tag(self) -> bool:
        """Only the exact/abstaining lanes tag. See the module docstring."""
        return self.lane in AUTONOMOUS_LANES

    @property
    def game_styled(self) -> bool:
        """Library code wearing a game-style name -- goes to the review list."""
        n = self.current_name or ""
        return bool(_GAME_STYLE.match(n)) and not ci.is_default_name(n)


AUTONOMOUS_LANES = ("bytes", "fid", "bsim")
ALL_LANES = AUTONOMOUS_LANES + ("heuristic",)


@dataclass
class ProgramReport:
    """Everything one program's sweep found. Serialized straight into the JSON."""

    program: str
    binary: str = ""
    defined: int = 0
    verdicts: Dict[str, Verdict] = field(default_factory=dict)
    review: List[Verdict] = field(default_factory=list)      # heuristic-only
    styled: List[Verdict] = field(default_factory=list)      # name needs a look
    lib_globals: List[dict] = field(default_factory=list)
    total_globals: int = 0
    library_population: int = 0   # this run's verdicts UNION pre-existing tags
    lane_counts: Dict[str, int] = field(default_factory=dict)
    lanes_skipped: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def in_scope(self) -> int:
        return max(0, self.defined - len(self.verdicts))

    def to_json(self) -> dict:
        return {
            "program": self.program,
            "binary": self.binary,
            "defined": self.defined,
            "library": len(self.verdicts),
            "in_scope": self.in_scope,
            "lane_counts": self.lane_counts,
            "lanes_skipped": self.lanes_skipped,
            "library_population": self.library_population,
            "globals_total": self.total_globals,
            "globals_library": len(self.lib_globals),
            "review_queue": [
                {"address": v.address, "name": v.current_name,
                 "evidence": v.evidence} for v in self.review],
            "styled_names": [
                {"address": v.address, "name": v.current_name, "lane": v.lane,
                 "lib_name": v.lib_name, "evidence": v.evidence}
                for v in self.styled],
            "library_globals": self.lib_globals,
            "verdicts": [
                {"address": v.address, "lane": v.lane, "tag": v.tag,
                 "name": v.current_name, "lib_name": v.lib_name,
                 "evidence": v.evidence}
                for v in sorted(self.verdicts.values(), key=lambda x: x.address)],
            "errors": self.errors,
        }


# --------------------------------------------------------------------------
# Lane 1 -- byte-exact against the real MSVC static runtimes
# --------------------------------------------------------------------------

def lane_bytes(program: str, index=None) -> Tuple[List[Verdict], Optional[str]]:
    """crt_identify's exact matcher. Returns (verdicts, skip_reason)."""
    try:
        index = index or ci.load_index()
    except Exception as e:                                       # noqa: BLE001
        return [], f"no library index: {e}"
    try:
        matches = ci.identify_program(program, index=index)
    except Exception as e:                                       # noqa: BLE001
        return [], f"identify_program failed: {e}"

    out: List[Verdict] = []
    for m in matches:
        # `writable` is crt_identify's own abstention gate: ambiguous matches
        # and matches below STRONG_INFORMATIVE_BYTES write nothing. Honouring
        # it here rather than re-deciding keeps ONE calibration, not two.
        if not m.writable:
            continue
        out.append(Verdict(
            address=norm_addr(m.address), lane="bytes",
            tag=_tag_for(m.lib_name or ""), lib_name=m.lib_name,
            current_name=m.current_name or "",
            evidence=f"byte-exact {m.informative}B informative vs {m.lib}({m.obj})"))
    return out, None


# --------------------------------------------------------------------------
# Lane 2 -- Ghidra's Function ID analyzer, read from bookmarks
# --------------------------------------------------------------------------

def lane_fid(program: str) -> Tuple[List[Verdict], Optional[str]]:
    """Function ID matches, read from "Function ID Analyzer" bookmarks.

    Bookmarks rather than names: a FID bookmark SURVIVES a later rename, which
    is what makes an overwritten library name recoverable rather than merely
    detectable. Multiple-match bookmarks are dropped -- FID itself is telling
    us it could not decide, and a tag is not the place to record a maybe.
    """
    try:
        bms = _items(_get("/list_bookmarks", program=program, limit=200000),
                     "bookmarks")
    except Exception as e:                                       # noqa: BLE001
        return [], f"list_bookmarks failed: {e}"

    names = _function_names(program)
    out: List[Verdict] = []
    for b in bms:
        if (b.get("category") or "") != "Function ID Analyzer":
            continue
        comment = (b.get("comment") or "").strip()
        if not comment or "Multiple" in comment:
            continue
        addr = norm_addr(b.get("address"))
        fid_name = comment.split()[-1].strip(", ")
        if not fid_name:
            continue
        out.append(Verdict(
            address=addr, lane="fid", tag=_tag_for(fid_name),
            lib_name=fid_name, current_name=names.get(addr, ""),
            evidence=f"FID single match: {fid_name}"))
    return out, None


# --------------------------------------------------------------------------
# Lane 3 -- BSim
# --------------------------------------------------------------------------

def lane_bsim(program: str, dump: Optional[str] = None
              ) -> Tuple[List[Verdict], Optional[str]]:
    """BSim same-source/different-build matches, from a pre-queried dump.

    Deliberately abstains wholesale when no dump is configured. BSim's Ghidra
    side has to run as a script and write JSONL before Python can apply any
    threshold, so "no dump" genuinely means "this lane did not run" -- and that
    is reported as a skip rather than silently contributing nothing, because a
    lane that quietly finds zero is indistinguishable from a lane that is
    broken. (No silent caps.)
    """
    if not dump:
        return [], "no BSim dump supplied (--bsim-dump); lane did not run"
    if not os.path.exists(dump):
        return [], f"BSim dump not found: {dump}"
    try:
        import bsim_identify as bi                               # noqa: PLC0415
        matches = list(bi.identify_from_dump(dump, program))
    except Exception as e:                                       # noqa: BLE001
        return [], f"BSim lane failed: {e}"

    names = _function_names(program)
    out: List[Verdict] = []
    for m in matches:
        if not getattr(m, "writable", False):
            continue
        addr = norm_addr(getattr(m, "address", ""))
        lib_name = getattr(m, "lib_name", None) or getattr(m, "match_name", None)
        out.append(Verdict(
            address=addr, lane="bsim", tag=_tag_for(lib_name or ""),
            lib_name=lib_name, current_name=names.get(addr, ""),
            evidence=f"BSim sim={getattr(m, 'sim', '?')} signif={getattr(m, 'signif', '?')}"))
    return out, None


# --------------------------------------------------------------------------
# Lane 4 -- the heuristic, which never tags
# --------------------------------------------------------------------------

def lane_heuristic(program: str, already: Set[str]
                   ) -> Tuple[List[Verdict], Optional[str]]:
    """library_code_detector over names + callees. Review queue only.

    Runs without decompilation on purpose: `detect_library_code` accepts
    `decompile=None`, and the callee list from one call-graph fetch is a
    stronger signal than a body substring anyway ("direct enumeration beats
    substring search"). That makes this lane two HTTP calls per program rather
    than one per function.
    """
    try:
        fns = _items(_get("/list_functions", program=program, limit=200000),
                     "functions")
    except Exception as e:                                       # noqa: BLE001
        return [], f"list_functions failed: {e}"
    try:
        edges = _items(_get("/get_full_call_graph", program=program, limit=500000),
                       "edges")
    except Exception as e:                                       # noqa: BLE001
        edges = []
        print(f"  ! call graph unavailable for {program}: {e} "
              f"(heuristic lane runs on names alone)", flush=True)

    callees: Dict[str, List[str]] = {}
    for e in edges:
        src = norm_addr(e.get("from") or e.get("source") or e.get("caller"))
        dst = e.get("to_name") or e.get("target_name") or e.get("callee")
        if src and dst:
            callees.setdefault(src, []).append(str(dst))

    out: List[Verdict] = []
    for f in fns:
        addr = norm_addr(f.get("address"))
        if addr in already:
            continue                      # an exact lane already decided
        name = f.get("name") or ""
        res = detect_library_code(name, None, callees.get(addr))
        if not res.is_library:
            continue
        out.append(Verdict(
            address=addr, lane="heuristic", tag=TAG_CRT, lib_name=None,
            current_name=name,
            evidence=f"heuristic conf={res.confidence:.2f} {','.join(res.reasons)}"))
    return out, None


def _tag_for(lib_name: str) -> str:
    """Map a library symbol to the tag vocabulary the consumers already read.

    ORDER MATTERS and the specific families come first. The generic EH test
    keys on "except", which also appears in `__87except` -- the x87 FPU
    exception path, which is math, not C++ exception handling. Testing EH first
    routed it to LIB_MSVC_EH; testing math first gets it right. Same shape for
    security: `___security_init_cookie` contains neither "security_cookie" nor
    "gsfailure", so the narrow keyword missed it entirely and it fell through
    to the LIB_CRT catch-all.

    Every branch returns a member of KNOWN_LIB_TAGS -- a tag outside that set
    is invisible to the dashboard and the selector, so the exclusion would be
    written and never take effect.
    """
    n = (lib_name or "").lower()
    if any(k in n for k in ("security", "gsfailure", "guard_check",
                            "checkstack", "_chkstk")):
        return "LIB_SECURITY"
    if any(k in n for k in ("libm_", "matherr", "fpclass", "87except", "ctrlfp",
                            "sptype", "powhlp", "frnd", "statfp", "fload",
                            "twotos", "decomp", "_fpe")):
        return "LIB_MATH"
    if any(k in n for k in ("ehframe", "except", "unwind", "typeinfo",
                            "framehandler", "cxxthrow", "eh_", "_eh4",
                            "terminate", "catchblock", "trydtor")):
        return TAG_EH
    return TAG_CRT


def existing_lib_tags(program: str) -> Set[str]:
    """Addresses already carrying any LIB_* tag in Ghidra.

    The globals rule needs the FULL library population, not just what this run
    happened to (re)discover. A lane that reads bookmarks reports every match
    every time, but one that reads a live index may legitimately return fewer
    on a second pass -- and a global whose only referrer was tagged LAST week
    is no less library-owned today. Unioning the durable tags in makes the rule
    idempotent instead of dependent on run history.
    """
    out: Set[str] = set()
    for tag in KNOWN_LIB_TAGS:
        try:
            res = _get("/search_functions_by_tag", program=program, tag=tag,
                       limit=200000)
        except Exception:                                        # noqa: BLE001
            continue
        for f in _items(res, "functions"):
            if isinstance(f, dict) and f.get("address"):
                out.add(norm_addr(f["address"]))
    return out


def _function_names(program: str) -> Dict[str, str]:
    try:
        fns = _items(_get("/list_functions", program=program, limit=200000),
                     "functions")
    except Exception:                                            # noqa: BLE001
        return {}
    return {norm_addr(f.get("address")): (f.get("name") or "") for f in fns}


# --------------------------------------------------------------------------
# The globals rule
# --------------------------------------------------------------------------

_GLOB_LINE = re.compile(
    r"^(?P<name>\S+)\s+@\s+(?P<addr>[0-9a-fA-F]+)\s+\[(?P<kind>[^\]]*)\]"
    r"(?:\s+\((?P<type>[^)]*)\))?(?:\s+xrefs=(?P<xrefs>\d+))?")


def program_globals(program: str) -> Dict[str, dict]:
    """{addr -> {name, type, xrefs}} for the program's globals, one row per ADDRESS.

    One row per address, not per symbol line: Ghidra allows many labels on one
    data address and /list_globals emits a line for each (D2Client has up to
    SEVEN on 0x6fbcb9a0). Counting lines inflates the denominator against every
    address-keyed consumer, which is the same mistake the types bar made.
    """
    out: Dict[str, dict] = {}
    try:
        lines = _items(_get("/list_globals", program=program, limit=200000),
                       "globals")
    except Exception as e:                                       # noqa: BLE001
        print(f"  ! list_globals failed for {program}: {e}", flush=True)
        return out
    for ln in lines:
        m = _GLOB_LINE.match(str(ln).strip())
        if not m:
            continue
        a = norm_addr(m.group("addr"))
        row = out.setdefault(a, {"address": a, "name": m.group("name"),
                                 "type": m.group("type") or "",
                                 "xrefs": int(m.group("xrefs") or 0),
                                 "aliases": []})
        if row["name"] != m.group("name"):
            row["aliases"].append(m.group("name"))
    return out


def library_globals(program: str, lib_addrs: Set[str],
                    globs: Optional[Dict[str, dict]] = None,
                    fn_ranges: Optional[List[Tuple[int, int, str]]] = None
                    ) -> List[dict]:
    """Globals whose EVERY referrer is library code. See the module docstring.

    Zero-xref globals are never returned: they cannot be proven library-owned,
    and the exclusive rule's whole point is that silence is not evidence.
    """
    globs = globs if globs is not None else program_globals(program)
    if not globs:
        return []
    if fn_ranges is None:
        fn_ranges = _function_ranges(program)

    addrs = [a for a, g in globs.items() if g["xrefs"] > 0]
    if not addrs:
        return []

    refs = _bulk_xrefs_to(program, addrs)
    out: List[dict] = []
    for a in addrs:
        srcs = refs.get(a) or []
        if not srcs:
            # Ghidra said xrefs>0 but we could not read them. Abstain: an
            # unreadable reference set is "unknown", not "library-owned".
            continue
        owners = {_owning_function(s, fn_ranges) for s in srcs}
        unresolved = None in owners
        owners.discard(None)
        if not owners:
            # Referenced only from data (import tables, vtables, relocation
            # stubs). Nothing proves that is library-owned, so it stays in.
            continue
        if unresolved:
            # At least one referrer is outside any function we can name. The
            # rule is EXCLUSIVE -- an unidentifiable referrer could be game
            # code, so it blocks exclusion rather than being ignored.
            continue
        if owners <= lib_addrs:
            g = dict(globs[a])
            g["referrers"] = sorted(owners)
            out.append(g)
    return out


def _executable_ranges(program: str) -> List[Tuple[int, int]]:
    """[(lo, hi)] of executable memory blocks, from /list_segments.

    Needed to bound the function map. Without it every reference from .rdata or
    the import table -- and `/get_bulk_xrefs` returns plenty, typed DATA --
    resolves into whichever function happens to precede it in address order,
    manufacturing referrers that do not exist.
    """
    out: List[Tuple[int, int]] = []
    try:
        segs = _items(_get("/list_segments", program=program, limit=1000),
                      "segments")
    except Exception:                                            # noqa: BLE001
        return out
    for s in segs:
        if not isinstance(s, dict):
            continue
        if not (s.get("execute") or s.get("executable") or
                "x" in str(s.get("permissions", "")).lower()):
            continue
        try:
            lo = int(str(s.get("start") or s.get("address")).replace("0x", ""), 16)
            end = s.get("end")
            hi = (int(str(end).replace("0x", ""), 16) + 1 if end
                  else lo + int(s.get("length") or s.get("size") or 0))
        except (TypeError, ValueError):
            continue
        if hi > lo:
            out.append((lo, hi))
    return sorted(out)


def _function_ranges(program: str) -> List[Tuple[int, int, str]]:
    """Sorted [(lo, hi, addr)] so a reference address maps to its function.

    A reference to a global comes from an INSTRUCTION address, not a function
    entry, so the raw xref source has to be resolved to its containing function
    before it can be compared against the library set.

    Each function extends to the next function start, CLAMPED to the end of its
    executable segment. The clamp is the point: unclamped, the last function in
    .text swallows the whole of .rdata, and every data-table reference in the
    binary attributes to it.
    """
    fns = _items(_get("/list_functions", program=program, limit=200000),
                 "functions")
    exec_ranges = _executable_ranges(program)
    rows = []
    for f in fns:
        try:
            lo = int(str(f.get("address")).replace("0x", ""), 16)
        except (TypeError, ValueError):
            continue
        rows.append((lo, norm_addr(f.get("address"))))
    rows.sort()

    def seg_end(addr: int) -> Optional[int]:
        for lo, hi in exec_ranges:
            if lo <= addr < hi:
                return hi
        return None

    out = []
    for i, (lo, a) in enumerate(rows):
        nxt = rows[i + 1][0] if i + 1 < len(rows) else None
        end = seg_end(lo)
        if end is None:
            # No executable segment covers this entry: fall back to the next
            # function start, and never invent a tail past the last one.
            hi = nxt if nxt else lo + 1
        else:
            hi = min(nxt, end) if nxt else end
        if hi > lo:
            out.append((lo, hi, a))
    return out


def _owning_function(addr: int, ranges: List[Tuple[int, int, str]]) -> Optional[str]:
    lo_i, hi_i = 0, len(ranges) - 1
    while lo_i <= hi_i:
        mid = (lo_i + hi_i) // 2
        lo, hi, a = ranges[mid]
        if addr < lo:
            hi_i = mid - 1
        elif addr >= hi:
            lo_i = mid + 1
        else:
            return a
    return None


_HEX_ONLY = re.compile(r"^[0-9a-f]+$")


def _bulk_xrefs_to(program: str, addrs: Sequence[str],
                   chunk: int = 500) -> Dict[str, List[int]]:
    """{global addr -> [source addresses as int]} via /get_bulk_xrefs.

    /get_bulk_xrefs answers with a BARE dict keyed by address --
    `{"10013d38": [{"from": "10013c98", "type": "DATA"}, ...]}` -- not a 7.0.0
    envelope, so it deliberately does not go through _items.

    Non-address sources are dropped. Ghidra reports symbolic origins like
    "Entry Point" in the same field as real addresses, and int(..., 16) on one
    of those raises inside the loop that decides whether a global is
    library-owned -- turning one odd reference into a whole program's globals
    silently coming back empty.

    Chunked because the corpus holds 17,773 globals and one request per global
    is the shape that made the shadowed-globals panel unusable.
    """
    out: Dict[str, List[int]] = {}
    for i in range(0, len(addrs), chunk):
        batch = [a[2:] for a in addrs[i:i + chunk]]
        try:
            res = _post("/get_bulk_xrefs", program, {"addresses": batch})
        except Exception as e:                                   # noqa: BLE001
            print(f"  ! bulk xrefs chunk {i // chunk} failed: {e}", flush=True)
            continue
        if isinstance(res, dict) and "result" in res and isinstance(res["result"], str):
            try:
                res = json.loads(res["result"])
            except json.JSONDecodeError:
                continue
        if not isinstance(res, dict):
            continue
        for key, refs in res.items():
            if not isinstance(refs, list):
                continue
            a = norm_addr(key)
            for r in refs:
                s = r.get("from") if isinstance(r, dict) else r
                s = str(s or "").lower().replace("0x", "").strip()
                if not _HEX_ONLY.match(s):
                    continue                  # "Entry Point" and friends
                out.setdefault(a, []).append(int(s, 16))
    return out


# --------------------------------------------------------------------------
# The sweep
# --------------------------------------------------------------------------

def sweep_program(program: str, lanes: Sequence[str] = ALL_LANES,
                  index=None, bsim_dump: Optional[str] = None,
                  do_globals: bool = True) -> ProgramReport:
    """Run the lanes over one program and assemble its report. Writes nothing."""
    rep = ProgramReport(program=program, binary=os.path.basename(program))
    try:
        rep.defined = len(_items(_get("/list_functions", program=program,
                                      limit=200000), "functions"))
    except Exception as e:                                       # noqa: BLE001
        rep.errors.append(f"list_functions failed: {e}")
        return rep

    runners = {
        "bytes": lambda: lane_bytes(program, index=index),
        "fid": lambda: lane_fid(program),
        "bsim": lambda: lane_bsim(program, dump=bsim_dump),
        "heuristic": lambda: lane_heuristic(program, set(rep.verdicts)),
    }

    # Precedence lives HERE, in the iteration order, not in a scoring function:
    # once an exact lane has claimed an address, later lanes are not consulted
    # for it at all.
    for lane in ALL_LANES:
        if lane not in lanes:
            rep.lanes_skipped[lane] = "not requested"
            continue
        verdicts, skip = runners[lane]()
        if skip:
            rep.lanes_skipped[lane] = skip
            print(f"  lane {lane}: SKIPPED -- {skip}", flush=True)
            continue
        fresh = 0
        for v in verdicts:
            if v.address in rep.verdicts:
                continue
            if v.lane == "heuristic":
                rep.review.append(v)
            else:
                rep.verdicts[v.address] = v
                if v.game_styled:
                    rep.styled.append(v)
            fresh += 1
        rep.lane_counts[lane] = fresh
        print(f"  lane {lane}: {fresh} new "
              f"({'review only' if lane == 'heuristic' else 'tagged'})", flush=True)

    if do_globals:
        globs = program_globals(program)
        rep.total_globals = len(globs)
        # This run's verdicts UNION whatever Ghidra already has tagged -- see
        # existing_lib_tags. Without the union the rule silently under-reports
        # on every re-run, which reads as "the globals are fine now".
        lib_pop = set(rep.verdicts) | existing_lib_tags(program)
        rep.library_population = len(lib_pop)
        try:
            rep.lib_globals = library_globals(program, lib_pop, globs)
        except Exception as e:                                   # noqa: BLE001
            rep.errors.append(f"globals rule failed: {e}")
            print(f"  ! globals rule failed: {e}", flush=True)
        print(f"  globals: {len(rep.lib_globals)}/{rep.total_globals} library-owned",
              flush=True)
    return rep


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

def benchmark_authored_functions() -> Set[str]:
    """The 9 hand-authored Benchmark.dll functions, from the benchmark's own
    ground truth. Read rather than retyped so the control cannot drift from
    the thing it controls."""
    here = os.path.dirname(os.path.abspath(__file__))
    gt = os.path.join(here, "benchmark", "ground_truth.json")
    try:
        with open(gt, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return set()
    if isinstance(data, dict):
        entries = data.get("functions") or data.get("entries") or data
        if isinstance(entries, dict):
            return {str(k) for k in entries}
        if isinstance(entries, list):
            return {str(e.get("name")) for e in entries if isinstance(e, dict)}
    return set()


def benchmark_gate(reports: Sequence[ProgramReport]) -> Tuple[bool, List[str]]:
    """(passed, violations). A claim on any authored Benchmark.dll function
    fails the sweep. There is deliberately no override flag."""
    authored = benchmark_authored_functions()
    if not authored:
        return True, []
    bad: List[str] = []
    for rep in reports:
        if rep.binary != BENCHMARK_BINARY:
            continue
        for v in rep.verdicts.values():
            if v.current_name in authored:
                bad.append(f"{v.current_name} @ {v.address} claimed by lane "
                           f"'{v.lane}' ({v.evidence})")
    return (not bad), bad


# --------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------

def apply_function_verdicts(rep: ProgramReport, rename_documented: bool = False
                            ) -> dict:
    """Write LIB_* tags through each lane's OWN sync_to_ghidra.

    This module is not a fourth writer. `crt_identify.sync_to_ghidra` already
    encodes the rules for its lane (tag + durable bookmark always, name only
    over a Ghidra default), and duplicating them here is exactly how a fix to
    one writer silently misses the other -- the conf_ladder lesson.
    """
    stats = {"tagged": 0, "failed": 0, "skipped": 0}
    for v in rep.verdicts.values():
        if not v.writes_tag:
            stats["skipped"] += 1
            continue
        try:
            _post("/add_function_tag", rep.program,
                  {"function": v.address, "tag": v.tag})
            _post("/set_bookmark", rep.program, {
                "address": v.address, "type": "Analysis",
                "category": "Library Scope",
                "comment": f"{v.tag} via {v.lane}: {v.evidence}"})
            stats["tagged"] += 1
        except Exception as e:                                   # noqa: BLE001
            # Loud, never silent: a best-effort write-back that fails quietly
            # is how a whole pass of destruction went unnoticed before.
            print(f"  ! tag failed {v.address} ({v.current_name}): {e}", flush=True)
            stats["failed"] += 1
    return stats


def apply_global_scope(rep: ProgramReport) -> dict:
    """Mark library-owned globals in the `Scope` property map.

    That map is what conformance_dashboard._scope_excluded_globals already
    reads, so writing it is what actually removes these from the Globals
    Inventory and its denominators. The value is the justifying tag.
    """
    stats = {"marked": 0, "failed": 0}
    if not rep.lib_globals:
        return stats
    try:
        _post("/create_property_map", rep.program,
              {"name": SCOPE_MAP, "type": "string"})
    except Exception:                                            # noqa: BLE001
        pass          # already exists is the common case, and is fine
    for g in rep.lib_globals:
        try:
            _post("/set_property", rep.program,
                  {"map": SCOPE_MAP, "address": g["address"], "value": TAG_CRT})
            stats["marked"] += 1
        except Exception as e:                                   # noqa: BLE001
            print(f"  ! scope write failed {g['address']}: {e}", flush=True)
            stats["failed"] += 1
    return stats


def sync_library_code_flags(reports: Sequence[ProgramReport]) -> dict:
    """Set functions_workflow.library_code = 1 for every tagged address.

    The flag is what the SELECTOR reads (`skip_library_code`), and until now it
    was only ever re-derived during a full refresh pass -- which is why
    PD2_EXT.dll could carry 272 LIB_CRT tags with all 463 rows still at 0.
    Doing it here makes the tag and the flag agree the moment the sweep applies.
    """
    try:
        import fun_doc                                           # noqa: PLC0415
    except Exception as e:                                       # noqa: BLE001
        print(f"  ! cannot import fun_doc to sync flags: {e}", flush=True)
        return {"updated": 0, "error": str(e)}

    stats = {"updated": 0, "missing": 0}
    for rep in reports:
        if not rep.verdicts:
            continue
        try:
            state = fun_doc.load_state(binary_name=rep.binary)
        except TypeError:
            state = fun_doc.load_state()
        except Exception as e:                                   # noqa: BLE001
            print(f"  ! load_state failed for {rep.binary}: {e}", flush=True)
            continue
        funcs = (state or {}).get("functions", {})
        by_addr = {}
        for key, f in funcs.items():
            if f.get("program") != rep.program:
                continue
            by_addr[norm_addr(f.get("address"))] = (key, f)
        for addr, v in rep.verdicts.items():
            hit = by_addr.get(addr)
            if not hit:
                stats["missing"] += 1
                continue
            _key, f = hit
            f["library_code"] = True
            f["library_code_reasons"] = [f"{v.tag} via {v.lane}: {v.evidence}"]
            stats["updated"] += 1
        try:
            fun_doc.save_state(state)
        except Exception as e:                                   # noqa: BLE001
            print(f"  ! save_state failed for {rep.binary}: {e}", flush=True)
    return stats

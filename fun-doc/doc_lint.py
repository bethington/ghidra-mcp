"""Find documentation that is well-formed but WRONG.

WHY THIS EXISTS
---------------
`analyze_function_completeness` asks "is documentation present and well-formed?"
-- name, plate sections, typed params. Nothing asks "is it true?" So a function
can score well while its name says something false about what it does.

The failure this module was built for is the expensive kind, because it
replicates itself. Cross-version hash propagation spreads a name from one
binary to every binary with a matching function hash. If the source name was
wrong, the error propagates -- and CRT/STL code is where it does the most
damage, because statically-linked runtime code is byte-identical everywhere, so
one bad name reaches every binary in the corpus at once.

Measured case that prompted this: PD2_EXT.dll is an 86KB `version.dll` proxy
shim, ~95% MSVC CRT by function count. 25 of its functions carry Diablo II
gameplay prefixes -- `DATATBLS_SortElements` (which is qsort),
`COLLISION_ProcessTileData` (float validation), `MONSTER_SetupStateContext`
(FPU state), `UNIT_ValidateDifficulty` (a locale helper). None of them touch a
monster, a unit, or a data table.

THE RULE
--------
Flag a function when BOTH hold:

  1. It is library code -- carries a `LIB_*` tag, or trips
     `library_code_detector` on its CALLEES. Callees matter: a CRT function
     renamed `DATATBLS_SortElements` no longer matches any CRT name pattern,
     but it still calls `__SEH_prolog4`. Renaming destroys the name signal and
     leaves the structural one intact, which is exactly the case we need.

  2. Its `UPPERCASE_` module prefix is a DOMAIN prefix -- one that the corpus
     predominantly uses on non-library code.

Point 2 is calibrated from the corpus, PLUS a fixed exemption list. Pure
calibration was the original design and it failed on first contact with the
data: the library detector is deliberately conservative, so it recognised only
10 of 79 `CRT_` functions corpus-wide, which made `CRT_` read as 87%
"non-library" -- a game domain -- and flagged `CRT_Init` as a defect. Low
recall in the input skews a calibration; it does not skew a fixed list. So
runtime-concern prefixes are exempted outright (RUNTIME_PREFIXES) and
calibration decides the rest.

The calibration table is printed with the report. A self-calibrating rule whose
calibration you cannot inspect is worse than a hand-written list, not better --
that is how the `CRT_` error would have shipped silently.

FINDINGS ARE TIERED, because the two library signals are not equally good:

  Tier 1 -- the function carries a curated `LIB_*` tag. Ghidra already says it
           is runtime code; the name contradicts stored ground truth.
  Tier 2 -- the heuristic detector classified it. Real defects live here too,
           but it is a judgement call and wants human review.

USAGE
-----
    python doc_lint.py --folder /Mods/PD2-S12
    python doc_lint.py --program /Mods/PD2-S12/PD2_EXT.dll
    python doc_lint.py --folder /Mods/PD2-S12 --json report.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from library_code_detector import detect_library_code  # noqa: E402

GHIDRA = __import__("os").environ.get(
    "GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")

# Matches NamingConventions.MODULE_PREFIX (`^[A-Z]+_[A-Z].*`), widened to allow
# digits so D2-era prefixes like `D2CLIENT_` are recognised rather than skipped.
MODULE_PREFIX = re.compile(r"^([A-Z][A-Z0-9]*)_[A-Z]")

# A prefix must be used this many times corpus-wide before its library/non-
# library split is treated as meaningful. Without a floor, a prefix appearing
# 3 times (all on CRT) reads as 0% domain and silently exempts itself.
MIN_PREFIX_SUPPORT = 20
# Share of a prefix's uses that must be on NON-library code for it to count as
# a domain prefix.
DOMAIN_SHARE = 0.70

# Prefixes naming a RUNTIME concern rather than a game subsystem. These are
# correct on CRT code, so they can never be a defect no matter what the
# calibration says.
#
# They need an explicit exemption because pure calibration gets them wrong: the
# library detector is deliberately conservative (its docstring: false negatives
# are cheaper than false positives), so it recognised only 10 of 79 `CRT_`
# functions corpus-wide. That 87% "non-library" reading made `CRT_` look like a
# game domain and flagged `CRT_Init` and `CRT_RotateSecurityCookie` as defects,
# which is exactly backwards. Low recall in the input skews the calibration; it
# does not skew a fixed list.
RUNTIME_PREFIXES = frozenset({
    "CRT", "ACRT", "VCRT", "MSVCRT", "MSVCP", "UCRT", "STD", "SCRT",
    "EH", "SEH", "EXCEPTION", "SECURITY", "SIGNAL",
    "STRING", "FILE", "STREAM", "IO", "LOCALE", "UTF8", "CMP",
    "MATH", "FPU", "MEM", "MEMMGR", "HEAP", "ALLOC", "THREAD", "TLS", "FLS",
})

# Callees that prove C++ exception handling but NOT library code. Ordinary
# user code that does `throw` calls `_CxxThrowException`, and any function with
# a try/catch gets a frame handler -- so accepting these as library evidence
# misfiled hand-written PD2 code (`PD2_AllocItemExtraData`,
# `GAME_GetInitStateOrThrow`) as CRT. The detector may keep them; this rule
# must not, because here they produce a false ACCUSATION rather than a missed
# skip.
EH_ONLY_CALLEES = frozenset({
    "_CxxThrowException", "__CxxThrowException@8",
    "__std_exception_copy", "__std_exception_destroy",
    "__CxxFrameHandler", "__CxxFrameHandler3",
})


def _get(path: str, **params):
    url = f"{GHIDRA}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=300) as r:
                raw = r.read().decode("utf-8", "replace")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < 2:
                time.sleep(0.3 * (attempt + 1))
    raise last


def _items(resp, key: str) -> list:
    """Items out of a 6.0.0 list envelope. Mirrors conformance_dashboard."""
    if isinstance(resp, dict):
        v = resp.get(key)
        if isinstance(v, list):
            return v
    if isinstance(resp, str):
        return [ln for ln in resp.splitlines() if ln.strip()]
    return []


def strip_ref(ref: str) -> str:
    """`KERNEL32.DLL::VirtualProtect@EXTERNAL:0000000d` -> `VirtualProtect`."""
    if not ref:
        return ""
    name = ref.rsplit("@", 1)[0] if "@" in ref else ref
    if "::" in name:
        name = name.rsplit("::", 1)[-1]
    return name


def module_prefix(name: str) -> Optional[str]:
    m = MODULE_PREFIX.match(name or "")
    return m.group(1) if m else None


@dataclass
class FunctionRec:
    program: str
    name: str
    address: str
    callees: List[str] = field(default_factory=list)
    is_library: bool = False
    library_reason: str = ""
    prefix: Optional[str] = None
    # 1 = curated LIB_* tag (ground truth), 2 = heuristic detector (review).
    tier: int = 0


def classify(functions: List[dict], edges: List[dict],
             lib_tagged: Iterable[str] = ()) -> List[FunctionRec]:
    """Build FunctionRecs with library classification and module prefix."""
    callees: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        caller = strip_ref(e.get("caller", ""))
        callee = strip_ref(e.get("callee", ""))
        if caller and callee:
            callees[caller].append(callee)

    tagged = set(lib_tagged)
    out: List[FunctionRec] = []
    for f in functions:
        name = f.get("name") or ""
        rec = FunctionRec(program=f.get("program", ""), name=name,
                          address=str(f.get("address", "")),
                          callees=callees.get(name, []))
        rec.prefix = module_prefix(name)
        if name in tagged:
            rec.is_library, rec.library_reason, rec.tier = True, "LIB_tag", 1
        else:
            # EH callees are stripped before classification: they prove C++
            # exception handling, not runtime code (see EH_ONLY_CALLEES).
            evidence = [c for c in rec.callees if c not in EH_ONLY_CALLEES]
            res = detect_library_code(name, None, evidence)
            if res.is_library:
                rec.is_library = True
                rec.library_reason = ",".join(res.reasons[:3])
                rec.tier = 2
        out.append(rec)
    return out


def calibrate(recs: Iterable[FunctionRec]) -> Dict[str, dict]:
    """Per-prefix library/non-library split across the whole corpus."""
    stats: Dict[str, dict] = defaultdict(
        lambda: {"library": 0, "nonlibrary": 0, "total": 0})
    for r in recs:
        if not r.prefix:
            continue
        s = stats[r.prefix]
        s["total"] += 1
        s["library" if r.is_library else "nonlibrary"] += 1
    for p, s in stats.items():
        s["domain_share"] = (s["nonlibrary"] / s["total"]) if s["total"] else 0.0
        s["runtime_prefix"] = p in RUNTIME_PREFIXES
        s["is_domain"] = (not s["runtime_prefix"]
                          and s["total"] >= MIN_PREFIX_SUPPORT
                          and s["domain_share"] >= DOMAIN_SHARE)
    return dict(stats)


def find_defects(recs: Iterable[FunctionRec],
                 stats: Dict[str, dict]) -> List[FunctionRec]:
    """Library-classified functions wearing a domain prefix."""
    out = []
    for r in recs:
        if r.is_library and r.prefix:
            s = stats.get(r.prefix)
            if s and s["is_domain"]:
                out.append(r)
    return out


# ----------------------------------------------------------------- I/O ------

def list_programs(folder: str) -> List[str]:
    resp = _get("/list_project_files", folder=folder)
    files = resp.get("files", []) if isinstance(resp, dict) else []
    return [f["path"] for f in files
            if f.get("content_type") == "Program" and not f["name"].endswith(".0")]


def lib_tagged_names(program: str) -> List[str]:
    """Names carrying any LIB_* tag, if the program uses them."""
    resp = _get("/list_function_tags", program=program)
    names: List[str] = []
    for t in _items(resp, "tags"):
        tag = t.get("name", "") if isinstance(t, dict) else str(t)
        if not tag.startswith("LIB_"):
            continue
        hits = _get("/search_functions_by_tag", program=program, tag=tag, limit=100000)
        for h in _items(hits, "functions"):
            n = h.get("name") if isinstance(h, dict) else None
            if n:
                names.append(n)
    return names


def collect(program: str) -> List[FunctionRec]:
    fns = _items(_get("/list_functions", program=program), "functions")
    for f in fns:
        f["program"] = program
    edges = _items(_get("/get_full_call_graph", program=program, limit=500000), "edges")
    recs = classify(fns, edges, lib_tagged_names(program))
    for r in recs:
        r.program = program
    return recs


def main() -> int:
    global MIN_PREFIX_SUPPORT, DOMAIN_SHARE

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--folder", help="sweep every Program in this project folder")
    g.add_argument("--program", help="single program path")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--min-support", type=int, default=MIN_PREFIX_SUPPORT)
    ap.add_argument("--domain-share", type=float, default=DOMAIN_SHARE)
    args = ap.parse_args()
    MIN_PREFIX_SUPPORT, DOMAIN_SHARE = args.min_support, args.domain_share

    programs = [args.program] if args.program else list_programs(args.folder)
    print(f"# scanning {len(programs)} program(s)\n", file=sys.stderr)

    recs: List[FunctionRec] = []
    for p in programs:
        try:
            r = collect(p)
        except Exception as e:  # noqa: BLE001
            print(f"  !! {p}: {e}", file=sys.stderr)
            continue
        recs.extend(r)
        print(f"  {p:44} {len(r):6} fn  "
              f"{sum(x.is_library for x in r):6} library", file=sys.stderr)

    stats = calibrate(recs)
    defects = find_defects(recs, stats)

    print("\n=== PREFIX CALIBRATION (domain = predominantly non-library) ===")
    print(f"{'prefix':<14}{'total':>7}{'library':>9}{'non-lib':>9}"
          f"{'domain%':>9}  verdict")
    for p, s in sorted(stats.items(), key=lambda kv: -kv[1]["total"]):
        if s["total"] < 5:
            continue
        print(f"{p:<14}{s['total']:>7}{s['library']:>9}{s['nonlibrary']:>9}"
              f"{s['domain_share']*100:>8.0f}%  "
              + ("DOMAIN" if s["is_domain"]
                 else "runtime-prefix (exempt)" if s["runtime_prefix"]
                 else "library/mixed"))

    print(f"\n=== DEFECTS: {len(defects)} library function(s) wearing a domain prefix ===")
    by_prefix: Dict[str, List[FunctionRec]] = defaultdict(list)
    for d in defects:
        by_prefix[d.prefix].append(d)
    for pfx, group in sorted(by_prefix.items(), key=lambda kv: -len(kv[1])):
        progs = sorted({g.program.rsplit("/", 1)[-1] for g in group})
        print(f"\n  {pfx}_  x{len(group)}  in {len(progs)} binary/binaries: "
              f"{', '.join(progs[:6])}{' …' if len(progs) > 6 else ''}")
        for d in sorted(group, key=lambda x: (x.tier, x.name))[:10]:
            print(f"      [T{d.tier}] {d.program.rsplit('/',1)[-1]:20} "
                  f"{d.address:>10}  {d.name}   [{d.library_reason}]")
        if len(group) > 10:
            print(f"      … and {len(group)-10} more")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "scanned_programs": programs,
                "function_count": len(recs),
                "calibration": stats,
                "defects": [{"program": d.program, "name": d.name,
                             "address": d.address, "prefix": d.prefix,
                             "tier": d.tier,
                             "reason": d.library_reason} for d in defects],
            }, fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

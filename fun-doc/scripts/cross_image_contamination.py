"""Cross-image plate contamination detector.

THE DEFECT: a plate that documents code from a DIFFERENT BINARY. Cross-version
hash propagation copies documentation between byte-identical functions, and the
prose it copies carries ABSOLUTE ADDRESSES with it. Land that text on a program
with a different image base and the plate now describes another image entirely --
wrong globals, wrong callees, wrong behaviour -- while looking perfectly written.

MEASURED ORIGIN (2026-08-09), full census of /Vanilla/1.00/D2Game.dll (base
0x10000000, 3,487 functions, 745 with plates):

    address signature (0x6f...... cited as fact)   38 / 745   5.1%
    callee signature  (names a 1.13c-only callee)   6 / 745   0.8%   DISJOINT
    combined confirmed floor                       44 / 745   5.9%

It is ONE-DIRECTIONAL: the 1.13c side (/Mods/PD2-S12/D2Game.dll, 3,631 plated)
yielded ~0% -- its only 0x100..... citations are import thunks legitimately
naming binkw32.dll, which really does base at 0x10000000.

It CLUSTERS in the statically-linked CRT: 27 of 38 sit at >=0x1009a000 -- 12% of
plated CRT functions vs 2.1% of plated game code -- and cite SEVERAL different
0x6F bases (6ff2/6ff3/6fdd/6fb9/6f9e), i.e. propagated from Storm/Fog-era modules
too, not just 1.13c D2Game. Byte-identical CRT is exactly what a hash propagator
matches, and it drags absolute addresses along.

WHY falsify.check_phantom_address (F8) DOES NOT COVER THIS -- read before
"fixing" one by widening the other. F8 requires a cited address to fall INSIDE
this program's data segments, and it says so deliberately:

    "outside every segment -> a mask (0xffffffff) or another module's address
     (0x6fc36ad4 is D2Game, 0x6ff7e33f is Fog). Not this function's claim to
     get wrong."

That calibration is correct for F8's target (a plate inventing a global that
belongs to this program) and it is precisely what makes F8 blind here: a
propagated plate's addresses are, by construction, OUTSIDE this program. The two
checks are complements, not duplicates. Widening F8 to cover this would
re-introduce the false-positive class its three calibration rounds removed.

DISCRIMINATOR. A foreign address is not by itself a defect -- a plate may
legitimately say "calls Fog.dll's ordinal 10021 at 0x6ff7e33f". The measured
separator is ATTRIBUTION: benign cross-module references NAME the module; a
propagated plate presents foreign addresses as this function's own globals and
names no module at all. So we fire only on unattributed foreign addresses, and
abstain on every way of being unsure.

TIER 2 (review), deliberately, matching phantom_address's precedent. The rule is
mechanical, but "the plate cites a foreign address" is evidence the text came
from elsewhere, not proof of what the function does -- and repair needs a human
because the NAME usually has to move too (see below).

REPAIR IS NOT PLATE-ONLY. The measured half-fix: D2Game v1.00 ordinal 10048 had
its plate repaired in an earlier pass while its name (`TickGameSessionFrames`)
and parameter (`nCapOverflow`) still came from the contaminated text -- the stale
plate even read "despite the name". A corrected plate over a wrong name is a half
fix, because the name is what every caller, listing and search shows. The report
therefore flags name-derivation risk separately.

Usage:
    python -m scripts.cross_image_contamination --programs /Vanilla/1.00/D2Game.dll --json report.json
    python -m scripts.cross_image_contamination --folder /Vanilla/1.00 --json report.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_FUNDOC_DIR = Path(__file__).resolve().parent.parent
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

import falsify  # noqa: E402

CHECK_ID = "cross_image_contamination"

# Same width rule as F8: absolute addresses only. `+0x14`, `0x5c` and string ids
# are offsets and constants; matching them would accuse every plate that
# documents a field layout.
_ABS_ADDR_RE = re.compile(r"\b0x([0-9a-fA-F]{6,8})\b")

# A plate that NAMES a module has attributed its foreign address. Benign.
# Measured false positive this kills: BinkBufferGetError thunks in 1.13c D2Game
# citing 0x100..... while naming binkw32.dll, which genuinely bases there.
_MODULE_RE = re.compile(
    r"\b(?:[A-Za-z0-9_]+\.dll|binkw32|storm|fog|d2common|d2client|d2game|d2net|"
    r"d2lang|d2win|d2gfx|d2sound|d2cmp|d2multi|d2launch|kernel32|user32|advapi32|"
    r"ntdll|msvcrt|wsock32)\b", re.IGNORECASE)

# A plate that cites a foreign address in order to REFUTE it is a REPAIR NOTE,
# not a defect. Measured: 9 of 47 address-citing plates in the census were
# already-repaired ones saying "belongs to a different image base". Counting
# those would re-flag exactly the functions someone already fixed -- and would
# make the rate look worse after a repair pass than before it.
_REFUTATION_RE = re.compile(
    r"different image base|suspect plate|does not match this|belongs to a "
    r"different|propagated from|contaminat|CORRECTION|wrong image|stale plate|"
    r"despite the name", re.IGNORECASE)

# Reuse F8's exempt sections: a function never references its own callers.
_EXEMPT_SECTIONS = falsify._ADDR_EXEMPT_SECTIONS


# --------------------------------------------------------------- pure -------

def strip_exempt_sections(plate: str) -> str:
    """Drop caller-listing sections, which legitimately name foreign addresses."""
    kept, skipping = [], False
    for line in (plate or "").splitlines():
        stripped = line.strip().lower().rstrip(":")
        head = stripped and not line.startswith((" ", "\t"))
        if head and stripped.endswith(tuple(s.split()[-1] for s in _EXEMPT_SECTIONS)):
            skipping = any(stripped.startswith(s.split()[0]) for s in _EXEMPT_SECTIONS)
        elif head and line.rstrip().endswith(":"):
            skipping = False
        if not skipping:
            kept.append(line)
    return "\n".join(kept)


# Well-known non-address constants that happen to be 8 hex digits wide.
_SENTINELS = {
    0xBAADF00D, 0xDEADBEEF, 0xFEEEFEEE, 0xCDCDCDCD, 0xABABABAB, 0xFDFDFDFD,
    0xDDDDDDDD, 0xCCCCCCCC, 0xC0000005, 0x80000000, 0xFFFFFFFE,
    # MSVC/CRT magics, all MEASURED in round 2 below.
    0x19930520,   # MSVC EH magic number
    0xE06D7363,   # MSVC C++ exception code, 'msc' | 0xE0000000
    0x7EFEFEFF, 0x81010100, 0x80808080, 0x01010101,   # strlen/strchr byte scans
    0xCCCCCCCD, 0x51EB851F, 0xAAAAAAAB, 0x66666667,   # reciprocal-multiply divisors
    # ROUND 4: crypto initialisation vectors. MEASURED -- the corpus sweep flagged
    # Fog.dll's ComputeSha1Hash for citing 0x10325476, which is SHA-1's H2, not an
    # address. These slip past corpus containment because several PD2-S12 modules
    # are based at 0x10000000, so the 0x10xxxxxx band IS a real sibling range.
    # Containment narrows the problem; it does not eliminate constants that happen
    # to land inside a sibling image.
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,   # SHA-1 / MD5 IV
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,               # SHA-1 round K
    0xD76AA478, 0xE8C7B756, 0x242070DB,                           # MD5 table head
}

# The lowest plausible Windows image base (an EXE at 0x400000). Anything below is
# a size, a count or a flag word, not an address in this or any other module.
_MIN_PLAUSIBLE_BASE = 0x00400000


def looks_like_mask(v: int) -> bool:
    """True for values that are constants, not addresses.

    MEASURED: the first live run of this detector on /Vanilla/1.00/D2Game.dll
    returned 6 findings and ALL SIX were this class -- `0xffffffff` sentinels in
    SafeDelete / EnqueueTimerEvent / SendItemActionResult, and `0xdddddddd` in
    the TSExplicitList helpers (Blizzard's own list terminator; the RTTI in the
    sibling D2Server binary literally reads TSExplicitList<SGAMEDATA,
    -0x22222223>, which is 0xDDDDDDDD). falsify F8 hit the same class and named
    it in its round-2 calibration; a detector that keys on 'outside every
    segment' inherits it, because a mask is outside every segment by definition.

    Three principled families, no hardcoded address ranges:
      * all four bytes identical      0xdddddddd, 0xcccccccc, 0xffffffff
      * an all-ones low run           0x7fffffff, 0x0000ffff, 0xffffffff
      * an all-ones high run          0xffff0000, 0xff000000, 0x80000000
    plus an explicit list of famous debug fills.

    ROUND 2 (same binary, after round 1 shipped): 50 findings, and inspecting the
    distinct cited values showed FOUR more constant families, all of them
    compiler output rather than anything a documenter chose:
      * small negatives as unsigned   0xfffffffd (-3), 0xfffffff4 (-12), 0xffffffe1
      * MSVC magics                   0x19930520 (EH), 0xe06d7363 ('msc' exception)
      * byte-scan / divide constants  0x7efefeff, 0x81010100, 0xcccccccd, 0x51eb851f
      * ASCII packed into a dword     0x20326671, 0x20786f62, 0x206d6468 -- text,
                                      read as a number only because it is 8 hex
                                      digits wide
    """
    if v in _SENTINELS:
        return True
    if v < _MIN_PLAUSIBLE_BASE:                        # sizes, counts, flags
        return True
    if v >= 0xFFFFFF00:                                # small negative as unsigned
        return True
    b = [(v >> s) & 0xFF for s in (0, 8, 16, 24)]
    if len(set(b)) == 1:
        return True
    if all(0x20 <= x <= 0x7E for x in b):              # four printable chars: text
        return True
    if v and (v & (v + 1)) == 0:                       # 0b0...01...1
        return True
    inv = (~v) & 0xFFFFFFFF
    if inv and (inv & (inv + 1)) == 0:                 # 0b1...10...0
        return True
    return False


def foreign_addresses(plate: str, ranges) -> list:
    """Absolute addresses cited by the plate that fall outside EVERY segment of
    this program. Those are the propagation signature; addresses inside the
    program are F8's problem, not ours."""
    scanned = strip_exempt_sections(plate)
    out = []
    for m in _ABS_ADDR_RE.finditer(scanned):
        try:
            v = int(m.group(1), 16)
        except ValueError:
            continue
        if looks_like_mask(v):
            continue
        if not any(lo <= v <= hi for lo, hi in ranges):
            out.append(m.group(1).lower())
    return sorted(set(out))


def check_program_function(plate: str, ranges, *, is_thunk: bool = False,
                           name: str = "", sibling_ranges=None) -> dict | None:
    """Return a finding dict, or None to abstain.

    Every abstention below kills a class that was OBSERVED in the census, not
    one that was imagined. Do not remove one without re-measuring.
    """
    if not plate or not ranges:
        return None                      # cannot tell -> abstain, never guess
    if is_thunk:
        return None                      # import thunks legitimately point elsewhere
    if _REFUTATION_RE.search(plate):
        return None                      # already-repaired plate, or a repair note
    foreign = foreign_addresses(plate, ranges)
    if not foreign:
        return None
    if _MODULE_RE.search(plate):
        return None                      # attributed cross-module reference

    # ROUND 3 -- the principled discriminator, and the one that ends the
    # constant-family whack-a-mole. Rounds 1 and 2 kept discovering new species
    # of compiler constant (masks, sentinels, small negatives, MSVC magics,
    # packed ASCII, IEEE float words) because "outside every segment of THIS
    # program" is a definition that lets in every number. What we actually mean
    # is narrower and checkable: the address belongs to ANOTHER BINARY IN THIS
    # CORPUS. Supply sibling image ranges and require containment, and float
    # words like 0x40000000 / 0x7fff8000 stop qualifying by construction --
    # they are not inside any module.
    # Measured on /Vanilla/1.00/D2Game.dll: round 2 left 18 findings of which 4
    # were CRT float/mask constants; containment removes exactly those.
    if sibling_ranges:
        foreign = [a for a in foreign
                   if any(lo <= int(a, 16) <= hi for lo, hi in sibling_ranges)]
        if not foreign:
            return None

    bases = sorted({a[:4] for a in foreign})
    return {
        "check": CHECK_ID,
        "tier": 2,
        "name": name,
        "claim": f"plate cites foreign address(es) 0x{', 0x'.join(foreign[:5])}"
                 + (" ..." if len(foreign) > 5 else ""),
        "evidence": "outside every segment of this program, and no module is named "
                    "to attribute them",
        "foreign_addresses": foreign,
        "foreign_bases": bases,
        # The measured half-fix: repairing the plate alone leaves the wrong name
        # in place, and the name is what every listing shows.
        "name_derivation_risk": True,
    }


def summarize(findings: list, plated_total: int) -> dict:
    by_base = {}
    for f in findings:
        for b in f.get("foreign_bases", []):
            by_base[b] = by_base.get(b, 0) + 1
    # NOT "findings" -- the report dict already holds the finding LIST under that
    # key, and out.update(summarize(...)) would overwrite the list with a count.
    # (Caught by the first live run; two writers of one key, in miniature.)
    return {
        "plated_total": plated_total,
        "findings_count": len(findings),
        "rate": round(len(findings) / plated_total, 4) if plated_total else 0.0,
        "by_foreign_base": dict(sorted(by_base.items(), key=lambda kv: -kv[1])),
    }


# ---------------------------------------------------------------- live ------

def program_ranges(program: str) -> list:
    """All segments of the program, as (lo, hi) ints. ALL segments, not just
    data: a propagated plate cites code addresses too, and unlike F8 we are not
    trying to distinguish code from data -- we are asking 'is this even this
    binary?'."""
    resp = falsify._get("/list_segments", program=program) or {}
    items = resp.get("segments") or resp.get("items") or []
    ranges = []
    for s in items:
        try:
            ranges.append((int(str(s["start"]), 16), int(str(s["end"]), 16)))
        except (KeyError, ValueError, TypeError):
            continue
    return ranges


def corpus_ranges(folders: list) -> list:
    """Image ranges of every program in the given folders -- the set of binaries
    an address could legitimately have been propagated FROM."""
    out = []
    for folder in folders or []:
        resp = falsify._get("/list_project_files", folder=folder) or {}
        for f in (resp.get("files") or []):
            if str(f.get("content_type")) != "Program":
                continue
            out.extend(program_ranges(f["path"]))
    return out


def scan_program(program: str, limit: int | None = None,
                 sibling_ranges=None) -> dict:
    ranges = program_ranges(program)
    if not ranges:
        return {"program": program, "error": "no segments; cannot tell", "findings": []}
    resp = falsify._get("/list_functions_enhanced", program=program, limit=100000) or {}
    funcs = resp.get("functions") or []
    findings, plated = [], 0
    for fn in funcs[: limit or len(funcs)]:
        addr = str(fn.get("address") or "")
        if not addr:
            continue
        c = falsify._get("/get_comment", program=program, address=addr,
                         comment_type="plate") or {}
        plate = c.get("plate") or c.get("comment") or ""
        if not plate:
            continue
        plated += 1
        hit = check_program_function(plate, ranges, is_thunk=bool(fn.get("isThunk")),
                                     name=fn.get("name") or "",
                                     sibling_ranges=sibling_ranges)
        if hit:
            hit["address"] = addr
            findings.append(hit)
    out = {"program": program, "findings": findings}
    out.update(summarize(findings, plated))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--programs", nargs="*", default=[])
    ap.add_argument("--folder", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--corpus-folders", nargs="*", default=[],
                    help="Folders whose programs' image ranges count as 'another "
                         "binary'. STRONGLY RECOMMENDED: without it every number "
                         "outside this program qualifies, and CRT float words and "
                         "masks come back as findings.")
    args = ap.parse_args(argv)

    siblings = corpus_ranges(args.corpus_folders)
    if args.corpus_folders and not siblings:
        print("--corpus-folders resolved to no ranges; refusing to run unconstrained",
              file=sys.stderr)
        return 2

    programs = list(args.programs)
    if args.folder:
        resp = falsify._get("/list_project_files", folder=args.folder) or {}
        programs += [f["path"] for f in (resp.get("files") or [])
                     if str(f.get("content_type")) == "Program"]
    if not programs:
        print("nothing to scan: pass --programs or --folder", file=sys.stderr)
        return 2

    reports = [scan_program(p, args.limit, siblings) for p in programs]
    total = sum(r.get("findings_count", len(r.get("findings", []))) for r in reports)
    for r in reports:
        if r.get("error"):
            print(f"{r['program']}: SKIPPED ({r['error']})")
            continue
        print(f"{r['program']}: {len(r['findings'])} finding(s) "
              f"of {r['plated_total']} plated ({r['rate']:.1%})"
              + (f"  bases={list(r['by_foreign_base'])[:5]}" if r["by_foreign_base"] else ""))
    if args.json:
        Path(args.json).write_text(json.dumps(reports, indent=2), encoding="utf-8")
        print(f"report -> {args.json}")
    # REPORT ONLY. Repair needs a human: the NAME usually has to move too, and a
    # tier-2 finding is not a verdict.
    print(f"\n{total} finding(s). Report only -- no writes. "
          f"Repair must move the function/parameter NAMES, not just the plate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

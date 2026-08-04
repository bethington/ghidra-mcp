#!/usr/bin/env python3
"""Audit every reimpl's hardcoded constants against the original's disassembly.

Third in the family after audit_ret_widths.py and audit_stdcall_argc.py, and
the one with the widest blast radius. Those two check the CALLING CONTRACT
(how many bytes come off the stack, how many bits of the return are real).
This one checks the BODY: the struct offsets, strides and magic numbers the
reimpl bakes in.

Why it exists. On 2026-07-30, three reimpls were examined because they diverged
in live shadow, and all three were wrong in the same way -- they carried struct
offsets from a DIFFERENT D2Common version:

  DATATBLS_GetMonStatsTxtRecord   count +0xBC8 (real +0xA80), base +0xBC4
                                  (real +0xA78), stride 0xC4 (real 0x1A8)
  ITEMS_CheckItemRecordField      count +0x24  (real +0xBFC), base +0x20
                                  (real +0xBF8)
  INV_IsItemTypeInInventory       walked memory by pointer arithmetic where the
                                  original dereferences a linked list

Three for three on the ones that got exercised. The uncomfortable part is that
all three were already CONF_LIVE -- they passed the oracle's direct-call proof
and still failed under live gameplay, because the oracle's inputs happened to
land where both implementations returned 0/NULL. So the oracle's bar is weaker
than live shadow, and there are very likely more latent wrong-offset reimpls
sitting at CONF_LIVE that simply have not been called yet. At the observed rate
we find roughly one per play session; this finds them all at once, offline.

The heuristic. Any constant a reimpl uses to walk a struct should appear
somewhere in the original's instruction stream -- as a displacement
(`[ECX + 0xa80]`), a stride (`IMUL EAX,EAX,0x1a8`), or a compared immediate
(`CMP dword ptr [EAX],0x1020304`). A constant present in the reimpl but absent
from the whole original is the signature of a version-mismatched offset.

VERDICT AFTER THE FIRST FULL RUN (2026-07-30): THIS HEURISTIC DOES NOT PAY OFF.
Use live shadow instead. Read this before spending time here again.

Across 173 dispatched reimpls it reported 154 clean and 19 suspect. FIVE of the
top-ranked suspects were hand-checked against the disassembly and ALL FIVE were
false positives. A constant can be absent from the original for at least five
innocent reasons, and the audit sees none of them:

  1. ARITHMETIC DECOMPOSITION -- the original reaches a field in two steps.
     `ADD EAX,0x5c` + `[EAX+0xd]` == the reimpl's `[0x69]`.
     (ITEMS_GetItemDataByte69.)  Handled now by explained_by_arithmetic().
  2. BOUND ENCODING -- `<` vs `<=` flips the literal by one.
     original `CMP EDX,0x96 / JL`  ==  reimpl `if (0x95 < scanned) break`.
     original `[0x230,0x231]` inclusive == reimpl `(0x22f,0x232)` exclusive.
     (GetDataTableRowEntryCount, MONSTER_GetBossCategory.)
  3. STRENGTH-REDUCED MULTIPLY -- no literal stride exists at all.
     `LEA EAX,[EAX+EAX*8]` + `SHL EAX,5` == *9*32 == the reimpl's `* 0x120`.
     (SKILLS_GetReqSkillTxtRecord.)
  4. DELEGATED WORK -- the original CALLs a helper and the constants live in
     the CALLEE, which this never disassembles. (ITEMS_IsItemRecordByte11CSet's
     original body is little more than a CALL.)
  5. INCOMPLETE LISTING -- Ghidra's disassembly can omit a load the code plainly
     needs; DATATBLS_GetItemStorePage's `ADD EAX,EDX` uses an EDX that never
     appears to be set, and the sibling ITEMS_GetCollisionGfxTier proves the
     flagged 0xbf8 is correct.

The three REAL defects it was built to find were all caught by LIVE SHADOW
first, not by static comparison. Shadow has a perfect record here and this has
none. The one thing below that is still worth having is the negative result:
154/173 reimpls use only constants the original also uses.

Kept as an advisory pre-flight, NOT as a gate, and deliberately not wired into
any build. Read-only; never edits a reimpl.

Usage:
    python -m scripts.audit_reimpl_offsets
    python -m scripts.audit_reimpl_offsets --name DATATBLS_GetMonStatsTxtRecord
    python -m scripts.audit_reimpl_offsets --dispatched-only   # manifest entries
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import requests

GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")
D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
CANDIDATES = D2MOO_REPO / "conformance" / "reimpl_provider" / "candidates"
MANIFEST = D2MOO_REPO / "conformance" / "shadow_manifest.json"
REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
BASE = 0x6FD50000
PROGRAM = "D2Common.dll"

_SESSION = requests.Session()

# Constants small enough to be ordinary C (array steps, sizeof, loop bounds,
# boolean returns). Flagging these would bury the real findings in noise.
_TRIVIAL_MAX = 0x10

# Deliberate provider sentinels, not struct offsets. They are SUPPOSED to be
# absent from the original -- DATATBLS_GetMonStatsTxtRecord returns 0xDEADBEEF
# when D2MOO_Resolve() fails, precisely so the mismatch is unmistakable.
_SENTINELS = {0xDEADBEEF, 0xBAADF00D, 0xCCCCCCCC, 0xFFFFFFFF, 0xFEEEFEEE}

_EXPORT_TAG = re.compile(r"D2MOO_REIMPL_EXPORT:\s*(\w+)")
_EXTERN_DECL = re.compile(r'extern\s+"C"\s+[\w\s*]+?__(?:stdcall|fastcall|cdecl)\s+(\w+)\s*\(')
_HEX = re.compile(r"0[xX]([0-9a-fA-F]+)")


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments.

    Non-negotiable for this audit: the fix notes written on 2026-07-30 quote the
    OLD, WRONG offsets verbatim so a reader can see what changed. Scanning raw
    text would re-report every constant we already corrected -- the audit would
    accuse itself of the bugs it just fixed.
    """
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)
    return src


def reimpl_files():
    if not CANDIDATES.is_dir():
        return []
    return sorted(CANDIDATES.glob("*.cpp"))


def _body_from(code: str, start: int) -> str:
    """Source from `start` to the brace-matched end of that function."""
    open_at = code.find("{", start)
    if open_at < 0:
        return ""
    depth = 0
    for i in range(open_at, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start:i + 1]
    return code[start:]


def functions_in(path: Path):
    """[(name, that_function's_body)] for each exported reimpl in the file.

    PER FUNCTION, not per file. Several candidate files hold many reimpls
    (unit_field_getters.cpp has five, batch_shakeout.cpp three), and attributing
    the whole file to each one made every getter inherit the union of its
    siblings' offsets -- all five reported an identical, entirely bogus
    {0x14,0x20,0x28,0x34,0x88,0x91,0x93}. That is a false-positive factory: the
    audit's whole value is that a flag means something.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    code = strip_comments(raw)
    out = []
    for m in _EXTERN_DECL.finditer(code):
        out.append((m.group(1), _body_from(code, m.start())))
    if out:
        return out
    # No parseable definition (macro-generated, say) -- fall back to the whole
    # file, but only when there is exactly ONE exported name, so the union
    # problem above cannot recur.
    names = set(_EXPORT_TAG.findall(raw))
    return [(n, code) for n in sorted(names)] if len(names) == 1 else []


def address_for(name):
    """Original's VA, from the manifest, then the registry, then Ghidra."""
    try:
        for e in json.loads(MANIFEST.read_text(encoding="utf-8"))["entries"]:
            if e["name"] == name:
                raw = e["offset"]
                return BASE + (raw if isinstance(raw, int) else int(str(raw), 0)), "manifest"
    except Exception:
        pass
    try:
        for line in REGISTRY.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("name") == name and r.get("address"):
                return int(str(r["address"]), 16), "registry"
    except Exception:
        pass
    try:
        r = _SESSION.get(f"{GHIDRA_HTTP}/search_functions",
                         params={"query": name, "program": PROGRAM, "limit": 5},
                         timeout=20).json()
        for f in r.get("functions", []):
            if f.get("name") == name:
                return int(str(f["address"]), 16), "ghidra"
    except Exception:
        pass
    return None, None


def original_constants(addr):
    """Every immediate/displacement in the original, or None if unreadable."""
    try:
        ins = _SESSION.get(f"{GHIDRA_HTTP}/disassemble_function",
                           params={"address": f"0x{addr:x}", "program": PROGRAM},
                           timeout=25).json().get("instructions") or []
    except Exception:
        return None
    if not ins:
        return None
    out = set()
    for i in ins:
        for h in _HEX.findall(i.get("instruction", "")):
            out.add(int(h, 16))
    return out


def is_mask(v: int) -> bool:
    """Bit masks and saturation limits, not struct offsets.

    `0xff`, `0xffffff00`, `0x7fffffff` and friends are how a reimpl narrows a
    return or clamps a value. They are legitimately absent from the original
    (which does the same job with `MOVZX`/`AND AL` and no immediate), so
    reporting them buries the offsets that actually matter.
    """
    if v in (0x7FFFFFFF, 0x80000000):
        return True
    for width in (8, 16, 32):
        full = (1 << width) - 1
        if v == full:
            return True
        # contiguous low ones (0xff) or high ones (0xffffff00) within the width
        if v <= full:
            inv = full ^ v
            if v and ((v & (v + 1)) == 0 or (inv and (inv & (inv + 1)) == 0)):
                return True
    return False


def explained_by_arithmetic(v: int, original) -> str | None:
    """Is `v` a SUM of constants the original uses? Returns the explanation.

    The original frequently reaches a field in two steps, so the literal never
    appears:

        ADD   EAX,0x5c                  ; ITEMS_GetItemDataByte69
        MOVSX EAX,byte ptr [EAX + 0xd]  ; 0x5c + 0xd == 0x69

    A reimpl that writes `pItemData[0x69]` is exactly equivalent, but a
    set-difference check calls 0x69 "absent" and flags a correct function. That
    was the first HIGH finding hand-checked on 2026-07-30 and it was wrong --
    which is why this exists before anyone acts on the report.
    """
    if v in original:
        return None
    for a in original:
        if a <= 0 or a >= v:
            continue
        b = v - a
        if b in original and b > 0:
            return f"0x{a:x}+0x{b:x}"
    return None


def triage(missing, original):
    """(rank, note) -- rank 0 = look first.

    THE RANKING IS DELIBERATELY THE OPPOSITE OF THE OBVIOUS ONE.

    My first version ranked a NEAR neighbour highest, reasoning that "right
    field, stale displacement" was the defect shape. Every one of the four HIGH
    findings that produced was hand-checked on 2026-07-30 and every one was a
    FALSE POSITIVE -- because a constant one or two away from the original's is
    almost always the same bound written with the opposite comparison:

        original  CMP EDX,0x96  / JL     (continue while scanned <  150)
        reimpl    if (0x95 < scanned)    (exit when      scanned >= 150)

        original  CMP EAX,0x230 / JC ; CMP EAX,0x231 / JA   -> [0x230,0x231]
        reimpl    (0x22f < id) && (id < 0x232)              -> (0x22f,0x232)

    Those are equivalences, not bugs. Near-miss is ANTI-correlated with defects.

    The genuine defects were FAR misses -- a whole different struct layout:
        0xBC8 vs 0xA80 (delta 0x348),  0x24 vs 0xBFC,  stride 0xC4 vs 0x1A8.

    So: a struct-range constant with NO close neighbour is the real signal, and
    an off-by-one or off-by-two is demoted to noise.
    """
    offsets = [m for m in missing if not is_mask(m)]
    if not offsets:
        return 2, "masks/limits only -- probably benign"

    def nearest(m):
        close = [o for o in original if o != m and abs(o - m) <= 2]
        return min(close, key=lambda o: abs(o - m)) if close else None

    bound_like, far = [], []
    for m in offsets:
        n = nearest(m)
        if n is not None:
            bound_like.append(f"0x{m:x}~0x{n:x}")
        elif 0x10 < m < 0x4000:
            far.append(f"0x{m:x}")
    if far:
        return 0, ("struct-range constant with NO nearby original -- the shape of a "
                   "version-mismatched offset: " + ", ".join(far))
    if bound_like:
        return 2, ("off-by-one/two from an original constant -- almost certainly a "
                   "`<` vs `<=` encoding, not a bug: " + ", ".join(bound_like))
    return 2, "no struct-range constant"


def reimpl_constants(code):
    """Hex constants the reimpl bakes in, excluding trivially small ones."""
    return {int(h, 16) for h in _HEX.findall(code)
            if int(h, 16) > _TRIVIAL_MAX and int(h, 16) not in _SENTINELS}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", help="audit a single reimpl")
    ap.add_argument("--dispatched-only", action="store_true",
                    help="only reimpls that have a shadow dispatcher (can diverge live)")
    args = ap.parse_args()

    dispatched = set()
    try:
        dispatched = {e["name"] for e in
                      json.loads(MANIFEST.read_text(encoding="utf-8"))["entries"]}
    except Exception:
        pass

    suspects, clean, unresolved = [], 0, []
    for path in reimpl_files():
        for name, code in functions_in(path):
            if args.name and name != args.name:
                continue
            if args.dispatched_only and name not in dispatched:
                continue
            rc = reimpl_constants(code)
            if not rc:
                clean += 1
                continue
            addr, src = address_for(name)
            if addr is None:
                unresolved.append((name, "no address"))
                continue
            oc = original_constants(addr)
            if oc is None:
                unresolved.append((name, "no disassembly"))
                continue
            missing = sorted(m for m in (rc - oc)
                             if explained_by_arithmetic(m, oc) is None)
            if missing:
                rank, note = triage(missing, oc)
                suspects.append((rank, note, name, path.name, addr, missing, sorted(oc), src))
            else:
                clean += 1

    print(f"reimpls audited: {clean + len(suspects)}   "
          f"CLEAN: {clean}   SUSPECT: {len(suspects)}   "
          f"UNRESOLVED: {len(unresolved)}\n")

    if suspects:
        print("SUSPECT -- constant used by the reimpl that appears NOWHERE in the original.")
        print("Diff each against the disassembly before changing anything; this is a")
        print("smell detector, not a prover.\n")
        for rank, note, name, fname, addr, missing, oc, src in sorted(suspects, key=lambda x: x[0]):
            tier = ("HIGH", "MEDIUM", "LOW")[rank]
            ms = ", ".join(f"0x{m:x}" for m in missing)
            live = "  [DISPATCHED -- can diverge live]" if name in dispatched else ""
            print(f"  [{tier}] {name}{live}")
            print(f"      why     {note}")
            print(f"      file    {fname}   original 0x{addr:x} (via {src})")
            print(f"      absent  {ms}")
            near = [f"0x{o:x}" for o in oc if o > _TRIVIAL_MAX][:12]
            print(f"      original uses: {', '.join(near) or '(none)'}")
    if unresolved:
        print(f"\nUNRESOLVED ({len(unresolved)}) -- could not check:")
        for n, why in unresolved[:20]:
            print(f"  {n:<44} {why}")
    return 1 if suspects else 0


if __name__ == "__main__":
    raise SystemExit(main())

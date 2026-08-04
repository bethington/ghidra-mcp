#!/usr/bin/env python3
"""Audit manifest ret_bits against the ACTUAL return-register write width.

Why this exists beyond gen_shadow_dispatch's validate_ret_bits: that guard
compares against Ghidra's DECLARED return type, which only catches one
direction of the error --

  * Ghidra says narrow, manifest says wide  -> caught (8 D2Common entries).
  * Ghidra says WIDE, the code writes narrow -> MISSED, because a declared
    `int`/`uint` isn't in the narrow-type table at all. That is exactly
    GetItemQualityStringId: Ghidra declared `int`, every path executed
    `MOV AX, imm` / `XOR AX,AX`, and the upper 16 bits carried stale caller
    garbage. Comparing 32 bits there produces false divergences forever.

So the authority is the disassembly, not the type. For each return path, find
the last write to the return register and classify how wide it actually was:

    MOV AL / XOR AL / SETcc AL          -> 8   (upper 24 bits untouched)
    MOV AX / XOR AX                     -> 16  (upper 16 bits untouched)
    MOV EAX / MOVZX EAX / XOR EAX / ... -> 32  (full register written)

The NARROWEST path wins: if any return path leaves the upper bits dirty, a
32-bit comparison is unsafe on that path.

Read-only. Prints findings; never edits a manifest.

Usage:
    python -m scripts.audit_ret_widths
    python -m scripts.audit_ret_widths --program D2Client.dll
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

MODULES = {
    "D2Common.dll": (0x6FD50000, D2MOO_REPO / "conformance" / "shadow_manifest.json"),
    "D2Client.dll": (0x6FAB0000, D2MOO_REPO / "conformance" / "shadow_manifest.D2Client.json"),
}

_SESSION = requests.Session()

# Writes that leave the upper bits of EAX UNTOUCHED (stale caller garbage).
_W8 = re.compile(r"^(MOV|XOR|OR|AND|ADD|SUB|SETN?[A-Z]{1,2})\s+AL\b", re.I)
_W16 = re.compile(r"^(MOV|XOR|OR|AND|ADD|SUB)\s+AX\b", re.I)
# Writes that fill the whole register.
_W32 = re.compile(r"^(MOV|MOVZX|MOVSX|XOR|OR|AND|ADD|SUB|SBB|NEG|IMUL|LEA|POP|INC|DEC|SHL|SHR|SAR|NOT|CDQ)\s+EAX\b", re.I)

# ZERO-extending load into EAX: the WRITE is 32 bits wide but the DATUM is the
# source operand's width, and the upper bits are provably zero rather than
# merely untouched. Those are different questions and conflating them is what
# produced 166,565 false divergences on DATATBLS_GetLevelRecordBitfield06 --
# see effective_mask_bits() below.
_MOVZX_SRC = re.compile(r"^MOVZX\s+EAX,\s*(byte|word)\s+ptr\b", re.I)

# A reimpl's declared C return type. `unsigned short f(...)` guarantees AX
# only; the upper half of EAX is unspecified by the ABI, so comparing it is
# comparing register residue, not an answer.
_REIMPL_DECL = re.compile(
    r'extern\s+"C"\s+(?:__declspec\([^)]*\)\s*)?'
    r'(unsigned\s+char|signed\s+char|char|unsigned\s+short|short|uint8_t|int8_t|'
    r'uint16_t|int16_t|bool|BYTE|WORD)\s+__(?:stdcall|fastcall|cdecl)\s+(\w+)\s*\(',
    re.I)

_REIMPL_WIDTH = {
    "unsigned char": 8, "signed char": 8, "char": 8, "uint8_t": 8, "int8_t": 8,
    "bool": 8, "byte": 8,
    "unsigned short": 16, "short": 16, "uint16_t": 16, "int16_t": 16, "word": 16,
}


def reimpl_return_widths():
    """name -> declared return width in bits, for reimpls narrower than a dword.

    The comparison spans TWO implementations, so the mask has to be legal for
    both. Only the original was ever consulted; the reimpl's own signature is
    the other half of the contract and is just as authoritative.
    """
    out = {}
    cdir = D2MOO_REPO / "conformance" / "reimpl_provider" / "candidates"
    if not cdir.is_dir():
        return out
    for f in cdir.glob("*.cpp"):
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _REIMPL_DECL.finditer(txt):
            out[m.group(2)] = _REIMPL_WIDTH[m.group(1).lower().replace("  ", " ")]
    return out


def _disasm(addr, program):
    try:
        return _SESSION.get(f"{GHIDRA_HTTP}/disassemble_function",
                            params={"address": f"0x{addr:x}", "program": program},
                            timeout=30).json().get("instructions", []) or []
    except Exception:
        return []


def observed_ret_width(ins):
    """Narrowest return-register DATUM width across all return paths, or None.

    Datum width, not write width. For a zero-extending load the two differ, and
    the datum is what a comparison must use:

        MOVZX EAX, word ptr [EAX+6]

    writes all 32 bits, but 16 of them are zeros the instruction manufactured.
    Masking to 16 therefore discards nothing the original actually computed,
    while tolerating the reimpl's ABI-permitted upper-half residue. Treating
    this as a 32-bit datum is what widened
    DATATBLS_GetLevelRecordBitfield06 16->32 on 2026-07-29 and produced 166,565
    false divergences within a day -- every one of them agreeing perfectly in
    the low 16 bits.

    MOVSX is deliberately NOT narrowed: sign extension makes the upper bits
    carry information, so they are part of the answer.
    """
    widths = []
    for idx, cur in enumerate(ins):
        if not re.match(r"^RET\b", cur.get("instruction", ""), re.I):
            continue
        # Walk backwards to the last write to the return register.
        for j in range(idx - 1, -1, -1):
            t = ins[j].get("instruction", "")
            if re.match(r"^(RET|JMP)\b", t, re.I):
                break                      # previous path; this RET writes nothing itself
            mz = _MOVZX_SRC.match(t)
            if mz:
                widths.append(8 if mz.group(1).lower() == "byte" else 16); break
            if _W32.match(t):
                widths.append(32); break
            if _W16.match(t):
                widths.append(16); break
            if _W8.match(t):
                widths.append(8); break
    return min(widths) if widths else None


def effective_mask_bits(observed, reimpl_bits):
    """The width both sides can be held to.

    The original may guarantee 32 zero-extended bits while the reimpl, declared
    `unsigned short`, guarantees only 16. Comparing at 32 then judges register
    residue the ABI never promised. Take the narrower: it is the widest window
    in which a mismatch is unambiguously a real disagreement.
    """
    return observed if reimpl_bits is None else min(observed, reimpl_bits)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--program", default="D2Common.dll", choices=list(MODULES))
    args = ap.parse_args()

    base, mpath = MODULES[args.program]
    entries = json.loads(mpath.read_text(encoding="utf-8"))["entries"]
    print(f"{args.program}: auditing {len(entries)} manifest entries "
          f"against actual write width\n")

    reimpl_bits = reimpl_return_widths()
    print(f"({len(reimpl_bits)} reimpls declare a sub-dword return type)\n")

    bad, unknown, ok = [], [], 0
    for e in entries:
        # Class B is void with an out-param buffer -- the comparison is the
        # written BYTES, not a return register, so ret_bits does not apply and
        # grading it produces noise (SetCoordPair/InitRngSeed/InitTimerState).
        if str(e.get("class", "A")).upper() == "B":
            continue
        raw = e["offset"]
        off = raw if isinstance(raw, int) else int(str(raw), 0)
        declared = int(e.get("ret_bits", 32))
        ins = _disasm(base + off, args.program)
        if not ins:
            unknown.append((e["name"], "no disassembly"))
            continue
        obs = observed_ret_width(ins)
        if obs is None:
            unknown.append((e["name"], "no return-register write found"))
            continue
        eff = effective_mask_bits(obs, reimpl_bits.get(e["name"]))
        if eff != declared:
            bad.append((e["name"], f"0x{off:x}", declared, obs,
                        reimpl_bits.get(e["name"]), eff))
        else:
            ok += 1

    print(f"MATCH: {ok}    MISMATCH: {len(bad)}    UNDETERMINED: {len(unknown)}\n")
    if bad:
        print("MISMATCHES (manifest vs the width BOTH sides guarantee):")
        for n, off, dec, obs, rb, eff in bad:
            worse = "FALSE DIVERGENCES" if eff < dec else "may hide a real divergence"
            src = f"orig datum={obs}"
            if rb is not None:
                src += f", reimpl declares {rb}"
            print(f"  {n:<44} {off:<9} declared={dec:<3} effective={eff:<3} "
                  f"({src})  -> {worse}")
    if unknown:
        print(f"\nUNDETERMINED ({len(unknown)}) -- inspect by hand, do not guess:")
        for n, why in unknown[:20]:
            print(f"  {n:<44} {why}")


if __name__ == "__main__":
    main()

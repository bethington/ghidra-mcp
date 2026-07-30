#!/usr/bin/env python3
"""Emit shadow-manifest entries for CONF_LIVE functions that have no dispatcher.

The gap this closes (measured 2026-07-29): 171 functions are CONF_LIVE --
bit-exact proven against the running game via the live oracle -- but only 37
are CONF_BATTLETESTED. 132 of the rest have NO shadow dispatcher, and 95 of
those already have a working reimpl compiled into the provider. They did all
the hard work and are stranded by a missing manifest entry: without a
dispatcher they can never accrue shadow evidence, so they can never promote,
no matter how long the game runs.

Sources, in order of authority (revised 2026-07-30 after the crash below):
  * arg count / callconv  -> the reimpl's own C declaration, CROSS-CHECKED
    against the callee's `RET n`. Two independent sources: agreement is
    evidence, disagreement is a refusal, and neither alone is enough. Ghidra's
    inferred signature is no longer consulted for arity at all.
  * ret width             -> min(original DATUM width, reimpl's declared return
    type). The comparison spans two implementations, so the mask must be legal
    for both.
  * class (A/B/D)         -> disassembly (Class D = register-explicit EAX
    input, single arg only), with the reimpl's stated convention settling cases
    the 6-instruction prologue scan cannot.
  * offset                -> Ghidra address minus module image base.

Why arity moved off Ghidra: on 2026-07-30 two harvested entries took their
arity from Ghidra's signature and crashed the game.
INV_CanItemFitInStoragePage declared 3 args against a real `RET 8`;
ITEMS_TestItemFlags declared 2 against a real `RET 0x10`. stdcall is
callee-cleans, so each thunk popped the wrong count, skewed ESP, and returned
into garbage (`eip=0x00000140`, an address in no loaded module). Both reimpls
had the right arity the whole time -- cross-checking would have caught it.

CONSERVATIVE BY DESIGN: anything that cannot be classified confidently is
SKIPPED with a reason rather than guessed. A wrong ret_bits or class produces
thousands of false divergences that look exactly like a broken reimpl and can
wrongly refute a correct one (that happened to ITEMS_GetItemDataInvPage on
2,620 phantom mismatches). A skipped entry costs nothing; a wrong one costs a
debugging session.

Usage:
    python -m scripts.harvest_stranded_dispatchers --limit 20            # dry run
    python -m scripts.harvest_stranded_dispatchers --limit 20 --apply    # write manifest
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests

GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")
D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
PROVIDER_DEF = (D2MOO_REPO / "out" / "build" / "pd2-focus" / "source" / "D2Debugger"
                / "D2MOO_ReimplProvider.gen.def")

MODULES = {
    "D2Common.dll": {"base": 0x6FD50000,
                     "manifest": D2MOO_REPO / "conformance" / "shadow_manifest.json"},
    "D2Client.dll": {"base": 0x6FAB0000,
                     "manifest": D2MOO_REPO / "conformance" / "shadow_manifest.D2Client.json"},
}

# registry `ret` -> ret_bits. Authoritative: it is what the oracle compared.
RET_BITS = {"u8": 8, "i8": 8, "u16": 16, "i16": 16, "u32": 32, "i32": 32}

_SESSION = requests.Session()


def _get(ep, **params):
    try:
        return _SESSION.get(f"{GHIDRA_HTTP}/{ep}", params=params, timeout=30).json()
    except Exception:
        return {}


def load_registry_best():
    """name -> newest row. The registry is append-only, so later rows win."""
    best = {}
    if not REGISTRY.exists():
        return best
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("name"):
            best[r["name"]] = r
    return best


def provider_exports():
    if not PROVIDER_DEF.exists():
        return set()
    return {l.strip() for l in PROVIDER_DEF.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().upper().startswith(("LIBRARY", "EXPORTS"))}


def manifest_names(path):
    try:
        return {e["name"] for e in json.loads(path.read_text(encoding="utf-8"))["entries"]}
    except Exception:
        return set()


def manifest_offsets(path):
    """Offsets already hooked. Deduping by NAME alone is not enough: D2MOO
    carries alias pairs (two names, one address), so a name-only filter keeps
    re-proposing an address that is already hooked. Detours installs one hook
    per address -- the duplicate would get a null trampoline and 0 hits
    forever. DATATBLS_GetItemTypeAutoStack (0x23590, alias of
    DATATBLS_GetItemTypesTxtByte13Field) was rejected in batch 1 and offered
    again in batch 2 for exactly this reason."""
    out = set()
    try:
        for e in json.loads(path.read_text(encoding="utf-8"))["entries"]:
            raw = e["offset"]
            out.add(raw if isinstance(raw, int) else int(str(raw), 0))
    except Exception:
        pass
    return out


def tagged(program, tag):
    r = _get("search_functions_by_tag", tag=tag, program=program, limit=2000)
    return {f["name"]: f["address"] for f in r.get("functions", [])}


def classify(address_hex, program, argc):
    """(class, reason). Class D = register-explicit: the arg arrives in EAX and
    the body uses it with no preceding stack load."""
    d = _get("disassemble_function", address=address_hex, program=program)
    ins = d.get("instructions") or []
    if not ins:
        return None, "no disassembly"
    head = [i.get("instruction", "") for i in ins[:6]]
    # A stack load into a register in the prologue => normal stack args.
    loads_stack = any(re.search(r"MOV\s+E?[A-D]X,\s*(dword ptr\s*)?\[E(SP|BP)", h, re.I)
                      for h in head)
    touches_eax_first = bool(re.match(r"(DEC|INC|CMP|TEST|MOV|AND|OR|XOR|SUB|ADD)\s+EAX\b",
                                      head[0], re.I))
    if argc >= 1 and touches_eax_first and not loads_stack:
        return "D", "EAX-input, no stack load"
    if not loads_stack and argc >= 1 and not touches_eax_first:
        # Can't tell: may be fastcall (ECX/EDX) which IS class A here, or an
        # unusual register ABI. Don't guess.
        return None, "no stack load and no EAX use -- ABI unclear"
    return "A", "stack args"


_RET_N = re.compile(r"^RET\s*(0x[0-9a-f]+|\d+)?\s*$", re.I)


def expected_cleanup(callconv, argc):
    """Bytes the callee should pop for this convention and arity."""
    if callconv == "cdecl":
        return 0                              # caller cleans
    if callconv == "fastcall":
        return 4 * max(0, argc - 2)           # first two dwords in ECX/EDX
    return 4 * argc                           # stdcall: callee cleans


def observed_pop(addr, program):
    """(bytes_popped, None) from the callee's RET, or (None, reason).

    The raw cleanup, deliberately NOT converted to an arity: under fastcall the
    conversion loses information (0/1/2 args all pop nothing) while the pop
    itself remains perfectly good corroboration for a declared arity.
    """
    d = _get("disassemble_function", address=f"0x{addr:x}", program=program)
    ins = d.get("instructions") or []
    if not ins:
        return None, "no disassembly -- cannot confirm arity"
    pops = {int(m.group(1), 0) if m.group(1) else 0
            for m in (_RET_N.match(i.get("instruction", "").strip()) for i in ins) if m}
    if not pops:
        return None, "no RET found -- cannot confirm arity"
    if len(pops) > 1:
        return None, f"return paths pop different amounts {sorted(pops)} -- ambiguous arity"
    return pops.pop(), None


def arg_count(addr, program, callconv):
    """(argc, None) from the callee's OWN stack cleanup, or (None, reason).

    Ghidra's signature was the original source here and it shipped two wrong
    arities on 2026-07-30 that access-violated the game on save load:
    INV_CanItemFitInStoragePage inferred 3 args against a real `RET 8`, and
    ITEMS_TestItemFlags inferred 2 against a real `RET 0x10`. Both reimpls
    already had the right arity -- only the harvested manifest was wrong.

    On a callee-cleans convention the arity is not a matter of inference: the
    compiler encoded it in `RET n`. A parameter list is Ghidra's best guess at
    what the args MEAN; `RET 0x8` is a fact about how many there were. Getting
    it wrong does not degrade the evidence like a bad ret_bits does -- it skews
    ESP on every call and kills the process, so this reads the instruction and
    refuses when it cannot.
    """
    d = _get("disassemble_function", address=f"0x{addr:x}", program=program)
    ins = d.get("instructions") or []
    if not ins:
        return None, "no disassembly -- cannot confirm arity"
    pops = {int(m.group(1), 0) if m.group(1) else 0
            for m in (_RET_N.match(i.get("instruction", "").strip()) for i in ins) if m}
    if not pops:
        return None, "no RET found -- cannot confirm arity"
    if len(pops) > 1:
        # One function, one convention: differing pops means we are misreading
        # the range (or it spans two functions). Never average a guess.
        return None, f"return paths pop different amounts {sorted(pops)} -- ambiguous arity"
    pop = pops.pop()
    if callconv == "cdecl":
        # Caller cleans, so the callee's RET says nothing about arity and the
        # only source left is the inference that already burned us.
        return None, "cdecl -- callee cleanup reveals no arity; review manually"
    if pop % 4:
        return None, f"RET pops {pop}, not a dword multiple -- unhandled ABI"
    argc = pop // 4 + (2 if callconv == "fastcall" else 0)
    if callconv == "fastcall" and pop == 0:
        # Could be 0, 1, or 2 args -- all pop nothing. Indistinguishable here.
        return None, "fastcall with no stack cleanup -- arity 0/1/2 indistinguishable"
    return argc, None


_CANDIDATES = D2MOO_REPO / "conformance" / "reimpl_provider" / "candidates"

# The reimpl's own declaration. Spans lines for wide signatures, so DOTALL.
_REIMPL_SIG = re.compile(
    r'extern\s+"C"\s+(?:__declspec\([^)]*\)\s*)?'
    r'([A-Za-z_][\w\s*]*?)\s*'                       # return type
    r'__(stdcall|fastcall|cdecl)\s+(\w+)\s*\((.*?)\)\s*\{',
    re.S)

_RET_TYPE_BITS = {
    "unsigned char": 8, "signed char": 8, "char": 8, "uint8_t": 8, "int8_t": 8,
    "bool": 8, "byte": 8,
    "unsigned short": 16, "short": 16, "uint16_t": 16, "int16_t": 16, "word": 16,
}


def _split_args(inner):
    """Top-level comma split, so `f(a, b)` is 2 but a comma inside <> or () is not."""
    inner = inner.strip()
    if inner in ("", "void"):
        return []
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [a for a in out if a.strip()]


def reimpl_signatures():
    """name -> {callconv, argc, ret_bits}, parsed from the reimpl sources.

    This is the ARITY AUTHORITY, cross-checked against `RET n` below. It is
    stronger than either the disassembly or Ghidra alone:

      * Ghidra's parameter list is inference, and it shipped two wrong arities
        that crashed the game on 2026-07-30.
      * `RET n` is a fact, but it under-determines fastcall (a `RET 0` fastcall
        is 0, 1, or 2 args -- indistinguishable), which made the harvester
        refuse five otherwise-ready functions.
      * The reimpl's declaration states the convention outright, and that
        reimpl is the exact code the oracle already proved bit-exact against
        the original.

    Two independent sources, so agreement is EVIDENCE and disagreement is a
    REFUSAL SIGNAL -- never a tiebreak. On the crash: Ghidra said 3, the reimpl
    said 2, the RET said 2. Cross-checking would have caught it outright.
    """
    out = {}
    if not _CANDIDATES.is_dir():
        return out
    for f in _CANDIDATES.glob("*.cpp"):
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _REIMPL_SIG.finditer(txt):
            rettype, cc, fname, inner = m.group(1), m.group(2), m.group(3), m.group(4)
            rt = " ".join(rettype.split()).lower()
            out[fname] = {
                "callconv": cc.lower(),
                "argc": len(_split_args(inner)),
                # None => a full dword; the mask is unconstrained by this side.
                "ret_bits": None if rt.endswith("*") else _RET_TYPE_BITS.get(rt),
                "is_void": rt == "void",
            }
    return out


def datum_ret_bits(addr, program):
    """Narrowest return DATUM width, or None. Mirrors audit_ret_widths."""
    d = _get("disassemble_function", address=f"0x{addr:x}", program=program)
    ins = d.get("instructions") or []
    widths = []
    for idx, cur in enumerate(ins):
        if not re.match(r"^RET\b", cur.get("instruction", "").strip(), re.I):
            continue
        for j in range(idx - 1, -1, -1):
            t = ins[j].get("instruction", "").strip()
            if re.match(r"^(RET|JMP)\b", t, re.I):
                break
            mz = re.match(r"^MOVZX\s+EAX,\s*(byte|word)\s+ptr\b", t, re.I)
            if mz:
                widths.append(8 if mz.group(1).lower() == "byte" else 16); break
            if re.match(r"^(MOV|MOVZX|MOVSX|XOR|OR|AND|ADD|SUB|SBB|NEG|IMUL|LEA|POP|"
                        r"INC|DEC|SHL|SHR|SAR|NOT|CDQ)\s+EAX\b", t, re.I):
                widths.append(32); break
            if re.match(r"^(MOV|XOR|OR|AND|ADD|SUB)\s+AX\b", t, re.I):
                widths.append(16); break
            if re.match(r"^(MOV|XOR|OR|AND|ADD|SUB|SETN?[A-Z]{1,2})\s+AL\b", t, re.I):
                widths.append(8); break
    return min(widths) if widths else None


def build_entry(name, row, program, sigs=None):
    """Return (entry, None) or (None, skip_reason)."""
    base = MODULES[program]["base"]
    addr = row.get("address")
    if not addr:
        return None, "no address in registry"
    try:
        off = int(str(addr), 16) - base
    except ValueError:
        return None, f"unparseable address {addr!r}"
    if off <= 0 or off > 0x400000:
        return None, f"address {addr} outside {program} image"

    sig = (sigs or {}).get(name)
    iaddr = int(str(addr), 16)

    # Convention: the reimpl's declaration outranks the registry -- it is the
    # code the oracle actually proved, and it is what the thunk must call.
    callconv = (sig or {}).get("callconv") or row.get("callconv")
    if callconv not in ("stdcall", "fastcall", "cdecl"):
        return None, f"unsupported/absent callconv {callconv!r}"

    if (sig or {}).get("is_void") or row.get("ret") == "void":
        return None, "void return -> class B (out-param) needs manual byte-width review"

    # --- arity: reimpl declaration, cross-checked against the callee's RET ---
    #
    # Cross-check the raw POP, not a derived arity. `RET 0` under fastcall
    # under-determines arity (0/1/2 all pop nothing) but it is still real
    # instruction evidence: expected_cleanup(fastcall, 1) == 0 corroborates a
    # reimpl declaring one arg exactly. Treating "could not derive an arity" as
    # "no evidence" would refuse every fastcall entry -- the opposite of the
    # unlock this path exists for.
    pop, pop_why = observed_pop(iaddr, program)
    pop_argc, argc_why = arg_count(iaddr, program, callconv)
    if sig is not None:
        argc = sig["argc"]
        if pop is None:
            # Genuinely no instruction evidence. Ghidra can hold a name and
            # signature for a body it never disassembled
            # (DATATBLS_GetItemTypeDataByte49 and SKILLS_GetSkillDescField0x34
            # both do: /disassemble_bytes returns success with 0 instructions),
            # so "reimpl says 1" and "Ghidra's signature says 1" can agree
            # while neither has read an instruction -- and Ghidra's signature
            # is precisely the source that shipped the crash.
            return None, (f"reimpl declares {argc} arg(s) but there is no disassembly "
                          f"to corroborate it ({pop_why}) -- single-source arity, refusing")
        if expected_cleanup(callconv, argc) != pop:
            # Two independent sources disagree. This is exactly the shape of
            # the 2026-07-30 crash, so refuse loudly rather than pick a side.
            return None, (f"ARITY CONFLICT: reimpl declares {argc} arg(s) (callee should "
                          f"pop {expected_cleanup(callconv, argc)}) but the callee's RET "
                          f"pops {pop} -- refusing (a wrong arity skews ESP and "
                          f"access-violates the game)")
        why_argc = (f"{argc} arg(s) from the reimpl's declaration, corroborated by the "
                    f"callee popping {pop}")
    else:
        if pop_argc is None:
            return None, ((argc_why or pop_why or "arity undetermined")
                      + " and no reimpl declaration to cross-check")
        argc, why_argc = pop_argc, f"{pop_argc} arg(s) from the callee's RET"

    if argc == 0:
        return None, "0 args -- no diversity axis; low value, review manually"
    if argc > 4:
        return None, f"{argc} args -- wide ABI, review manually"

    # --- class: the reimpl's stated convention settles the cases the 6-
    # instruction prologue scan cannot. A function that loads its stack arg
    # later reads as "ABI unclear" even though its reimpl says __stdcall. ---
    cls, why_cls = classify(f"0x{iaddr:x}", program, argc)
    if cls is None:
        if sig is None:
            return None, why_cls
        cls = "A"
        why_cls = (f"stack args per the reimpl's __{callconv} declaration "
                   f"(prologue scan was inconclusive)")

    # Class D v1 carries exactly ONE register arg (EAX), which the thunk hands
    # to the reimpl as fastcall arg 1 (ECX). A register-explicit function with
    # a SECOND input register has no dispatcher shape yet, and accepting it as
    # plain fastcall would pass arg 1 in ECX while the original reads EAX --
    # silently comparing against garbage. SKILLS_CalculateLeveledToHitBonus is
    # exactly this (EAX=nSkillId, EDX=dwSkillLevel) and was previously refused
    # only because its declaration failed to parse; that was luck, not a guard.
    if cls == "D" and argc != 1:
        return None, (f"class D (register-explicit) with {argc} args -- the v1 "
                      f"dispatcher carries a single EAX input only; needs a "
                      f"multi-register variant")

    # --- return width: the mask must be legal for BOTH implementations. ---
    datum = datum_ret_bits(iaddr, program)
    if datum is None:
        datum = RET_BITS.get(row.get("ret"), 32)
    rb = (sig or {}).get("ret_bits")
    ret_bits = datum if rb is None else min(datum, rb)

    return {
        "name": name,
        "offset": f"0x{off:x}",
        "callconv": callconv,
        "args": ["i32"] * argc,
        "ret_bits": ret_bits,
        "class": cls,
        "note": (f"Harvested 2026-07-30 from CONF_LIVE + existing provider reimpl "
                 f"(stranded without a dispatcher). {why_argc}; class {cls} ({why_cls}); "
                 f"ret_bits {ret_bits} = min(original datum {datum}, "
                 f"reimpl declares {rb if rb is not None else 'dword'})."),
    }, None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--program", default="D2Common.dll", choices=list(MODULES))
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    reg = load_registry_best()
    exports = provider_exports()
    sigs = reimpl_signatures()
    mpath = MODULES[args.program]["manifest"]
    have = manifest_names(mpath)
    have_offsets = manifest_offsets(mpath)
    live = tagged(args.program, "CONF_LIVE")

    stranded = [n for n in sorted(live) if n not in have and n in exports]
    print(f"{args.program}: {len(live)} CONF_LIVE, {len(have)} dispatchers, "
          f"{len(stranded)} stranded with an existing reimpl\n")

    made, skipped = [], []
    for n in stranded:
        row = reg.get(n)
        if not row:
            skipped.append((n, "no registry row"))
            continue
        e, why = build_entry(n, row, args.program, sigs)
        if e and int(e["offset"], 0) in have_offsets:
            skipped.append((n, f"offset {e['offset']} already hooked (alias of an "
                               f"existing entry) -- Detours hooks one per address"))
            continue
        if e:
            # Guard against two NEW entries colliding within this same batch.
            have_offsets.add(int(e["offset"], 0))
        (made.append(e) if e else skipped.append((n, why)))
        if len(made) >= args.limit:
            break

    print(f"ELIGIBLE THIS BATCH ({len(made)}):")
    for e in made:
        print(f"  {e['name']:<44} {e['offset']:<9} {e['callconv']:<9} "
              f"class {e['class']}  ret{e['ret_bits']}  {len(e['args'])} arg(s)")
    if skipped:
        print(f"\nSKIPPED ({len(skipped)}) -- not guessed:")
        for n, why in skipped[:25]:
            print(f"  {n:<44} {why}")

    if not args.apply:
        print("\n(dry run -- add --apply to write the manifest)")
        return

    data = json.loads(mpath.read_text(encoding="utf-8"))
    data["entries"].extend(made)
    mpath.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"\nwrote {len(made)} entries -> {mpath}")
    print("next: regenerate (heeds ret-width + duplicate-offset guards), rebuild, deploy")


if __name__ == "__main__":
    main()

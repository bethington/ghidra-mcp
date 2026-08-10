"""falsify.py -- mechanical, model-free contradiction checks: doc vs disassembly.

WHY THIS EXISTS
---------------
`analyze_function_completeness` asks "is documentation present and well-formed?"
Every one of its ~30 deduction categories is computed FROM the documentation, so
no observation about the binary can ever lower the score -- a confidently wrong
plate scores 100. `doc_lint.py` opened this front with one check (library code
wearing a domain prefix); this module is the check FAMILY, comparing what the
documentation CLAIMS (name, prototype, calling convention, plate) against what
the binary SHOWS (disassembly-derived ABI, memory writes, callees).

Falsifiability is the second axis, orthogonal to completeness: completeness
forces claims to exist, this module checks whether they are true. The CONF_
ladder (conf_ladder.py) is the dynamic version of the same idea for reimpls;
these checks are its static, proof-free sibling for documentation.

FINDINGS ARE TIERED, exactly like doc_lint:

  Tier 1 -- mechanical certainty. The disassembly states a fact (`RET 0x8` is a
           fact the compiler emitted) and the documentation contradicts it.
           These carry consequences: DOC_REFUTED, forced audit, re-queue.
  Tier 2 -- a real contradiction signal that wants human/audit review before
           any consequence. Report-only.

Every check follows the confidence-guard rule: when the ground truth is
ambiguous (multiple RET immediates, approximate ESP tracking, varargs, a CALL
that clobbers the return register), the check returns NO finding rather than a
weak one. "UNDETERMINED -- inspect by hand, do not guess" (audit_stdcall_argc).

CHECKS
------
  param_mismatch (T1/T2)          plate-documented params vs live signature
  convention_contradiction (T1)   declared callconv vs derive_abi()'s synthesis
  arity_contradiction (T1)        declared argc vs the callee's actual RET n
  return_contradiction (T2)       plate/prototype return claims vs return paths
  name_verb_contradiction (T2)    reader-verb names that write globals, and
                                  writer-verb names that write nothing
  library_domain_prefix (T1/T2)   doc_lint's rule, corpus-level only
  phantom_callee (T2, OFF)        plate Algorithm names callees that don't exist
  compiler_scaffolding (T2)       plate Algorithm describes SEH / TLS-static /
                                  cookie machinery as a step of the algorithm

Architecture is doc_lint's: PURE check functions over a pre-fetched bundle,
a thin I/O layer (`collect_bundle`), and a CLI. Standalone -- imports nothing
from fun_doc (same rule as conf_ladder.py), so fun_doc may import it freely.

USAGE
-----
    python falsify.py --program /Mods/PD2-S12/D2Common.dll
    python falsify.py --folder /Mods/PD2-S12 --json report.json
    python falsify.py --program <p> --enable phantom_callee
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from abi_static import derive_abi, parse_disasm  # noqa: E402
from plate_scaffold import (  # noqa: E402
    _PARAM_MD, _PARAM_PLAIN, _sec, parse_function_plate,
)

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")

TIER_MECHANICAL = 1   # disassembly fact vs documentation claim -- certain
TIER_REVIEW = 2       # real signal, wants review before consequences


@dataclass
class Finding:
    check_id: str
    tier: int
    program: str
    address: str
    function: str
    claim: str       # what the documentation asserts
    evidence: str    # what the binary shows
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# shared ground-truth helpers (pure)
# --------------------------------------------------------------------------- #

_CC_RE = re.compile(r"(?:__)?(cdecl|stdcall|fastcall|thiscall)", re.I)

_AUTO_NAME_RE = re.compile(r"^(FUN_|thunk_FUN_|Ordinal_|thunk_Ordinal_|SUB_|LAB_)")
# Signature params Ghidra invented rather than a human asserted.
_AUTO_PARAM_RE = re.compile(r"^(param_\d+|in_[A-Z]{2,3}\d*|unaff_\w+|extraout_\w+)$")

# A plate line is NOT a claim about the formal signature when it marks itself
# implicit -- either in the TYPE ("(implicit / not in signature)", what
# plate_scaffold emits for orphaned prose) or in the DESCRIPTION, where the
# corpus convention is a trailing "[IMPLICIT]" tag for a register-passed
# operand. Measured 2026-08-02: `StoreSehContext`'s plate documents
# "dwExceptionContext: uint - exception context value passed in EAX
# [IMPLICIT]" -- a correct description of a register input, which the
# type-only check read as a claim about a nonexistent formal parameter.
_IMPLICIT_RE = re.compile(r"\bimplicit\b", re.I)

# Return types that assert nothing. Ghidra writes `undefined` when it could not
# infer a return type at all, so "plate says void, prototype says undefined" is
# an ABSENCE of information on the prototype side, not a contradiction.
_UNKNOWN_RET_TYPES = frozenset({"", "undefined", "unknown"})

# Return-register datum-width classification, ported from
# scripts/audit_ret_widths.py (see its docstrings for the MOVZX-vs-MOVSX and
# datum-vs-write-width rationale -- the 166,565-false-divergence lesson).
_W8 = re.compile(r"^(MOV|XOR|OR|AND|ADD|SUB|SETN?[A-Z]{1,2})\s+AL\b", re.I)
_W16 = re.compile(r"^(MOV|XOR|OR|AND|ADD|SUB)\s+AX\b", re.I)
_W32 = re.compile(
    r"^(MOV|MOVZX|MOVSX|XOR|OR|AND|ADD|SUB|SBB|NEG|IMUL|LEA|POP|INC|DEC|SHL|SHR|SAR|NOT|CDQ)\s+EAX\b",
    re.I)

# Instructions whose first operand being a memory ref means a MEMORY WRITE.
_MEM_WRITE_MNEMONICS = frozenset({
    "MOV", "ADD", "SUB", "AND", "OR", "XOR", "INC", "DEC", "NOT", "NEG",
    "SHL", "SHR", "SAR",
})
_ABS_DST_RE = re.compile(r"\[\s*(0x[0-9a-fA-F]+)\s*\]")

_FLOAT_RET_RE = re.compile(r"^(float|double|long\s+double)\b", re.I)


def _declared_cc(bundle: dict) -> Optional[str]:
    m = _CC_RE.search(bundle.get("calling_convention") or "")
    return m.group(1).lower() if m else None


# Ghidra's per-parameter storage strings: "ECX:4", "Stack[0x4]:4",
# "EDX:4,ECX:4" (a split 8-byte value). Only STACK-resident parameters
# participate in callee cleanup.
_STACK_STORAGE_RE = re.compile(r"\bStack\[", re.I)


def _stack_param_count(bundle: dict) -> Optional[int]:
    """How many declared parameters actually live on the stack, per Ghidra's
    OWN storage assignment -- or None when storage is unavailable.

    Deriving this from the convention NAME (stdcall -> all params, fastcall ->
    argc-2, thiscall -> argc-1) is an assumption about standard MSVC storage,
    and D2's binaries are full of custom register conventions where it does not
    hold: Ghidra declares `__fastcall` while assigning EAX/ECX/EDX/ESI by hand,
    or declares `__stdcall` on a function whose only input arrives in EAX. The
    storage string is the authority the same way the disassembly is -- it is
    what Ghidra will actually emit and what the decompiler reasons about.

    A split storage ("EDX:4,ECX:4") counts as stack only if a Stack[] fragment
    appears; a value split ACROSS a register and the stack is deliberately
    counted as stack, since the caller did push part of it.
    """
    params = bundle.get("params")
    if not params:
        return 0 if params == [] else None
    n = 0
    for p in params:
        if not isinstance(p, dict):
            return None
        storage = p.get("storage")
        if not storage:
            return None                  # unknown for ANY param -> no verdict
        if _STACK_STORAGE_RE.search(str(storage)):
            n += 1
    return n


def _ret_pops(parsed: list) -> set:
    """Set of RET immediates (0 for bare RET). Every return path must agree
    before any check treats the value as fact -- the calling convention is a
    property of the function, not of the path (audit_stdcall_argc)."""
    pops = set()
    for _, mn, ops in parsed:
        if mn.startswith("RET"):
            s = ops.strip()
            pops.add(int(s, 0) if re.match(r"^(0x[0-9a-fA-F]+|\d+)$", s) else 0)
    return pops


def _rebuilt_lines(parsed: list) -> list:
    """'MN OPS' strings for the width regexes, which match instruction text."""
    return [f"{mn} {ops}".strip() for _, mn, ops in parsed]


def _observed_ret_width(parsed: list) -> Optional[int]:
    """Narrowest return-register datum width across return paths, or None.
    Port of audit_ret_widths.observed_ret_width over parse_disasm output."""
    lines = _rebuilt_lines(parsed)
    widths = []
    for idx, cur in enumerate(lines):
        if not re.match(r"^RET\b", cur, re.I):
            continue
        for j in range(idx - 1, -1, -1):
            t = lines[j]
            if re.match(r"^(RET|JMP)\b", t, re.I):
                break                       # previous path ends here
            mz = re.match(r"^MOVZX\s+EAX,\s*(byte|word)\s+ptr\b", t, re.I)
            if mz:
                widths.append(8 if mz.group(1).lower() == "byte" else 16)
                break
            if _W32.match(t):
                widths.append(32)
                break
            if _W16.match(t):
                widths.append(16)
                break
            if _W8.match(t):
                widths.append(8)
                break
    return min(widths) if widths else None


def _abs_global_writes(parsed: list) -> list:
    """Absolute-address memory writes: [(ins_addr, global_addr), ...]."""
    out = []
    for addr, mn, ops in parsed:
        if mn not in _MEM_WRITE_MNEMONICS:
            continue
        dst = ops.split(",", 1)[0]
        m = _ABS_DST_RE.search(dst)
        if m:
            out.append((addr, int(m.group(1), 16)))
    return out


def _has_any_mem_write(parsed: list) -> bool:
    """Any write through memory that is NOT a local (ESP/EBP-relative)."""
    for _, mn, ops in parsed:
        if mn not in _MEM_WRITE_MNEMONICS:
            continue
        dst = ops.split(",", 1)[0]
        if "[" in dst and "ESP" not in dst.upper() and "EBP" not in dst.upper():
            return True
    return False


def _doc_param_lines(plate: str) -> list:
    """[(name, type)] the plate's Parameters section asserts about the formal
    signature (implicit/orphaned-prose lines excluded)."""
    parsed = parse_function_plate(plate or "")
    body = _sec(parsed["sections"], "Parameters") or ""
    out = []
    for ln in body.splitlines():
        m = _PARAM_PLAIN.match(ln) or _PARAM_MD.match(ln)
        if not m:
            continue
        nm, ty, desc = m.group(1), m.group(2).strip(), m.group(3)
        if _IMPLICIT_RE.search(ty) or _IMPLICIT_RE.search(desc or ""):
            continue
        out.append((nm, ty))
    return out


def _plate_return_type(plate: str) -> Optional[str]:
    """The type token the plate's Returns section asserts, or None."""
    parsed = parse_function_plate(plate or "")
    body = _sec(parsed["sections"], "Returns") or ""
    ln = next((l for l in body.splitlines() if l.strip()), "")
    if not ln:
        return None
    m = re.match(r"\s*([A-Za-z_][\w\s\*]*?)\s*(?::|$)", ln)
    return m.group(1).strip() if m else None


def _mk(bundle: dict, check_id: str, tier: int, claim: str, evidence: str,
        **detail) -> Finding:
    return Finding(check_id=check_id, tier=tier,
                   program=bundle.get("program", ""),
                   address=str(bundle.get("address", "")),
                   function=bundle.get("name", ""),
                   claim=claim, evidence=evidence, detail=detail)


# --------------------------------------------------------------------------- #
# checks (pure -- bundle in, findings out)
# --------------------------------------------------------------------------- #

def check_param_mismatch(bundle: dict) -> List[Finding]:
    """F1: the plate documents parameters the signature does not have.

    Tier 1 only when the plate documents MORE params than the signature holds
    (a count contradiction -- the claimed parameter cannot exist). Same-count
    name drift is tier 2: it may be a rename the plate hasn't caught up with,
    which is staleness, not certainly a false claim.
    """
    params = bundle.get("params")
    if params is None:
        return []
    doc_params = _doc_param_lines(bundle.get("plate") or "")
    if not doc_params:
        return []
    sig_names = [str(p.get("name") or "") for p in params]
    sig_ci = {n.lower() for n in sig_names if n}
    missing = [nm for nm, _ in doc_params if nm.lower() not in sig_ci]
    if not missing:
        return []
    if len(doc_params) > len(sig_names):
        tier = TIER_MECHANICAL
        why = (f"signature has {len(sig_names)} parameter(s) "
               f"({', '.join(sig_names) or 'none'})")
        # Which side is wrong? If the callee's own cleanup implies at least as
        # many stack slots as the plate documents, the SIGNATURE is the stale
        # one -- say so, or the fixer deletes correct prose to satisfy a wrong
        # prototype (`StoreSehContext`: plate 1 param, signature 0, RET 0x4).
        parsed = parse_disasm(bundle.get("disasm_text") or "")
        pops = _ret_pops(parsed) if parsed else set()
        if len(pops) == 1:
            obs = next(iter(pops))
            if obs and obs // 4 >= len(doc_params) > len(sig_names):
                why += (f", but RET 0x{obs:x} implies {obs // 4} stack slot(s) "
                        f"-- the SIGNATURE is the stale side, not the plate")
    else:
        tier = TIER_REVIEW
        why = ("signature names differ "
               f"({', '.join(sig_names) or 'none'}) -- possible rename drift")
    return [_mk(bundle, "param_mismatch", tier,
                claim=f"plate documents {len(doc_params)} parameter(s) "
                      f"including {', '.join(missing)}",
                evidence=why,
                documented=[nm for nm, _ in doc_params],
                signature=sig_names, missing=missing)]


def check_convention(bundle: dict) -> List[Finding]:
    """F2: declared calling convention vs the disassembly's cleanup behavior.

    This is the exact defect class that leaked 4*argc bytes of ESP per call in
    port_live_prove (a bare RET with stack args is cdecl; declaring it stdcall
    means nobody pops). `RET 0x8` is a fact the compiler emitted; the declared
    convention gets no vote.
    """
    cc = _declared_cc(bundle)
    if not cc:
        return []
    parsed = parse_disasm(bundle.get("disasm_text") or "")
    if not parsed:
        return []
    pops = _ret_pops(parsed)
    if len(pops) != 1:
        return []                    # no RET, or paths disagree -- undetermined
    obs = next(iter(pops))
    out: List[Finding] = []
    if cc == "cdecl" and obs:
        out.append(_mk(bundle, "convention_contradiction", TIER_MECHANICAL,
                       claim="declared __cdecl (caller cleans the stack)",
                       evidence=f"function ends in RET 0x{obs:x} -- the callee "
                                f"cleans {obs} byte(s); callee-cleans is not cdecl",
                       declared=cc, ret_bytes=obs))
    elif cc in ("stdcall", "fastcall", "thiscall") and obs == 0:
        # Stack-arg count comes from Ghidra's OWN per-parameter storage, never
        # from the convention name -- see _stack_param_count. No storage means
        # no verdict (guard-first).
        stack_argc = _stack_param_count(bundle)
        if stack_argc is None:
            return out
        if stack_argc > 0:
            out.append(_mk(bundle, "convention_contradiction", TIER_MECHANICAL,
                           claim=f"declared __{cc} with {stack_argc} stack "
                                 f"argument(s) (callee must clean {4 * stack_argc} bytes)",
                           evidence="function ends in a bare RET -- the caller "
                                    "cleans, which is the cdecl shape; nobody pops "
                                    "the declared stack args",
                           declared=cc, declared_stack_args=stack_argc,
                           ret_bytes=0))
    return out


def check_arity(bundle: dict) -> List[Finding]:
    """F3: declared STACK parameters vs the callee's actual stack cleanup.

    A callee-cleans convention pops 4 bytes per stack-resident parameter, so
    `RET n` states how many the compiler believed there were. A wrong count
    skews ESP and access-violates the process (eip=0x140, 2026-07-30), which
    is why this is tier 1.

    The stack-parameter count comes from Ghidra's OWN per-parameter storage,
    never from the convention name. Deriving it as stdcall->argc /
    fastcall->argc-2 assumes standard MSVC storage, and D2 is full of custom
    register conventions where that is false: `FindRoomAtCoordinates` is
    declared `__fastcall` with storage `ECX, EDX, Stack[0x4]` (agrees), while
    `DATATBLS_GetSkillDescriptionRecord` is declared `__stdcall` with storage
    `Stack[0x4]` yet reads its input from EAX. Counting `Stack[...]` entries
    is the only reading that tracks what Ghidra will actually emit.
    """
    cc = _declared_cc(bundle)
    if cc not in ("stdcall", "fastcall", "thiscall"):
        return []
    params = bundle.get("params")
    if params is None:
        return []
    if "..." in (bundle.get("prototype") or ""):
        return []                    # varargs -- cleanup is caller business
    stack_argc = _stack_param_count(bundle)
    if stack_argc is None:
        return []                    # storage unknown -> no verdict
    parsed = parse_disasm(bundle.get("disasm_text") or "")
    if not parsed:
        return []
    pops = _ret_pops(parsed)
    if len(pops) != 1:
        return []
    obs = next(iter(pops))
    exp = 4 * stack_argc
    if obs == exp:
        return []
    if obs == 0 and exp > 0:
        return []                    # bare-RET shape: convention_contradiction owns it
    real_stack = obs // 4
    return [_mk(bundle, "arity_contradiction", TIER_MECHANICAL,
                claim=f"declared __{cc} with {stack_argc} stack parameter(s) "
                      f"of {len(params)} total (callee should pop {exp} bytes)",
                evidence=f"RET 0x{obs:x} pops {obs} bytes -> "
                         f"{real_stack} real stack slot(s)",
                declared_argc=len(params), declared_stack_argc=stack_argc,
                expected_bytes=exp, observed_bytes=obs,
                real_stack_slots=real_stack)]


def check_return(bundle: dict) -> List[Finding]:
    """F4 (tier 2): return-contract contradictions.

    (a) void prototype but the plate documents a returned value (or inverse);
    (b) non-void prototype but no path writes the return register before RET.
    (b) is guarded hard: leaf only (a CALL sets EAX invisibly), integer-family
    return only (float returns ride ST0), and RETs must exist.
    """
    rt = (bundle.get("return_type") or "").strip()
    out: List[Finding] = []
    plate_rt = _plate_return_type(bundle.get("plate") or "")
    # An `undefined` prototype return asserts nothing (Ghidra could not infer
    # one), so it cannot contradict the plate either way -- comparing against
    # it manufactured findings on functions whose plate was simply ahead of
    # the prototype.
    if plate_rt and rt.lower() not in _UNKNOWN_RET_TYPES:
        rt_void = rt.lower() == "void"
        plate_void = plate_rt.lower() == "void"
        if rt_void and not plate_void:
            out.append(_mk(bundle, "return_contradiction", TIER_REVIEW,
                           claim=f"plate Returns documents '{plate_rt}'",
                           evidence="prototype return type is void",
                           plate_return=plate_rt, prototype_return=rt))
        elif not rt_void and plate_void:
            out.append(_mk(bundle, "return_contradiction", TIER_REVIEW,
                           claim="plate Returns documents void",
                           evidence=f"prototype return type is '{rt}'",
                           plate_return=plate_rt, prototype_return=rt))
    if rt and rt.lower() not in ("void", "undefined") and not _FLOAT_RET_RE.match(rt):
        parsed = parse_disasm(bundle.get("disasm_text") or "")
        if (parsed and len(parsed) >= 3
                and not any(mn == "CALL" for _, mn, _ in parsed)
                and any(mn.startswith("RET") for _, mn, _ in parsed)
                and _observed_ret_width(parsed) is None):
            out.append(_mk(bundle, "return_contradiction", TIER_REVIEW,
                           claim=f"prototype declares a '{rt}' return value",
                           evidence="no return path writes EAX/AX/AL before RET "
                                    "(leaf function, no calls) -- the declared "
                                    "return value is never produced",
                           prototype_return=rt))
    return out


_READER_VERB_RE = re.compile(
    r"^(?:[A-Z][A-Z0-9]*_)?(Get|Is|Has|Query|Peek|Lookup|Count|Find)(?=[A-Z0-9_])")
_WRITER_VERB_RE = re.compile(
    r"^(?:[A-Z][A-Z0-9]*_)?(Set|Write|Store)(?=[A-Z0-9_])")
# Tokens that legitimize a write inside a reader (caching getters, lazy init).
_READER_MITIGATION_RE = re.compile(
    r"(Cache|Init|Ensure|Alloc|Create|Update|Load|Register|Or(Create|Init|Load))",
    re.I)


def check_name_verb(bundle: dict) -> List[Finding]:
    """F5 (tier 2): the name's verb contradicts the function's observable
    side effects.

    Reader-verb names (Get/Is/Has/...) that WRITE absolute globals, and
    writer-verb names (Set/Write/Store) that write no non-local memory at all.
    Writes through pointer params are invisible to the global-write scan, so
    out-param getters are exempt automatically; writer-verb checks skip any
    function that delegates (a CALL may do the write).
    """
    name = bundle.get("name") or ""
    if not name or _AUTO_NAME_RE.match(name):
        return []
    parsed = parse_disasm(bundle.get("disasm_text") or "")
    if not parsed:
        return []
    out: List[Finding] = []
    if _READER_VERB_RE.match(name) and not _READER_MITIGATION_RE.search(name):
        writes = _abs_global_writes(parsed)
        if writes:
            addrs = sorted({f"0x{g:08x}" for _, g in writes})
            out.append(_mk(bundle, "name_verb_contradiction", TIER_REVIEW,
                           claim=f"name '{name}' promises a read-only accessor",
                           evidence=f"writes {len(addrs)} global(s): "
                                    f"{', '.join(addrs[:4])}"
                                    + (" ..." if len(addrs) > 4 else ""),
                           verb=_READER_VERB_RE.match(name).group(1),
                           written_globals=addrs))
    elif _WRITER_VERB_RE.match(name):
        # Delegation makes the write invisible here: a CALL, or a TAIL CALL.
        # An IAT thunk is literally one `JMP dword ptr [0x...]` -- it performs
        # the mutation through the import and writes nothing itself, which the
        # CALL-only guard read as "promises a mutation, does nothing"
        # (measured 2026-08-02 on D2MCPClient's `WriteDataWithSizeVerification`
        # and `SetGameStateFields`, both pure import thunks).
        delegates = any(mn == "CALL" or mn.startswith("JMP")
                        for _, mn, _ in parsed)
        if not delegates and not _has_any_mem_write(parsed):
            out.append(_mk(bundle, "name_verb_contradiction", TIER_REVIEW,
                           claim=f"name '{name}' promises a mutation",
                           evidence="no non-local memory write and no call "
                                    "anywhere in the function",
                           verb=_WRITER_VERB_RE.match(name).group(1)))
    return out


_PREFIXED_NAME_RE = re.compile(r"\b([A-Z][A-Z0-9]+_[A-Za-z][A-Za-z0-9_]+)\b")


def check_phantom_callee(bundle: dict) -> List[Finding]:
    """F7 (tier 2, disabled by default): the plate's Algorithm/summary names
    module-prefixed functions the function does not actually call.

    Only module-prefixed names (`DATATBLS_GetRecord`) are matched -- bare
    PascalCase words are far too ambiguous. Only Algorithm + summary are
    scanned: 'Used by' / provenance sections legitimately mention callers.
    """
    callees = bundle.get("callees")
    if callees is None:
        return []
    name = bundle.get("name") or ""
    parsed = parse_function_plate(bundle.get("plate") or "")
    text = "\n".join(filter(None, [parsed.get("summary", ""),
                                   _sec(parsed["sections"], "Algorithm") or ""]))
    if not text:
        return []
    callee_ci = {str(c).lower() for c in callees}
    mentioned = {m.group(1) for m in _PREFIXED_NAME_RE.finditer(text)}
    phantom = sorted(m for m in mentioned
                     if m.lower() not in callee_ci and m != name)
    if not phantom:
        return []
    return [_mk(bundle, "phantom_callee", TIER_REVIEW,
                claim=f"plate describes calling {', '.join(phantom[:5])}"
                      + (" ..." if len(phantom) > 5 else ""),
                evidence=f"actual callees: {', '.join(sorted(callees)[:8]) or 'none'}",
                phantom=phantom, callees=sorted(callees))]


# An ABSOLUTE address, not a struct offset. Six-plus hex digits only: `+0x14`,
# `0x5c` and string ids like `0xFCA` are offsets and constants, and matching them
# would accuse a plate of lying every time it documented a field layout.
_PLATE_ABS_ADDR_RE = re.compile(r"\b0x([0-9a-fA-F]{6,8})\b")

# Sections that legitimately name addresses the function does NOT reference.
# "Called By" lists CALLERS -- a function never references its own callers, so
# scanning that section would produce a finding on every well-documented function.
_ADDR_EXEMPT_SECTIONS = ("called by", "callers", "used by", "references to",
                         "xrefs", "see also")


def check_phantom_address(bundle: dict) -> List[Finding]:
    """F8 (tier 2): the plate cites an absolute address the function never touches.

    Mechanical and model-free: an address a plate names either appears among the
    addresses the instructions reference, or it does not.

    MEASURED ORIGIN (2026-08-05). D2Client's `HandleSaveAndExitDialogConfirm`
    carries an AI-written plate naming `g_pSaveExitDialog (0x6fbcc994)` and
    `g_dwGameModeState (0x6fbcd5ac)`. Its disassembly writes `0x6fbc77e8` and
    `0x6fbcc2cc`. BOTH cited addresses are fabricated -- and D2Debugger had
    copied one of them into a hardcoded constant, which disabled a guard its own
    comment describes as protecting against refcount corruption. Nobody noticed
    because every existing falsify check is structural in a different dimension:
    convention, arity, return width, parameter counts, verb agreement.

    Deliberately narrow, because a tier-1 accusation carries consequences and a
    false one is worse than a miss:
      * only 6-8 hex-digit ABSOLUTE addresses, so struct offsets (`+0x14`),
        small constants and string ids are never matched;
      * caller-listing sections are exempt -- a function does not reference the
        things that call it;
      * a plate address that appears ANYWHERE in the disassembly passes, even as
        an immediate, so a documented constant is not accused.
    Tier 2 rather than 1 on first release: the rule is sound but unmeasured at
    corpus scale, and phantom_callee set the precedent for earning tier 1.

    NOT COVERED, BY DESIGN -- cross-image contamination. The data-segment
    containment filter below means this check CANNOT see a plate propagated
    wholesale from another binary, because such a plate's addresses are, by
    construction, outside this program. Measured 2026-08-09 on
    /Vanilla/1.00/D2Game.dll: 44 of 745 plated functions (~6%) document a
    0x6F......-based image while the program is based at 0x10000000, clustered
    12% inside the statically-linked CRT (byte-identical CRT is exactly what a
    hash propagator matches, and it drags absolute addresses along).
    That class belongs to scripts/cross_image_contamination.py, which discriminates
    on ATTRIBUTION (a benign cross-module reference NAMES the module; a propagated
    plate does not). Do NOT widen the containment filter here to try to cover it --
    that would re-introduce the false-positive class rounds 1-3 removed. The two
    checks are complements: F8 owns "invented a global of MINE", the sweep owns
    "this text is not about my binary at all".
    """
    disasm = bundle.get("disasm_text")
    if not disasm:
        return []
    plate = bundle.get("plate") or ""
    if not plate:
        return []

    # Drop exempt sections before scanning.
    kept, skipping = [], False
    for line in plate.splitlines():
        stripped = line.strip().lower().rstrip(":")
        if stripped and not line.startswith((" ", "\t")) and stripped.endswith(
                tuple(s.split()[-1] for s in _ADDR_EXEMPT_SECTIONS)):
            skipping = any(stripped.startswith(s.split()[0]) for s in _ADDR_EXEMPT_SECTIONS)
        elif stripped and not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            skipping = False
        if not skipping:
            kept.append(line)
    scanned = "\n".join(kept)

    cited = {m.group(1).lower() for m in _PLATE_ABS_ADDR_RE.finditer(scanned)}
    if not cited:
        return []
    referenced = {m.group(1).lower() for m in _PLATE_ABS_ADDR_RE.finditer(disasm)}
    # The function's own address is legitimately citable.
    own = str(bundle.get("address") or "").lower().lstrip("0x")
    if own:
        referenced.add(own)

    # CALIBRATION, in three measured rounds against the SAME 400-function
    # D2Client slice. Each filter kills a class that was observed in the output,
    # not one that was imagined:
    #
    #   round 1  no filters                      29 findings, >=4 of 6 sampled false
    #   round 2  + masks, + function addresses   12 findings, survivors still bad
    #   round 3  + DATA-SEGMENT containment       (this)
    #
    # Round 3 subsumes rounds 1 and 2 and is the principled version of both: a
    # global that a function falsely cites is, by construction, an address in
    # THIS program's data. So require exactly that.
    #   * outside every segment  -> a mask (0xffffffff) or another module's
    #                               address (0x6fc36ad4 is D2Game, 0x6ff7e33f is
    #                               Fog). Not this function's claim to get wrong.
    #   * inside an EXECUTABLE   -> code. A plate naming a routine, or a label a
    #     segment                  few bytes on (__sopen at 0x6faba467 citing
    #                               0x6faba473), is documentation, not a false
    #                               claim -- and the function-address list cannot
    #                               catch mid-function labels.
    # What survives is an address in .data/.rdata that the instructions never
    # touch, which is precisely the measured defect: D2Client's plate naming
    # g_pSaveExitDialog 0x6fbcc994 and g_dwGameModeState 0x6fbcd5ac, both in
    # .data, while the code writes 0x6fbc77e8 and 0x6fbcc2cc.
    data_ranges = bundle.get("data_ranges")
    if not data_ranges:
        return []          # cannot tell -> abstain, never guess

    def _in_program_data(a: str) -> bool:
        try:
            v = int(a, 16)
        except ValueError:
            return False
        return any(lo <= v <= hi for lo, hi in data_ranges)

    phantom = sorted(a for a in cited if a not in referenced and _in_program_data(a))
    if not phantom:
        return []
    return [_mk(bundle, "phantom_address", TIER_REVIEW,
                claim=f"plate cites address(es) 0x{', 0x'.join(phantom[:5])}"
                      + (" ..." if len(phantom) > 5 else ""),
                evidence="not referenced anywhere in the disassembly",
                phantom_addresses=phantom)]


# F9. The constructs below are the COMPILER'S, not the author's. Naming one as
# a numbered step describes machinery the source never wrote.
#
# WHY A CHECK AND NOT A PROMPT RULE. Both plate prompts were given this rule on
# 2026-08-06 and it was measured as a NO-OP the same day: the same 8 functions,
# blinded and re-documented, produced 0-of-5 invention-free plates before and
# after, and plates grew 19%. The model complied by LABELLING the scaffolding
# instead of omitting it -- one plate gained a whole new paragraph headed "NOT
# compiler-generated machinery:" enumerating the SEH prologue it had been told
# not to describe. "Do not describe X as behaviour" reads as "identify X".
#
# CALIBRATED, like every other threshold here, against a measured sample --
# 199 random plates from the 20,714 that carry one:
#
#     scaffolding named ANYWHERE in the plate      18  (9.0%)
#     scaffolding named as an ALGORITHM STEP       11  (5.5%)   <- the defect
#
# extrapolating to roughly 1,100 plates corpus-wide.
#
# THREE ABSTENTIONS, each killing a measured false-positive class:
#
#   ALGORITHM ONLY. A plate that says "these locals are compiler-emitted" in
#   Special Cases is REFUSING to treat them as behaviour -- that is the correct
#   answer and must not be accused. Only the numbered steps are scanned. This
#   is also what separates 9.0% from 5.5%.
#
#   NO `vftable`. Measured: 2 of its 3 sampled hits were legitimate object
#   layout -- "zero the vftable at this+0x24", "allocate root JSONObject with
#   vftable and empty data". A vtable pointer is a real field of a real C++
#   object, and documenting it is not describing the compiler's bookkeeping.
#
#   NO bare `unwind` or bare `TLS`. `Unwind_6fd179c0` is a CALLEE NAME, and
#   "get coordinates via Unwind_6fd179c0" is a step about the program;
#   `g_pdwTlsIndexTable3` is BH.dll's own data. Both matched in the first pass
#   and inflated the rate from 5.5% to 14.6%. Only the CRT spellings
#   (`RtlUnwind`, `_local_unwind`) and `_tls_index` survive.
#
# TIER 2, deliberately. This is a hygiene defect, not a contradiction with the
# disassembly: the plate is not claiming anything FALSE about the binary, it is
# describing the wrong layer. Tier 1 carries DOC_REFUTED, a forced audit and
# selector re-entry, and none of that is proportionate to verbosity.
_SCAFFOLD_RE = re.compile(
    r"\bSEH\b|__except\b|__try\b|_tls_index|\bSRW\b|InitOnce|__onexit"
    r"|security[- ]cookie|__security_cookie|stack cookie"
    r"|vector (?:constructor|destructor) iterator|ExceptionList"
    r"|exception registration|scope table"
    r"|RtlUnwind|_(?:local|global)_unwind|unwind the stack"
    r"|TLS[- ]gated|TLS block", re.I)


def check_compiler_scaffolding(bundle: dict) -> List[Finding]:
    """F9 (tier 2): the plate's Algorithm describes compiler machinery as a step.

    The `_tls_index` + SRW + InitOnce + `__onexit` cluster IS a function-local
    static; SEH frames and scope tables are C++ exception handling; vector
    ctor/dtor iterators are ordinary object construction. None of them is
    something the author wrote, so none of them is a step of the algorithm.
    """
    parsed = parse_function_plate(bundle.get("plate") or "")
    algo = _sec(parsed["sections"], "Algorithm") or ""
    if not algo.strip():
        return []
    hits = sorted({m.group(0).lower() for m in _SCAFFOLD_RE.finditer(algo)})
    if not hits:
        return []
    # The offending step, quoted, so a reviewer does not have to go looking.
    line = next((ln.strip() for ln in algo.splitlines() if _SCAFFOLD_RE.search(ln)), "")
    return [_mk(bundle, "compiler_scaffolding", TIER_REVIEW,
                claim=f"Algorithm describes compiler machinery as a step: {line[:160]}",
                evidence=f"constructs named: {', '.join(hits[:6])}",
                constructs=hits)]


ALL_CHECKS = {
    "param_mismatch": check_param_mismatch,
    "convention_contradiction": check_convention,
    "arity_contradiction": check_arity,
    "return_contradiction": check_return,
    "name_verb_contradiction": check_name_verb,
    "phantom_callee": check_phantom_callee,
    "phantom_address": check_phantom_address,
    "compiler_scaffolding": check_compiler_scaffolding,
}
# phantom_address is ENABLED after three measured calibration rounds against the
# SAME 400-function D2Client slice:
#
#   round 1  no filters                    29 findings; >=4 of 6 sampled FALSE
#                                          (masks like 0xffffffff; neighbouring routines)
#   round 2  + masks, + function addresses 12 findings; survivors still dominated by
#                                          cross-module addresses and mid-function labels
#   round 3  + DATA-SEGMENT containment     4 findings; 3 of 3 sampled VERIFIED GENUINE
#
# Round 3 is not a tuned threshold, which is why it works where the first two
# did not: a false global claim IS, by definition, an address in THIS program's
# data that the instructions never touch. Requiring exactly that excludes another
# module's address and this module's code without needing a distance guess.
#
# The three verified positives show the fabrication's shape -- the model gets the
# NEIGHBOURHOOD right and the value wrong: __unlock_file's plate cites 6fb8b1f7 /
# 6fb8b459 where the code uses 6fb8b1f8 / 6fb8b458 (off by one), __flsbuf cites
# 6fb8b794 against 6fb8b790 (off by four). That is exactly how D2Debugger came to
# hardcode 0x6FBCC994 instead of 0x6FBC77E8 and silently disable a guard.
#
# Tier 2 still: a wrong address is a real defect, but promoting to tier 1 (forced
# audit, DOC_REFUTED, selector re-entry) needs a corpus-scale rate, not one slice.
DEFAULT_DISABLED = frozenset({"phantom_callee"})


def enabled_check_ids(enable: Iterable[str] = (), disable: Iterable[str] = ()) -> list:
    ids = [c for c in ALL_CHECKS if c not in DEFAULT_DISABLED or c in set(enable or ())]
    return [c for c in ids if c not in set(disable or ())]


def run_checks(bundle: dict, enabled: Optional[Iterable[str]] = None) -> List[Finding]:
    """All findings for one function. A broken check prints loudly and is
    skipped -- it must never take the worker (or the sweep) down with it."""
    ids = list(enabled) if enabled is not None else enabled_check_ids()
    out: List[Finding] = []
    for cid in ids:
        fn = ALL_CHECKS.get(cid)
        if fn is None:
            continue
        try:
            out.extend(fn(bundle))
        except Exception as e:  # noqa: BLE001 - loud, never silent, never fatal
            print(f"[falsify] check {cid} failed on "
                  f"{bundle.get('program')}@{bundle.get('address')}: {e}",
                  file=sys.stderr)
    return out


def tier1(findings: Iterable[Finding]) -> List[Finding]:
    return [f for f in findings if f.tier == TIER_MECHANICAL]


def summarize(findings: Iterable[Finding]) -> dict:
    fs = list(findings)
    return {
        "tier1": len([f for f in fs if f.tier == TIER_MECHANICAL]),
        "tier2": len([f for f in fs if f.tier == TIER_REVIEW]),
        "check_ids": sorted({f.check_id for f in fs}),
    }


# --------------------------------------------------------------------------- #
# doc_lint bridge (corpus-level check F6)
# --------------------------------------------------------------------------- #

def doclint_findings(recs, stats) -> List[Finding]:
    """doc_lint defects -> Findings. doc_lint tier 1 (curated LIB_* tag --
    stored ground truth) maps to mechanical; tier 2 (heuristic detector) to
    review. Corpus-level only: the calibration needs the whole corpus, so the
    per-function worker stage does not run this -- the sweep does."""
    import doc_lint  # local, lazy: keeps falsify importable without it
    defects = doc_lint.find_defects(recs, stats)
    out = []
    for d in defects:
        out.append(Finding(
            check_id="library_domain_prefix",
            tier=TIER_MECHANICAL if d.tier == 1 else TIER_REVIEW,
            program=d.program, address=d.address, function=d.name,
            claim=f"name '{d.name}' claims the {d.prefix}_ game subsystem",
            evidence=f"classified as library/runtime code [{d.library_reason}]",
            detail={"prefix": d.prefix, "library_reason": d.library_reason,
                    "doclint_tier": d.tier}))
    return out


# --------------------------------------------------------------------------- #
# Ghidra write-back (single writer -- the worker stage, the sweep and the
# cross-version harvester all route through here, so status -> tag/property
# mapping cannot drift between lanes; same rule as conf_ladder).
# --------------------------------------------------------------------------- #

FALSIFY_PROPERTY_MAP = "Falsify"
DOC_REFUTED_TAG = "DOC_REFUTED"

VALID_STATUSES = ("unchecked", "passed", "contradicted", "unfalsifiable")

_SYNC_FAILURES = 0
_SYNC_MAX_FAILURES = 10

_FLAG_PREFIX = "[AUDIT falsify:"
# One flag paragraph: "[AUDIT falsify:<check> <date>] ..." up to a blank line.
_FLAG_BLOCK_RE = re.compile(
    r"^\[AUDIT falsify:[^\n]*(?:\n(?!\s*\n)[^\n]*)*\n?\s*\n?", re.M)


def status_for(findings: Iterable[Finding], checks_ran: bool = True) -> str:
    """Verdict from one run's findings. 'Can't be checked' is NOT 'passed'
    (the CONF_BLOCKED rule): a run where no check could reach a conclusion
    reports unfalsifiable, not a clean bill."""
    fs = list(findings)
    if not checks_ran:
        return "unchecked"
    if any(f.tier == TIER_MECHANICAL for f in fs):
        return "contradicted"
    return "passed"


def flag_marker(check_id: str) -> str:
    return f"{_FLAG_PREFIX}{check_id}"


def finding_flag_text(f: Finding, date: str) -> str:
    """The idempotent plate note for one finding. Keyed by its marker;
    fun_doc._ghidra_audit_flag-compatible (prefix-in-plate = already flagged).
    Tier-1 wording states a fact; tier-2 wording asks for review."""
    if f.tier == TIER_MECHANICAL:
        return (f"{flag_marker(f.check_id)} {date}] CONTRADICTION (mechanical): "
                f"{f.claim} -- but {f.evidence}. Fix the documentation to match "
                f"the disassembly; the disassembly is the authority.")
    return (f"{flag_marker(f.check_id)} {date}] REVIEW: {f.claim} -- but "
            f"{f.evidence}. Judgement call; verify before acting.")


def flag_finding(program: str, address: str, f: Finding,
                 date: Optional[str] = None) -> str:
    """Idempotently prepend ONE finding's plate note without touching the
    verdict machinery — for lanes that record evidence but don't own the
    falsify_status (e.g. the cross-version disagreement harvester, whose
    tier-2 findings are report-only by design). Returns 'flagged' |
    'already-flagged' | 'error:<msg>'.

    PASS THE FULL PROJECT PATH. This used to reduce `program` to its BASENAME,
    which is ambiguous in this project and silently wrote to the wrong binary.
    MEASURED 2026-08-10: stamping 21 findings for `/Vanilla/1.00/D2Net.dll` sent
    every one to `/Mods/PD2-S12/D2Net.dll` — a different image at base
    0x6fbf0000 — creating plate comments at 0x1000xxxx addresses that do not
    exist there. Ghidra accepted the writes, the run reported "21 stamped, 0
    FAILED", and the intended binary was untouched. Nothing warned.

    The lanes most exposed are exactly the ones this function exists for: the
    cross-version harvester runs across MULTIPLE VERSIONS of the same DLL, so
    duplicate basenames (`D2Net.dll`, `D2Game.dll`, `Fog.dll`, …) are guaranteed,
    not incidental. See project_port_live_prove_wrong_binary_fix for the previous
    instance of this same bug class."""
    prog = program
    a = address if str(address).startswith("0x") else "0x" + str(address)
    if date is None:
        import datetime as _dt
        date = _dt.date.today().isoformat()
    try:
        cur = _get("/get_comment", address=a, program=prog)
        plate = (cur.get("plate") if isinstance(cur, dict) else "") or ""
        if flag_marker(f.check_id) in plate:
            return "already-flagged"
        body = finding_flag_text(f, date) + ("\n\n" + plate if plate else "")
        _post("/set_comment",
              {"address": a, "comment": body, "type": "plate"}, program=prog)
        return "flagged"
    except Exception as e:  # noqa: BLE001
        print(f"[falsify] flag WARN @ {a} ({prog}): {e}", file=sys.stderr)
        return f"error:{e}"


def strip_falsify_flags(plate: str) -> str:
    """Remove every falsify flag paragraph from a plate (used when a function
    re-passes after a fix). Leaves all other content untouched."""
    if not plate or _FLAG_PREFIX not in plate:
        return plate
    return _FLAG_BLOCK_RE.sub("", plate).lstrip("\n")


def compact_record(status: str, findings: Iterable[Finding], source: str,
                   date: str) -> dict:
    """The Falsify property-map value: compact on purpose (the full findings
    blob lives in SQL; the map is for a human in CodeBrowser)."""
    fs = list(findings)
    rec = {"status": status, "source": source, "date": date,
           "tier1": len([f for f in fs if f.tier == TIER_MECHANICAL]),
           "tier2": len([f for f in fs if f.tier == TIER_REVIEW]),
           "checks": sorted({f.check_id for f in fs})}
    return rec


def sync_to_ghidra(program: str, address: str, status: str,
                   findings: Iterable[Finding], source: str,
                   date: Optional[str] = None) -> bool:
    """Project a falsify verdict onto Ghidra: DOC_REFUTED tag (contradicted
    adds it, passed removes it), the `Falsify` property record, and idempotent
    plate flags for tier-1 findings (cleared again on a later pass).

    Best-effort, never raises, loud on failure (a silently-swallowed
    write-back is how the wrong-binary bug went unnoticed). Circuit breaker
    mirrors fun_doc's conf-rung sync: after _SYNC_MAX_FAILURES consecutive
    failures the process stops paying HTTP timeouts.

    `program` may be a project path or bare name; writes send it IN THE QUERY
    STRING -- body-only `program` silently targets the active program.
    """
    global _SYNC_FAILURES
    if status not in VALID_STATUSES:
        print(f"[falsify] refusing to sync unknown status '{status}'",
              file=sys.stderr)
        return False
    if status in ("unchecked", "unfalsifiable"):
        return True                       # no Ghidra-side claim either way
    if _SYNC_FAILURES >= _SYNC_MAX_FAILURES:
        return False
    fs = list(findings)
    prog = program.rsplit("/", 1)[-1]
    a = address if str(address).startswith("0x") else "0x" + str(address)
    if date is None:
        import datetime as _dt
        date = _dt.date.today().isoformat()
    try:
        # 1) DOC_REFUTED tag -- mutually consistent with the verdict.
        if status == "contradicted":
            resp = _post("/add_function_tag",
                         {"function": a, "tags": DOC_REFUTED_TAG},
                         program=prog)
        else:
            resp = _post("/remove_function_tag",
                         {"function": a, "tags": DOC_REFUTED_TAG},
                         program=prog)
        if isinstance(resp, dict) and resp.get("error"):
            raise RuntimeError(f"tag write failed: {str(resp)[:160]}")

        # 2) Falsify property record (lazy map creation on first use).
        rec = json.dumps(compact_record(status, fs, source, date),
                         separators=(",", ":"))
        body = {"map": FALSIFY_PROPERTY_MAP, "address": a, "value": rec}
        p = _post("/set_property", body, program=prog)
        if isinstance(p, dict) and not p.get("success") and "No property map" in str(p):
            _post("/create_property_map",
                  {"name": FALSIFY_PROPERTY_MAP, "type": "string"}, program=prog)
            _post("/set_property", body, program=prog)

        # 3) Plate flags: add one per tier-1 finding; strip all when passed.
        cur = _get("/get_comment", address=a, program=prog)
        plate = cur.get("plate") if isinstance(cur, dict) else ""
        plate = plate or ""
        if status == "contradicted":
            new_plate = plate
            for f in tier1(fs):
                if flag_marker(f.check_id) not in new_plate:
                    new_plate = finding_flag_text(f, date) + \
                        ("\n\n" + new_plate if new_plate else "")
            if new_plate != plate:
                _post("/set_comment",
                      {"address": a, "comment": new_plate, "type": "plate"},
                      program=prog)
        elif _FLAG_PREFIX in plate:
            _post("/set_comment",
                  {"address": a, "comment": strip_falsify_flags(plate),
                   "type": "plate"}, program=prog)

        _SYNC_FAILURES = 0
        return True
    except Exception as e:  # noqa: BLE001 - must never take a worker down
        _SYNC_FAILURES += 1
        print(f"[falsify] write-back WARN: sync {status} @ {a} ({prog}): {e}",
              file=sys.stderr)
        return False


# --------------------------------------------------------------------------- #
# I/O layer
# --------------------------------------------------------------------------- #

def _post(path: str, data: dict, **params):
    """POST with `program` (and anything else) in the QUERY string --
    @Param(value="program") defaults to ParamSource.QUERY; a body-only
    program is ignored and the write leaks to the active program."""
    url = f"{GHIDRA}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(
        url, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


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


def render_disasm(resp) -> str:
    """'addr: instruction' lines from /disassemble_function (the format
    parse_disasm expects). Mirrors fun_doc.disasm_text without importing it."""
    out = []
    for ins in _items(resp, "instructions"):
        if isinstance(ins, dict):
            out.append(f"{ins.get('address', '')}: {ins.get('instruction', '')}")
    return "\n".join(out)


def attach_param_storage(params: list, func_name: Optional[str],
                         program: str) -> list:
    """Merge Ghidra's per-parameter STORAGE into the parameter dicts.

    `/get_function_documentation` reports name/type/ordinal but not storage;
    `/get_function_variables` reports storage ("ECX:4", "Stack[0x4]:4"). The
    ABI checks need storage to know which parameters the callee must pop, so
    fetch it here rather than letting them assume standard MSVC layout.

    Parameters are matched by ORDINAL when the endpoint supplies it and by
    position otherwise. On any failure the params come back UNCHANGED (no
    `storage` key), which the checks read as "unknown" and abstain -- the
    guard-first rule: a missing fact must never become a verdict.
    """
    if not params or not func_name:
        return params
    try:
        resp = _get("/get_function_variables", function_name=func_name,
                    program=program)
        live = resp.get("parameters") if isinstance(resp, dict) else None
        if not isinstance(live, list) or not live:
            return params
    except Exception as e:  # noqa: BLE001 - abstain, never fail the scan
        print(f"[falsify] storage unavailable for {func_name}: {e}",
              file=sys.stderr)
        return params
    by_ordinal = {p.get("ordinal"): p for p in live
                  if isinstance(p, dict) and p.get("ordinal") is not None}
    out = []
    for i, p in enumerate(params):
        if not isinstance(p, dict):
            out.append(p)
            continue
        src = by_ordinal.get(p.get("ordinal", i))
        if src is None and i < len(live) and isinstance(live[i], dict):
            src = live[i]
        merged = dict(p)
        if src is not None and src.get("storage"):
            merged["storage"] = src["storage"]
        out.append(merged)
    return out


_DATA_RANGE_CACHE: dict = {}


def _program_data_ranges(program: str) -> tuple:
    """Non-executable, initialised segment ranges of `program` as (lo, hi) ints.

    This is what lets check_phantom_address tell a false global claim from the
    two things that merely look like one: an address belonging to a DIFFERENT
    module, and an address inside this module's code. Cached per program -- one
    /list_segments call, not one per function.

    An unreachable Ghidra yields an EMPTY tuple, and the check abstains entirely
    rather than falling back to a looser rule.
    """
    if program in _DATA_RANGE_CACHE:
        return _DATA_RANGE_CACHE[program]
    ranges = []
    try:
        segs = _items(_get("/list_segments", program=program), "segments")
        for s in segs:
            if s.get("executable") or not s.get("initialized", True):
                continue
            try:
                lo = int(str(s.get("start", "")).lstrip("0x"), 16)
                hi = int(str(s.get("end", "")).lstrip("0x"), 16)
            except ValueError:
                continue
            if hi >= lo:
                ranges.append((lo, hi))
    except Exception as e:  # noqa: BLE001 - abstain, never fail the scan
        print(f"[falsify] segments unavailable for {program}: {e}", file=sys.stderr)
        ranges = []
    out = tuple(ranges)
    _DATA_RANGE_CACHE[program] = out
    return out


_FN_ADDR_CACHE: dict = {}


def _program_function_addresses(program: str) -> frozenset:
    """Every function address in `program`, lowercase and unprefixed.

    Cached per program: a sweep calls collect_bundle once per function, and
    re-listing thousands of functions each time would dominate the run. An
    unreachable Ghidra yields an EMPTY set, which makes check_phantom_address
    fall back to not excluding anything -- noisier, never wrong in the
    consequential direction.
    """
    if program in _FN_ADDR_CACHE:
        return _FN_ADDR_CACHE[program]
    try:
        fns = _items(_get("/list_functions", program=program, limit=200000), "functions")
        addrs = frozenset(str(f.get("address", "")).lower().lstrip("0x") for f in fns)
    except Exception as e:  # noqa: BLE001 - abstain, never fail the scan
        print(f"[falsify] function list unavailable for {program}: {e}", file=sys.stderr)
        addrs = frozenset()
    _FN_ADDR_CACHE[program] = addrs
    return addrs


def collect_bundle(program: str, address: str, with_callees: bool = False) -> dict:
    """One function's claims + ground truth, from a live Ghidra instance.

    /get_function_documentation carries name/prototype pieces/plate/params in a
    single call; /disassemble_function supplies the ground truth. Callees are
    fetched only when phantom_callee is enabled (extra round-trip)."""
    a = address if str(address).startswith("0x") else "0x" + str(address)
    doc = _get("/get_function_documentation", address=a, program=program)
    if not isinstance(doc, dict) or doc.get("error"):
        raise RuntimeError(f"get_function_documentation failed for {a}: {doc}")
    dis = _get("/disassemble_function", address=a, program=program)
    params = doc.get("parameters") if isinstance(doc.get("parameters"), list) else []
    bundle = {
        "program": program,
        "address": a,
        "name": doc.get("function_name") or "",
        "calling_convention": doc.get("calling_convention") or "",
        "return_type": doc.get("return_type") or "",
        "params": attach_param_storage(params, doc.get("function_name"), program),
        "plate": doc.get("plate_comment") or "",
        "disasm_text": render_disasm(dis),
        "prototype": "",
        # Every function address in this program, so check_phantom_address can
        # tell "the plate names a related ROUTINE" (documentation) from "the
        # plate names a global the code never touches" (a false claim). Cached
        # per program -- one /list_functions call, not one per function.
        "function_addresses": _program_function_addresses(program),
        # Non-executable segment ranges, so check_phantom_address can require a
        # cited global to actually live in THIS program's data.
        "data_ranges": _program_data_ranges(program),
    }
    if with_callees:
        resp = _get("/get_function_callees", name=bundle["name"], program=program)
        bundle["callees"] = [
            (c.get("name") if isinstance(c, dict) else str(c))
            for c in _items(resp, "callees")
        ]
    return bundle


def list_programs(folder: str) -> List[str]:
    resp = _get("/list_project_files", folder=folder)
    files = resp.get("files", []) if isinstance(resp, dict) else []
    return [f["path"] for f in files
            if f.get("content_type") == "Program" and not f["name"].endswith(".0")]


def scan_program_verdicts(program: str, enabled: list, limit: int = 0,
                          pause_every: int = 0, pause_secs: float = 0.0) -> list:
    """Per-function verdicts for every custom-named function in one program:
    [(address, name, status, [Finding, ...]), ...]. Auto-named functions carry
    no claims to falsify and are skipped. A function whose bundle fetch fails
    reports status 'error' (no information — never a pass).

    pause_every/pause_secs insert a sleep every N functions so a long sweep
    doesn't monopolize Ghidra's HTTP threads (inventory_scorer's chunk rule).
    """
    fns = _items(_get("/list_functions", program=program, limit=200000), "functions")
    out = []
    with_callees = "phantom_callee" in enabled
    scanned = 0
    for f in fns:
        name = (f.get("name") or "") if isinstance(f, dict) else ""
        addr = str(f.get("address") or "") if isinstance(f, dict) else ""
        if not name or not addr or _AUTO_NAME_RE.match(name):
            continue
        try:
            bundle = collect_bundle(program, addr, with_callees=with_callees)
        except Exception as e:  # noqa: BLE001
            print(f"  !! {program}@{addr} ({name}): {e}", file=sys.stderr)
            out.append((addr, name, "error", []))
            continue
        findings = run_checks(bundle, enabled)
        out.append((addr, name, status_for(findings), findings))
        scanned += 1
        if limit and scanned >= limit:
            break
        if pause_every and scanned % pause_every == 0 and pause_secs:
            time.sleep(pause_secs)
    return out


def scan_program(program: str, enabled: list, limit: int = 0) -> List[Finding]:
    """Findings only (CLI report shape); see scan_program_verdicts."""
    findings: List[Finding] = []
    for _, _, _, fs in scan_program_verdicts(program, enabled, limit=limit):
        findings.extend(fs)
    return findings


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _print_report(findings: List[Finding]) -> None:
    by_check: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_check[f.check_id].append(f)
    t1 = len(tier1(findings))
    print(f"\n=== FINDINGS: {len(findings)} total "
          f"({t1} tier-1 mechanical, {len(findings) - t1} tier-2 review) ===")
    for cid, group in sorted(by_check.items(), key=lambda kv: -len(kv[1])):
        print(f"\n  {cid}  x{len(group)}")
        for f in sorted(group, key=lambda x: (x.tier, x.program, x.function))[:15]:
            prog = f.program.rsplit("/", 1)[-1]
            print(f"    [T{f.tier}] {prog:20} {f.address:>10}  {f.function}")
            print(f"          claim:    {f.claim}")
            print(f"          evidence: {f.evidence}")
        if len(group) > 15:
            print(f"    ... and {len(group) - 15} more")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--folder", help="sweep every Program in this project folder")
    g.add_argument("--program", help="single program path")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--enable", action="append", default=[],
                    metavar="CHECK", help="enable a default-off check")
    ap.add_argument("--disable", action="append", default=[],
                    metavar="CHECK", help="disable a check")
    ap.add_argument("--limit", type=int, default=0,
                    help="max functions per program (0 = all)")
    ap.add_argument("--no-doclint", action="store_true",
                    help="skip the corpus-level library_domain_prefix check")
    args = ap.parse_args()

    bad = [c for c in args.enable + args.disable if c not in ALL_CHECKS
           and c != "library_domain_prefix"]
    if bad:
        ap.error(f"unknown check(s): {', '.join(bad)} "
                 f"(known: {', '.join(ALL_CHECKS)}, library_domain_prefix)")
    enabled = enabled_check_ids(args.enable, args.disable)

    programs = [args.program] if args.program else list_programs(args.folder)
    print(f"# scanning {len(programs)} program(s), checks: {', '.join(enabled)}",
          file=sys.stderr)

    findings: List[Finding] = []
    for p in programs:
        try:
            r = scan_program(p, enabled, limit=args.limit)
        except Exception as e:  # noqa: BLE001
            print(f"  !! {p}: {e}", file=sys.stderr)
            continue
        findings.extend(r)
        print(f"  {p:44} {len(r):5} finding(s)", file=sys.stderr)

    # Corpus-level doc_lint check (needs cross-program calibration).
    if not args.no_doclint and "library_domain_prefix" not in args.disable:
        try:
            import doc_lint
            recs = []
            for p in programs:
                recs.extend(doc_lint.collect(p))
            findings.extend(doclint_findings(recs, doc_lint.calibrate(recs)))
        except Exception as e:  # noqa: BLE001
            print(f"  !! library_domain_prefix sweep failed: {e}", file=sys.stderr)

    _print_report(findings)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "scanned_programs": programs,
                "checks": enabled,
                "summary": summarize(findings),
                "findings": [f.to_dict() for f in findings],
            }, fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

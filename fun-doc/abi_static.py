"""abi_static.py -- MECHANICAL ABI derivation from disassembly (no model, no oracle).

Why this exists (2026-07-08 batch lessons, see D2MOO conformance workflow): the two
worst port failures were the drafting model GUESSING ABI facts that the disassembly
states outright:

  * GetAnimSequenceRecord: model declared __fastcall/ECX for a function whose disasm
    reads `[ESP+4]` and ends `RET 0x4` -- plain 1-slot __stdcall. Wrong callconv makes
    the ORIGINAL read its arg from the wrong place -> live_prove_failed, 3 retries.
  * DATATBLS_GetItemDataByCode: Ghidra's prototype said ONE param, but the disasm
    ends `RET 0xC` -- THREE stack slots (two unused). Marshalling 1 arg while the
    callee pops 3 corrupted the oracle stack -> SEH fault -> the function was wrongly
    written off as "blocked".

Both facts are 100% derivable statically:
  RET n            -> callee cleans n bytes  -> n/4 stack slots, stdcall-family
  [ESP+x] reads    -> which slots are actually used
  reads-before-writes of GP registers -> register-explicit incoming args
  `dword ptr [0x...]` absolute derefs -> data globals the reimpl needs resolved
  CALL <addr>      -> delegates (delegate-rung / not-a-leaf detection)
  decompile "Subroutine does not return" / _exit / CleanupAndAbort -> abort class
    (out-of-range input KILLS the process/bridge -> vectors must stay in-envelope)

derive_abi() is heuristic-but-honest: linear scan with an ESP-delta tracker; any
construct it can't track precisely (calls, branches before stack reads) sets
`approx=True` so callers treat used_slots as advisory while ret_imm/slots stay
authoritative (RET n is unambiguous).

Standalone: stdlib only. Self-test: python abi_static.py  (runs the 4-function
known-answer corpus captured from live D2Common 1.13c).
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# disasm parsing
# ---------------------------------------------------------------------------
# Ghidra /disassemble_function lines: "6fdc19a0: MOV EAX,dword ptr [ESP + 0x4] ; comment"
_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{6,}):\s+(\S+)\s*(.*?)\s*(?:;.*)?$")

_GP32 = ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP")
# sub-register -> parent 32-bit register
_SUBREG = {}
for _r in _GP32:
    _SUBREG[_r] = _r
for _p, _subs in (("EAX", ("AX", "AL", "AH")), ("EBX", ("BX", "BL", "BH")),
                  ("ECX", ("CX", "CL", "CH")), ("EDX", ("DX", "DL", "DH")),
                  ("ESI", ("SI",)), ("EDI", ("DI",)), ("EBP", ("BP",))):
    for _s in _subs:
        _SUBREG[_s] = _p

_REG_TOKEN_RE = re.compile(r"\b(E?[ABCD]X|E?[SD]I|E?BP|[ABCD][LH])\b", re.IGNORECASE)
_ESP_READ_RE = re.compile(r"\[\s*ESP\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*\]", re.IGNORECASE)
_ABS_MEM_RE = re.compile(r"\[\s*(0x[0-9a-fA-F]+)\s*\]")
# A global used as the DISPLACEMENT of a base+index memory operand --
# `MOV AL, byte ptr [EAX + 0x6fdef0a8]` -- where 0x6fdef0a8 is an array-base GLOBAL,
# not a struct field offset. Struct offsets are small (< a few KB); loaded D2Common
# globals live in the image range (0x6fdxxxxx), so an image-range threshold cleanly
# separates the two. (Before this, array-base getters were mis-tagged provable_now.)
_DISP_GLOBAL_RE = re.compile(r"\+\s*(0x[0-9a-fA-F]+)\s*\]")
_IMAGE_MIN = 0x6f000000
_IMM_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|-?\d+)$")

_ABORT_DECOMPILE_RE = re.compile(
    r"Subroutine does not return|_exit\s*\(|CleanupAndAbort|ExitProcess|\babort\s*\(",
    re.IGNORECASE)

# The D2Common 1.13c abort-idiom helpers (GetReturnAddress / CleanupAndAbort /
# _exit). Every fatal out-of-range branch this session called exactly these three,
# and they are NOT delegates in the delegate-rung sense -- they're unreachable
# in-envelope. derive_abi() splits them out of `calls` so the planner doesn't
# misfile every abort-class getter as delegate-rung. Version-specific; extend or
# override for other targets.
ABORT_HELPERS = {0x6fd5921c, 0x6fd59216, 0x6fd51b0d}


def _regs_in(text: str) -> set:
    """Parent 32-bit GP registers mentioned anywhere in an operand string."""
    return {_SUBREG[m.group(1).upper()] for m in _REG_TOKEN_RE.finditer(text or "")}


def parse_disasm(text: str) -> list:
    """[(addr:int, mnemonic:str, operands:str)] from Ghidra disassembly text."""
    out = []
    for line in (text or "").splitlines():
        m = _LINE_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(2).upper(), m.group(3).strip()))
    return out


def detect_abort_path(decompiled_text: str) -> bool:
    """True when the DECOMPILE shows a noreturn/abort branch. Such a function is
    ABORT CLASS: an input that reaches the branch calls _exit/CleanupAndAbort and
    kills the process (or the oracle bridge) UNCATCHABLY -- so prove vectors must
    stay strictly in the valid envelope and V1 adversarial sweeps must skip it.
    (GetAnimSequenceRecord killed the :8790 bridge 3x before this was automated;
    contrast GetItemDataRecord whose out-of-range path RETURNS NULL -> full-range
    vectors are safe. The decompile states which one you have.)"""
    return bool(_ABORT_DECOMPILE_RE.search(decompiled_text or ""))


# A dwType (or ->dwType) comparison anywhere in the body. Combined with
# detect_abort_path, this flags a HANDLE-typed abort gated on the captured
# object's dispatch type -- distinct from a SCALAR out-of-range abort.
_DWTYPE_CMP_RE = re.compile(r"\bdwType\b\s*(?:==|!=|<|>|<=|>=)", re.IGNORECASE)


def detect_handle_abort_hazard(decompiled_text: str) -> bool:
    """True when a handle-getter's abort path is gated on the CAPTURED OBJECT's
    dwType (e.g. `if (pUnit->dwType == 0) {...} else CleanupAndAbort();`), not a
    numeric index. CONFIRMED LIVE CRASH (2026-07-08, STAT_GetUnitCalculatedStat):
    the oracle's handle-prove path round-robins DISTINCT captured object types
    (Player/Monster/Object/...) for branch-coverage diversity -- for a function
    gated this way, that diversity mechanism itself feeds it the wrong type and
    triggers an UNCATCHABLE abort (a real 'Halt' dialog that force-terminates the
    game process, unlike a wild-read SEH fault). detect_abort_path() alone can't
    distinguish this from a safe scalar-index abort class, so callers must check
    BOTH: abort present AND a dwType comparison -> refuse automated handle-prove
    (the fix needs a Player-only capture pin, which the C++ capture mechanism
    doesn't support yet -- so this is a SKIP, not a clamp, until it does)."""
    return bool(detect_abort_path(decompiled_text) and _DWTYPE_CMP_RE.search(decompiled_text or ""))


def derive_abi(disasm_text: str) -> dict:
    """Ground-truth ABI facts from a function's disassembly. See module docstring.

    Returns {
      ret_imm:      bytes the callee cleans (RET n), 0 for plain RET, None if no RET seen
      slots:        stack arg slots = ret_imm // 4 (None when ret_imm is None)
      used_slots:   sorted slot indices actually read via [ESP+x] (advisory if approx)
      reg_args:     GP registers read before written (register-explicit incoming args)
      callconv:     'stdcall' | 'fastcall' | 'thiscall' | 'register_explicit'
                    | 'cdecl_or_caller_clean' | 'unknown'
      calls:        CALL target addresses (delegates; non-empty => NOT a pure leaf)
      data_globals: absolute `[0x...]` memory-deref operands (globals to resolve)
      approx:       True when used_slots tracking crossed a call/branch (heuristic zone)
      notes:        human-readable derivation notes
    }
    """
    ins = parse_disasm(disasm_text)
    notes: list = []
    ret_imms: set = set()
    used_offsets: set = set()
    calls: list = []
    data_globals: list = []
    written: set = set()
    reg_args: set = set()
    depth = 0          # linear ESP delta (bytes pushed since entry)
    approx = False

    for addr, mn, ops in ins:
        # --- absolute data derefs (any instruction) ---
        for m in _ABS_MEM_RE.finditer(ops):
            v = int(m.group(1), 16)
            if v not in data_globals:
                data_globals.append(v)

        # --- global as a base+index displacement: `[reg + 0x<image-range global>]`
        # (array-base getters, e.g. `MOV AL,[EAX + 0x6fdef0a8]`). The image-range
        # threshold keeps small struct-field offsets from being mistaken for globals.
        for m in _DISP_GLOBAL_RE.finditer(ops):
            v = int(m.group(1), 16)
            if v >= _IMAGE_MIN and v not in data_globals:
                data_globals.append(v)

        # --- stack arg reads: [ESP] / [ESP+off], adjusted by tracked push depth ---
        for m in _ESP_READ_RE.finditer(ops):
            off = int(m.group(1), 0) if m.group(1) else 0
            orig = off - depth          # offset as seen at function entry
            if orig >= 4:               # 0 = return address slot
                used_offsets.add(orig)
            elif depth:                 # post-push read we can't attribute cleanly
                approx = True

        # --- register reads-before-writes (incoming register args) ---
        reads: set = set()
        writes: set = set()
        if mn in ("MOV", "MOVSX", "MOVZX", "LEA"):
            parts = ops.split(",", 1)
            if len(parts) == 2:
                dst, src = parts[0].strip(), parts[1].strip()
                reads |= _regs_in(src)
                if "[" in dst:                       # memory dst: its address regs are READ
                    reads |= _regs_in(dst)
                else:
                    writes |= _regs_in(dst)
        elif mn in ("TEST", "CMP"):
            reads |= _regs_in(ops)
        elif mn == "PUSH":
            reads |= _regs_in(ops)
            depth += 4
        elif mn == "POP":
            writes |= _regs_in(ops)
            depth -= 4
        elif mn == "IMUL":
            parts = [p.strip() for p in ops.split(",")]
            if parts:
                writes |= _regs_in(parts[0])
                for p in parts[1:]:
                    reads |= _regs_in(p)
        elif mn in ("ADD", "SUB", "AND", "OR", "XOR", "SBB", "ADC",
                    "SHL", "SHR", "SAR", "ROL", "ROR"):
            parts = ops.split(",", 1)
            if len(parts) == 2:
                dst, src = parts[0].strip(), parts[1].strip()
                d_esp = dst.upper() == "ESP"
                if d_esp and mn in ("SUB", "ADD") and _IMM_RE.match(src):
                    depth += int(src, 0) * (1 if mn == "SUB" else -1)
                if mn == "XOR" and dst.strip().upper() == src.strip().upper():
                    writes |= _regs_in(dst)          # xor r,r zero idiom: write-only
                else:
                    reads |= _regs_in(src)
                    if "[" in dst:
                        reads |= _regs_in(dst)
                    else:
                        reads |= _regs_in(dst)       # read-modify-write
                        writes |= _regs_in(dst)
        elif mn in ("INC", "DEC", "NEG", "NOT"):
            reads |= _regs_in(ops)
            writes |= _regs_in(ops)
        elif mn == "CALL":
            m = re.match(r"^(0x[0-9a-fA-F]+)$", ops.strip())
            if m:
                calls.append(int(m.group(1), 16))
            # caller-saved clobber; args consumed by a callee-clean callee. We can't
            # see the callee's cleanup, so RESET the linear depth (true whenever the
            # tracked depth came from arg pushes -- the norm in these leaf/thunk fns)
            # and flag the remainder of the scan as approximate.
            writes |= {"EAX", "ECX", "EDX"}
            if depth:
                depth = 0
                approx = True
        elif mn.startswith("RET"):
            m = re.match(r"^(0x[0-9a-fA-F]+|\d+)$", ops.strip()) if ops.strip() else None
            ret_imms.add(int(m.group(1), 0) if m else 0)

        reg_args |= {r for r in reads if r not in written and r not in ("EBP",)}
        written |= writes

    # --- synthesize ---
    ret_imm = None
    if ret_imms:
        nz = {r for r in ret_imms if r}
        if len(nz) > 1:
            notes.append(f"multiple RET immediates {sorted(nz)} -- shared epilogue?")
        ret_imm = max(nz) if nz else 0
    slots = (ret_imm // 4) if ret_imm is not None else None
    used_slots = sorted((o - 4) // 4 for o in used_offsets)
    if slots is not None and used_slots and used_slots[-1] >= slots and ret_imm:
        notes.append(f"stack read beyond RET-cleaned slots (used {used_slots}, slots {slots})")
        approx = True

    if ret_imm:
        if not reg_args:
            callconv = "stdcall"
        elif reg_args == {"ECX"}:
            callconv = "thiscall"
        elif reg_args <= {"ECX", "EDX"}:
            callconv = "fastcall"
        else:
            callconv = "register_explicit"
    elif ret_imm == 0:
        callconv = ("register_explicit" if reg_args
                    else ("cdecl_or_caller_clean" if used_slots else "unknown"))
    else:
        callconv = "unknown"
        notes.append("no RET instruction seen (noreturn tail?)")

    if slots is not None and slots and not used_slots and not approx:
        notes.append(f"RET 0x{ret_imm:x} cleans {slots} slot(s) but none are read -- "
                     "declare ALL of them (unused padding params) or the caller stack corrupts")

    real_calls = [c for c in calls if c not in ABORT_HELPERS]
    helper_calls = [c for c in calls if c in ABORT_HELPERS]
    return {
        "ret_imm": ret_imm, "slots": slots, "used_slots": used_slots,
        "reg_args": sorted(reg_args), "callconv": callconv,
        "calls": real_calls, "abort_helper_calls": helper_calls,
        "data_globals": data_globals,
        "approx": approx, "notes": notes,
    }


def abi_prompt_block(abi: dict, abort_class: bool = False) -> str:
    """A prompt section stating the DERIVED ABI as authoritative, for injection
    into draft prompts. The model no longer gets a vote on callconv/slot count."""
    if not abi or abi.get("slots") is None:
        lines = ["## ABI (static derivation unavailable -- follow the plate/decompile)"]
    else:
        lines = ["## AUTHORITATIVE ABI (derived mechanically from the disassembly -- "
                 "do NOT contradict this)"]
        cc = abi["callconv"]
        n = abi["slots"]
        lines.append(f"- Calling convention: {cc}; the callee cleans {abi['ret_imm']} bytes "
                     f"(RET 0x{abi['ret_imm']:x}) => declare EXACTLY {n} stack parameter(s).")
        if abi["used_slots"] and len(abi["used_slots"]) < (n or 0):
            unused = [i for i in range(n) if i not in abi["used_slots"]]
            lines.append(f"- Only slot(s) {abi['used_slots']} are read; slot(s) {unused} are "
                         f"UNUSED but MUST still be declared (e.g. `int unused{unused[0]+1}`) "
                         f"or the stack is corrupted at return.")
        if abi["reg_args"]:
            lines.append(f"- Register-explicit incoming args: {', '.join(abi['reg_args'])}.")
        if abi["calls"]:
            lines.append(f"- Calls {len(abi['calls'])} subroutine(s) -- not a pure leaf.")
    if abort_class:
        lines.append("- ABORT CLASS: the out-of-range branch terminates the process "
                     "(_exit/CleanupAndAbort). input_sets MUST stay strictly IN-RANGE: "
                     "small non-negative indices only. NO negatives, NO INT_MIN/INT_MAX, "
                     "NO huge values, NO 'boundary+1' probes -- any of those KILLS the game.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MECHANICAL GETTER TRANSLATION (no model). The hottest port class -- a shadow_leaf
# getter -- is 2-5 instructions of a pure MOV-chain: load the pointer param, walk a
# few [reg+off] derefs (each optionally null-guarded by a TEST/JNZ that skips an
# abort block), and return the final read (MOV/MOVSX/MOVZX = width+sign). That maps
# to C with ZERO model involvement, ZERO guesswork.
#
# WHY (2026-07-08): three reimpls diverged ~99% because the MODEL drafted from
# Ghidra's decompile PROSE -- `pStateLinkedList[1].pStateHead` became invented
# struct-size/index arithmetic reading a bogus fixed offset. The disasm is
# unambiguous (`MOV EAX,[EAX+0xa8]; MOV EAX,[EAX+0xc]`). Translating it directly
# removes the whole defect class (and the CONCAT31 u8/u32 oscillation) for the
# functions this handles; anything with a branch / arithmetic / call / 2nd arg
# returns None so the caller falls back to the model.
# ---------------------------------------------------------------------------
_MEM_OFF_RE = re.compile(
    r"\[\s*(E?[ABCD]X|E?[SD]I|E?BP)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*\]", re.IGNORECASE)


def _ret_c_type(ret: str):
    return {"u8": "unsigned char", "i8": "char", "u16": "unsigned short", "i16": "short",
            "u32": "unsigned int", "i32": "int", "void": "void*"}.get(ret, "unsigned int")


def translate_getter_to_c(name: str, disasm_text: str, *, callconv: str = "stdcall",
                          ret: str = "u32") -> dict:
    """A pure pointer-deref getter's disasm -> {ok, code, ret, chain, reason}.

    Handles the LINEAR shape: `MOV EAX,[ESP+4]` (the single pointer param), a
    sequence of `MOV/MOVSX/MOVZX EAX,[EAX+off]` (pointer walks; the LAST is the
    returned read, its mnemonic sets width+sign), optional null-guards (`TEST
    EAX,EAX` + a conditional to a return-0 / abort block, either JNZ-skips-abort or
    JZ-jumps-to-null-return), a trailing chain of value transforms on the final read
    (`AND/OR/XOR/SHL/SHR EAX, imm` -- flag/bit getters like `& 4` or `>>8 & 1`), the
    `XOR EAX,EAX` return-0 idiom, and a final `RET n`. ANY CMP / value-compare branch
    / IMUL/MUL/LEA/ADD/SUB on a data reg / a deref AFTER a transform (computed
    address) / CALL to a non-abort target / 2nd stack arg / a register outside the
    EAX chain -> ok=False with a reason (caller falls back to the model)."""
    ins = parse_disasm(disasm_text)
    if not ins:
        return {"ok": False, "reason": "no disassembly"}

    _COP = {"AND": "&", "OR": "|", "XOR": "^", "SHL": "<<", "SHR": ">>"}
    param_loaded = False
    derefs = []          # list of (offset, sign_class, width) -- pointer walks; last is the read
    guards = []          # indices into `derefs` (or -1 for the param itself) null-guarded
    post_ops = []        # (c_operator, imm) value transforms applied AFTER the last deref
    type_gates = []      # (chain_depth, off, imm, width) -- `CMP [chain+off],imm; Jcc->ret0`
    pending_guard_reg = None   # 'EAX' after a TEST EAX,EAX awaiting its conditional
    pending_cmp_gate = None    # (off, imm, width) after a CMP [EAX+off],imm awaiting its Jcc
    ret_imm = None
    default_ret = 0            # value returned on the guard-fail path (0 via XOR EAX,EAX,
                               # or a nonzero `MOV EAX,imm` -- e.g. GetItemQuality `return 2`)

    for _addr, mn, ops in ins:
        if mn == "PUSH":
            continue                     # abort-block arg / return addr
        if mn == "CALL":
            m = re.match(r"^(0x[0-9a-fA-F]+)$", ops.strip())
            tgt = int(m.group(1), 16) if m else None
            if tgt in ABORT_HELPERS:
                continue                 # abort idiom -- guarded, never taken
            return {"ok": False, "reason": f"calls non-abort subroutine {ops.strip()}"}
        if mn == "JMP":
            continue                     # into the abort / null-return block; harmless
        if mn.startswith("RET"):
            m = re.match(r"^(0x[0-9a-fA-F]+|\d+)$", ops.strip()) if ops.strip() else None
            ret_imm = int(m.group(1), 0) if m else 0
            continue                     # multiple RETs (null path + value path) are fine
        if mn == "TEST":
            regs = _regs_in(ops)
            if regs == {"EAX"}:
                pending_guard_reg = "EAX"
                continue
            return {"ok": False, "reason": f"TEST on {regs} (not the EAX chain)"}
        if mn[0] == "J" and mn != "JMP":
            # A conditional AFTER a `TEST EAX,EAX` is a NULL-GUARD on the current
            # pointer, whichever sense (JNZ skips the abort; JZ jumps to a return-0).
            if pending_guard_reg == "EAX":
                guards.append(len(derefs) - 1)
                pending_guard_reg = None
                continue
            # A conditional AFTER a `CMP [chain+off],imm` is a TYPE-GATE: the getter
            # returns the default (0) unless the field equals the immediate (the
            # ubiquitous `if (pUnit->dwType != 4) return 0;` item-getter guard). The
            # gate lands on the CURRENT chain pointer (len(derefs) walks applied).
            if pending_cmp_gate is not None:
                goff, gimm, gw = pending_cmp_gate
                type_gates.append((len(derefs), goff, gimm, gw))
                pending_cmp_gate = None
                continue
            return {"ok": False, "reason": f"conditional {mn} not a null-guard/type-gate"}
        if mn == "CMP":
            # Only a `CMP <mem on the EAX chain>, imm` is a translatable type-gate;
            # a register/global compare (bound check, computed branch) still bails.
            parts = ops.split(",", 1)
            if len(parts) == 2:
                lhs, rhs = parts[0].strip(), parts[1].strip()
                mm = _MEM_OFF_RE.search(lhs)
                if _IMM_RE.match(rhs) and mm and mm.group(1).upper() == "EAX":
                    goff = int(mm.group(2), 0) if mm.group(2) else 0
                    lsl = lhs.lower()
                    gw = "d" if "dword" in lsl else ("w" if "word" in lsl
                                                     else ("b" if "byte" in lsl else "d"))
                    pending_cmp_gate = (goff, int(rhs, 0), gw)
                    continue
            return {"ok": False, "reason": "CMP not a [EAX+off],imm type-gate -- computed branch"}
        if mn in ("ADD", "SUB"):
            # `ADD/SUB ESP, imm` = stack cleanup (harmless); on a data reg = computed.
            if ops.split(",", 1)[0].strip().upper() == "ESP":
                continue
            return {"ok": False, "reason": f"arithmetic {mn} on data reg -- computed getter"}
        if mn in _COP:
            parts = ops.split(",", 1)
            dst = parts[0].strip().upper()
            src = parts[1].strip() if len(parts) == 2 else ""
            # a sub-register (AX/AL) write is still the EAX accumulator (low bits).
            if _SUBREG.get(dst) != "EAX":
                return {"ok": False, "reason": f"{mn} writes {dst}, not the EAX chain"}
            if mn == "XOR" and _SUBREG.get(src.upper()) == "EAX":
                continue                 # `XOR EAX,EAX` / `XOR AX,AX` = return-0 idiom (null path)
            if _IMM_RE.match(src):       # AND/OR/XOR/SHL/SHR EAX, imm -> a value transform
                post_ops.append((_COP[mn], int(src, 0)))
                continue
            return {"ok": False, "reason": f"{mn} EAX,{src} -- non-immediate transform"}
        if mn in ("IMUL", "MUL", "LEA", "SAR", "ROL", "ROR", "NOT", "NEG"):
            return {"ok": False, "reason": f"arithmetic {mn} -- computed getter, needs the model"}
        if mn in ("MOV", "MOVSX", "MOVZX"):
            parts = ops.split(",", 1)
            if len(parts) != 2:
                return {"ok": False, "reason": f"unparsed MOV operands: {ops}"}
            dst, src = parts[0].strip().upper(), parts[1].strip()
            # MOVSX/MOVZX target EAX directly; a plain `MOV AX/AL,..` writes the low
            # bits of the EAX accumulator -- both are the return-value chain. The read
            # WIDTH comes from the operand (`byte/word ptr`), captured below.
            if _SUBREG.get(dst) != "EAX":
                return {"ok": False, "reason": f"writes {dst}, not the EAX chain"}
            esp = _ESP_READ_RE.search(src)
            if esp:
                off = int(esp.group(1), 0) if esp.group(1) else 0
                if off != 4 or param_loaded:
                    return {"ok": False, "reason": f"non-arg-0 stack read [ESP+{off}]"}
                param_loaded = True
                continue
            mm = _MEM_OFF_RE.search(src)
            if mm:
                if post_ops:
                    return {"ok": False, "reason": "deref AFTER a transform -- computed address"}
                base = mm.group(1).upper()
                if base != "EAX":
                    return {"ok": False, "reason": f"deref base {base}, not the EAX chain"}
                off = int(mm.group(2), 0) if mm.group(2) else 0
                sl = src.lower()
                width = ("d" if "dword" in sl else "w" if "word" in sl
                         else "b" if "byte" in sl else None)
                derefs.append((off, {"MOVSX": "sx", "MOVZX": "zx"}.get(mn, "mov"), width))
                continue
            # `MOV EAX, <immediate>` = the guard-fail DEFAULT return value (the non-zero
            # analogue of `XOR EAX,EAX`; e.g. GetItemQuality's `MOV EAX,0x2` -> return 2).
            if mn == "MOV" and _IMM_RE.match(src):
                default_ret = int(src, 0)
                continue
            return {"ok": False, "reason": f"MOV from non-memory {src} -- not a deref chain"}
        return {"ok": False, "reason": f"unhandled instruction {mn} {ops}"}

    if not param_loaded or not derefs:
        return {"ok": False, "reason": "not a [ESP+4] pointer-deref getter"}

    # width/sign of the FINAL read decides the return type -- UNLESS a trailing
    # transform is present (a mask/shift yields a full-width int, not a byte). The
    # width is READ from the memory operand (`byte/word/dword ptr`) so a plain
    # `MOV AX, word ptr [..]` correctly yields u16 -- CRITICAL: the oracle's RetMask
    # compares only the low <width> bits, so a byte/word read must declare u8/u16 or
    # the stale upper EAX bits (the high half of the intermediate pointer) get
    # compared and a bit-exact reimpl falsely mismatches (the ITEMS word-getter bug).
    final_off, final_sign, final_width = derefs[-1]
    if post_ops:
        eff_ret = ret if ret in ("u32", "i32") else "u32"
    elif final_width == "b":
        eff_ret = "i8" if final_sign == "sx" else "u8"
    elif final_width == "w":
        eff_ret = "i16" if final_sign == "sx" else "u16"
    elif final_width == "d":
        eff_ret = "i32" if (final_sign == "sx" or ret == "i32") else "u32"
    elif final_sign == "zx":            # width unknown: fall back to the sign class
        eff_ret = "u8" if "byte" in disasm_text.lower() else "u16"
    elif final_sign == "sx":
        eff_ret = "i8" if "byte" in disasm_text.lower() else "i16"
    else:
        eff_ret = ret if ret in ("u32", "i32", "void") else "u32"
    ret_c = _ret_c_type(eff_ret)

    _GATE_CT = {"b": "unsigned char", "w": "unsigned short", "d": "unsigned int"}

    _dflt = f"0x{default_ret:x}" if default_ret else "0"

    def _gates_at(depth):               # type-gate guards on the pointer at this depth
        return [f"    if (*({_GATE_CT.get(gw, 'unsigned int')}*)(r + 0x{go:x}) != 0x{gi:x}u)"
                f" return {_dflt};   // type-gate"
                for (dd, go, gi, gw) in type_gates if dd == depth]

    lines = ['#include "../provider_runtime.h"', "",
             f"// D2MOO_REIMPL_EXPORT: {name}",
             "// [abi_static] MECHANICALLY TRANSLATED from disassembly (no model): "
             "pure pointer-deref getter"
             + (" with type-gate(s)." if type_gates else ".")
             + (f"  (guard-fail default = {_dflt})" if default_ret else ""),
             f'extern "C" {ret_c} __stdcall {name}(void* p)', "{",
             f"    if (p == nullptr) return {_dflt};",
             "    char* r = (char*)p;"]
    lines += _gates_at(0)               # gate(s) on the param pointer itself
    for i, (off, _s, _w) in enumerate(derefs[:-1]):
        lines.append(f"    r = *(char**)(r + 0x{off:x});")
        if i in guards:
            lines.append(f"    if (r == nullptr) return {_dflt};")
        lines += _gates_at(i + 1)       # gate(s) on this chain pointer
    expr = f"*({_ret_c_type('u32') if post_ops else ret_c}*)(r + 0x{final_off:x})"
    for op, imm in post_ops:            # apply transforms left-to-right: ((v >> 8) & 1)
        expr = f"({expr} {op} 0x{imm:x}u)"
    lines.append(f"    return {expr};")
    lines.append("}")
    return {"ok": True, "code": "\n".join(lines) + "\n", "ret": eff_ret,
            "chain": [off for off, _s, _w in derefs], "ret_imm": ret_imm,
            "post_ops": post_ops, "type_gates": type_gates,
            "reason": f"linear getter: param -> {len(derefs)} deref(s)"
                      + (f", {len(type_gates)} type-gate(s)" if type_gates else "")
                      + (f" + {len(post_ops)} transform(s)" if post_ops else "")}


_RESOLVE_REV = None
_RESOLVE_GEN = (r"C:\Users\benam\source\cpp\D2MOO\D2.Detours.patches\1.13c"
                r"\D2Common_ResolveTable.gen.h")


def resolve_reverse_map(path: str = None) -> dict:
    """address(int) -> verified name, parsed from D2Common_ResolveTable.gen.h. A
    delegate reimpl resolves its callee BY NAME (D2MOO_Resolve), so the CALL target
    address from the disasm must map to a name the resolver knows. Cached."""
    global _RESOLVE_REV
    if _RESOLVE_REV is not None and path is None:
        return _RESOLVE_REV
    p = path or _RESOLVE_GEN
    rev = {}
    try:
        text = open(p, encoding="utf-8").read()
        for m in re.finditer(r'\{\s*"([^"]+)",\s*0x([0-9a-fA-F]+)u\s*\}', text):
            rev[int(m.group(2), 16)] = m.group(1)
    except OSError:
        pass
    if path is None:
        _RESOLVE_REV = rev
    return rev


def resolvable_callees(disasm_text: str, resolve_rev: dict = None) -> list:
    """Every `CALL 0x...` target in the disasm that maps to a RESOLVABLE D2Common name
    (excluding the abort helpers). Returns [(addr, name), ...], de-duplicated in order.
    Used to HINT the model: a reimpl must reach a game function via D2MOO_Resolve(name),
    never a direct call (unresolved symbol -> the whole provider build fails)."""
    rev = resolve_rev if resolve_rev is not None else resolve_reverse_map()
    out, seen = [], set()
    for _addr, mn, ops in parse_disasm(disasm_text):
        if mn != "CALL":
            continue
        m = re.match(r"^(0x[0-9a-fA-F]+)$", ops.strip())
        if not m:
            continue
        tgt = int(m.group(1), 16)
        if tgt in ABORT_HELPERS or tgt in seen:
            continue
        nm = rev.get(tgt)
        if nm:
            out.append((tgt, nm))
            seen.add(tgt)
    return out


def callthrough_prompt_block(callees: list) -> str:
    """A prompt fragment telling the model to resolve+call-through the given callees
    (list of (addr, name)) instead of calling them directly. Empty if no callees."""
    if not callees:
        return ""
    names = ", ".join(n for _a, n in callees)
    ex = callees[0][1]
    return (
        "\n\n## CALL-THROUGH REQUIRED -- this function CALLS other D2Common function(s): "
        f"{names}.\n"
        "The provider is a standalone DLL and CANNOT link those symbols -- calling one "
        "DIRECTLY is an unresolved external that FAILS THE WHOLE BUILD. Resolve each BY "
        "NAME via the injected resolver and call through a function pointer:\n"
        "```cpp\n"
        f'    typedef void* (__stdcall *{ex}_t)(unsigned int);   // match the callee ABI from the disasm\n'
        f'    {ex}_t _f = ({ex}_t)D2MOO_Resolve("{ex}");\n'
        "    if (_f == nullptr) return /*fallback*/ 0;\n"
        "    void* _r = _f(arg);\n"
        "```\n"
        "Use the EXACT verified name(s) above. Derive each callee's calling convention / "
        "arg count from the disasm (PUSH count, RET n, or ECX/EDX for __fastcall). "
        "D2MOO_Resolve is declared in provider_runtime.h (already included).")


def resolvable_globals(disasm_text: str, resolve_rev: dict = None) -> list:
    """Every absolute `[0x...]` data-global deref in the disasm that maps to a resolvable
    name. Returns [(addr, name), ...]. Hints the model to resolve game globals via
    D2MOO_Resolve (a direct extern reference = unresolved external = whole-build fail)."""
    rev = resolve_rev if resolve_rev is not None else resolve_reverse_map()
    out, seen = [], set()
    for _addr, _mn, ops in parse_disasm(disasm_text):
        for m in _ABS_MEM_RE.finditer(ops):
            a = int(m.group(1), 16)
            if a in rev and a not in seen:
                out.append((a, rev[a]))
                seen.add(a)
        # array-base globals addressed as a base+index displacement `[reg + 0x<global>]`
        # (e.g. `MOV AL,[EAX + 0x6fdef0a8]`) -- same image-range rule as derive_abi.
        # Without this the model is never told the wired name and invents one -> the
        # provider's D2MOO_Resolve(<invented>) returns null and the prove mismatches.
        for m in _DISP_GLOBAL_RE.finditer(ops):
            a = int(m.group(1), 16)
            if a >= _IMAGE_MIN and a in rev and a not in seen:
                out.append((a, rev[a]))
                seen.add(a)
    return out


def global_resolve_prompt_block(globals_: list) -> str:
    """Prompt fragment: resolve the given game globals (list of (addr, name)) via
    D2MOO_Resolve. Empty if none."""
    if not globals_:
        return ""
    names = ", ".join(n for _a, n in globals_)
    ex = globals_[0][1]
    return (
        f"\n\n## GLOBAL RESOLVE REQUIRED -- this function reads game global(s): {names}.\n"
        "The provider is a standalone DLL and CANNOT link game globals -- referencing one "
        "as an `extern` symbol is an unresolved external that FAILS THE WHOLE BUILD. "
        "Resolve each BY NAME; D2MOO_Resolve returns the ADDRESS OF THE VARIABLE:\n"
        "```cpp\n"
        f'    void* _g = D2MOO_Resolve("{ex}");   // address of the variable\n'
        "    if (_g == nullptr) return 0;\n"
        f'    // a `g_p*` POINTER variable holds a table base -> deref once:\n'
        f'    char* base = (char*)*(void**)_g;\n'
        "```\n"
        "Use the EXACT verified name(s) above. A `g_p<X>` name is a POINTER variable (the "
        "disasm does `MOV reg,[global]` then derefs reg) -- resolve, then deref once. "
        "D2MOO_Resolve is declared in provider_runtime.h (already included).\n"
        "CRITICAL -- read every field via a RAW OFFSET CAST from the disasm, e.g. "
        "`*(unsigned char*)(base + idx*STRIDE + 0xNN)`. Do NOT use Ghidra decompiler struct "
        "TYPE names (`ItemTypeDataEntry*`, `->bField10`, `undefined4`, ...) -- they are "
        "decompiler fictions NOT defined in the provider translation unit, so they FAIL "
        "THE BUILD. Only fixed-width casts (`unsigned char/short/int`) + numeric offsets.")


def translate_delegate_getter_to_c(name: str, disasm_text: str, *, callconv: str = "stdcall",
                                   ret: str = "u32", resolve_rev: dict = None) -> dict:
    """A DELEGATE getter -- `param -> [guards] -> load arg field -> CALL a resolvable
    D2Common function -> [null guard] -> read a field off the result -> [substitute] ->
    return` -- translated to a CALL-THROUGH reimpl that resolves the callee BY NAME
    (D2MOO_Resolve) and calls the REAL game function. Because it calls through, the
    callee's own data-globals are the game's real globals -- no global wiring needed.

    Handles the consistent ITEMS_GetItemRecord* family (Variant A): fallback-constant
    guards (`return 0x64`), one call to a resolvable stdcall(1) callee, a sub-dword
    result read (width from the operand -> correct RetMask), and an optional
    `CMP v,imm; Jcc` value-substitute (`return (v==imm) ? fallback : v`).

    BAILS (ok=False, caller falls back to the model) on: ABORT-class guards (CALL to an
    abort helper -- that's a handle-abort-hazard, not a fallback); 0 or >1 CALL; a callee
    not in the resolve table; an ECX/EDX base; >1 arg pushed; or any shape it can't map."""
    rev = resolve_rev if resolve_rev is not None else resolve_reverse_map()
    ins = parse_disasm(disasm_text)
    if not ins:
        return {"ok": False, "reason": "no disassembly"}

    param_loaded = False
    called = None            # (name) of the resolved callee once CALL is seen
    n_calls = 0
    n_push = 0
    arg_off = None           # offset of the field loaded as the callee arg
    type_gates = []          # (off, imm, w) pre-call field gates (dwType==imm)
    result_off = None        # offset of the field read off the call result
    result_sign = "mov"
    result_width = None
    subst = None             # (imm) from a post-read `CMP v,imm; Jcc`
    fallback = 0             # the guard/fallback return constant
    ret_imm = None
    pending_cmp = None       # (kind, off, imm, w): 'gate' pre-call or 'subst' post-read

    for _addr, mn, ops in ins:
        if mn == "PUSH":
            n_push += 1
            continue
        if mn == "JMP" or (mn[0] == "J" and mn != "JMP" and pending_cmp is None):
            # bare conditional after a TEST null-guard (or JMP into fallback) -- harmless
            continue
        if mn.startswith("RET"):
            m = re.match(r"^(0x[0-9a-fA-F]+|\d+)$", ops.strip()) if ops.strip() else None
            ret_imm = int(m.group(1), 0) if m else 0
            continue
        if mn == "TEST":
            continue                     # null-guard sentinel (either side of the call)
        if mn == "CMP":
            parts = ops.split(",", 1)
            if len(parts) != 2:
                return {"ok": False, "reason": f"unparsed CMP {ops}"}
            lhs, rhs = parts[0].strip(), parts[1].strip()
            if not _IMM_RE.match(rhs):
                return {"ok": False, "reason": f"CMP against non-imm {rhs}"}
            mm = _MEM_OFF_RE.search(lhs)
            if mm and mm.group(1).upper() == "EAX" and not called:
                lsl = lhs.lower()
                gw = "d" if "dword" in lsl else "w" if "word" in lsl else "b" if "byte" in lsl else "d"
                pending_cmp = ("gate", int(mm.group(2), 0) if mm.group(2) else 0, int(rhs, 0), gw)
                continue
            if _SUBREG.get(lhs.upper()) == "EAX" and called and result_off is not None:
                pending_cmp = ("subst", None, int(rhs, 0), None)
                continue
            return {"ok": False, "reason": f"CMP shape not a gate/substitute: {ops}"}
        if mn[0] == "J" and mn != "JMP":
            if pending_cmp and pending_cmp[0] == "gate":
                type_gates.append((pending_cmp[1], pending_cmp[2], pending_cmp[3]))
            elif pending_cmp and pending_cmp[0] == "subst":
                subst = pending_cmp[2]
            pending_cmp = None
            continue
        if mn == "CALL":
            m = re.match(r"^(0x[0-9a-fA-F]+)$", ops.strip())
            tgt = int(m.group(1), 16) if m else None
            if tgt in ABORT_HELPERS:
                return {"ok": False, "reason": "abort-class guard (CleanupAndAbort/_exit)"}
            nm = rev.get(tgt)
            if not nm:
                return {"ok": False, "reason": f"callee 0x{tgt:x} not in resolve table"}
            n_calls += 1
            if n_calls > 1:
                return {"ok": False, "reason": "more than one CALL -- not a simple delegate"}
            called = nm
            continue
        if mn in ("MOV", "MOVSX", "MOVZX"):
            parts = ops.split(",", 1)
            if len(parts) != 2:
                return {"ok": False, "reason": f"unparsed MOV {ops}"}
            dst, src = parts[0].strip().upper(), parts[1].strip()
            esp = _ESP_READ_RE.search(src)
            if esp:
                off = int(esp.group(1), 0) if esp.group(1) else 0
                if off != 4 or _SUBREG.get(dst) != "EAX" or param_loaded:
                    return {"ok": False, "reason": f"unexpected stack read {ops}"}
                param_loaded = True
                continue
            mm = _MEM_OFF_RE.search(src)
            if mm:
                base = mm.group(1).upper()
                if base != "EAX":
                    return {"ok": False, "reason": f"deref base {base}, not EAX chain"}
                off = int(mm.group(2), 0) if mm.group(2) else 0
                if not called:
                    if arg_off is not None:
                        return {"ok": False, "reason": "more than one pre-call arg load"}
                    arg_off = off               # the field passed to the callee
                else:
                    result_off = off            # LAST post-call read = the returned field
                    result_sign = {"MOVSX": "sx", "MOVZX": "zx"}.get(mn, "mov")
                    sl = src.lower()
                    result_width = ("d" if "dword" in sl else "w" if "word" in sl
                                    else "b" if "byte" in sl else None)
                continue
            # MOV reg, imm  (fallback constant on the guard path) or reg,reg (shuffle)
            if _IMM_RE.match(src) and _SUBREG.get(dst) == "EAX":
                fallback = int(src, 0)
                continue
            if _SUBREG.get(src.upper()) == "EAX" and _SUBREG.get(dst) == "EAX":
                continue                        # EAX<->sub shuffle (e.g. MOV EAX,ECX post-read)
            return {"ok": False, "reason": f"MOV shape unhandled: {ops}"}
        if mn in ("ADD", "SUB") and ops.split(",", 1)[0].strip().upper() == "ESP":
            continue                            # cdecl-arg cleanup after a foreign call
        if mn == "XOR":
            parts = ops.split(",", 1)
            if (len(parts) == 2 and _SUBREG.get(parts[0].strip().upper()) == "EAX"
                    and _SUBREG.get(parts[1].strip().upper()) == "EAX"):
                fallback = 0                    # `XOR EAX,EAX` / `XOR AL,AL` = return-0 fallback
                continue
            return {"ok": False, "reason": f"XOR shape unhandled: {ops}"}
        return {"ok": False, "reason": f"unhandled instruction {mn} {ops}"}

    if not (param_loaded and called and arg_off is not None and result_off is not None):
        return {"ok": False, "reason": "not a param->load->CALL->read delegate"}

    signed = (result_sign == "sx")
    if result_width == "b":
        eff_ret = "i8" if signed else "u8"
    elif result_width == "w":
        eff_ret = "i16" if signed else "u16"
    elif result_width == "d":
        eff_ret = "i32" if signed else "u32"
    else:
        eff_ret = ret if ret in ("u32", "i32") else "u32"
    ret_c = _ret_c_type(eff_ret)
    read_c = _ret_c_type(eff_ret)
    fb = f"0x{fallback:x}"

    lines = ['#include "../provider_runtime.h"', "",
             f"// D2MOO_REIMPL_EXPORT: {name}",
             f"// [abi_static] DELEGATE call-through (no model): resolves + calls {called}.",
             f'typedef void* (__stdcall *_callee_t)(unsigned int);',
             f'extern "C" {ret_c} __stdcall {name}(void* p)', "{",
             f"    if (p == nullptr) return {fb};",
             "    char* r = (char*)p;"]
    for (goff, gimm, gw) in type_gates:
        gt = {"b": "unsigned char", "w": "unsigned short", "d": "unsigned int"}.get(gw, "unsigned int")
        lines.append(f"    if (*({gt}*)(r + 0x{goff:x}) != 0x{gimm:x}u) return {fb};")
    lines += [
        f"    unsigned int _arg = *(unsigned int*)(r + 0x{arg_off:x});",
        f'    _callee_t _f = (_callee_t)D2MOO_Resolve("{called}");',
        f"    if (_f == nullptr) return {fb};",
        "    char* _rec = (char*)_f(_arg);",
        f"    if (_rec == nullptr) return {fb};",
        f"    {read_c} _v = *({read_c}*)(_rec + 0x{result_off:x});"]
    if subst is not None:
        lines.append(f"    return (_v == 0x{subst:x}) ? ({ret_c}){fb} : _v;")
    else:
        lines.append("    return _v;")
    lines.append("}")
    return {"ok": True, "code": "\n".join(lines) + "\n", "ret": eff_ret,
            "callee": called, "arg_off": arg_off, "result_off": result_off,
            "type_gates": type_gates, "fallback": fallback, "subst": subst,
            "ret_imm": ret_imm,
            "reason": f"delegate: param -> field 0x{arg_off:x} -> {called}() "
                      f"-> read 0x{result_off:x}" + (f" (subst {subst})" if subst is not None else "")}


def translate_global_table_getter_to_c(name: str, disasm_text: str, *,
                                       callconv: str = "stdcall", ret: str = "u32",
                                       resolve_rev: dict = None) -> dict:
    """A GLOBAL-TABLE INDEXED getter -- the dominant DATATBLS shape:
        idx = arg; if (idx < 0 || idx >= (*g_table)->count) return FB;
        rec = (*g_table)->records + idx*STRIDE; return rec->field;
    disasm idiom (regs may vary):
        MOV EAX,[ESP+4]              ; idx
        TEST EAX,EAX; JL  fb         ; idx < 0
        MOV  Cx,[0x<global>]         ; base = *(void**)g   (the table pointer's value)
        CMP  EAX,[Cx+<countOff>]; JGE fb
        MOV  Dx,[Cx+<recOff>]        ; records = *(void**)(base+recOff)
        IMUL EAX,EAX,<stride>
        ADD  EAX,Dx                  ; rec = records + idx*stride
        TEST EAX,EAX; JZ  fb
        MOV/MOVSX/MOVZX EAX,<w>[EAX+<fieldOff>]
        RET n ; fb: XOR EAX,EAX / MOV EAX,imm; RET n
    Emits a reimpl that resolves the global BY NAME (D2MOO_Resolve) and reads via RAW
    casts -- deterministic, no model (the model oscillates on the resolve-deref chain).
    The offsets/stride/width/global are all in the disasm. BAILS on any deviation."""
    rev = resolve_rev if resolve_rev is not None else resolve_reverse_map()
    ins = parse_disasm(disasm_text)
    if not ins:
        return {"ok": False, "reason": "no disassembly"}

    role = {}                # reg -> 'idx' | 'base' | 'records' | 'offset' | 'rec'
    param_loaded = False
    global_name = None
    count_off = records_off = stride = field_off = None
    field_sign = "mov"
    field_width = None
    fallback = 0
    ret_imm = None

    def _memparts(operand):
        m = _MEM_OFF_RE.search(operand)
        if not m:
            return None, None
        return m.group(1).upper(), (int(m.group(2), 0) if m.group(2) else 0)

    for _addr, mn, ops in ins:
        if mn in ("TEST", "PUSH"):
            continue
        if mn == "JMP" or (mn[0] == "J" and mn != "JMP"):
            continue                 # guards (idx<0 / idx>=count / rec==0) -> emitted below
        if mn.startswith("RET"):
            m = re.match(r"^(0x[0-9a-fA-F]+|\d+)$", ops.strip()) if ops.strip() else None
            ret_imm = int(m.group(1), 0) if m else 0
            continue
        if mn == "CMP":
            # idx >= count : CMP <idxreg>,[<basereg>+countOff]
            parts = ops.split(",", 1)
            if len(parts) == 2 and role.get(parts[0].strip().upper()) == "idx":
                base, off = _memparts(parts[1])
                if base and role.get(base) == "base":
                    count_off = off
                    continue
            return {"ok": False, "reason": f"CMP not the bound check: {ops}"}
        if mn == "IMUL":
            # IMUL EAX,EAX,imm  -> idx*stride
            p = [x.strip().upper() for x in ops.split(",")]
            if len(p) == 3 and role.get(p[0]) == "idx" and p[1] == p[0] and _IMM_RE.match(p[2].lower()):
                stride = int(p[2], 0)
                role[p[0]] = "offset"
                continue
            return {"ok": False, "reason": f"IMUL not idx*stride: {ops}"}
        if mn == "ADD":
            p = [x.strip().upper() for x in ops.split(",")]
            if p[0] == "ESP":
                continue
            if len(p) == 2 and role.get(p[0]) == "offset" and role.get(p[1]) == "records":
                role[p[0]] = "rec"
                continue
            return {"ok": False, "reason": f"ADD not offset+records: {ops}"}
        if mn == "XOR":
            p = [x.strip().upper() for x in ops.split(",")]
            if len(p) == 2 and _SUBREG.get(p[0]) == _SUBREG.get(p[1]):
                fallback = 0
                continue
            return {"ok": False, "reason": f"XOR unhandled: {ops}"}
        if mn in ("MOV", "MOVSX", "MOVZX"):
            parts = ops.split(",", 1)
            if len(parts) != 2:
                return {"ok": False, "reason": f"unparsed MOV {ops}"}
            dst, src = parts[0].strip().upper(), parts[1].strip()
            dparent = _SUBREG.get(dst)
            esp = _ESP_READ_RE.search(src)
            if esp:                                   # MOV EAX,[ESP+4] -> idx param
                off = int(esp.group(1), 0) if esp.group(1) else 0
                if off != 4 or param_loaded or dparent != "EAX":
                    return {"ok": False, "reason": f"unexpected stack read {ops}"}
                param_loaded = True
                role["EAX"] = "idx"
                continue
            am = _ABS_MEM_RE.search(src)
            if am:                                    # MOV reg,[0x<global>] -> base
                a = int(am.group(1), 16)
                nm = rev.get(a)
                if not nm or global_name:
                    return {"ok": False, "reason": f"global 0x{a:x} not resolvable / 2nd global"}
                global_name = nm
                role[dst] = "base"
                continue
            base, off = _memparts(src)
            if base:
                if role.get(base) == "base" and mn == "MOV":     # records = base->recOff
                    records_off = off
                    role[dst] = "records"
                    continue
                if role.get(base) == "rec":                       # final field read off rec
                    field_off = off
                    field_sign = {"MOVSX": "sx", "MOVZX": "zx"}.get(mn, "mov")
                    sl = src.lower()
                    field_width = ("d" if "dword" in sl else "w" if "word" in sl
                                   else "b" if "byte" in sl else None)
                    role[dst] = "result"
                    continue
                return {"ok": False, "reason": f"deref base role {role.get(base)}: {ops}"}
            if _IMM_RE.match(src) and dparent == "EAX":           # MOV EAX,imm fallback const
                fallback = int(src, 0)
                continue
            return {"ok": False, "reason": f"MOV shape unhandled: {ops}"}
        return {"ok": False, "reason": f"unhandled instruction {mn} {ops}"}

    if not (param_loaded and global_name and count_off is not None
            and records_off is not None and stride is not None and field_off is not None):
        return {"ok": False, "reason": "not a global-table indexed getter "
                f"(g={global_name} count={count_off} rec={records_off} stride={stride} field={field_off})"}

    # The original ends `MOV{ZX|SX} EAX, <w>[rec+off]` -- it returns the FULL EAX,
    # zero-/sign-EXTENDED to 32 bits. So the return type is the EXTENDED width (u32 for
    # MOVZX, i32 for MOVSX), NOT the sub-dword read type -- else a `unsigned char` return
    # leaves the upper EAX bits undefined and diverges from the original's clean MOVZX
    # under a 32-bit RetMask. Read at the native width, then cast to the 32-bit result.
    signed = (field_sign == "sx")
    read_c = {"b": ("signed char" if signed else "unsigned char"),
              "w": ("short" if signed else "unsigned short"),
              "d": ("int" if signed else "unsigned int")}.get(field_width, "unsigned int")
    if field_sign == "zx":
        eff_ret = "u32"
    elif field_sign == "sx":
        eff_ret = "i32"
    elif field_width == "d":
        eff_ret = "u32"
    else:                       # plain MOV sub-register read (rare) -> mask by width
        eff_ret = {"b": "u8", "w": "u16"}.get(field_width, "u32")
    ret_c = _ret_c_type(eff_ret)
    fb = f"0x{fallback:x}"

    lines = ['#include "../provider_runtime.h"', "",
             f"// D2MOO_REIMPL_EXPORT: {name}",
             f"// [abi_static] GLOBAL-TABLE getter (no model): {global_name}"
             f"->records[idx*0x{stride:x}] + 0x{field_off:x}.",
             f'extern "C" {ret_c} __stdcall {name}(int idx)', "{",
             f"    if (idx < 0) return {fb};",
             f'    void* _g = D2MOO_Resolve("{global_name}");',
             f"    if (_g == nullptr) return {fb};",
             "    char* base = (char*)*(void**)_g;",
             f"    if (base == nullptr) return {fb};",
             f"    if (idx >= *(int*)(base + 0x{count_off:x})) return {fb};",
             f"    char* records = (char*)*(void**)(base + 0x{records_off:x});",
             f"    char* rec = records + (int)idx * 0x{stride:x};",
             f"    if (rec == nullptr) return {fb};",
             f"    return ({ret_c})*({read_c}*)(rec + 0x{field_off:x});",
             "}"]
    return {"ok": True, "code": "\n".join(lines) + "\n", "ret": eff_ret,
            "global": global_name, "count_off": count_off, "records_off": records_off,
            "stride": stride, "field_off": field_off, "fallback": fallback, "ret_imm": ret_imm,
            "reason": f"global-table getter: {global_name}->records[idx*0x{stride:x}] "
                      f"+ 0x{field_off:x} ({eff_ret})"}


def apply_static_abi(layout: dict, input_sets: list, abi: dict) -> tuple:
    """Override a model-drafted register param_layout (the fun-doc 'inputs/outputs'
    shape) with statically derived facts. Returns (layout, input_sets, notes).
    - stdcall + N slots: every input forced to register 'stack'; missing unused
      slots are PADDED with zero-valued params so the marshal pushes all N.
    Only corrects what the disasm states; register_explicit layouts pass through."""
    notes: list = []
    if not abi or abi.get("slots") is None or not isinstance(layout, dict):
        return layout, input_sets, notes
    inputs = layout.get("inputs")
    if not isinstance(inputs, list):
        return layout, input_sets, notes

    if abi["callconv"] == "stdcall":
        for i in inputs:
            reg = str(i.get("register", "")).upper()
            if reg not in ("", "STACK", "STK"):
                notes.append(f"forced input '{i.get('name')}' register {reg} -> stack "
                             f"(disasm: RET 0x{abi['ret_imm']:x}, no register reads)")
                i["register"] = "stack"
        n = abi["slots"]
        if len(inputs) < n:
            for k in range(len(inputs), n):
                pad = f"unused{k + 1}"
                inputs.append({"name": pad, "register": "stack", "signed": True})
                for s in (input_sets or []):
                    s.setdefault(pad, 0)
            notes.append(f"padded {n - len(inputs) + (n - n)} -> declared {n} slots "
                         f"(RET 0x{abi['ret_imm']:x}; model declared fewer)")
        elif len(inputs) > n:
            notes.append(f"model declared {len(inputs)} inputs but callee cleans only "
                         f"{n} slot(s) -- NOT trimmed (verify manually)")
    return layout, input_sets, notes


def clamp_abort_vectors(input_sets: list, max_index: int = 32) -> tuple:
    """For an ABORT-CLASS function: keep only vectors whose every value lies in
    [0, max_index); if none survive, synthesize a dense in-range sweep. The valid
    upper bound is a LIVE global we can't read statically, so this is deliberately
    conservative -- small indices into any populated game table are in-range."""
    safe = [s for s in (input_sets or [])
            if all(isinstance(v, int) and 0 <= v < max_index for v in s.values())]
    dropped = len(input_sets or []) - len(safe)
    if not safe:
        names = sorted({k for s in (input_sets or []) for k in s}) or ["value"]
        safe = [{n: i for n in names} for i in range(16)]
    return safe, dropped


# ---------------------------------------------------------------------------
# self-test: known-answer corpus captured live from D2Common 1.13c (2026-07-08)
# ---------------------------------------------------------------------------
_CORPUS = {
    # RET 0x4, 1 slot used, stdcall, 2 data globals, 3 helper calls (abort path)
    "GetItemDataRecord": """
6fdc19a0: MOV EAX,dword ptr [ESP + 0x4]
6fdc19a4: CMP EAX,dword ptr [0x6fdefb94]
6fdc19aa: JC 0x6fdc19b1
6fdc19ac: XOR EAX,EAX
6fdc19ae: RET 0x4
6fdc19b1: MOV ECX,dword ptr [0x6fdefb98]
6fdc19b7: TEST ECX,ECX
6fdc19b9: JNZ 0x6fdc19da
6fdc19bb: PUSH 0x1ef
6fdc19c0: CALL 0x6fd5921c
6fdc19c5: PUSH EAX
6fdc19c6: PUSH 0x6fdda728
6fdc19cb: CALL 0x6fd59216
6fdc19d0: ADD ESP,0xc
6fdc19d3: PUSH -0x1
6fdc19d5: CALL 0x6fd51b0d
6fdc19da: IMUL EAX,EAX,0x1a8
6fdc19e0: ADD EAX,ECX
6fdc19e2: RET 0x4
""",
    # RET 0xC, THREE slots, only slot 0 read -- the stack-corruption discovery
    "DATATBLS_GetItemDataByCode": """
6fd9e1d0: MOV EAX,dword ptr [ESP + 0x4]
6fd9e1d4: TEST EAX,EAX
6fd9e1d6: JNZ 0x6fd9e1db
6fd9e1d8: RET 0xc
6fd9e1db: MOV EAX,dword ptr [EAX]
6fd9e1dd: MOVSX EAX,word ptr [EAX]
6fd9e1e0: RET 0xc
""",
    # RET 0x4, 1 slot, stdcall, abort path via CALL/_exit, 2 data globals
    "GetAnimSequenceRecord": """
6fd8e980: MOV EAX,dword ptr [ESP + 0x4]
6fd8e984: CMP EAX,dword ptr [0x6fdf0b98]
6fd8e98a: JL 0x6fd8e993
6fd8e98c: PUSH 0xdd
6fd8e991: JMP 0x6fd8e99c
6fd8e993: TEST EAX,EAX
6fd8e995: JGE 0x6fd8e9b6
6fd8e997: PUSH 0xde
6fd8e99c: CALL 0x6fd5921c
6fd8e9a1: PUSH EAX
6fd8e9a2: PUSH 0x6fdda728
6fd8e9a7: CALL 0x6fd59216
6fd8e9ac: ADD ESP,0xc
6fd8e9af: PUSH -0x1
6fd8e9b1: CALL 0x6fd51b0d
6fd8e9b6: MOV ECX,dword ptr [0x6fdf0b94]
6fd8e9bc: IMUL EAX,EAX,0x1c0
6fd8e9c2: ADD EAX,ECX
6fd8e9c4: RET 0x4
""",
    # RET 0x8, 2 slots, slot 1 read AFTER a call (depth-reset heuristic), delegate
    "ITEMS_LookupItemRecordByCode": """
6fdc1960: MOV EAX,dword ptr [ESP + 0x4]
6fdc1964: MOV ECX,dword ptr [0x6fdeff6c]
6fdc196a: PUSH 0x0
6fdc196c: PUSH EAX
6fdc196d: PUSH ECX
6fdc196e: CALL 0x6fd59240
6fdc1973: TEST EAX,EAX
6fdc1975: JGE 0x6fdc1986
6fdc1977: MOV EDX,dword ptr [ESP + 0x8]
6fdc197b: MOV dword ptr [EDX],0x0
6fdc1981: XOR EAX,EAX
6fdc1983: RET 0x8
6fdc1986: MOV ECX,dword ptr [ESP + 0x8]
6fdc198a: MOV dword ptr [ECX],EAX
6fdc198c: IMUL EAX,EAX,0x1a8
6fdc1992: ADD EAX,dword ptr [0x6fdefb98]
6fdc1998: RET 0x8
""",
    # PURE GETTERS the translator should handle (deref chain + null guards, no branch):
    # STAT_GetActiveSkillFieldC: deref +0xa8, read +0xc (the re-drafted 2026-07-08 fn)
    "STAT_GetActiveSkillFieldC": """
6fd80420: MOV EAX,dword ptr [ESP + 0x4]
6fd80424: TEST EAX,EAX
6fd80426: JNZ 0x6fd8042f
6fd80428: PUSH 0x64a
6fd8042d: JMP 0x6fd8043e
6fd8042f: MOV EAX,dword ptr [EAX + 0xa8]
6fd80435: TEST EAX,EAX
6fd80437: JNZ 0x6fd80458
6fd80439: PUSH 0x40f
6fd8043e: CALL 0x6fd5921c
6fd80443: PUSH EAX
6fd80444: PUSH 0x6fdda728
6fd80449: CALL 0x6fd59216
6fd8044e: ADD ESP,0xc
6fd80451: PUSH -0x1
6fd80453: CALL 0x6fd51b0d
6fd80458: MOV EAX,dword ptr [EAX + 0xc]
6fd8045b: RET 0x4
""",
    # PATH_GetDirection: single MOVZX byte read at +0x65 -> ret u8 (CONCAT31 getter)
    "PATH_GetDirection": """
6fd84c00: MOV EAX,dword ptr [ESP + 0x4]
6fd84c04: MOVZX EAX,byte ptr [EAX + 0x65]
6fd84c08: RET 0x4
""",
    # PATH_GetDynamicX: single dword read at +0xc
    "PATH_GetDynamicX": """
6fd68210: MOV EAX,dword ptr [ESP + 0x4]
6fd68214: MOV EAX,dword ptr [EAX + 0xc]
6fd68217: RET 0x4
""",
}


def _selftest() -> int:
    a = derive_abi(_CORPUS["GetItemDataRecord"])
    assert a["ret_imm"] == 4 and a["slots"] == 1 and a["used_slots"] == [0], a
    assert a["callconv"] == "stdcall" and not a["reg_args"], a
    assert 0x6fdefb94 in a["data_globals"] and 0x6fdefb98 in a["data_globals"], a
    # its 3 calls are ALL the abort idiom -> zero real delegates
    assert not a["calls"] and len(a["abort_helper_calls"]) == 3, a

    a = derive_abi(_CORPUS["DATATBLS_GetItemDataByCode"])
    assert a["ret_imm"] == 0xC and a["slots"] == 3 and a["used_slots"] == [0], a
    assert a["callconv"] == "stdcall" and not a["calls"], a

    a = derive_abi(_CORPUS["GetAnimSequenceRecord"])
    assert a["ret_imm"] == 4 and a["slots"] == 1 and a["used_slots"] == [0], a
    assert a["callconv"] == "stdcall", a
    assert 0x6fdf0b94 in a["data_globals"] and 0x6fdf0b98 in a["data_globals"], a

    # array-base global as a base+index displacement: `MOV AL,[EAX + 0x6fdef0a8]`.
    # This is the batch-B planner gap -- DATATBLS_GetBodyLocPropertyByte reads a global
    # but was mis-tagged provable_now because the bare-`[0x..]` regex never saw it.
    a = derive_abi("6fd6a2a0: MOVZX EAX,byte ptr [ESP + 0x4]\n"
                   "6fd6a2a5: MOV AL,byte ptr [EAX + 0x6fdef0a8]\n"
                   "6fd6a2ab: RET 0x4\n")
    assert 0x6fdef0a8 in a["data_globals"], a
    assert a["ret_imm"] == 4 and a["slots"] == 1, a
    # ...but small struct-field offsets in the same operand form must NOT be caught:
    b = derive_abi("6fd87ded: MOV EAX,dword ptr [EAX + 0x5c]\n"
                   "6fd87df4: MOV EAX,dword ptr [EAX + 0x10]\n"
                   "6fd87df7: RET 0x4\n")
    assert b["data_globals"] == [], b

    a = derive_abi(_CORPUS["ITEMS_LookupItemRecordByCode"])
    assert a["ret_imm"] == 8 and a["slots"] == 2, a
    assert a["used_slots"] == [0, 1], a          # slot 1 read post-call (depth reset)
    assert 0x6fd59240 in a["calls"], a           # the Fog bsearch delegate
    assert a["approx"], a                        # crossed a call -> flagged heuristic

    assert detect_abort_path("/* WARNING: Subroutine does not return */ _exit(-1);")
    assert detect_abort_path("CleanupAndAbort();")
    assert not detect_abort_path("return (ITEMS_ItemRecord *)0x0;")

    # handle-abort hazard: the EXACT decompile that crashed a live batch (2026-07-08)
    stat_calc = """
uint STAT_GetUnitCalculatedStat(UnitAny *pUnit)
{
  if ((pUnit != (UnitAny *)0x0) && (pUnit->dwType == 0)) {
    return *(uint *)&pUnit->pPlayerData->field_0x2c;
  }
  GetReturnAddress();
  CleanupAndAbort();
  _exit(-1);
}
"""
    assert detect_handle_abort_hazard(stat_calc), "must catch the confirmed live-crash pattern"
    # a scalar (index-gated) abort is NOT a handle hazard -- no dwType comparison
    assert not detect_handle_abort_hazard(
        "int f(int idx) { if (idx < count) return arr[idx]; CleanupAndAbort(); _exit(-1); }")
    # a dwType READ with no abort is fine (e.g. GetPathFieldByUnitType dispatches on
    # type but returns different VALUES per branch -- it never aborts)
    assert not detect_handle_abort_hazard(
        "int f(UnitAny *p) { if (p->dwType == 2) return *(int*)(p+8); return *(int*)(p+4); }")

    lay = {"inputs": [{"name": "nSequenceId", "register": "ECX", "signed": True}],
           "outputs": [{"name": "ret", "register": "EAX", "signed": False}]}
    sets = [{"nSequenceId": 3}]
    abi3 = derive_abi(_CORPUS["DATATBLS_GetItemDataByCode"])
    lay2, sets2, notes = apply_static_abi(lay, sets, abi3)
    assert lay2["inputs"][0]["register"] == "stack", lay2
    assert len(lay2["inputs"]) == 3 and sets2[0].get("unused2") == 0, (lay2, sets2)

    safe, dropped = clamp_abort_vectors(
        [{"i": 0}, {"i": 5}, {"i": -1}, {"i": 2147483647}, {"i": 31}], 32)
    assert dropped == 2 and len(safe) == 3, (safe, dropped)
    safe, dropped = clamp_abort_vectors([{"i": -1}, {"i": 99999}], 32)
    assert dropped == 2 and len(safe) == 16, (len(safe), dropped)

    # --- mechanical getter translation ---
    # STAT: param -> deref +0xa8 (guarded) -> read +0xc. The exact bug that cost the
    # session -- the disasm translator gets it right where the model got it wrong.
    t = translate_getter_to_c("STAT_GetActiveSkillFieldC", _CORPUS["STAT_GetActiveSkillFieldC"])
    assert t["ok"] and t["chain"] == [0xa8, 0xc], t
    assert "*(char**)(r + 0xa8)" in t["code"] and "if (r == nullptr) return 0;" in t["code"], t["code"]
    assert "*(unsigned int*)(r + 0xc)" in t["code"], t["code"]

    # PATH_GetDirection: MOVZX byte -> u8 return, single read at +0x65
    t = translate_getter_to_c("PATH_GetDirection", _CORPUS["PATH_GetDirection"])
    assert t["ok"] and t["ret"] == "u8" and t["chain"] == [0x65], t
    assert "unsigned char" in t["code"] and "*(unsigned char*)(r + 0x65)" in t["code"], t["code"]

    # PATH_GetDynamicX: single dword read at +0xc
    t = translate_getter_to_c("PATH_GetDynamicX", _CORPUS["PATH_GetDynamicX"])
    assert t["ok"] and t["chain"] == [0xc] and t["ret"] == "u32", t

    # TRAILING BIT-MASK getters -- the class the translator used to over-defer.
    # STAT_GetStatListFlag4: read +0x34, AND 4 (real disasm, 2026-07-08)
    t = translate_getter_to_c("STAT_GetStatListFlag4", """
6fd8b220: MOV EAX,dword ptr [ESP + 0x4]
6fd8b224: MOV EAX,dword ptr [EAX + 0x34]
6fd8b227: AND EAX,0x4
6fd8b22a: RET 0x4
""")
    assert t["ok"] and t["chain"] == [0x34] and t["post_ops"] == [("&", 4)], t
    assert "(*(unsigned int*)(r + 0x34) & 0x4u)" in t["code"], t["code"]

    # STAT_IsUnitStatListFlag8Set: deref +0x5c (JZ-null-guard) -> read +0x10 -> >>8 &1,
    # with a XOR EAX,EAX return-0 idiom on the null path (real disasm)
    t = translate_getter_to_c("STAT_IsUnitStatListFlag8Set", """
6fd87de0: MOV EAX,dword ptr [ESP + 0x4]
6fd87de4: TEST EAX,EAX
6fd87de6: JNZ 0x6fd87ded
6fd87de8: XOR EAX,EAX
6fd87dea: RET 0x4
6fd87ded: MOV EAX,dword ptr [EAX + 0x5c]
6fd87df0: TEST EAX,EAX
6fd87df2: JZ 0x6fd87de8
6fd87df4: MOV EAX,dword ptr [EAX + 0x10]
6fd87df7: SHR EAX,0x8
6fd87dfa: AND EAX,0x1
6fd87dfd: RET 0x4
""")
    assert t["ok"] and t["chain"] == [0x5c, 0x10], t
    assert t["post_ops"] == [(">>", 8), ("&", 1)], t
    assert "*(char**)(r + 0x5c)" in t["code"] and "if (r == nullptr) return 0;" in t["code"], t["code"]
    assert "((*(unsigned int*)(r + 0x10) >> 0x8u) & 0x1u)" in t["code"], t["code"]

    # a deref AFTER a transform is a computed address -> must still DEFER
    t = translate_getter_to_c("Computed", """
6f000000: MOV EAX,dword ptr [ESP + 0x4]
6f000004: MOV EAX,dword ptr [EAX + 0x8]
6f000007: SHL EAX,0x2
6f00000a: MOV EAX,dword ptr [EAX + 0x10]
6f00000d: RET 0x4
""")
    assert not t["ok"] and "computed address" in t["reason"], t

    # BRANCHY / COMPUTED getters must DEFER to the model (ok=False):
    t = translate_getter_to_c("HaveLightResBonus", """
6fd7fe10: MOV EAX,dword ptr [ESP + 0x4]
6fd7fe37: MOV ECX,dword ptr [EAX]
6fd7fe39: CMP ECX,0x2
6fd7fe3c: JZ 0x6fd7fe5a
6fd7fe5a: MOV EAX,dword ptr [EAX + 0x2c]
6fd7fe5f: RET 0x4
""")
    assert not t["ok"], t                # type-dispatch branch -> defers to the model
    t = translate_getter_to_c("GetItemDataRecord", _CORPUS["GetItemDataRecord"])
    assert not t["ok"], t                # has IMUL + data-global reads -> not a pure getter

    # TYPE-GATED sub-dword getters (ITEMS family, real 1.13c disasm, 2026-07-08):
    # `CMP [pUnit],0x4; JNZ ret0` dwType gate + a sub-register `MOV AX/AL,word/byte ptr`
    # read. The whole ITEMS_GetItem* getter family bailed the translator (CMP + AX/AL
    # dst) -> went to the model, which declared the WRONG return WIDTH (u32 for a word
    # read) -> the oracle's RetMask compared the stale upper-EAX pointer bits -> false
    # mismatch. Both facts are 100% in the disasm: gate as guard, width from operand.
    t = translate_getter_to_c("ITEMS_GetItemDataField32", """
6fd739e0: MOV EAX,dword ptr [ESP + 0x4]
6fd739e4: TEST EAX,EAX
6fd739e6: JZ 0x6fd739fb
6fd739e8: CMP dword ptr [EAX],0x4
6fd739eb: JNZ 0x6fd739fb
6fd739ed: MOV EAX,dword ptr [EAX + 0x14]
6fd739f0: TEST EAX,EAX
6fd739f2: JZ 0x6fd739fb
6fd739f4: MOV AX,word ptr [EAX + 0x32]
6fd739f8: RET 0x4
6fd739fb: XOR AX,AX
6fd739fe: RET 0x4
""")
    assert t["ok"] and t["ret"] == "u16" and t["chain"] == [0x14, 0x32], t
    assert t["type_gates"] == [(0, 0, 4, "d")], t
    assert "!= 0x4u) return 0" in t["code"] and "unsigned short" in t["code"], t

    t = translate_getter_to_c("ITEMS_GetItemDataByte44", """
6fd73c50: MOV EAX,dword ptr [ESP + 0x4]
6fd73c54: TEST EAX,EAX
6fd73c56: JZ 0x6fd73c6a
6fd73c58: CMP dword ptr [EAX],0x4
6fd73c5b: JNZ 0x6fd73c6a
6fd73c5d: MOV EAX,dword ptr [EAX + 0x14]
6fd73c60: TEST EAX,EAX
6fd73c62: JZ 0x6fd73c6a
6fd73c64: MOV AL,byte ptr [EAX + 0x44]
6fd73c67: RET 0x4
6fd73c6a: XOR AL,AL
6fd73c6c: RET 0x4
""")
    assert t["ok"] and t["ret"] == "u8" and t["chain"] == [0x14, 0x44], t
    assert t["type_gates"] == [(0, 0, 4, "d")] and "unsigned char" in t["code"], t

    # DELEGATE call-through getter (ITEMS_GetItemRecord* Variant A, real 1.13c disasm,
    # 2026-07-08): param -> dwType gate -> load field4 -> CALL GetItemDataRecord ->
    # null-guard -> read u16 -> (v==1)?0x64:v. Emits a reimpl that resolves the callee
    # BY NAME and calls the REAL game function (its globals are the game's real globals).
    # LIVE-verified: the emitted code == the hand-written call-through that PROVEN 1/1.
    _rev = {0x6fdc19a0: "GetItemDataRecord"}
    t = translate_delegate_getter_to_c("ITEMS_GetItemRecordField108", """
6fd72970: MOV EAX,dword ptr [ESP + 0x4]
6fd72974: TEST EAX,EAX
6fd72976: JZ 0x6fd72997
6fd72978: CMP dword ptr [EAX],0x4
6fd7297b: JNZ 0x6fd72997
6fd7297d: MOV EAX,dword ptr [EAX + 0x4]
6fd72980: PUSH EAX
6fd72981: CALL 0x6fdc19a0
6fd72986: TEST EAX,EAX
6fd72988: JZ 0x6fd72997
6fd7298a: MOV AX,word ptr [EAX + 0x108]
6fd72991: CMP AX,0x1
6fd72995: JNZ 0x6fd7299b
6fd72997: MOV AX,0x64
6fd7299b: RET 0x4
""", resolve_rev=_rev)
    assert t["ok"] and t["ret"] == "u16" and t["callee"] == "GetItemDataRecord", t
    assert t["arg_off"] == 0x4 and t["result_off"] == 0x108 and t["subst"] == 1 and t["fallback"] == 0x64, t
    assert 'D2MOO_Resolve("GetItemDataRecord")' in t["code"] and "(_v == 0x1) ?" in t["code"], t["code"]

    # DELEGATE with abort-class guards (GetItemCode: CleanupAndAbort/_exit on guard fail)
    # MUST bail -> handle-abort-hazard, not a fallback-return delegate.
    t = translate_delegate_getter_to_c("ITEMS_GetItemCode", """
6fd72ff0: MOV EAX,dword ptr [ESP + 0x4]
6fd72ff4: TEST EAX,EAX
6fd72ff6: JNZ 0x6fd72fff
6fd72ff8: PUSH 0x798
6fd72ffd: JMP 0x6fd73009
6fd72fff: CMP dword ptr [EAX],0x4
6fd73002: JZ 0x6fd73023
6fd73004: PUSH 0x799
6fd73009: CALL 0x6fd5921c
6fd7300e: PUSH EAX
6fd7300f: PUSH 0x6fdda728
6fd73014: CALL 0x6fd59216
6fd73019: ADD ESP,0xc
6fd7301c: PUSH -0x1
6fd7301e: CALL 0x6fd51b0d
6fd73023: MOV EAX,dword ptr [EAX + 0x4]
6fd73026: PUSH EAX
6fd73027: CALL 0x6fdc19a0
6fd7302c: MOV ECX,dword ptr [EAX + 0x84]
6fd73032: TEST ECX,ECX
6fd73034: JZ 0x6fd7303b
6fd73036: MOV EAX,ECX
6fd73038: RET 0x4
6fd7303b: MOV EAX,dword ptr [EAX + 0x80]
6fd73041: RET 0x4
""", resolve_rev=_rev)
    assert not t["ok"] and "abort-class" in t["reason"], t
    # a callee NOT in the resolve table must bail (can't resolve by name)
    t = translate_delegate_getter_to_c("X", """
6f000000: MOV EAX,dword ptr [ESP + 0x4]
6f000004: MOV EAX,dword ptr [EAX + 0x4]
6f000007: PUSH EAX
6f000008: CALL 0x6f999999
6f00000d: MOV EAX,dword ptr [EAX + 0x8]
6f000010: RET 0x4
""", resolve_rev=_rev)
    assert not t["ok"] and "not in resolve table" in t["reason"], t

    # resolvable_callees + callthrough_prompt_block: the model-hint path for delegates
    # the mechanical translator can't handle (multi-arg / fastcall callees). Must find
    # the resolvable CALL, skip abort helpers, and emit a D2MOO_Resolve hint.
    cs = resolvable_callees("""
6f000000: MOV EAX,dword ptr [ESP + 0x4]
6f000004: PUSH EAX
6f000005: CALL 0x6fdc19a0
6f00000a: PUSH 0x1
6f00000c: CALL 0x6fd5921c
6f000011: RET 0x4
""", resolve_rev={0x6fdc19a0: "GetItemDataRecord"})
    assert cs == [(0x6fdc19a0, "GetItemDataRecord")], cs   # abort helper 0x6fd5921c skipped
    hint = callthrough_prompt_block(cs)
    assert 'D2MOO_Resolve("GetItemDataRecord")' in hint and "CALL-THROUGH REQUIRED" in hint, hint
    assert callthrough_prompt_block([]) == ""

    # resolvable_globals + global_resolve_prompt_block: the global-table getter hint.
    gs = resolvable_globals("""
6f000000: MOV EAX,dword ptr [ESP + 0x4]
6f000004: MOV ECX,dword ptr [0x6fde9e1c]
6f00000a: MOVZX EAX,byte ptr [EAX + 0x10]
6f00000e: RET 0x4
""", resolve_rev={0x6fde9e1c: "g_pDataTables"})
    assert gs == [(0x6fde9e1c, "g_pDataTables")], gs
    gh = global_resolve_prompt_block(gs)
    assert 'D2MOO_Resolve("g_pDataTables")' in gh and "GLOBAL RESOLVE REQUIRED" in gh, gh
    assert global_resolve_prompt_block([]) == ""

    # GLOBAL-TABLE INDEXED getter (the dominant DATATBLS shape, real 1.13c disasm): the
    # model oscillates on the resolve-deref chain (proves FieldE, mismatches Field10) ->
    # translate it MECHANICALLY: resolve the global BY NAME, deref, bound-check, index by
    # stride, raw-cast the field. All offsets/stride/width from the disasm. 2026-07-08.
    _rev2 = {0x6fde9e1c: "g_pDataTables"}
    t = translate_global_table_getter_to_c("DATATBLS_GetItemTypeField10", """
6fd72f80: MOV EAX,dword ptr [ESP + 0x4]
6fd72f84: TEST EAX,EAX
6fd72f86: JL 0x6fd72fa8
6fd72f88: MOV ECX,dword ptr [0x6fde9e1c]
6fd72f8e: CMP EAX,dword ptr [ECX + 0xbfc]
6fd72f94: JGE 0x6fd72fa8
6fd72f96: MOV EDX,dword ptr [ECX + 0xbf8]
6fd72f9c: IMUL EAX,EAX,0xe4
6fd72fa2: ADD EAX,EDX
6fd72fa4: TEST EAX,EAX
6fd72fa6: JNZ 0x6fd72fad
6fd72fa8: XOR EAX,EAX
6fd72faa: RET 0x4
6fd72fad: MOVZX EAX,byte ptr [EAX + 0x10]
6fd72fb1: RET 0x4
""", resolve_rev=_rev2)
    # the original MOVZX-es byte->EAX, so the return is the ZERO-EXTENDED full 32-bit
    # value (u32), read at the native byte width.
    assert t["ok"] and t["ret"] == "u32" and t["global"] == "g_pDataTables", t
    assert t["count_off"] == 0xbfc and t["records_off"] == 0xbf8 and t["stride"] == 0xe4 and t["field_off"] == 0x10, t
    assert 'D2MOO_Resolve("g_pDataTables")' in t["code"] and "idx * 0xe4" in t["code"], t["code"]
    assert "(unsigned int)*(unsigned char*)(rec + 0x10)" in t["code"], t["code"]
    # a MOVSX word variant -> i16
    t = translate_global_table_getter_to_c("DATATBLS_GetItemTypeFieldE", """
6fd735d0: MOV EAX,dword ptr [ESP + 0x4]
6fd735d4: TEST EAX,EAX
6fd735d6: JL 0x6fd735f8
6fd735d8: MOV ECX,dword ptr [0x6fde9e1c]
6fd735de: CMP EAX,dword ptr [ECX + 0xbfc]
6fd735e4: JGE 0x6fd735f8
6fd735e6: MOV EDX,dword ptr [ECX + 0xbf8]
6fd735ec: IMUL EAX,EAX,0xe4
6fd735f2: ADD EAX,EDX
6fd735f4: TEST EAX,EAX
6fd735f6: JNZ 0x6fd735fd
6fd735f8: XOR EAX,EAX
6fd735fa: RET 0x4
6fd735fd: MOVSX EAX,word ptr [EAX + 0xe]
6fd73601: RET 0x4
""", resolve_rev=_rev2)
    assert t["ok"] and t["ret"] == "i32" and t["field_off"] == 0xe, t
    assert "(int)*(short*)(rec + 0xe)" in t["code"], t["code"]
    # a global NOT in the resolve table must bail
    t = translate_global_table_getter_to_c("X", """
6f000000: MOV EAX,dword ptr [ESP + 0x4]
6f000008: MOV ECX,dword ptr [0x6f111111]
6f00000e: CMP EAX,dword ptr [ECX + 0x10]
6f000014: JGE 0x6f000020
6f000016: MOV EDX,dword ptr [ECX + 0xc]
6f00001c: IMUL EAX,EAX,0x20
6f00001f: ADD EAX,EDX
6f000021: MOVZX EAX,byte ptr [EAX + 0x4]
6f000025: RET 0x4
""", resolve_rev=_rev2)
    assert not t["ok"] and "not resolvable" in t["reason"], t

    print("[ok] abi_static self-test: known-answer corpus + helpers + getter translator pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())

"""port_live_prove.py -- WS-6b of D2MOO's GRADUATED_CONFORMANCE_PIPELINE_PLAN.md.

The LIVE proving gate for the port pipeline, a sibling to port_pipeline.py's
static `run_harness` (which proves an OpenD2 draft against Ghidra-emulated
vectors, no game process). This module instead proves a **D2MOO** reimpl against
the **live running Project Diablo 2** via D2Debugger's direct-call oracle
(the D2Debugger MCP HTTP surface on 127.0.0.1:8790, GRADUATED plan WS-5).

Why live matters: `/emulate_function` is static (pure/leaf only). The live
oracle calls the REAL function in the REAL process, so it also covers functions
whose behavior depends on real globals/state -- strictly stronger.

Contract: run_live_prove(...) returns the SAME shape as port_pipeline.run_harness
-- {ok, passed, total, output, stage, error} -- so fun_doc.process_port_candidate
can gate on it and feed failures back through the existing bounded-retry loop
with no change to that machinery.

Design note (register-layout -> convention-ABI): fun-doc models a function's ABI
by REGISTER (param_layout inputs/outputs on ECX/EDX/EAX...), because that is what
Ghidra's /emulate_function speaks. The D2MOO oracle models it by CALLING
CONVENTION + positional 32-bit slots. translate_layout_to_spec() bridges the two
for the standard patterns (stack=stdcall, ECX=thiscall/fastcall-1, ECX+EDX=
fastcall); non-standard register ABIs (seed in ESI, etc.) are reported as
unsupported-for-live so the caller falls back to the static harness.

Standalone (imports nothing from fun_doc), like port_pipeline.py.
"""
from __future__ import annotations

import contextlib
import datetime
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse

# Windows spawns a console for every child process unless told not to, and
# these helpers run on a POLL: is_game_running fires every 45s, _pid_alive on
# every in-flight check. Each one flashed a console window on the desktop.
# CREATE_NO_WINDOW suppresses it; it is 0 on non-Windows so the flag is inert
# there.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

from pathlib import Path

# --- D2MOO side (the reimpl provider + prover live in the D2MOO repo) ---
D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
CANDIDATES_DIR = D2MOO_REPO / "conformance" / "reimpl_provider" / "candidates"
VECTORS_DIR = D2MOO_REPO / "conformance" / "vectors"
PROVE_SCRIPT = D2MOO_REPO / "conformance" / "tools" / "prove_candidate.py"
PROVEN_REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
RESOLVE_TABLE = D2MOO_REPO / "D2.Detours.patches" / "1.13c" / "D2Common_ResolveTable.gen.h"
LIVE_EXAMPLE = CANDIDATES_DIR / "datatable_rowcount.cpp"  # proven resolver-based reimpl
ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790")
# Ghidra plugin REST server (same one port_pipeline.py uses) -- source of truth
# for the RE. Every proof writes back here (writeback-source-of-truth principle).
GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")

_D2COMMON_BASE = 0x6FD50000


class UnsupportedLiveABI(Exception):
    """The function's register layout is outside the oracle's v1 (32-bit-slot,
    standard-convention) marshaller -- the caller should fall back to the static
    harness rather than treat this as a proof failure."""


def _int(v) -> int:
    if not isinstance(v, str):
        return int(v)
    try:
        return int(v, 0)          # "0x1a4" / "123"
    except ValueError:
        return int(v, 16)         # bare hex "6fd51250" (fun_doc's address convention)


_RET_RE = re.compile(r"^RET(?:\s+0x([0-9a-fA-F]+))?$")


def detect_stack_cleanup(program, address):
    """Bytes the CALLEE pops on return, read from the disassembly.

    Returns 0 for a bare `RET` (CALLER cleans -- cdecl), a positive byte count
    for `RET n` (callee cleans -- stdcall/fastcall/thiscall), or None when the
    answer isn't unambiguous (no RET found, or several RETs disagreeing).

    THE DISASSEMBLY IS THE AUTHORITY. This is the same rule the shadow manifest
    already lives by (CLAUDE.md: "arity from `RET n`" -- a wrong count on a
    callee-cleans convention skews ESP and access-violates the game). The live
    prove path never applied it: `translate_layout_to_spec` took the calling
    convention from the LLM-drafted `param_layout` alone, which knows only
    which REGISTERS hold inputs, not who cleans the stack.
    """
    try:
        d = _ghidra_get_json(
            "/disassemble_function?" + urllib.parse.urlencode(
                {"address": address, "program": program})
        )
    except Exception:
        return None
    widths = set()
    for ins in (d or {}).get("instructions", []):
        m = _RET_RE.match(str(ins.get("instruction", "")).strip())
        if m:
            widths.add(int(m.group(1), 16) if m.group(1) else 0)
    if len(widths) != 1:
        return None                      # no RET, or an inconsistent tail
    return widths.pop()


def resolve_callconv(name, address, program, argc, declared="stdcall"):
    """(callconv, note) for a spec, with the DISASSEMBLY overriding `declared`.

    THE single place this correction lives. It was originally inlined in
    translate_layout_to_spec only, and the other three spec builders
    (run_synth_prove / run_synth2_prove / run_delegate_prove) kept their
    hardcoded `"callconv": "stdcall"`. Measured 2026-07-31: of 282 written
    specs exactly ONE carried the correction, while `marshal_fault` grew
    152 -> 236 overnight. The fix was real and simply wasn't on the paths
    producing most of the faults.

    That is the same failure CLAUDE.md records for `_write_spec` -- "five call
    sites once wrote their own, which is how four of five would miss a fix like
    this". Route every spec's convention through here.

    Returns `declared` unchanged when the disassembly is unreadable or
    ambiguous: never guess, and never make things worse than the status quo.
    """
    if program is None:
        return declared, None
    actual = detect_stack_cleanup(program, address)
    if actual is None:
        return declared, None
    expected = _expected_cleanup(declared, argc)
    if actual == 0 and expected > 0:
        return "cdecl", (f"disassembly shows a bare RET with {argc} stack arg(s): "
                         f"callee does not clean -> cdecl, not {declared}")
    if actual != expected:
        # Report but do NOT rewrite the arity here: these callers build a
        # fixed-shape probe spec, so the honest signal is a warning plus the
        # unchanged convention. translate_layout_to_spec, which owns a real
        # drafted layout, refuses outright instead.
        return declared, (f"WARNING: {name} declared {argc} arg(s) as {declared} "
                          f"(callee should pop {expected}) but the disassembly "
                          f"ends in RET 0x{actual:x} -- probable arity mismatch")
    return declared, None


def _expected_cleanup(callconv: str, argc: int) -> int:
    """Bytes a callee-cleans convention must pop for `argc` 32-bit slots."""
    if callconv == "stdcall":
        return 4 * argc
    if callconv in ("fastcall", "thiscall"):
        # First two dwords arrive in ECX/EDX (one for thiscall) and are not on
        # the stack. thiscall marshals through the fastcall path here.
        return 4 * max(0, argc - 2)
    return 0                             # cdecl: caller cleans


def translate_layout_to_spec(name: str, address, param_layout: dict,
                             program=None) -> dict:
    """fun-doc register `param_layout` -> D2MOO oracle spec (callconv/args/
    ret/compare + the original's absolute `addr`). Raises UnsupportedLiveABI for
    register ABIs the v1 marshaller can't express.

    When `program` is supplied the drafted convention is CROSS-CHECKED against
    the callee's actual stack cleanup (see detect_stack_cleanup). Without that
    check every stack-argument function was declared `stdcall` unconditionally
    -- "D2 default for stack args" -- and a cdecl callee then had NOBODY clean
    its arguments: `D2Oracle_Call` casts to the declared convention, so a
    stdcall cast emits a call that expects the callee to pop, and a cdecl
    callee does not. ESP leaks 4*argc per call.

    Whether that leak faults depends on whether the enclosing frame's epilogue
    restores ESP from EBP or is ESP-relative, which is why it showed up as a
    strong tendency rather than a law. Measured 2026-07-31: 79% of
    `marshal_fault` functions end in a bare RET (cdecl) against 41% of the
    functions that proved live -- and `marshal_fault` is TERMINAL, so each one
    retired a function on an ABI verdict the ABI did not actually support.
    The oracle has accepted "cdecl" since it was written (ParseCallConv in
    D2Debugger.LiveDispatch.cpp); this translator simply never emitted it.
    """
    inputs = param_layout.get("inputs", [])
    outputs = param_layout.get("outputs", [])
    # The model sometimes emits a malformed layout where an input/output entry
    # is a LIST (e.g. ["nIndex","ECX"]) instead of a {name,register} dict --
    # `i.get(...)` then AttributeError'd and crashed the candidate
    # (2026-07-13, DATATBLS_GetLvlPrestDataField28). A malformed layout is an
    # UNSUPPORTED ABI (handled: the caller drops the candidate cleanly), not a
    # crash.
    if not all(isinstance(i, dict) for i in list(inputs) + list(outputs)):
        raise UnsupportedLiveABI(
            f"{name}: malformed layout -- input/output entries must be objects "
            f"with name/register, got a non-object entry")
    regs = [str(i.get("register", "")).upper() for i in inputs]

    # Classify the calling convention from the input register pattern.
    STACK = {"", "STACK", "STK"}
    GP = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI"}
    unknown = [r for r in regs if r not in STACK and r not in GP]
    if unknown:
        raise UnsupportedLiveABI(f"{name}: unknown register(s) {unknown}")
    has_stack = any(r in STACK for r in regs)
    has_reg = any(r in GP for r in regs)

    orig_regs = None
    if not has_reg:
        callconv = "stdcall"                       # D2 default for stack args
    elif regs[:2] == ["ECX", "EDX"] and all(r in STACK for r in regs[2:]):
        callconv = "fastcall"
    elif regs[:1] == ["ECX"] and all(r in STACK for r in regs[1:]):
        callconv = "fastcall"                      # ecx-only == thiscall shape; marshals the same
    elif not has_stack:
        # Register-only but NON-standard placement (e.g. arg in EAX/ESI). The
        # oracle calls the ORIGINAL register-explicit via orig_regs; the reimpl
        # is a normal __fastcall we write, so `callconv` is the reimpl's.
        callconv = "fastcall"
        orig_regs = {str(i["register"]).upper(): i["name"] for i in inputs}
    else:
        raise UnsupportedLiveABI(
            f"{name}: non-standard registers {regs} mixed with stack args -- "
            f"register-explicit path is register-only (no stack args) in v1")

    # Outputs: the oracle captures the EAX return only (v1). EDX (int64 hi) or
    # memory write-sets are not yet compared live.
    out_regs = [str(o.get("register", "")).upper() for o in outputs]
    if any(r not in {"EAX", ""} for r in out_regs):
        raise UnsupportedLiveABI(
            f"{name}: output registers {out_regs} beyond EAX not comparable live yet")
    signed = any(o.get("signed") for o in outputs if str(o.get("register", "")).upper() == "EAX")

    # Class B (2026-07-13, capability loop): an input may be a pure OUT-buffer
    # param -- `kind: "outbuf"` (+ optional `bytes`, default 4) in the drafted
    # layout. The oracle has ALWAYS supported buf args + buf compare channels
    # (see D2Debugger.LiveDispatch POST /oracle: {"kind":"buf","bytes":N},
    # compare ["ret","x"]); only THIS translator was i32/EAX-only, which is why
    # every void out-param writer (GetBeltTxtEntry, MONSTER_GetInvGridSize, the
    # ROOM coordinate pairs) dead-ended as unprovable. Out-buffers join the
    # compare set, so a void-return writer becomes a MEANINGFUL proof (and a
    # meaningful shadow dispatcher) via its written bytes. input_sets carry
    # ONLY the scalar params -- the oracle allocates fresh scratch buffers per
    # call for buf args.
    outbufs = [i for i in inputs if str(i.get("kind", "")).lower() == "outbuf"]
    args = []
    for i in inputs:
        if str(i.get("kind", "")).lower() == "outbuf":
            args.append({"id": i["name"], "kind": "buf",
                         "bytes": int(i.get("bytes") or 4)})
        else:
            args.append({"id": i["name"], "kind": "i32"})
    compare = (["ret"] if outputs else []) + [b["name"] for b in outbufs]

    # ---- disassembly cross-check (see docstring) -------------------------
    # Skipped for the register-explicit path: `orig_regs` calls the original
    # through a hand-asm register stub with no stack args at all, so the
    # callee's RET width says nothing about how we invoke it.
    cleanup_note = None
    if program is not None and not orig_regs:
        actual = detect_stack_cleanup(program, address)
        if actual is not None:
            expected = _expected_cleanup(callconv, len(args))
            if actual == 0 and expected > 0:
                # Callee does not pop, but we were about to promise it would.
                # This is the fix that matters: emit the convention the oracle
                # has always accepted instead of leaking ESP on every call.
                cleanup_note = (f"disassembly shows a bare RET with {len(args)} stack "
                                f"arg(s): callee does not clean -> cdecl, not {callconv}")
                callconv = "cdecl"
            elif actual != expected:
                # Neither convention explains the observed cleanup, so the
                # DRAFTED ARITY is wrong. Refusing here is not conservatism:
                # calling with the wrong slot count on a callee-cleans
                # convention skews ESP for the rest of the chain and
                # access-violates the GAME (CLAUDE.md records eip=0x00000140
                # from exactly this). Better an unsupported_abi verdict than a
                # crashed process.
                raise UnsupportedLiveABI(
                    f"{name}: drafted {len(args)} arg(s) as {callconv} implies the callee "
                    f"pops {expected} bytes, but the disassembly ends in "
                    f"RET 0x{actual:x} ({actual} bytes = {actual // 4} stack arg(s)). "
                    f"The disassembly is the authority -- the layout's arity is wrong. "
                    f"Re-draft with {actual // 4} stack argument(s).")

    spec = {
        "name": name,
        "addr": _int(address),
        "callconv": callconv,
        "ret": ("i32" if signed else "u32") if outputs else "void",
        "args": args,
        "compare": compare,
    }
    if orig_regs:
        spec["orig_regs"] = orig_regs
    if cleanup_note:
        # Carried into the spec file so a later reader can see WHY the
        # convention differs from what the layout implied.
        spec["callconv_source"] = cleanup_note
    return spec


def _fail(stage: str, msg: str, output: str = "") -> dict:
    return {"ok": False, "passed": 0, "total": 0, "stage": stage, "error": msg, "output": output,
            "failure_stage": stage, "failure_detail": msg}


# ---------------------------------------------------------------------------
# FAILURE TAXONOMY (2026-07-08). A bare "live_prove_failed" used to conflate five
# unrelated causes -- candidate compile error, compile-cascade from a SIBLING
# candidate, wrong-callconv marshal fault, oracle/bridge death, and a genuine
# mismatch -- and each cost a manual reconstruction to tell apart. Every prove
# result now carries failure_stage + failure_detail:
#   build_candidate        -- THIS candidate does not compile (detail = its errors)
#   build_provider_cascade -- a SIBLING candidate broke the shared provider build
#                             (self-healed when possible; see build_provider_attributed)
#   oracle_unreachable     -- :8790 was down before we started
#   oracle_died_during     -- :8790 was alive, this function's vectors killed it
#   bad_target             -- the original's address isn't mapped executable in the
#                             running game (module not loaded, or not at Ghidra's
#                             image base). ENVIRONMENTAL: nothing was called, so it
#                             is not a verdict about the function. Split out of
#                             marshal_fault 2026-07-30 -- it had been arriving as
#                             "handler-exception" and retiring D2Client functions
#                             whose reimpl never ran (104 of them).
#   marshal_fault          -- SEH-caught fault inside the oracle (bad ABI/pointer)
#   mismatch               -- real divergence: orig != reimpl on >=1 vector
#   prove_timeout / prove  -- prover subprocess timeout / unclassified
# ---------------------------------------------------------------------------
def check_oracle_alive(timeout: float = 3.0) -> bool:
    """GET /status on the oracle; False on any failure. Cheap; call after a failed
    prove to distinguish 'this function killed the bridge' from 'it diverged'."""
    u = urllib.parse.urlparse(ORACLE_URL)
    try:
        conn = http.client.HTTPConnection(u.hostname, u.port or 8790, timeout=timeout)
        conn.request("GET", "/status")
        ok = conn.getresponse().status == 200
        conn.close()
        return ok
    except OSError:
        return False


_CANDIDATE_ERR_RE = re.compile(r"candidates[\\/](\w+)\.cpp\((\d+)[,)]")
_MSVC_ERR_LINE_RE = re.compile(r"error [A-Z]+\d+.*")
# LNK2005 (duplicate symbol) references *.obj filenames, not `candidates\X.cpp(line,col)`
# -- _CANDIDATE_ERR_RE never matches it, so a duplicate-symbol collision between two
# candidates used to fall through to a blanket, unattributed "build_provider" failure
# with NOTHING healed, poisoning the shared build for every other candidate on every
# subsequent prove until a human noticed and fixed it by hand (confirmed live 2026-07-25:
# a stray duplicate `GetByte0x94` between candidates/GetByte0x94.cpp and
# candidates/unit_field_getters.cpp broke 16+ consecutive prove attempts across
# unrelated functions before anyone caught it). Captures (dup_stem, symbol, orig_stem):
# dup_stem's object is the one the linker was processing when it hit the redefinition,
# orig_stem's object is where the symbol was first defined.
_DUP_SYMBOL_RE = re.compile(
    r"(\w+)\.obj\s*:\s*error LNK2005:\s*(\S+)\s+already defined in\s+(\w+)\.obj")

# LNK2019/LNK2001 (unresolved external) is the THIRD MSBuild error shape, and the
# one that did the most damage. It names neither `candidates\X.cpp(line,col)` nor
# an .obj -- just the .vcxproj -- so _CANDIDATE_ERR_RE finds no offender,
# _DUP_SYMBOL_RE does not match, and every one of these fell through to the
# blanket unattributed `build_provider` verdict. `live_prove_failed` is TERMINAL,
# so whichever function happened to be proving got permanently retired for a
# link error caused by somebody ELSE's candidate.
#
# Measured 2026-07-31 over 523 live_prove_failed rows: 126 were exactly this --
# the unresolved symbol was "referenced in" a function that was NOT the one under
# test -- traced to just 35 distinct offending candidates (top 15 = 67%). e.g.
# `x_ismbbtype` retired because `_BINK_CheckVideoFrameReady@4` was unresolved in
# `_BINKW32_ProcessFrameWriteAsync@4`, a function it has nothing to do with.
#
# The referring function is the attribution key: its name maps to the candidate
# file that declared the call it cannot link.
_UNRESOLVED_SYM_RE = re.compile(
    r"error LNK(?:2019|2001):\s*unresolved external symbol\s+(\S+)"
    r"(?:\s+referenced in function\s+(\"[^\"]+\"|\S+))?")


def _undecorate(sym: str) -> str:
    """Best-effort MSVC symbol -> plain function name.

      _Foo@8                    -> Foo     (stdcall)
      _Foo                      -> Foo     (cdecl)
      @Foo@4                    -> Foo     (FASTCALL -- leading @, not _)
      ?Foo@@YGHPAXH0@Z          -> Foo     (C++ mangled)
      "int __stdcall Foo(...)"  -> Foo     (already-undecorated, quoted)

    The fastcall form is easy to miss and fails silently: `@Foo@4`.split("@")[0]
    is the EMPTY STRING, so every fastcall referrer attributed to an offender
    named "" -- which then out-sorted every real candidate. Caught 2026-07-31
    when 34 of 125 collateral rows blamed a nameless offender.
    """
    s = (sym or "").strip().strip('"')
    if s.startswith("?"):
        m = re.match(r"\?([A-Za-z_]\w*)@", s)
        return m.group(1) if m else s
    if "(" in s:                      # undecorated prototype form
        m = re.search(r"([A-Za-z_]\w*)\s*\(", s)
        return m.group(1) if m else s
    return s.lstrip("_@").split("@")[0]


def _find_unresolved_symbol_offender(out: str, current_name: str):
    """Attribute an LNK2019/LNK2001 unresolved-external failure.

    Returns None when nothing is attributable (leave it to the generic
    build_provider bucket). Otherwise (stage, detail, quarantine_name):

      * quarantine_name set  -> the referring function belongs to a SIBLING
        candidate, i.e. this build is broken by somebody else's draft and the
        function under test is collateral. Quarantine the sibling (move, not
        delete) and retry, exactly as the duplicate-symbol path does.
      * quarantine_name None -> the referring function IS current_name, so our
        own draft calls something that does not exist. That is a real defect in
        this candidate; stage 'build_candidate' feeds it to the fix loop.
    """
    refs = _UNRESOLVED_SYM_RE.findall(out or "")
    if not refs:
        return None
    own, siblings = [], {}
    for symbol, referrer in refs:
        if not referrer:
            continue
        fn = _undecorate(referrer)
        if not fn:
            continue                  # truncated/unparseable decoration
        if fn == current_name:
            own.append(symbol)
        elif (CANDIDATES_DIR / f"{fn}.cpp").exists():
            # Only attribute to a file that actually exists -- the referring
            # function may live in provider runtime code we must never touch.
            siblings.setdefault(fn, []).append(symbol)
    if own:
        # Our own draft is (also) broken -- fix ours first regardless of any
        # sibling, since healing a sibling would not make this candidate link.
        return ("build_candidate",
                f"unresolved external symbol(s) {', '.join(sorted(set(own))[:5])} "
                f"referenced in {current_name} -- the draft calls something the "
                f"provider does not define", None)
    if siblings:
        offender = max(siblings, key=lambda k: len(siblings[k]))
        syms = ", ".join(sorted(set(siblings[offender]))[:5])
        return ("build_provider_unresolved_symbol",
                f"candidate {offender}.cpp references undefined symbol(s) {syms}, "
                f"failing the shared provider link for every other candidate "
                f"(including {current_name}, which is collateral)", offender)
    return None


def _classify_prove_failure(out: str) -> tuple:
    """(failure_stage, detail) from prover output. Call check_oracle_alive
    separately to upgrade to oracle_died_during."""
    o = out or ""
    if "not reachable" in o or "refused" in o.lower() or "ConnectionRefused" in o:
        return "oracle_unreachable", "D2Debugger :8790 unreachable"
    # Checked BEFORE handler-exception: the oracle's bad-target gate now rejects an
    # unmapped call target up front instead of letting the call fault into SEH, and
    # this is the one failure that must never be read as an ABI verdict.
    if "bad-target" in o or "module not loaded in the game process" in o:
        detail = next((ln.strip() for ln in o.splitlines() if "bad-target" in ln
                       or "module not loaded in the game process" in ln), "")
        return "bad_target", (detail[:400] or "original target not mapped in the running game")
    if "handler-exception" in o:
        return "marshal_fault", ("SEH fault inside the oracle handler -- usually a wrong "
                                 "callconv/slot-count (check RET n) or a bad pointer arg")
    if "error C" in o or "fatal error" in o or "error LNK" in o:
        errs = "; ".join(m.group(0) for m in _MSVC_ERR_LINE_RE.finditer(o))[:400]
        return "build_provider", errs or "compile error in provider build"
    if "DIVERGED" in o or "MISMATCH" in o.upper():
        return "mismatch", "original != reimpl on >=1 vector (see output)"
    return "prove", (o.strip().splitlines() or ["no output"])[-1][:200]


def _find_duplicate_symbol_offender(out: str, current_name: str):
    """Attribute an LNK2005 duplicate-symbol build failure (see _DUP_SYMBOL_RE).

    Returns None if no duplicate-symbol line resolves to two real candidate files
    (leave it to the generic build_provider bucket). Otherwise (stage, detail,
    quarantine_name):
      * quarantine_name set   -> a candidate that is CLEARLY the intruder relative
        to current_name is safe to sideline automatically (see cases below) --
        quarantine it (move, not delete -- see quarantine_candidate) and retry.
      * quarantine_name None  -> either current_name's own fresh draft is the
        redefinition (stage='build_candidate', feed to the normal fix loop), or
        the collision is between two OLD, ESTABLISHED siblings that both compile
        fine and have nothing to do with what's being proved right now -- there is
        no correctness basis to prefer one over the other automatically (both
        "work"; only one is semantically right, e.g. the 2026-07-25 GetByte0x94 /
        unit_field_getters collision where the two bodies differed on a NULL
        check), so surface it distinctly instead of silently deleting code.
    """
    for dup_stem, symbol, orig_stem in _DUP_SYMBOL_RE.findall(out):
        if dup_stem == orig_stem:
            continue
        if not (CANDIDATES_DIR / f"{dup_stem}.cpp").exists() or \
           not (CANDIDATES_DIR / f"{orig_stem}.cpp").exists():
            continue  # not two real candidates -- leave to the generic bucket
        detail = (f"duplicate symbol {symbol}: {dup_stem}.cpp and {orig_stem}.cpp "
                  f"both export it, poisoning the shared provider build")
        if dup_stem == current_name:
            # OUR fresh draft is the redefinition -- our own problem, not an
            # established sibling's; feed it to the fix loop (rename/regenerate)
            # instead of quarantining code that predates this attempt.
            return "build_candidate", detail, None
        if orig_stem == current_name:
            # A DIFFERENT candidate just redefined the symbol WE already own --
            # it's the intruder, and current_name is what the caller is actively
            # trying to prove, so keeping it and sidelining the newcomer is safe.
            return "build_provider_duplicate_symbol", detail, dup_stem
        return "build_provider_duplicate_symbol", detail, None
    return None


_BUILD_LOCK_TIMEOUT = float(os.environ.get("FUNDOC_PROVIDER_BUILD_LOCK_TIMEOUT", "1800"))
_INFLIGHT_DIR = Path(tempfile.gettempdir()) / "fundoc_provider_inflight"
# How long a candidate stays protected from another worker's heal loop. See
# inflight_candidates for why an age bound is required and not just PID liveness.
_INFLIGHT_TTL_SEC = float(os.environ.get("FUNDOC_INFLIGHT_TTL_SEC", "1800"))


@contextlib.contextmanager
def _provider_build_lock(timeout: float = None):
    """Serialize the shared-provider build across threads AND processes.

    ALL candidates/*.cpp link into ONE provider DLL, built in ONE CMake tree
    (`build-1.13c`) whose candidate glob is CONFIGURE_DEPENDS. Until 2026-07-31
    nothing serialized that, while the dashboard routinely runs SIX port
    workers at once. The resulting races are exactly the failure pattern seen
    in the data:

      * worker A configures; CMake re-globs and sweeps in worker B's
        just-written candidate, so A's build fails on B's code and A is
        retired with a `build_provider` verdict about a file it never wrote;
      * A's heal loop then removes or quarantines B.cpp *while B is still
        proving it*, so B fails too;
      * and two `cmake --build` runs against one tree produce arbitrary
        MSBuild failures on their own.

    Deliberately scoped to the BUILD, not the whole prove: drafting is the
    slow part (LLM calls, minutes) and stays fully parallel, while the build
    critical section is short. This keeps ~all the fleet's throughput and
    removes the race.

    Unlike port_pipeline._interprocess_lock's 5s fail-open ceiling -- fine for
    appending a vector file, useless for a build that legitimately runs for
    minutes -- this waits a long time and says so loudly if it ever gives up.
    """
    timeout = _BUILD_LOCK_TIMEOUT if timeout is None else timeout
    lock_dir = Path(tempfile.gettempdir()) / "fundoc_provider_build_lock"
    f = None
    acquired = False
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
        f = open(lock_dir / "provider_build.lock", "a+")
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    print(f"[build-lock] WARNING: could not acquire the provider "
                          f"build lock within {int(timeout)}s -- proceeding UNLOCKED. "
                          f"Concurrent builds can misattribute failures.", flush=True)
                    break
                time.sleep(0.5)
        yield acquired
    except Exception as e:
        print(f"[build-lock] locking unavailable ({e}) -- proceeding unlocked", flush=True)
        yield False
    finally:
        if f is not None:
            try:
                if acquired:
                    if os.name == "nt":
                        import msvcrt
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            f.close()


def mark_candidate_inflight(name: str) -> None:
    """Record that THIS process is actively proving `name`.

    Read by the heal loop, which must never quarantine or delete a candidate
    another live worker is mid-prove on -- doing so fails that worker for a
    file that was removed out from under it, turning one bad candidate into
    two terminal verdicts.
    """
    try:
        _INFLIGHT_DIR.mkdir(parents=True, exist_ok=True)
        (_INFLIGHT_DIR / f"{name}.inflight").write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        pass


def clear_candidate_inflight(name: str) -> None:
    try:
        (_INFLIGHT_DIR / f"{name}.inflight").unlink()
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=5,
                creationflags=_NO_WINDOW)
            return str(pid) in out.stdout
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def inflight_candidates() -> set:
    """Candidate names currently owned by a LIVE worker process.

    A marker is honoured only while BOTH hold:

      * its owning PID is alive -- a force-killed dashboard must not leave a
        broken candidate permanently un-healable;
      * it is younger than _INFLIGHT_TTL_SEC -- the owner is a long-lived
        dashboard process, so PID-liveness alone would keep every marker it
        ever wrote valid forever. The TTL is what makes success, failure,
        exception and crash all self-clean without threading a try/finally
        through all five prove entry points.

    A prove is minutes; the TTL is deliberately several times that, so it
    expires stale claims without ever expiring a live one.
    """
    names = set()
    try:
        entries = list(_INFLIGHT_DIR.glob("*.inflight"))
    except OSError:
        return names
    now = time.time()
    for p in entries:
        try:
            pid = int((p.read_text(encoding="utf-8") or "0").strip() or 0)
            age = now - p.stat().st_mtime
        except (OSError, ValueError):
            continue
        if pid == os.getpid():
            continue                      # our own claim never blocks us
        if age < _INFLIGHT_TTL_SEC and _pid_alive(pid):
            names.add(p.stem)
        else:
            try:
                p.unlink()
            except OSError:
                pass
    return names


def build_provider_attributed(current_name: str, *, config: str = "Release",
                              max_heal: int = 4) -> dict:
    """Build + stage the reimpl provider with FAILURE ATTRIBUTION and SELF-HEALING.

    All candidates/*.cpp compile into ONE provider DLL, so one broken candidate
    poisons the build for every other function and the failure lands on whichever
    function happened to be proving (the compile-cascade class: a CORRECT
    GetUnitPathCoordY was failed 3x by sibling/type issues before this existed).

    This wrapper parses MSBuild errors for `candidates\\<name>.cpp`:
      * offender == current_name -> {ok:False, stage:'build_candidate', detail:errors}
        (the caller's own draft is broken -- feed detail to the fix loop)
      * offender is a SIBLING    -> remove the stale broken sibling (a failed
        candidate has no staged value; its content lives in run logs), log it,
        and REBUILD -- healing the cascade instead of misattributing it.
    LNK2005 duplicate-symbol failures (a DIFFERENT MSBuild error shape -- see
    _find_duplicate_symbol_offender) get the same attribution+heal treatment where
    it's safe, and a distinct 'build_provider_duplicate_symbol' stage (instead of
    the old unattributed blanket 'build_provider') where it isn't.
    Serialized by _provider_build_lock: the tree is shared and the fleet runs
    several port workers at once. Returns {ok, stage, detail, healed:[names]}."""
    with _provider_build_lock():
        return _build_provider_attributed_locked(current_name, config=config,
                                                 max_heal=max_heal)


def _build_provider_attributed_locked(current_name: str, *, config: str,
                                      max_heal: int) -> dict:
    healed: list = []
    build_dir = str(D2MOO_REPO / "build-1.13c")
    # Candidates other LIVE workers are mid-prove on. Healing must route
    # around these: deleting one fails its owner for a file that vanished
    # underneath it, converting one broken candidate into two terminal
    # verdicts.
    protected = inflight_candidates()
    for _round in range(max_heal + 1):
        # reconfigure first: CONFIGURE_DEPENDS re-globs candidates + regens the .def
        subprocess.run(["cmake", "-S", str(D2MOO_REPO), "-B", build_dir],
                       capture_output=True, text=True, creationflags=_NO_WINDOW)
        proc = subprocess.run(
            ["cmake", "--build", build_dir, "--config", config,
             "--target", "D2MOO_ReimplProvider"],
            capture_output=True, text=True, creationflags=_NO_WINDOW)
        out = proc.stdout + proc.stderr
        if proc.returncode == 0:
            built = os.path.join(build_dir, "source", "D2Debugger", config,
                                 "D2MOO_ReimplProvider.dll")
            if not os.path.exists(built):
                for dirpath, _, files in os.walk(build_dir):
                    if ("D2MOO_ReimplProvider.dll" in files
                            and os.sep + "patch" + os.sep not in dirpath):
                        built = os.path.join(dirpath, "D2MOO_ReimplProvider.dll")
                        break
            import shutil
            shutil.copyfile(built, os.path.join(build_dir, "patch", "D2MOO_ReimplProvider.dll"))
            return {"ok": True, "stage": "build", "detail": "", "healed": healed}

        offenders = sorted({m.group(1) for m in _CANDIDATE_ERR_RE.finditer(out)})
        errs = "; ".join(m.group(0) for m in _MSVC_ERR_LINE_RE.finditer(out))[:500]
        if current_name in offenders:
            return {"ok": False, "stage": "build_candidate",
                    "detail": errs or "candidate compile error", "healed": healed}
        siblings = [n for n in offenders if n != current_name]
        if not siblings:
            dup = _find_duplicate_symbol_offender(out, current_name)
            if dup is not None:
                stage, detail, quarantine_name = dup
                if quarantine_name and quarantine_name in protected:
                    # Owned by a live worker -- see the `healable` guard below.
                    return {"ok": False, "stage": "build_provider_cascade",
                            "detail": (f"shared provider build broken by "
                                       f"{quarantine_name}, currently being proved by "
                                       f"another worker -- {current_name} is collateral"),
                            "healed": healed}
                if quarantine_name:
                    print(f"[build-heal] quarantining duplicate-symbol candidate "
                          f"{quarantine_name}.cpp (collided with {current_name}, "
                          f"poisoning the shared provider build)")
                    quarantine_candidate(quarantine_name, detail)
                    healed.append(quarantine_name)
                    continue
                return {"ok": False, "stage": stage, "detail": detail, "healed": healed}
            # LNK2019/LNK2001: the shape that produced 126 collateral
            # retirements because nothing here could attribute it.
            unres = _find_unresolved_symbol_offender(out, current_name)
            if unres is not None:
                stage, detail, quarantine_name = unres
                if quarantine_name and quarantine_name in protected:
                    # Owned by a live worker -- see the `healable` guard below.
                    return {"ok": False, "stage": "build_provider_cascade",
                            "detail": (f"shared provider build broken by "
                                       f"{quarantine_name}, currently being proved by "
                                       f"another worker -- {current_name} is collateral"),
                            "healed": healed}
                if quarantine_name:
                    print(f"[build-heal] quarantining candidate {quarantine_name}.cpp "
                          f"(unresolved external symbol poisoning the shared provider "
                          f"link; {current_name} was collateral)")
                    quarantine_candidate(quarantine_name, detail)
                    healed.append(quarantine_name)
                    continue
                return {"ok": False, "stage": stage, "detail": detail, "healed": healed}
            return {"ok": False, "stage": "build_provider",
                    "detail": errs or out[-500:], "healed": healed}
        healable = [n for n in siblings if n not in protected]
        if not healable:
            # Every offender belongs to a live worker. Removing one would fail
            # ITS owner for a file that disappeared mid-prove; better to report
            # this build as collateral (non-terminal -- see
            # fun_doc._prove_failure_is_environmental) and let the owner finish.
            return {"ok": False, "stage": "build_provider_cascade",
                    "detail": (f"shared provider build broken by candidate(s) "
                               f"{', '.join(sorted(siblings))}, currently being proved by "
                               f"another worker -- {current_name} is collateral"),
                    "healed": healed}
        for n in healable:
            print(f"[build-heal] removing broken sibling candidate {n}.cpp "
                  f"(it was poisoning the shared provider build)")
            remove_candidate(n)
            healed.append(n)
    return {"ok": False, "stage": "build_provider",
            "detail": f"still failing after healing {healed}", "healed": healed}


# ---------------------------------------------------------------------------
# LIVE-path drafting: a resolver-based D2MOO reimpl for a "global_leaf" function
# (reads named game globals -> not statically provable, but provable LIVE because
# the running game has the globals populated). classify_function tags these
# "global_leaf"; process_port_candidate routes them here instead of the static
# OpenD2 harness. The reimpl reads globals BY NAME via D2MOO_Resolve (the injected
# verified-address resolver), exactly like the proven datatable_rowcount.cpp.
# ---------------------------------------------------------------------------
_GLOBAL_NAME_RE = re.compile(r'"(g_[A-Za-z_]\w*)"')


def resolvable_globals() -> list:
    """The g_* global names D2MOO_Resolve knows (from the generated resolve
    table). A live reimpl may only reference these; anything else must be added
    to conformance/tools/gen_resolve_table.py first."""
    try:
        text = RESOLVE_TABLE.read_text(encoding="utf-8")
    except OSError:
        return []
    return sorted(set(_GLOBAL_NAME_RE.findall(text)))


def _prompt_module(program) -> str:
    """The owning DLL to name in a draft prompt. Falls back to an explicit
    'unknown module' rather than a plausible-looking default -- a wrong module
    name in the prompt is worse than an absent one, because the model will act
    on it."""
    return module_name_for_program(program) or "unknown module"


def build_live_draft_prompt(func_name: str, address, decompiled_text: str,
                            program=None) -> str:
    globals_list = resolvable_globals()
    try:
        example = LIVE_EXAMPLE.read_text(encoding="utf-8")
    except OSError:
        example = "(example unavailable)"
    addr = f"0x{_int(address):x}"
    parts = []
    parts.append(
        "OUTPUT CONTRACT (a machine parses your reply; a human never sees it): reply with "
        "EXACTLY TWO fenced blocks and nothing that matters outside them -- BLOCK 1 ```cpp (the "
        "reimpl), BLOCK 2 ```json (the register layout + input_sets). Tag them literally ```cpp "
        "and ```json. No third block, no split code blocks, no trailing prose. "
        "CRITICAL: both blocks must appear in your FINAL ANSWER message -- anything that exists "
        "only inside your private reasoning/thinking is DISCARDED unread. Keep reasoning SHORT; "
        "spend the output budget on the blocks.")
    parts.append("")
    parts.append("## Task: reimplement a Diablo II function for LIVE conformance proving")
    parts.append(
        "You are writing a D2MOO 'reimpl provider' version of this Ghidra-analyzed PD2-S12 function. "
        "It will be PROVEN by calling BOTH the ORIGINAL (in the live running game) and YOUR reimpl "
        "with identical inputs and comparing results -- so it must reproduce the decompiled algorithm "
        "EXACTLY (every offset, magic constant, integer width, and edge case).")
    parts.append(
        "This function reads GLOBAL game state, so it cannot be proven statically. Your reimpl must "
        "read the SAME global from the running game via the injected resolver D2MOO_Resolve -- NOT a "
        "hardcoded address, NOT an extern.")
    parts.append("")
    # The module comes from the CALLER's program, never a literal. This line said
    # "(D2Common.dll)" unconditionally, so every D2Client draft was told it was
    # documenting a D2Common function -- which also steers the model toward
    # D2Common-flavoured resolve names (2026-07-30).
    parts.append(f"Function: {func_name} at {addr}   ({_prompt_module(program)})")
    parts.append("")
    parts.append("## Decompiled source (the spec -- includes the plate comment)")
    parts.append("```")
    parts.append(str(decompiled_text))
    parts.append("```")
    parts.append("")
    parts.append("## REQUIRED reimpl shape")
    parts.append(
        "- `#include \"../provider_runtime.h\"` and a `// D2MOO_REIMPL_EXPORT: " + func_name + "` marker.\n"
        "- `extern \"C\"` with the right calling convention (see below) + integer widths.\n"
        "- TYPES: use ONLY plain C types the provider already has. Return `void*` for ANY pointer "
        "return (a record/struct pointer, an array element pointer, etc.) -- do NOT name a Ghidra struct "
        "type like `SomeTxtRecord*` / `MonStatsTxtRec*`: those are NOT defined in the provider and will "
        "not compile (`error C2143`). Use `int`/`unsigned int`/`char`/`short`/`void*` and nothing else.\n"
        "- Resolve each global by NAME. Ghidra's `_g_Foo` resolves as `\"g_Foo\"` (drop a leading "
        "underscore). D2MOO_Resolve ALWAYS returns the ADDRESS OF THE SYMBOL (i.e. &g_Foo).\n"
        "- MECHANICAL RULE for using a resolved global -- do EXACTLY this, do not improvise extra "
        "dereferences:\n"
        "    STEP 1: compute a base pointer ONCE at the top of the function.\n"
        "       * If the symbol is a POINTER VARIABLE (name starts `g_p`, or Ghidra types it `T*`): the "
        "decompile's bare `_g_pFoo` is the pointer's VALUE, so deref the resolved address ONCE:\n"
        "           `char* base = (char*)*(void**)D2MOO_Resolve(\"g_pFoo\");`\n"
        "       * Otherwise (data/array/struct base: `g_dw`, `g_an`, `g_<Struct>`): use the return directly:\n"
        "           `char* base = (char*)D2MOO_Resolve(\"g_dwFoo\");`\n"
        "    STEP 2: translate the decompile LITERALLY, replacing every `_g_Foo` with `base` and keeping "
        "each cast/offset EXACTLY as written. `*(int *)(_g_pFoo + 0xNN)` -> `*(int*)(base + 0xNN)`; "
        "`*(int *)(_g_pFoo + 0xMM)` -> `*(int*)(base + 0xMM)`. Add NO dereference beyond the single one in "
        "STEP 1, and remove none. Guard null: if the resolve (or the deref) is null, return an obvious "
        "wrong-value sentinel.\n"
        "  (Tell for getting STEP 1 wrong: the proof matches on out-of-range/negative inputs but FAILS on "
        "valid ones.)\n"
        "- If D2MOO_Resolve returns null (resolver missing), return an obvious wrong-value sentinel so a "
        "misconfig fails loudly rather than matching by accident.\n"
        "- The decompile's FATAL/abort branch (e.g. `if (_g_pFoo == 0) { GetReturnAddress(); "
        "CleanupAndAbort(); _exit(-1); }`) calls helpers that are NOT defined in the provider and will "
        "NOT compile (error C3861). NEVER emit `GetReturnAddress`/`CleanupAndAbort`/`_exit`/`FID_conflict:*` "
        "or ANY function the decompile names -- for such a not-initialized/abort branch just `return 0;` "
        "(the oracle exercises valid in-range inputs, so that branch only has to compile).\n"
        "- Read-only: never mutate global state. No STL. Plain C-ish C++.\n"
        "- NEVER call a compiler-internal helper (__alldiv/__aulldiv/__allmul/...) by name -- write the "
        "plain operator on the correct fixed-width type and let the compiler emit it.\n"
        "- CALLING CONVENTION: DEFAULT to `__stdcall` with EVERY arg on the STACK -- that is the norm for "
        "these D2Common data-table getters (arg read from `[ESP+n]`, callee-cleaned `RET n`). Set the "
        "param_layout input `register` to `\"stack\"`, NOT `\"ECX\"`/`\"EAX\"`. Only declare `__fastcall` / a "
        "register input if the PLATE COMMENT EXPLICITLY says an arg is passed in a register (e.g. 'nIndex in "
        "ECX', 'seed in ESI'). A bare `func(int x)` signature with no such note is `__stdcall` on the stack "
        "-- do NOT infer ECX/fastcall from the signature alone (a wrong guess makes the original read its "
        "arg from the wrong place and the proof fails). The prover marshals the original's real (possibly "
        "non-standard) register ABI for you -- you only need your reimpl's declared convention to match this rule.")
    parts.append("")
    parts.append("Resolvable global names (use ONLY these; if you need one not listed, put a `// NEEDS "
                 "GLOBAL: <name>` comment and it will be skipped until added):")
    parts.append(", ".join(globals_list) or "(none found)")
    parts.append("")
    parts.append("## Example -- a PROVEN reimpl of exactly this resolver-based shape")
    parts.append("```cpp")
    parts.append(example)
    parts.append("```")
    parts.append("")
    parts.append("## OUT-PARAM (pointer the function only WRITES through)")
    parts.append(
        "If a parameter is a pointer the function ONLY WRITES results into (an out-buffer -- e.g. "
        "`uint *pnWidth`, a record struct the fn fills), declare it in param_layout.inputs with "
        "`\"kind\": \"outbuf\"` and `\"bytes\": <written size>` (the full byte size the function writes; "
        "a plain `*p = x` dword is 4). The prover allocates a fresh buffer per call, passes its address "
        "in that arg slot to BOTH original and reimpl, and COMPARES THE WRITTEN BYTES -- so a void-return "
        "writer is still a real proof. In your reimpl, declare that param as the pointer it is and write "
        "through it exactly like the decompile. input_sets must contain ONLY the scalar params (never the "
        "outbuf ones). If the function READS meaningful data through a pointer param (not just writes), "
        "it is NOT an outbuf -- reply with the single word UNSUPPORTED instead of guessing.")
    parts.append("")
    parts.append("## Output")
    parts.append("BLOCK 1 -- ```cpp: the complete reimpl (include + marker + function, all in one block).")
    parts.append(
        "BLOCK 2 -- ```json: the register layout + input_sets. Read the plate comment's register mapping "
        "(implicit EAX/ECX/ESI/EDX + any stack args). Shape:")
    parts.append("```json")
    parts.append(json.dumps({
        "fn": func_name,
        "param_layout": {
            "inputs": [{"name": "example_index", "register": "EAX", "signed": True}],
            "outputs": [{"name": "ret", "register": "EAX", "signed": False}],
        },
        "input_sets": [{"example_index": 0}, {"example_index": 1}, {"example_index": -1}],
    }, indent=2))
    parts.append("```")
    parts.append(
        "input_sets: cover 0, 1, a few valid indices, out-of-range (returns null/0), and negatives -- "
        "at least 10-15 cases. The return is often a POINTER (an absolute game address); the oracle "
        "compares it as a 32-bit value, and orig vs reimpl agree because both read the same live global.")
    return "\n".join(parts)


def build_handle_draft_prompt(func_name: str, address, decompiled_text: str,
                              program=None) -> str:
    """Draft prompt for a LIVE-POINTER GETTER (classify_function 'shadow_leaf'):
    the function takes a pointer to a heap-allocated live game object (unit/record/
    struct) + optional scalar args, and reads fields. Proven by calling BOTH the
    original and the reimpl with the SAME captured live pointer (oracle arg kind
    'handle') and comparing -- so no resolver, no static emulation; the pointer is
    passed in, not looked up."""
    addr = f"0x{_int(address):x}"
    p = []
    p.append("OUTPUT CONTRACT (a machine parses your reply): reply with EXACTLY TWO fenced blocks -- "
             "BLOCK 1 ```cpp (the reimpl), BLOCK 2 ```json (param_layout + input_sets). Tag them "
             "literally ```cpp and ```json. Nothing else that matters outside them. "
             "CRITICAL: both blocks must appear in your FINAL ANSWER message -- anything that exists "
             "only inside your private reasoning/thinking is DISCARDED unread. Keep reasoning SHORT; "
             "spend the output budget on the blocks.")
    p.append("")
    p.append("## Task: reimplement a Diablo II LIVE-POINTER getter for handle conformance proving")
    p.append(
        "This function takes a POINTER to a live game object the running game allocated on the heap "
        "(a unit / record / struct -- Ghidra often types it as a bare int*/short*). It will be PROVEN "
        "by calling BOTH the ORIGINAL and YOUR reimpl with the SAME captured live pointer and comparing "
        "the result, so reproduce the decompiled field reads EXACTLY -- every offset, cast, width, branch.")
    p.append("")
    p.append(f"Function: {func_name} at {addr}   ({_prompt_module(program)})")  # see build_live_draft_prompt
    p.append("")
    p.append("## Decompiled source (the spec)")
    p.append("```")
    p.append(str(decompiled_text))
    p.append("```")
    p.append("")
    p.append("## REQUIRED reimpl shape")
    p.append(
        "- `#include \"../provider_runtime.h\"` and a `// D2MOO_REIMPL_EXPORT: " + func_name + "` marker.\n"
        "- `extern \"C\"` with the SAME calling convention as the original: a SINGLE pointer arg passed on "
        "the stack -> `__stdcall`; a pointer passed in ECX -> `__fastcall`.\n"
        "- TYPES: use ONLY plain C types -- `int`/`unsigned int`/`short`/`unsigned short`/`char`/"
        "`unsigned char`/`void*`. Do NOT use `uint`/`ushort`/`byte`/`undefined4` (Ghidra spellings) or "
        "`DWORD`/`WORD`/`BYTE` (Win32 spellings) even though the decompile shows them -- rewrite each as "
        "its plain-C equivalent (`uint`->`unsigned int`, `DWORD`->`unsigned int`, `byte`->`unsigned char`).\n"
        "- Take the live object pointer as `void*` -- do NOT name a Ghidra struct type (UnitAny*, Room*, "
        "etc.); those are not defined in the provider and won't compile. Read fields by casting + offset, "
        "EXACTLY as the decompile does. Translate literally: `pUnit[0xc]` (an int* index) -> "
        "`((int*)p)[0xc]`; `*(int *)(pUnit + 0x40)` -> `*(int*)((char*)p + 0x40)`; `**(short **)p` -> "
        "`*(*(short**)p)`. Preserve every offset, cast, and integer width; add/remove NO dereference.\n"
        "- NULL-guard the pointer with a plain `if (p == nullptr) return 0;`. The decompile may show the "
        "null path calling helpers like `GetReturnAddress()`, `CleanupAndAbort()`, `_exit(-1)`, "
        "`FID_conflict:*`, or `__report_*` -- those are NOT defined in the provider and will NOT compile "
        "(error C3861). NEVER emit them: the oracle never passes null, so the null branch only has to "
        "compile -- just `return 0;`. Likewise call NO function the decompile names unless it is a plain "
        "arithmetic operator you can inline.\n"
        "- Additional SCALAR args (indices/ids) come AFTER the pointer in declared order, as plain "
        "int/unsigned int.\n"
        "- Read-only; never mutate. No STL. Never call a compiler-internal helper (__alldiv/...) by name.")
    p.append("")
    p.append("## Output")
    p.append("BLOCK 1 -- ```cpp: the complete reimpl (include + marker + function).")
    p.append("BLOCK 2 -- ```json:")
    p.append("```json")
    p.append(json.dumps({
        "fn": func_name,
        "param_layout": {
            "handle_arg": "pUnit",
            "scalar_args": [],
            "callconv": "stdcall",
            "ret": "i32",
        },
        "input_sets": [{}],
    }, indent=2))
    p.append("```")
    p.append(
        "param_layout.handle_arg = the live-pointer param name; scalar_args = names of any additional int "
        "args in order; callconv = stdcall (ptr on stack) or fastcall (ptr in ecx); ret = i32|u32|void|u8. "
        "IMPORTANT: if the original returns a BYTE (a CONCAT31 decompiler artifact -- the upper 3 bytes are "
        "pointer-derived garbage, only the low byte is meaningful), set ret=\"u8\" and return JUST the byte; "
        "the oracle masks to the low 8 bits so it matches. "
        "input_sets: one dict per proof case keyed by scalar_args (cover 0/1/-1/boundaries); if the ONLY "
        "input is the live pointer, use [{}] -- the oracle supplies the captured object.")
    return "\n".join(p)


def build_handle_fix_prompt(func_name: str, decompiled_text: str, prior_reimpl: str,
                            prove_output: str) -> str:
    p = []
    p.append("OUTPUT CONTRACT: reply with EXACTLY TWO fenced blocks -- BLOCK 1 ```cpp (corrected reimpl), "
             "BLOCK 2 ```json (SAME param_layout + input_sets). Nothing else.")
    p.append("")
    p.append(f"## Your reimpl of {func_name} did not prove against the live captured object. Fix it.")
    p.append("The oracle called BOTH the original and your reimpl with the SAME live pointer and compared:")
    p.append("```")
    p.append((prove_output or "(no output)")[-2500:])
    p.append("```")
    p.append("Re-check every offset/cast/width against the decompile; a single wrong offset or an extra/"
             "missing dereference flips the result.")
    p.append("## Decompiled source (the spec)")
    p.append("```")
    p.append(str(decompiled_text))
    p.append("```")
    p.append("## Your previous reimpl")
    p.append("```cpp")
    p.append(prior_reimpl)
    p.append("```")
    p.append("Output the corrected ```cpp + the ```json layout. Keep the include and the "
             "// D2MOO_REIMPL_EXPORT marker.")
    return "\n".join(p)


_HEX_LITERAL_RE = re.compile(r'(?<![\w"])0[xX][0-9a-fA-F]+')


def _is_provider_reimpl(cpp: str) -> bool:
    """A PROVIDER candidate must define an `extern "C"` exported function -- that is
    what the generated .def exports and what the DLL must resolve. Reject an OpenD2
    STATIC-HARNESS draft (`namespace D2Lib { inline T fn(){...} }`), which has NO
    extern-C symbol: written as a provider candidate it makes the .def export a symbol
    the DLL never defines -> LNK2001 -> the WHOLE provider build fails for every
    function (found 2026-07-08: SKILLS_GetSkillNodeRecord poisoned the build). Treating
    such a draft as malformed here keeps it out of the provider dir entirely.

    Also rejects a TRUNCATED draft (2026-07-13, capability loop): the model
    sometimes emits an incomplete reimpl (cut off mid-body), which the parser
    accepted, wrote to candidates/, and the compiler then failed with C1075
    ('{' no matching token) / C1004 (unexpected EOF) -- and because the provider
    is ONE shared DLL, that truncated file fails the build for EVERY function
    (the provider-compile-cascade). A balanced brace/paren count is a cheap,
    reliable truncation signal; rejecting here forces a re-draft and keeps the
    broken file out of the shared build entirely."""
    c = cpp or ""
    if 'extern "C"' not in c or "namespace D2Lib" in c:
        return False
    code = re.sub(r"//[^\n]*", "", c)   # ignore braces inside line comments
    if code.count("{") != code.count("}") or code.count("(") != code.count(")"):
        return False
    return True


def _json_loads_lenient(s: str):
    """json.loads, but first rewrite bare hex integer literals (0x7FFFFFFF) to
    decimal. The model habitually puts hex in input_sets (0x80000000, 0x7FFFFFFF)
    even though JSON has no hex literals, which makes json.loads reject the WHOLE
    block -> a correct reimpl gets scored malformed_response (found 2026-07-08:
    GetAnimSequenceRecord drew hex in all 3 attempts). The lookbehind avoids
    touching hex inside quoted strings/identifiers. Raises JSONDecodeError like
    json.loads on anything still malformed."""
    return json.loads(_HEX_LITERAL_RE.sub(lambda m: str(int(m.group(0), 16)), s or ""))


def parse_handle_response(text: str):
    """(reimpl_cpp, param_layout, input_sets) from a build_handle_draft_prompt reply.
    (None,None,None) on any failure. param_layout must have handle_arg + callconv."""
    import port_pipeline as pp
    blocks = pp._fenced_blocks(text or "")
    cpp = [c for lang, c in blocks if lang in pp._CPP_LANGS]
    js = [c for lang, c in blocks if lang in pp._JSON_LANGS]
    # LAST-valid-block-wins (2026-07-14): when the deliverable is salvaged from
    # the reasoning channel the text contains MANY draft iterations; the final
    # one is the model's actual answer. Scanning for validity (instead of
    # blindly taking [0]) also survives stray early snippets in normal replies.
    layout = input_sets = None
    for c in reversed(js):
        try:
            s = _json_loads_lenient(c)
        except json.JSONDecodeError:
            continue
        lay = s.get("param_layout") if isinstance(s, dict) else None
        if isinstance(lay, dict) and lay.get("handle_arg"):
            layout, input_sets = lay, s.get("input_sets")
            break
    if layout is None:
        return None, None, None
    if not isinstance(input_sets, list) or not input_sets:
        input_sets = [{}]
    body = next((c for c in reversed(cpp) if _is_provider_reimpl(c)), None)
    if body is None:   # reject OpenD2/non-extern-C drafts (build poison)
        return None, None, None
    reimpl = body.strip() + "\n"
    if 'provider_runtime.h' not in reimpl:
        reimpl = '#include "../provider_runtime.h"\n' + reimpl
    return reimpl, layout, input_sets


def build_handle_spec(name: str, address, param_layout: dict) -> dict:
    """fun-doc handle param_layout -> oracle spec: arg0 = the captured live object
    (kind 'handle'), followed by scalar args (kind 'i32') the vectors fill."""
    cc = str(param_layout.get("callconv", "stdcall")).lower()
    if cc not in ("stdcall", "fastcall", "cdecl", "thiscall"):
        cc = "stdcall"
    ret = str(param_layout.get("ret", "i32")).lower()
    if ret not in ("i32", "u32", "void", "u8", "i8"):   # u8/i8: byte getters (CONCAT31 artifact)
        ret = "i32"
    args = [{"id": param_layout["handle_arg"], "kind": "handle"}]
    for s in param_layout.get("scalar_args", []) or []:
        args.append({"id": str(s), "kind": "i32"})
    return {
        "name": name, "addr": _int(address), "callconv": cc, "ret": ret,
        "args": args, "compare": [] if ret == "void" else ["ret"],
        "onGameThread": True,  # the object is live game state -- call on the game thread
    }


_GATE_W = {"b": 1, "w": 2, "d": 4}


def _gate_spec(gates):
    """abi_static type_gates [(depth,off,imm,w_char)] -> oracle spec [{depth,off,imm,w}]."""
    return [{"depth": d, "off": o, "imm": i, "w": _GATE_W.get(w, 4)}
            for (d, o, i, w) in (gates or [])]


def run_synth_prove(reimpl_cpp: str, name: str, address, *, program: str, ret: str = "u32",
                    struct_size: int = 256, gates=None, build: bool = True) -> dict:
    """Prove a FLAT getter (a single fixed-offset read, no sub-pointer deref) via the
    oracle's SYNTHETIC DISCRIMINATING object (arg kind 'synth', 2026-07-08). The oracle
    passes both the original and the reimpl a scratch buffer whose every byte is unique
    to its offset, so a getter reading a fixed field returns a value UNIQUE to that
    offset -- a wrong-offset reimpl MISMATCHES the original. This kills the degenerate
    all-zeros false positive that idle-town live captures produce (a weak_proof), giving
    a STRONG proof for exactly the flat-getter class the mechanical translator emits.

    CALLER MUST ensure the getter is FLAT -- a synth byte is not a valid pointer, so a
    sub-deref getter would fault. (chain length 1 from abi_static.translate_getter_to_c.)"""
    parg = {"id": "p", "kind": "synth", "bytes": struct_size}
    gspec = _gate_spec(gates)
    if gspec:
        parg["gates"] = gspec
    _cc, _ccnote = resolve_callconv(name, address, program, 1)
    if _ccnote:
        print(f"  [callconv] {name}: {_ccnote}", flush=True)
    spec = {"name": name, "addr": _int(address), "callconv": _cc,
            "ret": ret if ret in ("u8", "i8", "u16", "i16", "u32", "i32") else "u32",
            "args": [parg],
            "compare": ["ret"],
            "vectors": [{}]}
    write_candidate(reimpl_cpp, name)
    spec_path = _write_spec(spec, name, program)
    if build:
        b = build_provider_attributed(name)
        if not b["ok"]:
            res = _fail(b["stage"], b["detail"])
            res["spec"] = spec
            return res
    res = _invoke_prove(spec_path, build=False)
    res["spec"] = spec
    res["proof_kind"] = "synth"          # a discriminating proof -- never weak
    if res.get("ok"):
        res["writeback"] = record_proof(name, address, spec, res, program=program)
    return res


def run_synth2_prove(reimpl_cpp: str, name: str, address, *, program: str, ret: str = "u32",
                     gates=None, build: bool = True) -> dict:
    """Prove a 2-LEVEL getter (read a pointer at O1, deref, read the field at O2 --
    no third level) via the oracle's NESTED discriminating object (arg kind
    'synth2', 2026-07-08). The primary buffer is an array of pointers all pointing at
    a shared secondary buffer whose byte[o]=(o*13+0x37) is unique per offset, so the
    getter returns pattern(O2) and a wrong FIELD offset MISMATCHES the original. This
    lifts the degenerate-town-capture weak_proof for the 2-level getter class -- the
    majority of struct getters -- which flat synth can't reach.

    CALLER MUST ensure the getter is exactly 2-level (chain length 2 from
    abi_static.translate_getter_to_c); a 3rd deref would read the pattern as a
    pointer and fault."""
    parg = {"id": "p", "kind": "synth2", "bytes": 256}
    gspec = _gate_spec(gates)
    if gspec:
        parg["gates"] = gspec
    _cc, _ccnote = resolve_callconv(name, address, program, 1)
    if _ccnote:
        print(f"  [callconv] {name}: {_ccnote}", flush=True)
    spec = {"name": name, "addr": _int(address), "callconv": _cc,
            "ret": ret if ret in ("u8", "i8", "u16", "i16", "u32", "i32") else "u32",
            "args": [parg],
            "compare": ["ret"], "vectors": [{}]}
    write_candidate(reimpl_cpp, name)
    spec_path = _write_spec(spec, name, program)
    if build:
        b = build_provider_attributed(name)
        if not b["ok"]:
            res = _fail(b["stage"], b["detail"])
            res["spec"] = spec
            return res
    res = _invoke_prove(spec_path, build=False)
    res["spec"] = spec
    res["proof_kind"] = "synth2"        # discriminates the field offset -- never weak
    if res.get("ok"):
        res["writeback"] = record_proof(name, address, spec, res, program=program)
    return res


_DELEGATE_INDICES = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]


def run_delegate_prove(reimpl_cpp: str, name: str, address, *, program: str, ret: str = "u32",
                       arg_off: int, type_gates=None, indices=None,
                       build: bool = True) -> dict:
    """Prove a DELEGATE call-through getter (abi_static.translate_delegate_getter_to_c):
    it resolves + calls a REAL D2Common function, so the callee's data-globals must be
    LOADED -> this only works IN-GAME (at the title screen the callee's tables are NULL
    and every vector degenerates). Strategy: a MULTI-INDEX gated synth -- patch the
    dwType gate(s) + the callee's arg field to each of several record INDICES, so the
    real callee returns a real (different) record per index. STRONG iff the reimpl
    matches the original on EVERY index AND the original's value VARIES across indices
    (a UNIFORM original = the read field is constant -> a wrong offset would match too ->
    can't discriminate -> weak_proof, not strong). This variance check is the delegate
    analogue of _degenerate_capture_note (single-vector synth can't see it)."""
    idxs = indices or _DELEGATE_INDICES
    base_gates = _gate_spec([(0, g[0], g[1], g[2]) for g in (type_gates or [])])
    rr = ret if ret in ("u8", "i8", "u16", "i16", "u32", "i32") else "u32"
    write_candidate(reimpl_cpp, name)
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    if build:
        b = build_provider_attributed(name)
        if not b["ok"]:
            r = _fail(b["stage"], b["detail"]); r["proof_kind"] = "delegate"; return r

    npass = 0
    orig_vals = set()
    last = None
    # Resolved ONCE, outside the sweep: every vector calls the same function,
    # so the convention cannot change per-index and re-deriving it would cost
    # one Ghidra round-trip per probe.
    _cc, _ccnote = resolve_callconv(name, address, program, 1)
    if _ccnote:
        print(f"  [callconv] {name}: {_ccnote}", flush=True)
    for i in idxs:
        parg = {"id": "p", "kind": "synth", "bytes": 256,
                "gates": base_gates + [{"depth": 0, "off": arg_off, "imm": i, "w": 4}]}
        spec = {"name": name, "addr": _int(address), "callconv": _cc, "ret": rr,
                "args": [parg], "compare": ["ret"], "vectors": [{}]}
        sp = _write_spec(spec, name, program)
        r = _invoke_prove(sp, build=False)
        last = r
        if r.get("ok"):
            npass += 1
        ov = (r.get("oracle") or {}).get("results") or []
        for row in ov:
            rr_ = row.get("ret")
            if isinstance(rr_, dict) and "o" in rr_:
                orig_vals.add(rr_["o"])
        # oracle death mid-sweep -> stop (don't burn the rest against a dead bridge)
        if r.get("failure_stage") == "oracle_died_during":
            break

    res = {"passed": npass, "total": len(idxs), "stage": "prove",
           "output": (last or {}).get("output", ""), "spec": spec,
           "proof_kind": "delegate_call_through", "orig_distinct": len(orig_vals)}
    if npass == len(idxs) and len(orig_vals) > 1:
        res["ok"] = True
        res["writeback"] = record_proof(name, address, spec, res, program=program)
        res["note"] = f"delegate call-through; discriminating multi-index ({npass}/{len(idxs)}, orig varies)"
    elif npass == len(idxs) and len(orig_vals) <= 1:
        res["ok"] = False
        res["failure_stage"] = "weak_uniform"
        res["failure_detail"] = ("delegate matched all indices but the ORIGINAL returned a "
                                 "single value on every index (uniform field) -> non-discriminating")
    else:
        res["ok"] = False
        res["failure_stage"] = (last or {}).get("failure_stage", "mismatch")
        res["failure_detail"] = f"delegate matched only {npass}/{len(idxs)} indices"
    return res


def run_handle_prove(reimpl_cpp: str, name: str, address, param_layout: dict,
                     input_sets: list, *, program: str, build: bool = True) -> dict:
    """Prove a live-pointer getter against the running game via the oracle handle
    path (a real captured object is passed to both original and reimpl). Same
    {ok,passed,total,output,...} shape as run_live_prove."""
    spec = build_handle_spec(name, address, param_layout)
    # scalar-arg vectors only; the handle arg is filled by the oracle from capture.
    # For a HANDLE-ONLY getter, emit N empty vectors: the oracle snapshots
    # D2Capture_LastUnit() once PER vector, and the game thread advances the captured
    # object between iterations, so N vectors prove against up to N DISTINCT live
    # objects (guards the "matched by luck on one object" risk) and confirm
    # determinism. With scalar args, sweep those instead.
    HANDLE_ONLY_VECTORS = 8
    scalar_ids = [a["id"] for a in spec["args"] if a["kind"] == "i32"]
    spec["vectors"] = ([{k: case.get(k, 0) for k in scalar_ids} for case in input_sets]
                       if scalar_ids else [{} for _ in range(HANDLE_ONLY_VECTORS)])
    write_candidate(reimpl_cpp, name)
    spec_path = _write_spec(spec, name, program)
    if build:
        # attributed + self-healing build: a broken SIBLING candidate is healed
        # instead of failing THIS (possibly correct) reimpl; our own compile
        # errors come back as build_candidate with the real compiler message.
        b = build_provider_attributed(name)
        if not b["ok"]:
            res = _fail(b["stage"], b["detail"])
            res["spec"] = spec
            return res
    res = _invoke_prove(spec_path, build=False)
    res["spec"] = spec
    # Surface the per-vector dispatch-field probe (dwType of each captured object)
    # for the post-proof BRANCH-COVERAGE analysis.
    oracle = res.get("oracle")
    if oracle and isinstance(oracle.get("results"), list):
        res["dispatch_values"] = [r["probe"][0] for r in oracle["results"]
                                  if isinstance(r.get("probe"), list) and r["probe"]]
    res["weak_proof"] = _degenerate_capture_note(oracle)
    if res.get("ok"):
        res["writeback"] = record_proof(name, address, spec, res, program=program,
                                        weak_proof=res["weak_proof"])
    return res


def _degenerate_capture_note(oracle) -> str | None:
    """A handle proof is DEGENERATE if the ORIGINAL returned the SAME value on every
    vector -- then a wrong-offset reimpl matches by luck (all-zeros) and earns a
    FALSE CONF_LIVE. Exactly how STAT_GetActiveSkillFieldC / SKILLS_GetActiveSkillAnimData
    passed 8/8 on idle-town captures yet diverged ~99% under shadow (2026-07-08). If
    every original return is identical (esp. 0), flag it so the row can't silently
    promote/freeze until DIVERSE objects (dispatch values) are seen. Returns a note
    or None."""
    if not oracle or not isinstance(oracle.get("results"), list):
        return None
    results = oracle["results"]
    orig_rets = [r["ret"]["o"] for r in results
                 if isinstance(r.get("ret"), dict) and "o" in r["ret"]]
    if len(orig_rets) < 2:
        return None
    distinct = set(orig_rets)
    # distinct captured objects seen (probe dispatch field), if available
    probes = {r["probe"][0] for r in results if isinstance(r.get("probe"), list) and r["probe"]}
    if len(distinct) == 1:
        v = next(iter(distinct))
        objs = f", only {len(probes)} distinct object(s)" if probes else ""
        return (f"DEGENERATE CAPTURE: the original returned the SAME value ({v}) on all "
                f"{len(orig_rets)} vectors{objs} -- a wrong-offset reimpl matches by luck. "
                f"This CONF_LIVE proof is WEAK; re-prove against DIVERSE objects (or trust "
                f"shadow/V2) before promoting or freezing.")
    return None


def provider_outcome(text, meta) -> str:
    """Classify an invoke_claude (text, meta) result so the retry loop can tell a
    PROVIDER hiccup from a MODEL/reimpl problem -- they need opposite handling:
      'quota'       -> paused; stop.
      'hiccup'      -> the PROVIDER misbehaved (empty/None text, or a timeout/error
                       marker in meta). This is NOT a bad reimpl -- retry the SAME
                       prompt without consuming the fix budget, and DON'T discard the
                       last good draft (2026-07-08: a minimax 300s hard-timeout mid-
                       retry stranded PATH_GetDirection on a wrong u32 attempt after
                       the correct u8 was already found).
      'got_text'    -> the provider returned content; parse it normally.
    """
    if (meta or {}).get("quota_paused"):
        return "quota"
    m = meta or {}
    if m.get("timeout") or m.get("hard_timeout") or m.get("error") or m.get("stalled"):
        return "hiccup"
    if not (text or "").strip():
        return "hiccup"
    return "got_text"


class BestDraft:
    """Accumulator that keeps the highest-scoring parseable draft across retries, so
    a later provider hiccup or a worse re-draft never loses earlier progress. Score =
    proven (ok) > more vectors passed > first seen."""
    __slots__ = ("reimpl", "layout", "input_sets", "score", "result")

    def __init__(self):
        self.reimpl = self.layout = self.input_sets = self.result = None
        self.score = (-1, -1)

    def offer(self, reimpl, layout, input_sets, result) -> None:
        if reimpl is None:
            return
        ok = 1 if (result or {}).get("ok") else 0
        passed = (result or {}).get("passed") or 0
        s = (ok, passed)
        if s > self.score:
            self.reimpl, self.layout, self.input_sets = reimpl, layout, input_sets
            self.result, self.score = result, s

    def have(self) -> bool:
        return self.reimpl is not None


def build_adversarial_vectors_prompt(func_name: str, decompiled_text: str,
                                     input_names: list) -> str:
    """QA/adversary prompt: generate a hard input-set purely from the DECOMPILED
    ORIGINAL (never shown the reimpl), to catch a subtly-wrong reimplementation
    the author's own vectors would miss. Rung V1 of SHIPPING_PROMOTION_PLAN.md."""
    parts = []
    parts.append("OUTPUT CONTRACT: reply with EXACTLY ONE ```json block and nothing else: "
                 '{"input_sets": [ {..}, {..} ]}.')
    parts.append("")
    parts.append(f"## You are QA. Try to BREAK a reimplementation of {func_name} with adversarial inputs.")
    parts.append(
        "Below is the DECOMPILED ORIGINAL. You will NOT see the reimplementation -- derive inputs purely "
        "from what the ORIGINAL does, to maximize the chance of exposing a subtly-wrong reimpl. Cover: "
        "EVERY branch boundary the code compares against and +/-1 around it; a DENSE sweep of the valid "
        "input range; and the extremes 0, 1, -1, INT_MIN (-2147483648), INT_MAX (2147483647), and powers "
        "of two. Aim for 30-50 input_sets.")
    parts.append("")
    parts.append("## Decompiled original (the spec)")
    parts.append("```")
    parts.append(str(decompiled_text))
    parts.append("```")
    parts.append("Input field names -- use EXACTLY these keys in every input_set: " + ", ".join(input_names))
    parts.append("```json")
    parts.append(json.dumps({"input_sets": [
        {n: 0 for n in input_names}, {n: 1 for n in input_names}, {n: -1 for n in input_names},
    ]}, indent=2))
    parts.append("```")
    return "\n".join(parts)


def parse_adversarial_vectors(text: str, input_names: list) -> list:
    """Extract input_sets from a build_adversarial_vectors_prompt reply. Returns []
    on any failure (vetting is best-effort -- a bad adversary reply just means no
    extra coverage that round, never a broken proof)."""
    import port_pipeline as pp
    blocks = pp._fenced_blocks(text or "")
    js = [c for lang, c in blocks if lang in pp._JSON_LANGS]
    if not js:
        return []
    try:
        obj = json.loads(js[0])
    except json.JSONDecodeError:
        return []
    sets = obj.get("input_sets") if isinstance(obj, dict) else obj
    if not isinstance(sets, list):
        return []
    out = []
    for s in sets:
        if isinstance(s, dict) and all(n in s for n in input_names):
            out.append({n: s[n] for n in input_names})
    return out


def build_live_fix_prompt(func_name: str, decompiled_text: str, prior_reimpl: str,
                          prove_output: str) -> str:
    parts = []
    parts.append(
        "OUTPUT CONTRACT: reply with EXACTLY TWO fenced blocks -- BLOCK 1 ```cpp (the corrected "
        "reimpl), BLOCK 2 ```json (the SAME register layout + input_sets as before). Nothing else.")
    parts.append("")
    parts.append(f"## Your reimpl of {func_name} did not prove against the live game. Fix it.")
    parts.append(
        "The oracle called BOTH the original (in the running game) and your reimpl with each input and "
        "compared. Read the result carefully:")
    parts.append("```")
    parts.append((prove_output or "(no output)")[-2500:])
    parts.append("```")
    parts.append(
        "IMPORTANT diagnostic: if it MATCHES on out-of-range/negative inputs (the null path) but FAILS "
        "on valid in-range ones, you dereferenced a resolved global one level too FEW or too MANY -- "
        "re-check the pointer-vs-base STEP 1 rule (a `g_p*` pointer variable needs "
        "`base = *(void**)D2MOO_Resolve(\"g_p...\")`).")
    parts.append("")
    parts.append("## Decompiled source (the spec)")
    parts.append("```")
    parts.append(str(decompiled_text))
    parts.append("```")
    parts.append("## Your previous reimpl")
    parts.append("```cpp")
    parts.append(prior_reimpl)
    parts.append("```")
    parts.append(
        "Output the corrected ```cpp reimpl and the ```json layout+input_sets. Keep the include and the "
        "// D2MOO_REIMPL_EXPORT marker.")
    return "\n".join(parts)


def parse_live_response(text: str):
    """Extract (reimpl_cpp, param_layout, input_sets) from a build_live_draft_prompt
    reply (1 cpp block + 1 json block). Returns (None, None, None) on any failure."""
    import port_pipeline as pp  # reuse the tolerant fenced-block splitter
    blocks = pp._fenced_blocks(text or "")
    cpp = [c for lang, c in blocks if lang in pp._CPP_LANGS]
    js = [c for lang, c in blocks if lang in pp._JSON_LANGS]
    # LAST-valid-block-wins — see parse_handle_response for rationale.
    layout = input_sets = None
    for c in reversed(js):
        try:
            s = _json_loads_lenient(c)
        except json.JSONDecodeError:
            continue
        lay = s.get("param_layout") if isinstance(s, dict) else None
        ins = s.get("input_sets") if isinstance(s, dict) else None
        if (isinstance(lay, dict) and "inputs" in lay and "outputs" in lay
                and isinstance(ins, list) and ins):
            layout, input_sets = lay, ins
            break
    if layout is None:
        return None, None, None
    body = next((c for c in reversed(cpp) if _is_provider_reimpl(c)), None)
    if body is None:   # reject OpenD2/non-extern-C drafts (build poison)
        return None, None, None
    reimpl = body.strip() + "\n"
    if 'provider_runtime.h' not in reimpl:  # ensure the resolver header is present
        reimpl = '#include "../provider_runtime.h"\n' + reimpl
    return reimpl, layout, input_sets


def remove_candidate(name: str) -> None:
    """Delete a candidate's .cpp + spec. CRITICAL for the automated loop: a
    candidate that fails to PROVE is also often a candidate that fails to COMPILE
    (e.g. an undefined Ghidra type name), and every candidates/*.cpp is compiled
    into the ONE provider DLL -- so one broken file poisons the build for EVERY
    other function (found by hand 2026-07-07: a --count 20 batch cascaded into
    all-failures after one bad reimpl landed). A failed reimpl has no value staged,
    so remove it; its content is preserved in the run log if needed. Best-effort."""
    for p in (CANDIDATES_DIR / f"{name}.cpp",
              VECTORS_DIR / f"{name}.spec.json",
              VECTORS_DIR / f"{name}.adversarial.spec.json"):
        try:
            p.unlink()
        except OSError:
            pass
    # The file is gone, so the in-flight claim must go with it -- a stale claim
    # would protect a candidate that no longer exists from ever being healed.
    clear_candidate_inflight(name)


QUARANTINE_DIR = CANDIDATES_DIR / "_quarantine"


def quarantine_candidate(name: str, reason: str) -> None:
    """MOVE (not delete) a candidate's .cpp out of the glob path into
    candidates/_quarantine/, for the one duplicate-symbol self-heal case where the
    file being sidelined is NOT known to be broken code (unlike remove_candidate's
    broken-compile siblings) -- it may well be a correct, working reimpl that only
    lost a symbol-name coin flip. CMake's `candidates/*.cpp` glob is non-recursive
    (see CMakeLists.txt) so anything under _quarantine/ silently drops out of the
    build without losing the source. Appends one line to _quarantine/MANIFEST.txt
    so a human can find and review/restore it later. Best-effort."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    src = CANDIDATES_DIR / f"{name}.cpp"
    try:
        src.replace(QUARANTINE_DIR / f"{name}.cpp")
    except OSError:
        return
    try:
        ts = datetime.datetime.utcnow().isoformat()
        with open(QUARANTINE_DIR / "MANIFEST.txt", "a", encoding="utf-8") as f:
            f.write(f"{ts}\t{name}\t{reason}\n")
    except OSError:
        pass
    # Out of the glob path, so it is no longer in flight for anyone.
    clear_candidate_inflight(name)


def write_candidate(reimpl_cpp: str, name: str) -> Path:
    """Drop a drafted D2MOO reimpl into the provider's candidates/ dir. Ensures
    the `// D2MOO_REIMPL_EXPORT: <name>` marker the provider build reads is
    present. Canonical one-file-per-function name avoids duplicate symbols."""
    # Last line of defense against build poison: refuse a non-extern-C draft LOUDLY
    # here rather than let it silently break the whole provider .def at the next build.
    if not _is_provider_reimpl(reimpl_cpp):
        raise ValueError(
            f"write_candidate({name}): content is not a provider reimpl (needs an "
            f'`extern "C"` export, not an OpenD2 `namespace D2Lib` draft) -- refusing to '
            f"write build poison into the provider candidates dir")
    CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    body = reimpl_cpp
    # Output-normalization (phase b): rewrite width spellings to D2MOO's canonical stdint
    # (unsigned int -> uint32_t, uint -> uint32_t, ...). Typedef-identical via <cstdint>, so it
    # can't change compiled behavior -- and the prove that follows this write validates it.
    try:
        import d2moo_types
        body, _n = d2moo_types.normalize_c_types(body)
    except Exception:
        pass
    if "D2MOO_REIMPL_EXPORT:" not in body:
        body = f"// D2MOO_REIMPL_EXPORT: {name}\n{body}"
    path = CANDIDATES_DIR / f"{name}.cpp"
    path.write_text(body, encoding="utf-8")
    # Claim it before any other worker's heal loop can see it. From here until
    # the prove finishes, a concurrent build that trips over this file reports
    # collateral instead of deleting it out from under us.
    mark_candidate_inflight(name)
    return path


def _preflight_spec_target(spec_path: Path) -> dict:
    """bad_target failure for a spec whose module+rva isn't mapped live, else None.

    Sits in front of EVERY prove path (all five run_* functions funnel through
    _invoke_prove), so a base mistake is reported as `bad_target` -- environmental,
    re-queued -- rather than discovered as an SEH fault the taxonomy reads as a
    wrong ABI. Silent on anything it can't judge: this gate exists to remove a
    false NEGATIVE and must never invent a false one of its own."""
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    module, rva = spec.get("module"), spec.get("rva")
    if not module or not isinstance(rva, int):
        return None
    body = _oracle_json("/asset/peek", {"module": module, "rva": rva, "count": 1})
    if not isinstance(body, dict) or not body.get("ok") or int(body.get("got") or 0) > 0:
        return None
    addr = spec.get("addr")
    where = f" (Ghidra 0x{addr:08x})" if isinstance(addr, int) else ""
    return _fail("bad_target",
                 f"bad-target: {module}+0x{rva:x}{where} is not mapped in the running "
                 f"game -- module not loaded, or not at Ghidra's image base. Nothing "
                 f"was called; this is NOT a verdict about the function.")


def _invoke_prove(spec_path: Path, *, build: bool, timeout: int = 900) -> dict:
    """Run prove_candidate.py --spec and map its result to run_harness's shape."""
    if not PROVE_SCRIPT.exists():
        return _fail("config", f"prover not found: {PROVE_SCRIPT}")
    bad = _preflight_spec_target(spec_path)
    if bad:
        print(f"[port_live_prove] {bad['failure_detail']}", file=sys.stderr)
        return bad
    # --json emits the raw per-vector oracle result (incl. the coverage "probe"),
    # which we parse back out for branch-coverage analysis without a second call.
    cmd = [sys.executable, str(PROVE_SCRIPT), "--spec", str(spec_path), "--url", ORACLE_URL, "--json"]
    if build:
        cmd.append("--build")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return _fail("prove", f"prove_candidate.py timed out after {timeout}s")
    out = proc.stdout + proc.stderr
    m = re.search(r"(\d+)/(\d+) match", out)
    passed, total = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    res = {
        "ok": proc.returncode == 0,
        "passed": passed,
        "total": total,
        "stage": "prove",
        "error": "" if proc.returncode == 0 else f"prover exit {proc.returncode}",
        "output": out.strip(),
        "oracle": _extract_oracle_json(out),
    }
    if not res["ok"]:
        stage, detail = _classify_prove_failure(out)
        # upgrade: the bridge was alive when we started (prove ran) but is dead
        # now -> THIS function's vectors killed it. Name the killer.
        if stage in ("marshal_fault", "prove", "mismatch") and not check_oracle_alive():
            stage = "oracle_died_during"
            detail = (f"the oracle bridge died while proving this function "
                      f"(likely an abort-class out-of-range vector or an ABI fault); {detail}")
        res["failure_stage"], res["failure_detail"] = stage, detail
    return res


def _extract_oracle_json(out: str):
    """Pull the raw oracle result object (the one with a 'results' array) out of
    prove_candidate.py --json stdout. Returns the dict or None."""
    i = 0
    while True:
        start = out.find("{", i)
        if start < 0:
            return None
        depth = 0
        for j in range(start, len(out)):
            if out[j] == "{":
                depth += 1
            elif out[j] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(out[start:j + 1])
                        if isinstance(obj, dict) and "results" in obj:
                            return obj
                    except json.JSONDecodeError:
                        pass
                    i = start + 1
                    break
        else:
            return None


# ---------------------------------------------------------------------------
# LIVE IDENTITY: module + RVA, never a Ghidra absolute address (2026-07-30).
#
# Every spec built here used to carry only "addr": the Ghidra absolute address.
# The oracle took it literally, which is sound ONLY for a module that loaded at
# its preferred base. D2Common (0x6fd50000) and D2Game (0x6fc20000) do. D2Client
# does NOT -- the live process maps it at 0x03600000 and leaves Ghidra's
# 0x6fab0000 unmapped -- so the oracle `call`ed unmapped memory, faulted, and
# returned "handler-exception", which _classify_prove_failure files as
# `marshal_fault`: "wrong callconv/slot-count or a bad pointer arg". That verdict
# is terminal, so 104 D2Client functions were retired without their reimpl ever
# executing once (including a zero-arg void setter, for which no ABI theory
# applies). Specs now carry module+rva so the oracle adds the RUNTIME base.
# ---------------------------------------------------------------------------
_IMAGE_BASE_CACHE: dict = {}


def _ghidra_get_json(path: str):
    """GET a Ghidra REST endpoint, returning the decoded payload or None."""
    u = urllib.parse.urlparse(GHIDRA_HTTP)
    conn = http.client.HTTPConnection(u.hostname, u.port or 8089, timeout=15)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        body = json.loads(resp.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None
    finally:
        conn.close()
    # /get_metadata answers {"result": "<json string>"} through the 6.0.0 envelope.
    if isinstance(body, dict) and isinstance(body.get("result"), str):
        try:
            return json.loads(body["result"])
        except ValueError:
            return None
    return body


def module_name_for_program(program) -> str:
    """'/Mods/PD2-S12/D2Client.dll' -> 'D2Client.dll' (the name GetModuleHandleA
    wants). Empty when the caller has no program -- callers must treat that as
    "cannot resolve", never as a default module: a hardcoded 'D2Common.dll'
    default in exactly this position is what wrote every non-D2Common proof's tag
    to the wrong binary for the whole project history (2026-07-27)."""
    if not program:
        return ""
    return str(program).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def ghidra_image_base(program):
    """Ghidra's image base for `program`, or None. Cached per program: it is a
    property of the loaded binary and cannot change under us."""
    module = module_name_for_program(program)
    if not module:
        return None
    if module in _IMAGE_BASE_CACHE:
        return _IMAGE_BASE_CACHE[module]
    meta = _ghidra_get_json(
        "/get_metadata?program=" + urllib.parse.quote(str(program), safe=""))
    base = None
    if isinstance(meta, dict):
        raw = meta.get("base_address") or meta.get("image_base")
        if raw is not None:
            try:
                base = int(str(raw), 16)
            except ValueError:
                base = None
    if base is not None:
        _IMAGE_BASE_CACHE[module] = base
    return base


def stamp_live_identity(spec: dict, program) -> dict:
    """Add "module"+"rva" to a spec so the oracle resolves against the RUNTIME
    base. "addr" is left in place for back-compat with an older D2Debugger and as
    a diagnostic; the oracle prefers module+rva when both are present.

    LOUD on failure, per the loud-failures rule: a spec that silently falls back
    to absolute-only is the pre-fix behaviour, and its failure mode is a false
    verdict about a function, so say so on stderr rather than degrade quietly."""
    module = module_name_for_program(program)
    base = ghidra_image_base(program)
    addr = spec.get("addr")
    if not module or base is None or not isinstance(addr, int):
        print(f"[port_live_prove] WARNING: cannot stamp live identity for "
              f"{spec.get('name')!r} (module={module!r} image_base={base!r} "
              f"addr={addr!r}) -- the oracle will fall back to the absolute "
              f"address, which is WRONG for any relocated module",
              file=sys.stderr)
        return spec
    if addr < base:
        print(f"[port_live_prove] WARNING: {spec.get('name')!r} addr 0x{addr:08x} is "
              f"below {module}'s image base 0x{base:08x} -- not stamping module+rva",
              file=sys.stderr)
        return spec
    spec["module"] = module
    spec["rva"] = addr - base
    return spec


def _oracle_json(path: str, payload=None):
    """One request to the oracle; None on any failure (caller decides what that
    means -- an unreachable oracle is a separate environmental case)."""
    u = urllib.parse.urlparse(ORACLE_URL)
    conn = http.client.HTTPConnection(u.hostname, u.port or 8790, timeout=10)
    try:
        if payload is None:
            conn.request("GET", path)
        else:
            conn.request("POST", path, json.dumps(payload),
                         {"Content-Type": "application/json"})
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        return json.loads(resp.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None
    finally:
        conn.close()


def oracle_live_bases() -> dict:
    """{module_lower: live_base} from GET /modules; {} if the route is absent
    (an older D2Debugger) or the oracle is unreachable."""
    body = _oracle_json("/modules")
    if not isinstance(body, dict) or not body.get("ok"):
        return {}
    out = {}
    for entry in body.get("modules") or []:
        name, base = entry.get("name"), entry.get("base")
        if isinstance(name, str) and isinstance(base, int):
            out[name.lower()] = base
    return out


def oracle_supports_module_rva():
    """True/False when the oracle answered, None when it didn't.

    An oracle without `specModuleRva` IGNORES the module+rva we stamp and falls
    back to the absolute address -- correct only for a module at its preferred
    base. Proving a RELOCATED module against such a build is what produced 104
    false terminal verdicts, so check_live_target refuses that combination
    outright rather than let it look like an ABI failure again."""
    body = _oracle_json("/status")
    if not isinstance(body, dict) or not body.get("ok"):
        return None
    return bool(body.get("specModuleRva"))


def live_bytes_differ_from_ghidra(program, addr, module, rva, length: int = 16):
    """True when the live module's bytes at +rva differ from Ghidra's at addr.

    An independent relocation detector that needs NO live base, so it works even
    against an oracle without GET /modules. If the module really were at its
    Ghidra image base, the two reads would be byte-identical; a relocated module
    differs in every absolute operand (Ghidra's `mov eax,[0x6fbcc4d4]` reads back
    as `mov eax,[0x0371c4d4]` when D2Client sits at 0x03600000).

    Returns None when either side can't be read -- and note the one blind spot:
    code with no absolute operands is identical either way, so False is "no
    evidence of relocation", not proof of its absence.

    Worth its own keep beyond the base question: a difference also means the
    Ghidra program is not the binary the game actually loaded, which makes any
    proof against it meaningless. (Both PD2 programs here have an
    `executable_path` under ProjectD2_backup, while the game runs ProjectD2.)
    """
    body = _oracle_json("/asset/peek",
                        {"module": module, "rva": rva, "count": max(1, length // 4)})
    if not isinstance(body, dict) or not body.get("ok"):
        return None
    vals = body.get("vals") or []
    if len(vals) < max(1, length // 4):
        return None
    live = b"".join(int(v & 0xFFFFFFFF).to_bytes(4, "little") for v in vals)
    meta = _ghidra_get_json(
        f"/read_memory?address=0x{addr:x}&length={len(live)}&program="
        + urllib.parse.quote(str(program), safe=""))
    if not isinstance(meta, dict):
        return None
    data = meta.get("data")
    if not isinstance(data, list) or len(data) != len(live):
        return None
    return bytes(int(b) & 0xFF for b in data) != live


def check_live_target(program, address) -> tuple:
    """Pre-flight: is `address` reachable in the RUNNING game? (ok, detail).

    Three cheap questions, all BEFORE any draft or build -- so a wrong base costs
    one HTTP round-trip instead of an LLM draft, an adversarial-vector call, a
    cmake+msbuild cycle and a false terminal verdict:

      1. Is module+rva mapped at all?
      2. If the module is RELOCATED, does this oracle actually honour module+rva?
         An older build would silently use the (wrong) absolute address.
      3. Failing a definitive answer to (2) -- an oracle without GET /modules --
         do the live bytes even match Ghidra's? A difference is evidence the
         absolute address is not this function.

    A non-answer from the oracle returns ok=True: an unreachable oracle is a
    separate, already-handled environmental case and must not surface here as a
    bad target."""
    module = module_name_for_program(program)
    base = ghidra_image_base(program)
    try:
        addr = _int(address)
    except (TypeError, ValueError):
        return True, ""
    if not module or base is None or addr < base:
        return True, ""            # can't judge -> don't block
    rva = addr - base

    live = oracle_live_bases().get(module.lower())
    supports = None
    if live is not None and live != base:
        supports = oracle_supports_module_rva()
        if supports is False:
            return False, (
                f"bad-target: {module} is RELOCATED (live 0x{live:08x} != Ghidra "
                f"0x{base:08x}) and this D2Debugger predates module+rva spec support "
                f"(no specModuleRva in /status) -- it would call the absolute address "
                f"0x{addr:08x}, which is not this function. Rebuild D2Debugger and "
                f"relaunch. Nothing was tested.")
    elif live is None:
        # No GET /modules -> an oracle that predates module+rva. Fall back to the
        # byte comparison, which needs no live base. Without this the pre-relaunch
        # window still produced false ABI verdicts on a relocated module.
        if oracle_supports_module_rva() is False:
            differ = live_bytes_differ_from_ghidra(program, addr, module, rva)
            if differ:
                return False, (
                    f"bad-target: the live bytes at {module}+0x{rva:x} do not match "
                    f"Ghidra's at 0x{addr:08x}, so the module is relocated (or is a "
                    f"different build) -- and this D2Debugger predates module+rva spec "
                    f"support, so it would call 0x{addr:08x} regardless. Rebuild "
                    f"D2Debugger and relaunch. Nothing was tested.")
    body = _oracle_json("/asset/peek", {"module": module, "rva": rva, "count": 1})
    if not isinstance(body, dict) or not body.get("ok"):
        return True, ""
    if int(body.get("got") or 0) > 0:
        return True, ""
    return False, (f"bad-target: {module}+0x{rva:x} (Ghidra 0x{addr:08x}) is not mapped "
                   f"in the running game -- the module is either not loaded or not at "
                   f"Ghidra's image base 0x{base:08x}. Nothing was tested.")


def _write_spec(spec: dict, name: str, program) -> "Path":
    """Stamp the live identity onto `spec` and write it to VECTORS_DIR.

    THE ONLY place a spec reaches disk. Five call sites used to write their own
    (run_synth_prove / run_synth2_prove / run_delegate_prove / run_handle_prove /
    run_live_prove), which is precisely how a whole prove path can miss a
    cross-cutting fix: keeping one writer means module+rva can never be stamped
    onto four of five specs."""
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    stamp_live_identity(spec, program)
    spec_path = VECTORS_DIR / f"{name}.spec.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    return spec_path


def _ghidra_post(path: str, data: dict) -> dict:
    """POST a JSON body to the Ghidra plugin REST server (source of truth).
    Best-effort -- write-back must NEVER fail a proof.

    `program`, if present in `data`, is moved to the URL QUERY string, never
    left in the JSON body. Ghidra's `@McpTool` endpoints declare `program`
    with no explicit `source`, which defaults to `ParamSource.QUERY` (see
    CLAUDE.md "Code Conventions") -- every endpoint this module posts to
    (/add_function_tag, /remove_function_tag, /set_property,
    /create_property_map, /save_program) resolves `program` this way. Before
    2026-07-27 every one of THIS function's callers passed `program` in the
    body instead, where the Java side never looks for it -- it silently fell
    back to Ghidra's ACTIVE program (or 400'd "No function found" when the
    active program didn't have a function at that address). That is the
    actual mechanism behind the wrong-binary tag writes this module produced
    for its entire history: fixing the Python-level `program` plumbing (this
    same commit) was necessary but not sufficient without this half too."""
    data = dict(data)
    program = data.pop("program", None)
    if program:
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}{urllib.parse.urlencode({'program': program})}"
    u = urllib.parse.urlparse(GHIDRA_HTTP)
    conn = http.client.HTTPConnection(u.hostname, u.port or 8089, timeout=15)
    try:
        conn.request("POST", path, body=json.dumps(data),
                     headers={"Content-Type": "application/json"})
        raw = conn.getresponse().read().decode("utf-8", "replace")
    except OSError as e:
        return {"error": f"ghidra unreachable: {e}"}
    finally:
        conn.close()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": raw[:200]}


# Conformance-proof tag ladder (CONF_ axis), rungs low->high. Mutually exclusive:
# promoting to one rung removes the others. See the conformance taxonomy in
# conformance/CONFORMANCE_TAXONOMY.md.
CONF_TAGS = ["CONF_DRAFT", "CONF_VECTORS", "CONF_LIVE", "CONF_BATTLETESTED"]
# Orthogonal documentation-maturity ladder (DOC_ axis). Set by the documentation
# workflow (not proving). Also mutually exclusive.
DOC_TAGS = ["DOC_DRAFT", "DOC_REVIEWED", "DOC_VERIFIED"]


def _set_rung(address, level: str, ladder, program: str) -> dict:
    """Set ONE rung on a mutually-exclusive Ghidra tag ladder: remove the other
    rungs, add this one. Additive to OTHER axes and to decompiler comments.
    Best-effort -- never raises, so a write-back failure can't fail a proof --
    but LOUD: `program` has no default (2026-07-27: a hardcoded "D2Common.dll"
    default silently wrote every non-D2Common proof's tag to the wrong binary
    -- and often to no function at all, since the address rarely resolves in
    D2Common -- for the whole project history; nothing ever surfaced it because
    the failed /add_function_tag call was swallowed here). Callers MUST pass
    the function's actual program; omitting it is now a TypeError, not a silent
    wrong-binary write. Shared by the DOC_ and CONF_ write-backs."""
    if level not in ladder:
        return {"status": f"bad level {level!r} (want one of {ladder})"}
    addr = f"0x{address:x}" if isinstance(address, int) else str(address)
    others = ",".join(t for t in ladder if t != level)
    _ghidra_post("/remove_function_tag", {"function": addr, "tags": others, "program": program})
    tag = _ghidra_post("/add_function_tag", {"function": addr, "tags": level, "program": program})
    ok = tag.get("status") == "success"
    if not ok:
        print(f"  [write-back WARN] Ghidra tag write FAILED: {level} @ {addr} "
              f"(program={program!r}): {str(tag.get('error', tag))[:200]}")
    return {"level": level, "status": "ok" if ok else tag.get("error", tag)}


def set_doc_level(address, doc_level: str, *, program: str) -> dict:
    """WRITE-BACK the DOC_ documentation-maturity rung in Ghidra (source of truth),
    mutually exclusive. Call from fun-doc's documentation stages:
      first-pass model doc            -> DOC_DRAFT
      passed review/score >= threshold-> DOC_REVIEWED  (ABI confirmed from disasm)
      fully ground-truthed            -> DOC_VERIFIED
    Orthogonal to CONF_* and non-destructive to decompiler comments."""
    return _set_rung(address, doc_level, DOC_TAGS, program)


_PROP_ENDPOINTS_AVAILABLE: bool | None = None


def _property_endpoints_available() -> bool:
    """The Conf property-map endpoints live on the ghidra-mcp branch
    feat/program-options-property-map-tools, which is NOT in the deployed plugin
    (found 2026-07-15: /set_property 404'd silently since the 5.16.2 jar deploy,
    losing every prove-time proof-detail write). Probe once per process; when the
    endpoints are missing, the proof record goes into the function's CONFORMANCE
    bookmark instead -- same record, same address, readable by the dashboard and
    sync_conformance_to_ghidra.py --export. A transient unreachable Ghidra is NOT
    cached, so a later proof re-probes."""
    global _PROP_ENDPOINTS_AVAILABLE
    if _PROP_ENDPOINTS_AVAILABLE is None:
        u = urllib.parse.urlparse(GHIDRA_HTTP)
        conn = http.client.HTTPConnection(u.hostname, u.port or 8089, timeout=10)
        try:
            conn.request("GET", "/list_properties?map=Conf")
            _PROP_ENDPOINTS_AVAILABLE = conn.getresponse().status != 404
        except OSError:
            return False               # unreachable: don't cache, just fall through
        finally:
            conn.close()
    return _PROP_ENDPOINTS_AVAILABLE


def _conf_record_json(row: dict) -> str:
    """The compact proof record stored in the `Conf` property map (Ghidra = single source
    of truth for the semantic proof facts; a typed per-address map, queryable via
    list_properties -- not a bookmark comment). Kept in sync with
    conformance/tools/sync_conformance_to_ghidra.py::_conf_record so a prove-time write
    and a later reconcile agree byte-for-byte. Only durable proof facts -- never
    queue/token/telemetry state."""
    rec: dict = {"conf": row.get("conf")}
    if row.get("proof_kind"):
        rec["method"] = row["proof_kind"]
    for k in ("vectors", "passed", "total", "ret", "callconv", "orig_regs", "date"):
        v = row.get(k)
        if v not in (None, "", 0):
            rec[k] = v
    rec["reimpl"] = f"candidates/{row.get('name')}.cpp"
    for flag in ("abort_class", "weak_proof", "needs_review"):
        if row.get(flag):
            rec[flag] = row[flag]
    return json.dumps(rec, separators=(",", ":"))


def record_proof(name: str, address, spec: dict, result: dict, *,
                 program: str, conf_level: str = "CONF_LIVE",
                 abort_class: bool = False, weak_proof: str = None) -> dict:
    """WRITE-BACK (see the writeback-source-of-truth principle). On a successful
    live proof, make GHIDRA the source of truth for the proof, three ways:
      (1) set the CONF_ rung tag (mutually exclusive -- removes the other CONF_ rungs),
      (2) write the compact proof record (method, vectors, ABI, date, reimpl path) into
          the `Conf` PROPERTY MAP -- Ghidra's typed per-address store, queryable via
          list_properties -- so the DETAIL is authoritative at prove time, not just after
          a sync_conformance_to_ghidra.py reconcile, and
      (3) append a machine-readable row to conformance/proven_functions.jsonl -- now a
          git-tracked MIRROR of (1)+(2).
    Additive to the DOC_ axis and decompiler comments (never clobbered). Each write is
    independent best-effort; never raises -- but every failure prints a loud
    `[write-back WARN]` (see _set_rung's docstring for why: a silently-swallowed
    write-back is how the wrong-binary default and a lost 5-day property-write outage
    both went unnoticed). `program` has no default -- the caller must know which
    binary it just proved a function in.

    conf_level defaults to CONF_LIVE (the live-oracle proof). A future battle-test
    promoter passes CONF_BATTLETESTED (earned by zero shadow divergences in real
    gameplay)."""
    status = {"ghidra_tag": None, "property": None, "registry": None}
    a = spec.get("addr", address)
    addr = f"0x{a:x}" if isinstance(a, int) else str(a)

    # Mutual exclusivity handled by the shared ladder helper (which itself prints
    # a WARN on failure -- this line just folds that outcome into `status`).
    r = _set_rung(addr, conf_level, CONF_TAGS, program)
    status["ghidra_tag"] = f"{conf_level}={r['status']}"

    row = {
        "name": name, "address": addr, "program": program,
        "conf": conf_level,
        "callconv": spec.get("callconv"), "ret": spec.get("ret"),
        "orig_regs": spec.get("orig_regs"),
        "vectors": len(spec.get("vectors", [])),
        "passed": result.get("passed"), "total": result.get("total"),
        "date": datetime.date.today().isoformat(),
    }
    if abort_class or spec.get("abort_class"):
        # out-of-range input is FATAL: V1 adversarial (and any fuzzing tool
        # reading this registry) must stay in-envelope or skip entirely.
        row["abort_class"] = True
    if weak_proof:
        # DEGENERATE capture -> this CONF_LIVE proof matched by luck; must not
        # silently promote/freeze. shadow_promote + freeze tooling should honor this.
        row["weak_proof"] = weak_proof
    # proof provenance (synth / synth2 / delegate_call_through) + delegate metadata,
    # so the record is self-describing (a delegate row names its callee).
    for _k in ("proof_kind", "callee", "note"):
        if result.get(_k) is not None:
            row[_k] = result[_k]

    # (2) `Conf` property map -- Ghidra's purpose-built per-address store is authoritative
    # for the proof detail (typed, queryable via list_properties, no bookmark/plate
    # pollution). Ensure the map exists, then set this function's record.
    try:
        rec = _conf_record_json(row)
        if _property_endpoints_available():
            p = _ghidra_post("/set_property", {"map": "Conf", "address": addr, "value": rec, "program": program})
            if not p.get("success") and "No property map" in str(p):
                _ghidra_post("/create_property_map", {"name": "Conf", "type": "string", "program": program})
                p = _ghidra_post("/set_property", {"map": "Conf", "address": addr, "value": rec, "program": program})
        else:
            # property endpoints missing in the deployed plugin -> CONFORMANCE bookmark
            # is the store (program is a QUERY param on the bookmark endpoints)
            p = _ghidra_post("/set_bookmark?" + urllib.parse.urlencode({"program": program}),
                             {"address": addr, "category": "CONFORMANCE", "comment": rec})
        status["property"] = "ok" if p.get("success") else p.get("error", p)
    except OSError as e:
        status["property"] = f"error: {e}"
    if status["property"] != "ok":
        # a swallowed contract violation hid 5 days of lost writes -- be loud, stay non-fatal
        print(f"  [write-back WARN] Ghidra proof-detail write FAILED for {name} @ {addr}: "
              f"{str(status['property'])[:160]}")

    # (3) git-tracked registry mirror.
    try:
        PROVEN_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
        with open(PROVEN_REGISTRY, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        status["registry"] = str(PROVEN_REGISTRY)
    except OSError as e:
        status["registry"] = f"error: {e}"
        print(f"  [write-back WARN] registry mirror write FAILED for {name} @ {addr}: {e}")

    # (4) per-proof save -- persist the tag + property to the .rep immediately. Chosen
    # cadence: zero-loss over speed. save_program is a full program save, so batches run
    # slower, but no Ghidra write is ever lost to an unexpected close/crash.
    try:
        saved = _ghidra_post("/save_program", {"program": program})
        status["saved"] = "ok" if saved.get("success", True) else saved.get("error", saved)
    except OSError as e:
        status["saved"] = f"error: {e}"
    if status["saved"] != "ok":
        print(f"  [write-back WARN] save_program FAILED for {name} @ {addr} "
              f"(program={program!r}): {str(status['saved'])[:160]}")
    return status


def run_live_prove(reimpl_cpp: str, name: str, address, param_layout: dict,
                   input_sets: list, *, program: str, build: bool = True,
                   abort_class: bool = False) -> dict:
    """Prove a D2MOO reimpl of `name` against the live game. Writes the reimpl
    into the provider, translates fun-doc's layout+cases into an oracle spec,
    and runs the prover. Returns run_harness's {ok,passed,total,output,...}.
    Raises UnsupportedLiveABI (caller falls back to static) for exotic ABIs.

    abort_class=True stamps the spec with a safety/envelope annotation (the
    function's out-of-range path is FATAL -- see abi_static.detect_abort_path)
    and flags the registry row so V1 adversarial sweeps skip it."""
    spec = translate_layout_to_spec(name, address, param_layout, program=program)
    spec["vectors"] = [dict(case) for case in input_sets]  # {name:val} == oracle vector
    if abort_class:
        spec["safety"] = ("ABORT CLASS: the original's out-of-range path is fatal "
                          "(_exit/CleanupAndAbort kills the process/bridge). Vectors are "
                          "strictly in-envelope; do NOT fuzz out-of-range (no V1 widening).")
        spec["abort_class"] = True

    write_candidate(reimpl_cpp, name)
    spec_path = _write_spec(spec, name, program)

    if build:
        b = build_provider_attributed(name)   # attributed + self-healing (see docstring)
        if not b["ok"]:
            res = _fail(b["stage"], b["detail"])
            res["spec"] = spec
            return res
    res = _invoke_prove(spec_path, build=False)
    res["spec"] = spec  # additive: lets a caller (e.g. shadow_promote.py) classify
                        # the ABI shape without recomputing translate_layout_to_spec
    if res.get("ok"):
        # Write-back to the source of truth on every successful proof.
        res["writeback"] = record_proof(name, address, spec, res, program=program,
                                        abort_class=abort_class)
    return res


# ---------------------------------------------------------------------------
# Self-test: unit-check the ABI translator, then LIVE-prove against a running
# game using the already-built town-level capstone spec (no rebuild, no write --
# exercises the subprocess+parse contract end to end). Run: python port_live_prove.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # 1) translator unit checks (no side effects)
    fast = translate_layout_to_spec("RNG_Foo", "0x6fd80000", {
        "inputs": [{"name": "seedLo", "register": "ECX", "signed": False},
                   {"name": "seedHi", "register": "EDX", "signed": False}],
        "outputs": [{"name": "ret", "register": "EAX", "signed": False}],
    })
    assert fast["callconv"] == "fastcall" and [a["id"] for a in fast["args"]] == ["seedLo", "seedHi"], fast
    assert fast["compare"] == ["ret"] and fast["addr"] == 0x6FD80000, fast

    stackspec = translate_layout_to_spec("DUNGEON_GetTownLevelIdFromActNo", "0x6fd8b1e0", {
        "inputs": [{"name": "act", "register": "STACK", "signed": False}],
        "outputs": [{"name": "ret", "register": "EAX", "signed": True}],
    })
    assert stackspec["callconv"] == "stdcall" and stackspec["ret"] == "i32", stackspec

    # register-explicit: non-standard reg placement (RNG's max-in-EAX) -> orig_regs
    rng = translate_layout_to_spec("SEED_GetRandomNumber", "0x6fd510b0", {
        "inputs": [{"name": "seed", "register": "ECX"}, {"name": "max", "register": "EAX"}],
        "outputs": [{"name": "ret", "register": "EAX", "signed": False}],
    })
    assert rng.get("orig_regs") == {"ECX": "seed", "EAX": "max"}, rng
    assert rng["callconv"] == "fastcall", rng

    # mixed NON-standard register + stack arg -> still unsupported (regs path is register-only)
    try:
        translate_layout_to_spec("Weird", "0x1", {
            "inputs": [{"name": "a", "register": "ESI"}, {"name": "b", "register": "STACK"}],
            "outputs": []})
        raise SystemExit("FAIL: expected UnsupportedLiveABI for reg+stack mix")
    except UnsupportedLiveABI:
        pass
    print("[ok] translate_layout_to_spec unit checks passed")

    # 2) live integration: prove the already-built town capstone via its spec.
    town_spec = VECTORS_DIR / "town_levelid.spec.json"
    if not town_spec.exists():
        raise SystemExit(f"[skip] {town_spec} missing")
    res = _invoke_prove(town_spec, build=False)
    print(f"[live] {res['stage']}: ok={res['ok']} passed={res['passed']}/{res['total']}")
    if not res["ok"]:
        print(res["output"])
        raise SystemExit("FAIL: live prove of town capstone did not pass")
    print("[ok] live prove contract works (town capstone proven via port_live_prove)")

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

import datetime
import http.client
import json
import os
import re
import subprocess
import sys
import urllib.parse
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


def translate_layout_to_spec(name: str, address, param_layout: dict) -> dict:
    """fun-doc register `param_layout` -> D2MOO oracle spec (callconv/args/
    ret/compare + the original's absolute `addr`). Raises UnsupportedLiveABI for
    register ABIs the v1 marshaller can't express."""
    inputs = param_layout.get("inputs", [])
    outputs = param_layout.get("outputs", [])
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

    args = [{"id": i["name"], "kind": "i32"} for i in inputs]
    spec = {
        "name": name,
        "addr": _int(address),
        "callconv": callconv,
        "ret": ("i32" if signed else "u32") if outputs else "void",
        "args": args,
        "compare": ["ret"] if outputs else [],
    }
    if orig_regs:
        spec["orig_regs"] = orig_regs
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


def _classify_prove_failure(out: str) -> tuple:
    """(failure_stage, detail) from prover output. Call check_oracle_alive
    separately to upgrade to oracle_died_during."""
    o = out or ""
    if "not reachable" in o or "refused" in o.lower() or "ConnectionRefused" in o:
        return "oracle_unreachable", "D2Debugger :8790 unreachable"
    if "handler-exception" in o:
        return "marshal_fault", ("SEH fault inside the oracle handler -- usually a wrong "
                                 "callconv/slot-count (check RET n) or a bad pointer arg")
    if "error C" in o or "fatal error" in o:
        errs = "; ".join(m.group(0) for m in _MSVC_ERR_LINE_RE.finditer(o))[:400]
        return "build_provider", errs or "compile error in provider build"
    if "DIVERGED" in o or "MISMATCH" in o.upper():
        return "mismatch", "original != reimpl on >=1 vector (see output)"
    return "prove", (o.strip().splitlines() or ["no output"])[-1][:200]


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
    Returns {ok, stage, detail, healed:[names]}."""
    healed: list = []
    build_dir = str(D2MOO_REPO / "build-1.13c")
    for _round in range(max_heal + 1):
        # reconfigure first: CONFIGURE_DEPENDS re-globs candidates + regens the .def
        subprocess.run(["cmake", "-S", str(D2MOO_REPO), "-B", build_dir],
                       capture_output=True, text=True)
        proc = subprocess.run(
            ["cmake", "--build", build_dir, "--config", config,
             "--target", "D2MOO_ReimplProvider"],
            capture_output=True, text=True)
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
            return {"ok": False, "stage": "build_provider",
                    "detail": errs or out[-500:], "healed": healed}
        for n in siblings:
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


def build_live_draft_prompt(func_name: str, address, decompiled_text: str) -> str:
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
        "and ```json. No third block, no split code blocks, no trailing prose.")
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
    parts.append(f"Function: {func_name} at {addr}   (D2Common.dll)")
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


def build_handle_draft_prompt(func_name: str, address, decompiled_text: str) -> str:
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
             "literally ```cpp and ```json. Nothing else that matters outside them.")
    p.append("")
    p.append("## Task: reimplement a Diablo II LIVE-POINTER getter for handle conformance proving")
    p.append(
        "This function takes a POINTER to a live game object the running game allocated on the heap "
        "(a unit / record / struct -- Ghidra often types it as a bare int*/short*). It will be PROVEN "
        "by calling BOTH the ORIGINAL and YOUR reimpl with the SAME captured live pointer and comparing "
        "the result, so reproduce the decompiled field reads EXACTLY -- every offset, cast, width, branch.")
    p.append("")
    p.append(f"Function: {func_name} at {addr}   (D2Common.dll)")
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
    such a draft as malformed here keeps it out of the provider dir entirely."""
    c = cpp or ""
    return 'extern "C"' in c and "namespace D2Lib" not in c


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
    if not cpp or not js:
        return None, None, None
    try:
        spec = _json_loads_lenient(js[0])
    except json.JSONDecodeError:
        return None, None, None
    layout = spec.get("param_layout")
    input_sets = spec.get("input_sets")
    if not isinstance(layout, dict) or not layout.get("handle_arg"):
        return None, None, None
    if not isinstance(input_sets, list) or not input_sets:
        input_sets = [{}]
    if not _is_provider_reimpl(cpp[0]):   # reject OpenD2/non-extern-C drafts (build poison)
        return None, None, None
    reimpl = cpp[0].strip() + "\n"
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


def run_synth_prove(reimpl_cpp: str, name: str, address, *, ret: str = "u32",
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
    spec = {"name": name, "addr": _int(address), "callconv": "stdcall",
            "ret": ret if ret in ("u8", "i8", "u16", "i16", "u32", "i32") else "u32",
            "args": [parg],
            "compare": ["ret"],
            "vectors": [{}]}
    write_candidate(reimpl_cpp, name)
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    spec_path = VECTORS_DIR / f"{name}.spec.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
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
        res["writeback"] = record_proof(name, address, spec, res)
    return res


def run_synth2_prove(reimpl_cpp: str, name: str, address, *, ret: str = "u32",
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
    spec = {"name": name, "addr": _int(address), "callconv": "stdcall",
            "ret": ret if ret in ("u8", "i8", "u16", "i16", "u32", "i32") else "u32",
            "args": [parg],
            "compare": ["ret"], "vectors": [{}]}
    write_candidate(reimpl_cpp, name)
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    spec_path = VECTORS_DIR / f"{name}.spec.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
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
        res["writeback"] = record_proof(name, address, spec, res)
    return res


_DELEGATE_INDICES = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]


def run_delegate_prove(reimpl_cpp: str, name: str, address, *, ret: str = "u32",
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
    for i in idxs:
        parg = {"id": "p", "kind": "synth", "bytes": 256,
                "gates": base_gates + [{"depth": 0, "off": arg_off, "imm": i, "w": 4}]}
        spec = {"name": name, "addr": _int(address), "callconv": "stdcall", "ret": rr,
                "args": [parg], "compare": ["ret"], "vectors": [{}]}
        sp = VECTORS_DIR / f"{name}.spec.json"
        sp.write_text(json.dumps(spec) + "\n", encoding="utf-8")
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
        res["writeback"] = record_proof(name, address, spec, res)
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
                     input_sets: list, *, build: bool = True) -> dict:
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
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    spec_path = VECTORS_DIR / f"{name}.spec.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
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
        res["writeback"] = record_proof(name, address, spec, res, weak_proof=res["weak_proof"])
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
    if not cpp or not js:
        return None, None, None
    try:
        spec = _json_loads_lenient(js[0])
    except json.JSONDecodeError:
        return None, None, None
    layout = spec.get("param_layout")
    input_sets = spec.get("input_sets")
    if not isinstance(layout, dict) or not isinstance(input_sets, list) or not input_sets:
        return None, None, None
    if "inputs" not in layout or "outputs" not in layout:
        return None, None, None
    if not _is_provider_reimpl(cpp[0]):   # reject OpenD2/non-extern-C drafts (build poison)
        return None, None, None
    reimpl = cpp[0].strip() + "\n"
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
    if "D2MOO_REIMPL_EXPORT:" not in body:
        body = f"// D2MOO_REIMPL_EXPORT: {name}\n{body}"
    path = CANDIDATES_DIR / f"{name}.cpp"
    path.write_text(body, encoding="utf-8")
    return path


def _invoke_prove(spec_path: Path, *, build: bool, timeout: int = 900) -> dict:
    """Run prove_candidate.py --spec and map its result to run_harness's shape."""
    if not PROVE_SCRIPT.exists():
        return _fail("config", f"prover not found: {PROVE_SCRIPT}")
    # --json emits the raw per-vector oracle result (incl. the coverage "probe"),
    # which we parse back out for branch-coverage analysis without a second call.
    cmd = [sys.executable, str(PROVE_SCRIPT), "--spec", str(spec_path), "--url", ORACLE_URL, "--json"]
    if build:
        cmd.append("--build")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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


def _ghidra_post(path: str, data: dict) -> dict:
    """POST a JSON body to the Ghidra plugin REST server (source of truth).
    Best-effort -- write-back must NEVER fail a proof."""
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


def _set_rung(address, level: str, ladder, program: str = "D2Common.dll") -> dict:
    """Set ONE rung on a mutually-exclusive Ghidra tag ladder: remove the other
    rungs, add this one. Additive to OTHER axes and to decompiler comments.
    Best-effort; never raises. Shared by the DOC_ and CONF_ write-backs."""
    if level not in ladder:
        return {"status": f"bad level {level!r} (want one of {ladder})"}
    addr = f"0x{address:x}" if isinstance(address, int) else str(address)
    others = ",".join(t for t in ladder if t != level)
    _ghidra_post("/remove_function_tag", {"function": addr, "tags": others, "program": program})
    tag = _ghidra_post("/add_function_tag", {"function": addr, "tags": level, "program": program})
    return {"level": level, "status": "ok" if tag.get("status") == "success" else tag.get("error", tag)}


def set_doc_level(address, doc_level: str, *, program: str = "D2Common.dll") -> dict:
    """WRITE-BACK the DOC_ documentation-maturity rung in Ghidra (source of truth),
    mutually exclusive. Call from fun-doc's documentation stages:
      first-pass model doc            -> DOC_DRAFT
      passed review/score >= threshold-> DOC_REVIEWED  (ABI confirmed from disasm)
      fully ground-truthed            -> DOC_VERIFIED
    Orthogonal to CONF_* and non-destructive to decompiler comments."""
    return _set_rung(address, doc_level, DOC_TAGS, program)


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
                 program: str = "D2Common.dll", conf_level: str = "CONF_LIVE",
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
    independent best-effort; never raises. (No save_program here -- matches the existing
    tag write; the open program persists on the next save / sync.)

    conf_level defaults to CONF_LIVE (the live-oracle proof). A future battle-test
    promoter passes CONF_BATTLETESTED (earned by zero shadow divergences in real
    gameplay)."""
    status = {"ghidra_tag": None, "property": None, "registry": None}
    a = spec.get("addr", address)
    addr = f"0x{a:x}" if isinstance(a, int) else str(a)

    # Mutual exclusivity handled by the shared ladder helper.
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
        p = _ghidra_post("/set_property", {"map": "Conf", "address": addr, "value": rec, "program": program})
        if not p.get("success") and "No property map" in str(p):
            _ghidra_post("/create_property_map", {"name": "Conf", "type": "string", "program": program})
            p = _ghidra_post("/set_property", {"map": "Conf", "address": addr, "value": rec, "program": program})
        status["property"] = "ok" if p.get("success") else p.get("error", p)
    except OSError as e:
        status["property"] = f"error: {e}"

    # (3) git-tracked registry mirror.
    try:
        PROVEN_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
        with open(PROVEN_REGISTRY, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        status["registry"] = str(PROVEN_REGISTRY)
    except OSError as e:
        status["registry"] = f"error: {e}"
    return status


def run_live_prove(reimpl_cpp: str, name: str, address, param_layout: dict,
                   input_sets: list, *, build: bool = True,
                   abort_class: bool = False) -> dict:
    """Prove a D2MOO reimpl of `name` against the live game. Writes the reimpl
    into the provider, translates fun-doc's layout+cases into an oracle spec,
    and runs the prover. Returns run_harness's {ok,passed,total,output,...}.
    Raises UnsupportedLiveABI (caller falls back to static) for exotic ABIs.

    abort_class=True stamps the spec with a safety/envelope annotation (the
    function's out-of-range path is FATAL -- see abi_static.detect_abort_path)
    and flags the registry row so V1 adversarial sweeps skip it."""
    spec = translate_layout_to_spec(name, address, param_layout)
    spec["vectors"] = [dict(case) for case in input_sets]  # {name:val} == oracle vector
    if abort_class:
        spec["safety"] = ("ABORT CLASS: the original's out-of-range path is fatal "
                          "(_exit/CleanupAndAbort kills the process/bridge). Vectors are "
                          "strictly in-envelope; do NOT fuzz out-of-range (no V1 widening).")
        spec["abort_class"] = True

    write_candidate(reimpl_cpp, name)
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    spec_path = VECTORS_DIR / f"{name}.spec.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")

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
        res["writeback"] = record_proof(name, address, spec, res,
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

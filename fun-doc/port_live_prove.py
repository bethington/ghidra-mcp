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
    return {"ok": False, "passed": 0, "total": 0, "stage": stage, "error": msg, "output": output}


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
        "- `extern \"C\"` with the right return type + calling convention (see below) + integer widths.\n"
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
        "- Read-only: never mutate global state. No STL. Plain C-ish C++.\n"
        "- NEVER call a compiler-internal helper (__alldiv/__aulldiv/__allmul/...) by name -- write the "
        "plain operator on the correct fixed-width type and let the compiler emit it.\n"
        "- CALLING CONVENTION: if EVERY input is on the stack, declare it `__stdcall`; if ANY input is in "
        "a register (the plate says e.g. 'passed in EAX/ECX/ESI'), declare it `__fastcall` and list the "
        "parameters in logical order. The prover marshals the original's real (possibly non-standard) "
        "register ABI for you -- you only need your reimpl's declared convention to match this rule.")
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
        spec = json.loads(js[0])
    except json.JSONDecodeError:
        return None, None, None
    layout = spec.get("param_layout")
    input_sets = spec.get("input_sets")
    if not isinstance(layout, dict) or not isinstance(input_sets, list) or not input_sets:
        return None, None, None
    if "inputs" not in layout or "outputs" not in layout:
        return None, None, None
    reimpl = cpp[0].strip() + "\n"
    if 'provider_runtime.h' not in reimpl:  # ensure the resolver header is present
        reimpl = '#include "../provider_runtime.h"\n' + reimpl
    return reimpl, layout, input_sets


def write_candidate(reimpl_cpp: str, name: str) -> Path:
    """Drop a drafted D2MOO reimpl into the provider's candidates/ dir. Ensures
    the `// D2MOO_REIMPL_EXPORT: <name>` marker the provider build reads is
    present. Canonical one-file-per-function name avoids duplicate symbols."""
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
    cmd = [sys.executable, str(PROVE_SCRIPT), "--spec", str(spec_path), "--url", ORACLE_URL]
    if build:
        cmd.append("--build")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _fail("prove", f"prove_candidate.py timed out after {timeout}s")
    out = proc.stdout + proc.stderr
    m = re.search(r"(\d+)/(\d+) match", out)
    passed, total = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    return {
        "ok": proc.returncode == 0,
        "passed": passed,
        "total": total,
        "stage": "prove",
        "error": "" if proc.returncode == 0 else f"prover exit {proc.returncode}",
        "output": out.strip(),
    }


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


def record_proof(name: str, address, spec: dict, result: dict, *,
                 program: str = "D2Common.dll", conf_level: str = "CONF_LIVE") -> dict:
    """WRITE-BACK (see the writeback-source-of-truth principle). On a successful
    live proof: (1) set the CONF_ rung in Ghidra -- the RE source of truth,
    queryable via search_functions_by_tag -- REMOVING the other (mutually
    exclusive) CONF_ rungs first, and (2) append a machine-readable row to
    conformance/proven_functions.jsonl. Additive to the DOC_ axis and decompiler
    comments (never clobbered). Best-effort; never raises.

    conf_level defaults to CONF_LIVE (the live-oracle proof). A future battle-test
    promoter passes CONF_BATTLETESTED (earned by zero shadow divergences in real
    gameplay)."""
    status = {"ghidra_tag": None, "registry": None}
    a = spec.get("addr", address)
    addr = f"0x{a:x}" if isinstance(a, int) else str(a)

    # Mutual exclusivity handled by the shared ladder helper.
    r = _set_rung(addr, conf_level, CONF_TAGS, program)
    status["ghidra_tag"] = f"{conf_level}={r['status']}"

    try:
        row = {
            "name": name, "address": addr, "program": program,
            "conf": conf_level,
            "callconv": spec.get("callconv"), "ret": spec.get("ret"),
            "orig_regs": spec.get("orig_regs"),
            "vectors": len(spec.get("vectors", [])),
            "passed": result.get("passed"), "total": result.get("total"),
            "date": datetime.date.today().isoformat(),
        }
        PROVEN_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
        with open(PROVEN_REGISTRY, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        status["registry"] = str(PROVEN_REGISTRY)
    except OSError as e:
        status["registry"] = f"error: {e}"
    return status


def run_live_prove(reimpl_cpp: str, name: str, address, param_layout: dict,
                   input_sets: list, *, build: bool = True) -> dict:
    """Prove a D2MOO reimpl of `name` against the live game. Writes the reimpl
    into the provider, translates fun-doc's layout+cases into an oracle spec,
    and runs the prover. Returns run_harness's {ok,passed,total,output,...}.
    Raises UnsupportedLiveABI (caller falls back to static) for exotic ABIs."""
    spec = translate_layout_to_spec(name, address, param_layout)
    spec["vectors"] = [dict(case) for case in input_sets]  # {name:val} == oracle vector

    write_candidate(reimpl_cpp, name)
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    spec_path = VECTORS_DIR / f"{name}.spec.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")

    res = _invoke_prove(spec_path, build=build)
    res["spec"] = spec  # additive: lets a caller (e.g. shadow_promote.py) classify
                        # the ABI shape without recomputing translate_layout_to_spec
    if res.get("ok"):
        # Write-back to the source of truth on every successful proof.
        res["writeback"] = record_proof(name, address, spec, res)
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

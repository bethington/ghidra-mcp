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
    return int(str(v), 0) if isinstance(v, str) else int(v)


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

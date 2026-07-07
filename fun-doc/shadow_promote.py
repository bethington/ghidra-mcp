"""shadow_promote.py -- the "shadow the original function to verify it" leg of
the continuous port-and-prove loop (D2MOO's conformance/D2COMMON_FULL_SHADOW_PLAN.md).

Sibling to port_live_prove.py, which proves a reimpl bit-exact via the ONE-SHOT
direct-call oracle (CONF_LIVE: our chosen inputs, checked once). This module
promotes an already-CONF_LIVE function to a live SHADOW DISPATCHER: hooked into
the real game's call path, comparing original vs reimpl on EVERY real call the
game makes, at volume, for free. That is the strictly stronger CONF_BATTLETESTED
rung -- battletest_promoter.py (sibling) closes the loop by watching shadow
hit/divergence counters and promoting once real-play evidence crosses a bar.

Design constraints (learned by hand, 2026-07-07, before this module existed):
  1. `translate_layout_to_spec` (port_live_prove.py) only ever emits i32-slot
     args + an EAX-only return -- so every candidate it can prove today is
     naturally "Class A" (return-value integer) shaped for
     conformance/tools/gen_shadow_dispatch.py's generator. A `void`-return spec
     captures NOTHING (compare=[]) -- promoting it would be a shadow dispatcher
     that can never observe a divergence, which is false confidence, not proof.
     Such specs are DEFERRED, not silently promoted.
  2. A reimpl whose decompiled source calls a wall-clock/tick/rand function is
     NON-DETERMINISTIC -- a correct reimpl would still show spurious
     "divergences" from timing drift between the two calls. Deferred.
  3. A reimpl whose decompiled source can reach an abort/exit path is a REAL
     hazard for autonomous vector generation elsewhere in the pipeline (a stray
     out-of-range input is a hard process termination, not a catchable fault)
     -- flagged for human review rather than silently promoted, even though
     shadowing itself (game-supplied inputs only) would be safe.
  4. Promotion here only STAGES the manifest + regenerates the generated header
     (cheap, local, reversible). It deliberately does NOT rebuild D2Common.dll
     or restart the game -- that is a separate, explicit, batched step
     (rebuild_and_stage_batch / the `--build` CLI flag) so an autonomous loop
     never kills the user's running game out from under them without opt-in.

Standalone (imports nothing from fun_doc), like port_pipeline.py / port_live_prove.py.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
MANIFEST_PATH = D2MOO_REPO / "conformance" / "shadow_manifest.json"
GEN_SCRIPT = D2MOO_REPO / "conformance" / "tools" / "gen_shadow_dispatch.py"
BUILD_TREE = os.environ.get("FUNDOC_D2MOO_BUILD_TREE", str(D2MOO_REPO / "build-1.13c"))

_D2COMMON_BASE = 0x6FD50000

# Hazard heuristics over the DECOMPILED SOURCE TEXT. Deliberately conservative --
# false positives just mean an extra function waits for human review; false
# negatives mean a real hazard (crash, flaky divergence) reaches production.
_NONDETERMINISTIC_RE = re.compile(
    r"\b(GetTickCount|QueryPerformanceCounter|timeGetTime|__time32|_time32|"
    r"FID_conflict___time32|\btime\s*\(|\brand\s*\(|srand\s*\()", re.IGNORECASE)
_ABORT_PATH_RE = re.compile(
    r"\b(CleanupAndAbort|_exit\s*\(|\bexit\s*\(|ExitProcess|abort\s*\(|"
    r"RaiseException|std::terminate)", re.IGNORECASE)


class DeferPromotion(Exception):
    """Function is not safe/meaningful to promote yet. .reason is human-readable."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def classify_dispatcher_shape(spec: dict) -> str:
    """spec (port_live_prove.translate_layout_to_spec's output) -> generator
    Class letter, or raises DeferPromotion if this shape isn't safe/meaningful
    to promote given the CURRENT generator (Class A only; see module docstring)."""
    orig_regs = spec.get("orig_regs")
    if orig_regs:
        # Class D: register-explicit ABI. The generator's v1 naked thunk supports
        # the single-EAX-input, u32/pointer-return pattern (the DATATBLS_* accessors).
        # Anything else (multi-register, ESI/EDI inputs, stack args, non-u32 return)
        # still defers.
        args = spec.get("args", [])
        ret = spec.get("ret")
        if (list(orig_regs.keys()) == ["EAX"] and len(args) == 1
                and ret in ("u32", "i32") and spec.get("compare") == ["ret"]
                and all(a.get("kind") in (None, "i32") for a in args)):
            return "D"
        raise DeferPromotion(
            f"register-explicit ABI {orig_regs} outside Class D v1 (single EAX "
            f"input, u32 return) -- multi-register/stack marshalling not implemented")
    if spec.get("ret") in (None, "void") or not spec.get("compare"):
        raise DeferPromotion(
            "void/uncaptured return -- this spec's oracle proof (EAX-only) "
            "observes nothing, so a shadow dispatcher for it could never show "
            "a divergence; not meaningful proof. Needs out-param modeling "
            "(Class B) in translate_layout_to_spec before this is provable.")
    ret_bits = 32
    if spec["ret"] in ("u8", "i8"):
        ret_bits = 8
    elif spec["ret"] in ("u16", "i16"):
        ret_bits = 16
    if any(a.get("kind") not in (None, "i32") for a in spec.get("args", [])):
        raise DeferPromotion(f"unsupported arg kind(s) in {spec.get('args')}")
    return "A"  # only shape this pipeline can produce today; ret_bits carried separately


def check_hazards(decompiled_text: str) -> None:
    """Raise DeferPromotion if the decompiled source shows a known-dangerous
    pattern. Best-effort text heuristic, not a substitute for human review of
    anything genuinely borderline."""
    text = decompiled_text or ""
    m = _NONDETERMINISTIC_RE.search(text)
    if m:
        raise DeferPromotion(
            f"non-deterministic (matched {m.group(0)!r}) -- a correct reimpl "
            f"would still show spurious shadow divergences from timing drift")
    m = _ABORT_PATH_RE.search(text)
    if m:
        raise DeferPromotion(
            f"reaches an abort/exit path (matched {m.group(0)!r}) -- shadowing "
            f"real gameplay calls is safe (the game only supplies values its own "
            f"code already validated), but flagged for human review before "
            f"promotion since a HARD process termination is not the same "
            f"failure mode as a catchable access violation")


def _load_manifest() -> dict:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {"_comment": "shadow-dispatcher promotion manifest (auto-managed by "
                         "fun-doc/shadow_promote.py + hand-authored entries).",
            "entries": []}


def _save_manifest(manifest: dict) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def regenerate_dispatch_header() -> dict:
    """Re-run the generator so D2Common_ShadowDispatch.gen.h reflects the
    manifest. Cheap (pure codegen, no compile). Best-effort."""
    if not GEN_SCRIPT.exists():
        return {"ok": False, "error": f"generator not found: {GEN_SCRIPT}"}
    try:
        proc = subprocess.run([sys.executable, str(GEN_SCRIPT)],
                               capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "generator timed out"}
    return {"ok": proc.returncode == 0, "output": (proc.stdout + proc.stderr).strip()}


def maybe_promote(name: str, address, spec: dict, decompiled_text: str = "") -> dict:
    """Given a function that just passed CONF_LIVE (one-shot oracle proof),
    decide whether it's safe+meaningful to promote to a live shadow dispatcher,
    and if so STAGE it (manifest + regenerated header; NOT built/deployed --
    see module docstring). Never raises; returns a status dict:
        {"promoted": bool, "reason": str, "class": str|None}
    Best-effort and non-fatal, matching port_live_prove.py's write-back contract
    -- a promotion failure must never fail the underlying proof."""
    try:
        check_hazards(decompiled_text)
        cls = classify_dispatcher_shape(spec)
    except DeferPromotion as e:
        return {"promoted": False, "reason": e.reason, "class": None}
    except Exception as e:  # never let a promotion bug fail the caller's proof
        return {"promoted": False, "reason": f"error: {e}", "class": None}

    try:
        if isinstance(address, str):
            try:
                addr_int = int(address, 0)      # "0x6fd51250"
            except ValueError:
                addr_int = int(address, 16)     # bare hex "6fd51250" (fun_doc convention)
        else:
            addr_int = int(address)
        offset = addr_int - _D2COMMON_BASE
        if offset < 0:
            return {"promoted": False, "reason": f"address below D2Common base: {address}", "class": None}

        ret_bits = {"u8": 8, "i8": 8, "u16": 16, "i16": 16}.get(spec["ret"], 32)
        args = [a["id"] for a in spec.get("args", [])] or []  # generator normalizes strings -> i32

        manifest = _load_manifest()
        entries = manifest.setdefault("entries", [])
        if any(e["name"] == name for e in entries):
            return {"promoted": True, "reason": "already staged", "class": cls}

        entries.append({
            "name": name, "offset": f"0x{offset:x}", "callconv": spec["callconv"],
            "args": args, "ret_bits": ret_bits, "class": cls,
            "note": f"auto-staged by fun-doc/shadow_promote.py from a CONF_LIVE oracle proof",
        })
        _save_manifest(manifest)
        gen = regenerate_dispatch_header()
        if not gen.get("ok"):
            return {"promoted": False, "reason": f"manifest staged but codegen failed: {gen.get('error') or gen.get('output')}", "class": cls}
        return {"promoted": True, "reason": "staged (manifest + header regenerated; "
                                             "build+deploy is a separate batched step)", "class": cls}
    except Exception as e:
        return {"promoted": False, "reason": f"error: {e}", "class": None}


if __name__ == "__main__":
    # Self-test: hazard + shape classification, no side effects on the real manifest.
    try:
        check_hazards("int Foo(int a) { return FID_conflict___time32(0) + a; }")
        raise SystemExit("FAIL: expected DeferPromotion for time32 call")
    except DeferPromotion as e:
        assert "non-deterministic" in e.reason, e.reason

    try:
        check_hazards("void Foo(int a) { if (a<0) CleanupAndAbort(); }")
        raise SystemExit("FAIL: expected DeferPromotion for abort path")
    except DeferPromotion as e:
        assert "abort" in e.reason, e.reason

    check_hazards("int Foo(int a) { return a + 1; }")  # should NOT raise

    ok_spec = {"callconv": "stdcall", "ret": "u8", "args": [{"id": "act", "kind": "i32"}], "compare": ["ret"]}
    assert classify_dispatcher_shape(ok_spec) == "A"

    void_spec = {"callconv": "stdcall", "ret": "void", "args": [], "compare": []}
    try:
        classify_dispatcher_shape(void_spec)
        raise SystemExit("FAIL: expected DeferPromotion for void/uncaptured spec")
    except DeferPromotion:
        pass

    regs_spec = {"callconv": "fastcall", "ret": "u32", "args": [{"id": "x", "kind": "i32"}],
                 "compare": ["ret"], "orig_regs": {"EAX": "x"}}
    try:
        classify_dispatcher_shape(regs_spec)
        raise SystemExit("FAIL: expected DeferPromotion for orig_regs")
    except DeferPromotion:
        pass

    print("[ok] shadow_promote unit checks passed")

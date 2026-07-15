"""submission_api -- the drafting agent's ground-truth feedback surface.

The core of the submission-MCP design (2026-07-14): instead of a model
emitting fenced text that a pipeline parses, grades once, and discards, the
drafting agent CALLS these functions (via the d2debugger-mcp tools that wrap
them) and gets immediate, specific, staged feedback:

    port_context(address)       -> everything needed to draft: decompile,
                                   disasm, mechanical ABI facts, the VERIFIED
                                   resolvable names (and the unresolvable ones,
                                   explicitly), plus a route verdict up front --
                                   "direct" or "shadow_first" with reasons.
    check_candidate(code)       -> <1s static verdict, no build: unknown
                                   D2MOO_Resolve names, provider-shape rules.
    submit_candidate(...)       -> staged pipeline: static_check -> compile
                                   (attributed MSVC errors) -> live prove
                                   against the running game (existing oracle),
                                   with per-vector mismatches on failure and
                                   proof write-back on success.
    withdraw_candidate(name)    -> remove a broken candidate so it can't
                                   poison the shared provider build.

Code arrives as a function ARGUMENT -- there is no fenced-block contract, no
reasoning_split exposure, nothing to parse. Every check reuses the proven
pipeline primitives (abi_static, port_live_prove); this module only composes
and shapes them into verdicts an agent can act on.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

DEFAULT_PROGRAM = "/Mods/PD2-S12/D2Common.dll"

# Every submit_candidate verdict is appended here. The agentic-escalation
# wrapper (fun_doc.run_agentic_escalation) reads this to learn how a session
# ended without parsing the agent's prose -- the ledger IS the outcome.
VERDICTS_LOG = Path(__file__).parent / "logs" / "submission_verdicts.jsonl"


def _log_verdict(name, address, verdict):
    try:
        VERDICTS_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(VERDICTS_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": datetime.now().isoformat(), "name": name,
                                "address": address, **{k: v for k, v in verdict.items()
                                                       if k != "detail"}},
                               default=str) + "\n")
    except OSError:
        pass


def _ghidra(path, **params):
    import fun_doc
    r = fun_doc.ghidra_get(path, params=params)
    if not r or fun_doc._is_error_response(r):
        return None
    return str(r)


def port_context(address: str, program: str = DEFAULT_PROGRAM) -> dict:
    """Everything a drafting agent needs for ONE function, plus a route
    verdict. `address` is bare hex or 0x-prefixed."""
    import abi_static
    addr = address.lower().removeprefix("0x")
    dec = _ghidra("/decompile_function", address=f"0x{addr}", program=program)
    dis = _ghidra("/disassemble_function", address=f"0x{addr}", program=program)
    if not dec or not dis:
        return {"ok": False, "error": "decompile/disassembly fetch failed",
                "address": addr, "program": program}

    abi = {}
    try:
        abi = abi_static.derive_abi(dis)
    except Exception as e:
        abi = {"error": str(e)}
    abort_class = False
    try:
        abort_class = bool(abi_static.detect_abort_path(dec))
    except Exception:
        pass
    r_globs = r_callees = []
    try:
        r_globs = abi_static.resolvable_globals(dis)
        r_callees = abi_static.resolvable_callees(dis)
    except Exception:
        pass

    # The complement sets are what make feedback IMMEDIATE: the agent is told
    # up front which references it can never satisfy from the provider.
    unresolvable_globals = sorted(
        hex(a) for a in (abi.get("data_globals") or [])
        if a not in {ga for ga, _n in r_globs})
    unresolvable_callees = sorted(
        hex(a) for a in (abi.get("calls") or [])
        if a not in {ca for ca, _n in r_callees})

    reasons = []
    if unresolvable_callees:
        reasons.append(f"calls {len(unresolvable_callees)} function(s) with no "
                       f"resolve-table name ({', '.join(unresolvable_callees)}) -- "
                       "the provider cannot call through to them")
    if unresolvable_globals:
        reasons.append(f"reads global(s) with no resolve-table name "
                       f"({', '.join(unresolvable_globals)})")
    if abort_class:
        reasons.append("abort-class: the out-of-range path is fatal; vectors "
                       "must stay in-envelope")
    route = "shadow_first" if (unresolvable_callees or unresolvable_globals) else "direct"

    return {
        "ok": True, "address": addr, "program": program,
        "route": route, "route_reasons": reasons,
        "abi": {k: v for k, v in abi.items() if k != "notes"},
        "abort_class": abort_class,
        "resolvable_globals": [{"addr": hex(a), "name": n} for a, n in r_globs],
        "resolvable_callees": [{"addr": hex(a), "name": n} for a, n in r_callees],
        "unresolvable_globals": unresolvable_globals,
        "unresolvable_callees": unresolvable_callees,
        "decompile": dec,
        "disassembly": dis,
        "house_rules": (
            'extern "C" exported function; #include "../provider_runtime.h"; '
            "reach ANY game global/function ONLY via D2MOO_Resolve(<verified "
            "name from resolvable_* above>); never extern game symbols; "
            "preserve integer widths/magic constants exactly."),
    }


def check_candidate(code: str, name: str = "") -> dict:
    """Fast static verdict on candidate code -- no build, <1s."""
    import fun_doc
    import port_live_prove as plp
    violations = []
    unknown = sorted(fun_doc._unknown_resolve_names(code) or set())
    if unknown:
        violations.append({
            "kind": "unknown_resolve_name", "names": unknown,
            "detail": "D2MOO_Resolve on name(s) the resolve table does not "
                      "contain -- resolves to NULL at runtime. Use ONLY names "
                      "from port_context.resolvable_globals/callees."})
    if not plp._is_provider_reimpl(code):
        violations.append({
            "kind": "not_provider_shape",
            "detail": 'must be an extern "C" function for the provider DLL '
                      "(no OpenD2/namespace-only code; see the house_rules)."})
    return {"ok": not violations, "violations": violations, "name": name}


def submit_candidate(name: str, address: str, code: str,
                     param_layout: dict, input_sets: list,
                     program: str = DEFAULT_PROGRAM,
                     keep_on_failure: bool = False) -> dict:
    """Staged submission: static_check -> compile -> live prove. Returns
    {stage, ok, ...} where `stage` names how far it got; failures carry the
    attributed detail the agent needs to fix and resubmit. A failing
    candidate is withdrawn automatically (one broken .cpp poisons the shared
    provider build) unless keep_on_failure=True."""
    import port_live_prove as plp
    addr = address.lower().removeprefix("0x")

    static = check_candidate(code, name)
    if not static["ok"]:
        v = {"stage": "static_check", "ok": False,
             "violations": static["violations"],
             "next_action": "fix the violations and resubmit -- no build "
                            "was attempted"}
        _log_verdict(name, addr, v)
        return v

    ctx_route = None
    abort_class = False
    try:
        ctx = port_context(addr, program)
        ctx_route = ctx.get("route")
        abort_class = bool(ctx.get("abort_class"))
        if ctx.get("ok") and ctx_route == "shadow_first":
            v = {"stage": "route_check", "ok": False,
                 "route": "shadow_first",
                 "route_reasons": ctx["route_reasons"],
                 "next_action": "this function is NOT direct-provable from "
                                "the provider; stage it shadow-first "
                                "instead (shadow_leaf_backlog)"}
            _log_verdict(name, addr, v)
            return v
    except Exception:
        pass  # route pre-check is advisory; the prove itself is the arbiter

    try:
        res = plp.run_live_prove(code, name, addr, param_layout, input_sets,
                                 abort_class=abort_class)
    except plp.UnsupportedLiveABI as e:
        plp.remove_candidate(name)
        v = {"stage": "abi_translate", "ok": False, "detail": str(e),
             "next_action": "this register layout is outside the oracle "
                            "marshaller -- fall back to the static harness "
                            "or shadow-first"}
        _log_verdict(name, addr, v)
        return v
    except Exception as e:
        if not keep_on_failure:
            plp.remove_candidate(name)
        v = {"stage": "error", "ok": False, "detail": f"{type(e).__name__}: {e}"}
        _log_verdict(name, addr, v)
        return v

    verdict = {"stage": res.get("stage", "prove"), "ok": bool(res.get("ok")),
               "passed": res.get("passed"), "total": res.get("total"),
               "detail": (res.get("detail") or res.get("output") or "")[-2000:]}
    if verdict["ok"]:
        verdict["next_action"] = ("proven_live_pending_review -- proof recorded; "
                                  "candidate staged for shadow/battletest promotion")
        verdict["writeback"] = res.get("writeback")
    else:
        if not keep_on_failure:
            plp.remove_candidate(name)
            verdict["withdrawn"] = True
        verdict["next_action"] = (
            "fix the mismatch and resubmit" if verdict["stage"] == "prove"
            else "fix the compile errors and resubmit")
    _log_verdict(name, addr, verdict)
    return verdict


def withdraw_candidate(name: str) -> dict:
    import port_live_prove as plp
    plp.remove_candidate(name)
    return {"ok": True, "removed": name}


def _cli():
    """CLI for the agentic escalation lane -- the drafting agent shells out to
    these subcommands (via the fun-doc venv python) and reads JSON verdicts:

        python submission_api.py context 6fd9e5a0 [--program P]
        python submission_api.py check code.cpp [--name N]
        python submission_api.py submit NAME 6fd9e5a0 code.cpp \
               --layout layout.json --vectors vectors.json [--program P]
        python submission_api.py withdraw NAME
    """
    import argparse
    p = argparse.ArgumentParser(description=_cli.__doc__)
    sp = p.add_subparsers(dest="cmd", required=True)
    c = sp.add_parser("context"); c.add_argument("address")
    c.add_argument("--program", default=DEFAULT_PROGRAM)
    k = sp.add_parser("check"); k.add_argument("code_file")
    k.add_argument("--name", default="")
    s = sp.add_parser("submit"); s.add_argument("name"); s.add_argument("address")
    s.add_argument("code_file"); s.add_argument("--layout", required=True)
    s.add_argument("--vectors", required=True)
    s.add_argument("--program", default=DEFAULT_PROGRAM)
    w = sp.add_parser("withdraw"); w.add_argument("name")
    a = p.parse_args()

    if a.cmd == "context":
        out = port_context(a.address, a.program)
    elif a.cmd == "check":
        out = check_candidate(Path(a.code_file).read_text(encoding="utf-8"), a.name)
    elif a.cmd == "submit":
        out = submit_candidate(
            a.name, a.address, Path(a.code_file).read_text(encoding="utf-8"),
            json.loads(Path(a.layout).read_text(encoding="utf-8")),
            json.loads(Path(a.vectors).read_text(encoding="utf-8")),
            program=a.program)
    else:
        out = withdraw_candidate(a.name)
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    _cli()

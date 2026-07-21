"""fast_path.py -- batch getter-proving engine (the validated fast path, automated).

Turns the manual loop (decompile -> recognize pattern -> draft reimpl -> build ->
prove -> document) into a repeatable batch tool. It ROUTES each candidate to the
right MECHANICAL translator + DISCRIMINATING prover that already exist in fun-doc,
then auto-documents the winners.

Routing (first match wins), all using the live oracle with SYNTHETIC discriminating
objects (no gameplay, no real handle, no shadow rebuild for these classes):

  flat getter          abi_static.translate_getter_to_c        -> run_synth_prove
    (1 ptr param, fixed-offset read, optional dwType gate; the synth object's
     unique-per-offset bytes make a wrong offset MISMATCH)
  2-level getter       (chain len 2: ptr@O1 -> deref -> field@O2) -> run_synth2_prove
    (the class that used to stateful_skip -> hand-shadowed; synth2 nests a
     discriminating object so it proves statically-live, no game needed)
  delegate call-through abi_static.translate_delegate_getter_to_c -> run_delegate_prove
  global-table indexed  abi_static.translate_global_table_getter_to_c -> prove_spec sweep

On a STRONG (allMatch + discriminating) proof: register CONF_LIVE + canonical-name
(d2moo_names) + stamp a plate + tag. Non-discriminating / non-matching -> reported,
NOT promoted (never overclaim).

    python fast_path.py --addrs 0x6fd73b40,0x6fd72920 [--program /Mods/PD2-S12/D2Common.dll]
    python fast_path.py --selftest      # routing dry-run on the translators, no oracle
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

PROGRAM = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")
D2COMMON_BASE = 0x6FD50000


def _addr_hex(a) -> str:
    if isinstance(a, str):
        a = int(a, 16) if a.lower().startswith("0x") else int(a, 16)
    return f"0x{a:x}"


def classify_and_draft(name: str, decompile: str, disasm: str):
    """Route to a (class, reimpl_code, prover_kwargs) via the mechanical translators.
    Returns dict {cls, code, ret, prover, kwargs} or {cls:'unsupported', reason}."""
    import abi_static
    # 1) flat getter (single fixed-offset read, optional dwType gate)
    flat = abi_static.translate_getter_to_c(name, disasm)
    if flat.get("ok") and len(flat.get("chain", [1])) <= 1:
        return {"cls": "flat", "code": flat["code"], "ret": flat.get("ret", "u32"),
                "prover": "synth", "gates": flat.get("type_gates") or flat.get("gates")}
    # 2) delegate call-through
    dele = abi_static.translate_delegate_getter_to_c(name, disasm)
    if dele.get("ok"):
        return {"cls": "delegate", "code": dele["code"], "ret": dele.get("ret", "u32"),
                "prover": "delegate", "arg_off": dele.get("arg_off", 4),
                "type_gates": dele.get("type_gates")}
    # 3) global-table indexed getter
    try:
        import d2moo_names
        rev = d2moo_names.resolve_reverse_map() if hasattr(d2moo_names, "resolve_reverse_map") else None
    except Exception:
        rev = None
    gt = abi_static.translate_global_table_getter_to_c(name, disasm, resolve_rev=rev)
    if gt.get("ok"):
        return {"cls": "global_table", "code": gt["code"], "ret": gt.get("ret", "u32"),
                "prover": "prove_spec"}
    # 4) 2-level getter (the synth2 class) -- flat translator reports a 2-deep chain
    if flat.get("chain") and len(flat["chain"]) == 2:
        return {"cls": "two_level", "code": flat["code"], "ret": flat.get("ret", "u32"),
                "prover": "synth2", "gates": flat.get("type_gates") or flat.get("gates")}
    return {"cls": "unsupported",
            "reason": flat.get("reason") or dele.get("reason") or gt.get("reason") or "no translator matched"}


def _draft_one(addr, program: str = PROGRAM) -> dict:
    """Decompile+disasm -> route -> write the candidate (NO build/prove). For batch mode:
    draft all, build the provider ONCE, then prove each with build=False."""
    import fun_doc
    import port_live_prove as plp
    ah = _addr_hex(addr)
    dec = fun_doc.ghidra_get("/decompile_function", params={"address": ah, "program": program})
    dis = fun_doc.ghidra_get("/disassemble_function", params={"address": ah, "program": program})
    if not dec or fun_doc._is_error_response(dec) or not dis or fun_doc._is_error_response(dis):
        return {"addr": ah, "result": "fetch_failed"}
    name = _name_of(dec) or f"FUN_{ah[2:]}"
    route = classify_and_draft(name, str(dec), str(dis))
    if route["cls"] == "unsupported":
        return {"addr": ah, "name": name, "result": "unsupported", "reason": route["reason"]}
    plp.write_candidate(route["code"], name)   # stage so ONE build compiles them all
    return {"addr": ah, "name": name, "route": route, "result": "drafted"}


def prove_one(addr, program: str = PROGRAM, *, build: bool = True) -> dict:
    """Full loop for ONE function: decompile+disasm -> route -> prove -> (doc)."""
    import fun_doc
    import port_live_prove as plp
    ah = _addr_hex(addr)
    dec = fun_doc.ghidra_get("/decompile_function", params={"address": ah, "program": program})
    dis = fun_doc.ghidra_get("/disassemble_function", params={"address": ah, "program": program})
    if not dec or fun_doc._is_error_response(dec) or not dis or fun_doc._is_error_response(dis):
        return {"addr": ah, "result": "fetch_failed"}
    name = _name_of(dec) or f"FUN_{ah[2:]}"
    route = classify_and_draft(name, str(dec), str(dis))
    if route["cls"] == "unsupported":
        return {"addr": ah, "name": name, "result": "unsupported", "reason": route["reason"]}
    return _prove_routed(addr, ah, name, route, program, build=build)


def _prove_routed(addr, ah, name, route, program, *, build=True) -> dict:
    import port_live_prove as plp
    if route["prover"] == "synth":
        res = plp.run_synth_prove(route["code"], name, addr, ret=route["ret"], gates=route.get("gates"), build=build)
    elif route["prover"] == "synth2":
        res = plp.run_synth2_prove(route["code"], name, addr, ret=route["ret"], gates=route.get("gates"), build=build)
    elif route["prover"] == "delegate":
        res = plp.run_delegate_prove(route["code"], name, addr, ret=route["ret"],
                                     arg_off=route.get("arg_off", 4), type_gates=route.get("type_gates"), build=build)
    else:  # global_table -> prove via a discriminating index sweep through prove_spec
        res = _prove_global_table(route["code"], name, addr, route["ret"], build=build)

    out = {"addr": ah, "name": name, "cls": route["cls"], "prover": route["prover"],
           "ok": bool(res.get("ok")), "allMatch": res.get("allMatch"),
           "discriminating": res.get("discriminating", res.get("proof_kind") in ("synth", "synth2")),
           "result": "PROVEN" if res.get("ok") else res.get("failure_stage", "failed")}
    if out["ok"]:
        out["doc"] = _document(addr, name, route, res, program)
    return out


def _prove_global_table(code, name, addr, ret, *, build=True) -> dict:
    """Build + prove a global-table (scalar-index) getter via the live oracle (_invoke_prove)
    with a spread index sweep; STRONG only if allMatch AND the original VARIES across indices
    (>=3 distinct) -- else non-discriminating (a wrong offset would match a uniform field too).
    Requires the game IN-GAME (tables load on game entry), like the delegate prover."""
    import json
    import port_live_prove as plp
    rr = ret if ret in ("u8", "i8", "u16", "i16", "u32", "i32") else "u32"
    plp.write_candidate(code, name)
    if build:
        b = plp.build_provider_attributed(name)
        if not b.get("ok"):
            return {"ok": False, "failure_stage": b.get("stage")}
    idxs = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 120, 160, 200, 300, 450, -1]
    spec = {"name": name, "addr": plp._int(addr), "callconv": "stdcall", "ret": rr,
            "args": [{"id": "i", "kind": "i32"}], "compare": ["ret"],
            "vectors": [{"i": i} for i in idxs]}
    plp.VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    sp = plp.VECTORS_DIR / f"{name}.spec.json"
    sp.write_text(json.dumps(spec) + "\n", encoding="utf-8")
    r = plp._invoke_prove(sp, build=False)
    ov = (r.get("oracle") or {}).get("results") or []
    orig = set(row["ret"]["o"] for row in ov if isinstance(row.get("ret"), dict) and "o" in row["ret"])
    r["discriminating"] = bool(r.get("ok") and len(orig) >= 3)
    if r.get("ok") and not r["discriminating"]:
        r["ok"] = False
        r["failure_stage"] = f"non_discriminating (distinct={len(orig)})"
    if r.get("ok"):
        r["writeback"] = plp.record_proof(name, addr, spec, r)
    return r


def _document(addr, name, route, res, program) -> str:
    """Canonical-name + plate + CONF_LIVE tag + registry, on a strong proof."""
    try:
        import fun_doc
        import d2moo_names
        ah = _addr_hex(addr)
        final = name
        if d2moo_names.is_offset_name(name):
            c = d2moo_names.canonicalize(name, route["code"])
            if c.get("ok"):
                fun_doc.ghidra_post("/rename_function_by_address",
                                    data={"function_address": ah, "new_name": c["proposed_name"]},
                                    params={"program": Path(program).name})
                final = c["proposed_name"]
        note = (f"[FAST-PATH PROVEN] {route['cls']} getter, discriminating "
                f"{route['prover']} proof (allMatch). CONF_LIVE.")
        fun_doc.ghidra_post("/set_plate_comment", data={"address": ah, "comment": note},
                            params={"program": program})
        fun_doc.ghidra_post("/add_function_tag",
                            data={"function": ah, "tags": "CONF_LIVE"},
                            params={"program": Path(program).name})
        return f"documented -> {final}"
    except Exception as e:
        return f"doc_error: {e}"


_NAME_STOP = {"NULL", "if", "while", "for", "return", "switch", "sizeof", "CONCAT22",
              "CONCAT31", "CONCAT13", "SUB84", "void", "int", "uint", "char", "byte",
              "short", "ushort", "bool", "undefined", "code", "float", "double"}


def _name_of(dec) -> str:
    """The real function name from the decompile signature: the first identifier-before-'('
    that isn't a C keyword / decompiler pseudo-op / NULL guard (which the naive regex grabbed,
    drafting a junk 'NULL.cpp' that poisoned the batch build until the sibling-heal removed it).

    STRIP COMMENTS FIRST: Ghidra prepends a plate comment, and for functions that call a
    named helper the plate's prose mentions the CALLEE (e.g. "aborts via CleanupAndAbort")
    before the real signature -- scanning the raw text grabbed the callee name and registered
    the proof under the WRONG function (STAT_GetUnitCalculatedStat mis-named CleanupAndAbort)."""
    text = re.sub(r"/\*.*?\*/", " ", str(dec), flags=re.S)   # drop plate/block comments
    text = re.sub(r"//[^\n]*", " ", text)                    # drop line comments
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]+)\s*\(", text):
        nm = m.group(1)
        if nm not in _NAME_STOP and ("_" in nm or re.match(r"[A-Z][a-z]", nm)):
            return nm
    return ""


def run(addrs, program: str = PROGRAM) -> list:
    """BATCH: draft (route + stage candidate) all -> build the provider ONCE -> prove each
    (build=False) + document. One rebuild for the whole batch instead of one per function."""
    import port_live_prove as plp
    drafts = []
    for a in addrs:
        d = _draft_one(a, program)
        drafts.append(d)
        tag = f"{d['route']['cls']}/{d['route']['prover']}" if d.get("route") else d["result"]
        print(f"  draft {a}: {tag}", flush=True)
    staged = [d for d in drafts if d["result"] == "drafted"]
    if staged:
        print(f"\n[build] one provider build for {len(staged)} staged candidate(s)...", flush=True)
        b = plp.build_provider_attributed(staged[0]["name"])
        if not b.get("ok"):
            print(f"[build] FAILED: {b.get('stage')} -- {str(b.get('detail'))[:200]}", flush=True)
            for d in staged:
                d["result"] = "build_failed"
            return drafts
    results = []
    for d in drafts:
        if d["result"] != "drafted":
            results.append({"addr": d["addr"], "name": d.get("name"), "cls": "-",
                            "result": d["result"], "reason": d.get("reason")})
            continue
        r = _prove_routed(int(d["addr"], 16), d["addr"], d["name"], d["route"], program, build=False)
        results.append(r)
        print(f"  [{r.get('cls','?')}/{r.get('prover','?')}] {d['name']}: {r['result']}"
              f"{'  ' + str(r.get('doc','')) if r.get('doc') else ''}", flush=True)
    return results


def scorecard(results):
    import collections
    c = collections.Counter(r["result"] for r in results)
    proven = [r for r in results if r["result"] == "PROVEN"]
    print("\n" + "=" * 64)
    print(f"FAST-PATH SCORECARD -- {len(results)} candidates")
    for k, v in c.most_common():
        print(f"  {k:<22} {v}")
    print(f"\nPROVEN (CONF_LIVE, discriminating): {len(proven)}")
    for r in proven:
        print(f"  {r['name']:<38} {r['cls']}/{r['prover']}  {r.get('doc','')}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--addrs", help="comma-separated function addresses (0x...)")
    ap.add_argument("--program", default=PROGRAM)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if not args.addrs:
        ap.error("--addrs required (or --selftest)")
    addrs = [a.strip() for a in args.addrs.split(",") if a.strip()]
    results = run(addrs, args.program)
    scorecard(results)
    Path("fast_path_results.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    return 0


def _selftest() -> int:
    # Routing dry-run: feed canned disasm to classify_and_draft (no oracle/Ghidra).
    # A genuinely FLAT gated getter (read +0x40, null-guard, XOR return-0 default).
    flat = ("6fd70000: MOV EAX,dword ptr [ESP + 0x4]\n6fd70004: TEST EAX,EAX\n"
            "6fd70006: JZ 0x6fd70012\n6fd70008: MOV EAX,dword ptr [EAX + 0x40]\n"
            "6fd7000c: RET 0x4\n6fd70012: XOR EAX,EAX\n6fd70014: RET 0x4\n")
    r = classify_and_draft("SomeFlagGetter", "", flat)
    print(f"[selftest] flat getter routed -> cls={r['cls']} prover={r.get('prover')}")
    assert r["cls"] == "flat" and r["prover"] == "synth", r
    # 2-level getter with a NON-ZERO default return (GetItemQuality's `MOV EAX,0x2`) now
    # routes to synth2 (abi_static learned the nonzero-default idiom, 2026-07-09).
    gq = ("6fd73b40: MOV EAX,dword ptr [ESP + 0x4]\n6fd73b44: TEST EAX,EAX\n6fd73b46: JZ 0x6fd73b59\n"
          "6fd73b48: CMP dword ptr [EAX],0x4\n6fd73b4b: JNZ 0x6fd73b59\n"
          "6fd73b4d: MOV EAX,dword ptr [EAX + 0x14]\n6fd73b50: TEST EAX,EAX\n6fd73b52: JZ 0x6fd73b59\n"
          "6fd73b54: MOV EAX,dword ptr [EAX]\n6fd73b56: RET 0x4\n6fd73b59: MOV EAX,0x2\n6fd73b5e: RET 0x4\n")
    r2 = classify_and_draft("ITEMS_GetItemQuality", "", gq)
    print(f"[selftest] GetItemQuality (2-level, nonzero default) -> cls={r2['cls']} prover={r2.get('prover')}")
    assert r2["cls"] == "two_level" and r2["prover"] == "synth2", r2
    # _name_of must return the SIGNATURE name, not a callee mentioned in the plate
    # comment (the bug that registered STAT_GetUnitCalculatedStat as "CleanupAndAbort").
    dec = ("/* Reads a stat; on out-of-range it aborts via CleanupAndAbort(pGame).\n"
           "   Helper GetReturnAddress() is used for the log. */\n"
           "uint __stdcall STAT_GetUnitCalculatedStat(UnitAny *pUnit)\n{\n"
           "  if (x) CleanupAndAbort(0);\n  return pUnit->stat;\n}\n")
    assert _name_of(dec) == "STAT_GetUnitCalculatedStat", _name_of(dec)
    print("[ok] fast_path routing self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

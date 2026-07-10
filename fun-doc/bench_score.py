"""bench_score.py -- score the documentation pipeline against the benchmark DLL.

The benchmark DLL is compiled from KNOWN ground truth (conformance/benchmark/), loaded
fresh into Ghidra (Ordinal/FUN_ only), and fed BLIND to the pipeline. This scores what
the REAL production tooling recovers from that fresh binary against answer_key.json --
an objective "how true is the documentation" number, because we authored the answer.

Phase-1 axes (MECHANICAL, objective from disasm -- no model, no game):
  * ret_width   : did we recover the true return width?
  * field_reads : did we recover the exact (offset,width) fields the fn accesses?
  * gate        : did we recover the type-gate (offset+immediate)?
Recovery uses the ACTUAL abi_static translators (production code), so a bail is an
honest finding (e.g. a compiler idiom the translator doesn't yet handle), not hidden.

The prose/name axes (plate accuracy, semantic-name recovery) need doc-gen + an
independent judge -- Phase 2.

Usage:
    python bench_score.py --program bench_core.dll
    python bench_score.py --selftest
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

# the benchmark program lives OUTSIDE the PD2 scope guard -- re-scope to the benchmark
# folder BEFORE fun_doc imports (it reads the scope at module load).
os.environ["FUN_DOC_PROJECT_FOLDER"] = "/benchmark"

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
BENCH_DIR = D2MOO_REPO / "conformance" / "benchmark"
ANSWER_KEY = BENCH_DIR / "answer_key" / "bench_core.answer.json"

# ordinal -> fresh-Ghidra address (from the .def RVAs + 0x10000000 image base).
ORD_ADDR = {10001: "0x100010c0", 10042: "0x100010a0", 10108: "0x10001080",
            10205: "0x10001050", 10333: "0x10001030"}
# the benchmark's own global (g_pMonsterTable) -- there is no resolve table, so give
# the translators a benchmark resolve map keyed by the address the disasm derefs.
BENCH_GLOBALS = {0x10015948: "g_pMonsterTable"}


def _facts_from_translators(name: str, disasm: str, abi_static) -> dict:
    """Run the production translators on a fresh-binary disasm; return the recovered
    facts + which translator matched (or the bail reason)."""
    rev = BENCH_GLOBALS
    # try flat/gated getter, then global-table, then delegate -- as the pipeline routes.
    t = abi_static.translate_getter_to_c(name, disasm)
    if t.get("ok"):
        reads = [{"off": o, "width": {"u8": 1, "i8": 1, "u16": 2, "i16": 2,
                                      "u32": 4, "i32": 4}.get(t["ret"], 4)}
                 for o in (t.get("chain") or [])]
        # the LAST chain entry is the value read (its width = ret); earlier are ptr walks (4).
        for r in reads[:-1]:
            r["width"] = 4
        gates = [{"off": g[1], "imm": g[2]} for g in (t.get("type_gates") or [])]
        return {"matched": "flat_getter", "ret": t["ret"], "reads": reads, "gates": gates}
    gt = abi_static.translate_global_table_getter_to_c(name, disasm, resolve_rev=rev)
    if gt.get("ok"):
        reads = [{"off": gt["count_off"], "width": 4}, {"off": gt["records_off"], "width": 4},
                 {"off": gt["field_off"], "width": {"u8": 1, "u16": 2, "u32": 4,
                                                    "i8": 1, "i16": 2, "i32": 4}.get(gt["ret"], 4)}]
        return {"matched": "global_table", "ret": gt["ret"], "reads": reads, "gates": [],
                "global": gt["global"], "stride": gt["stride"]}
    dl = abi_static.translate_delegate_getter_to_c(name, disasm, resolve_rev=rev)
    if dl.get("ok"):
        w = {"u8": 1, "u16": 2, "u32": 4, "i8": 1, "i16": 2, "i32": 4}.get(dl["ret"], 4)
        return {"matched": "delegate", "ret": dl["ret"],
                "reads": [{"off": dl["result_off"], "width": w}],
                "gates": [{"off": g[0], "imm": g[1]} for g in (dl.get("type_gates") or [])]}
    return {"matched": None,
            "bail": {"flat": t.get("reason"), "global_table": gt.get("reason"),
                     "delegate": dl.get("reason")}}


def score_function(ak: dict, recovered: dict) -> dict:
    """Score one function's recovered facts against its answer-key truth."""
    truth_ret_w = ak["ret"]["width"]
    rw = {"u8": 1, "i8": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4}
    got_ret_w = rw.get(recovered.get("ret"), None)
    ret_ok = (got_ret_w == truth_ret_w)

    # field-read recovery: fraction of TRUE (offset,width) field reads recovered.
    truth_reads = {(r["off"], r["width"]) for r in ak.get("reads", [])}
    got_reads = {(r["off"], r["width"]) for r in recovered.get("reads", [])}
    if truth_reads:
        field_recall = len(truth_reads & got_reads) / len(truth_reads)
    else:
        field_recall = 1.0 if not got_reads else 0.0   # pure-computed: no reads is correct

    # gate recovery
    truth_gates = {(g.get("off"), g.get("imm")) for g in ak.get("gates", []) if "imm" in g}
    got_gates = {(g["off"], g["imm"]) for g in recovered.get("gates", [])}
    gate_ok = (truth_gates == got_gates) if truth_gates else (not got_gates)

    axes = {"ret_width": 1.0 if ret_ok else 0.0,
            "field_reads": round(field_recall, 3),
            "gate": 1.0 if gate_ok else 0.0}
    score = round(sum(axes.values()) / len(axes), 3)
    return {"matched": recovered.get("matched"), "score": score, "axes": axes,
            "truth_reads": sorted(truth_reads), "got_reads": sorted(got_reads),
            "bail": recovered.get("bail")}


def run(program: str) -> dict:
    import fun_doc, abi_static
    ak = json.loads(ANSWER_KEY.read_text(encoding="utf-8"))
    fns = {f["name"]: f for f in ak["functions"]}
    results = {}
    for name, meta in fns.items():
        ordn = meta.get("export_ordinal")
        if ordn not in ORD_ADDR:
            continue   # un-exported (bench_LookupMonster) -> Phase 2 (needs FUN_ discovery)
        addr = ORD_ADDR[ordn]
        disasm = str(fun_doc.ghidra_get("/disassemble_function",
                                        params={"address": addr, "program": program}))
        recovered = _facts_from_translators(name, disasm, abi_static)
        results[name] = {"address": addr, "shape": meta["shape"],
                         **score_function(meta, recovered)}
    scored = [r["score"] for r in results.values()]
    agg = round(sum(scored) / len(scored), 3) if scored else 0.0
    return {"program": program, "aggregate_mechanical_score": agg,
            "n": len(results), "functions": results}


def _selftest() -> int:
    ak = {"ret": {"width": 2}, "reads": [{"off": 0x8, "width": 4}, {"off": 0x4, "width": 2}],
          "gates": [{"off": 0, "imm": 2}]}
    rec = {"matched": "flat_getter", "ret": "u16",
           "reads": [{"off": 0x8, "width": 4}, {"off": 0x4, "width": 2}],
           "gates": [{"off": 0, "imm": 2}]}
    s = score_function(ak, rec)
    assert s["score"] == 1.0 and s["axes"] == {"ret_width": 1.0, "field_reads": 1.0, "gate": 1.0}, s
    # a miss: wrong field width recovered
    rec2 = {"matched": "flat_getter", "ret": "u32",
            "reads": [{"off": 0x8, "width": 4}, {"off": 0x4, "width": 4}], "gates": []}
    s2 = score_function(ak, rec2)
    assert s2["axes"]["ret_width"] == 0.0 and s2["axes"]["field_reads"] == 0.5 and s2["axes"]["gate"] == 0.0, s2
    # pure computed: no reads, none recovered -> field axis perfect
    s3 = score_function({"ret": {"width": 4}, "reads": [], "gates": []},
                        {"matched": None, "ret": "i32", "reads": [], "gates": []})
    assert s3["axes"]["field_reads"] == 1.0, s3
    print("[ok] bench_score self-test: scoring axes pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--program", default="bench_core.dll")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    print(json.dumps(run(args.program), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

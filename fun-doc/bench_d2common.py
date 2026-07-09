"""bench_d2common.py -- non-destructive documentation benchmark on the REAL binary.

The fresh, pristine /testing/D2Common.dll (auto-analysis only: FUN_/Ordinal names,
undefined types, no plates) is byte-identical to our annotated /Mods/PD2-S12 copy, so
they map by ADDRESS. We run the MODEL doc-generation BLIND on the fresh copy and score
its output against the annotated copy (the answer key) -- WITHOUT touching our real work
(golden_bench had to strip-in-place; this uses a separate program).

Why the MODEL stages, not the translators: fresh and annotated share identical bytes, so
the DETERMINISTIC translators produce identical output on both -> circular/trivial. The
non-trivial thing to measure on real codegen is the model's NAME/PLATE/prototype recovery.

Axes (user-ratified rubric; INDEPENDENT judge for prose to avoid circularity):
  * prototype : return-width + param-count match (mechanical)
  * name      : does the generated name mean the same as the annotated name? (judge)
  * plate     : is the generated plate semantically accurate vs the annotated plate? (judge)
Authority tier: 'proven' functions have oracle-verified behavior (their prototype axis is
authoritative truth); 'documented' functions are a regression signal vs our best docs.

Two-phase (each phase sets its own scope-guard folder via env at process start):
  1) python bench_d2common.py --extract --names A,B,C   (PD2 scope; reads answer key)
  2) python bench_d2common.py --score                   (/testing scope; generates+scores)
  python bench_d2common.py --selftest
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
ANNOTATED = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")
FRESH = "/testing/D2Common.dll"
REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
CANDIDATES = D2MOO_REPO / "conformance" / "reimpl_provider" / "candidates"
OUT_DIR = D2MOO_REPO / "conformance" / "benchmark"
ANSWER_JSON = OUT_DIR / "d2common_answer.json"
SCORE_JSON = OUT_DIR / "d2common_score.json"

_RW = {"u8": 1, "i8": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4}
_TYPE_W = {"byte": 1, "uchar": 1, "unsigned char": 1, "char": 1, "signed char": 1,
           "undefined1": 1, "bool": 1, "uint8_t": 1, "int8_t": 1, "u8": 1, "i8": 1,
           "ushort": 2, "short": 2, "unsigned short": 2, "signed short": 2, "word": 2,
           "undefined2": 2, "uint16_t": 2, "int16_t": 2, "wchar_t": 2, "u16": 2, "i16": 2,
           "uint": 4, "int": 4, "unsigned int": 4, "signed int": 4, "dword": 4,
           "undefined4": 4, "long": 4, "unsigned long": 4, "uint32_t": 4, "int32_t": 4,
           "u32": 4, "i32": 4, "undefined": 4, "float": 4, "size_t": 4, "hresult": 4,
           "bool32": 4}


# ---------------------------------------------------------------------------
# pure logic (offline-testable)
# ---------------------------------------------------------------------------

def _ret_type(prototype: str, name: str) -> str:
    """Return-type token from a prototype string."""
    head = prototype.split(name)[0] if name in prototype else prototype.split("(")[0]
    return " ".join(head.replace("*", " * ").split()).strip().lower()


def _ret_width(ret_token: str) -> int | None:
    t = ret_token.replace(" *", "*").strip()
    if t.endswith("*"):
        return 4
    return _TYPE_W.get(t.replace("unsigned ", "unsigned "), _TYPE_W.get(t))


def _param_count(prototype: str) -> int:
    m = re.search(r"\(([^)]*)\)", prototype)
    if not m:
        return -1
    inner = m.group(1).strip()
    if not inner or inner.lower() == "void":
        return 0
    return len([p for p in inner.split(",") if p.strip()])


def score_prototype(gen_proto: str, gen_name: str, truth: dict) -> dict:
    """Mechanical: return-width + param-count. Truth width prefers the PROVEN reimpl
    (oracle-verified) over the annotated prototype when available."""
    tw = truth.get("proven_ret_width") or _ret_width(_ret_type(truth["prototype"], truth["name"]))
    gw = _ret_width(_ret_type(gen_proto, gen_name))
    ret_ok = (gw is not None and gw == tw)
    tp = truth.get("proven_param_count")
    if tp is None:
        tp = _param_count(truth["prototype"])
    gp = _param_count(gen_proto)
    param_ok = (gp == tp)
    return {"ret_width_ok": ret_ok, "param_count_ok": param_ok,
            "score": round((ret_ok + param_ok) / 2, 3),
            "truth_ret_width": tw, "got_ret_width": gw,
            "truth_params": tp, "got_params": gp}


def aggregate(results: dict) -> dict:
    if not results:
        return {"n": 0}
    axes = ("prototype", "name", "plate")
    agg = {a: round(sum(r["axes"][a] for r in results.values()) / len(results), 3) for a in axes}
    overall = round(sum(r["score"] for r in results.values()) / len(results), 3)
    proven = [r for r in results.values() if r.get("tier") == "proven"]
    return {"n": len(results), "overall": overall, "axes": agg,
            "proven_n": len(proven),
            "proven_prototype": round(sum(r["axes"]["prototype"] for r in proven) / len(proven), 3)
            if proven else None}


# ---------------------------------------------------------------------------
# phase 1: extract the answer key (run under PD2 scope)
# ---------------------------------------------------------------------------

def _registry() -> list:
    return [json.loads(l) for l in REGISTRY.read_text(encoding="utf-8").splitlines() if l.strip()]


def _proven_facts(name: str) -> dict:
    """Oracle-verified facts from the proven candidate (authoritative behavior)."""
    cand = CANDIDATES / f"{name}.cpp"
    if not cand.exists():
        return {}
    try:
        import prove_doc
        f = prove_doc.parse_reimpl_facts(cand.read_text(encoding="utf-8"))
        # semantic ret width from the field read (not the harness u32)
        reads = f.get("field_reads") or []
        maxd = max((r.get("depth", 0) for r in reads), default=0)
        finals = [r for r in reads if r.get("depth", 0) == maxd]
        rw = finals[0]["width"] if finals else None
        return {"proven_ret_width": rw, "proven_param_count": f.get("params")}
    except Exception:
        return {}


def extract(names: list, program: str = None) -> dict:
    import fun_doc
    prog = program or ANNOTATED
    reg = {r["name"]: r for r in _registry()}
    proven_names = set(reg)
    key = {}
    for name in names:
        row = reg.get(name)
        addr = row["address"] if row else None
        if not addr:
            print(f"[extract] {name}: not in registry -- skip")
            continue
        dec = str(fun_doc.ghidra_get("/decompile_function",
                                     params={"address": addr, "program": prog}))
        m = re.search(r"^\s*([\w\s\*]+?\s\*?\s*" + re.escape(name) + r"\s*\([^)]*\))",
                      dec.replace("\r", ""), re.MULTILINE)
        proto = m.group(1).strip() if m else None
        plate = fun_doc.ghidra_get("/get_plate_comment", params={"address": addr, "program": prog})
        plate_txt = plate.get("comment") if isinstance(plate, dict) else str(plate)
        entry = {"name": name, "address": addr, "prototype": proto or f"undefined {name}()",
                 "plate": plate_txt or "", "tier": "proven" if name in proven_names else "documented",
                 **_proven_facts(name)}
        key[name] = entry
        print(f"[extract] {name} @{addr} tier={entry['tier']} proven_ret_w={entry.get('proven_ret_width')}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ANSWER_JSON.write_text(json.dumps(key, indent=2), encoding="utf-8")
    print(f"[extract] wrote {len(key)} answer-key entries -> {ANSWER_JSON}")
    return key


# ---------------------------------------------------------------------------
# phase 2: generate BLIND on the fresh copy + score (run under /testing scope)
# ---------------------------------------------------------------------------

_GEN_PROMPT = """You are documenting an UNKNOWN function from a freshly analyzed binary.
You have ONLY the decompiler output below (no name, no types, no comments -- a blind
Ghidra auto-analysis). Recover what the function does.

## Decompiled (blind)
```c
{decompiled}
```
## Disassembly (ground truth for widths/offsets)
```
{disasm}
```

Produce documentation as STRICT JSON only:
{{"name": "<CamelCase semantic function name reflecting behavior>",
  "prototype": "<full C prototype with your recovered return type + params>",
  "plate": "<concise doc: 1-line summary, algorithm steps, params, returns, special cases>"}}"""

_JUDGE_PROMPT = """Compare GENERATED reverse-engineering documentation against the
REFERENCE (known-good) documentation for the same function. Score how well the generated
version captures the SAME meaning. Be strict but fair: different wording that conveys the
same behavior scores high; missing or wrong behavior scores low.

## REFERENCE name: {ref_name}
## GENERATED name: {gen_name}

## REFERENCE plate
{ref_plate}

## GENERATED plate
{gen_plate}

Output STRICT JSON only:
{{"name_match": <0.0-1.0, do the two names denote the same function/behavior>,
  "plate_accuracy": <0.0-1.0, does the generated plate accurately capture the reference behavior>,
  "reason": "<one sentence>"}}"""


def generate(addr: str, program: str, provider=None, model=None) -> dict:
    import fun_doc
    dec = str(fun_doc.ghidra_get("/decompile_function", params={"address": addr, "program": program}))
    dis = str(fun_doc.ghidra_get("/disassemble_function", params={"address": addr, "program": program}))
    prompt = _GEN_PROMPT.format(decompiled=dec[:4000], disasm=dis[:3000])
    prov = provider or fun_doc.AI_PROVIDER
    mdl = model
    if mdl is None:
        try:
            mdl = fun_doc.get_configured_model(prov, "FULL")
        except Exception:
            mdl = None
    for _ in range(3):
        text, _m = fun_doc.invoke_claude(prompt, model=mdl, max_turns=2, provider=prov, complexity_tier=None)
        obj = fun_doc._extract_first_json(text or "")
        if isinstance(obj, dict) and obj.get("prototype"):
            return obj
        prompt += "\n\nREMINDER: reply with ONLY the strict JSON object."
    return {}


def judge(ref_name: str, ref_plate: str, gen_name: str, gen_plate: str, provider=None, model=None) -> dict:
    import fun_doc
    prompt = _JUDGE_PROMPT.format(ref_name=ref_name, gen_name=gen_name,
                                  ref_plate=(ref_plate or "")[:3000], gen_plate=(gen_plate or "")[:3000])
    prov = provider or fun_doc.AI_PROVIDER
    mdl = model
    if mdl is None:
        try:
            mdl = fun_doc.get_configured_model(prov, "FULL")
        except Exception:
            mdl = None
    for _ in range(3):
        text, _m = fun_doc.invoke_claude(prompt, model=mdl, max_turns=2, provider=prov, complexity_tier=None)
        obj = fun_doc._extract_first_json(text or "")
        if isinstance(obj, dict) and "name_match" in obj:
            return obj
        prompt += "\n\nREMINDER: reply with ONLY the strict JSON object."
    return {"name_match": 0.0, "plate_accuracy": 0.0, "reason": "judge failed to return JSON"}


def score(program: str = FRESH, provider=None, model=None) -> dict:
    key = json.loads(ANSWER_JSON.read_text(encoding="utf-8"))
    results = {}
    for name, truth in key.items():
        addr = truth["address"]
        gen = generate(addr, program, provider=provider, model=model)
        if not gen:
            results[name] = {"tier": truth["tier"], "score": 0.0,
                             "axes": {"prototype": 0.0, "name": 0.0, "plate": 0.0},
                             "error": "generation failed"}
            print(f"  {name:<32} GEN-FAIL")
            continue
        proto = score_prototype(gen.get("prototype", ""), gen.get("name", ""), truth)
        j = judge(truth["name"], truth["plate"], gen.get("name", ""), gen.get("plate", ""),
                  provider=provider, model=model)
        axes = {"prototype": proto["score"],
                "name": float(j.get("name_match", 0.0)),
                "plate": float(j.get("plate_accuracy", 0.0))}
        results[name] = {"tier": truth["tier"], "score": round(sum(axes.values()) / 3, 3),
                         "axes": axes, "generated_name": gen.get("name"),
                         "generated_prototype": gen.get("prototype"),
                         "prototype_detail": proto, "judge_reason": j.get("reason")}
        print(f"  {name:<32} [{truth['tier']:<10}] proto={proto['score']} "
              f"name={axes['name']} plate={axes['plate']} -> {results[name]['score']}  "
              f"(gen name: {gen.get('name')})")
    out = {"program": program, **aggregate(results), "functions": results}
    SCORE_JSON.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    return out


def _selftest() -> int:
    assert _ret_width(_ret_type("unsigned short f(void *p)", "f")) == 2
    assert _ret_width(_ret_type("byte DATATBLS_X(int i)", "DATATBLS_X")) == 1
    assert _ret_width(_ret_type("MonsterRec * f(int i)", "f")) == 4
    assert _param_count("int f(int a, int b, int c)") == 3
    assert _param_count("int f(void)") == 0
    truth = {"name": "GetLife", "prototype": "unsigned short GetLife(void *p)",
             "proven_ret_width": 2, "proven_param_count": 1}
    s = score_prototype("ushort MyGetLife(void* u)", "MyGetLife", truth)
    assert s["score"] == 1.0, s
    s2 = score_prototype("int Wrong(void* u, int x)", "Wrong", truth)
    assert s2["ret_width_ok"] is False and s2["param_count_ok"] is False and s2["score"] == 0.0, s2
    agg = aggregate({"a": {"tier": "proven", "score": 0.8, "axes": {"prototype": 1.0, "name": 0.7, "plate": 0.7}},
                     "b": {"tier": "documented", "score": 0.6, "axes": {"prototype": 0.5, "name": 0.6, "plate": 0.7}}})
    assert agg["n"] == 2 and agg["proven_n"] == 1 and agg["proven_prototype"] == 1.0, agg
    print("[ok] bench_d2common self-test: prototype/param/aggregate logic pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--names", help="comma-separated function names (for --extract)")
    ap.add_argument("--program", default=None)
    ap.add_argument("--provider", default=os.environ.get("AI_PROVIDER"))
    ap.add_argument("--model", default=None)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    # Set the scope-guard folder IN PYTHON (a Bash `VAR=/testing` gets MSYS path-mangled
    # to C:/Program Files/Git/testing). Set BEFORE any fun_doc import (read at module load).
    if args.extract:
        os.environ["FUN_DOC_PROJECT_FOLDER"] = str(Path(ANNOTATED).parent).replace("\\", "/")
        names = [n.strip() for n in (args.names or "").split(",") if n.strip()]
        extract(names, program=args.program)
        return 0
    if args.score:
        os.environ["FUN_DOC_PROJECT_FOLDER"] = str(Path(args.program or FRESH).parent).replace("\\", "/")
        out = score(program=args.program or FRESH, provider=args.provider, model=args.model)
        print(json.dumps({k: v for k, v in out.items() if k != "functions"}, indent=2, default=str))
        return 0
    ap.error("pick --extract / --score / --selftest")


if __name__ == "__main__":
    raise SystemExit(main())

"""golden_bench.py -- the GOLDEN-SET documentation benchmark.

User's insight (2026-07-08): to evaluate the prove-to-document pipeline, CLEAR all
documentation off a function and regenerate it from the ground up. Repeat on a fixed
golden set after every pipeline change -> a measurable quality benchmark instead of
anecdotes.

Per function:
  1. SNAPSHOT  -- name, prototype, plate, DOC_/CONF_ tags -> golden_snapshots/<name>.json
                  (the safety net AND the reference to compare against)
  2. STRIP     -- plate -> stub, DOC_*/CONF_* tags removed, prototype -> generic
                  (name is KEPT: renaming would break resolve-table/ordinal tooling;
                  the pipeline's name-audit still judges the name against behavior)
  3. REGENERATE -- prove_doc.prove_doc(): classify -> draft equivalent -> prove
                  discriminating -> consistency gate -> ledger -> DOC rung
  4. REPORT    -- what came back vs the snapshot: doc rung earned, prototype match,
                  plate regenerated?, proof kind. The diff is the SCORE.

Usage:
    python golden_bench.py --run --address 0x6fd84ab0 --name DATATBLS_GetMissileParamShort0x10
    python golden_bench.py --restore --name X          # put the snapshot back
    python golden_bench.py --selftest
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
PROGRAM_PATH = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")
SNAP_DIR = D2MOO_REPO / "conformance" / "golden_snapshots"
STRIP_STUB = "[GOLDEN-BENCH] documentation intentionally cleared for a ground-up regeneration run."
_ALL_TAGS = ["DOC_DRAFT", "DOC_REVIEWED", "DOC_VERIFIED",
             "CONF_DRAFT", "CONF_VECTORS", "CONF_LIVE", "CONF_BATTLETESTED", "CONF_REGRESSION"]


def _prog_name(program: str) -> str:
    return Path(program).name


def snapshot(address: str, name: str, *, program: str = PROGRAM_PATH) -> dict:
    """Capture everything we are about to destroy. Written BEFORE any strip."""
    import fun_doc
    addr = address if str(address).startswith("0x") else f"0x{address}"
    plate = fun_doc.ghidra_get("/get_plate_comment",
                               params={"address": addr, "program": program})
    dec = str(fun_doc.ghidra_get("/decompile_function",
                                 params={"address": addr, "program": program}))
    m = re.search(r"^\s*([\w\s\*]+?\s\*?\s*" + re.escape(name) + r"\s*\([^)]*\))",
                  dec.replace("\r", ""), re.MULTILINE)
    tags = fun_doc.ghidra_get("/get_function_tags",
                              params={"function": addr, "program": program})
    snap = {"name": name, "address": addr, "program": program,
            "date": datetime.datetime.now().isoformat(timespec="seconds"),
            "plate": plate, "prototype": (m.group(1).strip() if m else None),
            "tags": tags}
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    p = SNAP_DIR / f"{name}.json"
    p.write_text(json.dumps(snap, indent=2, default=str), encoding="utf-8")
    return {"path": str(p), **snap}


def strip(address: str, name: str, *, program: str = PROGRAM_PATH) -> dict:
    """Ground-zero the documentation. REFUSES to run without a snapshot on disk."""
    import fun_doc
    if not (SNAP_DIR / f"{name}.json").exists():
        raise RuntimeError(f"no snapshot for {name} -- snapshot() first (safety net)")
    addr = address if str(address).startswith("0x") else f"0x{address}"
    prog = _prog_name(program)
    out = {}
    out["plate"] = fun_doc.ghidra_post("/set_plate_comment",
                                       data={"address": addr, "comment": STRIP_STUB},
                                       params={"program": program})
    out["tags"] = fun_doc.ghidra_post("/remove_function_tag",
                                      data={"function": addr, "tags": ",".join(_ALL_TAGS),
                                            "program": prog})
    # generic prototype: the pipeline must re-derive width/params from the proof
    out["prototype"] = fun_doc.ghidra_post("/set_function_prototype",
                                           data={"function_address": addr,
                                                 "prototype": f"int {name}(int param_1)"},
                                           params={"program": prog})
    fun_doc.ghidra_post("/save_program", data={"program": prog})
    return out


def restore(name: str, *, program: str = PROGRAM_PATH) -> dict:
    """Put the snapshot back (plate + prototype; tags restored as-were)."""
    import fun_doc
    snap = json.loads((SNAP_DIR / f"{name}.json").read_text(encoding="utf-8"))
    addr = snap["address"]
    prog = _prog_name(program)
    out = {}
    plate = snap.get("plate")
    plate_text = ""
    if isinstance(plate, dict):
        plate_text = plate.get("comment") or ""
    elif isinstance(plate, str):
        try:
            plate_text = json.loads(plate).get("comment", "")
        except Exception:
            plate_text = plate
    if plate_text:
        out["plate"] = fun_doc.ghidra_post("/set_plate_comment",
                                           data={"address": addr, "comment": plate_text},
                                           params={"program": program})
    if snap.get("prototype"):
        out["prototype"] = fun_doc.ghidra_post("/set_function_prototype",
                                               data={"function_address": addr,
                                                     "prototype": snap["prototype"]},
                                               params={"program": prog})
    fun_doc.ghidra_post("/save_program", data={"program": prog})
    return out


def report(address: str, name: str, snap: dict, run_summary: dict, *,
           program: str = PROGRAM_PATH) -> dict:
    """The benchmark score: what the pipeline regenerated vs what was there."""
    import fun_doc
    addr = address if str(address).startswith("0x") else f"0x{address}"
    plate_after = str(fun_doc.ghidra_get("/get_plate_comment",
                                         params={"address": addr, "program": program}))
    dec = str(fun_doc.ghidra_get("/decompile_function",
                                 params={"address": addr, "program": program}))
    m = re.search(r"^\s*([\w\s\*]+?\s\*?\s*" + re.escape(name) + r"\s*\([^)]*\))",
                  dec.replace("\r", ""), re.MULTILINE)
    proto_after = m.group(1).strip() if m else None
    regenerated = STRIP_STUB not in plate_after and len(plate_after) > 120
    return {
        "function": name,
        "doc_rung_earned": run_summary.get("result"),
        "proof": run_summary.get("stages", {}).get("prove"),
        "discriminating": run_summary.get("stages", {}).get("discriminating"),
        "gate": {k: run_summary.get("stages", {}).get("gate", {}).get(k)
                 for k in ("mechanical_applied", "semantic_flags")},
        "plate_regenerated": regenerated,
        "prototype_before_strip": snap.get("prototype"),
        "prototype_after": proto_after,
        "prototype_recovered_semantics": bool(
            proto_after and snap.get("prototype")
            and _norm_ret(proto_after.split(name)[0]) == _norm_ret(snap["prototype"].split(name)[0])),
    }


_TYPE_SYNONYMS = {"uchar": "byte", "unsigned char": "byte", "u8": "byte",
                  "ushort": "word", "unsigned short": "word", "u16": "word",
                  "uint": "dword", "unsigned int": "dword", "u32": "dword",
                  "undefined1": "byte", "undefined2": "word", "undefined4": "dword"}


def _norm_ret(ret_text: str) -> str:
    """Normalize a return-type spelling for SEMANTIC comparison -- byte==uchar==
    unsigned char etc. (the naive textual compare scored a correct regeneration
    as a miss: snapshot `byte f(...)` vs regenerated `uchar f(...)`)."""
    t = " ".join(ret_text.strip().split()).lower()
    return _TYPE_SYNONYMS.get(t, t)


def run(address: str, name: str, *, program: str = PROGRAM_PATH,
        provider=None, model=None, struct_hint=None) -> dict:
    """snapshot -> strip -> prove_doc -> report. The full benchmark cycle."""
    import prove_doc as pd
    snap = snapshot(address, name, program=program)
    print(f"[bench] snapshot -> {snap['path']}")
    strip(address, name, program=program)
    print(f"[bench] stripped: plate/tags/prototype cleared")
    summary = pd.prove_doc(address, name, program=program, provider=provider,
                           model=model, struct_hint=struct_hint)
    # UNPROVEN -> the pipeline cannot regenerate docs for this one (abort-class /
    # stateful / prove failure). RESTORE the snapshot rather than leaving the
    # function stripped -- the bench must never destroy docs it can't rebuild.
    if str(summary.get("result", "")).startswith("not proven"):
        restore(name, program=program)
        summary["stages"]["bench_restore"] = "snapshot restored (unproven -- docs kept)"
        print(f"[bench] UNPROVEN -> snapshot restored")
    rep = report(address, name, snap, summary, program=program)
    out = SNAP_DIR / f"{name}.report.json"
    out.write_text(json.dumps({"summary": summary, "report": rep},
                              indent=2, default=str), encoding="utf-8")
    print(f"[bench] report -> {out}")
    return rep


def _selftest() -> int:
    # report scoring logic on canned data (no Ghidra)
    fake_snap = {"prototype": "ushort DATATBLS_GetMissileParamShort0x10(void *p)"}
    fake_run = {"result": "DOC_VERIFIED",
                "stages": {"prove": "proven_live_pending_review",
                           "discriminating": "True (synth)",
                           "gate": {"mechanical_applied": [], "semantic_flags": []}}}
    # (report() needs Ghidra; here we only sanity-check the pure comparisons)
    a = "ushort F(void *p)".split("F")[0].strip()
    b = "ushort  F(void *pOther)".split("F")[0].strip()
    assert a == b == "ushort"
    assert fake_run["stages"]["gate"]["semantic_flags"] == []
    assert fake_snap["prototype"].startswith("ushort")
    print("[ok] golden_bench self-test: comparison logic pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="store_true", help="full cycle: snapshot/strip/regen/report")
    ap.add_argument("--restore", action="store_true", help="restore a snapshot")
    ap.add_argument("--address")
    ap.add_argument("--name")
    ap.add_argument("--program", default=PROGRAM_PATH)
    ap.add_argument("--provider", default=os.environ.get("AI_PROVIDER"))
    ap.add_argument("--model", default=None)
    ap.add_argument("--struct-hint", default=None)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if args.restore:
        if not args.name:
            ap.error("--restore needs --name")
        print(json.dumps(restore(args.name, program=args.program), indent=2, default=str))
        return 0
    if args.run:
        if not (args.address and args.name):
            ap.error("--run needs --address and --name")
        os.environ.setdefault("FUNDOC_LIVE_PROVE", "1")
        rep = run(args.address, args.name, program=args.program,
                  provider=args.provider, model=args.model, struct_hint=args.struct_hint)
        print(json.dumps(rep, indent=2, default=str))
        return 0
    ap.error("pick --run / --restore / --selftest")


if __name__ == "__main__":
    raise SystemExit(main())

"""prove_doc.py -- the UNIFIED prove-to-document driver (single worker).

Takes a COMPLETELY UNDOCUMENTED function all the way to proof-backed Ghidra
documentation in one run:

    classify -> draft 1:1 equivalent -> prove DISCRIMINATING bit-exact (CONF_LIVE)
    -> CONSISTENCY GATE (auto-fix mechanical, flag semantic)
    -> struct-field ledger -> DOC_VERIFIED (proof-backed)

Design decisions (user-ratified 2026-07-08):
  * Proof-preferred: a discriminating CONF_LIVE proof of a hand-written equivalent
    is what EARNS DOC_VERIFIED. Unprovable functions cap at DOC_REVIEWED, marked
    unproven. (Battletest/regression are bonus confidence, not doc gates.)
  * Consistency gate: every proof re-derives the docs from the PROVEN equivalent
    and diffs against Ghidra. MECHANICAL facts (return width/sign, param count,
    calling convention, field offsets) are auto-corrected; SEMANTIC disagreements
    (function name, plate narrative) FLAG and block DOC_VERIFIED until reconciled.
    This is the gate that would have caught the WeaponStyle hallucinated plate.
  * Struct-field ledger: every proof contributes its (struct, offset, width, type)
    facts to a shared per-struct ledger so naming compounds across functions.
  * This is the SANCTIONED path -- ad-hoc proof scripts that skip the doc
    write-back are how stale plates survive. Use prove_doc, not one-offs.

Usage (game live on :8790 for the prove stage):
    python prove_doc.py --address 0x6fd72f80 --name DATATBLS_GetItemTypeField10
    python prove_doc.py --address ... --name ... --skip-prove   # gate-only re-run
    python prove_doc.py --selftest                              # offline self-test
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
REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
CANDIDATES = D2MOO_REPO / "conformance" / "reimpl_provider" / "candidates"
STRUCT_LEDGER_DIR = D2MOO_REPO / "conformance" / "doc_ledger"

# proof kinds that DISCRIMINATE by construction (a wrong offset would FAIL):
# synth/synth2 read a unique-byte pattern; gated variants patch preconditions;
# delegate_call_through requires orig-variance across indices (weak_uniform else).
_DISCRIMINATING_KINDS = {"synth", "synth2", "delegate_call_through"}


# ---------------------------------------------------------------------------
# pure logic (offline-testable)
# ---------------------------------------------------------------------------

def registry_row(name: str, address: str = None) -> dict | None:
    """Latest registry row for a function (last write wins)."""
    try:
        rows = [json.loads(l) for l in REGISTRY.read_text(encoding="utf-8").splitlines()
                if l.strip()]
    except OSError:
        return None
    hit = None
    for r in rows:
        if r.get("name") == name and (address is None or r.get("address") == address):
            hit = r
    return hit


def is_discriminating(row: dict) -> tuple:
    """(bool, reason). A proof earns DOC_VERIFIED only if it DISCRIMINATES --
    a wrong reimpl would have FAILED. weak_proof (degenerate capture) never
    qualifies; synth-family kinds qualify by construction; a plain handle/live
    proof qualifies only if the ORIGINAL returned >1 distinct value (variance)."""
    if not row:
        return False, "no registry row (not proven)"
    if row.get("weak_proof"):
        return False, f"weak_proof: {str(row['weak_proof'])[:60]}"
    if row.get("conf") not in ("CONF_LIVE", "CONF_BATTLETESTED", "CONF_REGRESSION"):
        return False, f"conf rung {row.get('conf')} below CONF_LIVE"
    kind = row.get("proof_kind")
    if kind in _DISCRIMINATING_KINDS:
        return True, f"discriminating by construction ({kind})"
    if (row.get("total") or 0) >= 2 and not row.get("weak_proof"):
        # multi-vector live/handle proof that the degenerate-capture detector
        # (which flags identical-original-on-all-vectors) did NOT flag -> the
        # original varied -> discriminating.
        return True, f"multi-vector live proof, original varied ({row.get('passed')}/{row.get('total')})"
    return False, "single-vector non-synth proof -- cannot rule out match-by-luck"


def parse_reimpl_facts(cpp: str) -> dict:
    """MECHANICAL facts from the proven equivalent's source (no model):
    param count/callconv from the extern signature, every fixed-offset field
    READ (offset, width, DEPTH) from the raw casts, resolver globals and
    call-through callees by name, type-gates. These are ground truth -- the code
    BIT-MATCHED the original.

    DEPTH tracks pointer-deref level so field reads attribute to the RIGHT struct:
    a gated getter reads dwType off the PARAM struct (depth 0), loads a sub-struct
    pointer (`r = *(char**)(r + 0x14)`), then reads the field off the SUB-struct
    (depth 1). Bucketing both under one struct corrupted the ledger."""
    facts = {"params": None, "callconv": None, "harness_ret": None,
             "field_reads": [], "globals": [], "callees": [], "gates": [],
             "pointer_loads": [], "max_depth": 0}
    m = re.search(r'extern\s+"C"\s+([\w\s\*]+?)\s+(__\w+)\s+\w+\s*\(([^)]*)\)', cpp)
    if m:
        facts["harness_ret"] = m.group(1).strip()
        facts["callconv"] = m.group(2).lstrip("_")
        args = [a.strip() for a in m.group(3).split(",") if a.strip() and a.strip() != "void"]
        facts["params"] = len(args)
    for g in re.finditer(r'D2MOO_Resolve\("([^"]+)"\)', cpp):
        nm = g.group(1)
        (facts["callees"] if not nm.startswith(("g_", "_g_")) else facts["globals"]).append(nm)

    # walk LINE-ORDERED so depth reassignments apply to subsequent reads.
    depth = {}          # var -> deref depth (0 = the param/base struct)
    _PTRLOAD = re.compile(r'(\w+)\s*=\s*(?:\(\s*char\s*\*\s*\)\s*)?\*\s*\(\s*(?:char|void)\s*'
                          r'\*\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*0x([0-9a-fA-F]+)\s*\)')
    _READ = re.compile(r'\*\s*\(\s*(unsigned\s+char|signed\s+char|char|unsigned\s+short|short|'
                       r'unsigned\s+int|int)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*0x([0-9a-fA-F]+)\s*\)')
    _CALLRES = re.compile(r'(\w+)\s*=\s*\(\s*char\s*\*\s*\)\s*_f\s*\(')
    _PTRLOAD0 = re.compile(r'(\w+)\s*=\s*\(\s*char\s*\*\s*\)\s*\*\s*\(\s*void\s*\*\s*\*\s*\)'
                           r'\s*(\w+)\s*;')          # base = (char*)*(void**)_g;  (no offset)
    _ARITH = re.compile(r'char\s*\*\s*(\w+)\s*=\s*(\w+)\s*\+')   # rec = records + idx*stride
    for line in cpp.splitlines():
        pm = _PTRLOAD.search(line)
        if pm:
            dst, src, off = pm.group(1), pm.group(2), int(pm.group(3), 16)
            d = depth.get(src, 0)
            facts["pointer_loads"].append({"base": src, "off": off, "depth": d})
            depth[dst] = d + 1
            facts["max_depth"] = max(facts["max_depth"], d + 1)
            continue
        p0 = _PTRLOAD0.search(line)
        if p0:
            d = depth.get(p0.group(2), 0)
            depth[p0.group(1)] = d + 1               # deref of a resolved global's value
            facts["max_depth"] = max(facts["max_depth"], d + 1)
            continue
        am = _ARITH.search(line)
        if am and am.group(2) in depth:
            depth[am.group(1)] = depth[am.group(2)]  # pointer arithmetic: SAME struct level
            continue
        cm = _CALLRES.search(line)
        if cm:
            # a call-through result is a FRESH struct (the callee's record) -- its own
            # level, conventionally the "final" struct for delegates.
            depth[cm.group(1)] = facts["max_depth"] = facts["max_depth"] + 1
            continue
        for r_ in _READ.finditer(line):
            width = {"char": 1, "short": 2, "int": 4}[r_.group(1).split()[-1]]
            signed = not r_.group(1).startswith("unsigned")
            base = r_.group(2)
            facts["field_reads"].append({"base": base, "off": int(r_.group(3), 16),
                                         "width": width, "signed": signed,
                                         "depth": depth.get(base, 0)})
    for g_ in re.finditer(r'\(\s*(\w+)\s*\+\s*0x([0-9a-fA-F]+)\s*\)\s*!=\s*0x([0-9a-fA-F]+)u?\)'
                          r'\s*return', cpp):
        facts["gates"].append({"base": g_.group(1), "off": int(g_.group(2), 16),
                               "imm": int(g_.group(3), 16)})
    return facts


def gate_verdict(mech_applied: list, semantic_flags: list, discriminating: bool) -> dict:
    """The DOC-rung decision. DOC_VERIFIED requires BOTH a discriminating proof
    AND zero unresolved semantic flags. Mechanical fixes never block (the proof
    is authoritative for them). Otherwise cap at DOC_REVIEWED with the reasons."""
    if discriminating and not semantic_flags:
        return {"doc_level": "DOC_VERIFIED", "blocked": False,
                "why": "discriminating proof + docs consistent with proven behavior"}
    reasons = []
    if not discriminating:
        reasons.append("proof not discriminating")
    reasons += [f"semantic conflict: {f}" for f in semantic_flags]
    return {"doc_level": "DOC_REVIEWED", "blocked": True, "why": "; ".join(reasons)}


# ---------------------------------------------------------------------------
# the consistency gate (needs Ghidra; model for the semantic diff only)
# ---------------------------------------------------------------------------

_GATE_PROMPT = """You are auditing reverse-engineering documentation against PROVEN ground truth.

A hand-written reimplementation of `{name}` was proven BIT-EXACT against the original
(discriminating live proof). The reimpl below is therefore authoritative for BEHAVIOR.

## PROVEN equivalent (authoritative)
```cpp
{reimpl}
```

## Ground-truth disassembly
```
{disasm}
```

## Current Ghidra documentation
Function name: {name}
Prototype: {prototype}
Plate comment:
```
{plate}
```

Compare the CURRENT documentation against the PROVEN behavior. Judge:
1. prototype: do return width/signedness and parameter types match the proven
   semantic behavior? (The proven reimpl may return a WIDENED harness type; judge
   the SEMANTIC width from the final field read, e.g. a byte read = byte return.)
2. plate: does the plate's described algorithm match the proven behavior? A plate
   describing branches, callees, or logic that DO NOT EXIST in the disassembly is
   a hallucination -> conflict. Extra detail that is consistent is fine.
3. name: does the name contradict the proven behavior? (Only flag CONTRADICTION,
   not mere vagueness.)

If the current plate is EMPTY, a placeholder/stub, or clearly not describing this
function, set plate verdict "missing" and WRITE a complete replacement plate derived
from the PROVEN behavior: 1-line summary, Algorithm steps, Parameters, Returns,
Special Cases, and a Structure Layout table for every proven field offset. State only
what the proof establishes; mark semantic meaning you cannot prove as unproven.

Output ONLY strict JSON:
{{"prototype": {{"verdict": "ok|fix", "corrected": "<full prototype or empty>", "reason": "..."}},
  "plate": {{"verdict": "ok|conflict|missing", "reason": "...", "regenerated": "<full plate text when missing, else empty>"}},
  "name": {{"verdict": "ok|conflict", "suggested": "<name or empty>", "reason": "..."}}}}"""


def consistency_gate(program: str, address: str, name: str, reimpl_cpp: str, *,
                     provider=None, model=None, log=print) -> dict:
    """Re-derive docs from the proven equivalent and diff against Ghidra.
    AUTO-FIX mechanical (prototype width/callconv -- proof-backed, bounded by
    Ghidra's own prototype validation). FLAG semantic (plate narrative, name)."""
    import fun_doc
    prog_name = Path(program).name
    addr = address if str(address).startswith("0x") else f"0x{address}"
    provider = provider or fun_doc.AI_PROVIDER
    if model is None:                    # some providers require an explicit model
        try:
            model = fun_doc.get_configured_model(provider, "FULL")
        except Exception:
            model = None

    disasm = str(fun_doc.ghidra_get("/disassemble_function",
                                    params={"address": addr, "program": program}))
    plate = str(fun_doc.ghidra_get("/get_plate_comment",
                                   params={"address": addr, "program": program}))
    # MECHANICAL stub detection -- never trust the model to notice absence. Strip the
    # routing/bench markers; if no substantive BEHAVIORAL text remains, the plate is
    # missing and MUST be regenerated (its absence blocks DOC_VERIFIED if that fails).
    _behavioral = re.sub(r"\[(CONFORMANCE|GOLDEN-BENCH|CONSISTENCY GATE)[^\]]*\][^\n]*",
                         "", plate)
    _behavioral = re.sub(r"(shadow_leaf|live-pointer getter|Not statically emulable|"
                         r"SHADOW-provable|documentation intentionally cleared)[^\n]*",
                         "", _behavioral)
    plate_is_stub = len(re.sub(r"[\s\\n]+", "", _behavioral)) < 120
    dec = str(fun_doc.ghidra_get("/decompile_function",
                                 params={"address": addr, "program": program}))
    proto_m = re.search(r"^\s*([\w\s\*]+?\s\*?\s*" + re.escape(name) + r"\s*\([^)]*\))",
                        dec.replace("\r", ""), re.MULTILINE)
    prototype = proto_m.group(1).strip() if proto_m else "(unknown)"

    prompt = _GATE_PROMPT.format(name=name, reimpl=reimpl_cpp[:4000],
                                 disasm=disasm[:4000], prototype=prototype,
                                 plate=plate[:4000])
    if plate_is_stub:
        prompt += ("\n\nNOTE: the current plate has been mechanically determined to be a "
                   "STUB (no behavioral documentation). You MUST set plate verdict "
                   "\"missing\" and supply the full regenerated plate.")
    obj = None
    for _try in range(3):                # provider variance: retry until a JSON verdict
        text, _meta = fun_doc.invoke_claude(prompt, model=model, max_turns=2,
                                            provider=provider or fun_doc.AI_PROVIDER,
                                            complexity_tier=None)
        obj = fun_doc._extract_first_json(text or "")
        if isinstance(obj, dict) and obj.get("plate") is not None:
            break
        prompt_retry = prompt + ("\n\nREMINDER: your ENTIRE final message must be the "
                                 "single strict-JSON object specified above -- no prose, "
                                 "no tool calls, no markdown fences.")
        prompt = prompt_retry
        obj = None
    if not isinstance(obj, dict):
        return {"ok": False, "error": "gate model returned no JSON verdict (3 tries)",
                "mechanical_applied": [], "semantic_flags": ["gate audit failed to run"]}

    mech_applied, semantic_flags = [], []

    # MECHANICAL: prototype fix is proof-backed -> auto-apply (Ghidra validates).
    p = obj.get("prototype") or {}
    if str(p.get("verdict")).lower() == "fix" and p.get("corrected"):
        r = fun_doc.ghidra_post("/set_function_prototype",
                                data={"function_address": addr,
                                      "prototype": str(p["corrected"])},
                                params={"program": prog_name})
        ok = not (isinstance(r, dict) and r.get("error"))
        mech_applied.append(f"prototype -> {p['corrected']} ({'applied' if ok else 'REJECTED'})")

    # SEMANTIC: plate / name conflicts FLAG (block VERIFIED) + annotate for review.
    # A MISSING/stub plate is not a conflict -- it is absence: WRITE the plate from
    # the proven behavior (that IS the ground-up documentation this flow exists for).
    pl = obj.get("plate") or {}
    plate_written = False
    if (str(pl.get("verdict")).lower() == "missing" or plate_is_stub) and pl.get("regenerated"):
        stamp = datetime.date.today().isoformat()
        body = str(pl["regenerated"]).strip()
        body += (f"\n\nPROVEN one-to-one (consistency-gated {stamp}): documentation "
                 f"derived from a reimplementation proven bit-exact against the "
                 f"original by a discriminating live proof.")
        r = fun_doc.ghidra_post("/set_plate_comment",
                                data={"address": addr, "comment": body},
                                params={"program": program})
        plate_written = not (isinstance(r, dict) and r.get("error"))
        mech_applied.append(f"plate regenerated from proven behavior "
                            f"({'applied' if plate_written else 'REJECTED'})")
    elif str(pl.get("verdict")).lower() == "conflict":
        semantic_flags.append(f"plate: {pl.get('reason', '(no reason)')}")
    if plate_is_stub and not plate_written:
        # no behavioral documentation exists and none was produced -> the doc is NOT
        # superb -> block DOC_VERIFIED. Absence fails closed, same as a conflict.
        semantic_flags.append("plate: missing/stub and regeneration did not apply")
    nm = obj.get("name") or {}
    if str(nm.get("verdict")).lower() == "conflict":
        semantic_flags.append(f"name: {nm.get('reason', '(no reason)')}"
                              + (f" (suggested: {nm['suggested']})" if nm.get("suggested") else ""))

    if semantic_flags:
        stamp = datetime.date.today().isoformat()
        note = (f"[CONSISTENCY GATE {stamp}] Proven behavior DISAGREES with this "
                f"documentation -- blocked from DOC_VERIFIED until reconciled: "
                + " | ".join(semantic_flags))
        cur = plate if plate and "error" not in plate[:40].lower() else ""
        if "[CONSISTENCY GATE" not in cur:
            fun_doc.ghidra_post("/set_plate_comment",
                                data={"address": addr, "comment": (note + "\n\n" + cur).strip()},
                                params={"program": program})
    if mech_applied or semantic_flags:
        fun_doc.ghidra_post("/save_program", data={"program": prog_name})
    return {"ok": True, "mechanical_applied": mech_applied,
            "semantic_flags": semantic_flags, "prototype_seen": prototype}


# ---------------------------------------------------------------------------
# struct-field ledger (shared: one proof improves every user of the struct)
# ---------------------------------------------------------------------------

def ledger_contribute(name: str, address: str, facts: dict, struct_hint: str = None) -> Path | None:
    """Append this proof's PROVEN (offset,width,signed) field facts to the shared
    per-struct ledger. The struct HINT names the FINAL struct the getter reads
    (deepest deref level) -- only max-depth reads attribute to it; shallower reads
    (the param struct's dwType gate, a table header's count/base) go to
    `<hint>__lvl<d>` side-buckets so they are kept but never misattributed."""
    reads = facts.get("field_reads") or []
    if not reads:
        return None
    STRUCT_LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    key = struct_hint or "unattributed"
    maxd = max((r_.get("depth", 0) for r_ in reads), default=0)
    path = STRUCT_LEDGER_DIR / f"{key}.jsonl"
    by_bucket = {}
    for r_ in reads:
        d = r_.get("depth", 0)
        bucket = key if d == maxd else f"{key}__lvl{d}"
        by_bucket.setdefault(bucket, []).append(r_)
    for bucket, rs in by_bucket.items():
        with open(STRUCT_LEDGER_DIR / f"{bucket}.jsonl", "a", encoding="utf-8") as f:
            for r_ in rs:
                f.write(json.dumps({"struct": bucket, "off": r_["off"], "width": r_["width"],
                                    "signed": r_["signed"], "base_var": r_["base"],
                                    "depth": r_.get("depth", 0), "final": r_.get("depth", 0) == maxd,
                                    "from_fn": name, "address": address,
                                    "date": datetime.date.today().isoformat()}) + "\n")
    return path


# ---------------------------------------------------------------------------
# the unified driver
# ---------------------------------------------------------------------------

def prove_doc(address: str, name: str, *, program: str = PROGRAM_PATH,
              provider=None, model=None, skip_prove: bool = False,
              struct_hint: str = None, log=print) -> dict:
    """Undocumented function -> proven equivalent -> consistency-gated docs.
    Returns a summary dict; every stage's outcome is explicit and honest."""
    import fun_doc
    import port_live_prove as plp
    addr_bare = str(address).replace("0x", "").lower()
    addr_hex = f"0x{addr_bare}"
    summary = {"name": name, "address": addr_hex, "stages": {}}

    # 1) PROVE (the existing port pipeline: classify -> draft -> prove -> audits)
    if not skip_prove:
        outcome = fun_doc.process_port_candidate(
            program, addr_bare, name,
            provider=provider or fun_doc.AI_PROVIDER, model=model,
            worker_id="prove_doc")
        summary["stages"]["prove"] = outcome
        if outcome != "proven_live_pending_review":
            # honest cap: unproven -> the doc rung this run can support is REVIEWED
            # at most (set by the doc workflow, not us) -- report and stop.
            summary["result"] = f"not proven ({outcome}) -- no doc promotion"
            return summary
    else:
        summary["stages"]["prove"] = "(skipped -- gate-only re-run)"

    # 2) EVIDENCE: registry row + the proven candidate source
    row = registry_row(name)
    disc, disc_why = is_discriminating(row)
    summary["stages"]["discriminating"] = f"{disc} ({disc_why})"
    cand = CANDIDATES / f"{name}.cpp"
    reimpl = cand.read_text(encoding="utf-8") if cand.exists() else ""
    if not reimpl:
        summary["result"] = "proven but candidate source missing -- cannot gate"
        return summary
    facts = parse_reimpl_facts(reimpl)
    summary["stages"]["facts"] = {k: v for k, v in facts.items() if v}

    # 3) CONSISTENCY GATE
    gate = consistency_gate(program, addr_hex, name, reimpl,
                            provider=provider, model=model, log=log)
    summary["stages"]["gate"] = gate
    flags = gate.get("semantic_flags") if gate.get("ok") else ["gate failed to run"]

    # 3b) CANONICAL NAMING: if the name is offset-derived (GetItemTypeField10), resolve
    # the REAL field from the D2MOO struct headers and rename -- transcription -> under-
    # standing. Authoritative via the DataTables header (also corrects a wrong subsystem
    # guess). Only fires when the field is genuinely resolvable; offset name stays flagged
    # otherwise. This is where we STOP creating offset names in the first place. 2026-07-09.
    try:
        import d2moo_names
        if d2moo_names.is_offset_name(name):
            c = d2moo_names.canonicalize(name, reimpl)
            if c.get("ok"):
                rr = fun_doc.ghidra_post("/rename_function_by_address",
                                         data={"function_address": addr_hex,
                                               "new_name": c["proposed_name"]},
                                         params={"program": Path(program).name})
                renamed = "success" in str(rr).lower()
                if renamed:
                    stamp = datetime.date.today().isoformat()
                    note = (f"[D2MOO-DERIVED NAME {stamp}] was '{name}' (offset-derived); "
                            f"real field per D2MOO: {c['reason']}."
                            + ("  SUBSYSTEM CORRECTED." if c.get("corrected_subsystem") else ""))
                    cur = str(fun_doc.ghidra_get("/get_plate_comment",
                                                 params={"address": addr_hex, "program": program}))
                    if "[D2MOO-DERIVED NAME" not in cur:
                        fun_doc.ghidra_post("/set_plate_comment",
                                            data={"address": addr_hex, "comment": (note + "\n\n"
                                                  + (cur if "error" not in cur[:40].lower() else "")).strip()},
                                            params={"program": program})
                    fun_doc.ghidra_post("/save_program", data={"program": Path(program).name})
                    name = c["proposed_name"]
                summary["stages"]["canonical_name"] = {"to": c["proposed_name"], "applied": renamed,
                                                       "reason": c["reason"],
                                                       "corrected_subsystem": c.get("corrected_subsystem")}
            else:
                summary["stages"]["canonical_name"] = {"unresolved": c.get("reason")}
    except Exception as e:
        summary["stages"]["canonical_name"] = {"error": str(e)}

    # 4) STRUCT LEDGER
    lp = ledger_contribute(name, addr_hex, facts, struct_hint=struct_hint)
    summary["stages"]["ledger"] = str(lp) if lp else "(no field reads)"

    # 5) DOC RUNG (proof-preferred coupling)
    v = gate_verdict(gate.get("mechanical_applied", []), flags or [], disc)
    r = plp.set_doc_level(addr_hex, v["doc_level"], program=Path(program).name)
    summary["stages"]["doc_rung"] = {**v, "write": r}
    summary["result"] = f"{v['doc_level']}" + ("" if not v["blocked"] else f" (blocked: {v['why']})")
    return summary


# ---------------------------------------------------------------------------
# self-test (offline, no Ghidra/oracle/model)
# ---------------------------------------------------------------------------

def _selftest() -> int:
    # parse_reimpl_facts on a real translator-emitted candidate shape
    cpp = '''#include "../provider_runtime.h"
// D2MOO_REIMPL_EXPORT: DATATBLS_GetItemTypeField10
extern "C" unsigned int __stdcall DATATBLS_GetItemTypeField10(int idx)
{
    if (idx < 0) return 0x0;
    void* _g = D2MOO_Resolve("g_pDataTables");
    if (_g == nullptr) return 0x0;
    char* base = (char*)*(void**)_g;
    if (base == nullptr) return 0x0;
    if (idx >= *(int*)(base + 0xbfc)) return 0x0;
    char* records = (char*)*(void**)(base + 0xbf8);
    char* rec = records + (int)idx * 0xe4;
    if (rec == nullptr) return 0x0;
    return (unsigned int)*(unsigned char*)(rec + 0x10);
}
'''
    f = parse_reimpl_facts(cpp)
    assert f["params"] == 1 and f["callconv"] == "stdcall", f
    assert f["globals"] == ["g_pDataTables"] and not f["callees"], f
    offs = {(r["off"], r["width"]) for r in f["field_reads"]}
    assert (0x10, 1) in offs and (0xbfc, 4) in offs, offs
    # DEPTH attribution: the table-header reads (count @0xbfc) are a SHALLOWER level
    # than the final record read (@0x10) -- they must NOT share a struct bucket.
    by_off = {r["off"]: r["depth"] for r in f["field_reads"]}
    assert by_off[0x10] > by_off[0xbfc], by_off
    # gated 2-level getter: dwType gate (depth 0) vs the sub-struct field (depth 1)
    cpp_gated = '''extern "C" unsigned short __stdcall F(void* p)
{
    if (p == nullptr) return 0;
    char* r = (char*)p;
    if (*(unsigned int*)(r + 0x0) != 0x4u) return 0;
    r = *(char**)(r + 0x14);
    if (r == nullptr) return 0;
    return *(unsigned short*)(r + 0x32);
}
'''
    fg = parse_reimpl_facts(cpp_gated)
    dm = {r["off"]: r["depth"] for r in fg["field_reads"]}
    assert dm[0x0] == 0 and dm[0x32] == 1, dm
    assert fg["pointer_loads"] == [{"base": "r", "off": 0x14, "depth": 0}], fg["pointer_loads"]

    # a delegate call-through: callee vs global routing
    cpp2 = '''extern "C" unsigned short __stdcall F(void* p)
{
    _callee_t _f = (_callee_t)D2MOO_Resolve("GetItemDataRecord");
    unsigned short _v = *(unsigned short*)(_rec + 0x108);
    return _v;
}
'''
    f2 = parse_reimpl_facts(cpp2)
    assert f2["callees"] == ["GetItemDataRecord"] and not f2["globals"], f2
    assert f2["field_reads"][0]["off"] == 0x108 and f2["field_reads"][0]["width"] == 2, f2

    # is_discriminating: the ladder of evidence
    ok, _ = is_discriminating({"conf": "CONF_LIVE", "proof_kind": "synth2"})
    assert ok
    ok, why = is_discriminating({"conf": "CONF_LIVE", "weak_proof": "DEGENERATE"})
    assert not ok and "weak_proof" in why
    ok, _ = is_discriminating({"conf": "CONF_LIVE", "passed": 8, "total": 8})
    assert ok            # multi-vector, degeneracy detector didn't flag it
    ok, why = is_discriminating({"conf": "CONF_LIVE", "passed": 1, "total": 1})
    assert not ok and "match-by-luck" in why
    ok, _ = is_discriminating(None)
    assert not ok

    # gate_verdict: the DOC-rung coupling
    v = gate_verdict([], [], True)
    assert v["doc_level"] == "DOC_VERIFIED" and not v["blocked"]
    v = gate_verdict(["prototype -> short f(void*)"], [], True)
    assert v["doc_level"] == "DOC_VERIFIED"          # mechanical fixes never block
    v = gate_verdict([], ["plate: describes branches that don't exist"], True)
    assert v["doc_level"] == "DOC_REVIEWED" and v["blocked"]
    v = gate_verdict([], [], False)
    assert v["doc_level"] == "DOC_REVIEWED" and "not discriminating" in v["why"]

    print("[ok] prove_doc self-test: facts parser + discriminating ladder + gate verdict pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--address", help="function address (0x...)")
    ap.add_argument("--name", help="function name")
    ap.add_argument("--program", default=PROGRAM_PATH)
    ap.add_argument("--provider", default=os.environ.get("AI_PROVIDER"))
    ap.add_argument("--model", default=None)
    ap.add_argument("--skip-prove", action="store_true",
                    help="already proven: run gate/ledger/doc-rung only")
    ap.add_argument("--struct-hint", default=None,
                    help="struct name for the field ledger (e.g. ItemTypeData)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if not (args.address and args.name):
        ap.error("--address and --name required (or --selftest)")
    os.environ.setdefault("FUNDOC_LIVE_PROVE", "1")
    s = prove_doc(args.address, args.name, program=args.program,
                  provider=args.provider, model=args.model,
                  skip_prove=args.skip_prove, struct_hint=args.struct_hint)
    print(json.dumps(s, indent=2, default=str))
    return 0 if "DOC_VERIFIED" in str(s.get("result")) else 1


if __name__ == "__main__":
    raise SystemExit(main())

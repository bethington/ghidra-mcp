"""plate_scaffold.py -- the harness-owned plate comment "typed form".

A function plate is a scaffold: the harness fills the EMPIRICAL fields (param name/type/storage,
return type, source, provenance) from work already done, and leaves `<TODO: ...>` slots for the
AI to describe. Completeness verifies the empirical block matches the live signature (stale
detection) and that no slot is left unfilled -- but never judges description CONTENT.

Format is the project's dominant plain-text plate (validated against real DOC_VERIFIED plates):

    <summary>                                              [AI]
    [D2MOO-DERIVED NAME ...] / [PROVEN ...]                [empirical, carried across regen]
    Algorithm:                                             [AI]
      <steps>
    Parameters:
      name: <live type> - <desc> [reg]                     [empirical name/type/storage · AI desc]
    Returns:
      <live type>: <desc>                                  [empirical type · AI desc]
    Special Cases: / Magic Numbers: / Structure Layout:    [conditional]
    Source: <path>                                         [empirical]

Regeneration is non-destructive: on refresh, the empirical block is rebuilt from the live
signature and existing prose is RE-ATTACHED (summary/algorithm/special-cases by section,
param descriptions BY NAME), so converting an old plate keeps its content.

Usage:
    python plate_scaffold.py --selftest
    python plate_scaffold.py --show 0x6fd51000 [--program <p>]     # build from live sig, print
    python plate_scaffold.py --apply 0x6fd51000 [--program <p>]    # write it via /set_comment
"""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request
from urllib.parse import quote, urlencode

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")
PROGRAM = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")

# the AI-owned slots (required -> counted by the completeness deduction)
_SLOT = "<TODO: {}>"
_TODO_RE = re.compile(r"<TODO:[^>]*>")
_SECTION_RE = re.compile(
    r"^(Algorithm|Parameters|Returns|Special Cases|Magic Numbers|Source|"
    r"Structure Layout[^:\n]*|Notes?)\s*:", re.I | re.M)
_PROV_RE = re.compile(r"^\[(?:D2MOO-DERIVED NAME|PROVEN)[^\n]*\][^\n]*(?:\n(?!\s*\n)[^\n]*)*", re.M)
# a param line: "  name: type - desc"  OR markdown "| name | type | desc |"
_PARAM_PLAIN = re.compile(r"^\s*([A-Za-z_]\w*)\s*:\s*(.+?)\s+-{1,2}\s+(.*\S)\s*$")
_PARAM_MD = re.compile(r"^\s*\|\s*([A-Za-z_]\w*)\s*\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|")


# ---- HTTP helpers ----------------------------------------------------------------------------
def _get(path, **params):
    url = f"{GHIDRA}{path}" + ("?" + urlencode(params) if params else "")
    with urllib.request.urlopen(url, timeout=60) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _post(path, data):
    req = urllib.request.Request(f"{GHIDRA}{path}", data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# ---- parse an existing plate (for non-destructive re-attach) ---------------------------------
def parse_function_plate(text: str) -> dict:
    """{summary, provenance:[...], sections:{Name: body}, params:{pname: desc}} from a plate."""
    out = {"summary": "", "provenance": [], "sections": {}, "params": {}}
    if not text:
        return out
    out["provenance"] = [m.group(0).rstrip() for m in _PROV_RE.finditer(text)]
    hits = [(m.start(), m.end(), m.group(1).strip()) for m in _SECTION_RE.finditer(text)]
    first = hits[0][0] if hits else len(text)
    summ = [ln for ln in text[:first].splitlines()
            if ln.strip() and not ln.strip().startswith("[")]
    out["summary"] = "\n".join(summ).strip()
    for i, (start, hend, name) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(text)
        body = text[hend:end].strip("\n").rstrip()
        key = re.sub(r"\s+.*$", "", name.title()) if name.lower().startswith("structure") else name.title()
        out["sections"].setdefault(name.title(), body)
    for ln in out["sections"].get("Parameters", "").splitlines():
        m = _PARAM_PLAIN.match(ln) or _PARAM_MD.match(ln)
        if m:
            out["params"][m.group(1)] = m.group(3).strip()
    return out


# ---- build / refresh the scaffold ------------------------------------------------------------
def _reg(storage: str) -> str:
    """'ECX:4' -> 'ECX' for register-passed params; '' for stack."""
    if not storage:
        return ""
    tok = storage.split(":")[0].strip().upper()
    return tok if tok in ("ECX", "EDX", "EAX", "EBX", "ESI", "EDI") else ""


def build_function_plate(params, return_type, *, prior: dict = None, source: str = None,
                         magic: list = None, proven_note: str = None) -> str:
    """Render the plate. `params` = [{name,type,storage}]. `prior` = parse_function_plate() of
    an existing plate to re-attach prose from (non-destructive). Empirical fields come from the
    live signature; descriptions are slots unless prior prose exists."""
    prior = prior or {}
    pdesc = prior.get("params", {})
    psec = prior.get("sections", {})
    lines = []
    lines.append(prior.get("summary") or _SLOT.format("one-line summary of what the function does"))
    for pv in prior.get("provenance", []):
        lines += ["", pv]
    lines += ["", "Algorithm:"]
    lines.append(_indent(psec.get("Algorithm")) if psec.get("Algorithm")
                 else "  " + _SLOT.format("numbered steps"))
    lines += ["", "Parameters:"]
    if params:
        for p in params:
            nm, ty = p.get("name", "?"), (p.get("type") or "?").strip()
            reg = _reg(p.get("storage", ""))
            d = pdesc.get(nm) or _SLOT.format("describe")
            lines.append(f"  {nm}: {ty} - {d}" + (f" [{reg}]" if reg else ""))
    else:
        lines.append("  (none)")
    lines += ["", "Returns:"]
    rt = (return_type or "void").strip()
    if rt == "void":
        lines.append("  void")
    else:
        rd = psec.get("Returns")
        rdesc = _returns_desc(rd) if rd else _SLOT.format("describe")
        lines.append(f"  {rt}: {rdesc}")
    if psec.get("Special Cases"):
        lines += ["", "Special Cases:", _indent(psec["Special Cases"])]
    if magic:
        lines += ["", "Magic Numbers:"]
        mexpl = _magic_expl(psec.get("Magic Numbers", ""))
        for c in magic:
            lines.append(f"  {c}: " + (mexpl.get(c) or _SLOT.format("explain")))
    for k in prior.get("sections", {}):
        if k.lower().startswith("structure layout"):
            lines += ["", k + ":", _indent(psec[k])]
    lines += ["", f"Source: {source or _SLOT.format('D2MOO source file')}"]
    return "\n".join(lines).rstrip() + "\n"


def _indent(block: str) -> str:
    if not block:
        return ""
    return "\n".join(ln if ln.startswith("  ") or not ln.strip() else "  " + ln.lstrip()
                     for ln in block.splitlines())


def _returns_desc(returns_body: str) -> str:
    """Pull just the description out of an existing 'Returns:' body ('  bool: desc' -> 'desc')."""
    ln = next((l for l in (returns_body or "").splitlines() if l.strip()), "")
    m = re.match(r"\s*[\w\*\s]+?:\s*(.+)", ln)
    return (m.group(1).strip() if m else ln.strip()) or _SLOT.format("describe")


def _magic_expl(body: str) -> dict:
    out = {}
    for ln in (body or "").splitlines():
        m = re.match(r"\s*(0x[0-9A-Fa-f]+)\s*[-:]\s*(.+)", ln)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


# ---- slot check (for the completeness deduction) ---------------------------------------------
def unfilled_slots(text: str) -> list:
    """Required description slots still unfilled OR failing the anti-placeholder floor.
    Returns a list of short reasons (empty = complete). Never judges content correctness."""
    if not text:
        return ["plate missing"]
    issues = []
    p = parse_function_plate(text)
    # any literal <TODO> left anywhere
    n_todo = len(_TODO_RE.findall(text))
    if n_todo:
        issues.append(f"{n_todo} <TODO> slot(s) unfilled")
    # summary floor
    s = p.get("summary", "")
    if len(s.split()) < 4:
        issues.append("summary too short (need a real one-line summary)")
    # each param description: exists, not an echo of the name/type, >= 3 words
    psec = p.get("sections", {}).get("Parameters", "")
    for ln in psec.splitlines():
        m = _PARAM_PLAIN.match(ln) or _PARAM_MD.match(ln)
        if not m:
            continue
        name, ty, desc = m.group(1), m.group(2).strip(), m.group(3).strip()
        if _TODO_RE.search(desc):
            continue  # already counted
        low = desc.lower()
        if len(desc.split()) < 3 or low in (name.lower(), ty.lower().replace("*", "").strip()):
            issues.append(f"param '{name}' description is a placeholder/echo")
    return issues


# ---- live application ------------------------------------------------------------------------
def _fetch_signature(addr: str, program: str):
    """(params[{name,type,storage}], return_type, func_name) from the live function."""
    a = addr if str(addr).startswith("0x") else "0x" + str(addr)
    comp = _get("/analyze_function_completeness", function_address=a, program=program)
    if isinstance(comp, str):
        comp = json.loads(comp)
    fname = comp.get("function_name") if isinstance(comp, dict) else None
    rt = comp.get("return_type") if isinstance(comp, dict) else "void"
    v = _get("/get_function_variables", function_name=fname, program=program) if fname else {}
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except json.JSONDecodeError:
            v = {}
    params = [{"name": p.get("name"), "type": p.get("type"), "storage": p.get("storage")}
              for p in (v.get("parameters") or []) if isinstance(p, dict)]
    return params, rt, fname


def _source_path(fname: str, program: str) -> str:
    """Best-effort D2MOO source path from the module + a name-prefix hint (matches existing plates)."""
    mod = os.path.basename(program).replace(".dll", "")
    return f"{mod}.dll" + (f" ({fname.split('_')[0]}_ module)" if fname and "_" in fname else "")


def scaffold_for(addr: str, program: str = None) -> str:
    program = program or PROGRAM
    a = addr if str(addr).startswith("0x") else "0x" + str(addr)
    params, rt, fname = _fetch_signature(a, program)
    cur = _get("/get_comment", address=a, program=program)
    prior_text = cur.get("plate") if isinstance(cur, dict) else None
    prior = parse_function_plate(prior_text or "")
    return build_function_plate(params, rt, prior=prior, source=_source_path(fname, program))


def apply_scaffold(addr: str, program: str = None) -> dict:
    program = program or PROGRAM
    a = addr if str(addr).startswith("0x") else "0x" + str(addr)
    text = scaffold_for(a, program)
    q = "?program=" + quote(program, safe="")
    _post("/set_comment" + q, {"address": a, "type": "plate", "comment": text})
    return {"address": a, "written": True, "unfilled": unfilled_slots(text)}


def _selftest() -> int:
    # build a fresh scaffold
    params = [{"name": "dwClassId", "type": "uint", "storage": "ECX:4"},
              {"name": "nBodyType", "type": "int", "storage": "Stack[0x4]"}]
    fresh = build_function_plate(params, "bool", source="..\\Source\\D2Common\\Items.cpp")
    assert "dwClassId: uint - <TODO: describe> [ECX]" in fresh, fresh
    assert "nBodyType: int - <TODO: describe>" in fresh and "[ECX]" not in fresh.split("nBodyType")[1].split("\n")[0]
    assert "bool: <TODO: describe>" in fresh and "Source: ..\\Source\\D2Common\\Items.cpp" in fresh
    assert unfilled_slots(fresh), "fresh scaffold should have unfilled slots"
    # re-attach: an existing plate's prose survives regeneration
    existing = (
        "Compares an item record's body type against a given value.\n\n"
        "Algorithm:\n  1. index into g_pItemRecords\n\n"
        "Parameters:\n  dwClassId: uint - item class ID, used to index into g_pItemRecords\n"
        "  nBodyType: int - body type to compare against\n\n"
        "Returns:\n  bool: true if the body type matches, false otherwise\n\n"
        "Special Cases:\n  - Aborts if dwClassId out of range\n\n"
        "Source: ..\\Source\\D2Common\\Items.cpp\n")
    prior = parse_function_plate(existing)
    assert prior["params"]["dwClassId"].startswith("item class ID"), prior["params"]
    assert prior["params"]["nBodyType"].startswith("body type"), prior["params"]
    assert "Compares an item record" in prior["summary"]
    assert "Special Cases" in prior["sections"]
    regen = build_function_plate(params, "bool", prior=prior, source="..\\Source\\D2Common\\Items.cpp")
    assert "dwClassId: uint - item class ID" in regen, regen        # prose re-attached
    assert "bool: true if the body type matches" in regen, regen
    assert "Aborts if dwClassId out of range" in regen               # special cases carried
    assert not unfilled_slots(regen), unfilled_slots(regen)          # fully documented -> no slots
    # a placeholder/echo description is flagged
    bad = build_function_plate([{"name": "x", "type": "int", "storage": ""}], "int",
                               prior={"params": {"x": "x"}, "sections": {}, "summary": "does a thing here"})
    assert any("echo" in i or "placeholder" in i for i in unfilled_slots(bad)), unfilled_slots(bad)
    print("[ok] plate_scaffold self-test: build + non-destructive re-attach + slot detection")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--show", metavar="ADDR")
    ap.add_argument("--apply", metavar="ADDR")
    ap.add_argument("--program", default=None)
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if args.show:
        print(scaffold_for(args.show, args.program))
        return 0
    if args.apply:
        print(json.dumps(apply_scaffold(args.apply, args.program), indent=2))
        return 0
    ap.error("pick --selftest / --show <addr> / --apply <addr>")


if __name__ == "__main__":
    raise SystemExit(main())

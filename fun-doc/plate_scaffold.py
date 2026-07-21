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
    r"^[ \t]*(Algorithm|Parameters|Returns|Special Cases|Magic Numbers|Source|"
    r"Structure Layout[^:\n]*|Notes?|Used by)\s*:", re.I | re.M)


def _unwrap(text: str) -> str:
    """Strip a /* ... */ box and per-line '* ' prefixes some plates carry, so the section parser
    (which anchors on line starts) sees the real content. Indented section headers are handled by
    the section regex's leading [ \\t]*."""
    if not text:
        return text
    t = text.strip()
    if t.startswith("/*"):
        t = t[2:]
    if t.endswith("*/"):
        t = t[:-2]
    lines = t.split("\n")
    if sum(1 for l in lines if l.lstrip().startswith("*")) > len(lines) // 2:
        lines = [re.sub(r"^\s*\*\s?", "", l) for l in lines]
    return "\n".join(lines).strip()
_PROV_RE = re.compile(r"^\[(?:D2MOO-DERIVED NAME|PROVEN)[^\n]*\][^\n]*(?:\n(?!\s*\n)[^\n]*)*", re.M)
# a param line: "  name: type - desc"  OR markdown "| name | type | desc |"
_PARAM_PLAIN = re.compile(r"^\s*([A-Za-z_]\w*)\s*:\s*(.+?)\s+-{1,2}\s+(.*\S)\s*$")
_PARAM_MD = re.compile(r"^\s*\|\s*([A-Za-z_]\w*)\s*\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|")
# a trailing inline storage annotation carried in an old description (harness re-adds it canonically)
_STORAGE_TAIL = re.compile(r"\s*\[[^\]]*(?:register|IMPLICIT|Stack|E[A-DS][XIP])[^\]]*\]\s*$", re.I)


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
def _sec(sections: dict, name: str):
    """Case-insensitive section body lookup ('Algorithm' finds 'algorithm', 'Structure Layout (X)')."""
    for k, v in sections.items():
        if k.lower().startswith(name.lower()):
            return v
    return None


def parse_function_plate(text: str) -> dict:
    """{summary, provenance:[...], sections:{RawName: body}, params:{name: desc},
    param_list:[(name, desc)]} -- raw section names are preserved for verbatim catch-all
    re-emit, and param_list keeps order for the positional re-attach fallback."""
    out = {"summary": "", "provenance": [], "sections": {}, "params": {}, "param_list": []}
    if not text:
        return out
    text = _unwrap(text)
    out["provenance"] = [m.group(0).rstrip() for m in _PROV_RE.finditer(text)]
    hits = [(m.start(), m.end(), m.group(1).strip()) for m in _SECTION_RE.finditer(text)]
    first = hits[0][0] if hits else len(text)
    summ = [ln for ln in text[:first].splitlines()
            if ln.strip() and not ln.strip().startswith("[")]
    out["summary"] = "\n".join(summ).strip()
    for i, (start, hend, name) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(text)
        out["sections"].setdefault(name.strip(), text[hend:end].strip("\n").rstrip())
    for ln in (_sec(out["sections"], "Parameters") or "").splitlines():
        m = _PARAM_PLAIN.match(ln) or _PARAM_MD.match(ln)
        if m:
            out["params"][m.group(1)] = m.group(3).strip()
            out["param_list"].append((m.group(1), m.group(3).strip()))
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
    plist = prior.get("param_list", [])
    psec = prior.get("sections", {})
    emitted = set()   # section names already emitted (lower) -> excluded from the catch-all
    lines = []
    lines.append(prior.get("summary") or _SLOT.format("one-line summary of what the function does"))
    for pv in prior.get("provenance", []):
        lines += ["", pv]
    lines += ["", "Algorithm:"]
    lines.append(_indent(_sec(psec, "Algorithm")) if _sec(psec, "Algorithm")
                 else "  " + _SLOT.format("numbered steps"))
    emitted |= {"algorithm", "parameters", "returns", "source"}
    lines += ["", "Parameters:"]
    consumed = set()
    if params:
        positional = len(plist) == len(params)   # same count -> re-attach prose by ORDINAL
        for i, p in enumerate(params):
            nm, ty = p.get("name", "?"), (p.get("type") or "?").strip()
            reg = _reg(p.get("storage", ""))
            d = pdesc.get(nm)
            if d:
                consumed.add(nm)
            elif positional and plist[i][1]:
                d, _ = plist[i][1], consumed.add(plist[i][0])
            d = _STORAGE_TAIL.sub("", d or _SLOT.format("describe")).rstrip()
            lines.append(f"  {nm}: {ty} - {d}" + (f" [{reg}]" if reg else ""))
    else:
        lines.append("  (none)")
    # preserve orphaned param descriptions (implicit/register params the plate documented but
    # that aren't in the formal signature, e.g. in_EAX) so conversion never loses prose
    for pname, pd in plist:
        if pname not in consumed and pd and not _TODO_RE.search(pd):
            lines.append(f"  {pname}: (implicit / not in signature) - {_STORAGE_TAIL.sub('', pd).rstrip()}")
    lines += ["", "Returns:"]
    rt = (return_type or "void").strip()
    if rt == "void":
        lines.append("  void")
    else:
        rd = _sec(psec, "Returns")
        lines.append(f"  {rt}: " + (_returns_desc(rd) if rd else _SLOT.format("describe")))
    sc = _sec(psec, "Special Cases")
    if sc:
        lines += ["", "Special Cases:", _indent(sc)]
        emitted.add("special cases")
    if magic:
        lines += ["", "Magic Numbers:"]
        mexpl = _magic_expl(_sec(psec, "Magic Numbers") or "")
        for c in magic:
            lines.append(f"  {c}: " + (mexpl.get(c) or _SLOT.format("explain")))
        emitted.add("magic numbers")
    # catch-all: carry EVERY other original section verbatim (Magic Numbers, Note, Structure
    # Layout, ...) so conversion is truly lossless. Skip the empirical/already-emitted ones.
    for k, body in psec.items():
        if any(k.lower().startswith(e) for e in emitted) or not (body or "").strip():
            continue
        lines += ["", f"{k}:", _indent(body)]
        emitted.add(k.lower())
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


# ---- global plates (different shape: identity + who writes/reads + conditional specializations) ----
_GLOB_LINE = re.compile(r"^(?P<name>\S+)\s+@\s+(?P<addr>[0-9a-fA-F]+)\s+\[[^\]]*\]\s+\((?P<type>[^)]*)\)")
_XREF_LINE = re.compile(r"From\s+[0-9a-fA-F]+\s+in\s+(?P<fn>\S+)\s+\[(?P<dir>WRITE|READ)\]")
_TYPE_WIDTH = {"undefined1": 1, "byte": 1, "char": 1, "bool": 1, "undefined2": 2, "word": 2,
               "short": 2, "ushort": 2, "undefined4": 4, "dword": 4, "int": 4, "uint": 4,
               "undefined8": 8, "qword": 8, "double": 8, "float": 4}
_GLOB_SECTION_RE = re.compile(r"^[ \t]*(Set by|Read by|Lifecycle|Bitfield|Callback|Used by|Notes?)\s*:", re.I | re.M)


def _type_size(t: str) -> int:
    t = (t or "").strip()
    if "*" in t:
        return 4
    return _TYPE_WIDTH.get(t.lower(), 0)


def parse_global_plate(text: str) -> dict:
    """{summary, sections:{Name: body}} -- for re-attaching a global's prose (summary/lifecycle/
    bitfield). Set-by/Read-by are regenerated from xrefs, not re-attached."""
    out = {"summary": "", "sections": {}}
    if not text:
        return out
    text = _unwrap(text)
    hits = [(m.start(), m.end(), m.group(1).strip()) for m in _GLOB_SECTION_RE.finditer(text)]
    first = hits[0][0] if hits else len(text)
    out["summary"] = "\n".join(l for l in text[:first].splitlines() if l.strip()).strip()
    for i, (start, hend, name) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(text)
        out["sections"][name.title()] = text[hend:end].strip("\n").rstrip()
    return out


def build_global_plate(name, gtype, address, *, size=None, writers=None, readers=None,
                       prior: dict = None, bitfield: bool = False, callback: bool = False) -> str:
    """Render a global plate: identity + Set-by/Read-by (empirical) + Lifecycle slot, with
    conditional Bitfield/Callback sub-scaffolds. `prior` re-attaches summary + lifecycle prose."""
    prior = prior or {}
    psec = prior.get("sections", {})
    lines = [prior.get("summary") or _SLOT.format("one-line summary of what this global holds")]
    ident = f"Type: {gtype} · Address: {address}"
    if size:
        ident = f"Type: {gtype} · Size: {size} · Address: {address}"
    lines += ["", ident]
    if writers:
        lines.append("Set by: " + ", ".join(writers[:6]) + (" …" if len(writers) > 6 else ""))
    if readers is not None:
        rn = len(readers)
        top = ", ".join(readers[:6])
        lines.append(f"Read by: {rn} site(s)" + (f" ({top}" + (" …)" if rn > 6 else ")") if top else ""))
    lines += ["Lifecycle: " + (_glific(_sec(psec, "Lifecycle")) or _SLOT.format("when set / owned by"))]
    # catch-all: carry any other original section (Notes, ...) verbatim so conversion is lossless
    for k, body in psec.items():
        if k.lower().startswith(("set by", "read by", "lifecycle", "bitfield", "callback")) \
                or not (body or "").strip():
            continue   # 'Used by' is NOT skipped -- carry it verbatim (Read-by regen may not cover it)
        lines += ["", f"{k}:", _indent(body)]
    if bitfield:
        lines += ["", "Bitfield:", _indent(psec.get("Bitfield")) if psec.get("Bitfield")
                  else "  bit0: " + _SLOT.format("meaning")]
    if callback:
        lines += ["", "Callback:", "  " + (_glific(psec.get("Callback")) or _SLOT.format("what calls through + args"))]
    return "\n".join(lines).rstrip() + "\n"


def _glific(block):
    return (block or "").strip() or None


def _fetch_global(addr: str, program: str):
    """(name, type, size, writers[], readers[]) for a data global from list_globals + xref dirs."""
    a = addr if str(addr).startswith("0x") else "0x" + str(addr)
    bare = a[2:].lower().lstrip("0")
    txt = _get("/list_globals", program=program, limit=100000)
    name = gtype = None
    for ln in (txt if isinstance(txt, str) else "").splitlines():
        m = _GLOB_LINE.match(ln.strip())
        if m and m.group("addr").lower().lstrip("0") == bare:
            name, gtype = m.group("name"), m.group("type").strip()
            break
    writers, readers = [], []
    xr = _get("/get_xrefs_to", address=a, program=program, limit=100000)
    for ln in (xr if isinstance(xr, str) else "").splitlines():
        m = _XREF_LINE.search(ln)
        if not m:
            continue
        (writers if m.group("dir") == "WRITE" else readers).append(m.group("fn"))
    # unique, order-preserving
    writers = list(dict.fromkeys(writers))
    readers = list(dict.fromkeys(readers))
    return name, gtype, _type_size(gtype), writers, readers


def _glob_triggers(name: str, gtype: str):
    """(bitfield, callback) conditional-section triggers from empirical signals."""
    n, t = (name or ""), (gtype or "")
    bitfield = bool(re.search(r"Flags|Bits|Mask|State|Mode", n)) and _type_size(t) in (1, 2, 4) and "*" not in t
    callback = n.startswith("g_pfn") or "(" in t or ("*" in t and "code" in t.lower())
    return bitfield, callback


def global_scaffold_for(addr: str, program: str = None) -> str:
    program = program or PROGRAM
    a = addr if str(addr).startswith("0x") else "0x" + str(addr)
    name, gtype, size, writers, readers = _fetch_global(a, program)
    cur = _get("/get_comment", address=a, program=program)
    prior = parse_global_plate(cur.get("plate") if isinstance(cur, dict) else "")
    bf, cb = _glob_triggers(name, gtype)
    return build_global_plate(name, gtype or "undefined", a, size=size or None,
                              writers=writers, readers=readers, prior=prior, bitfield=bf, callback=cb)


def apply_global_scaffold(addr: str, program: str = None) -> dict:
    program = program or PROGRAM
    a = addr if str(addr).startswith("0x") else "0x" + str(addr)
    text = global_scaffold_for(a, program)
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
    # --- globals ---
    g = build_global_plate("g_dwSkillsTxtCount", "uint", "0x6fdf0a78", size=4,
                           writers=["SKILLS_FreeAllSkillTables"],
                           readers=["DATATBLS_Init", "SKILLS_GetSkillRange"])
    assert "Type: uint · Size: 4 · Address: 0x6fdf0a78" in g, g
    assert "Set by: SKILLS_FreeAllSkillTables" in g and "Read by: 2 site(s)" in g, g
    assert "Lifecycle: <TODO:" in g and unfilled_slots(g), g
    # conditional bitfield trigger + re-attach of a global's summary/lifecycle
    gp = parse_global_plate("Locale ID for GetCPInfo.\n\nSet by: SetupCodePage\nLifecycle: set at init\n")
    assert "Locale ID" in gp["summary"] and "set at init" in gp["sections"].get("Lifecycle", "")
    g2 = build_global_plate("g_dwStateFlags", "uint", "0x6fd00000", size=4, writers=["A"], readers=["B"],
                            prior=gp, bitfield=True)
    assert "Locale ID" in g2 and "Lifecycle: set at init" in g2 and "Bitfield:" in g2, g2
    bf, cb = _glob_triggers("g_dwStateFlags", "uint")
    assert bf and not cb
    assert _glob_triggers("g_pfnThreadInit", "code *")[1]      # callback trigger
    print("[ok] plate_scaffold self-test: function + global scaffold, re-attach, slot detection")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--show", metavar="ADDR", help="build a FUNCTION scaffold, print")
    ap.add_argument("--apply", metavar="ADDR", help="write a FUNCTION scaffold")
    ap.add_argument("--show-global", metavar="ADDR", help="build a GLOBAL scaffold, print")
    ap.add_argument("--apply-global", metavar="ADDR", help="write a GLOBAL scaffold")
    ap.add_argument("--program", default=None)
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if args.show:
        print(scaffold_for(args.show, args.program)); return 0
    if args.apply:
        print(json.dumps(apply_scaffold(args.apply, args.program), indent=2)); return 0
    if args.show_global:
        print(global_scaffold_for(args.show_global, args.program)); return 0
    if args.apply_global:
        print(json.dumps(apply_global_scaffold(args.apply_global, args.program), indent=2)); return 0
    ap.error("pick --selftest / --show / --apply / --show-global / --apply-global")


if __name__ == "__main__":
    raise SystemExit(main())

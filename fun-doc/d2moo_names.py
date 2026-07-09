"""d2moo_names.py -- authoritative field/struct names from the D2MOO reimplementation.

The D2MOO source (source/D2Common/include/**) carries community-canonical struct
definitions built from 20+ years of D2 reverse engineering -- every field NAMED at its
offset (`uint8_t nThrowable;  //0x10`). We proved our reimpls bit-exact against these
functions but never imported the NAMES; that is why getters ended up as `GetItemTypeField10`
(transcription) instead of `GetItemTypeThrowable` (understanding).

This module parses those headers into {struct: {offset: field}} + a size index, so a
proven getter -- whose STRUCT is identified by stride==struct-size and whose OFFSET comes
from the proof -- can be named from the REAL field. Offset names become a flagged last
resort only where D2MOO itself has no field.

Usage:
    python d2moo_names.py --selftest
    python d2moo_names.py --lookup D2ItemTypesTxt:0x10      # -> nThrowable
    python d2moo_names.py --size 0xe4                       # structs of that size
"""
from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
INCLUDE_DIRS = [D2MOO_REPO / "source" / "D2Common" / "include",
                D2MOO_REPO / "source" / "D2CommonDefinitions" / "include"]

_SCALAR_W = {
    "char": 1, "int8_t": 1, "uint8_t": 1, "byte": 1, "BYTE": 1, "bool": 1, "BOOLEAN": 1,
    "int16_t": 2, "uint16_t": 2, "short": 2, "WORD": 2, "wchar_t": 2, "unsigned short": 2,
    "int": 4, "int32_t": 4, "uint32_t": 4, "DWORD": 4, "long": 4, "unsigned long": 4,
    "float": 4, "BOOL": 4, "unsigned int": 4, "uint": 4, "HANDLE": 4, "LPVOID": 4,
    "int64_t": 8, "uint64_t": 8, "double": 8, "__int64": 8,
}
_FIELD_RE = re.compile(
    r"^\s*((?:const\s+|struct\s+|union\s+|unsigned\s+|signed\s+)*[\w:]+)\s*(\**)\s*"
    r"(\w+)\s*((?:\[\s*\w+\s*\])*)\s*;\s*//\s*0x([0-9a-fA-F]+)")
_STRUCT_HEAD_RE = re.compile(r"\b(struct|union)\s+([A-Za-z_]\w*)\s*(?:final\s*)?\{")
_UNION_HEAD_RE = re.compile(r"\b(?:union|struct)\s*//\s*0x([0-9a-fA-F]+)")
_MEMBER_RE = re.compile(r"^\s*((?:struct\s+|const\s+)*[\w:]+)\s*(\*+)\s*(\w+)\s*;")
# D2 unit type -> the type-specific data-struct member name fragment (dwType gate value).
_UNITTYPE_MEMBER = {0: "Player", 1: "Monster", 2: "Object", 3: "Missile", 4: "Item", 5: "Tile"}

_CACHE = None


def _width(type_tok: str, ptr: str, array: str, structs: dict) -> int:
    if ptr:
        return 4
    base = 1
    if type_tok in _SCALAR_W:
        base = _SCALAR_W[type_tok]
    elif type_tok in structs:                 # nested struct value
        base = structs[type_tok]["size"] or 4
    else:
        base = 4                              # enum / unknown scalar -> 4
    for m in re.finditer(r"\[\s*(\w+)\s*\]", array or ""):
        n = m.group(1)
        base *= int(n, 0) if re.fullmatch(r"(0x)?[0-9a-fA-F]+", n) else 1
    return base


def _parse_file(text: str, structs: dict):
    """Brace-match each top-level struct/union; collect offset-annotated field lines."""
    i = 0
    while True:
        m = _STRUCT_HEAD_RE.search(text, i)
        if not m:
            break
        name = m.group(2)
        depth, j = 1, m.end()
        start = m.end()
        while j < len(text) and depth:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            j += 1
        body = text[start:j - 1]
        fields = {}
        for line in body.splitlines():
            fm = _FIELD_RE.match(line)
            if not fm:
                continue
            type_tok = fm.group(1).replace("struct ", "").replace("union ", "").strip()
            ptr, fname, array, off = fm.group(2), fm.group(3), fm.group(4), int(fm.group(5), 16)
            fields.setdefault(off, {"name": fname, "type": (type_tok + (ptr or "")).strip(),
                                    "width": _width(type_tok, ptr, array, structs),
                                    "array": bool(array), "is_ptr": bool(ptr)})
        # anonymous offset-annotated UNIONS (`union //0x14 { D2ItemDataStrc* pItemData; ... }`)
        # -- the type-specific data pointer at a unit offset; members keyed for chain-follow.
        for um in _UNION_HEAD_RE.finditer(body):
            uoff = int(um.group(1), 16)
            bo = body.find("{", um.end())
            if bo < 0:
                continue
            d2, k = 1, bo + 1
            while k < len(body) and d2:
                d2 += 1 if body[k] == "{" else -1 if body[k] == "}" else 0
                k += 1
            members = []
            for line in body[bo + 1:k - 1].splitlines():
                mm = _MEMBER_RE.match(line)
                if mm and mm.group(2):        # pointer members only (the data-struct ptrs)
                    members.append({"name": mm.group(3), "type": (mm.group(1) + mm.group(2)).strip()})
            if members:
                fields.setdefault(uoff, {"name": members[0]["name"], "type": members[0]["type"],
                                         "width": 4, "kind": "union", "members": members, "is_ptr": True})
        if fields:
            size = max(off + f["width"] for off, f in fields.items())
            # keep the LARGEST definition if a name repeats across headers
            if name not in structs or size >= structs[name]["size"]:
                structs[name] = {"size": size, "fields": fields}
        i = j
    return structs


def load(include_dirs=None) -> dict:
    """{struct_name: {'size': int, 'fields': {offset: {name,type,width,...}}}}. Cached."""
    global _CACHE
    if _CACHE is not None and include_dirs is None:
        return _CACHE
    structs = {}
    for d in (include_dirs or INCLUDE_DIRS):
        for p in Path(d).rglob("*.h"):
            try:
                _parse_file(p.read_text(encoding="utf-8", errors="replace"), structs)
            except OSError:
                pass
    if include_dirs is None:
        _CACHE = structs
    return structs


def by_size(size: int, structs=None) -> list:
    """Struct names whose total size equals `size` (the stride==size bridge)."""
    s = structs if structs is not None else load()
    return sorted(n for n, d in s.items() if d["size"] == size)


def field_at(struct: str, off: int, structs=None) -> dict | None:
    s = structs if structs is not None else load()
    d = s.get(struct)
    return d["fields"].get(off) if d else None


_HUNGARIAN = re.compile(r"^(dw|n|w|b|sz|p|f|h|a|wsz|q|u|i|l|g)(?=[A-Z0-9])")


def resolve_unit_chain(gate_imm: int, union_off: int, read_off: int,
                       unit_struct: str = "D2UnitStrc", structs=None) -> dict | None:
    """A 2-level UNIT getter: pUnit gated on dwType==gate_imm, deref the type-data pointer
    at `union_off` (the D2UnitStrc union), read a field at `read_off` in that sub-struct.
    dwType selects the union member (4=Item -> pItemData -> D2ItemDataStrc)."""
    s = structs if structs is not None else load()
    u = (s.get(unit_struct) or {}).get("fields", {}).get(union_off)
    if not u or u.get("kind") != "union":
        return None
    frag = _UNITTYPE_MEMBER.get(gate_imm)
    member = next((m for m in u["members"] if frag and frag.lower() in m["name"].lower()), None)
    if not member:
        return {"ok": False, "reason": f"no union member for dwType=={gate_imm} at {unit_struct}+0x{union_off:x}"}
    sub = re.sub(r"\s*\*+$", "", member["type"])
    f = field_at(sub, read_off, s)
    if not f:
        return {"ok": False, "struct": sub, "read_off": read_off,
                "reason": f"D2MOO {sub} has no field at +0x{read_off:x}"}
    return {"ok": True, "struct": sub, "member": member["name"], "field": f["name"],
            "field_type": f["type"], "field_width": f["width"], "read_off": read_off,
            "reason": f"{unit_struct}.{member['name']}(dwType {gate_imm})->{sub}+0x{read_off:x} = {f['name']} ({f['type']})"}


def unit_union_member_names(unit_struct: str = "D2UnitStrc", structs=None) -> list:
    """All member identifier names of the D2UnitStrc type-data union (pPlayerData,
    pMonsterData, pItemData, ...). Used to correct a stale union-member reference in a
    plate body to the one this getter actually uses."""
    s = structs if structs is not None else load()
    names = []
    for fld in (s.get(unit_struct) or {}).get("fields", {}).values():
        if fld.get("kind") == "union":
            names += [m["name"] for m in fld["members"] if m.get("name")]
    return names


def semantic_suffix(field_name: str) -> str:
    """Strip a Hungarian prefix -> a PascalCase name suffix (nThrowable -> Throwable)."""
    base = _HUNGARIAN.sub("", field_name)
    return base[:1].upper() + base[1:] if base else field_name


def derive_getter_name(current_name: str, struct: str, off: int, structs=None) -> dict:
    """Propose a real function name from the field at (struct, off). Returns
    {ok, field, proposed_name, reason} -- ok=False means D2MOO has no field there
    (offset name stays, flagged)."""
    f = field_at(struct, off, structs)
    if not f:
        return {"ok": False, "reason": f"no D2MOO field at {struct}+0x{off:x} -- offset name is honest here"}
    suffix = semantic_suffix(f["name"])
    # replace a trailing Field<hex>/Byte<hex>/Short<hex>/Dword<hex>/0x.. token with the real suffix
    stem = re.sub(r"(Field|Byte|Short|Dword|Word|Flag|Get)?0?x?[0-9A-Fa-f]{1,4}$", "", current_name)
    stem = re.sub(r"(Field|Byte|Short|Dword|Word)$", "", stem).rstrip("_")
    proposed = f"{stem}{suffix}" if stem and not stem.endswith(suffix) else f"{stem}_{suffix}"
    return {"ok": True, "field": f["name"], "field_type": f["type"], "field_width": f["width"],
            "proposed_name": proposed,
            "reason": f"{struct}+0x{off:x} = {f['name']} ({f['type']})"}


_OFFSET_NAME_RE = re.compile(
    r"(Field|Byte|Short|Dword|Word|Flag|Bit|Struct)_?(0x)?[0-9A-Fa-f]{1,4}(Set|Bit\d+)?$"
    r"|0x[0-9A-Fa-f]{1,4}\w*$")
# single-level getters: subsystem/name -> the PARAM struct type (the getter reads a field
# directly off its pointer param). Ordered; first match wins.
_PARAM_STRUCT = [
    (re.compile(r"GetSkillNode|GetSkill(?!s)"), "D2SkillStrc"),
    (re.compile(r"StatList"), "D2StatListStrc"),
    (re.compile(r"GetInventory|Inventory"), "D2InventoryStrc"),
    (re.compile(r"GetRoom|Room"), "D2RoomStrc"),
]
# subsystem/name-pattern -> canonical D2MOO record struct (disambiguates same-offset fields).
_NAME_STRUCT = [
    (re.compile(r"GetItemType|ItemTypesTxt|ItemTypeProperty"), "D2ItemTypesTxt"),
    (re.compile(r"GetItemRecord|ItemsTxt|GetItemData.*Record|GetUltraOrBase|GetItemRecordCode"), "D2ItemsTxt"),
    (re.compile(r"GetMissileRecord|MissilesTxt|GetMissileData"), "D2MissilesTxt"),
    (re.compile(r"GetMonStats|MonStatsTxt|GetMonsterData"), "D2MonStatsTxt"),
    (re.compile(r"GetSkill.*Record|SkillsTxt|GetSkillsTxt"), "D2SkillsTxt"),
    (re.compile(r"GetLevelRecord|LevelsTxt|GetLevelData"), "D2LevelsTxt"),
    (re.compile(r"GetOverlayRecord|OverlayTxt"), "D2OverlayTxt"),
]


def is_offset_name(name: str) -> bool:
    """True if the function name ends in an offset-derived token (Field10/Byte44/Short0x10)."""
    return bool(_OFFSET_NAME_RE.search(name))


def _extract_from_candidate(cpp: str) -> dict:
    """stride, records-ptr offset, final-read offset+width, callee from a proven candidate."""
    out = {"stride": None, "read_off": None, "read_w": None, "callee": None, "records_off": None,
           "gate_off": None, "gate_imm": None, "union_off": None}
    m = re.search(r"idx\s*\*\s*0x([0-9a-fA-F]+)", cpp) or re.search(r"\*\s*0x([0-9a-fA-F]+)\s*;", cpp)
    if m:
        out["stride"] = int(m.group(1), 16)
    # the records pointer of a global-table getter: `*(void**)(base + 0xRECOFF)` -- this
    # offset into the DataTables header NAMES the table authoritatively (stride can collide).
    rm = re.search(r"\*\s*\(\s*void\s*\*\s*\*\s*\)\s*\(\s*base\s*\+\s*0x([0-9a-fA-F]+)\s*\)", cpp)
    if rm:
        out["records_off"] = int(rm.group(1), 16)
    for c in re.finditer(r'D2MOO_Resolve\("([^"]+)"\)', cpp):
        if not c.group(1).startswith(("g_", "_g_")):
            out["callee"] = c.group(1)
    # BASE: mechanical uses `r + 0x`; model-drafted uses `(char*)pUnit + 0x` / `pItemData + 0x`.
    _B = r"(?:\(\s*char\s*\*\s*\)\s*)?\w+"
    # 2-level UNIT getter: dwType gate + the type-data pointer deref (union offset). The gate
    # reads a uint at the param+off and compares != imm (dwType).
    # dwType gate: `*(uint*)(pUnit + 0x0) != 4` OR `*(uint*)pUnit != 4` (offset omitted = 0);
    # imm may be decimal or hex.
    gm = re.search(r"\*\s*\(\s*(?:unsigned\s+int|int|uint)\s*\*\s*\)\s*\(?\s*" + _B
                   + r"(?:\s*\+\s*0x([0-9a-fA-F]+))?\s*\)?\s*!=\s*(0x[0-9a-fA-F]+|\d+)", cpp)
    if gm:
        out["gate_off"] = int(gm.group(1), 16) if gm.group(1) else 0
        out["gate_imm"] = int(gm.group(2), 0)
    # the type-data pointer deref: `VAR = *(void**|char**)((char*)pUnit + 0x14)` (NOT the
    # DataTables `base` deref, which is the records path).
    pl = re.search(r"=\s*\*\s*\(\s*(?:char|void)\s*\*\s*\*\s*\)\s*\(\s*" + _B + r"\s*\+\s*0x([0-9a-fA-F]+)\s*\)", cpp)
    if pl and out["records_off"] is None and out["stride"] is None:
        out["union_off"] = int(pl.group(1), 16)
    out["masked"] = bool(re.search(r"return[^;]*(&|>>|<<)\s*0x", cpp))
    out["single_level"] = (out["union_off"] is None and out["stride"] is None
                           and out["records_off"] is None and out["callee"] is None)
    # the DEEPEST scalar field read = the returned field (the gate's uint read at the param
    # is earlier in source order, so `reads[-1]` is the real field).
    reads = []
    for r in re.finditer(r"\*\s*\(\s*(unsigned\s+char|signed\s+char|char|unsigned\s+short|short|"
                         r"unsigned\s+int|int)\s*\*\s*\)\s*\(\s*" + _B + r"\s*\+\s*0x([0-9a-fA-F]+)\s*\)", cpp):
        w = {"char": 1, "short": 2, "int": 4}[r.group(1).split()[-1]]
        reads.append((int(r.group(2), 16), w))
    if reads:
        out["read_off"], out["read_w"] = reads[-1]
    return out


def _domain(struct: str) -> str:
    """D2ItemTypesTxt -> ItemType, D2OverlayTxt -> Overlay, D2ItemsTxt -> Item (short,
    for building a function name)."""
    core = re.sub(r"^D2", "", struct)
    core = re.sub(r"(Txt|Strc|Rec|Record)$", "", core)
    if core.endswith("s") and not core.endswith("ss"):
        core = core[:-1]                      # ItemTypes -> ItemType, Items -> Item
    return core


def canonicalize(name: str, cpp: str, structs=None) -> dict:
    """Resolve a proven getter's REAL name from D2MOO. Struct identity is taken from the
    DataTables HEADER field (records-ptr offset -> the named table pointer) when available
    -- AUTHORITATIVE, and it also catches a WRONG subsystem guess (a 'Missile' getter that
    actually reads the Overlay table). Falls back to stride==size, then name pattern.
    Returns {ok, struct, field, proposed_name, corrected_subsystem, reason}."""
    s = structs if structs is not None else load()
    ex = _extract_from_candidate(cpp)
    off = ex["read_off"]
    if off is None:
        return {"ok": False, "reason": "no field read found in candidate"}
    # 2-LEVEL UNIT getter: resolve through the D2UnitStrc union (dwType -> data struct).
    if ex["union_off"] is not None and ex["gate_imm"] is not None:
        uc = resolve_unit_chain(ex["gate_imm"], ex["union_off"], off, structs=s)
        if uc and uc.get("ok"):
            prefix = name.split("_")[0] + "_" if "_" in name else ""
            domain = _domain(uc["struct"])
            proposed = f"{prefix}Get{domain}{semantic_suffix(uc['field'])}"
            old_core = re.sub(r"^\w+_Get", "", name)
            return {"ok": True, "struct": uc["struct"], "field": uc["field"],
                    "field_type": uc["field_type"], "field_width": uc.get("field_width"),
                    "read_off": off, "proposed_name": proposed, "member": uc.get("member"),
                    "corrected_subsystem": domain.lower() not in old_core.lower(),
                    "how": "unit-union chain", "reason": uc["reason"]}
        if uc and not uc.get("ok"):
            return {"ok": False, "read_off": off, "reason": uc["reason"]}

    # SINGLE-LEVEL getter on a NAMED PARAM struct (STAT/SKILLS/...): read a field directly
    # off the param pointer. SAFETY: if the getter MASKS the value (a flag) but the D2MOO
    # field there is a POINTER, the layouts disagree (version drift) -> FLAG, never guess.
    if ex.get("single_level"):
        for rx, st in _PARAM_STRUCT:
            if rx.search(name) and st in s:
                f = field_at(st, off, s)
                if not f:
                    return {"ok": False, "struct": st, "read_off": off,
                            "reason": f"D2MOO {st} has no field at +0x{off:x}"}
                if ex.get("masked") and f.get("is_ptr"):
                    return {"ok": False, "struct": st, "read_off": off,
                            "reason": f"SUSPECT: {st}+0x{off:x} = {f['name']} is a POINTER but the "
                            f"getter masks it as a flag -- likely a 1.13c-vs-D2MOO layout drift; VERIFY"}
                prefix = name.split("_")[0] + "_" if "_" in name else ""
                domain = _domain(st)
                proposed = f"{prefix}Get{domain}{semantic_suffix(f['name'])}"
                old_core = re.sub(r"^\w+_Get", "", name)
                return {"ok": True, "struct": st, "field": f["name"], "field_type": f["type"],
                        "field_width": f["width"], "read_off": off, "proposed_name": proposed,
                        "corrected_subsystem": domain.lower() not in old_core.lower(),
                        "how": "param struct", "reason": f"{st}+0x{off:x} = {f['name']} ({f['type']})"}

    struct, how = None, None
    dt = s.get("D2DataTablesStrc")
    if ex["records_off"] is not None and dt:
        hdr = dt["fields"].get(ex["records_off"])
        if hdr and hdr.get("is_ptr"):
            struct = re.sub(r"\s*\*$", "", hdr["type"])   # D2OverlayTxt* -> D2OverlayTxt
            how = f"DataTables header +0x{ex['records_off']:x} = {hdr['name']}"
    if not struct and ex["stride"]:
        matches = by_size(ex["stride"], s)
        txt = [m for m in matches if m.endswith("Txt")]
        struct = (txt or matches or [None])[0]
        how = f"stride 0x{ex['stride']:x} == sizeof({struct})" if struct else None
    if not struct:
        for rx, st in _NAME_STRUCT:
            if rx.search(name) and st in s:
                struct, how = st, "name pattern"
                break
    if not struct:
        return {"ok": False, "reason": f"struct not identified (stride={ex['stride']}, "
                f"records_off={ex['records_off']}, callee={ex['callee']})", "read_off": off}
    f = field_at(struct, off, s)
    if not f:
        return {"ok": False, "struct": struct, "read_off": off,
                "reason": f"D2MOO {struct} has no field at +0x{off:x} -- offset name is honest here"}
    prefix = name.split("_")[0] + "_" if "_" in name else ""
    domain = _domain(struct)
    suffix = semantic_suffix(f["name"])
    proposed = f"{prefix}Get{domain}{suffix}"
    # did the OLD name claim a different domain than the true table? (Missile vs Overlay)
    old_core = re.sub(r"^\w+_Get", "", name)
    corrected = domain.lower() not in old_core.lower() and not is_offset_name(domain)
    return {"ok": True, "struct": struct, "field": f["name"], "field_type": f["type"],
            "field_width": f["width"], "read_off": off, "proposed_name": proposed,
            "corrected_subsystem": corrected, "how": how,
            "reason": f"{struct}+0x{off:x} = {f['name']} ({f['type']}) [{how}]"}


def _selftest() -> int:
    structs = load()
    assert structs, "no structs parsed"
    it = structs.get("D2ItemTypesTxt")
    assert it, "D2ItemTypesTxt not found"
    # the money shot: offset 0x10 is nThrowable, struct size is the 0xe4 stride.
    assert it["size"] == 0xE4, hex(it["size"])
    assert it["fields"][0x10]["name"] == "nThrowable", it["fields"][0x10]
    assert it["fields"][0x0C]["name"] == "wShoots" and it["fields"][0x0C]["width"] == 2, it["fields"][0x0C]
    assert "D2ItemTypesTxt" in by_size(0xE4), by_size(0xE4)
    assert semantic_suffix("nThrowable") == "Throwable"
    assert semantic_suffix("wShoots") == "Shoots"
    assert semantic_suffix("dwFlags") == "Flags"
    d = derive_getter_name("DATATBLS_GetItemTypeField10", "D2ItemTypesTxt", 0x10)
    assert d["ok"] and d["field"] == "nThrowable" and "Throwable" in d["proposed_name"], d
    d2 = derive_getter_name("X", "D2ItemTypesTxt", 0x999)
    assert not d2["ok"], d2
    # is_offset_name + canonicalize from a candidate cpp
    assert is_offset_name("DATATBLS_GetItemTypeField10")
    assert is_offset_name("ITEMS_GetItemRecordField104")
    assert not is_offset_name("DATATBLS_GetItemTypeThrowable")
    gt_cpp = ('extern "C" unsigned char __stdcall DATATBLS_GetItemTypeField10(int idx){\n'
              '  char* records = (char*)*(void**)(base + 0xbf8);\n'
              '  char* rec = records + (int)idx * 0xe4;\n'
              '  return (unsigned int)*(unsigned char*)(rec + 0x10); }')
    c = canonicalize("DATATBLS_GetItemTypeField10", gt_cpp, structs)
    assert c["ok"] and c["struct"] == "D2ItemTypesTxt" and c["field"] == "nThrowable", c
    dl_cpp = ('extern "C" unsigned char __stdcall ITEMS_GetItemRecordField104(void* p){\n'
              '  _callee_t _f = (_callee_t)D2MOO_Resolve("GetItemDataRecord");\n'
              '  return *(unsigned char*)(_rec + 0x104); }')
    c2 = canonicalize("ITEMS_GetItemRecordField104", dl_cpp, structs)
    assert c2["ok"] and c2["struct"] == "D2ItemsTxt" and c2["field"] == "nRangeAdder", c2
    # UNION parse + 2-level unit-getter chain: D2UnitStrc union@0x14, dwType==4 -> pItemData
    u = structs["D2UnitStrc"]["fields"].get(0x14)
    assert u and u.get("kind") == "union" and any("Item" in m["name"] for m in u["members"]), u
    uc = resolve_unit_chain(4, 0x14, 0x32, structs=structs)
    assert uc["ok"] and uc["struct"] == "D2ItemDataStrc" and uc["field"] == "wRarePrefix", uc
    gated_cpp = ('extern "C" unsigned short __stdcall ITEMS_GetItemDataField32(void* p){\n'
                 '  char* r = (char*)p;\n'
                 '  if (*(unsigned int*)(r + 0x0) != 0x4u) return 0;\n'
                 '  r = *(char**)(r + 0x14);\n'
                 '  return *(unsigned short*)(r + 0x32); }')
    c3 = canonicalize("ITEMS_GetItemDataField32", gated_cpp, structs)
    assert c3["ok"] and c3["struct"] == "D2ItemDataStrc" and c3["field"] == "wRarePrefix", c3
    assert "RarePrefix" in c3["proposed_name"], c3
    # single-level param-struct getter: SKILLS reads D2SkillStrc.nQuantity (clean)
    sk_cpp = ('extern "C" unsigned int __stdcall SKILLS_GetSkillNodeField0x30(void* p){\n'
              '  char* r = (char*)p; return *(unsigned int*)(r + 0x30); }')
    c4 = canonicalize("SKILLS_GetSkillNodeField0x30", sk_cpp, structs)
    assert c4["ok"] and c4["struct"] == "D2SkillStrc" and c4["field"] == "nQuantity", c4
    # SAFETY: STAT flag getter masks a POINTER field -> layout drift -> must FLAG, not rename
    fl_cpp = ('extern "C" unsigned int __stdcall STAT_GetStatListFlag4(void* p){\n'
              '  char* r = (char*)p; return (*(unsigned int*)(r + 0x34) & 0x4u); }')
    c5 = canonicalize("STAT_GetStatListFlag4", fl_cpp, structs)
    assert not c5["ok"] and "SUSPECT" in c5["reason"], c5
    print(f"[ok] d2moo_names self-test: parsed {len(structs)} structs; "
          f"D2ItemTypesTxt+0x10 = nThrowable; GetItemTypeField10 -> {d['proposed_name']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lookup", help="Struct:0xOFF -> field")
    ap.add_argument("--size", help="0xNN -> struct names of that size")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if args.lookup:
        struct, off = args.lookup.split(":")
        f = field_at(struct.strip(), int(off, 16))
        print(f"{args.lookup} -> {f}")
        return 0
    if args.size:
        print(f"size {args.size}: {by_size(int(args.size, 16))}")
        return 0
    ap.error("pick --lookup / --size / --selftest")


if __name__ == "__main__":
    raise SystemExit(main())

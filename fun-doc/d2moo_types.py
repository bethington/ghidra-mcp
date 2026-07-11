"""d2moo_types.py -- the authoritative TYPE vocabulary of the D2MOO reimplementation.

The type-side sibling of d2moo_names.py. D2MOO's source (source/*/include/**) defines the
canonical set of types the project develops against -- stdint scalars, ~750 game/data structs
(D2UnitStrc, D2ItemsTxt, ...), ~200 enums, unions, and typedef aliases. Ghidra, by contrast,
carries its own analysis vocabulary (undefined4, dword, uint, code, ...) that we would NEVER
use in D2MOO. This module lets us:

  * enumerate the canonical type set (the allowed list), regenerated from source;
  * validate any Ghidra type string on a global / variable / parameter ->
        VALID       (a real D2MOO type)
        UNREFINED   (a Ghidra width type -> suggest the D2MOO stdint spelling)
        INVALID     (a placeholder like undefined4 -> the field is genuinely un-typed)
        UNKNOWN     (not in our vocabulary -- likely CRT/library, out of scope);
  * compute a version marker (count + hash) so a loader can stamp a program option and a
    lightweight check can tell "loaded & current" from "missing/stale" in one read.

Usage:
    python d2moo_types.py --selftest
    python d2moo_types.py --summary                 # counts + version marker
    python d2moo_types.py --validate undefined4     # -> INVALID
    python d2moo_types.py --validate dword          # -> UNREFINED (suggest uint32_t)
    python d2moo_types.py --validate D2UnitStrc*     # -> VALID
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
SOURCE_DIR = D2MOO_REPO / "source"

# The fixed scalar vocabulary (D2BasicTypes.h: stdint + a few C base types). BOOL and the GUID
# aliases are discovered as `using` aliases and merged in via load().
SCALARS = frozenset({
    "void", "bool", "char", "int", "short", "long", "float", "double",
    "signed char", "unsigned char", "unsigned short", "unsigned int", "unsigned long",
    "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t",
    "size_t", "wchar_t", "intptr_t", "uintptr_t",
})

# Ghidra's analysis PLACEHOLDER types -- present in every program, but they mean "not typed".
# A global/field/param carrying one of these is, by D2MOO's standard, un-typed.
PLACEHOLDERS = frozenset({
    "undefined", "undefined1", "undefined2", "undefined3", "undefined4", "undefined5",
    "undefined6", "undefined7", "undefined8", "code", "pointer", "pointer32", "pointer64",
})

# Ghidra built-in WIDTH types (and Windows spellings) -> the canonical D2MOO stdint spelling.
# Semantically fine, but not our vocabulary; the validator suggests the rewrite.
NORMALIZE = {
    "byte": "uint8_t", "sbyte": "int8_t", "uchar": "uint8_t",
    "word": "uint16_t", "sword": "int16_t", "ushort": "uint16_t", "wchar": "uint16_t",
    "dword": "uint32_t", "sdword": "int32_t", "uint": "uint32_t", "ulong": "uint32_t",
    "qword": "uint64_t", "ulonglong": "uint64_t", "sqword": "int64_t",
    "byte": "uint8_t", "BYTE": "uint8_t", "WORD": "uint16_t", "DWORD": "uint32_t",
    "UINT": "uint32_t", "USHORT": "uint16_t", "UCHAR": "uint8_t", "ULONG": "uint32_t",
    "CHAR": "char", "LONG": "int32_t", "SHORT": "int16_t", "INT": "int32_t",
    "u_char": "uint8_t", "u_short": "uint16_t", "u_int": "uint32_t", "u_long": "uint32_t",
}

# ---- header enumeration ----------------------------------------------------------------------
_CMT_BLOCK = re.compile(r"/\*.*?\*/", re.S)
_CMT_LINE = re.compile(r"//[^\n]*")
_STRUCT = re.compile(r"\b(?:struct|class)\s+([A-Za-z_]\w*)\s*(?:final\s*)?(?::[^{;]+)?\{")
_UNION = re.compile(r"\bunion\s+([A-Za-z_]\w*)\s*\{")
_ENUM = re.compile(r"\benum\s+(?:class\s+|struct\s+)?([A-Za-z_]\w*)\s*(?::[^{]+)?\{")
_USING = re.compile(r"\busing\s+([A-Za-z_]\w*)\s*=\s*([^;]+);")
_TYPEDEF = re.compile(r"\btypedef\s+(.+?)\b([A-Za-z_]\w*)\s*;")

_CACHE = None


def _strip_comments(text: str) -> str:
    return _CMT_LINE.sub("", _CMT_BLOCK.sub("", text))


def load(source_dir: Path = None) -> dict:
    """Parse every module header into the canonical vocabulary. Returns
    {structs:set, unions:set, enums:set, aliases:{name:target}, scalars:set}. Cached."""
    global _CACHE
    if _CACHE is not None and source_dir is None:
        return _CACHE
    structs, unions, enums, aliases = set(), set(), set(), {}
    root = source_dir or SOURCE_DIR
    for p in Path(root).rglob("*.h"):
        try:
            txt = _strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        structs.update(_STRUCT.findall(txt))
        unions.update(_UNION.findall(txt))
        enums.update(_ENUM.findall(txt))
        for name, target in _USING.findall(txt):
            aliases[name] = target.strip()
        for target, name in _TYPEDEF.findall(txt):
            aliases[name] = target.strip()
    # a class/struct captured as a union head shouldn't double count; unions win their own set
    structs -= unions
    out = {"structs": structs, "unions": unions, "enums": enums, "aliases": aliases,
           "scalars": set(SCALARS) | set(aliases)}
    if source_dir is None:
        _CACHE = out
    return out


def canonical_names(vocab: dict = None) -> set:
    """The full set of valid D2MOO type NAMES (scalars + aliases + structs + unions + enums)."""
    v = vocab or load()
    return set(SCALARS) | set(v["aliases"]) | v["structs"] | v["unions"] | v["enums"]


# ---- validation ------------------------------------------------------------------------------
_DECORATOR = re.compile(r"\b(const|volatile|struct|union|enum|class)\b")
_PTR_ARR = re.compile(r"[\*\[\]\d\s]+$")


def _base(type_str: str) -> str:
    """Strip pointer/array/const decoration -> the base type name (best effort)."""
    s = _DECORATOR.sub(" ", str(type_str or "")).strip()
    s = re.sub(r"\s*\*[\s\*]*$", "", s)            # trailing pointer stars
    s = re.sub(r"\s*(\[\s*\d*\s*\])+\s*$", "", s)  # trailing array dims
    s = re.sub(r"\s*\*[\s\*]*", "", s)             # any remaining stars
    return s.strip()


def validate_type(type_str: str, vocab: dict = None) -> dict:
    """Classify a Ghidra type string against D2MOO's vocabulary.
    Returns {verdict, base, suggestion, reason} where verdict in
    VALID | UNREFINED | INVALID | UNKNOWN."""
    v = vocab or load()
    base = _base(type_str)
    if not base:
        return {"verdict": "INVALID", "base": base, "suggestion": None,
                "reason": "empty / unparseable type"}
    if base in PLACEHOLDERS:
        return {"verdict": "INVALID", "base": base, "suggestion": None,
                "reason": f"{base} is a Ghidra placeholder -- the field is not actually typed"}
    if base in NORMALIZE:
        sug = NORMALIZE[base]
        return {"verdict": "UNREFINED", "base": base, "suggestion": sug,
                "reason": f"{base} is a Ghidra width type -- use D2MOO's {sug}"}
    if base in SCALARS or base in v["aliases"] or base in v["structs"] \
            or base in v["unions"] or base in v["enums"]:
        return {"verdict": "VALID", "base": base, "suggestion": None,
                "reason": f"{base} is a canonical D2MOO type"}
    return {"verdict": "UNKNOWN", "base": base, "suggestion": None,
            "reason": f"{base} is not in D2MOO's vocabulary (likely CRT/library or a missing type)"}


# ---- version marker --------------------------------------------------------------------------
MARKER_GROUP, MARKER_OPTION = "Program Information", "D2MOO.types.version"


def version_marker(vocab: dict = None) -> str:
    """A stable marker for 'these types are loaded & current': 'v1:<count>:<sha1_8>'. Changes
    whenever the canonical name set changes, so a stale load is detectable in one option read."""
    names = sorted(canonical_names(vocab))
    h = hashlib.sha1("\n".join(names).encode("utf-8")).hexdigest()[:8]
    return f"v1:{len(names)}:{h}"


def summary(vocab: dict = None) -> dict:
    v = vocab or load()
    return {"structs": len(v["structs"]), "unions": len(v["unions"]), "enums": len(v["enums"]),
            "aliases": len(v["aliases"]), "scalars": len(SCALARS),
            "total_names": len(canonical_names(v)), "marker": version_marker(v)}


def _selftest() -> int:
    v = load()
    s = summary(v)
    assert s["structs"] > 500, s
    assert s["enums"] > 100, s
    # marquee types present
    for t in ("D2UnitStrc", "D2GameStrc", "D2ItemsTxt", "D2CoordStrc"):
        assert t in v["structs"], f"{t} missing from parsed structs"
    # aliases: BOOL + D2UnitGUID discovered
    assert "BOOL" in v["aliases"] or "BOOL" in canonical_names(v), "BOOL alias missing"
    assert "D2UnitGUID" in v["aliases"], "D2UnitGUID alias missing"
    # validation verdicts
    assert validate_type("undefined4")["verdict"] == "INVALID"
    assert validate_type("code")["verdict"] == "INVALID"
    d = validate_type("dword"); assert d["verdict"] == "UNREFINED" and d["suggestion"] == "uint32_t", d
    assert validate_type("byte")["suggestion"] == "uint8_t"
    assert validate_type("uint32_t")["verdict"] == "VALID"
    assert validate_type("D2UnitStrc *")["verdict"] == "VALID"
    assert validate_type("D2ItemsTxt*")["verdict"] == "VALID"
    assert validate_type("__lc_time_data")["verdict"] == "UNKNOWN"
    # marker stable across calls
    assert version_marker(v) == version_marker(v)
    print(f"[ok] d2moo_types self-test: {s['total_names']} canonical names "
          f"({s['structs']} structs, {s['enums']} enums, {s['unions']} unions, "
          f"{s['aliases']} aliases); marker {s['marker']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--validate", help="classify a Ghidra type string")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if args.summary:
        for k, val in summary().items():
            print(f"  {k:12} {val}")
        return 0
    if args.validate:
        r = validate_type(args.validate)
        print(f"{args.validate!r} -> {r['verdict']}"
              + (f" (suggest {r['suggestion']})" if r["suggestion"] else "") + f"  -- {r['reason']}")
        return 0
    ap.error("pick --selftest / --summary / --validate")


if __name__ == "__main__":
    raise SystemExit(main())

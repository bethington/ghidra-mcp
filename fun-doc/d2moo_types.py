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
    "size_t", "wchar_t", "intptr_t", "uintptr_t", "BOOL",
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
_PP_LINE = re.compile(r"^[ \t]*#.*$", re.M)   # preprocessor directives (after joining continuations)
_STRUCT = re.compile(r"\b(?:struct|class)\s+([A-Za-z_]\w*)\s*(?:final\s*)?(?::[^{;]+)?\{")
_UNION = re.compile(r"\bunion\s+([A-Za-z_]\w*)\s*\{")
_ENUM = re.compile(r"\benum\s+(?:class\s+|struct\s+)?([A-Za-z_]\w*)\s*(?::[^{]+)?\{")
_USING = re.compile(r"\busing\s+([A-Za-z_]\w*)\s*=\s*([^;]+);")
_TYPEDEF = re.compile(r"\btypedef\s+(.+?)\b([A-Za-z_]\w*)\s*;")

_CACHE = None


def _strip_comments(text: str) -> str:
    text = _CMT_LINE.sub("", _CMT_BLOCK.sub("", text))
    text = text.replace("\\\n", " ")                 # join backslash line-continuations
    text = _PP_LINE.sub("", text)                    # drop #define/#include/#if... entirely
    # drop token-paste macro artifacts (DLL##_##NAME, name##__) that a #define body left behind
    text = "\n".join(ln for ln in text.splitlines() if "##" not in ln)
    return text


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
    for name, _stmt in _raw_typedefs(root):           # C-style typedefs (incl. fn-ptr form)
        aliases.setdefault(name, "")
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


# ---- flat header emission (for Ghidra's C parser) --------------------------------------------
# We emit each type's REAL brace-matched body (sanitized), never a reconstructed layout -- the
# D2MOO source IS the authoritative layout. Ghidra's CParser is C, not C++, so we strip the
# C++-isms and provide a scalar/Windows preamble + forward declarations so order/pointers resolve.
_HEAD = re.compile(r"\b(struct|union|enum)\s+(?:class\s+|struct\s+)?([A-Za-z_]\w*)"
                   r"\s*(?:final\s*)?(?::[^{]+)?\{")
_PREAMBLE = """/* D2MOO canonical types -- generated by d2moo_types.py; do not edit. */
#pragma pack(push, 1)
typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef short              int16_t;
typedef unsigned short     uint16_t;
typedef int                int32_t;
typedef unsigned int       uint32_t;
typedef long long          int64_t;
typedef unsigned long long uint64_t;
typedef unsigned int       size_t;
typedef int32_t            BOOL;
typedef unsigned short     wchar_t;
/* Windows/external shims referenced by some D2 headers (widths, not semantics) */
typedef unsigned long  DWORD;
typedef unsigned short WORD;
typedef unsigned char  BYTE;
typedef unsigned int   UINT;
typedef int            INT;
typedef unsigned long  ULONG;
typedef long           LONG;
typedef unsigned short USHORT;
typedef short          SHORT;
typedef unsigned char  UCHAR;
typedef uint32_t       WPARAM;
typedef int32_t        LPARAM;
typedef int32_t        LRESULT;
typedef int32_t        HRESULT;
typedef uint32_t       COLORREF;
typedef uint16_t       ATOM;
typedef unsigned long  DWORD_PTR;
typedef long           LONG_PTR;
typedef unsigned long  ULONG_PTR;
typedef void *  HANDLE;
typedef void *  LPVOID;
typedef void *  HWND;
typedef void *  HDC;
typedef void *  HINSTANCE;
typedef void *  HMODULE;
typedef void *  HKEY;
typedef void *  HMENU;
typedef void *  HICON;
typedef void *  HCURSOR;
typedef void *  HBRUSH;
typedef void *  HFONT;
typedef void *  HBITMAP;
typedef void *  HPALETTE;
typedef void *  HPEN;
typedef void *  HRGN;
typedef void *  HGDIOBJ;
typedef void *  HGLOBAL;
typedef void *  HLOCAL;
typedef void *  FARPROC;
typedef char *  LPSTR;
typedef const char *  LPCSTR;
typedef char *  LPTSTR;
typedef const char *  LPCTSTR;
typedef uint8_t *  LPBYTE;
typedef uint32_t * LPDWORD;
typedef void *  SOCKET;
typedef struct { DWORD dwLowDateTime; DWORD dwHighDateTime; } FILETIME;
typedef struct { WORD wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds; } SYSTEMTIME;
typedef struct { DWORD Data1; WORD Data2; WORD Data3; BYTE Data4[8]; } GUID;
typedef struct { LONG x; LONG y; } POINT;
typedef struct { LONG left, top, right, bottom; } RECT;
typedef struct { LONG cx, cy; } SIZE;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
/* external opaque handles (Storm / D2 archive) referenced but not defined in D2MOO headers */
typedef void *  HSFILE;
typedef void *  HSARCHIVE;
typedef void *  HD2ARCHIVE__;
typedef wchar_t Unicode;
typedef struct { void *DebugInfo; LONG LockCount; LONG RecursionCount; void *OwningThread; void *LockSemaphore; ULONG_PTR SpinCount; } CRITICAL_SECTION;
typedef CRITICAL_SECTION *  LPCRITICAL_SECTION;
typedef struct { ULONG_PTR Internal; ULONG_PTR InternalHigh; DWORD Offset; DWORD OffsetHigh; HANDLE hEvent; } OVERLAPPED;
typedef struct { BYTE peRed; BYTE peGreen; BYTE peBlue; BYTE peFlags; } PALETTEENTRY;
typedef struct { UINT length; UINT flags; UINT showCmd; POINT ptMinPosition; POINT ptMaxPosition; RECT rcNormalPosition; } WINDOWPLACEMENT;
typedef struct { void *opaque; } JPEG_CORE_PROPERTIES;
"""

# C++ constructs a C parser can't ingest -- strip whole lines / spans that match.
_STRIP_LINE = re.compile(
    r"^\s*(?:public|private|protected)\s*:.*$"                 # access specifiers
    r"|^\s*static_assert\b.*$"                                 # static_assert(...)
    r"|^\s*#\s*(?:pragma|include|if|ifdef|ifndef|endif|else|elif|define|undef|error)\b.*$"
    r"|^\s*(?:using|namespace|template|friend)\b.*$",          # C++ keywords
    re.M)
_STRIP_METHOD = re.compile(
    r"^\s*(?:virtual\s+|static\s+|inline\s+|explicit\s+)*"
    r"[~\w:<>,&*\s]+\([^;{]*\)\s*(?:const)?\s*(?::[^{;]+)?\s*"
    r"(?:\{[^{}]*\}|=\s*(?:default|delete)\s*;|;)\s*$", re.M)
_STRIP_CONSTEXPR = re.compile(r"^\s*(?:static\s+)?constexpr\b.*$", re.M)
_DEFAULT_INIT = re.compile(r"(=\s*[^,;{}]+)(?=\s*[;,])")       # `int x = 0;` -> `int x;`


def _definitions(source_dir: Path = None):
    """Brace-match every top-level struct/union/enum -> [(kind, name, body_incl_braces, deps)].
    deps = names referenced BY VALUE (no `*`) so we can order definitions."""
    defs, seen = [], set()
    for p in Path(source_dir or SOURCE_DIR).rglob("*.h"):
        try:
            txt = _strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        i = 0
        while True:
            m = _HEAD.search(txt, i)
            if not m:
                break
            kind, name = m.group(1), m.group(2)
            depth, j = 1, m.end()
            while j < len(txt) and depth:
                depth += 1 if txt[j] == "{" else -1 if txt[j] == "}" else 0
                j += 1
            body = txt[m.start():j]                       # `struct X {...}` (no trailing ;)
            i = j
            if name in seen:                              # keep first definition of a name
                continue
            seen.add(name)
            inner = txt[m.end():j - 1]
            deps = {d for d in re.findall(r"\b([A-Za-z_]\w*)\b(?!\s*\*)", inner)
                    if d != name}
            defs.append({"kind": kind, "name": name, "body": body, "deps": deps})
    return defs


def _strip_method_bodies(body: str) -> str:
    """Remove member-function definitions with (possibly nested) brace bodies -- identified by
    a ')' followed (mod const/noexcept) by a balanced '{...}'. Walks back to the start of the
    declaration. Anonymous struct/union opens ('union {') aren't preceded by ')', so they stay."""
    while True:
        m = re.search(r"\)\s*(?:const\s+|noexcept\s+)*\{", body)
        if not m:
            return body
        bo = body.index("{", m.start())
        depth, j = 1, bo + 1
        while j < len(body) and depth:
            depth += 1 if body[j] == "{" else -1 if body[j] == "}" else 0
            j += 1
        start = max(body.rfind(";", 0, m.start()), body.rfind("{", 0, m.start()),
                    body.rfind("}", 0, m.start())) + 1
        body = body[:start] + body[j:]


def _sanitize(body: str) -> str:
    body = _strip_method_bodies(body)                     # methods with { ... } bodies (nested ok)
    body = _STRIP_METHOD.sub("", body)                    # remaining `;`-terminated method decls
    body = _STRIP_CONSTEXPR.sub("", body)
    body = _STRIP_LINE.sub("", body)
    body = _DEFAULT_INIT.sub(r"", body)                   # drop `= <init>`
    body = re.sub(r"\benum\s+class\b", "enum", body)
    body = re.sub(r"\bfinal\b", "", body)
    # strip a ': base' in the TYPE HEAD (sized enum `enum X : uint8_t`, struct inheritance
    # `struct X : Base`) -- CParser rejects it. Safe: bitfield colons live inside the braces.
    head, brace, rest = body.partition("{")
    head = re.sub(r"\s*:\s*[^{]*$", "", head)
    return head + brace + rest


_CALLCONV = re.compile(
    r"\b(?:__(?:stdcall|fastcall|cdecl|thiscall|vectorcall)"
    r"|CALLBACK|WINAPI|WINAPIV|APIENTRY|APIPRIVATE|PASCAL|STDMETHODCALLTYPE)\b")
# names already provided by the preamble -- raw typedefs of these are skipped (no redefinition)
PREAMBLE_NAMES = frozenset({
    "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t",
    "size_t", "wchar_t", "BOOL", "DWORD", "WORD", "BYTE", "UINT", "INT", "ULONG", "LONG",
    "USHORT", "SHORT", "UCHAR", "WPARAM", "LPARAM", "LRESULT", "HRESULT", "COLORREF", "ATOM",
    "DWORD_PTR", "LONG_PTR", "ULONG_PTR", "HANDLE", "LPVOID", "HWND", "HDC", "HINSTANCE",
    "HMODULE", "HKEY", "HMENU", "HICON", "HCURSOR", "HBRUSH", "HFONT", "HBITMAP", "HPALETTE",
    "HPEN", "HRGN", "HGDIOBJ", "HGLOBAL", "HLOCAL", "FARPROC", "LPSTR", "LPCSTR", "LPTSTR",
    "LPCTSTR", "LPBYTE", "LPDWORD", "SOCKET", "FILETIME", "SYSTEMTIME", "GUID", "POINT",
    "RECT", "SIZE", "LARGE_INTEGER",
})
_RAW_TYPEDEF = re.compile(r"\btypedef\s+[^;{}]+;")   # brace-free typedefs (simple + fn-ptr)


def _typedef_name(stmt: str):
    m = re.search(r"\*\s*([A-Za-z_]\w*)\s*\)", stmt)            # fn-ptr: (* NAME)(...)
    if m:
        return m.group(1)
    m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;\s*$", stmt)   # simple: ... NAME;
    return m.group(1) if m else None


def _raw_typedefs(source_dir: Path = None):
    """Verbatim brace-free `typedef` statements (C-style, incl. fn-ptr form), callconv-stripped,
    deduped by name, skipping preamble-provided names. -> [(name, sanitized_stmt)]."""
    out, seen = [], set()
    for p in Path(source_dir or SOURCE_DIR).rglob("*.h"):
        try:
            txt = _strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for stmt in _RAW_TYPEDEF.findall(txt):
            s = _CALLCONV.sub("", stmt).strip()
            name = _typedef_name(s)
            if not name or name in seen or name in PREAMBLE_NAMES:
                continue
            seen.add(name)
            out.append((name, s))
    return out


def _emit_aliases(aliases: dict, defined: set):
    """Convert `using NAME = TARGET;` -> C typedefs. Returns (early, late): early typedefs
    (scalars, pointers, function pointers) go BEFORE structs so fields can reference them;
    by-value aliases to a defined struct/enum go AFTER (target must exist first). Unparseable
    targets (decltype/templates) fall back to `void *` so the name still resolves."""
    early, late = [], []
    for name, target in sorted(aliases.items()):
        t = _CALLCONV.sub("", str(target)).strip()
        m = re.match(r"^(.*?)\(\s*\*\s*\)\s*(\(.*\))\s*$", t, re.S)   # RET (*)(ARGS)
        if m:
            ret = m.group(1).strip() or "void"
            early.append(f"typedef {ret} (*{name}){m.group(2)};")
            continue
        if "decltype" in t or "<" in t or "(" in t:
            early.append(f"typedef void *{name};  /* fallback: {t[:48]} */")
            continue
        base = re.sub(r"\s*\*+\s*$", "", t)
        if "*" in t or base not in defined:
            early.append(f"typedef {t} {name};")
        else:
            late.append(f"typedef {t} {name};")   # by-value alias to a defined type
    return early, late


def emit_header(source_dir: Path = None) -> tuple[str, dict]:
    """Return (header_text, stats). Emits scalar/Windows preamble, forward decls for all struct/
    union tags, then each definition topologically ordered by by-value deps (pointer cycles are
    covered by the forward decls). enums first (no deps)."""
    defs = _definitions(source_dir)
    by_name = {d["name"]: d for d in defs}
    structs_unions = [d for d in defs if d["kind"] in ("struct", "union")]
    enums = [d for d in defs if d["kind"] == "enum"]

    fwd = "".join(f"{d['kind']} {d['name']};\n" for d in structs_unions)

    # topological order on by-value deps (only deps that are themselves defined types matter)
    ordered, placed = [], set()
    def visit(d, stack):
        if d["name"] in placed or d["name"] in stack:
            return
        stack.add(d["name"])
        for dep in d["deps"]:
            if dep in by_name and by_name[dep] is not d:
                visit(by_name[dep], stack)
        stack.discard(d["name"])
        placed.add(d["name"])
        ordered.append(d)
    for d in structs_unions:
        visit(d, set())

    vocab = load(source_dir)
    raw_tds = _raw_typedefs(source_dir)
    raw_names = {n for n, _ in raw_tds}
    # `using` aliases whose name a raw typedef already defines are skipped (no redefinition)
    using = {k: v for k, v in vocab["aliases"].items() if v and k not in raw_names}
    early_aliases, late_aliases = _emit_aliases(
        using, vocab["structs"] | vocab["unions"] | vocab["enums"])

    parts = [_PREAMBLE, "\n/* forward declarations */\n", fwd,
             "\n/* enums */\n"] + [_sanitize(d["body"]) + ";\n" for d in enums]
    parts += ["\n/* C-style typedefs (incl. function pointers) */\n"]
    parts += [stmt + "\n" for _n, stmt in raw_tds]
    parts += ["\n/* using-aliases (scalars / pointers / function pointers) */\n"]
    parts += [a + "\n" for a in early_aliases]
    # C++ template fields (e.g. TSExportTableSyncReuse<...> x;) can't be represented in C/Ghidra;
    # skip those whole structs (their forward-decl remains, so pointers to them still resolve).
    tmpl = re.compile(r"\b[A-Za-z_]\w*\s*<[^;{}<>]*>\s*\**\s*\w+\s*(?:\[[^\]]*\])?\s*;")
    emit_bodies, skipped = [], []
    for d in ordered:
        body = _sanitize(d["body"])
        if tmpl.search(body):
            skipped.append(d["name"])
        else:
            emit_bodies.append(body + ";\n")
    parts += ["\n/* structs & unions */\n"] + emit_bodies
    parts += ["\n/* by-value aliases */\n"] + [a + "\n" for a in late_aliases]
    parts.append("#pragma pack(pop)\n")
    header = "".join(parts)
    stats = {"structs_unions": len(structs_unions), "enums": len(enums),
             "typedefs": len(raw_tds), "using_aliases": len(early_aliases) + len(late_aliases),
             "skipped_template": len(skipped), "total": len(defs), "bytes": len(header)}
    return header, stats


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
    ap.add_argument("--emit-header", metavar="PATH", help="write the flat Ghidra-parseable header")
    args = ap.parse_args()
    if args.emit_header:
        header, stats = emit_header()
        Path(args.emit_header).write_text(header, encoding="utf-8")
        print(f"wrote {args.emit_header}: {stats}")
        return 0
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

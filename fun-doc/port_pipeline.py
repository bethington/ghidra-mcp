"""
port_pipeline.py -- Stage 2/3 ("port" + "prove") of the OpenD2 conformance
pipeline described in OpenD2/docs/EMULATION_CONFORMANCE_PLAN.md Sec 14.

Stage 1 (document) is fun_doc's existing auto-doc worker. This module adds
the two stages that were, until now, entirely manual: drafting an OpenD2 C++
port and proving it against golden vectors minted from the original binary.

Scope (Phase 1, deliberately narrow): only PURE/LEAF functions provable via
the static `/emulate_function` oracle -- no live game process, no debugger,
no WOW64 dependency. Stateful functions (pointer/global-state args) are
classified and skipped, left to the existing manual `d2-port-function` /
`d2-conformance-harness` Claude Code skills in the OpenD2 repo. See the
CMake hazard note on GENERATED_CANDIDATES_DIR below before touching that
constant.

This module is standalone (like its sibling conformance_workbench.py) -- it
does not import fun_doc, so fun_doc/web.py import it, never the reverse.
Callers pass in whatever fun_doc state (conformance_protected set, funcs
dict) it needs rather than this module loading its own copies.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

OPEND2_REPO = Path(os.environ.get("FUNDOC_OPEND2_REPO", r"C:\Users\benam\source\cpp\OpenD2"))
GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")

D2CONFORM_DIR = OPEND2_REPO / "Tools" / "d2conform"
PENDING_VECTORS_DIR = D2CONFORM_DIR / "vectors" / "_pending"


def pascal_to_snake_case(symbol):
    """Convert a D2 symbol to a vector-file-safe snake_case name. D2 symbols
    mix ALL_CAPS module prefixes with CamelCase (e.g.
    "COMMON_ScaledMultiplyDivide") -- inserting "_" before EVERY capital
    mangles an acronym run into "c_o_m_m_o_n__scaled_multiply_divide"
    (confirmed live). Only insert at a lowercase/digit -> uppercase
    boundary (a real camelCase hump); an existing ALL-CAPS run or
    underscore is left untouched."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", symbol).lower()

# CMake hazard (see CMakeLists.txt:22 GLOB_RECURSE SHARED_SRC, folded into
# ENGINE_SRC/D2COMMON_SRC/D2SERVER_SRC): anything under Shared/ compiles into
# the production game/D2Common/D2Server binaries. Generated, unproven drafts
# must live HERE and nowhere else -- never move this under Shared/.
GENERATED_CANDIDATES_DIR = D2CONFORM_DIR / "_generated_candidates"
DRAFT_RUNNER_PATH = GENERATED_CANDIDATES_DIR / "draft_runner.cpp"
DRAFT_VECTORS_PATH = GENERATED_CANDIDATES_DIR / "draft_vectors.json"

# Isolated scratch CMake build dir for the draft harness only. Never
# build_allegro/build_sdl (Ben's own build dirs) -- those stay untouched.
# Matches the `build_*/` .gitignore pattern, so it's never accidentally
# committed.
DRAFT_BUILD_DIR = OPEND2_REPO / "build_port_pipeline"
CMAKE_GENERATOR = os.environ.get("FUNDOC_CMAKE_GENERATOR", "Visual Studio 17 2022")
CMAKE_ARCH = os.environ.get("FUNDOC_CMAKE_ARCH", "Win32")

_GP_REGISTERS = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"}


def _ghidra_get(endpoint, params=None, timeout=15):
    import requests
    try:
        r = requests.get(f"{GHIDRA_HTTP}/{endpoint.lstrip('/')}", params=params, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller as an error string
        return f"<ghidra fetch failed: {exc}>"


def _ghidra_post(endpoint, data=None, params=None, timeout=30):
    import requests
    try:
        # json=, not data= -- BODY-sourced @Param fields (address, registers,
        # etc.) are read from a JSON request body, not form-encoding. Matches
        # fun_doc.ghidra_post's convention exactly (confirmed live: data=
        # produced "Address parameter is required" from every /emulate_
        # function call before this fix).
        r = requests.post(
            f"{GHIDRA_HTTP}/{endpoint.lstrip('/')}", json=data, params=params, timeout=timeout
        )
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            return {"error": f"non-JSON response: {r.text[:500]}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"ghidra post failed: {exc}"}


# ---------------------------------------------------------------------------
# classify_function -- pure/leaf heuristic (picks the oracle mode)
# ---------------------------------------------------------------------------

# Signals that a decompiled function touches global state or deep pointer
# chains -- exactly what makes the static-emulation oracle unreliable (per
# EMULATION_CONFORMANCE_PLAN.md Sec 3, mode 1 vs mode 2/3). Conservative by
# design: classify_function must fail CLOSED (call it "stateful") on any
# ambiguity, since a false "leaf" would silently hand a stateful function to
# an oracle that can't prove it.
#
# IMPORTANT: a pointer parameter is NOT automatically disqualifying. The
# d2-port-function skill's own Step 3 classifies "reads args + maybe a seed
# pointer; no global state" as pure/leaf -- e.g. SEED_GetRandomNumberAlt
# takes `ulonglong *pSeed` (an in/out scalar blob the caller owns) and is
# PROVEN via static emulation (rng.json, 20/20). What actually disqualifies
# a function is a pointer to a *named struct/class type* (UnitAny*, Room*,
# StatList*) implying pre-existing game-world state that can't be
# constructed from scalar inputs -- that's the real "deep pointer chain"
# the plan means. Distinguish by base type: plain scalar/blob pointer types
# are fine; anything else is treated as a struct pointer -> stateful.
# Global access -> stateful (out of the STATIC emulation harness's scope: it
# can't populate a global's memory + the struct it points to). Two forms:
#   DAT_<hex>       -- Ghidra's auto-named data globals
#   _g_* / g_*      -- NAMED globals (e.g. _g_pDataTables, the data-tables root
#                      that every DATATBLS_* accessor dereferences). Found by
#                      hand 2026-07-07: the DAT_-only regex let these named
#                      globals through as "leaf", so the pipeline drafted them,
#                      minted (unusable) vectors, and only discovered the problem
#                      at STATIC-harness link time ("unresolved external symbol
#                      _g_pDataTables") -- three wasted LLM calls + builds per
#                      function. These are provable LIVE (the running game has
#                      the global populated), but that needs the runtime-resolver
#                      reimpl shape + a live-only path (see the note in
#                      classify_function); until then they are honestly stateful.
_GLOBAL_ACCESS_RE = re.compile(r"\bDAT_[0-9a-fA-F]+\b|\b_?g_[A-Za-z_]\w*\b")
# Split the two global forms: a NAMED global (g_*/_g_*) is resolvable by name via
# the D2MOO live resolver (D2MOO_Resolve) -> the function is provable LIVE against
# the running game even though it can't be proven statically. A DAT_<hex> global is
# an unnamed raw address NOT in the resolver -> still hard-stateful.
_DAT_GLOBAL_RE = re.compile(r"\bDAT_[0-9a-fA-F]+\b")
_NAMED_GLOBAL_RE = re.compile(r"\b_?g_[A-Za-z_]\w*\b")
_STRUCT_ACCESS_RE = re.compile(r"->\s*\w+")
# `TYPE *name` (a pointer declaration) and `a * b` (a multiplication
# expression) are IDENTICAL at the token level -- "word, *, word" -- so a
# whole-text regex can't tell them apart (confirmed false positive:
# `(nMultiplier * in_EAX)` inside a return expression matched as if
# "nMultiplier" were a pointer type). Fixed by restricting the scan to
# where pointer declarations actually appear in Ghidra's decompiler output:
# the parameter list (inside the signature's outer parens, before the first
# `{`) and standalone local-declaration lines (a line that is ENTIRELY
# `TYPE *name;`, nothing else -- multiplication only ever appears inside a
# larger statement with `=`/`return`/operators, never as a bare `a * b;`
# line by itself).
_POINTER_PARAM_RE = re.compile(r"(?:^|,)\s*(\w+)\s*\*+\s*\w+\s*(?=,|$)", re.MULTILINE)
_POINTER_LOCAL_LINE_RE = re.compile(r"^\s*(?:\w+\s+)?(\w+)\s*\*+\s*\w+\s*;\s*$", re.MULTILINE)
_C_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
# DOUBLE dereference: `*(TYPE *)(*var ...)` -- reading a POINTER out of another
# pointer and dereferencing it. That's a struct-with-pointers / pointer-to-pointer
# chain (e.g. Room.pSubRooms[i]), which the static /emulate_function harness can't
# build -> stateful, even when the base pointer is typed int*/void* so the
# pointer-base-type check below never fires. Found by hand 2026-07-07:
# FindRoomByCoordinates (Room* typed as int*, `*(int *)(*in_EAX + i*4)`) sailed
# through as "leaf", got drafted, and failed the harness -- a wasted cycle that
# recurs on every Room*/Unit* accessor Ghidra types as a bare int*.
_DEEP_DEREF_RE = re.compile(r"\*\s*\(\s*\w+\s*\*+\s*\)\s*\(\s*\*")
# A pointer Ghidra types as a bare SCALAR (int*/short*/void*) that is actually a
# LIVE-STRUCT base: indexed at a NONZERO offset (`pUnit[0xc]`, `pUnit[4]`) or
# cast-double-dereferenced (`**(short **)pItemCode`). The scalar-pointer allowlist
# wrongly calls these "pure leaf", so they dead-end in the static /emulate harness
# (no_vectors / harness_failed) -- yet they are TRIVIAL live-pointer getters,
# provable via SHADOW (the game passes the real pointer; original+reimpl both read
# it and compare). Distinct from "stateful" (complex / delegating / global-reading)
# because the body is a simple field read. Class = "shadow_leaf". Found 2026-07-07
# running the hot backlog: GetPathFieldByUnitType (pUnit[0xc], 617M hits) and
# DATATBLS_GetItemDataByCode (**(short**)p, 334M hits) both wasted static cycles.
_STRUCT_PTR_INDEX_RE = re.compile(r"\b\w+\s*\[\s*(?:0x0*[1-9a-fA-F][0-9a-fA-F]*|[1-9]\d*)\s*\]")
_CAST_DOUBLE_DEREF_RE = re.compile(r"\*\s*\*\s*\(\s*\w+\s*\*\s*\*\s*\)")
# Clean double-deref of a variable in UNARY position (`return **p;`, `= **p`,
# `(**p`) -- the cast-free form. Once a param's type is corrected to T** (e.g. the
# write-back that fixed DATATBLS_GetItemDataByCode short*->short**), Ghidra drops
# the `**(short**)` cast and emits a bare `**p`, which _CAST_DOUBLE_DEREF_RE misses.
# Anchored to a unary lead-in so `a ** b` (a * (*b)) can't false-match.
_CLEAN_DOUBLE_DEREF_RE = re.compile(r"(?:^|return|[=(,)])\s*\*\s*\*\s*\w")
# A param Ghidra typed as a BARE scalar integer (plain `int`, not `int*`) that the
# BODY uses as a live-STRUCT base -- `*(T *)(param + off)`, `*(T *)param`, or
# `param[idx]`. Ghidra frequently types a struct pointer as plain `int` on
# single-field getters (found 2026-07-08: PATH_GetDynamicX `int pPath` /
# `*(dword *)(pPath + 0xc)` sailed through as "leaf" and dead-ended in the static
# harness). _POINTER_PARAM_RE requires a `*` in the decl, so it misses these; this
# recovers them into shadow_leaf, where they prove trivially via the handle path.
_SCALAR_PARAM_DECL_RE = re.compile(
    r"(?:^|[,(])\s*(?:const\s+)?"
    r"(?:int|uint|dword|long|ulong|__int32|uint32_t|int32_t|intptr_t|uintptr_t)\s+"
    r"(\w+)\s*(?=[,)]|$)")


def _scalar_params_used_as_ptr(params_text, body):
    """Names of BARE-scalar params the body dereferences as a pointer base (cast
    `*(T *)(name...` / `*(T *)name`) or indexes as an array base (`name[idx]`).
    These are struct pointers Ghidra under-typed as `int`."""
    names = []
    for m in _SCALAR_PARAM_DECL_RE.finditer(params_text):
        name = m.group(1)
        esc = re.escape(name)
        # cast-and-deref: *(TYPE *) [(] name ...   -- name is the pointer base
        cast_deref = re.search(r"\*\s*\(\s*\w[\w ]*\*+\s*\)\s*\(?\s*" + esc + r"\b", body)
        # array-base index at a nonzero offset: name[0xNN] / name[1..]
        arr_index = re.search(esc + r"\s*\[\s*(?:0x0*[1-9a-fA-F]|[1-9])", body)
        if cast_deref or arr_index:
            names.append(name)
    return names


# A DECLARED pointer param (`void *pUnit`, `T *p`) name -- _POINTER_PARAM_RE
# captures the base TYPE, not the name; this captures the name.
_POINTER_PARAM_NAME_RE = re.compile(
    r"(?:^|[,(])\s*(?:const\s+)?\w[\w ]*\*+\s*(\w+)\s*(?=[,)]|$)")


def _ptr_params_cast_derefed(params_text, body):
    """Names of DECLARED-pointer params the body dereferences ONLY via a cast
    (`*(T *)pUnit`, `*(T *)(pUnit + off)`, `*(T *)((int)pUnit + off)`) with no
    `->` / `[idx]` / double-deref. This is the canonical Ghidra idiom for a
    read-only handle-getter on a `void *`/`int *` param -- struct_access stays
    False (no `->` or index) and the bare-SCALAR detector skips it (the param is
    a declared pointer, not an under-typed int), so WITHOUT this signal the
    shadow_leaf gate misses it and the getter dead-ends in the static harness as
    `harness_failed` (2026-07-12: UNIT_GetGfxInfo `*(void**)((int)pUnit+0x3c)`,
    ITEMS_GetItemDataEarLvl `*(int*)pUnit` both wasted a static cycle). The
    shadow_leaf gate's own no-global/no-delegate/no-write gates still apply."""
    names = []
    for m in _POINTER_PARAM_NAME_RE.finditer(params_text):
        name = m.group(1)
        esc = re.escape(name)
        # *(T*)  [ ( [ (int) ] ]  name    -- allows `(pUnit` and `((int)pUnit`
        cast_deref = re.search(
            r"\*\s*\(\s*\w[\w ]*\*+\s*\)\s*\(?\s*(?:\(\s*int\s*\)\s*)?" + esc + r"\b",
            body)
        if cast_deref:
            names.append(name)
    return names

# --- handle_leaf gate: a READ-ONLY live-object getter provable via the oracle
# capture path (a real captured object passed to orig+reimpl). It takes exactly one
# pointer, reads its fields, touches NO globals, calls NO real delegates, and
# MUTATES nothing through the pointer. These are the biggest hot-path class, marked
# "stateful" today only because Ghidra types the pointer as a named struct. ---
_CALL_ID_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
# Calls that DON'T disqualify: control flow, abort/exit helpers (null-guard paths),
# and decompiler intrinsics (CONCAT/SUB/ZEXT/... are bit ops, not real functions).
_SAFE_CALL_RE = re.compile(
    r"^(if|while|for|switch|return|sizeof|do|GetReturnAddress|CleanupAndAbort|"
    r"_?exit|abort|assert\w*|CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|CARRY\d+|SBORROW\d+)$")
# A WRITE through a pointer/struct: `p->f =`, `*p =`, `a[i] =`, `*(T*)(..) =`.
# CRITICAL SAFETY GATE -- a fn that mutates the pointed-to object must NEVER be
# handle-proven: passing a live captured game object would CORRUPT it. `==` excluded.
_PTR_WRITE_RE = re.compile(r"(?:->\s*\w+|\]|\*\s*\([^;{}]*\)|\*\s*\w+)\s*=(?!=)")


def _has_delegate_call(body):
    """True if `body` calls any function that is NOT control-flow / an abort helper
    / a decompiler intrinsic -- i.e. a real delegate a passthrough reimpl can't
    reproduce from field reads alone."""
    for m in _CALL_ID_RE.finditer(body):
        if not _SAFE_CALL_RE.match(m.group(1)):
            return True
    return False


def _strip_comments(text):
    """Drop /* ... */ blocks before classification. fun-doc's plate comments
    are English prose (algorithm descriptions, parameter docs) that can
    accidentally look like C pointer declarations to a regex -- e.g. a
    module-name aside like "(SEED_* module)" false-matches a "type *ident"
    pattern. Only the real decompiled code should drive classification."""
    return _C_COMMENT_RE.sub(" ", text)


def _extract_signature_params(text):
    """Return the raw text between the function signature's outer parens
    (the parameter list) -- the first top-level paren group in the
    decompile, matching Ghidra's standard "ReturnType FuncName(params)"
    shape. "" if no parens found. Isolating this substring is what makes
    _POINTER_PARAM_RE safe: a bare multiplication expression like
    "(nMultiplier * in_EAX)" inside the function BODY never gets scanned as
    if it were a parameter declaration."""
    start = text.find("(")
    if start == -1:
        return ""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
    return ""

# Ghidra/decompiler spellings for scalar or opaque-blob pointer base types.
# A pointer to any of these is an in/out value, not a struct/world-state
# reference -- does not disqualify static emulation.
_SCALAR_POINTER_BASE_TYPES = {
    "void", "char", "uchar", "byte", "sbyte", "bool", "boolean",
    "short", "ushort", "int", "uint", "long", "ulong",
    "longlong", "ulonglong", "float", "double",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "int8", "int16", "int32", "int64",
    "uint8", "uint32", "uint32_t", "uint16", "uint16_t", "uint8_t", "uint64", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "wchar_t", "wchar16",
}


def classify_function(decompiled_text, variables=None):
    """Classify a function for the port pipeline. Returns:
      "leaf"        -- pure/leaf, provable via static /emulate_function.
      "global_leaf" -- reads only NAMED globals, provable LIVE via the resolver.
      "shadow_leaf" -- trivial LIVE-POINTER getter (a scalar-typed pointer used as
                       a struct base): not statically emulable, provable via SHADOW
                       (the game passes the real pointer). The hot-path getter class.
      "stateful"    -- complex/struct-pointer/delegating; out of auto-port scope.
      "unknown"     -- decompile fetch failed; treat as do-not-auto-port.

    Heuristic (deliberately conservative -- see module docstring):
    - Any DAT_<addr> OR named g_*/_g_* global reference in the decompile
      -> stateful.
    - Any `->` struct-field navigation -> stateful (deep pointer chains,
      per the d2-port-function skill's Step 3).
    - Any pointer parameter/local whose base type is NOT a known
      scalar/blob type (i.e. looks like a named struct, e.g. UnitAny*,
      Room*) -> stateful. A scalar/blob pointer (uint*, ulonglong*, an
      in/out seed or accumulator the caller owns) does NOT disqualify.
    - Otherwise -> leaf.

    NOTE (future work, 2026-07-07): the named-global class (e.g. every
    DATATBLS_* accessor dereferencing _g_pDataTables) is skipped as
    "stateful" here because the STATIC /emulate_function harness can't
    populate a global + the struct it points to. But this class IS
    provable LIVE against the running game (the global is populated there)
    -- exactly how the D2MOO conformance work proves GetDataTableRowEntryCount
    by hand. Automating it needs (a) a reimpl draft that resolves the global
    at runtime via the injected resolver (D2MOO_Resolve), not an OpenD2-style
    `extern _g_pDataTables`, and (b) a live-prove-ONLY path that skips the
    static harness for this class. Until both exist, skipping is the honest
    behavior (better than burning LLM calls + builds on a guaranteed static
    link failure).
    """
    if not decompiled_text or decompiled_text.startswith("<ghidra fetch failed"):
        return "unknown"

    text = _strip_comments(str(decompiled_text))
    # Pointer-type checks are scoped to where declarations actually appear
    # (signature params + standalone local-decl lines), NOT the whole text -- a
    # whole-text scan can't tell `TYPE *name` (declaration) from `a * b`
    # (multiplication). See _extract_signature_params/_POINTER_LOCAL_LINE_RE.
    header, _, body = text.partition("{")
    params_text = _extract_signature_params(header)
    has_ptr_param = bool(_POINTER_PARAM_RE.search(params_text))

    # VESTIGIAL `this` (2026-07-13, capability loop): Ghidra types a register-arg
    # getter as `__thiscall FN(void *this, int arg)` where `this` is UNUSED (the
    # real arg arrives in EAX as `in_EAX`). The phantom pointer param made the
    # whole SKILLS mana/damage getter family -- pure `g_pDataTables->pRows[idx]`
    # global-table reads -- miss the global_leaf gate ("no pointer param") and
    # dead-end in stateful_skip. A `this` param never referenced in the body is
    # noise: drop it before the pointer-param gates so these route to the
    # resolver-based global_leaf path. (26+ fns in the stateful_struct_arrow
    # bucket are this shape.) Only when `this` is the exact param name AND absent
    # from the body -- a real self/context pointer that IS used stays counted.
    if re.search(r"\bthis\b", params_text) and not re.search(r"\bthis\b", body):
        params_text = re.sub(r"(?:^|,)\s*\w[\w ]*\*+\s*this\s*(?=,|$)", ",", params_text).strip(", ")
        has_ptr_param = bool(_POINTER_PARAM_RE.search(params_text))

    # handle_leaf FIRST -- a READ-ONLY live-object getter: EXACTLY ONE pointer arg,
    # reads its fields (struct access), touches NO globals, calls NO real delegate,
    # and writes NOTHING through the pointer. Provable via the oracle handle path (a
    # real captured object passed to orig+reimpl -- the GetPathFieldByUnitType /
    # UNIT_GetMode mechanism). Checked BEFORE the stateful guards, which a struct
    # getter would otherwise trip (`->` / named-struct param), because it is the
    # biggest hot-path class and IS provable. SAFETY: the no-write gate is REQUIRED
    # -- handle-proving a mutator would corrupt the live captured game object.
    struct_access = bool(_STRUCT_ACCESS_RE.search(body) or _STRUCT_PTR_INDEX_RE.search(body)
                         or _CAST_DOUBLE_DEREF_RE.search(body) or _CLEAN_DOUBLE_DEREF_RE.search(body))
    # A single live-pointer param can be either a declared pointer (`T *p`) OR a
    # bare scalar Ghidra under-typed (`int p` used as `*(T*)(p+off)`). Count both so
    # the under-typed getters (PATH_GetDynamicX etc.) reach shadow_leaf instead of
    # dead-ending in the static harness.
    declared_ptr_params = _POINTER_PARAM_RE.findall(params_text)
    scalar_ptr_params = _scalar_params_used_as_ptr(params_text, body)
    # A DECLARED pointer param dereferenced ONLY via cast (`*(T*)pUnit`) -- no
    # `->`/index, so struct_access is False and it's not a bare-scalar either.
    # Without this the read-only handle-getter falls through to `leaf` and dies
    # in the static harness (see _ptr_params_cast_derefed).
    cast_deref_ptr_params = _ptr_params_cast_derefed(params_text, body)
    total_ptr_params = len(declared_ptr_params) + len(scalar_ptr_params)
    if (total_ptr_params == 1
            and (struct_access or scalar_ptr_params or cast_deref_ptr_params)
            and not _DAT_GLOBAL_RE.search(text) and not _NAMED_GLOBAL_RE.search(text)
            and not _has_delegate_call(body) and not _PTR_WRITE_RE.search(body)):
        return "shadow_leaf"

    # NAMED-GLOBAL TABLE GETTER (before the ->/deep-deref guards): a function that
    # reads a NAMED global (g_*/_g_*), takes NO live-object pointer param (only scalar/
    # index args), and does NOT delegate, is provable LIVE via the resolver regardless
    # of Ghidra TYPING. Its `->`/deep derefs are on a pointer COMPUTED from the named
    # global + a scalar index (`records[idx]->field`) -- fully resolvable, NOT a captured-
    # object chain (which needs a pointer PARAM). Without this, typing a record ptr
    # (`rec->field` -> `->`) mis-routes it to stateful while the structurally-identical
    # UNTYPED getter reaches global_leaf. (DATATBLS batch 2026-07-08: GetItemTypeFieldE
    # global_leaf+proved vs identical GetItemTypeField10 stateful-skipped, only because
    # its record ptr was typed -> `->`.) Gated: named global, no unnamed DAT_, no pointer
    # param at all, no delegate -> the derefs can only be global/scalar-derived.
    if (_NAMED_GLOBAL_RE.search(text) and not _DAT_GLOBAL_RE.search(text)
            and not has_ptr_param and not scalar_ptr_params
            and not _has_delegate_call(body)):
        return "global_leaf"

    # HARD-stateful signals (not provable statically AND not simply live-resolvable):
    if _DAT_GLOBAL_RE.search(text):
        return "stateful"  # unnamed raw-address global -- not in the name resolver
    if _STRUCT_ACCESS_RE.search(text):
        return "stateful"  # `->` struct navigation
    if _DEEP_DEREF_RE.search(text):
        return "stateful"  # pointer-to-pointer / struct-with-pointers chain

    for m in _POINTER_PARAM_RE.finditer(params_text):
        base_type = m.group(1).lower().replace("const", "").strip()
        if base_type not in _SCALAR_POINTER_BASE_TYPES:
            return "stateful"
    for m in _POINTER_LOCAL_LINE_RE.finditer(body):
        base_type = m.group(1).lower().replace("const", "").strip()
        if base_type not in _SCALAR_POINTER_BASE_TYPES:
            return "stateful"

    if isinstance(variables, dict):
        for group in ("parameters", "locals"):
            for v in variables.get(group, []) or []:
                dtype = str(v.get("data_type") or v.get("type") or "")
                if "*" in dtype:
                    base_type = dtype.split("*")[0].strip().lower()
                    if base_type not in _SCALAR_POINTER_BASE_TYPES:
                        return "stateful"

    # (The live-pointer GETTER class 'shadow_leaf' is decided EARLY, above, with the
    # full read-only/no-global/no-delegate safety gate -- it must precede the
    # stateful guards a struct getter would otherwise trip.)

    # No hard-stateful signal. If the only "state" it touches is a NAMED global
    # (g_*/_g_*), it's provable LIVE via the D2MOO resolver (D2MOO_Resolve gives
    # the real running-game address) -- a distinct class the live-prove path
    # handles, not a static-harness candidate. Otherwise it's a pure leaf.
    if _NAMED_GLOBAL_RE.search(text):
        return "global_leaf"
    return "leaf"


def stateful_reason(decompiled_text, variables=None):
    """WHY did classify_function say 'stateful'? A short bucket code for the
    capability loop (2026-07-13): the stateful class is the largest blocked
    bucket (23/40 in the 07-12 sweep) but was logged as one opaque outcome, so
    there was no data to decide WHICH prove capability to build next. Mirrors
    classify_function's guard order; each code names the capability that would
    unlock the function. Returns 'not_stateful' when classify wouldn't have
    said stateful (caller bug), 'other' when no specific guard is identified.

    Codes:
      ptr_write            -- mutates through a pointer (needs write-capture; may never auto-prove)
      delegate_call        -- calls a real subroutine (needs call-through lane to fire)
      global_plus_ptr      -- named global AND pointer param (needs shadow-first / resolver+handle mix)
      dat_global           -- unnamed DAT_/raw-address global (needs resolver entry or rename)
      multi_ptr_params     -- >1 pointer param (needs multi-handle marshalling)
      struct_arrow         -- `->` navigation w/ struct-typed locals/params (needs handle path widening)
      deep_deref           -- pointer-to-pointer chains (needs deeper capture)
      named_struct_ptr     -- param/local typed as a named struct ptr (typing-driven; often handle-leaf-able)
      other                -- none of the above matched
    """
    text = decompiled_text or ""
    header, _, body = text.partition("{")
    params_text = _extract_signature_params(header)
    declared = _POINTER_PARAM_RE.findall(params_text)
    scalar_ptr = _scalar_params_used_as_ptr(params_text, body)
    has_ptr = bool(declared or scalar_ptr)
    if _PTR_WRITE_RE.search(body):
        return "ptr_write"
    if _has_delegate_call(body):
        return "delegate_call"
    if _NAMED_GLOBAL_RE.search(text) and has_ptr:
        return "global_plus_ptr"
    if _DAT_GLOBAL_RE.search(text):
        return "dat_global"
    if len(declared) + len(scalar_ptr) > 1:
        return "multi_ptr_params"
    if _STRUCT_ACCESS_RE.search(text):
        return "struct_arrow"
    if _DEEP_DEREF_RE.search(text):
        return "deep_deref"
    for m in _POINTER_PARAM_RE.finditer(params_text):
        base = m.group(1).lower().replace("const", "").strip()
        if base not in _SCALAR_POINTER_BASE_TYPES:
            return "named_struct_ptr"
    if isinstance(variables, dict):
        for group in ("parameters", "locals"):
            for v in variables.get(group, []) or []:
                dtype = str(v.get("data_type") or v.get("type") or "")
                if "*" in dtype and dtype.split("*")[0].strip().lower() not in _SCALAR_POINTER_BASE_TYPES:
                    return "named_struct_ptr"
    return "other"


# ---------------------------------------------------------------------------
# mint_vectors -- Stage 3 input, static-emulation oracle only (Mode 1)
# ---------------------------------------------------------------------------

def _hex_to_int(value, signed_bits=None):
    if isinstance(value, int):
        v = value
    else:
        v = int(str(value), 16) if str(value).lower().startswith("0x") else int(value)
    if signed_bits:
        half = 1 << (signed_bits - 1)
        full = 1 << signed_bits
        if v >= half:
            v -= full
    return v


def mint_vectors(program, address, fn_name, param_layout, input_sets, *, max_steps=10000, timeout=30):
    """Mint golden vectors for one leaf/pure function via the static
    `/emulate_function` oracle. Fully automatable -- no live game process.

    param_layout: {
        "inputs":  [{"name": "seedLo", "register": "ECX", "signed": false}, ...],
        "outputs": [{"name": "ret",    "register": "EAX", "signed": false}, ...],
    }
    input_sets: list of {name: int_value, ...} dicts, one per case. Callers
    (the port_pipeline drafting step, or the d2-port-function skill for a
    manual mint) are responsible for covering edge cases (0, 1, powers of
    two, decompiler-flagged overflow guards) -- see EMULATION_CONFORMANCE_PLAN
    Sec 8 "coverage, not overfitting".

    Returns (vectors, errors): vectors is a list of {fn, in, out, note}
    dicts ready for vectors/_pending/<system>.json; errors is a list of
    per-case failure strings (emulation fault, timeout, etc.) for cases that
    could not be minted -- callers should not silently drop these.
    """
    vectors = []
    errors = []
    # A drafted layout can omit 'register' entirely (the model describes a
    # STACK arg for a cdecl CRT leaf like shortsort). inp['register'] then
    # KeyError'd and killed the whole candidate (2026-07-13). The static
    # /emulate_function oracle is register-based -- no register mapping means
    # this function can't be minted, which is an ERRORS outcome, not a crash.
    missing = [p.get("name", "?") for p in
               list(param_layout.get("inputs", [])) + list(param_layout.get("outputs", []))
               if "register" not in p]
    if missing:
        return [], [f"layout has no register mapping for {missing} "
                    f"(stack-arg layout -- not statically mintable)"]
    return_registers = ",".join(o["register"] for o in param_layout["outputs"])

    for case in input_sets:
        registers = {}
        for inp in param_layout["inputs"]:
            if inp["name"] not in case:
                errors.append(f"case {case!r} missing input '{inp['name']}'")
                registers = None
                break
            # The model's input_sets sometimes use hex STRINGS for
            # pointer-looking values (e.g. "0x10000000") rather than a plain
            # int -- _hex_to_int (already used for the OUTPUT side below)
            # normalizes either form. Found by hand 2026-07-07: an int-only
            # `&` here raised an unhandled TypeError that killed the entire
            # worker pass, not just this one candidate. 2026-07-13: the model
            # can also emit an EMPTY/garbage string ('' on
            # ProcessFormatStringData) -- same policy, fail the CASE not the fn.
            try:
                registers[inp["register"]] = f"0x{_hex_to_int(case[inp['name']]) & 0xFFFFFFFF:x}"
            except (ValueError, TypeError):
                errors.append(f"case {case!r}: unparseable input "
                              f"{inp['name']!r}={case[inp['name']]!r}")
                registers = None
                break
        if registers is None:
            continue

        result = _ghidra_post(
            "/emulate_function",
            data={
                "address": address if str(address).startswith("0x") else f"0x{address}",
                "registers": json.dumps(registers),
                "max_steps": max_steps,
                "return_registers": return_registers,
            },
            # `program` defaults to ParamSource.QUERY (no `source = BODY` on
            # that @Param) -- POST endpoints must send it as a URL query
            # param, not in the JSON body (CLAUDE.md's Code Conventions).
            # Confirmed live: putting it in `data` silently resolved against
            # whatever program Ghidra treats as "current" instead of the one
            # named here, producing "No function at address" for a real,
            # valid entry point.
            params={"program": program},
            timeout=timeout,
        )
        if result.get("error"):
            errors.append(f"case {case!r}: {result['error']}")
            continue
        if not result.get("success") or not result.get("hit_return"):
            errors.append(
                f"case {case!r}: emulation did not return cleanly "
                f"(stop_reason={result.get('stop_reason')!r})"
            )
            continue

        reg_values = result.get("registers", {})
        out = {}
        ok = True
        for outp in param_layout["outputs"]:
            raw = reg_values.get(outp["register"])
            if raw is None:
                errors.append(f"case {case!r}: missing return register {outp['register']!r}")
                ok = False
                break
            try:
                out[outp["name"]] = _hex_to_int(raw, signed_bits=32 if outp.get("signed") else None)
            except (ValueError, TypeError):
                # The emulator reports a per-register failure as a STRING value
                # (e.g. "error: Undefined register: MEM" when a drafted layout
                # names a register the emulator doesn't have). int()-ing it was
                # an UNCAUGHT ValueError that killed the whole candidate
                # (2026-07-13, SEED_GetRandomInRange). Fail the CASE, keep the fn.
                errors.append(f"case {case!r}: unreadable register "
                              f"{outp['register']!r}: {str(raw)[:80]}")
                ok = False
                break
        if not ok:
            continue

        vectors.append({
            "fn": fn_name,
            "in": dict(case),
            "out": out,
            "note": f"PD2-S12; src {program} 0x{str(address).replace('0x', '')}",
        })

    return vectors, errors


def write_pending_vectors(system_name, vectors):
    """Append/merge vectors into vectors/_pending/<system>.json (existing
    staging convention -- see the treasureclass.json precedent). Returns the
    path written."""
    PENDING_VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    path = PENDING_VECTORS_DIR / f"{system_name}.json"
    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = []
    existing.extend(vectors)
    path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# run_harness -- Stage 3 gate. Builds + runs the isolated d2conform_draft
# target (see CMakeLists.txt's D2CONFORM_ENABLE_DRAFTS option). Never
# touches d2conform.cpp (hand-maintained production harness) or Shared/.
# ---------------------------------------------------------------------------

_DRAFT_RUNNER_TEMPLATE = '''\
// ============================================================================
//  d2conform_draft - single-candidate draft port runner (GENERATED)
//
//  Regenerated by fun-doc's port_pipeline.write_draft() for whichever ONE
//  candidate is currently being proven. Do not hand-edit -- see
//  Tools/d2conform/_generated_candidates/ and CMakeLists.txt's
//  D2CONFORM_ENABLE_DRAFTS option.
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cinttypes>   // PRIXPTR / PRId64 / PRIu32 etc. -- models use these pointer/
                       // width format macros in FAIL-diagnostic printfs; without
                       // this the whole draft_runner fails to compile with
                       // "'PRIXPTR': undeclared identifier" and the candidate is
                       // scored harness_failed (found by the self-improving loop
                       // 2026-07-15: SafeDereferencePointer, 3 wasted attempts).
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>

#include "{header_name}"   // candidate under test

#ifndef D2CONFORM_DRAFT_VECTOR_DIR
#define D2CONFORM_DRAFT_VECTOR_DIR "."
#endif

struct JVal
{{
	enum Type {{ NUL, BOOL, NUM, STR, ARR, OBJ }} type = NUL;
	bool          b = false;
	long long     num = 0;
	std::string   str;
	std::vector<JVal>          arr;
	std::map<std::string,JVal> obj;

	const JVal* find(const char* k) const
	{{
		auto it = obj.find(k);
		return it == obj.end() ? nullptr : &it->second;
	}}
	long long n(const char* k, long long dflt = 0) const
	{{
		const JVal* v = find(k);
		return v ? v->num : dflt;
	}}
	bool has(const char* k) const {{ return find(k) != nullptr; }}
}};

struct JParser
{{
	const char* p;
	const char* end;
	bool ok = true;

	explicit JParser(const std::string& s) : p(s.c_str()), end(s.c_str() + s.size()) {{}}

	void ws() {{ while (p < end && (*p==' '||*p=='\\t'||*p=='\\n'||*p=='\\r')) ++p; }}

	JVal parse() {{ ws(); return value(); }}

	JVal value()
	{{
		ws();
		if (p >= end) {{ ok = false; return {{}}; }}
		char c = *p;
		if (c == '{{') return object();
		if (c == '[') return array();
		if (c == '"') {{ JVal v; v.type = JVal::STR; v.str = str(); return v; }}
		if (c == 't' || c == 'f') return boolean();
		if (c == 'n') {{ p += 4; JVal v; v.type = JVal::NUL; return v; }}
		return number();
	}}

	JVal object()
	{{
		JVal v; v.type = JVal::OBJ; ++p; ws();
		if (p < end && *p == '}}') {{ ++p; return v; }}
		while (p < end)
		{{
			ws();
			std::string key = str(); ws();
			if (p < end && *p == ':') ++p;
			v.obj[key] = value(); ws();
			if (p < end && *p == ',') {{ ++p; continue; }}
			if (p < end && *p == '}}') {{ ++p; break; }}
			break;
		}}
		return v;
	}}

	JVal array()
	{{
		JVal v; v.type = JVal::ARR; ++p; ws();
		if (p < end && *p == ']') {{ ++p; return v; }}
		while (p < end)
		{{
			v.arr.push_back(value()); ws();
			if (p < end && *p == ',') {{ ++p; continue; }}
			if (p < end && *p == ']') {{ ++p; break; }}
			break;
		}}
		return v;
	}}

	std::string str()
	{{
		std::string s;
		if (p < end && *p == '"') ++p;
		while (p < end && *p != '"')
		{{
			if (*p == '\\\\' && p + 1 < end) {{ ++p; s.push_back(*p++); }}
			else s.push_back(*p++);
		}}
		if (p < end && *p == '"') ++p;
		return s;
	}}

	JVal boolean()
	{{
		JVal v; v.type = JVal::BOOL;
		if (*p == 't') {{ v.b = true;  p += 4; }}
		else           {{ v.b = false; p += 5; }}
		return v;
	}}

	JVal number()
	{{
		JVal v; v.type = JVal::NUM;
		const char* s = p;
		while (p < end && (*p=='-'||*p=='+'||(*p>='0'&&*p<='9')||*p=='.'||*p=='e'||*p=='E')) ++p;
		std::string tok(s, p);
		v.num = (long long)strtoll(tok.c_str(), nullptr, 10);
		return v;
	}}
}};

static bool run_case(const JVal& c, int idx)
{{
	const JVal* fnv = c.find("fn");
	const JVal* in  = c.find("in");
	const JVal* out = c.find("out");
	if (!fnv || !in || !out) {{ printf("  FAIL [%d]: malformed case\\n", idx); return false; }}
	const std::string& fn = fnv->str;

{dispatch_body}

	printf("  FAIL [%d]: no candidate staged ('%s' requested)\\n", idx, fn.c_str());
	return false;
}}

int main()
{{
	std::string path = std::string(D2CONFORM_DRAFT_VECTOR_DIR) + "/draft_vectors.json";
	std::ifstream f(path, std::ios::binary);
	if (!f)
	{{
		printf("ERROR: cannot open vector file '%s'\\n", path.c_str());
		return 1;
	}}
	std::stringstream ss; ss << f.rdbuf();
	std::string text = ss.str();  // named, not a temporary -- JParser stores raw pointers into it
	JParser jp(text);
	JVal root = jp.parse();
	if (root.type != JVal::ARR)
	{{
		printf("ERROR: '%s' is not a JSON array of cases\\n", path.c_str());
		return 1;
	}}

	printf("d2conform_draft - single-candidate draft runner\\n");
	int pass = 0, fail = 0;
	for (size_t i = 0; i < root.arr.size(); ++i)
	{{
		if (run_case(root.arr[i], (int)i)) ++pass;
		else ++fail;
	}}
	printf("%d/%d passed%s\\n", pass, pass + fail, fail ? "   <<< FAIL" : "");
	return fail == 0 ? 0 : 1;
}}
'''


def write_draft(module, symbol, header_content, dispatch_body, vectors):
    """Stage the candidate for proving. Writes ONLY to
    _generated_candidates/ -- never Shared/*.hpp, never a git commit.

    dispatch_body: C++ source implementing the `if (fn == "...") {...}`
    block(s) for this candidate's function(s), matching d2conform.cpp's
    run_case style (see Tools/d2conform/d2conform.cpp for the pattern).

    Returns {header_path, runner_path, vectors_path}.
    """
    GENERATED_CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    header_name = f"{module}_{symbol}.hpp"
    header_path = GENERATED_CANDIDATES_DIR / header_name
    header_path.write_text(header_content, encoding="utf-8")

    DRAFT_VECTORS_PATH.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")

    runner_src = _DRAFT_RUNNER_TEMPLATE.format(header_name=header_name, dispatch_body=dispatch_body)
    DRAFT_RUNNER_PATH.write_text(runner_src, encoding="utf-8")

    return {
        "header_path": str(header_path),
        "runner_path": str(DRAFT_RUNNER_PATH),
        "vectors_path": str(DRAFT_VECTORS_PATH),
    }


_HARNESS_LINE_RE = re.compile(r"^(\d+)/(\d+) passed")


def run_harness(*, configure=True, build_timeout=180, run_timeout=30):
    """Build + run the isolated d2conform_draft target against whatever is
    currently staged in _generated_candidates/. Returns:
        {ok: bool, passed: int, total: int, output: str, exit_code: int|None,
         stage: "configure"|"build"|"run"|"done", error: str|None}

    `ok` is True only when the build succeeded AND every vector passed.
    Never touches build_allegro/build_sdl (Ben's own build dirs) -- always
    uses the isolated DRAFT_BUILD_DIR.
    """
    if configure or not (DRAFT_BUILD_DIR / "CMakeCache.txt").exists():
        cfg = subprocess.run(
            [
                "cmake", "-B", str(DRAFT_BUILD_DIR),
                "-G", CMAKE_GENERATOR, "-A", CMAKE_ARCH,
                "-DD2CONFORM_ENABLE_DRAFTS=ON",
                "-DBUILD_GAME=OFF", "-DBUILD_D2CLIENT=OFF", "-DBUILD_D2SERVER=OFF",
            ],
            cwd=str(OPEND2_REPO),
            capture_output=True, text=True, timeout=build_timeout,
        )
        if cfg.returncode != 0:
            return {
                "ok": False, "passed": 0, "total": 0,
                "output": cfg.stdout + cfg.stderr, "exit_code": cfg.returncode,
                "stage": "configure", "error": "cmake configure failed",
            }

    build = subprocess.run(
        ["cmake", "--build", str(DRAFT_BUILD_DIR), "--config", "Debug", "--target", "d2conform_draft"],
        cwd=str(OPEND2_REPO),
        capture_output=True, text=True, timeout=build_timeout,
    )
    if build.returncode != 0:
        return {
            "ok": False, "passed": 0, "total": 0,
            "output": build.stdout + build.stderr, "exit_code": build.returncode,
            "stage": "build", "error": "build failed",
        }

    exe_path = DRAFT_BUILD_DIR / "Debug" / "d2conform_draft.exe"
    if not exe_path.exists():
        exe_path = DRAFT_BUILD_DIR / "d2conform_draft.exe"
    try:
        run = subprocess.run(
            [str(exe_path)], capture_output=True, text=True, timeout=run_timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False, "passed": 0, "total": 0,
            "output": "", "exit_code": None,
            "stage": "run", "error": f"draft runner exceeded {run_timeout}s (possible infinite loop)",
        }

    output = run.stdout + run.stderr
    passed = total = 0
    for line in output.splitlines():
        m = _HARNESS_LINE_RE.match(line.strip())
        if m:
            passed, total = int(m.group(1)), int(m.group(2))
            break

    return {
        "ok": run.returncode == 0 and total > 0,
        "passed": passed, "total": total,
        "output": output, "exit_code": run.returncode,
        "stage": "done", "error": None,
    }


# ---------------------------------------------------------------------------
# select_port_candidates -- Stage 2 candidate selection.
#
# Deliberately NOT a copy of fun_doc.select_candidates: that selector's score
# gate means "needs more Stage-1 documentation work" (score < good_enough).
# Stage 2 wants the OPPOSITE population -- functions Stage 1 already
# finished -- so score >= good_enough_score is a requirement here, not an
# exclusion. Everything else (thunks/externals/library_code/conformance-
# protected exclusion) mirrors select_candidates' filters exactly.
# ---------------------------------------------------------------------------

_BINARY_PORT_PRIORITY = {"D2Common.dll": 0, "D2Game.dll": 1, "D2Client.dll": 2}

# Library / C-runtime / FLIRT-matched functions that are NOT D2 game logic and must
# never be port candidates -- they're linked-in CRT/STL, not something to reimplement.
# Found by hand 2026-07-07: a --count 20 batch wasted cycles on FID_conflict:_memcpy,
# FID_conflict:_atoi, __cinit, doexit, STL template instantiations, etc. -- they score
# HIGH (a FLIRT match gives them a real name) so they sail through the score>=80 gate.
# The `library_code` flag doesn't catch them (detector missed them), but the NAME is a
# dead giveaway. D2's own exports are PREFIX_Name / CamelCase and never start with '_'.
_KNOWN_CRT_NAMES = frozenset({"doexit", "mainret", "_initterm", "_cinit", "atexit"})


def _looks_like_library_or_runtime(name):
    if not name:
        return False
    if name[0] == "_":                       # _initterm, __cinit, _Tidy, _ftol, _memcpy
        return True
    for p in ("FID_", "FUN_", "thunk_", "j_"):
        if name.startswith(p):               # FLIRT matches, unnamed, thunks
            return True
    if "<" in name or ">" in name:           # STL template instantiations
        return True
    return name in _KNOWN_CRT_NAMES

# port_status values that mean "already resolved -- do NOT re-select". Found by
# hand 2026-07-07: without this, select_port_candidates returns the SAME
# deterministically-sorted top-N every call, so a continuous loop re-processed
# the identical 3 functions every batch and never advanced to new ones. Terminal
# outcomes are excluded so the loop moves forward; `blocked` (quota/transient)
# is intentionally NOT terminal so it retries later. To deliberately re-attempt
# a terminal function (e.g. after a prompt/generator fix), clear its port_status
# in state -- see scripts or the --retry-failed path.
_PORT_TERMINAL_STATUSES = frozenset({
    "proven_pending_review",       # static harness succeeded, awaiting human promotion
    "proven_live_pending_review",  # LIVE oracle proof succeeded, awaiting human promotion
    "stateful_skip",               # classified out of scope (deterministic)
    "harness_failed",              # exhausted the bounded fix-retry loop
    "live_prove_failed",           # live-path reimpl drafted but didn't prove
    "unsupported_abi",             # register layout outside the oracle marshaller
    "malformed_response",          # provider never returned parseable blocks after retries
    "no_vectors",                  # /emulate_function couldn't mint any vectors
    "unknown_skip",                # decompile fetch failed
    "error",                       # unexpected pipeline exception (guarded per-candidate)
    # WAIT-STATES owned by the shadow pipeline (2026-07-14): the routing that
    # produces these is deterministic (decompile regexes + resolve-table
    # lookups), so re-selecting them re-derives the identical verdict every
    # pass -- observed burning 3 of 5 count slots in EVERY dashboard batch.
    # They advance via a shadow-dispatcher build + battletest, not this
    # worker; the shadow batch builder reads them from the state DB /
    # shadow_leaf_backlog.jsonl, and include_terminal=True re-admits them.
    "shadow_leaf_pending",         # deferred to shadow-first; awaiting a shadow batch build
    "handle_abort_hazard_skip",    # type-gated fatal abort; unsafe until capture pinning exists
    # CONFIRMED shadow-unreachable (2026-07-14 triage): 0 hits across a full
    # instrumented playthrough AND 0 static callers in Ghidra — the game
    # inlined every call site. A shadow dispatcher would idle forever; the
    # planner's shadow_unreachable_risk PREDICTION is upgraded to fact.
    # Terminal for the port worker; the offline CONF_REGRESSION lane owns
    # these (conformance/CONF_REGRESSION_OFFLINE_SUITE.md).
    "shadow_unreachable",
})


def select_port_candidates(funcs, conformance_protected, active_binary=None,
                            good_enough_score=80, limit=20,
                            include_terminal=False):
    """Select functions eligible for Stage 2 (port) work.

    `funcs`: the same {key: func_dict} state fun_doc.select_candidates
    consumes. `conformance_protected`: the set from
    fun_doc.load_conformance_protected() -- passed in, not loaded here (this
    module has no fun_doc import; see module docstring).

    Does NOT run classify_function -- that needs a live decompile fetch per
    candidate, which the caller (the PORT worker) does one candidate at a
    time, skipping any that classify "stateful". This function only narrows
    the pool to "Stage 1 complete, not already conformance-tracked, priority-
    ordered" candidates.

    Sort: binary priority (D2Common -> D2Game -> D2Client, per
    EMULATION_CONFORMANCE_PLAN.md Sec 15) first, then leaves before callers
    (bottom-up, matching select_candidates' own readiness ordering), then
    highest caller_count (more xrefs = more valuable to prove first).
    """
    out = []
    for key, func in funcs.items():
        if func.get("is_thunk") or func.get("is_external"):
            continue
        if func.get("library_code") or _looks_like_library_or_runtime(func.get("name")):
            continue
        if key in conformance_protected:
            continue
        binary_name = func.get("program_name", "") or ""
        # active_binary arrives as a bare name from CLI callers but as the
        # full program path (/Mods/.../D2Common.dll) from the pipeline UI's
        # Prove lane — accept both, else the UI's port worker always exits
        # no_eligible_candidates.
        if active_binary and active_binary not in (binary_name, func.get("program") or ""):
            continue

        score = func.get("effective_score", func.get("score", 0)) or 0
        if score < good_enough_score:
            continue  # Stage 1 not finished yet -- not ready for Stage 2

        if not include_terminal and func.get("port_status") in _PORT_TERMINAL_STATUSES:
            continue  # already resolved -- don't re-select (loop must advance)

        # oracle_unavailable (2026-07-15): a live-provable fn skipped ONLY because
        # the oracle was down. NON-terminal -- never lost -- but excluded from
        # selection WHILE the oracle is down (else it churns the same fns every
        # pass). Re-admitted the moment FUNDOC_LIVE_PROVE=1 so it proves when the
        # game is back. See fun_doc.process_port_candidate global_leaf branch.
        if (not include_terminal and func.get("port_status") == "oracle_unavailable"
                and os.environ.get("FUNDOC_LIVE_PROVE") != "1"):
            continue

        # "program" must be the full project path (func["program"], e.g.
        # /Mods/PD2-S12/D2Common.dll), NOT the bare binary name: the PORT
        # worker keys update_function_state with f"{program}::{address}", and
        # only the full path matches fun_doc's state key. Found live
        # 2026-07-07: emitting program_name here made every port_status write
        # upsert a nameless, scoreless skeleton row (D2Common.dll::<addr>)
        # while the real row never advanced past re-selection.
        program = func.get("program") or binary_name
        out.append({
            "key": key,
            "func": func,
            "program": program,
            "binary_priority": _BINARY_PORT_PRIORITY.get(binary_name, 99),
            "caller_count": func.get("caller_count", 0),
            "is_leaf": not func.get("callees"),
        })

    out.sort(key=lambda c: (c["binary_priority"], not c["is_leaf"], -c["caller_count"]))
    return out[:limit] if limit else out


# ---------------------------------------------------------------------------
# Drafting prompts -- Stage 2. Mirrors fun_doc.py's build_full_doc_prompt /
# build_fix_prompt shape: (func_name, address, ..., program) -> str. Kept
# here (not fun_doc.py) since these are port-pipeline-specific and this
# module owns the OpenD2-side conventions (house style, harness contract).
# ---------------------------------------------------------------------------

def _few_shot_style_examples(repo=None, limit=3):
    """Pull existing PROVEN/PORTED functions from the OpenD2 repo as style
    anchors, via conformance_workbench (already scans @PD2S12 markers)."""
    import conformance_workbench as cw
    idx = cw.build_index(repo)
    # Prefer PROVEN examples -- they're validated, not just drafted.
    idx.sort(key=lambda e: e.get("state") != "PROVEN")
    examples = []
    for entry in idx[:limit]:
        code, _ = cw._extract_source_symbol(
            repo or cw.OPEND2_REPO, entry["file"], entry["symbol"], entry.get("line")
        )
        if code:
            examples.append({**entry, "code": code})
    return examples


def build_port_prompt(func_name, address, program, decompiled_text, style_examples=None):
    """Assemble a Stage-2 drafting prompt. Follows the d2-port-function
    skill's Step 5 ("port the ALGORITHM, not the decompiled C... no STL in
    engine/modcode hot paths, bounded fixed arrays, plain C-ish C++") and
    Step 6's harness dispatch contract (see Tools/d2conform/d2conform.cpp's
    run_case for the exact shape the dispatch snippet must match).

    Returns a prompt string. The model must respond with exactly two fenced
    ```cpp blocks: the header-only port, then the draft_runner dispatch
    snippet -- parse_port_response() extracts them mechanically.
    """
    if style_examples is None:
        style_examples = _few_shot_style_examples()

    sections = []
    sections.append("## Task: port a Diablo II function into OpenD2 (Stage 2 of document -> port -> prove)")
    sections.append("")
    sections.append(
        "OUTPUT CONTRACT (read first -- a machine parses your reply, a human never sees it): "
        "reply with EXACTLY THREE fenced code blocks and NOTHING that matters outside them, "
        "in THIS order:\n"
        "  BLOCK 1  ```cpp   -- the ENTIRE header-only port: the function AND every helper it "
        "needs, all in this ONE block (never split code across multiple cpp blocks).\n"
        "  BLOCK 2  ```cpp   -- the single draft_runner dispatch snippet.\n"
        "  BLOCK 3  ```json  -- the vector spec.\n"
        "Tag them literally ```cpp / ```cpp / ```json (NOT ```c++, ```C, or untagged). Produce "
        "exactly two cpp blocks and exactly one json block -- no more, no fewer. If you must think, "
        "do it briefly BEFORE block 1; put nothing between or after the blocks. Getting this shape "
        "wrong wastes the whole attempt.\n"
        "CRITICAL: all three blocks must appear in your FINAL ANSWER message. Anything that exists "
        "only inside your private reasoning/thinking is DISCARDED unread -- drafting the blocks "
        "while thinking and then not restating them in the answer is the #1 wasted attempt. Keep "
        "your reasoning SHORT (a few sentences); spend your output budget on the blocks themselves.")
    sections.append("")
    sections.append(
        "You are drafting an OpenD2 C++ port of a Ghidra-analyzed PD2-S12 function. This draft "
        "will be PROVEN or REJECTED by an automated harness that replays golden vectors minted "
        "from the original binary -- your draft is a hypothesis, not the final word. Port the "
        "ALGORITHM described in the plate comment, not a literal transliteration of the decompiled "
        "pseudocode (decompiler artifacts like Unwind_*/extraout_* are not real behavior)."
    )
    sections.append("")
    sections.append(f"Function: {func_name} at 0x{address}")
    sections.append(f"Program: {program}")
    sections.append("")
    sections.append("## Decompiled source (includes the plate comment -- this IS the spec)")
    sections.append("```")
    sections.append(str(decompiled_text))
    sections.append("```")
    sections.append("")

    if style_examples:
        sections.append("## House style -- existing proven ports (match this exactly)")
        for ex in style_examples:
            sections.append(f"### {ex['file']} :: {ex['symbol']} ({ex.get('state', '?')})")
            sections.append("```cpp")
            sections.append(ex.get("code") or "")
            sections.append("```")
        sections.append("")

    sections.append("## House style rules (OpenD2 Shared/ conventions)")
    sections.append("- Header-only: `#pragma once`, `inline` functions, `namespace D2Lib { ... }`.")
    sections.append("- No STL in hot paths. Plain C-ish C++, bounded fixed arrays (ARM target).")
    sections.append(
        "- Preserve every magic constant, integer width, and overflow/rounding behavior EXACTLY "
        "(e.g. 0x6AC690C5 is the D2 RNG LCG multiplier -- never approximate)."
    )
    sections.append(
        "- Reproduce in-place side effects (e.g. seed-state mutation via a pointer/reference "
        "parameter) -- the harness checks mutated state, not just the return value."
    )
    sections.append(
        "- NEVER call a COMPILER-INTERNAL runtime helper by name. The decompiler shows "
        "`__alldiv`/`__aulldiv`/`__allmul`/`__allrem`/`__allshl`/`__allshr` etc. because MSVC "
        "EMITS those for 64-bit `/ % * << >>` on 32-bit x86 -- they are NOT callable identifiers "
        "(you'll get `error C3861: identifier not found`). Write the plain C++ operator on the "
        "correct fixed-width type instead and let the compiler emit the helper: e.g. a 64-bit "
        "signed divide is `(int32_t)((int64_t)a * (int64_t)b / (int64_t)divisor)`, NOT "
        "`__alldiv(lo, hi, ...)`."
    )
    sections.append("")

    sections.append("## Output format -- exactly three fenced code blocks, nothing else")
    sections.append(
        "1. A ```cpp block: the complete header-only port. Put the function AND all helpers it "
        "needs INSIDE this single block -- do NOT open a second cpp block for helpers.")
    sections.append(
        "2. A ```cpp block: a draft_runner.cpp dispatch snippet in this EXACT shape (see "
        "Tools/d2conform/d2conform.cpp's run_case for the pattern):"
    )
    sections.append("```cpp")
    sections.append('if (fn == "YourPortFunctionName")')
    sections.append("{")
    sections.append('\t// extract typed inputs via in->n("field"), call the port, compare against out->n("field")')
    sections.append('\t// on mismatch: printf("  FAIL [%d] %s(...): expected %d got %d\\n", idx, fn.c_str(), ...); return false;')
    sections.append("\treturn true;")
    sections.append("}")
    sections.append("```")
    sections.append(
        "3. A ```json block describing how to mint golden vectors via ghidra-mcp's static "
        "`/emulate_function` oracle -- YOU must read the plate comment's register mapping "
        "(explicit params + any IMPLICIT register like EAX/ESI/EDX) and propose the exact "
        "layout, since this is D2's non-standard calling convention, not something inferable "
        "mechanically. Shape:"
    )
    sections.append("```json")
    sections.append(json.dumps({
        "fn": "YourPortFunctionName",
        "param_layout": {
            "inputs": [{"name": "example_input", "register": "ECX", "signed": False}],
            "outputs": [{"name": "ret", "register": "EAX", "signed": False}],
        },
        "input_sets": [{"example_input": 0}, {"example_input": 1}],
    }, indent=2))
    sections.append("```")
    sections.append(
        "Cover the edge cases the plate comment/decompile flag: 0, 1, powers of two "
        "(the RNG family has a bitwise-AND fast path vs modulo -- exercise BOTH), and any "
        "documented overflow/underflow guards. Aim for at least 15-20 input_sets, not one sample "
        "-- one matching case is not proof (EMULATION_CONFORMANCE_PLAN.md Sec 8)."
    )
    sections.append("")
    sections.append(
        "Reminder -- the parser is mechanical (parse_port_response_full). These specific mistakes "
        "make your ENTIRE reply unusable, so double-check before you send:\n"
        "  - splitting the port across more than one cpp block (all code goes in block 1);\n"
        "  - tagging a block ```c++ / ```C / ```C++ or leaving it untagged instead of ```cpp;\n"
        "  - tagging the vector spec anything other than ```json, or wrapping it in ```cpp;\n"
        "  - emitting more or fewer than exactly two cpp blocks + one json block;\n"
        "  - trailing prose or a fourth block after the json.\n"
        "Output the three blocks and stop."
    )
    return "\n".join(sections)


def build_port_fix_prompt(func_name, address, program, decompiled_text,
                           prior_header, prior_dispatch, harness_output):
    """Assemble a Stage-2 retry prompt after a harness FAIL. Mirrors
    fun_doc.build_fix_prompt's pattern: feed back the SPECIFIC mismatch, not
    just "try again" (see d2-port-function Step 6: "a single mismatch means
    the port is WRONG... do not weaken a vector to force a pass")."""
    sections = []
    sections.append("## Task: fix a failing OpenD2 port draft (Stage 2 retry)")
    sections.append("")
    sections.append(
        "Your previous draft for this function FAILED the conformance harness. A single mismatch "
        "means the port is WRONG -- re-read the decompilation for an integer-width, sign, rounding, "
        "or missed-side-effect bug. Do NOT change the vectors; they were minted from the real binary. "
        "Never weaken a vector to force a pass."
    )
    sections.append("")
    sections.append(f"Function: {func_name} at 0x{address}")
    sections.append(f"Program: {program}")
    sections.append("")
    sections.append("## Decompiled source (the spec)")
    sections.append("```")
    sections.append(str(decompiled_text))
    sections.append("```")
    sections.append("")
    sections.append("## Your previous header")
    sections.append("```cpp")
    sections.append(prior_header)
    sections.append("```")
    sections.append("")
    sections.append("## Your previous dispatch snippet")
    sections.append("```cpp")
    sections.append(prior_dispatch)
    sections.append("```")
    sections.append("")
    sections.append("## Harness output (the failure -- read it carefully)")
    sections.append("```")
    sections.append(harness_output)
    sections.append("```")
    sections.append("")
    sections.append(
        "## Output format -- exactly TWO fenced ```cpp blocks, nothing that matters outside them: "
        "BLOCK 1 = the full corrected header (function + all helpers in this one block), BLOCK 2 = "
        "the dispatch snippet. Tag both literally ```cpp (never ```c++/```C/untagged). Do NOT emit "
        "a json block on a fix (the vectors are frozen). A machine parses this; wrong shape wastes "
        "the retry."
    )
    return "\n".join(sections)


# Lang tag capture allows `+`/`#`/`.`/`-` so a ```c++ / ```c# fence is captured at
# all (the old `\w*` couldn't match the `+`, silently DROPPING the whole block and
# turning a perfectly good draft into a "malformed_response" -- a real flakiness
# source with models that tag C++ as `c++`). Normalization below maps the whole
# C/C++ family onto "cpp".
_CODE_BLOCK_RE = re.compile(r"```([\w+#.\-]*)[ \t]*\r?\n(.*?)```", re.DOTALL)
_CPP_LANGS = {"", "cpp", "c++", "cxx", "cc", "c", "hpp", "hxx", "hh", "h", "cplusplus"}
_JSON_LANGS = {"json", "jsonc", "json5"}


def _fenced_blocks(response_text):
    """Return [(lang, content), ...] for every fenced code block, in order."""
    return [(lang.lower(), content) for lang, content in _CODE_BLOCK_RE.findall(response_text)]


# The dispatch snippet is structurally unmistakable: it opens with the
# run_case pattern `if (fn == "Name")`. Header code never references `fn`.
# Classifying by CONTENT (instead of demanding an exact block count in an
# exact order) tolerates the failure shapes observed live 2026-07-14:
# extra/iterated blocks (M3 redrafts inside its reasoning), reordered
# blocks, and salvage output where only the final iteration of each block
# survives. Last-of-each-kind wins -- the model's final iteration is its
# actual answer.
_DISPATCH_MARKER_RE = re.compile(r"if\s*\(\s*fn\s*==")

_SPEC_KEYS = ("fn", "param_layout", "input_sets")

# Bare hex integer literals (0xCAFEBABE) rewritten to decimal before
# json.loads: the model habitually puts hex in input_sets even though JSON
# has no hex literals, which made a PERFECTLY-SHAPED 3-block draft score
# malformed_response (2026-07-14: SetLinkedListFieldForAll, all 3 attempts;
# same class the handle lane fixed 2026-07-08 for GetAnimSequenceRecord).
# The lookbehind avoids touching hex inside quoted strings/identifiers.
_HEX_LITERAL_RE = re.compile(r'(?<![\w"])0[xX][0-9a-fA-F]+')


def json_loads_lenient(s):
    """json.loads with bare-hex-literal tolerance. Raises JSONDecodeError
    like json.loads on anything still malformed."""
    return json.loads(_HEX_LITERAL_RE.sub(
        lambda m: str(int(m.group(0), 16)), s or ""))


def _is_json_dict(text):
    try:
        return isinstance(json_loads_lenient(text), dict)
    except (json.JSONDecodeError, TypeError):
        return False


def _classify_cpp_blocks(cpp_blocks):
    """Return (header, dispatch): last non-dispatch block, last dispatch block.
    Blocks that parse as a JSON dict are excluded -- an UNTAGGED vector spec
    lands in the cpp-family bucket (lang "" is in _CPP_LANGS) and must not
    displace the real header as "last non-dispatch block"."""
    code = [b for b in cpp_blocks if not _is_json_dict(b)]
    headers = [b for b in code if not _DISPATCH_MARKER_RE.search(b)]
    dispatches = [b for b in code if _DISPATCH_MARKER_RE.search(b)]
    return (headers[-1] if headers else None,
            dispatches[-1] if dispatches else None)


def _extract_vector_spec(blocks):
    """Last block (any tag -- models mis-tag json as ``` or ```jsonc) that
    parses as JSON with the required spec keys, or None."""
    for _lang, content in reversed(blocks):
        try:
            spec = json_loads_lenient(content)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(spec, dict):
            continue
        if all(k in spec for k in _SPEC_KEYS) and \
                all(k in spec["param_layout"] for k in ("inputs", "outputs")):
            return spec
    return None


def parse_port_response(response_text):
    """Extract (header_content, dispatch_body) from a build_port_fix_prompt
    response. Content-classified: header = last cpp-family block WITHOUT the
    `if (fn ==` dispatch marker, dispatch = last block WITH it. Returns
    (None, None) if either is missing."""
    cpp_blocks = [content for lang, content in _fenced_blocks(response_text) if lang in _CPP_LANGS]
    header, dispatch = _classify_cpp_blocks(cpp_blocks)
    if not header or not dispatch:
        return None, None
    return header.strip() + "\n", dispatch.strip()


def parse_port_response_full(response_text):
    """Extract (header_content, dispatch_body, vector_spec) from a
    build_port_prompt response (```cpp header, ```cpp dispatch, ```json
    vector spec with {fn, param_layout, input_sets}). Blocks are classified
    by content (see _classify_cpp_blocks / _extract_vector_spec), so extra,
    reordered, or mis-tagged blocks no longer sink an otherwise-good draft.
    Returns (None, None, None) if any of the three pieces is missing, so
    callers treat it uniformly as "retry the draft", not a partial success."""
    blocks = _fenced_blocks(response_text)
    cpp_blocks = [content for lang, content in blocks if lang in _CPP_LANGS]
    header, dispatch = _classify_cpp_blocks(cpp_blocks)
    spec = _extract_vector_spec(blocks)
    if not header or not dispatch or spec is None:
        return None, None, None
    return header.strip() + "\n", dispatch.strip(), spec

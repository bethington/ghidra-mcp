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
    """Classify a function as "leaf" (pure/leaf, provable via static
    emulation) or "stateful" (needs a live-trace oracle, out of Phase 1
    scope). Returns "leaf" | "stateful" | "unknown" (fetch failure -- treat
    as stateful, i.e. do not auto-port).

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
    # HARD-stateful signals (not provable statically AND not simply live-resolvable):
    if _DAT_GLOBAL_RE.search(text):
        return "stateful"  # unnamed raw-address global -- not in the name resolver
    if _STRUCT_ACCESS_RE.search(text):
        return "stateful"  # `->` struct navigation
    if _DEEP_DEREF_RE.search(text):
        return "stateful"  # pointer-to-pointer / struct-with-pointers chain

    # Pointer-type check is scoped to where declarations actually appear
    # (signature parameter list + standalone local-decl lines), NOT the
    # whole text -- a whole-text scan can't tell `TYPE *name` (declaration)
    # apart from `a * b` (multiplication); both are "word * word" at the
    # token level. See _extract_signature_params/_POINTER_LOCAL_LINE_RE.
    header, _, body = text.partition("{")
    params_text = _extract_signature_params(header)
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

    # No hard-stateful signal. If the only "state" it touches is a NAMED global
    # (g_*/_g_*), it's provable LIVE via the D2MOO resolver (D2MOO_Resolve gives
    # the real running-game address) -- a distinct class the live-prove path
    # handles, not a static-harness candidate. Otherwise it's a pure leaf.
    if _NAMED_GLOBAL_RE.search(text):
        return "global_leaf"
    return "leaf"


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
            # worker pass, not just this one candidate.
            registers[inp["register"]] = f"0x{_hex_to_int(case[inp['name']]) & 0xFFFFFFFF:x}"
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
            out[outp["name"]] = _hex_to_int(raw, signed_bits=32 if outp.get("signed") else None)
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
        if active_binary and binary_name != active_binary:
            continue

        score = func.get("effective_score", func.get("score", 0)) or 0
        if score < good_enough_score:
            continue  # Stage 1 not finished yet -- not ready for Stage 2

        if not include_terminal and func.get("port_status") in _PORT_TERMINAL_STATUSES:
            continue  # already resolved -- don't re-select (loop must advance)

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
        "wrong wastes the whole attempt.")
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


def parse_port_response(response_text):
    """Extract (header_content, dispatch_body) from a build_port_fix_prompt
    response (2 blocks: header, dispatch -- no vector spec on a retry, since
    vectors must not change once minted). Returns (None, None) if fewer than
    two cpp-family blocks are found."""
    cpp_blocks = [content for lang, content in _fenced_blocks(response_text) if lang in _CPP_LANGS]
    if len(cpp_blocks) < 2:
        return None, None
    return cpp_blocks[0].strip() + "\n", cpp_blocks[1].strip()


def parse_port_response_full(response_text):
    """Extract (header_content, dispatch_body, vector_spec) from a
    build_port_prompt response (3 blocks: ```cpp header, ```cpp dispatch,
    ```json vector spec with {fn, param_layout, input_sets}). Returns
    (None, None, None) on any parse failure -- malformed JSON, missing
    blocks, or a vector spec missing required keys -- so callers treat it
    uniformly as "retry the draft", not a partial success."""
    blocks = _fenced_blocks(response_text)
    cpp_blocks = [content for lang, content in blocks if lang in _CPP_LANGS]
    json_blocks = [content for lang, content in blocks if lang in _JSON_LANGS]
    if len(cpp_blocks) < 2 or not json_blocks:
        return None, None, None
    try:
        spec = json.loads(json_blocks[0])
    except json.JSONDecodeError:
        return None, None, None
    if not all(k in spec for k in ("fn", "param_layout", "input_sets")):
        return None, None, None
    if not all(k in spec["param_layout"] for k in ("inputs", "outputs")):
        return None, None, None
    return cpp_blocks[0].strip() + "\n", cpp_blocks[1].strip(), spec

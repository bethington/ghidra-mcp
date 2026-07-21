"""
Regression tests for fun-doc's port_pipeline.py -- Stage 2/3 ("port" +
"prove") of the OpenD2 conformance pipeline (see OpenD2/docs/
EMULATION_CONFORMANCE_PLAN.md Sec 14).

These exercise only the offline-testable pieces: classify_function's
regex heuristic, select_port_candidates' filtering/sort, and the prompt
build/parse round trip. Fast, pure Python, no network, no Ghidra, no LLM.

mint_vectors/run_harness/write_draft (CMake build + live Ghidra
/emulate_function) and process_port_candidate/run_port_worker_pass (live
LLM calls) are exercised manually against the real OpenD2 repo + Ghidra
instance -- see the port_pipeline module docstring and CLAUDE.md's OpenD2
conformance section for that workflow; they are not practical to run in an
offline unit suite (they shell out to cmake/msbuild and a real HTTP oracle).
"""
import sys
from pathlib import Path

import pytest

# Ensure fun-doc is importable
FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import port_pipeline as pp  # noqa: E402
from fun_doc import _state_func_to_row, _row_to_state_func, _STATE_DIRECT_FIELDS  # noqa: E402


# ---------------------------------------------------------------------------
# classify_function
# ---------------------------------------------------------------------------

class TestClassifyFunction:
    def test_empty_or_error_is_unknown(self):
        assert pp.classify_function(None) == "unknown"
        assert pp.classify_function("") == "unknown"
        assert pp.classify_function("<ghidra fetch failed: timeout>") == "unknown"

    def test_scalar_pointer_param_is_leaf(self):
        # SEED_GetRandomNumberAlt's real shape: a pointer to an 8-byte seed
        # blob the caller owns -- documented exception, not a struct pointer.
        text = """
        uint __fastcall SEED_GetRandomNumberAlt(ulonglong *pSeed)
        {
            ulonglong qwNewSeed;
            if ((int)dwMax < 1) { return 0; }
            qwNewSeed = (ulonglong)(uint)*pSeed * 0x6ac690c5;
            *pSeed = qwNewSeed;
            return (uint)(qwNewSeed & 0xffffffff);
        }
        """
        assert pp.classify_function(text) == "leaf"

    def test_readonly_struct_pointer_getter_is_shadow_leaf(self):
        # A read-only getter over EXACTLY ONE struct pointer -- reads a field,
        # touches no globals, calls no delegate, writes nothing through the
        # pointer -- is the shadow_leaf class: provable LIVE via the oracle
        # handle path (a real captured object passed to orig+reimpl). This is
        # checked BEFORE the `->` stateful guard on purpose (classify_function
        # lines ~328-348); it is the biggest hot-path class and IS provable, so
        # a named-struct-pointer getter must NOT dead-end as "stateful".
        text = """
        int __fastcall CalcDamageBonusByLevel(CalcDamageBonusByLevel_MonsterData *pMonsterData)
        {
            if (pMonsterData->bDamageBonusEnabled != 0) { return 1; }
            return 0;
        }
        """
        assert pp.classify_function(text) == "shadow_leaf"

    def test_struct_pointer_that_writes_is_stateful(self):
        # The shadow_leaf gate REQUIRES read-only (no write through the pointer):
        # handle-proving a mutator would corrupt the live captured game object.
        # A struct pointer that is written through stays "stateful".
        text = """
        void __fastcall SetDamageBonus(CalcDamageBonusByLevel_MonsterData *pMonsterData, int v)
        {
            pMonsterData->bDamageBonusEnabled = v;
        }
        """
        assert pp.classify_function(text) == "stateful"

    def test_global_reference_is_stateful(self):
        text = "int Foo(void) { return DAT_006fd123 + 1; }"
        assert pp.classify_function(text) == "stateful"

    def test_plate_comment_prose_does_not_false_positive(self):
        # Regression: "(SEED_* module)" in an English plate comment aside
        # used to false-match the pointer-param regex ("SEED_" as a type,
        # "module" as the identifier) before comments were stripped first.
        text = """
        /* Get Random Number from Seed
           Source: D2Common.dll (SEED_* module)
        */
        uint __fastcall SEED_GetRandomNumber(ulonglong *pSeedState)
        {
            return (uint)*pSeedState;
        }
        """
        assert pp.classify_function(text) == "leaf"

    def test_no_pointer_params_is_leaf(self):
        text = "int __fastcall D2_ToHitPercent(int AR, int DEF, int aLvl, int dLvl) { return 50; }"
        assert pp.classify_function(text) == "leaf"

    def test_multiplication_expression_does_not_false_positive(self):
        # Regression: "(nMultiplier * in_EAX)" inside a body expression
        # (real COMMON_ScaledMultiplyDivide shape) used to false-match the
        # pointer-param regex ("nMultiplier" read as a pointer TYPE) before
        # the scan was scoped to the signature params + whole-line locals.
        # "TYPE *name" and "a * b" are identical at the token level.
        text = """
        int __fastcall COMMON_ScaledMultiplyDivide(uint dwDivisor,int nMultiplier)
        {
            int in_EAX;
            longlong lVar1;
            if (dwDivisor == 0) { return 0; }
            if (nMultiplier < 0x100001) {
                if (in_EAX < 0x10001) {
                    return (nMultiplier * in_EAX) / (int)dwDivisor;
                }
            }
            return 0;
        }
        """
        assert pp.classify_function(text) == "leaf"

    def test_pointer_local_declaration_line_is_detected(self):
        # A standalone `TYPE *name;` local-decl line (not a param) should
        # still be caught -- e.g. a locally-declared struct-pointer helper.
        text = """
        int Foo(int x)
        {
            SomeStruct *pHelper;
            return x + 1;
        }
        """
        assert pp.classify_function(text) == "stateful"


# ---------------------------------------------------------------------------
# select_port_candidates
# ---------------------------------------------------------------------------

class TestSelectPortCandidates:
    def _funcs(self):
        return {
            "D2Common.dll::100": {
                "program_name": "D2Common.dll", "effective_score": 100,
                "caller_count": 5, "callees": [],
            },
            "D2Common.dll::200_not_done": {
                "program_name": "D2Common.dll", "effective_score": 40,
                "caller_count": 10, "callees": [],
            },
            "D2Game.dll::300": {
                "program_name": "D2Game.dll", "effective_score": 100,
                "caller_count": 3, "callees": ["x"],
            },
            "D2Common.dll::400_thunk": {
                "program_name": "D2Common.dll", "effective_score": 100,
                "caller_count": 1, "callees": [], "is_thunk": True,
            },
            "D2Common.dll::500_lib": {
                "program_name": "D2Common.dll", "effective_score": 100,
                "caller_count": 1, "callees": [], "library_code": True,
            },
        }

    def test_excludes_not_stage1_complete(self):
        cands = pp.select_port_candidates(self._funcs(), set())
        keys = [c["key"] for c in cands]
        assert "D2Common.dll::200_not_done" not in keys

    def test_excludes_thunks_and_library_code(self):
        cands = pp.select_port_candidates(self._funcs(), set())
        keys = [c["key"] for c in cands]
        assert "D2Common.dll::400_thunk" not in keys
        assert "D2Common.dll::500_lib" not in keys

    def test_excludes_conformance_protected(self):
        cands = pp.select_port_candidates(self._funcs(), {"D2Common.dll::100"})
        keys = [c["key"] for c in cands]
        assert "D2Common.dll::100" not in keys

    def test_binary_priority_order(self):
        # D2Common before D2Game (EMULATION_CONFORMANCE_PLAN.md Sec 15)
        cands = pp.select_port_candidates(self._funcs(), set())
        keys = [c["key"] for c in cands]
        assert keys.index("D2Common.dll::100") < keys.index("D2Game.dll::300")

    def test_active_binary_filter(self):
        cands = pp.select_port_candidates(self._funcs(), set(), active_binary="D2Game.dll")
        keys = [c["key"] for c in cands]
        assert keys == ["D2Game.dll::300"]

    def test_limit(self):
        cands = pp.select_port_candidates(self._funcs(), set(), limit=1)
        assert len(cands) == 1


# ---------------------------------------------------------------------------
# Prompt build + parse round trip
# ---------------------------------------------------------------------------

class TestPromptRoundTrip:
    def test_build_port_prompt_shape(self):
        prompt = pp.build_port_prompt(
            "TestFn", "1234", "/Mods/PD2-S12/D2Common.dll",
            "int TestFn(uint x) { return x; }", style_examples=[],
        )
        assert "TestFn" in prompt
        assert "0x1234" in prompt
        assert "three fenced code blocks" in prompt

    def test_parse_port_response_full_round_trip(self):
        response = '''Sure, here it is.
```cpp
#pragma once
namespace D2Lib { inline int TestFn(unsigned int x) { return (int)x; } }
```
```cpp
if (fn == "TestFn") { return (int)D2Lib::TestFn((unsigned int)in->n("x")) == (int)out->n("ret"); }
```
```json
{"fn": "TestFn", "param_layout": {"inputs": [{"name": "x", "register": "ECX"}], "outputs": [{"name": "ret", "register": "EAX"}]}, "input_sets": [{"x": 0}, {"x": 1}]}
```
'''
        header, dispatch, spec = pp.parse_port_response_full(response)
        assert header is not None and "namespace D2Lib" in header
        assert dispatch is not None and "TestFn" in dispatch
        assert spec["fn"] == "TestFn"
        assert spec["input_sets"] == [{"x": 0}, {"x": 1}]

    def test_parse_port_response_full_rejects_missing_json_block(self):
        response = "```cpp\nheader\n```\n```cpp\ndispatch\n```"
        header, dispatch, spec = pp.parse_port_response_full(response)
        assert (header, dispatch, spec) == (None, None, None)

    def test_parse_port_response_full_rejects_malformed_json(self):
        response = '```cpp\nheader\n```\n```cpp\ndispatch\n```\n```json\nnot json{{{\n```'
        header, dispatch, spec = pp.parse_port_response_full(response)
        assert (header, dispatch, spec) == (None, None, None)

    def test_parse_port_response_full_rejects_missing_required_keys(self):
        response = (
            '```cpp\nheader\n```\n```cpp\ndispatch\n```\n'
            '```json\n{"fn": "X"}\n```'
        )
        header, dispatch, spec = pp.parse_port_response_full(response)
        assert (header, dispatch, spec) == (None, None, None)

    def test_parse_port_response_two_block_retry(self):
        # Blocks are content-classified, not positional: the dispatch block
        # is recognized by its `if (fn ==` marker, the header is the last
        # cpp-family block without it.
        response = (
            "```cpp\nheader content\n```\n"
            '```cpp\nif (fn == "target_fn") { return run(); }\n```'
        )
        header, dispatch = pp.parse_port_response(response)
        assert header.strip() == "header content"
        assert dispatch.strip() == 'if (fn == "target_fn") { return run(); }'

    def test_parse_port_response_reordered_blocks(self):
        """Dispatch-first ordering must still classify correctly — the whole
        point of content classification over positional parsing."""
        response = (
            '```cpp\nif (fn == "target_fn") { return run(); }\n```\n'
            "```cpp\nheader content\n```"
        )
        header, dispatch = pp.parse_port_response(response)
        assert header.strip() == "header content"
        assert dispatch.strip() == 'if (fn == "target_fn") { return run(); }'

    def test_parse_port_response_needs_two_blocks(self):
        header, dispatch = pp.parse_port_response("```cpp\njust one\n```")
        assert (header, dispatch) == (None, None)


class TestPascalToSnakeCase:
    def test_mixed_acronym_and_camel_case(self):
        # Regression: naively inserting "_" before every capital produced
        # "c_o_m_m_o_n__scaled_multiply_divide" for this exact real D2
        # symbol (confirmed live) -- ALL_CAPS module-prefix runs must stay
        # intact; only a lowercase/digit -> uppercase boundary is a real
        # camelCase hump.
        assert pp.pascal_to_snake_case("COMMON_ScaledMultiplyDivide") == "common_scaled_multiply_divide"

    def test_plain_camel_case(self):
        assert pp.pascal_to_snake_case("ScaledMultiplyDivide") == "scaled_multiply_divide"

    def test_all_caps_stays_intact(self):
        assert pp.pascal_to_snake_case("SEED_GetRandomNumberAlt") == "seed_get_random_number_alt"


# ---------------------------------------------------------------------------
# port_status persistence round trip (fun_doc.py, not port_pipeline.py).
#
# Regression: repository.py's _UPDATABLE_WORKFLOW_FIELDS is NOT the only
# allowlist a partial update passes through. fun_doc._state_func_to_row runs
# FIRST (state.json-dict -> workflow-row-dict) and is gated by a SEPARATE
# allowlist, _STATE_DIRECT_FIELDS -- a field missing from the SECOND gate
# gets silently dropped before repository.py's gate ever sees it. Confirmed
# live: update_function_state(key, {"port_status": ...}) returned
# successfully (no exception) but the write never reached the database,
# because _STATE_DIRECT_FIELDS didn't list the port_* fields yet. Both
# allowlists must be kept in sync for any new pass-through field.
# ---------------------------------------------------------------------------

class TestPortStatusPersistenceRoundTrip:
    def test_port_fields_are_in_state_direct_fields(self):
        for field in ("port_status", "port_attempts", "port_draft_path", "port_last_result"):
            assert field in _STATE_DIRECT_FIELDS, (
                f"{field!r} missing from _STATE_DIRECT_FIELDS -- a partial "
                "update_function_state() call setting only this field would "
                "silently no-op (see _state_func_to_row)"
            )

    def test_state_func_to_row_carries_port_fields(self):
        rec = {
            "program": "/Mods/PD2-S12/D2Common.dll",
            "address": "6fd511e0",
            "port_status": "proven_pending_review",
            "port_attempts": 1,
            "port_draft_path": "/some/path.hpp",
            "port_last_result": "20/20 passed",
        }
        row = _state_func_to_row("/Mods/PD2-S12/D2Common.dll::6fd511e0", rec)
        assert row["port_status"] == "proven_pending_review"
        assert row["port_attempts"] == 1
        assert row["port_draft_path"] == "/some/path.hpp"
        assert row["port_last_result"] == "20/20 passed"

    def test_row_to_state_func_round_trips_port_fields(self):
        row = {
            "program_path": "/Mods/PD2-S12/D2Common.dll",
            "binary_name": "D2Common.dll",
            "address": "6fd511e0",
            "port_status": "harness_failed",
            "port_attempts": 3,
            "port_draft_path": "/some/path.hpp",
            "port_last_result": "18/20 passed",
        }
        rec = _row_to_state_func(row)
        assert rec["port_status"] == "harness_failed"
        assert rec["port_attempts"] == 3
        assert rec["port_draft_path"] == "/some/path.hpp"
        assert rec["port_last_result"] == "18/20 passed"


# ---------------------------------------------------------------------------
# write_draft template rendering (no build -- just checks the .format()
# escaping is correct, which is easy to get wrong with braces in embedded
# C++ source; see the module's _DRAFT_RUNNER_TEMPLATE).
# ---------------------------------------------------------------------------

class TestWriteDraftTemplate:
    def test_template_renders_without_stray_braces(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pp, "GENERATED_CANDIDATES_DIR", tmp_path)
        monkeypatch.setattr(pp, "DRAFT_RUNNER_PATH", tmp_path / "draft_runner.cpp")
        monkeypatch.setattr(pp, "DRAFT_VECTORS_PATH", tmp_path / "draft_vectors.json")

        paths = pp.write_draft(
            "Test", "Fn",
            "#pragma once\nnamespace D2Lib { inline int Fn() { return 1; } }\n",
            'if (fn == "Fn") { return true; }',
            [{"fn": "Fn", "in": {}, "out": {"ret": 1}}],
        )
        runner_text = Path(paths["runner_path"]).read_text(encoding="utf-8")
        # The JSON-parser struct bodies must survive with real braces (not
        # left as literal "{{"/"}}" from an unescaped .format() call).
        assert "{{" not in runner_text
        assert "}}" not in runner_text
        assert "struct JVal" in runner_text
        assert '#include "Test_Fn.hpp"' in runner_text
        assert 'if (fn == "Fn")' in runner_text

        header_text = Path(paths["header_path"]).read_text(encoding="utf-8")
        assert "namespace D2Lib" in header_text

        vectors_text = Path(paths["vectors_path"]).read_text(encoding="utf-8")
        assert '"Fn"' in vectors_text


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

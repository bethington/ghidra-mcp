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
import json
import sys
from pathlib import Path

import pytest

# Ensure fun-doc is importable
FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import port_pipeline as pp  # noqa: E402
from fun_doc import (  # noqa: E402
    _state_func_to_row, _row_to_state_func, _STATE_DIRECT_FIELDS,
    _void_return_needs_hard_skip, _class_b_outbuf_eligible, _model_declined_outbuf,
)


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

    def test_struct_pointer_that_writes_is_never_shadow_leaf(self):
        # The shadow_leaf gate REQUIRES read-only (no write through the pointer):
        # handle-proving a mutator would corrupt the live captured game object.
        # That safety property is unchanged and is what this test guards.
        #
        # The VERDICT changed on 2026-07-30 (was: "stateful"). This shape is now
        # mutator_leaf -- provable against a fresh SYNTHETIC object rather than a
        # live captured one, so the corruption hazard above simply does not
        # apply to its route. The invariant that matters is that it must never
        # reach the handle path, so assert that directly instead of asserting the
        # old "unprovable" verdict, which was only ever true because the synth
        # route did not exist yet.
        text = """
        void __fastcall SetDamageBonus(CalcDamageBonusByLevel_MonsterData *pMonsterData, int v)
        {
            pMonsterData->bDamageBonusEnabled = v;
        }
        """
        assert pp.classify_function(text) != "shadow_leaf"
        assert pp.classify_function(text) == "mutator_leaf"

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
# process_port_candidate's routing gates (fun_doc.py)
#
# 2026-07-28: these three gates decide whether a stateful-classified,
# void-return, or pointer-writing function reaches Class B out-param/buffer
# proving or gets terminally stateful_skip'd. Extracted from
# process_port_candidate/process_global_leaf_live specifically so this
# safety-relevant routing logic is unit-testable without a live LLM/Ghidra
# (process_port_candidate itself is manual-only -- see this file's module
# docstring). See fun_doc.py's docstrings on each function for the full
# incident history (STAT_ImportStateFlagsFromBuffer's wild frees, the
# MONSTER_GetInvGridSize read+write hybrid) that shaped these gates.
# ---------------------------------------------------------------------------

class TestVoidReturnNeedsHardSkip:
    def test_void_with_delegate_call_is_hard_skipped(self):
        assert _void_return_needs_hard_skip(True, True) is True

    def test_void_with_bare_pointer_deref_no_longer_hard_skipped(self):
        """The 2026-07-28 loosening: a plain '->' with no call at all now
        reaches classification instead of being pre-LLM skipped."""
        assert _void_return_needs_hard_skip(True, False) is False

    def test_non_void_never_hard_skipped(self):
        assert _void_return_needs_hard_skip(False, True) is False
        assert _void_return_needs_hard_skip(False, False) is False


class TestClassBOutbufEligible:
    def test_ptr_write_with_live_prove_is_eligible(self):
        assert _class_b_outbuf_eligible("ptr_write", True) is True

    def test_ptr_write_without_live_prove_is_not_eligible(self):
        """Class B still needs the live oracle -- FUNDOC_LIVE_PROVE gates
        this route exactly like every other live-prove path."""
        assert _class_b_outbuf_eligible("ptr_write", False) is False

    def test_other_skip_reasons_are_not_eligible(self):
        for reason in ("delegate_call", "global_plus_ptr", "dat_global", "other"):
            assert _class_b_outbuf_eligible(reason, True) is False


class TestModelDeclinedOutbuf:
    def test_bare_unsupported_reply(self):
        assert _model_declined_outbuf("UNSUPPORTED") is True

    def test_lowercase_and_whitespace_tolerant(self):
        assert _model_declined_outbuf("  unsupported  \n") is True

    def test_trailing_period_tolerant(self):
        assert _model_declined_outbuf("UNSUPPORTED.") is True

    def test_real_draft_is_not_a_decline(self):
        assert _model_declined_outbuf("```cpp\nvoid Foo() {}\n```") is False

    def test_explanatory_prose_is_not_a_bare_decline(self):
        # The prompt asks for the single word UNSUPPORTED; extra prose means
        # parse_live_response's own retry path handles it, not this fast path.
        assert _model_declined_outbuf(
            "UNSUPPORTED because this reads meaningful data") is False

    def test_empty_or_none_is_not_a_decline(self):
        assert _model_declined_outbuf("") is False
        assert _model_declined_outbuf(None) is False


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


class TestPendingVectorsNamespacing:
    """Regression: pending-vector staging files are keyed by BINARY + function,
    not function alone. Before 2026-07-30 `shutdown_stub_no_op.json` merged 101
    vectors from five DLLs under one `fn` key -- five distinct compiled
    functions that merely share a stub name."""

    def _vec(self, fn, program, ret):
        return [{"fn": fn, "in": {}, "out": {"ret": ret},
                 "note": f"PD2-S12; src {program} 0x1000"}]

    def test_stem_is_namespaced_by_module(self):
        assert pp.pending_vectors_stem("Fog", "shutdown_stub_no_op") == \
            "Fog_shutdown_stub_no_op"

    def test_same_function_name_in_two_binaries_does_not_merge(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pp, "PENDING_VECTORS_DIR", tmp_path)

        fog = pp.write_pending_vectors(
            "Fog", "shutdown_stub_no_op",
            self._vec("ShutdownStubNoOp", "/Mods/PD2-S12/Fog.dll", 0))
        storm = pp.write_pending_vectors(
            "Storm", "shutdown_stub_no_op",
            self._vec("ShutdownStubNoOp", "/Mods/PD2-S12/Storm.dll", 7))

        assert fog != storm
        assert fog.name == "Fog_shutdown_stub_no_op.json"
        assert storm.name == "Storm_shutdown_stub_no_op.json"

        # Each file holds ONLY its own binary's vector -- the whole point.
        fog_data = json.loads(fog.read_text(encoding="utf-8"))
        storm_data = json.loads(storm.read_text(encoding="utf-8"))
        assert len(fog_data) == 1 and fog_data[0]["out"]["ret"] == 0
        assert len(storm_data) == 1 and storm_data[0]["out"]["ret"] == 7

    def test_same_binary_appends_rather_than_replaces(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pp, "PENDING_VECTORS_DIR", tmp_path)
        for ret in (1, 2, 3):
            path = pp.write_pending_vectors(
                "Fog", "some_fn", self._vec("SomeFn", "/Mods/PD2-S12/Fog.dll", ret))
        assert [e["out"]["ret"] for e in json.loads(path.read_text(encoding="utf-8"))] == [1, 2, 3]

    def test_concurrent_appends_do_not_lose_entries(self, tmp_path, monkeypatch):
        """The read-modify-write was unguarded; concurrent stagers dropped
        entries. _interprocess_lock must serialize them."""
        import threading

        monkeypatch.setattr(pp, "PENDING_VECTORS_DIR", tmp_path)
        errors = []

        def stage(i):
            try:
                pp.write_pending_vectors(
                    "Fog", "race_fn",
                    self._vec("RaceFn", "/Mods/PD2-S12/Fog.dll", i))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=stage, args=(i,)) for i in range(24)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert not errors, errors
        data = json.loads((tmp_path / "Fog_race_fn.json").read_text(encoding="utf-8"))
        assert len(data) == 24, f"lost updates: kept {len(data)}/24"
        assert sorted(e["out"]["ret"] for e in data) == list(range(24))

    def test_corrupt_existing_file_does_not_lose_the_new_vector(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pp, "PENDING_VECTORS_DIR", tmp_path)
        (tmp_path / "Fog_broken.json").write_text("{not json", encoding="utf-8")
        path = pp.write_pending_vectors(
            "Fog", "broken", self._vec("Broken", "/Mods/PD2-S12/Fog.dll", 5))
        assert len(json.loads(path.read_text(encoding="utf-8"))) == 1


class TestMigratePendingVectors:
    """The one-shot splitter for files staged before the namespacing fix."""

    @staticmethod
    def _mig():
        sys.path.insert(0, str(FUN_DOC / "scripts"))
        import migrate_pending_vectors as m
        return m

    def _entry(self, fn, program):
        return {"fn": fn, "in": {}, "out": {"ret": 0},
                "note": f"PD2-S12; src {program} 0x1000"}

    def test_module_of_normalizes_both_spellings(self):
        m = self._mig()
        assert m.module_of(self._entry("F", "/Mods/PD2-S12/D2Common.dll")) == "D2Common"
        assert m.module_of(self._entry("F", "D2Common.dll")) == "D2Common"
        assert m.module_of({"fn": "F", "note": "no source here"}) is None

    def test_splits_multi_binary_file_by_source(self, tmp_path, capsys):
        m = self._mig()
        (tmp_path / "shutdown_stub_no_op.json").write_text(json.dumps([
            self._entry("ShutdownStubNoOp", "/Mods/PD2-S12/Fog.dll"),
            self._entry("ShutdownStubNoOp", "/Mods/PD2-S12/Storm.dll"),
            self._entry("ShutdownStubNoOp", "/Mods/PD2-S12/Fog.dll"),
        ]), encoding="utf-8")

        assert m.main(["--apply", "--pending-dir", str(tmp_path)]) == 0

        fog = json.loads((tmp_path / "Fog_shutdown_stub_no_op.json").read_text(encoding="utf-8"))
        storm = json.loads((tmp_path / "Storm_shutdown_stub_no_op.json").read_text(encoding="utf-8"))
        assert len(fog) == 2 and len(storm) == 1
        # original archived, not destroyed
        assert (tmp_path / "_premigration" / "shutdown_stub_no_op.json").exists()
        assert not (tmp_path / "shutdown_stub_no_op.json").exists()

    def test_unattributed_entries_are_never_dropped(self, tmp_path):
        m = self._mig()
        (tmp_path / "mystery.json").write_text(json.dumps([
            self._entry("Fn", "/Mods/PD2-S12/Fog.dll"),
            {"fn": "Fn", "in": {}, "out": {"ret": 1}},  # no note at all
        ]), encoding="utf-8")

        assert m.main(["--apply", "--pending-dir", str(tmp_path)]) == 0
        assert len(json.loads((tmp_path / "Fog_mystery.json").read_text(encoding="utf-8"))) == 1
        assert len(json.loads(
            (tmp_path / "mystery_unattributed.json").read_text(encoding="utf-8"))) == 1

    def test_is_idempotent(self, tmp_path):
        m = self._mig()
        (tmp_path / "stub.json").write_text(json.dumps([
            self._entry("Stub", "/Mods/PD2-S12/Fog.dll"),
        ]), encoding="utf-8")

        assert m.main(["--apply", "--pending-dir", str(tmp_path)]) == 0
        first = (tmp_path / "Fog_stub.json").read_text(encoding="utf-8")
        # Second pass must not produce Fog_Fog_stub.json nor duplicate entries.
        assert m.main(["--apply", "--pending-dir", str(tmp_path)]) == 0
        assert not (tmp_path / "Fog_Fog_stub.json").exists()
        assert (tmp_path / "Fog_stub.json").read_text(encoding="utf-8") == first

    def test_dry_run_writes_nothing(self, tmp_path):
        m = self._mig()
        src = tmp_path / "stub.json"
        src.write_text(json.dumps([self._entry("Stub", "/Mods/PD2-S12/Fog.dll")]),
                       encoding="utf-8")
        before = src.read_text(encoding="utf-8")

        assert m.main(["--pending-dir", str(tmp_path)]) == 0
        assert src.read_text(encoding="utf-8") == before
        assert not (tmp_path / "Fog_stub.json").exists()
        assert not (tmp_path / "_premigration").exists()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


# ---------------------------------------------------------------------------
# mutator_leaf (2026-07-30, state-diff capability)
#
# The mirror of shadow_leaf: same shape, but WRITES through the pointer. Proved
# against a fresh synthetic object per call and judged on the bytes left behind,
# which only became possible once the oracle's buffer readback was widened from
# 8 bytes to the full region.
#
# The two gates that look like style but are SAFETY:
#   - no delegate call  (a callee handed a synth pointer can free/walk it and
#     take the game down -- the documented void-return-guard crash mechanism)
#   - no deep deref     (synth bytes are not valid pointers)
# ---------------------------------------------------------------------------

def _mut(body, params="int *pOut, int nVal"):
    return "void __fastcall FN(%s)\n{\n%s\n}\n" % (params, body)


def test_mutator_leaf_basic_pointer_writer():
    assert pp.classify_function(
        _mut("  pOut->field = nVal;\n  pOut->other = 1;")) == "mutator_leaf"


def test_mutator_leaf_allows_multiple_pointer_params():
    """The oracle takes up to 8 arg slots and each can be its own synth buffer,
    so an N-pointer mutator is no harder to isolate than a 1-pointer one.
    Mirroring shadow_leaf's one-pointer gate matched 0 of 19 real mutators."""
    assert pp.classify_function(
        _mut("  pOut->a = nVal;\n  pB->b = nVal;", "int *pOut, int *pB, int nVal")
    ) == "mutator_leaf"


def test_mutator_leaf_allows_named_globals():
    """A named global is reachable via D2MOO_Resolve at runtime, exactly as in
    global_leaf, so both sides read the same live global."""
    assert pp.classify_function(
        _mut("  pOut->field = g_dwSomething;")) == "mutator_leaf"


def test_mutator_leaf_rejects_unnamed_dat_global():
    """DAT_<addr> has no resolver name -- genuinely unprovable."""
    assert pp.classify_function(
        _mut("  pOut->field = DAT_6fbc1234;")) != "mutator_leaf"


def test_mutator_leaf_rejects_delegate_call_SAFETY():
    """A callee handed a synth pointer can free or walk it in-process. This is
    the crash mechanism behind the whole void-return guard -- never relax it."""
    assert pp.classify_function(
        _mut("  pOut->field = nVal;\n  SomeOtherFunction(pOut);")) != "mutator_leaf"


def test_mutator_leaf_rejects_deep_deref_SAFETY():
    """synth fills the object with byte[o]=(o*13+0x37); those are not valid
    pointers, so writing THROUGH one loaded from the object faults the oracle."""
    assert pp.classify_function(
        _mut("  pOut->inner->field = nVal;")) != "mutator_leaf"


def test_read_only_getter_still_shadow_leaf_not_mutator():
    """The no-write gate on shadow_leaf must keep winning for pure readers --
    handle-proving a mutator would corrupt the real captured game object."""
    assert pp.classify_function(
        "int __fastcall FN(int *pUnit)\n{\n  return pUnit->field;\n}\n") == "shadow_leaf"


def test_mutator_leaf_rejects_pointer_field_index_SAFETY():
    """`p->a[i]` is a pointer-field index and an array-member index at the same
    time in decompiled C. Over-refuse: a wrong refusal costs one unproven
    function, a wrong acceptance faults the oracle and takes the game down."""
    assert pp.classify_function(
        _mut("  pOut->buf[2] = nVal;")) != "mutator_leaf"


def test_mutator_leaf_rejects_deref_of_loaded_pointer_SAFETY():
    assert pp.classify_function(
        _mut("  *pOut->target = nVal;")) != "mutator_leaf"


# ---------------------------------------------------------------------------
# Non-terminal routing for environment/capability refusals (2026-07-30).
#
# The recurring bug this whole area keeps hitting: a verdict about the
# ENVIRONMENT (provider down, oracle down, capability not deployed) recorded as
# a TERMINAL verdict about the FUNCTION. Each occurrence silently retired
# functions that were never actually unprovable.
# ---------------------------------------------------------------------------

def test_capability_pending_is_not_terminal():
    assert "capability_pending" not in pp._PORT_TERMINAL_STATUSES


def test_capability_pending_excluded_while_capability_is_off(monkeypatch):
    """Excluded while the flag is off, or it churns the same functions every
    pass -- but never retired."""
    monkeypatch.delenv("FUNDOC_MUTATOR_LEAF", raising=False)
    funcs = {"p::a": {"address": "a", "name": "Pending", "program": "p",
                      "program_name": "D2Client.dll", "effective_score": 95,
                      "port_status": "capability_pending"}}
    assert port_pipeline_select(funcs) == []


def test_capability_pending_readmitted_when_capability_turns_on(monkeypatch):
    monkeypatch.setenv("FUNDOC_MUTATOR_LEAF", "1")
    funcs = {"p::a": {"address": "a", "name": "Pending", "program": "p",
                      "program_name": "D2Client.dll", "effective_score": 95,
                      "port_status": "capability_pending"}}
    assert [c["func"]["name"] for c in port_pipeline_select(funcs)] == ["Pending"]


def port_pipeline_select(funcs):
    return pp.select_port_candidates(funcs, set(), limit=10)


# --- delegation to unproven callees -----------------------------------------
# MEASURED 2026-08-05 on SGD2FreeRes. `sgd2fr::patches::Patches::Apply` -- the
# function that installs every patch the mod applies -- classified `leaf` on a
# body that is four calls and nothing else. It has no DAT_ global, no `->`, no
# struct-typed pointer, so it cleared every hard-stateful guard and fell through
# to "Otherwise -> leaf".
#
# `leaf` means "provable via the static /emulate_function harness", and a
# class-A shadow dispatcher runs the reimpl IN ADDITION TO the original -- so
# proving this one that way applies every patch a SECOND time.
#
# The rule already existed and was only wired to one class: `_callee_is_pure`
# states "a body that was not supplied cannot be shown pure and returns False --
# unproven is treated as unsafe", but `_all_callees_pure` was consulted only on
# the outbuf_leaf path. The plain-leaf fallthrough had no rule about calls.

_DELEGATING_BODY = """void __fastcall FUN_100059e0(int param_1)
{
  FUN_10010ba0(param_1);
  FUN_10010bd0(param_1 + 0x30);
  FUN_10010bf0(param_1 + 0x54);
  FUN_10010c20(param_1 + 0x90);
  return;
}"""

_PURE_CALLEES = {n: f"int {n}(int a) {{ return a + 1; }}"
                 for n in ("FUN_10010ba0", "FUN_10010bd0",
                           "FUN_10010bf0", "FUN_10010c20")}


def test_delegation_to_unknown_callees_is_not_a_leaf():
    """The measured case: a clean-looking body that does all its work elsewhere."""
    assert pp.classify_function(_DELEGATING_BODY) == "stateful"


def test_provable_purity_still_reaches_leaf():
    """Failing closed must not mean refusing everything -- supply the bodies and
    the verdict is earned rather than assumed."""
    assert pp.classify_function(
        _DELEGATING_BODY, callee_bodies=_PURE_CALLEES) == "leaf"


def test_one_dirty_callee_disqualifies_the_caller():
    dirty = dict(_PURE_CALLEES)
    dirty["FUN_10010bf0"] = "int FUN_10010bf0(int a) { DAT_10099000 = a; return a; }"
    assert pp.classify_function(
        _DELEGATING_BODY, callee_bodies=dirty) == "stateful"


def test_a_missing_callee_body_is_unproven_not_pure():
    """Three of four supplied is not three-quarters safe."""
    partial = {k: v for k, v in list(_PURE_CALLEES.items())[:3]}
    assert pp.classify_function(
        _DELEGATING_BODY, callee_bodies=partial) == "stateful"


def test_a_genuinely_callless_body_is_unaffected():
    """The guard must not sweep up real leaves -- this is the class the static
    harness exists for."""
    body = "int FUN_1000(int a, int b) { return (a * 3 + b) & 0xff; }"
    assert pp.classify_function(body) == "leaf"


# --- callee-body supply -----------------------------------------------------
# MEASURED 2026-08-05/06. Nothing in the codebase ever passed `callee_bodies`:
# all three production call sites called classify_function(text) with it None.
# Two consequences, both silent:
#   * `outbuf_leaf` was UNREACHABLE -- its gate needs _has_delegate_call AND
#     _all_callees_pure, and with no bodies those can never both hold, so a
#     class written and tested for delegate-calling mutators never once fired.
#   * The plain-leaf fallthrough had no call rule, so Patches::Apply was a leaf.

class _FakeGhidra:
    """Bulk /decompile_function stand-in. Per-name failures come back as STRING
    VALUES inside a 200 response, which is how the real endpoint behaves."""

    def __init__(self, bodies):
        self.bodies = bodies
        self.calls = 0

    def __call__(self, endpoint, params=None, timeout=15):
        import json as _json
        self.calls += 1
        wanted = (params or {}).get("functions", "").split(",")
        return _json.dumps({n: self.bodies.get(n, "Error: Function not found")
                            for n in wanted if n})


def test_fetch_walks_the_transitive_closure():
    g = _FakeGhidra({"a": "int a(int x){ return b(x); }", "b": "int b(int x){ return x+1; }"})
    bodies, complete = pp.fetch_callee_bodies("int f(int x){ return a(x); }", "P", getter=g)
    assert complete and set(bodies) == {"a", "b"}


def test_a_functions_own_name_is_not_a_callee():
    """The name sits in the signature line, so passing the FULL decompilation
    makes every function appear to call itself and the closure never closes."""
    g = _FakeGhidra({})
    bodies, complete = pp.fetch_callee_bodies("undefined4 FUN_10003eb0(void)\n{\n  return 1;\n}",
                                              "P", getter=g)
    assert complete and bodies == {} and g.calls == 0


def test_an_error_string_is_unreadable_not_a_body():
    """{"thunk_X": "Error: Function not found"} arrives inside a 200. Stored as
    a body it would be analysed for purity, find no brace, and report the
    caller STATEFUL -- when the truth is that we could not read it."""
    g = _FakeGhidra({})
    bodies, complete = pp.fetch_callee_bodies("int f(int x){ return thunk_X(x); }", "P", getter=g)
    assert not complete and bodies == {}


def test_unreadable_callees_abstain_rather_than_accuse():
    g = _FakeGhidra({})
    assert pp.classify_function_live("int f(int x){ return mystery(x); }", "P", getter=g) == "unknown"


def test_a_callless_function_needs_no_fetch():
    g = _FakeGhidra({})
    assert pp.classify_function_live("int f(int a){ return a+1; }", "P", getter=g) == "leaf"
    assert g.calls == 0


# --- static vs live purity --------------------------------------------------
# A std::vector subscript reaches the allocator, which reaches the OS: measured,
# sgd2fr::GetMinConfigResolutionId is 20 lines with a 55-body closure bottoming
# out in malloc/free/_CxxThrowException. Requiring transitive purity through
# that chain clears no STL-using C++ function at all.

_ALLOCATING = "int f(int n){ return helper(n); }"
_HELPER = {"helper": "int helper(int n){ void* p = malloc(n); free(p); return n; }"}


def test_allocation_is_fatal_on_the_static_path():
    """The P-code emulator has no heap: a malloc is not a tolerated effect, it
    is a call that cannot execute."""
    g = _FakeGhidra(_HELPER)
    assert pp.classify_function_live(_ALLOCATING, "P", getter=g, live=False) == "stateful"


def test_allocation_is_invisible_to_a_live_comparison():
    """Both implementations allocate their OWN memory, and the comparison
    observes a return value or an out-buffer -- never the heap."""
    g = _FakeGhidra(_HELPER)
    assert pp.classify_function_live(_ALLOCATING, "P", getter=g, live=True) == "leaf"


def test_live_mode_does_not_forgive_observable_state():
    """The relaxation is scoped to effects the comparison cannot see. A global
    write stays disqualifying in BOTH modes."""
    g = _FakeGhidra({"helper": "int helper(int n){ DAT_10099000 = n; return n; }"})
    for live in (False, True):
        assert pp.classify_function_live(_ALLOCATING, "P", getter=g, live=live) == "stateful"

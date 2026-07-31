"""
Regression tests for fun-doc's port_live_prove.py duplicate-symbol attribution
(added 2026-07-25 after a real LNK2005 collision between candidates/GetByte0x94.cpp
and candidates/unit_field_getters.cpp silently poisoned the shared D2MOO_ReimplProvider
build for 16+ consecutive prove attempts across unrelated functions, each logged as an
opaque, unattributed "build_provider" failure).

Exercises only the offline-testable pure-Python pieces: the LNK2005 regex, the
attribution helper (with CANDIDATES_DIR monkeypatched to a tmp dir), and
quarantine_candidate's move-not-delete behavior. build_provider_attributed itself
shells out to cmake/msbuild against a real D2MOO checkout and is not practical to
run in an offline unit suite -- see the module docstring.
"""
import json
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import port_live_prove as plp  # noqa: E402


LNK2005_OUTPUT = (
    r"  unit_field_getters.obj : error LNK2005: _GetByte0x94@4 already defined "
    r"in GetByte0x94.obj [C:\build\D2MOO_ReimplProvider.vcxproj]" "\n"
    r"  D2MOO_ReimplProvider.vcxproj -> error LNK1169: one or more multiply "
    r"defined symbols found"
)


class TestDupSymbolRegex:
    def test_matches_typical_msbuild_line(self):
        m = plp._DUP_SYMBOL_RE.search(LNK2005_OUTPUT)
        assert m is not None
        assert m.groups() == ("unit_field_getters", "_GetByte0x94@4", "GetByte0x94")

    def test_no_match_on_compile_error(self):
        out = r"candidates\Foo.cpp(12,3): error C2065: 'x': undeclared identifier"
        assert plp._DUP_SYMBOL_RE.search(out) is None


class TestClassifyProveFailureLnk:
    def test_lnk_error_classified_as_build_provider(self):
        stage, detail = plp._classify_prove_failure(LNK2005_OUTPUT)
        assert stage == "build_provider"
        assert "LNK2005" in detail

    def test_compile_error_still_classified_as_build_provider(self):
        stage, _ = plp._classify_prove_failure("fatal error C1083: cannot open file")
        assert stage == "build_provider"

    def test_mismatch_still_detected(self):
        stage, _ = plp._classify_prove_failure("vector 3: DIVERGED original=1 reimpl=2")
        assert stage == "mismatch"


@pytest.fixture
def fake_candidates(tmp_path, monkeypatch):
    """Point CANDIDATES_DIR at a scratch dir with two colliding candidate files,
    mirroring the real GetByte0x94/unit_field_getters collision."""
    d = tmp_path / "candidates"
    d.mkdir()
    (d / "GetByte0x94.cpp").write_text("// D2MOO_REIMPL_EXPORT: GetByte0x94\n")
    (d / "unit_field_getters.cpp").write_text("// D2MOO_REIMPL_EXPORT: GetByte0x94\n")
    (d / "ValidateSkillId.cpp").write_text("// D2MOO_REIMPL_EXPORT: ValidateSkillId\n")
    monkeypatch.setattr(plp, "CANDIDATES_DIR", d)
    monkeypatch.setattr(plp, "QUARANTINE_DIR", d / "_quarantine")
    return d


class TestFindDuplicateSymbolOffender:
    def test_unrelated_current_name_is_not_auto_healed(self, fake_candidates):
        # Mirrors the real 2026-07-25 incident: neither colliding file is the
        # candidate currently being proved -- no correctness basis to delete
        # either one automatically, so it must surface distinctly, not quietly.
        result = plp._find_duplicate_symbol_offender(LNK2005_OUTPUT, "ValidateSkillId")
        assert result is not None
        stage, detail, quarantine_name = result
        assert stage == "build_provider_duplicate_symbol"
        assert quarantine_name is None
        assert "GetByte0x94.cpp" in detail and "unit_field_getters.cpp" in detail

    def test_own_fresh_draft_is_the_redefinition(self, fake_candidates):
        # current_name IS the file whose object the linker flagged as the
        # redefinition -- this candidate's own naming problem, feed to fix loop.
        result = plp._find_duplicate_symbol_offender(LNK2005_OUTPUT, "unit_field_getters")
        assert result == ("build_candidate",
                           result[1],  # detail text checked separately below
                           None)
        assert "duplicate symbol" in result[1]

    def test_intruder_redefines_symbol_we_own_is_auto_quarantined(self, fake_candidates):
        # current_name IS the ORIGINAL definition; the other file is a fresh
        # intruder colliding with us -- safe to auto-quarantine the intruder.
        result = plp._find_duplicate_symbol_offender(LNK2005_OUTPUT, "GetByte0x94")
        assert result is not None
        stage, _, quarantine_name = result
        assert stage == "build_provider_duplicate_symbol"
        assert quarantine_name == "unit_field_getters"

    def test_no_match_returns_none(self, fake_candidates):
        assert plp._find_duplicate_symbol_offender("no errors here", "Anything") is None

    def test_nonexistent_candidate_files_fall_through(self, fake_candidates):
        out = (r"  Ghost.obj : error LNK2005: _Ghost@4 already defined in "
               r"Phantom.obj")
        assert plp._find_duplicate_symbol_offender(out, "ValidateSkillId") is None


class TestQuarantineCandidate:
    def test_moves_file_and_writes_manifest(self, fake_candidates):
        plp.quarantine_candidate("unit_field_getters", "duplicate symbol GetByte0x94")
        assert not (fake_candidates / "unit_field_getters.cpp").exists()
        quarantined = fake_candidates / "_quarantine" / "unit_field_getters.cpp"
        assert quarantined.exists()
        manifest = (fake_candidates / "_quarantine" / "MANIFEST.txt").read_text()
        assert "unit_field_getters" in manifest
        assert "duplicate symbol GetByte0x94" in manifest

    def test_missing_file_is_best_effort(self, fake_candidates):
        plp.quarantine_candidate("DoesNotExist", "irrelevant")  # must not raise


# ---------------------------------------------------------------------------
# LIVE IDENTITY: module + RVA (2026-07-30)
#
# Regression cover for the relocated-module bug: specs carried only the Ghidra
# ABSOLUTE address, which the oracle called verbatim. D2Client loads at
# 0x03600000 live while Ghidra has it at 0x6fab0000, so every D2Client oracle
# call hit unmapped memory, faulted, came back as "handler-exception", and was
# filed as `marshal_fault` -- a TERMINAL ABI verdict. 104 D2Client functions were
# retired without their reimpl ever executing (including a zero-arg void setter,
# for which no ABI theory applies).
# ---------------------------------------------------------------------------

D2CLIENT_GHIDRA_BASE = 0x6FAB0000
D2CLIENT_LIVE_BASE = 0x03600000


class TestModuleNameForProgram:
    def test_extracts_dll_from_project_path(self):
        assert plp.module_name_for_program(
            "/Mods/PD2-S12/D2Client.dll") == "D2Client.dll"

    def test_handles_backslashes(self):
        assert plp.module_name_for_program(
            "\\Mods\\PD2-S12\\D2Common.dll") == "D2Common.dll"

    def test_bare_name_passes_through(self):
        assert plp.module_name_for_program("Fog.dll") == "Fog.dll"

    def test_empty_program_is_empty_never_a_default(self):
        # A plausible-looking default here (e.g. "D2Common.dll") is the exact
        # shape of the 2026-07-27 wrong-binary tag bug.
        assert plp.module_name_for_program(None) == ""
        assert plp.module_name_for_program("") == ""


class TestStampLiveIdentity:
    def test_adds_module_and_rva(self, monkeypatch):
        monkeypatch.setattr(plp, "ghidra_image_base", lambda p: D2CLIENT_GHIDRA_BASE)
        spec = {"name": "CLIENT_GetRosterSkillId", "addr": 0x6FAD16D0}
        plp.stamp_live_identity(spec, "/Mods/PD2-S12/D2Client.dll")
        assert spec["module"] == "D2Client.dll"
        assert spec["rva"] == 0x216D0

    def test_keeps_addr_for_backcompat(self, monkeypatch):
        monkeypatch.setattr(plp, "ghidra_image_base", lambda p: D2CLIENT_GHIDRA_BASE)
        spec = {"name": "X", "addr": 0x6FAD16D0}
        plp.stamp_live_identity(spec, "/Mods/PD2-S12/D2Client.dll")
        assert spec["addr"] == 0x6FAD16D0

    def test_rva_plus_live_base_is_the_real_function(self, monkeypatch):
        """The whole point: rva + RUNTIME base lands on the function.

        Verified against the live process on 2026-07-30 -- D2Client+0x11c4d4
        resolved to 0x0371c4d4, exactly the operand in the relocated
        `mov eax,[0x0371c4d4]` at CLIENT_GetRosterSkillId.
        """
        monkeypatch.setattr(plp, "ghidra_image_base", lambda p: D2CLIENT_GHIDRA_BASE)
        spec = {"name": "CLIENT_GetRosterSkillId", "addr": 0x6FAD16D0}
        plp.stamp_live_identity(spec, "/Mods/PD2-S12/D2Client.dll")
        assert D2CLIENT_LIVE_BASE + spec["rva"] == 0x036216D0

    def test_no_stamp_without_image_base(self, monkeypatch):
        monkeypatch.setattr(plp, "ghidra_image_base", lambda p: None)
        spec = {"name": "X", "addr": 0x6FAD16D0}
        plp.stamp_live_identity(spec, "/Mods/PD2-S12/D2Client.dll")
        assert "module" not in spec and "rva" not in spec

    def test_no_stamp_when_addr_below_image_base(self, monkeypatch):
        monkeypatch.setattr(plp, "ghidra_image_base", lambda p: D2CLIENT_GHIDRA_BASE)
        spec = {"name": "X", "addr": 0x1000}
        plp.stamp_live_identity(spec, "/Mods/PD2-S12/D2Client.dll")
        assert "rva" not in spec


class TestClassifyProveFailureBadTarget:
    def test_bad_target_beats_handler_exception(self):
        """Ordering matters: the gate message and the SEH fallout can co-occur,
        and reading it as marshal_fault is what made the verdict terminal."""
        out = ("[oracle] Foo (general ABI, stdcall) x 1 vectors\n"
               "[fatal] oracle error: bad-target: original for Foo resolved via addr "
               "to 0x6FAD0F20, which is not mapped executable in the game process\n"
               "handler-exception")
        stage, detail = plp._classify_prove_failure(out)
        assert stage == "bad_target"
        assert "0x6FAD0F20" in detail

    def test_module_not_loaded_is_bad_target(self):
        out = "[fatal] oracle error: module not loaded in the game process: D2Client.dll"
        stage, _ = plp._classify_prove_failure(out)
        assert stage == "bad_target"

    def test_plain_handler_exception_is_still_marshal_fault(self):
        out = "[fatal] oracle error: handler-exception"
        stage, _ = plp._classify_prove_failure(out)
        assert stage == "marshal_fault"


class TestCheckLiveTarget:
    def _patch(self, monkeypatch, *, peek_got, live_bases=None, supports=None):
        monkeypatch.setattr(plp, "ghidra_image_base", lambda p: D2CLIENT_GHIDRA_BASE)
        monkeypatch.setattr(plp, "oracle_live_bases", lambda: live_bases or {})
        monkeypatch.setattr(plp, "oracle_supports_module_rva", lambda: supports)
        monkeypatch.setattr(
            plp, "_oracle_json",
            lambda path, payload=None: {"ok": True, "got": peek_got, "vals": [0]})

    def test_mapped_target_passes(self, monkeypatch):
        self._patch(monkeypatch, peek_got=1)
        ok, why = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert ok and why == ""

    def test_unmapped_target_is_rejected(self, monkeypatch):
        self._patch(monkeypatch, peek_got=0)
        ok, why = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert not ok
        assert "bad-target" in why

    def test_relocated_module_on_old_oracle_is_rejected(self, monkeypatch):
        """An oracle without specModuleRva ignores module+rva and calls the
        absolute address -- exactly the pre-fix behaviour. Refuse rather than
        manufacture another false ABI verdict."""
        self._patch(monkeypatch, peek_got=1,
                    live_bases={"d2client.dll": D2CLIENT_LIVE_BASE}, supports=False)
        ok, why = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert not ok
        assert "RELOCATED" in why and "specModuleRva" in why

    def test_relocated_module_on_new_oracle_passes(self, monkeypatch):
        self._patch(monkeypatch, peek_got=1,
                    live_bases={"d2client.dll": D2CLIENT_LIVE_BASE}, supports=True)
        ok, _ = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert ok

    def test_module_at_its_base_needs_no_capability(self, monkeypatch):
        self._patch(monkeypatch, peek_got=1,
                    live_bases={"d2client.dll": D2CLIENT_GHIDRA_BASE}, supports=False)
        ok, _ = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert ok

    def test_unreachable_oracle_does_not_block(self, monkeypatch):
        """An unreachable oracle is a separate environmental case; reporting it as
        a bad target here would trade one false verdict for another."""
        monkeypatch.setattr(plp, "ghidra_image_base", lambda p: D2CLIENT_GHIDRA_BASE)
        monkeypatch.setattr(plp, "oracle_live_bases", lambda: {})
        monkeypatch.setattr(plp, "_oracle_json", lambda path, payload=None: None)
        ok, why = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert ok and why == ""

    def test_no_program_does_not_block(self, monkeypatch):
        monkeypatch.setattr(plp, "_oracle_json", lambda path, payload=None: None)
        ok, _ = plp.check_live_target(None, "6fad16d0")
        assert ok


class TestPreflightSpecTarget:
    def test_unmapped_spec_fails_before_the_prover_runs(self, monkeypatch, tmp_path):
        spec = tmp_path / "Foo.spec.json"
        spec.write_text(json.dumps(
            {"name": "Foo", "addr": 0x6FAD0F20, "module": "D2Client.dll",
             "rva": 0x20F20}), encoding="utf-8")
        monkeypatch.setattr(
            plp, "_oracle_json",
            lambda path, payload=None: {"ok": True, "got": 0, "vals": []})
        res = plp._preflight_spec_target(spec)
        assert res is not None
        assert res["failure_stage"] == "bad_target"
        assert res["ok"] is False

    def test_mapped_spec_returns_none(self, monkeypatch, tmp_path):
        spec = tmp_path / "Foo.spec.json"
        spec.write_text(json.dumps(
            {"name": "Foo", "module": "D2Client.dll", "rva": 0x20F20}),
            encoding="utf-8")
        monkeypatch.setattr(
            plp, "_oracle_json",
            lambda path, payload=None: {"ok": True, "got": 1, "vals": [0]})
        assert plp._preflight_spec_target(spec) is None

    def test_spec_without_module_rva_is_not_judged(self, tmp_path):
        spec = tmp_path / "Foo.spec.json"
        spec.write_text(json.dumps({"name": "Foo", "addr": 0x6FD866B0}),
                        encoding="utf-8")
        assert plp._preflight_spec_target(spec) is None


class TestPromptModuleIsNotHardcoded:
    def test_draft_prompt_names_the_callers_module(self):
        """Both live draft prompts said "(D2Common.dll)" unconditionally, so every
        D2Client draft was told it was documenting a D2Common function."""
        p = plp.build_live_draft_prompt("CLIENT_GetRosterSkillId", "0x6fad16d0",
                                        "int foo(void) { return 0; }",
                                        program="/Mods/PD2-S12/D2Client.dll")
        assert "(D2Client.dll)" in p
        assert "(D2Common.dll)" not in p

    def test_handle_prompt_names_the_callers_module(self):
        p = plp.build_handle_draft_prompt("GetUnitMode", "0x6fad16d0",
                                          "int foo(void*) { return 0; }",
                                          program="/Mods/PD2-S12/D2Client.dll")
        assert "(D2Client.dll)" in p
        assert "(D2Common.dll)" not in p

    def test_missing_program_says_unknown_not_a_plausible_default(self):
        p = plp.build_live_draft_prompt("Foo", "0x1000", "void foo(void) {}")
        assert "(unknown module)" in p


class TestLiveBytesDifferFromGhidra:
    """The relocation detector that needs no live base -- the only guard available
    against an oracle without GET /modules, and the one that actually fired on the
    running (pre-rebuild) oracle for D2Client while passing D2Common."""

    def _patch(self, monkeypatch, live_dwords, ghidra_bytes):
        monkeypatch.setattr(
            plp, "_oracle_json",
            lambda path, payload=None: {"ok": True, "got": len(live_dwords),
                                        "vals": live_dwords})
        monkeypatch.setattr(
            plp, "_ghidra_get_json", lambda path: {"data": ghidra_bytes})

    def test_identical_bytes_report_no_difference(self, monkeypatch):
        self._patch(monkeypatch, [0x6FBCC4D4], [0xD4, 0xC4, 0xBC, 0x6F])
        assert plp.live_bytes_differ_from_ghidra(
            "/Mods/PD2-S12/D2Common.dll", 0x6FD866B0, "D2Common.dll", 0x366B0,
            length=4) is False

    def test_relocated_operand_is_detected(self, monkeypatch):
        """Ground truth 2026-07-30: Ghidra `mov eax,[0x6fbcc4d4]` reads back live as
        `mov eax,[0x0371c4d4]` because D2Client sits at 0x03600000."""
        self._patch(monkeypatch, [0x0371C4D4], [0xD4, 0xC4, 0xBC, 0x6F])
        assert plp.live_bytes_differ_from_ghidra(
            "/Mods/PD2-S12/D2Client.dll", 0x6FAD16D0, "D2Client.dll", 0x216D0,
            length=4) is True

    def test_unreadable_side_returns_none_not_a_verdict(self, monkeypatch):
        monkeypatch.setattr(plp, "_oracle_json", lambda path, payload=None: None)
        assert plp.live_bytes_differ_from_ghidra(
            "/Mods/PD2-S12/D2Client.dll", 0x6FAD16D0, "D2Client.dll", 0x216D0) is None

    def test_length_mismatch_returns_none(self, monkeypatch):
        self._patch(monkeypatch, [0x11223344], [0x44, 0x33])
        assert plp.live_bytes_differ_from_ghidra(
            "/Mods/PD2-S12/D2Client.dll", 0x6FAD16D0, "D2Client.dll", 0x216D0,
            length=4) is None


class TestCheckLiveTargetOldOracleFallback:
    """Without GET /modules the relocated check has no live base, so it must fall
    back to the byte comparison -- otherwise the window between deploying the
    Python fix and rebuilding D2Debugger still manufactures false ABI verdicts."""

    def _patch(self, monkeypatch, *, differ, supports=False):
        monkeypatch.setattr(plp, "ghidra_image_base", lambda p: D2CLIENT_GHIDRA_BASE)
        monkeypatch.setattr(plp, "oracle_live_bases", lambda: {})
        monkeypatch.setattr(plp, "oracle_supports_module_rva", lambda: supports)
        monkeypatch.setattr(
            plp, "_oracle_json",
            lambda path, payload=None: {"ok": True, "got": 1, "vals": [0]})
        monkeypatch.setattr(plp, "live_bytes_differ_from_ghidra",
                            lambda *a, **k: differ)

    def test_differing_bytes_on_old_oracle_are_rejected(self, monkeypatch):
        self._patch(monkeypatch, differ=True)
        ok, why = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert not ok
        assert "relocated (or is a different build)" in why

    def test_matching_bytes_on_old_oracle_pass(self, monkeypatch):
        self._patch(monkeypatch, differ=False)
        ok, _ = plp.check_live_target("/Mods/PD2-S12/D2Common.dll", "6fd866b0")
        assert ok

    def test_inconclusive_bytes_do_not_block(self, monkeypatch):
        self._patch(monkeypatch, differ=None)
        ok, _ = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert ok

    def test_new_oracle_skips_the_byte_fallback(self, monkeypatch):
        self._patch(monkeypatch, differ=True, supports=True)
        ok, _ = plp.check_live_target("/Mods/PD2-S12/D2Client.dll", "6fad16d0")
        assert ok

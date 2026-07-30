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

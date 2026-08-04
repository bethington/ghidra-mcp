"""Guards for fun-doc/bsim_identify.py -- the BSim identification decision layer.

Every test here is a lesson that was measured, not imagined. The headline one is
`test_calibration_regression`: it replays the Phase 0 calibration dumps (when
present) and fails if precision ever drops below 1.0000. The synthetic tests
below cover the same rules without needing those large files.
"""

from __future__ import annotations

import json
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "fun-doc"))

import bsim_identify as bi                                      # noqa: E402


def row(name="FUN_00401000", addr="0x401000", size=64, matches=()):
    return {"query_function": name, "query_address": addr,
            "body_size": size, "matches": list(matches)}


def cand(name, sim=0.99, signif=50.0, exe="ref.dll", addr="0x1000"):
    return {"exe": exe, "name": name, "addr": addr, "sim": sim, "signif": signif}


# --------------------------------------------------------------------------
# The abstain rule -- worth ~14 points of precision on the calibration set
# --------------------------------------------------------------------------

def test_tie_with_different_names_abstains():
    """Two names at the same top similarity identify nothing.

    This is the `__ld12tod` / `*_it` accessor shape: without this rule naive
    application peaks at ~86% precision no matter how the floors are set.
    """
    m = bi.decide(row(matches=[cand("AES_encrypt"), cand("AES_decrypt")]))
    assert m.ambiguous is True
    assert m.match_name is None
    assert m.writable is False
    assert m.bucket == "ambiguous"
    # The rejected candidates still surface, so review sees WHAT was rejected.
    assert m.candidates == ["AES_decrypt", "AES_encrypt"]


def test_tie_with_same_name_is_not_ambiguous():
    """The same function at several reference addresses is one answer, not two."""
    m = bi.decide(row(matches=[cand("AES_encrypt", signif=50.0, addr="0x1000"),
                               cand("AES_encrypt", signif=90.0, addr="0x2000")]))
    assert m.ambiguous is False
    assert m.match_name == "AES_encrypt"
    assert m.writable is True
    # Tie broken by significance, the stronger signal.
    assert m.significance == 90.0


def test_decoration_differences_do_not_manufacture_a_tie():
    """`_foo`, `foo` and `foo@12` are one name across builds, not three."""
    m = bi.decide(row(matches=[cand("_memcpy"), cand("memcpy"), cand("memcpy@12")]))
    assert m.ambiguous is False
    assert m.writable is True


def test_unnamed_top_match_abstains():
    """The closest reference function has no name to give -> write nothing.

    Costs zero recall on the calibration set (the index was 99.3% named) and
    protects the partially-named reference builds Phase 2 will produce.
    """
    m = bi.decide(row(matches=[cand("FUN_00120000", sim=1.0),
                               cand("real_name", sim=0.97)]))
    assert m.unnamed_top is True
    assert m.writable is False
    assert m.bucket == "unnamed_top_match"


def test_unnamed_below_top_tier_does_not_block():
    """An unnamed candidate that is strictly WORSE is not evidence of anything."""
    m = bi.decide(row(matches=[cand("real_name", sim=0.99),
                               cand("FUN_00120000", sim=0.96)]))
    assert m.unnamed_top is False
    assert m.writable is True
    assert m.match_name == "real_name"


# --------------------------------------------------------------------------
# Ordering: floors BEFORE the tie test
# --------------------------------------------------------------------------

def test_junk_below_the_floor_cannot_manufacture_ambiguity():
    """A candidate under either floor is noise and must not suppress a good write.

    If the tie test ran before the floors, one weak junk match would abstain
    every otherwise-clean identification in the corpus.
    """
    m = bi.decide(row(matches=[cand("good_name", sim=0.99, signif=80.0),
                               cand("junk_name", sim=0.99, signif=5.0),
                               cand("other_junk", sim=0.40, signif=99.0)]))
    assert m.ambiguous is False
    assert m.match_name == "good_name"
    assert m.writable is True


# --------------------------------------------------------------------------
# The calibrated floors
# --------------------------------------------------------------------------

def test_below_similarity_floor_yields_no_verdict():
    assert bi.decide(row(matches=[cand("x", sim=0.94, signif=99.0)])) is None


def test_below_significance_floor_yields_no_verdict():
    """Significance is the real discriminator; 29.9 is the negative-control zone."""
    assert bi.decide(row(matches=[cand("x", sim=1.0, signif=29.9)])) is None


def test_floors_match_the_calibration():
    """If these move, the measured precision guarantee no longer applies."""
    assert bi.SIM_FLOOR == 0.95
    assert bi.SIGNIF_FLOOR == 30.0
    assert bi.MIN_CONFIDENT_LEN == 16


def test_empty_matches_yields_no_verdict():
    assert bi.decide(row(matches=[])) is None


# --------------------------------------------------------------------------
# Name-quality gates
# --------------------------------------------------------------------------

def test_tiny_body_is_taggable_but_not_renamable():
    """Degenerate bodies match anything; both negative-control FPs were <52b."""
    m = bi.decide(row(size=12, matches=[cand("some_name")]))
    assert m.writable is True          # tag + bookmark are fine
    assert m.confident_name is False   # the NAME is not
    assert m.bucket == "too_short"


def test_linker_local_names_are_never_written():
    """`$L12345` is a label, not a function name.

    25 of a claimed FID "+29" win were exactly this shape and would have been
    written as function names.
    """
    m = bi.decide(row(matches=[cand("$L12345")]))
    assert m.confident_name is False


def test_default_name_is_never_copied_out_of_the_index():
    m = bi.decide(row(matches=[cand("FUN_00401000")]))
    assert m.writable is False


@pytest.mark.parametrize("name,expected", [
    ("FUN_00401000", True), ("SUB_00401000", True), ("thunk_FUN_00401000", True),
    ("Ordinal_42", True), ("entry", True),
    ("AES_encrypt", False), ("_memcpy", False), ("D2COMMON_GetUnitStat", False),
])
def test_is_default_name(name, expected):
    assert bi.is_default_name(name) is expected


# --------------------------------------------------------------------------
# The single writer
# --------------------------------------------------------------------------

def test_writer_writes_nothing_at_all_for_non_writable():
    """A LIB_* tag makes the selector skip a function FOREVER.

    An ambiguous match must not earn one -- not a tag, not a bookmark, nothing.
    """
    m = bi.decide(row(matches=[cand("a"), cand("b")]))
    with mock.patch.object(bi, "_post") as post:
        res = bi.sync_to_ghidra(m)
    post.assert_not_called()
    assert res["tagged"] is False and res["bookmarked"] is False
    assert res["renamed"] is None
    assert res["skipped"] == "ambiguous"


def test_writer_tags_bookmarks_and_renames_a_default_name():
    m = bi.decide(row(name="FUN_00401000", matches=[cand("AES_encrypt")]),
                  program="/p/x.dll")
    with mock.patch.object(bi, "_post", return_value={"success": True}) as post:
        res = bi.sync_to_ghidra(m)
    paths = [c.args[0] for c in post.call_args_list]
    assert paths == ["/add_function_tag", "/set_bookmark", "/rename_function"]
    assert res["renamed"] == "AES_encrypt"
    assert res["tagged"] and res["bookmarked"]


def test_writer_sends_strict_mode_false():
    """Upstream symbols are not ours to restyle.

    strict_mode rejected 66 real OpenSSL names (X448, CMAC_Final,
    OPENSSL_Uplink) for `missing_specifier` during the PDB recovery pass.
    """
    m = bi.decide(row(matches=[cand("X448")]), program="/p/x.dll")
    with mock.patch.object(bi, "_post", return_value={"success": True}) as post:
        bi.sync_to_ghidra(m)
    rename = [c for c in post.call_args_list if c.args[0] == "/rename_function"][0]
    assert rename.args[2]["strict_mode"] is False


def test_writer_preserves_documented_names_by_default():
    m = bi.decide(row(name="D2COMMON_GetUnitStat", matches=[cand("AES_encrypt")]),
                  program="/p/x.dll")
    with mock.patch.object(bi, "_post", return_value={"success": True}) as post:
        res = bi.sync_to_ghidra(m)
    assert res["renamed"] is None
    assert res["skipped"] == "documented_preserved"
    # Tag + bookmark still land: the evidence is real even when the name stays.
    assert [c.args[0] for c in post.call_args_list] == \
        ["/add_function_tag", "/set_bookmark"]


def test_writer_overwrites_documented_name_only_when_asked():
    m = bi.decide(row(name="D2COMMON_GetUnitStat", matches=[cand("AES_encrypt")]),
                  program="/p/x.dll")
    with mock.patch.object(bi, "_post", return_value={"success": True}) as post:
        res = bi.sync_to_ghidra(m, rename_documented=True)
    assert res["renamed"] == "AES_encrypt"
    assert "/rename_function" in [c.args[0] for c in post.call_args_list]


def test_writer_skips_a_name_that_is_already_correct():
    m = bi.decide(row(name="AES_encrypt", matches=[cand("_AES_encrypt")]),
                  program="/p/x.dll")
    with mock.patch.object(bi, "_post", return_value={"success": True}) as post:
        res = bi.sync_to_ghidra(m)
    assert res["skipped"] == "already_correct"
    assert "/rename_function" not in [c.args[0] for c in post.call_args_list]


def test_writer_retries_once_past_a_duplicate_label():
    """An analyzer label on the address blocks the rename with the same name."""
    m = bi.decide(row(matches=[cand("AES_encrypt")]), program="/p/x.dll")
    responses = [{"success": True},                      # tag
                 {"success": True},                      # bookmark
                 {"error": "already exists at this address"},
                 {"success": True},                      # delete_label
                 {"success": True}]                      # rename retry
    with mock.patch.object(bi, "_post", side_effect=responses) as post:
        res = bi.sync_to_ghidra(m)
    assert res["renamed"] == "AES_encrypt"
    assert "/delete_label" in [c.args[0] for c in post.call_args_list]


def test_writer_reports_failure_loudly():
    """A silent best-effort write-back is how the wrong-binary bug hid for weeks."""
    m = bi.decide(row(matches=[cand("AES_encrypt")]), program="/p/x.dll")
    with mock.patch.object(bi, "_post",
                           side_effect=[{"success": True}, {"success": True},
                                        {"status": "rejected", "error": "nope"}]):
        res = bi.sync_to_ghidra(m)
    assert res["renamed"] is None
    assert "nope" in res["error"]


def test_program_rides_as_a_query_parameter_not_in_the_body():
    """A POST without a resolvable `program` query param hits the ACTIVE program.

    That is exactly how a dry run once performed a real write on the wrong
    binary.
    """
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"success": true}'

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode())
        return FakeResponse()

    with mock.patch.object(bi.urllib.request, "urlopen", fake_urlopen):
        bi._post("/rename_function", "/Mods/PD2-S12/D2Common.dll", {"a": 1})

    assert "program=%2FMods%2FPD2-S12%2FD2Common.dll" in captured["url"]
    assert "program" not in captured["body"]


# --------------------------------------------------------------------------
# The calibration guarantee itself
# --------------------------------------------------------------------------

CALIB = r"C:\tmp\bsim_phase0\calib_dump.jsonl"
NEGCTL = r"C:\tmp\bsim_phase0\negctl_d2common.jsonl"


@pytest.mark.skipif(not os.path.exists(CALIB),
                    reason="Phase 0 calibration dump not present on this box")
def test_calibration_regression():
    """Replay Phase 0: precision must stay 1.0000 at the calibrated floors.

    Ground truth is available because both sides of that experiment carry names
    from authoritative PDBs, so the query function's own name IS the answer.
    """
    matches = bi.identify_from_dump(CALIB, program="calib")
    scored = [m for m in matches
              if m.confident_name and not bi.is_default_name(m.current_name)]
    wrong = [m for m in scored
             if bi._canon(m.match_name) != bi._canon(m.current_name)]
    assert scored, "calibration dump produced no scorable writes"
    assert not wrong, f"PRECISION REGRESSION: {len(wrong)} false positives, " \
                      f"e.g. {wrong[:3]}"
    # Recall guard: a change that keeps precision by writing almost nothing has
    # broken the lane just as surely as one that writes garbage.
    assert len(scored) >= 1700, f"recall collapsed to {len(scored)} writes"


@pytest.mark.skipif(not os.path.exists(NEGCTL),
                    reason="Phase 0 negative control not present on this box")
def test_negative_control_stays_clean():
    """D2Common against an OpenSSL index: exactly one write, and it is correct.

    `__allmul` -> `_allmul` is a hand-written CRT helper genuinely shared
    between them. The two 29-byte false positives that this control produced at
    significance 20.7 are what set SIGNIF_FLOOR to 30.
    """
    matches = bi.identify_from_dump(NEGCTL, program="negctl")
    writes = [m for m in matches if m.confident_name]
    assert len(writes) == 1, f"expected 1 write, got {[m.match_name for m in writes]}"
    assert bi._canon(writes[0].match_name) == "allmul"

"""Regression tests for the shadow-manifest correctness guards.

Two outages on 2026-07-29/30, both from the same root mistake: trusting
Ghidra's INFERRED type information over the instructions the compiler actually
emitted.

  1. ARG COUNT (crash). Two harvested entries took their arity from Ghidra's
     signature. INV_CanItemFitInStoragePage declared 3 args against a real
     `RET 8`; ITEMS_TestItemFlags declared 2 against a real `RET 0x10`. stdcall
     is callee-cleans, so each thunk popped the wrong number of bytes, skewed
     ESP for the rest of the call chain, and returned into garbage. The game
     access-violated with `eip=0x00000140` the instant a save's inventory
     populated. Both reimpls had the right arity all along.

  2. RETURN WIDTH (false divergences). `MOVZX EAX, word ptr [...]` writes all
     32 bits, so a write-width reading called it 32 and 19 manifest entries got
     widened 16/8 -> 32. But MOVZX MANUFACTURES the upper bits as zeros -- they
     were never part of the answer -- and the reimpls are declared
     `unsigned short`, which by ABI guarantees only AX. Comparing the residue
     above it produced 166,565 false divergences on
     DATATBLS_GetLevelRecordBitfield06 in under a day, every one agreeing
     perfectly in the low 16 bits. False divergences are not cosmetic: 2,620 of
     them wrongly refuted ITEMS_GetItemDataInvPage.

The invariant both share: for a shadow comparison the DISASSEMBLY is the
authority, and where two implementations meet, the contract is whatever BOTH
sides guarantee.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

argc_mod = pytest.importorskip("scripts.audit_stdcall_argc")
width_mod = pytest.importorskip("scripts.audit_ret_widths")
harvest = pytest.importorskip("scripts.harvest_stranded_dispatchers")


def _ins(*text):
    return [{"instruction": t} for t in text]


# --- arg count: the crash ---------------------------------------------------

@pytest.mark.parametrize("ret,expected", [
    ("RET", 0), ("RET 0x4", 4), ("RET 0x8", 8), ("RET 0xc", 12), ("RET 0x10", 16),
])
def test_cleanup_read_from_ret(ret, expected):
    assert argc_mod.observed_cleanup(_ins("MOV EAX,1", ret)) == expected


def test_cleanup_ambiguous_when_paths_disagree():
    """One function has one convention. Disagreement means we are misreading
    the range, so refuse rather than pick -- guessing here crashes the game."""
    assert argc_mod.observed_cleanup(_ins("RET 0x4", "RET 0x8")) is None


def test_cleanup_none_when_no_ret():
    assert argc_mod.observed_cleanup(_ins("MOV EAX,1")) is None


@pytest.mark.parametrize("cc,argc,expected", [
    ("stdcall", 0, 0), ("stdcall", 1, 4), ("stdcall", 2, 8), ("stdcall", 4, 16),
    ("cdecl", 3, 0),                       # caller cleans
    ("fastcall", 1, 0), ("fastcall", 2, 0),  # both dwords in ECX/EDX
    ("fastcall", 4, 8),                    # two spill to the stack
])
def test_expected_cleanup_per_convention(cc, argc, expected):
    assert argc_mod.expected_cleanup(cc, argc) == expected


def test_the_two_entries_that_crashed_the_game():
    """Regression on the exact outage. Each manifest arity disagrees with the
    callee's own RET, and the disagreement is what skewed ESP."""
    # INV_CanItemFitInStoragePage: manifest said 3, RET 8 says 2.
    assert argc_mod.expected_cleanup("stdcall", 3) == 12
    assert argc_mod.observed_cleanup(_ins("MOV EAX,1", "RET 0x8")) == 8
    assert argc_mod.expected_cleanup("stdcall", 2) == 8      # corrected value agrees

    # ITEMS_TestItemFlags: manifest said 2, RET 0x10 says 4.
    assert argc_mod.expected_cleanup("stdcall", 2) == 8
    assert argc_mod.observed_cleanup(_ins("MOV EAX,1", "RET 0x10")) == 16
    assert argc_mod.expected_cleanup("stdcall", 4) == 16     # corrected value agrees


# --- the harvester, which produced them -------------------------------------

def test_harvester_reads_arity_from_ret(monkeypatch):
    monkeypatch.setattr(harvest, "_get",
                        lambda *a, **k: {"instructions": _ins("MOV EAX,1", "RET 0x10")})
    assert harvest.arg_count(0x1000, "D2Common.dll", "stdcall") == (4, None)


def test_harvester_refuses_cdecl(monkeypatch):
    """A bare RET under cdecl says nothing about arity -- the only source left
    is the inference that caused the outage."""
    monkeypatch.setattr(harvest, "_get",
                        lambda *a, **k: {"instructions": _ins("MOV EAX,1", "RET")})
    argc, why = harvest.arg_count(0x1000, "D2Common.dll", "cdecl")
    assert argc is None and "cdecl" in why


def test_harvester_refuses_ambiguous_fastcall(monkeypatch):
    """fastcall popping nothing is 0, 1, or 2 args -- indistinguishable."""
    monkeypatch.setattr(harvest, "_get",
                        lambda *a, **k: {"instructions": _ins("MOV EAX,1", "RET")})
    argc, why = harvest.arg_count(0x1000, "D2Common.dll", "fastcall")
    assert argc is None and "indistinguishable" in why


def test_harvester_refuses_conflicting_paths(monkeypatch):
    monkeypatch.setattr(harvest, "_get",
                        lambda *a, **k: {"instructions": _ins("RET 0x4", "RET 0x8")})
    argc, why = harvest.arg_count(0x1000, "D2Common.dll", "stdcall")
    assert argc is None and "ambiguous" in why


def test_harvester_refuses_without_disassembly(monkeypatch):
    monkeypatch.setattr(harvest, "_get", lambda *a, **k: {})
    argc, why = harvest.arg_count(0x1000, "D2Common.dll", "stdcall")
    assert argc is None and "cannot confirm" in why


def test_harvester_fastcall_adds_register_args(monkeypatch):
    """Two dwords arrive in ECX/EDX and never touch the stack, so a `RET 8`
    fastcall is 4 args, not 2."""
    monkeypatch.setattr(harvest, "_get",
                        lambda *a, **k: {"instructions": _ins("RET 0x8")})
    assert harvest.arg_count(0x1000, "D2Common.dll", "fastcall") == (4, None)


# --- return width: the false divergences ------------------------------------

def test_movzx_is_the_source_width_not_32():
    """The regression that cost 166,565 phantom mismatches. MOVZX writes 32
    bits but the DATUM is a word; the upper half is manufactured zeros."""
    ins = _ins("MOV EAX,dword ptr [ESP + 0x4]", "MOVZX EAX,word ptr [EAX + 0x6]", "RET 0x4")
    assert width_mod.observed_ret_width(ins) == 16


def test_movzx_byte_is_eight():
    ins = _ins("MOVZX EAX,byte ptr [EAX + 0x2]", "RET 0x4")
    assert width_mod.observed_ret_width(ins) == 8


def test_movsx_stays_wide():
    """Sign extension makes the upper bits carry information, so unlike MOVZX
    they are part of the answer and must still be compared."""
    ins = _ins("MOVSX EAX,word ptr [EAX + 0x6]", "RET 0x4")
    assert width_mod.observed_ret_width(ins) == 32


def test_partial_register_write_is_narrow():
    """MOV AL leaves the upper 24 bits as whatever the caller left there --
    PATH_GetDirection returned leftover POINTER bytes above AL."""
    assert width_mod.observed_ret_width(_ins("MOV AL,byte ptr [EAX + 0x65]", "RET 0x4")) == 8
    assert width_mod.observed_ret_width(_ins("MOV AX,0x10", "RET 0x4")) == 16


def test_full_register_write_stays_32():
    assert width_mod.observed_ret_width(_ins("MOV EAX,dword ptr [EAX]", "RET 0x4")) == 32


def test_narrowest_return_path_wins():
    """If ANY path leaves the upper bits dirty, a wide comparison is unsafe."""
    ins = _ins("MOV EAX,dword ptr [EAX]", "RET 0x4", "XOR AL,AL", "RET 0x4")
    assert width_mod.observed_ret_width(ins) == 8


# --- the two-sided contract -------------------------------------------------

def test_effective_mask_takes_the_narrower_side():
    """The original may zero-extend to a clean 32 bits while the reimpl,
    declared `unsigned short`, guarantees only AX. Comparing 32 then judges
    register residue the ABI never promised."""
    assert width_mod.effective_mask_bits(32, 16) == 16
    assert width_mod.effective_mask_bits(32, 8) == 8


def test_effective_mask_unconstrained_when_reimpl_is_dword():
    assert width_mod.effective_mask_bits(32, None) == 32
    assert width_mod.effective_mask_bits(16, None) == 16


def test_effective_mask_never_widens_past_the_original():
    """A reimpl declaring a wider type cannot license comparing bits the
    original never wrote."""
    assert width_mod.effective_mask_bits(8, 16) == 8


def test_the_entry_that_logged_166k_false_divergences():
    """DATATBLS_GetLevelRecordBitfield06 end to end: original zero-extends a
    word, reimpl is `unsigned short`, so the honest comparison width is 16 --
    which is exactly what the live counters confirmed (85,133 hits, 45 distinct
    inputs, 0 divergences after the correction)."""
    ins = _ins("MOV EAX,dword ptr [ESP + 0x4]",
               "MOVZX EAX,word ptr [EAX + 0x6]", "RET 0x4")
    observed = width_mod.observed_ret_width(ins)
    assert width_mod.effective_mask_bits(observed, 16) == 16, "32 produced the phantoms"


# --- cross-source arity: reimpl declaration x RET n -------------------------
#
# Added 2026-07-30 after the crash. `RET n` is a fact but UNDER-DETERMINES
# fastcall (a `RET 0` fastcall is 0, 1, or 2 args), which made the harvester
# refuse five otherwise-ready functions. The reimpl's declaration states the
# convention outright and is the exact code the oracle proved bit-exact. Using
# both turns a guess into corroboration -- and would have caught the crash,
# where Ghidra said 3 while the reimpl and the RET both said 2.

def _sig(callconv="stdcall", argc=1, ret_bits=None, is_void=False):
    return {"callconv": callconv, "argc": argc, "ret_bits": ret_bits, "is_void": is_void}


def _row(addr="0x6fd73000", callconv="stdcall", ret="u32"):
    return {"address": addr, "callconv": callconv, "ret": ret}


def _wire(monkeypatch, instructions):
    monkeypatch.setattr(harvest, "_get", lambda ep, **k: (
        {"instructions": instructions} if ep in ("disassemble_function",)
        else {"signature": "int f(int)"}))


def test_reimpl_signature_parsing_handles_real_shapes(tmp_path, monkeypatch):
    """Multi-line signatures, a file named differently from the function, and
    nested commas in the arg list all appear in the real candidate tree --
    SEED_GetRandomNumber lives in seed_getrandom.cpp and was invisible to a
    per-file name lookup."""
    (tmp_path / "seed_getrandom.cpp").write_text(
        'extern "C" unsigned int __fastcall SEED_GetRandomNumber(\n'
        '    unsigned int* pSeed,\n'
        '    unsigned int max)\n{\n  return 0;\n}\n', encoding="utf-8")
    (tmp_path / "b.cpp").write_text(
        'extern "C" unsigned short __stdcall Narrow(void* p) {\n  return 0;\n}\n',
        encoding="utf-8")
    monkeypatch.setattr(harvest, "_CANDIDATES", tmp_path)
    sigs = harvest.reimpl_signatures()
    assert sigs["SEED_GetRandomNumber"]["argc"] == 2
    assert sigs["SEED_GetRandomNumber"]["callconv"] == "fastcall"
    assert sigs["Narrow"] == {"callconv": "stdcall", "argc": 1,
                              "ret_bits": 16, "is_void": False}


def test_arity_conflict_is_refused_not_resolved(monkeypatch):
    """The crash shape. Reimpl says 2, RET says 4 -- refuse; do NOT pick one."""
    _wire(monkeypatch, _ins("MOV EAX,1", "RET 0x10"))
    e, why = harvest.build_entry("F", _row(), "D2Common.dll", {"F": _sig(argc=2)})
    assert e is None and "ARITY CONFLICT" in why


def test_agreement_is_accepted(monkeypatch):
    _wire(monkeypatch, _ins("MOV EAX,dword ptr [ESP + 0x4]", "RET 0x8"))
    e, why = harvest.build_entry("F", _row(), "D2Common.dll", {"F": _sig(argc=2)})
    assert e is not None, why
    assert len(e["args"]) == 2


def test_fastcall_is_unlocked_by_the_reimpl_declaration(monkeypatch):
    """`RET 0` under fastcall is 0/1/2 args from the disassembly alone. The
    reimpl says 1, and pops-0 is consistent with that, so it is no longer a
    refusal -- this is the unlock that recovered UNITS_GetUnitLevel et al."""
    _wire(monkeypatch, _ins("MOV EAX,ECX", "RET"))
    e, why = harvest.build_entry("F", _row(callconv="fastcall"), "D2Common.dll",
                                 {"F": _sig(callconv="fastcall", argc=1)})
    assert e is not None, why
    assert e["callconv"] == "fastcall" and len(e["args"]) == 1


def test_single_source_arity_is_refused(monkeypatch):
    """Ghidra can hold a name+signature for a body it never disassembled, so
    'reimpl says 1' and 'Ghidra says 1' can agree while neither read an
    instruction -- and Ghidra's signature is what shipped the crash."""
    monkeypatch.setattr(harvest, "_get", lambda ep, **k: {"instructions": []})
    e, why = harvest.build_entry("F", _row(), "D2Common.dll", {"F": _sig(argc=1)})
    assert e is None and "single-source arity" in why


def test_class_d_rejects_multiple_register_args(monkeypatch):
    """Class D v1 carries ONE EAX input. A second input register (EAX+EDX, as
    in SKILLS_CalculateLeveledToHitBonus) has no dispatcher shape; accepting it
    as fastcall would pass arg1 in ECX while the original reads EAX."""
    _wire(monkeypatch, _ins("DEC EAX", "RET"))
    e, why = harvest.build_entry("F", _row(callconv="fastcall"), "D2Common.dll",
                                 {"F": _sig(callconv="fastcall", argc=2)})
    assert e is None and "class D" in why


def test_ret_bits_is_the_narrower_of_both_sides(monkeypatch):
    """min(original datum, reimpl declared type) -- the rule that ended the
    166,565 false divergences."""
    _wire(monkeypatch, _ins("MOV EAX,dword ptr [ESP + 0x4]",
                            "MOVZX EAX,word ptr [EAX + 0x6]", "RET 0x4"))
    e, why = harvest.build_entry("F", _row(), "D2Common.dll",
                                 {"F": _sig(argc=1, ret_bits=16)})
    assert e is not None, why
    assert e["ret_bits"] == 16


def test_void_reimpl_is_deferred_to_manual_review(monkeypatch):
    _wire(monkeypatch, _ins("RET 0x4"))
    e, why = harvest.build_entry("F", _row(), "D2Common.dll",
                                 {"F": _sig(argc=1, is_void=True)})
    assert e is None and "class B" in why

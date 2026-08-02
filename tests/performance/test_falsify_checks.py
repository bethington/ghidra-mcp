"""Coverage for falsify.py's mechanical contradiction checks.

Offline: no Ghidra, no network. Only the pure check layer is exercised over
hand-built bundles; the HTTP collection layer is I/O and is covered by running
the tool. Each check gets BOTH a firing case and a guard-suppressed case --
the confidence guards (multi-RET, varargs, delegation, float returns) are the
part that keeps tier-1 findings trustworthy enough to carry consequences.
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

fz = pytest.importorskip("falsify")


def _bundle(**kw):
    b = {
        "program": "/Mods/PD2-S12/D2Common.dll",
        "address": "0x6fd51000",
        "name": "DATATBLS_GetRecordCount",
        "calling_convention": "__stdcall",
        "return_type": "int",
        "params": [{"name": "nRecordId", "type": "int"}],
        "plate": "",
        "disasm_text": "",
        "prototype": "",
    }
    b.update(kw)
    return b


def _dis(*instructions):
    """Disassembly text in the 'addr: instruction' shape parse_disasm expects."""
    return "\n".join(f"6fd5{1000 + i:04x}: {ins}" for i, ins in enumerate(instructions))


def _ids(findings):
    return [f.check_id for f in findings]


# ------------------------------------------------------ F1 param_mismatch ---

PLATE_TWO_PARAMS = """Counts records in the stat table.

Algorithm:
  1. Look up the record.

Parameters:
  nRecordId: int - identifier of the record row
  pTable: DataTable* - table to search

Returns:
  int: number of records
"""


def test_param_mismatch_excess_documented_param_is_tier1():
    b = _bundle(plate=PLATE_TWO_PARAMS,
                params=[{"name": "nRecordId", "type": "int"}])
    f = fz.check_param_mismatch(b)
    assert len(f) == 1
    assert f[0].tier == fz.TIER_MECHANICAL
    assert "pTable" in f[0].detail["missing"]


def test_param_mismatch_same_count_name_drift_is_tier2():
    b = _bundle(plate=PLATE_TWO_PARAMS,
                params=[{"name": "nRecordId", "type": "int"},
                        {"name": "pStatTable", "type": "DataTable*"}])
    f = fz.check_param_mismatch(b)
    assert len(f) == 1
    assert f[0].tier == fz.TIER_REVIEW


def test_param_mismatch_matching_plate_is_clean():
    b = _bundle(plate=PLATE_TWO_PARAMS,
                params=[{"name": "nRecordId", "type": "int"},
                        {"name": "pTable", "type": "DataTable*"}])
    assert fz.check_param_mismatch(b) == []


def test_param_mismatch_case_insensitive_names_match():
    b = _bundle(plate=PLATE_TWO_PARAMS,
                params=[{"name": "nrecordid", "type": "int"},
                        {"name": "PTABLE", "type": "DataTable*"}])
    assert fz.check_param_mismatch(b) == []


def test_param_mismatch_implicit_lines_are_not_claims():
    plate = """Does the thing.

Parameters:
  nRecordId: int - identifier
  in_EAX: (implicit / not in signature) - implicit register operand
"""
    b = _bundle(plate=plate, params=[{"name": "nRecordId", "type": "int"}])
    assert fz.check_param_mismatch(b) == []


def test_param_mismatch_no_plate_params_is_silent():
    assert fz.check_param_mismatch(_bundle(plate="Just a summary.")) == []


# --------------------------------------------- F2 convention_contradiction --

def test_cdecl_with_ret_n_is_tier1():
    b = _bundle(calling_convention="__cdecl",
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET 0x4"))
    f = fz.check_convention(b)
    assert _ids(f) == ["convention_contradiction"]
    assert f[0].tier == fz.TIER_MECHANICAL


def test_stdcall_with_bare_ret_and_stack_args_is_tier1():
    b = _bundle(calling_convention="__stdcall",
                params=[{"name": "a", "type": "int"}],
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET"))
    f = fz.check_convention(b)
    assert _ids(f) == ["convention_contradiction"]
    assert f[0].tier == fz.TIER_MECHANICAL


def test_stdcall_zero_args_bare_ret_is_legitimate():
    b = _bundle(calling_convention="__stdcall", params=[],
                disasm_text=_dis("MOV EAX,0x1", "RET"))
    assert fz.check_convention(b) == []


def test_fastcall_reg_args_do_not_need_cleanup():
    """fastcall with <=2 args passes everything in ECX/EDX -- bare RET is right."""
    b = _bundle(calling_convention="__fastcall",
                params=[{"name": "a", "type": "int"}, {"name": "b", "type": "int"}],
                disasm_text=_dis("MOV EAX,ECX", "ADD EAX,EDX", "RET"))
    assert fz.check_convention(b) == []


def test_multiple_ret_immediates_are_undetermined():
    """Paths that pop different amounts mean the disassembly is being misread
    (shared epilogue / two functions) -- report nothing, never guess."""
    b = _bundle(calling_convention="__cdecl",
                disasm_text=_dis("MOV EAX,0x1", "RET 0x4", "XOR EAX,EAX", "RET 0x8"))
    assert fz.check_convention(b) == []


def test_matching_stdcall_is_clean():
    b = _bundle(calling_convention="__stdcall",
                params=[{"name": "a", "type": "int"}],
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET 0x4"))
    assert fz.check_convention(b) == []


def test_undeclared_convention_is_silent():
    b = _bundle(calling_convention="",
                disasm_text=_dis("MOV EAX,0x1", "RET 0x8"))
    assert fz.check_convention(b) == []


# ------------------------------------------------- F3 arity_contradiction ---

def test_stdcall_argc_mismatch_is_tier1():
    """The eip=0x140 class: manifest says 1 arg, RET 0x8 says 2."""
    b = _bundle(calling_convention="__stdcall",
                params=[{"name": "a", "type": "int"}],
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET 0x8"))
    f = fz.check_arity(b)
    assert _ids(f) == ["arity_contradiction"]
    assert f[0].tier == fz.TIER_MECHANICAL
    assert f[0].detail["real_stack_slots"] == 2


def test_fastcall_register_args_reduce_expected_cleanup():
    """3 declared fastcall args -> 1 on the stack -> RET 0x4 is a MATCH."""
    b = _bundle(calling_convention="__fastcall",
                params=[{"name": "a"}, {"name": "b"}, {"name": "c"}],
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET 0x4"))
    assert fz.check_arity(b) == []


def test_thiscall_this_rides_ecx():
    """2 declared thiscall params (this + one) -> RET 0x4 expected."""
    b = _bundle(calling_convention="__thiscall",
                params=[{"name": "this"}, {"name": "a"}],
                disasm_text=_dis("MOV EAX,dword ptr [ECX + 0x8]", "RET 0x4"))
    assert fz.check_arity(b) == []


def test_arity_bare_ret_defers_to_convention_check():
    """obs==0 with declared stack args is the cdecl-shape contradiction --
    convention_contradiction owns it; arity must not double-report."""
    b = _bundle(calling_convention="__stdcall",
                params=[{"name": "a", "type": "int"}],
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET"))
    assert fz.check_arity(b) == []
    assert fz.check_convention(b), "the convention check must own this shape"


def test_arity_varargs_is_undetermined():
    b = _bundle(calling_convention="__stdcall",
                params=[{"name": "fmt", "type": "char*"}],
                prototype="int Foo(char* fmt, ...)",
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET 0x8"))
    assert fz.check_arity(b) == []


def test_arity_cdecl_is_out_of_scope():
    b = _bundle(calling_convention="__cdecl",
                params=[{"name": "a"}, {"name": "b"}],
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET"))
    assert fz.check_arity(b) == []


# ------------------------------------------------ F4 return_contradiction ---

def test_void_prototype_with_plate_return_value_is_tier2():
    plate = "Does a thing.\n\nReturns:\n  int: count of records\n"
    b = _bundle(return_type="void", plate=plate)
    f = fz.check_return(b)
    assert _ids(f) == ["return_contradiction"]
    assert f[0].tier == fz.TIER_REVIEW


def test_nonvoid_prototype_with_plate_void_is_tier2():
    plate = "Does a thing.\n\nReturns:\n  void\n"
    b = _bundle(return_type="int", plate=plate,
                disasm_text=_dis("MOV EAX,0x1", "RET"))
    f = fz.check_return(b)
    assert _ids(f) == ["return_contradiction"]


def test_declared_return_never_produced_in_leaf_is_tier2():
    b = _bundle(return_type="int", plate="",
                disasm_text=_dis("MOV ECX,dword ptr [ESP + 0x4]",
                                 "MOV dword ptr [0x6fdef0a8],ECX", "RET 0x4"))
    f = fz.check_return(b)
    assert _ids(f) == ["return_contradiction"]
    assert "never produced" in f[0].evidence


def test_return_via_call_is_not_flagged():
    """A CALL sets EAX invisibly -- the leaf-only guard must suppress."""
    b = _bundle(return_type="int", plate="",
                disasm_text=_dis("CALL 0x6fd52000", "RET 0x4"))
    assert fz.check_return(b) == []


def test_float_return_rides_st0_not_eax():
    b = _bundle(return_type="float", plate="",
                disasm_text=_dis("FLD dword ptr [ESP + 0x4]", "RET 0x4"))
    assert fz.check_return(b) == []


def test_matching_return_is_clean():
    plate = "Does a thing.\n\nReturns:\n  int: the count\n"
    b = _bundle(return_type="int", plate=plate,
                disasm_text=_dis("MOV EAX,dword ptr [0x6fdef0a8]", "RET"))
    assert fz.check_return(b) == []


# -------------------------------------------- F5 name_verb_contradiction ----

def test_getter_writing_a_global_is_tier2():
    b = _bundle(name="DATATBLS_GetRecordCount",
                disasm_text=_dis("MOV EAX,dword ptr [0x6fdef0a8]",
                                 "MOV dword ptr [0x6fdef0b0],EAX", "RET"))
    f = fz.check_name_verb(b)
    assert _ids(f) == ["name_verb_contradiction"]
    assert f[0].tier == fz.TIER_REVIEW
    assert "0x6fdef0b0" in f[0].detail["written_globals"]


def test_pure_getter_is_clean():
    b = _bundle(name="DATATBLS_GetRecordCount",
                disasm_text=_dis("MOV EAX,dword ptr [0x6fdef0a8]", "RET"))
    assert fz.check_name_verb(b) == []


def test_caching_getter_is_exempt():
    b = _bundle(name="GetOrCreateContext",
                disasm_text=_dis("MOV EAX,dword ptr [0x6fdef0a8]",
                                 "MOV dword ptr [0x6fdef0b0],EAX", "RET"))
    assert fz.check_name_verb(b) == []


def test_out_param_getter_is_exempt_automatically():
    """Writes through pointer params are register-relative, not absolute --
    the global-write scan cannot see them, so no false accusation."""
    b = _bundle(name="UNITS_GetCoords",
                disasm_text=_dis("MOV ECX,dword ptr [ESP + 0x4]",
                                 "MOV dword ptr [ECX],EAX",
                                 "MOV dword ptr [ECX + 0x4],EDX", "RET 0x4"))
    assert fz.check_name_verb(b) == []


def test_setter_that_writes_nothing_is_tier2():
    b = _bundle(name="D2CLIENT_SetVideoFlag",
                disasm_text=_dis("MOV EAX,0x1", "RET"))
    f = fz.check_name_verb(b)
    assert _ids(f) == ["name_verb_contradiction"]


def test_setter_that_delegates_is_exempt():
    b = _bundle(name="D2CLIENT_SetVideoFlag",
                disasm_text=_dis("CALL 0x6fd52000", "RET"))
    assert fz.check_name_verb(b) == []


def test_setter_writing_a_global_is_clean():
    b = _bundle(name="D2CLIENT_SetVideoFlag",
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]",
                                 "MOV dword ptr [0x6fdef0a8],EAX", "RET 0x4"))
    assert fz.check_name_verb(b) == []


def test_auto_names_carry_no_claims():
    b = _bundle(name="FUN_6fd51000",
                disasm_text=_dis("MOV dword ptr [0x6fdef0a8],EAX", "RET"))
    assert fz.check_name_verb(b) == []


# ------------------------------------------------------ F7 phantom_callee ---

PLATE_PHANTOM = """Sorts the elements table.

Algorithm:
  1. Call DATATBLS_CompareRecords for each pair.
  2. Swap via UNITS_SwapPositions.

Parameters:
  pTable: DataTable* - table to sort
"""


def test_phantom_callee_fires_on_uncalled_mentions():
    b = _bundle(name="DATATBLS_SortElements", plate=PLATE_PHANTOM,
                params=[{"name": "pTable", "type": "DataTable*"}],
                callees=["DATATBLS_CompareRecords"])
    f = fz.check_phantom_callee(b)
    assert _ids(f) == ["phantom_callee"]
    assert f[0].tier == fz.TIER_REVIEW
    assert f[0].detail["phantom"] == ["UNITS_SwapPositions"]


def test_phantom_callee_clean_when_all_mentions_called():
    b = _bundle(name="DATATBLS_SortElements", plate=PLATE_PHANTOM,
                callees=["DATATBLS_CompareRecords", "UNITS_SwapPositions"])
    assert fz.check_phantom_callee(b) == []


def test_phantom_callee_needs_callee_data():
    b = _bundle(name="DATATBLS_SortElements", plate=PLATE_PHANTOM)
    assert fz.check_phantom_callee(b) == [], "no callee data -> no accusation"


def test_phantom_callee_is_disabled_by_default():
    assert "phantom_callee" not in fz.enabled_check_ids()
    assert "phantom_callee" in fz.enabled_check_ids(enable=["phantom_callee"])


# ------------------------------------------------------------- harness ------

def test_run_checks_survives_a_broken_check(monkeypatch, capsys):
    """A crashing check prints loudly and is skipped -- never fatal."""
    def boom(bundle):
        raise RuntimeError("synthetic check failure")
    monkeypatch.setitem(fz.ALL_CHECKS, "param_mismatch", boom)
    b = _bundle(calling_convention="__cdecl",
                disasm_text=_dis("MOV EAX,0x1", "RET 0x4"))
    f = fz.run_checks(b)
    assert "convention_contradiction" in _ids(f), "other checks still run"
    assert "synthetic check failure" in capsys.readouterr().err


def test_summarize_and_tier1():
    b = _bundle(calling_convention="__cdecl",
                params=[{"name": "a", "type": "int"}],
                plate=PLATE_TWO_PARAMS,
                disasm_text=_dis("MOV EAX,dword ptr [ESP + 0x4]", "RET 0x4"))
    f = fz.run_checks(b)
    s = fz.summarize(f)
    assert s["tier1"] >= 1
    assert s["tier1"] == len(fz.tier1(f))
    assert set(s["check_ids"]) <= set(fz.ALL_CHECKS)


def test_finding_round_trips_to_dict():
    b = _bundle(calling_convention="__cdecl",
                disasm_text=_dis("MOV EAX,0x1", "RET 0x4"))
    d = fz.check_convention(b)[0].to_dict()
    assert d["check_id"] == "convention_contradiction"
    assert d["tier"] == 1
    assert isinstance(d["detail"], dict)


# ------------------------------------ false positives found by the corpus ---
# Every case below is a REAL finding the first whole-corpus dry-run produced
# (2026-08-02, 4 scannable binaries, 107 findings) that hand-verification
# against live disassembly showed to be wrong. Tier-1 findings carry
# consequences, so each of these is a guard, not a preference.

def test_implicit_marker_in_description_is_not_a_signature_claim():
    """D2MCPClient `StoreSehContext`: the plate documents a REGISTER input and
    says so ("passed in EAX [IMPLICIT]"). Reading it as a claim about a
    nonexistent formal parameter was a tier-1 false accusation."""
    plate = ("Stores SEH context.\n\nParameters:\n"
             "  dwExceptionContext: uint - exception context value passed in "
             "EAX [IMPLICIT]\n")
    b = _bundle(plate=plate, params=[])
    assert fz.check_param_mismatch(b) == []


def test_param_mismatch_names_the_stale_side():
    """When the callee's own cleanup implies at least as many slots as the
    plate documents, the SIGNATURE is stale — the evidence has to say so or
    the fixer deletes correct prose to satisfy a wrong prototype."""
    plate = ("Stores it.\n\nParameters:\n"
             "  dwContext: uint - the context dword\n")
    b = _bundle(plate=plate, params=[], calling_convention="__stdcall",
                disasm_text=_dis("MOV ECX,dword ptr [ESP + 0x4]", "RET 0x4"))
    f = fz.check_param_mismatch(b)
    assert len(f) == 1 and f[0].tier == fz.TIER_MECHANICAL
    assert "SIGNATURE is the stale side" in f[0].evidence


def test_undefined_prototype_return_asserts_nothing():
    """SmackW32 `SMACK_InitializeDecodeState`: plate correctly says the
    function returns nothing; Ghidra simply never inferred a return type
    (`undefined`). An absence of information is not a contradiction."""
    plate = "Initializes state.\n\nReturns:\n  void: No return value.\n"
    b = _bundle(return_type="undefined", plate=plate,
                disasm_text=_dis("MOV EAX,0x1", "RET"))
    assert fz.check_return(b) == []
    # ...and the inverse direction is equally uninformative.
    plate2 = "Reads it.\n\nReturns:\n  uint: the value\n"
    assert fz.check_return(_bundle(return_type="undefined", plate=plate2,
                                   disasm_text=_dis("MOV EAX,0x1", "RET"))) == []


def test_import_thunk_is_delegation_not_a_broken_setter():
    """D2MCPClient `WriteDataWithSizeVerification` / `SetGameStateFields` are
    one-instruction IAT thunks: `JMP dword ptr [0x...]`. The mutation happens
    through the import — a tail call is delegation exactly like a CALL."""
    for name in ("WriteDataWithSizeVerification", "SetGameStateFields"):
        b = _bundle(name=name,
                    disasm_text=_dis("JMP dword ptr [0x6fa28014]"))
        assert fz.check_name_verb(b) == [], f"{name} is a thunk, not a defect"


def test_real_broken_setter_still_fires_after_the_thunk_guard():
    """The thunk guard must not disarm the check it guards."""
    b = _bundle(name="D2CLIENT_SetVideoFlag",
                disasm_text=_dis("MOV EAX,0x1", "RET"))
    assert _ids(fz.check_name_verb(b)) == ["name_verb_contradiction"]

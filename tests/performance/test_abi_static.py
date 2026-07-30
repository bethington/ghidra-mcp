"""Offline unit tests for abi_static.py.

abi_static derives ground-truth ABI facts from a function's disassembly and
translates pure getters to C -- all static string analysis, no Ghidra/oracle.
The module ships a known-answer corpus (`_CORPUS`) + `_selftest()` that pins the
derive_abi / translator contracts; we run it here so the corpus is a CI gate,
plus a few direct checks on the smaller pure helpers.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))

import abi_static as abi  # noqa: E402


def test_selftest_known_answer_corpus_passes():
    # Exercises derive_abi across the whole _CORPUS + the getter translators +
    # abort detection. Returns 0 on success; asserts internally otherwise.
    assert abi._selftest() == 0


def test_parse_disasm_shape():
    text = (
        "6fd70000: MOV EAX,dword ptr [ESP + 0x4]\n"
        "6fd70004: TEST EAX,EAX\n"
        "6fd70006: RET 0x4\n"
    )
    rows = abi.parse_disasm(text)
    assert rows[0] == (0x6FD70000, "MOV", "EAX,dword ptr [ESP + 0x4]")
    assert rows[1][1] == "TEST"
    assert rows[2] == (0x6FD70006, "RET", "0x4")
    # blank / non-matching lines are dropped
    assert abi.parse_disasm("") == []
    assert abi.parse_disasm("not a disasm line") == []


def test_regs_in_normalizes_subregisters():
    # sub-registers fold to their parent 32-bit GP register
    regs = abi._regs_in("MOV AL,byte ptr [ECX + 0x8]")
    assert "ECX" in regs
    assert "EAX" in regs  # AL -> EAX
    assert abi._regs_in("") == set()


def test_detect_abort_path():
    assert abi.detect_abort_path("/* WARNING: Subroutine does not return */ _exit(-1);")
    assert abi.detect_abort_path("CleanupAndAbort();")
    assert not abi.detect_abort_path("return pRecords[idx].nField;")


def test_clamp_abort_vectors_keeps_in_range_and_backfills():
    # returns (surviving_vectors, count). A mix: only the in-range vector survives.
    kept, _n = abi.clamp_abort_vectors([{"idx": 3}, {"idx": 9999}], max_index=32)
    assert {"idx": 3} in kept
    assert {"idx": 9999} not in kept
    # all out-of-range -> a dense in-range sweep is synthesized (non-empty, in range)
    synth, _m = abi.clamp_abort_vectors([{"idx": 9999}], max_index=8)
    assert synth, "must backfill an in-range sweep when nothing survives"
    assert all(0 <= list(v.values())[0] for v in synth)


def test_derive_abi_reg_args_preserve_program_order_not_alphabetical():
    """2026-07-25: derive_abi() used to return reg_args via sorted(set(...)) --
    alphabetical register-NAME order, which has nothing to do with a compiler's
    actual argument order for a register_explicit ABI. apply_static_abi() maps
    reg_args[idx] positionally onto the model's declared parameters, so an
    alphabetical mix-up assigns the wrong register to the wrong parameter and
    the live oracle SEH-faults calling the real function with garbage in the
    wrong register (confirmed live: DATATBLS_TestSkillDescriptionFlag and
    GetElemTypeRecord both hit live_prove_failed[marshal_fault] this way).

    This function reads ESI first, then EAX second -- alphabetically EAX
    sorts before ESI, so the old code would report ["EAX", "ESI"], backwards
    from the true ["ESI", "EAX"] read order.
    """
    text = (
        "6fd80000: CMP ESI,0x0\n"
        "6fd80004: CMP EAX,0x1\n"
        "6fd80008: MOV EAX,ESI\n"
        "6fd8000c: RET 0x0\n"
    )
    result = abi.derive_abi(text)
    assert result["callconv"] == "register_explicit"
    assert result["reg_args"] == ["ESI", "EAX"], (
        f"expected program-order ['ESI', 'EAX'], got {result['reg_args']} "
        "(alphabetical order would wrongly give ['EAX', 'ESI'])"
    )


def test_apply_static_abi_maps_registers_in_program_order():
    """End-to-end: apply_static_abi must assign the model's declared parameters
    to registers in the disasm's TRUE read order, not alphabetical order."""
    static_abi = {
        "ret_imm": 0, "slots": 0, "callconv": "register_explicit",
        "reg_args": ["ESI", "EAX"],  # true program order: arg1=ESI, arg2=EAX
    }
    layout = {"inputs": [
        {"name": "param1", "register": "ECX"},  # model's wrong initial guess
        {"name": "param2", "register": "EDX"},
    ]}
    fixed_layout, _input_sets, notes = abi.apply_static_abi(layout, [], static_abi)
    regs = [i["register"] for i in fixed_layout["inputs"]]
    assert regs == ["ESI", "EAX"], (
        f"expected param1->ESI (true first arg), param2->EAX; got {regs}. "
        "An alphabetical-order regression would produce ['EAX', 'ESI'] instead, "
        "silently swapping the two arguments."
    )
    assert notes  # both inputs' registers were forced -> notes recorded


def test_apply_static_abi_pads_underdeclared_register_args():
    """2026-07-25: when the disasm reads MORE registers as incoming args than
    the model declared parameters for, the extra registers used to be silently
    dropped from the oracle spec entirely -- the oracle then called the
    ORIGINAL with whatever garbage was sitting in those registers, a
    guaranteed marshal_fault. Confirmed live: LIST_DetachNode (disasm reads
    ESI, EAX, EDI; model only declared one param 'pListNode') and
    UnlinkAndClearListNodes hit live_prove_failed[marshal_fault] this way
    even after the reg_args program-order fix, because the register-count
    mismatch is a separate bug from ordering.

    apply_static_abi must pad the layout with synthetic zero-valued params
    for every register the model didn't account for, mirroring the existing
    stdcall slot-padding a few lines below."""
    static_abi = {
        "ret_imm": 0, "slots": 0, "callconv": "register_explicit",
        "reg_args": ["ESI", "EAX", "EDI"],  # 3 true incoming args
    }
    layout = {"inputs": [{"name": "pListNode", "register": "EAX"}]}  # model saw only 1
    input_sets = [{"pListNode": 100}, {"pListNode": 200}]

    fixed_layout, fixed_sets, notes = abi.apply_static_abi(layout, input_sets, static_abi)

    regs = [i["register"] for i in fixed_layout["inputs"]]
    assert regs == ["ESI", "EAX", "EDI"], (
        f"expected all 3 true registers declared in program order, got {regs}"
    )
    assert len(fixed_layout["inputs"]) == 3, "under-declared registers must be padded, not dropped"
    for s in fixed_sets:
        assert "unusedReg2" in s and "unusedReg3" in s, (
            f"padded params must appear in every input_set so the marshal has a value "
            f"for every register; got {s}"
        )
        assert s["unusedReg2"] == 0 and s["unusedReg3"] == 0
    assert any("padded" in n for n in notes)


def test_resolve_reverse_map_parses_gen_header(tmp_path):
    # address(int) -> name, parsed from the `{ "name", 0xADDRu }` initializer table.
    hdr = tmp_path / "resolve.gen.h"
    hdr.write_text(
        'static const Entry kTable[] = {\n'
        '  { "FOG_10021_BSearch", 0x6fd59240u },\n'
        '  { "D2Common_10426_GetItemsBin", 0x6fdefb94u },\n'
        '};\n',
        encoding="utf-8",
    )
    rev = abi.resolve_reverse_map(str(hdr))
    assert rev[0x6FD59240] == "FOG_10021_BSearch"
    assert rev[0x6FDEFB94] == "D2Common_10426_GetItemsBin"


def test_negative_displacement_is_not_a_global():
    """Ghidra renders a NEGATIVE displacement as unsigned 32-bit hex, so
    `[ECX + 0xfffffd94]` (really ECX - 620) used to clear the image-range floor
    and be collected as a data global. Nothing can ever wire that address, so
    the candidate parked forever on a blocker that did not exist -- this was 10
    of the 13 functions still blocked after the 2026-07-28 whole-program wiring
    pass (real case: CLIENT_IsPointInScrollDownArrowRegion @6fac0f70)."""
    text = (
        "6fac0f70: MOV ECX,dword ptr [0x6fb8bc48]\n"
        "6fac0f76: LEA EAX,[ECX + 0xfffffd94]\n"
        "6fac0f7c: RET\n"
    )
    a = abi.derive_abi(text)
    assert 0xFFFFFD94 not in a["data_globals"], a["data_globals"]
    # the genuine absolute deref on the first line is still picked up
    assert 0x6FB8BC48 in a["data_globals"], a["data_globals"]


def test_image_range_displacement_global_still_detected():
    """The upper bound must not cost us real array-base globals addressed as a
    displacement (the case _DISP_GLOBAL_RE exists for)."""
    text = "6fd70000: MOV AL,byte ptr [EAX + 0x6fdef0a8]\n6fd70006: RET\n"
    a = abi.derive_abi(text)
    assert 0x6FDEF0A8 in a["data_globals"], a["data_globals"]


def test_resolve_reverse_map_refreshes_when_the_table_changes(tmp_path, monkeypatch):
    """The dashboard process is long-lived. If the resolve map were cached
    forever, a wiring pass would be invisible to already-running workers and
    every freshly-wired name would read back as "unknown" -- which on
    2026-07-28 turned into false `unresolvable_global_defer`s that parked
    candidates whose globals were already in the table on disk."""
    gen = tmp_path / "D2Common_ResolveTable.gen.h"
    gen.write_text(
        'static const D2MOO_ResolveEntry g_d2moo_resolve_table[] = {\n'
        '\t{ "g_first", 0x6fd50000u },\n};\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(abi, "_RESOLVE_GEN", str(gen))
    monkeypatch.setattr(abi, "_RESOLVE_REV", None)
    monkeypatch.setattr(abi, "_RESOLVE_REV_STAMP", None)

    first = abi.resolve_reverse_map()
    assert first == {0x6FD50000: "g_first"}
    # cached while unchanged (same object, no re-parse)
    assert abi.resolve_reverse_map() is first

    gen.write_text(
        'static const D2MOO_ResolveEntry g_d2moo_resolve_table[] = {\n'
        '\t{ "g_first", 0x6fd50000u },\n'
        '\t{ "g_added_later", 0x6fd50004u },\n};\n',
        encoding="utf-8",
    )
    # bump the stamp explicitly: mtime granularity can hide a same-second write
    os.utime(gen, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))

    after = abi.resolve_reverse_map()
    assert after[0x6FD50004] == "g_added_later", after
    assert set(after.values()) == {"g_first", "g_added_later"}

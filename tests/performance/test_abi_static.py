"""Offline unit tests for abi_static.py.

abi_static derives ground-truth ABI facts from a function's disassembly and
translates pure getters to C -- all static string analysis, no Ghidra/oracle.
The module ships a known-answer corpus (`_CORPUS`) + `_selftest()` that pins the
derive_abi / translator contracts; we run it here so the corpus is a CI gate,
plus a few direct checks on the smaller pure helpers.
"""

from __future__ import annotations

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

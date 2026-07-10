"""Offline unit tests for fast_path.py.

fast_path routes a decompiled/disassembled getter to a (class, reimpl, prover)
without touching Ghidra or the oracle -- the routing (`classify_and_draft`) is
pure string analysis. The module's `_selftest()` drives canned disasm through
the router; we run it as a CI gate, plus direct checks on the small helpers.
"""

from __future__ import annotations

import sys
from pathlib import Path

FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))

import fast_path as fp  # noqa: E402


def test_selftest_routing_passes():
    # Routes canned flat/two-level getters (no oracle/Ghidra); asserts internally.
    assert fp._selftest() == 0


def test_flat_gated_getter_routes_to_synth():
    flat = (
        "6fd70000: MOV EAX,dword ptr [ESP + 0x4]\n"
        "6fd70004: TEST EAX,EAX\n"
        "6fd70006: JZ 0x6fd70012\n"
        "6fd70008: MOV EAX,dword ptr [EAX + 0x40]\n"
        "6fd7000c: RET 0x4\n"
        "6fd70012: XOR EAX,EAX\n"
        "6fd70014: RET 0x4\n"
    )
    r = fp.classify_and_draft("SomeFlagGetter", "", flat)
    assert r["cls"] == "flat"
    assert r["prover"] == "synth"


def test_two_level_nonzero_default_routes_to_synth2():
    gq = (
        "6fd73b40: MOV EAX,dword ptr [ESP + 0x4]\n"
        "6fd73b44: TEST EAX,EAX\n6fd73b46: JZ 0x6fd73b59\n"
        "6fd73b48: CMP dword ptr [EAX],0x4\n6fd73b4b: JNZ 0x6fd73b59\n"
        "6fd73b4d: MOV EAX,dword ptr [EAX + 0x14]\n6fd73b50: TEST EAX,EAX\n"
        "6fd73b52: JZ 0x6fd73b59\n6fd73b54: MOV EAX,dword ptr [EAX]\n"
        "6fd73b56: RET 0x4\n6fd73b59: MOV EAX,0x2\n6fd73b5e: RET 0x4\n"
    )
    r = fp.classify_and_draft("ITEMS_GetItemQuality", "", gq)
    assert r["cls"] == "two_level"
    assert r["prover"] == "synth2"


def test_addr_hex_normalizes():
    assert fp._addr_hex(0x6FD70000) == "0x6fd70000"
    assert fp._addr_hex("0x6fd70000") == "0x6fd70000"


def test_name_of_skips_keywords_and_null_guards():
    dec = "int __fastcall DATATBLS_GetItemTypeThrowable(int idx)\n{\n  if (idx == 0) return 0;\n}"
    assert fp._name_of(dec) == "DATATBLS_GetItemTypeThrowable"
    # a naive regex grabs `if`/`return`; _name_of must skip stop-words
    assert fp._name_of("if (x) { return NULL; }") != "if"

"""Generate the deploy-regression benchmark fixture.

Produces two 32-bit PE images next to this file:

``Benchmark.dll``
    The read/write/negative/multi-program subject. Exports eleven functions
    with deliberately varied shapes -- a nested-loop CRC with recognisable
    constants, a division loop, a null-scan, a state ladder with many basic
    blocks, a four-parameter mutator and four one-parameter accessors.

``BenchmarkDebug.exe``
    A runnable console debuggee for the ``debugger-live`` tier. Run with no
    arguments it computes the CRC of its own banner string and returns it as
    the process exit code -- which is how this fixture proves its own machine
    code is correct without a debugger, a disassembler or Ghidra. Run with any
    argument containing ``-`` it sleeps for three minutes so something can
    attach to it.

Why generated rather than compiled
----------------------------------
The previous fixture was compiled from C by a pinned, licensed MSVC 6 / VS2003
toolchain that lived outside the repository, and both the toolchain and the
build outputs were gitignored. When ``fun-doc/`` moved to another repository on
2026-08-10 the fixture went with it and six of the eight deploy-regression
tiers have raised ever since. Nothing about that arrangement could survive a
directory move, and nothing about it worked on a machine without the media.

This generator has no inputs but its own source. It emits byte-identical
images on any machine with a Python interpreter, so the committed binaries can
be checked against a fresh regeneration in CI -- and so the addresses in
``regression/*.yaml`` are a property of code under review rather than an
observation of whatever compiler happened to be installed.

The old baseline recorded the trap this replaces, in its own header comment:
a 2026-08-08 toolchain switch moved every function in the binary while the C
sources were untouched, and ``build_manifest.json`` was the only way to tell
which toolchain had produced it. Here the layout is deterministic, the manifest
is still written, and ``tests/unit/test_benchmark_fixture.py`` fails offline if
the YAML baseline and the binary ever disagree about an address.

Usage::

    python tests/fixtures/benchmark/make_fixture.py            # regenerate
    python tests/fixtures/benchmark/make_fixture.py --check    # verify only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import pe32  # type: ignore
    import x86  # type: ignore
    from x86 import EAX, EBP, ECX, EDX, ESP, DL, Assembler  # type: ignore
else:  # pragma: no cover - import style depends on how the module is loaded
    from . import pe32, x86
    from .x86 import EAX, EBP, ECX, EDX, ESP, DL, Assembler

FIXTURE_DIR = Path(__file__).resolve().parent
GENERATOR_VERSION = "1.0.0"

DLL_NAME = "Benchmark.dll"
EXE_NAME = "BenchmarkDebug.exe"
DLL_IMAGE_BASE = 0x10000000
EXE_IMAGE_BASE = 0x00400000

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
DATA_RVA = 0x3000

SUBSYSTEM_GUI = 2
SUBSYSTEM_CONSOLE = 3

BANNER = "GhidraMCP benchmark fixture"
DESCRIBE = "benchmark: deterministic PE32 regression subject, generator 1.0.0"

# Strings that assertions may name. Everything here is intentional; the
# `filler` block below exists only to give /list_strings a population worth
# counting, the way a real binary's CRT does.
NAMED_STRINGS: list[tuple[str, str]] = [
    ("str_banner", BANNER),
    ("str_describe", DESCRIBE),
    ("str_calling_convention", "benchmark functions use __cdecl"),
    ("str_parser_open", "parser: expected an opening brace"),
    ("str_parser_string", "parser: unterminated string literal"),
    ("str_parser_colon", "parser: expected a colon after the key"),
    ("str_parser_done", "parser: reached the accepting state"),
    ("str_stat_null", "stat_list_add: null list argument rejected"),
    ("str_stat_ok", "stat_list_add: entry appended to the list"),
    ("str_crc_poly", "crc16: CCITT polynomial 0x1021, seed 0xFFFF"),
    ("str_gcd", "gcd: Euclidean remainder loop, unsigned"),
    ("str_strlen", "strlen: scan to the null terminator"),
    ("str_selftest", "self test: crc + gcd + strlen composed"),
    ("str_tick", "tick counter sampled from KERNEL32"),
    ("str_debuggee_idle", "debuggee: sleeping so a debugger can attach"),
    ("str_debuggee_exit", "debuggee: returning the banner crc as exit code"),
    ("str_license", "Apache-2.0, part of the ghidra-mcp test fixtures"),
    ("str_regen", "regenerate with tests/fixtures/benchmark/make_fixture.py"),
    ("str_manifest", "provenance is recorded in build_manifest.json"),
    ("str_no_toolchain", "no compiler was involved in producing this image"),
    ("str_addresses", "addresses are fixed by the generator, not observed"),
    ("str_sections", "sections: .text, .rdata, .data"),
    ("str_arch", "architecture x86, 32-bit, little endian"),
    ("str_purpose", "purpose: deploy regression subject for tools.setup"),
    ("str_dll_name", DLL_NAME),
    ("str_export_name", "calc_crc16"),
]

FILLER_COUNT = 40


def _filler_strings() -> list[tuple[str, str]]:
    return [
        (f"str_filler_{index:02d}",
         f"benchmark filler string {index:02d}: deterministic table padding")
        for index in range(FILLER_COUNT)
    ]


GLOBALS: list[tuple[str, int, int]] = [
    # (symbol, size in bytes, initial dword value repeated across the extent)
    ("g_benchmark_version", 4, 0x00070000),
    ("g_stat_add_count", 4, 0),
    ("g_last_tick", 4, 0),
    ("g_self_test_result", 4, 0),
    ("g_parser_transitions", 4, 0),
    ("g_stat_list_table", 64, 0),
]

IMPORTS = [
    pe32.ImportedDll(
        name="KERNEL32.dll",
        functions=[
            "ExitProcess",
            "GetCommandLineA",
            "GetProcAddress",
            "GetTickCount",
            "LoadLibraryA",
            "Sleep",
        ],
    )
]

# Exported, in the order they are laid out in .text. The manifest and the YAML
# baseline both read this order, so moving an entry moves an address and the
# offline test says so.
EXPORTED_FUNCTIONS = [
    "calc_crc16",
    "compute_gcd",
    "compute_str_len",
    "advance_parser_state",
    "stat_list_add",
    "get_stat_list_flags",
    "get_stat_list_layer",
    "get_stat_list_owner_guid",
    "get_stat_list_prev_link",
    "benchmark_self_test",
    "benchmark_describe",
]


def reference_crc16(data: bytes) -> int:
    """The CRC-16/CCITT the generated ``calc_crc16`` computes.

    Kept here so the test suite can check the emitted machine code by running
    ``BenchmarkDebug.exe`` and comparing its exit code against this function.
    """
    crc = 0xFFFF
    for byte in data:
        crc = (crc ^ (byte << 8)) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# Function bodies
# ---------------------------------------------------------------------------

def _emit_calc_crc16(asm: Assembler) -> None:
    """unsigned short calc_crc16(const unsigned char *data, unsigned len)

    Nested loops, five recovered variables, and the two constants that make a
    CRC-16/CCITT recognisable (0x1021, 0xFFFF). This is the function the deploy
    tests look for by name, and the one the write tier renames and retypes, so
    it deliberately keeps crc/i/j in stack slots rather than registers: the
    write tier needs a named, non-phantom local to operate on.
    """
    asm.label("calc_crc16")
    asm.enter_frame(12)
    asm.mov_local_imm32(-4, 0xFFFF)          # crc
    asm.mov_local_imm32(-8, 0)               # i
    asm.label("crc_outer")
    asm.mov_reg_local(EAX, -8)
    asm.cmp_reg_local(EAX, 0x0C)             # i < len
    asm.jcc("nb", "crc_done")
    asm.mov_reg_local(ECX, 0x08)             # data
    asm.add_reg_reg(ECX, EAX)
    asm.movzx_reg_byte_mem(EDX, ECX, 0)
    asm.shl_reg_imm8(EDX, 8)
    asm.mov_reg_local(EAX, -4)
    asm.xor_reg_reg(EAX, EDX)
    asm.and_reg_imm32(EAX, 0xFFFF)
    asm.mov_local_reg(-4, EAX)
    asm.mov_local_imm32(-12, 0)              # j
    asm.label("crc_inner")
    asm.cmp_local_imm32(-12, 8)
    asm.jcc("nb", "crc_inner_done")
    asm.mov_reg_local(EAX, -4)
    asm.test_reg_imm32(EAX, 0x8000)
    asm.jcc("z", "crc_no_xor")
    asm.shl_reg_imm8(EAX, 1)
    asm.xor_reg_imm32(EAX, 0x1021)
    asm.jmp("crc_store")
    asm.label("crc_no_xor")
    asm.shl_reg_imm8(EAX, 1)
    asm.label("crc_store")
    asm.and_reg_imm32(EAX, 0xFFFF)
    asm.mov_local_reg(-4, EAX)
    asm.inc_local(-12)
    asm.jmp("crc_inner")
    asm.label("crc_inner_done")
    asm.inc_local(-8)
    asm.jmp("crc_outer")
    asm.label("crc_done")
    asm.mov_reg_local(EAX, -4)
    asm.leave()
    asm.ret()


def _emit_compute_gcd(asm: Assembler) -> None:
    """unsigned compute_gcd(unsigned a, unsigned b) -- Euclidean remainder."""
    asm.label("compute_gcd")
    asm.enter_frame()
    asm.mov_reg_local(EAX, 0x08)
    asm.mov_reg_local(ECX, 0x0C)
    asm.label("gcd_loop")
    asm.test_reg_reg(ECX, ECX)
    asm.jcc("z", "gcd_done")
    asm.xor_reg_reg(EDX, EDX)
    asm.div_reg(ECX)                         # edx = a % b
    asm.mov_reg_reg(EAX, ECX)
    asm.mov_reg_reg(ECX, EDX)
    asm.jmp("gcd_loop")
    asm.label("gcd_done")
    asm.leave()
    asm.ret()


def _emit_compute_str_len(asm: Assembler) -> None:
    """unsigned compute_str_len(const char *s) -- scan to the terminator."""
    asm.label("compute_str_len")
    asm.enter_frame()
    asm.mov_reg_local(ECX, 0x08)
    asm.xor_reg_reg(EAX, EAX)
    asm.label("strlen_loop")
    asm.mov_byte_reg_mem(DL, ECX, 0)
    asm.test_byte_reg(DL, DL)
    asm.jcc("z", "strlen_done")
    asm.inc_reg(EAX)
    asm.inc_reg(ECX)
    asm.jmp("strlen_loop")
    asm.label("strlen_done")
    asm.leave()
    asm.ret()


def _emit_advance_parser_state(asm: Assembler) -> None:
    """int advance_parser_state(int state, int input)

    A five-state ladder. Its only job is to be structurally dense: it is the
    function whose basic-block count and cyclomatic complexity the YAML
    baseline pins, so a change in how the plugin measures either shows up here.
    """
    asm.label("advance_parser_state")
    asm.enter_frame(4)
    asm.mov_reg_local(EAX, 0x08)             # state
    asm.mov_reg_local(ECX, 0x0C)             # input
    asm.cmp_reg_imm32(EAX, 0)
    asm.jcc("nz", "parser_s1")
    asm.cmp_reg_imm32(ECX, 0x7B)             # '{'
    asm.jcc("nz", "parser_stay0")
    asm.mov_reg_imm32(EAX, 1)
    asm.jmp("parser_done")
    asm.label("parser_stay0")
    asm.xor_reg_reg(EAX, EAX)
    asm.jmp("parser_done")

    asm.label("parser_s1")
    asm.cmp_reg_imm32(EAX, 1)
    asm.jcc("nz", "parser_s2")
    asm.cmp_reg_imm32(ECX, 0x22)             # '"'
    asm.jcc("nz", "parser_s1_close")
    asm.mov_reg_imm32(EAX, 2)
    asm.jmp("parser_done")
    asm.label("parser_s1_close")
    asm.cmp_reg_imm32(ECX, 0x7D)             # '}'
    asm.jcc("nz", "parser_stay1")
    asm.mov_reg_imm32(EAX, 4)
    asm.jmp("parser_done")
    asm.label("parser_stay1")
    asm.mov_reg_imm32(EAX, 1)
    asm.jmp("parser_done")

    asm.label("parser_s2")
    asm.cmp_reg_imm32(EAX, 2)
    asm.jcc("nz", "parser_s3")
    asm.cmp_reg_imm32(ECX, 0x22)
    asm.jcc("nz", "parser_stay2")
    asm.mov_reg_imm32(EAX, 3)
    asm.jmp("parser_done")
    asm.label("parser_stay2")
    asm.mov_reg_imm32(EAX, 2)
    asm.jmp("parser_done")

    asm.label("parser_s3")
    asm.cmp_reg_imm32(EAX, 3)
    asm.jcc("nz", "parser_reject")
    asm.cmp_reg_imm32(ECX, 0x3A)             # ':'
    asm.jcc("nz", "parser_stay3")
    asm.mov_reg_imm32(EAX, 1)
    asm.jmp("parser_done")
    asm.label("parser_stay3")
    asm.mov_reg_imm32(EAX, 3)
    asm.jmp("parser_done")

    asm.label("parser_reject")
    asm.mov_reg_imm32(EAX, 0xFFFFFFFF)

    asm.label("parser_done")
    asm.mov_local_reg(-4, EAX)
    asm.mov_reg_global(ECX, "g_parser_transitions")
    asm.inc_reg(ECX)
    asm.mov_global_reg("g_parser_transitions", ECX)
    asm.mov_reg_local(EAX, -4)
    asm.leave()
    asm.ret()


def _emit_stat_list_add(asm: Assembler) -> None:
    """int stat_list_add(void *list, int stat, int value, int flags)

    Four parameters, a null guard and a global counter -- the widest signature
    in the fixture, and the one that keeps ``param_count`` honest.
    """
    asm.label("stat_list_add")
    asm.enter_frame()
    asm.mov_reg_local(EAX, 0x08)
    asm.test_reg_reg(EAX, EAX)
    asm.jcc("z", "stat_add_fail")
    asm.mov_reg_local(ECX, 0x0C)             # stat
    asm.mov_mem_reg(EAX, 0, ECX)
    asm.mov_reg_local(EDX, 0x10)             # value
    asm.mov_mem_reg(EAX, 4, EDX)
    asm.mov_reg_local(EDX, 0x14)             # flags
    asm.or_mem_reg(EAX, 8, EDX)
    asm.mov_reg_global(ECX, "g_stat_add_count")
    asm.inc_reg(ECX)
    asm.mov_global_reg("g_stat_add_count", ECX)
    asm.mov_reg_imm32(EAX, 1)
    asm.jmp("stat_add_done")
    asm.label("stat_add_fail")
    asm.xor_reg_reg(EAX, EAX)
    asm.label("stat_add_done")
    asm.leave()
    asm.ret()


def _emit_accessor(asm: Assembler, name: str, offset: int,
                   shift: int, mask: int | None) -> None:
    """A one-parameter field accessor with a null guard."""
    asm.label(name)
    asm.enter_frame()
    asm.mov_reg_local(ECX, 0x08)
    asm.test_reg_reg(ECX, ECX)
    asm.jcc("z", f"{name}_null")
    asm.mov_reg_mem(EAX, ECX, offset)
    if shift:
        asm.shr_reg_imm8(EAX, shift)
    if mask is not None:
        asm.and_reg_imm32(EAX, mask)
    asm.jmp(f"{name}_done")
    asm.label(f"{name}_null")
    asm.xor_reg_reg(EAX, EAX)
    asm.label(f"{name}_done")
    asm.leave()
    asm.ret()


def _emit_benchmark_self_test(asm: Assembler) -> None:
    """void benchmark_self_test(void)

    Calls three of the exported functions and one import, so those functions
    have inbound cross-references and this one has a non-empty callee list.
    Without it every function in the fixture would be a leaf reached only from
    the export table, and the xref assertions would be vacuous.
    """
    asm.label("benchmark_self_test")
    asm.enter_frame(8)
    asm.call_import("KERNEL32.dll!GetTickCount")
    asm.mov_global_reg("g_last_tick", EAX)

    asm.push_imm32(len(BANNER))
    asm.push_abs("str_banner")
    asm.call("calc_crc16")
    asm.add_reg_imm32(ESP, 8)
    asm.mov_local_reg(-4, EAX)

    asm.push_imm32(48)
    asm.push_imm32(18)
    asm.call("compute_gcd")
    asm.add_reg_imm32(ESP, 8)
    asm.mov_reg_local(ECX, -4)
    asm.add_reg_reg(EAX, ECX)
    asm.mov_local_reg(-4, EAX)

    asm.push_abs("str_describe")
    asm.call("compute_str_len")
    asm.add_reg_imm32(ESP, 4)
    asm.mov_reg_local(ECX, -4)
    asm.add_reg_reg(EAX, ECX)
    asm.mov_global_reg("g_self_test_result", EAX)
    asm.leave()
    asm.ret()


def _emit_benchmark_describe(asm: Assembler) -> None:
    """const char *benchmark_describe(void)"""
    asm.label("benchmark_describe")
    asm.enter_frame()
    asm.mov_reg_abs_addr(EAX, "str_describe")
    asm.leave()
    asm.ret()


def _emit_shared_functions(asm: Assembler) -> None:
    """Emit every exported function, in ``EXPORTED_FUNCTIONS`` order.

    Both images start with this same block, so a function has the same
    *offset* in the DLL and the EXE (the addresses differ only by image base).
    """
    emitters = {
        "calc_crc16": _emit_calc_crc16,
        "compute_gcd": _emit_compute_gcd,
        "compute_str_len": _emit_compute_str_len,
        "advance_parser_state": _emit_advance_parser_state,
        "stat_list_add": _emit_stat_list_add,
        "get_stat_list_flags":
            lambda a: _emit_accessor(a, "get_stat_list_flags", 0x0C, 0, 0xFF),
        "get_stat_list_layer":
            lambda a: _emit_accessor(a, "get_stat_list_layer", 0x0C, 8, 0xFF),
        "get_stat_list_owner_guid":
            lambda a: _emit_accessor(a, "get_stat_list_owner_guid", 0x10, 0, None),
        "get_stat_list_prev_link":
            lambda a: _emit_accessor(a, "get_stat_list_prev_link", 0x14, 0, None),
        "benchmark_self_test": _emit_benchmark_self_test,
        "benchmark_describe": _emit_benchmark_describe,
    }
    if set(emitters) != set(EXPORTED_FUNCTIONS):
        raise AssertionError("EXPORTED_FUNCTIONS and the emitter table disagree")
    for name in EXPORTED_FUNCTIONS:
        emitters[name](asm)
        asm.int3(4)                          # inter-function padding


def _emit_dll_main(asm: Assembler) -> None:
    """BOOL __stdcall DllMain(HINSTANCE, DWORD reason, LPVOID)"""
    asm.label("DllMain")
    asm.enter_frame()
    asm.mov_reg_local(EAX, 0x0C)             # reason
    asm.cmp_reg_imm32(EAX, 1)                # DLL_PROCESS_ATTACH
    asm.jcc("nz", "dllmain_done")
    asm.call("benchmark_self_test")
    asm.label("dllmain_done")
    asm.mov_reg_imm32(EAX, 1)
    asm.leave()
    asm.ret_imm16(12)


def _emit_exe_entry(asm: Assembler) -> None:
    """The console debuggee's entry point.

    No CRT, so this is the real entry: it must never return. Three modes,
    selected by scanning the raw command line:

    ``@`` in the arguments
        Load ``Benchmark.dll``, resolve ``calc_crc16`` through its export
        table, call it, and exit with the result. This is how the offline test
        proves the *DLL* is a real loadable image with a working export
        directory, without needing Ghidra or a 32-bit Python.
    ``-`` in the arguments
        Sleep for three minutes so a debugger can attach. This is the mode
        ``run_debugger_live_test`` gets, since it launches with
        ``--seconds 180``.
    neither
        Exit immediately with the banner CRC as the exit code.

    "In the arguments" is load-bearing -- see the comment on the argv[0] skip.
    """
    asm.label("exe_entry")
    asm.enter_frame(8)
    asm.call("benchmark_self_test")
    asm.call_import("KERNEL32.dll!GetCommandLineA")
    asm.mov_reg_reg(ECX, EAX)

    # Step over argv[0] before looking for mode characters. GetCommandLineA
    # returns the program path too, and skipping this cost real debugging time:
    # run from a checkout whose path contains a hyphen -- a git worktree named
    # `agent-...`, or the repository's own `ghidra-mcp` -- the scan found a '-'
    # in the executable's own path and every invocation took the three-minute
    # sleep branch. The bug is invisible from a directory whose name happens to
    # be plain, which is exactly the kind of fixture defect that survives.
    asm.mov_byte_reg_mem(DL, ECX, 0)
    asm.cmp_byte_reg_imm8(DL, 0x22)          # '"'
    asm.jcc("z", "skip_quoted_argv0")
    asm.label("skip_plain_argv0")
    asm.mov_byte_reg_mem(DL, ECX, 0)
    asm.test_byte_reg(DL, DL)
    asm.jcc("z", "cmdline_scan")
    asm.cmp_byte_reg_imm8(DL, 0x20)          # ' '
    asm.jcc("z", "cmdline_scan")
    asm.inc_reg(ECX)
    asm.jmp("skip_plain_argv0")
    asm.label("skip_quoted_argv0")
    asm.inc_reg(ECX)                         # past the opening quote
    asm.label("skip_quoted_body")
    asm.mov_byte_reg_mem(DL, ECX, 0)
    asm.test_byte_reg(DL, DL)
    asm.jcc("z", "cmdline_scan")
    asm.inc_reg(ECX)
    asm.cmp_byte_reg_imm8(DL, 0x22)          # closing quote consumed
    asm.jcc("z", "cmdline_scan")
    asm.jmp("skip_quoted_body")

    asm.label("cmdline_scan")
    asm.mov_byte_reg_mem(DL, ECX, 0)
    asm.test_byte_reg(DL, DL)
    asm.jcc("z", "exe_finish")
    asm.cmp_byte_reg_imm8(DL, 0x40)          # '@'
    asm.jcc("z", "exe_dll_roundtrip")
    asm.cmp_byte_reg_imm8(DL, 0x2D)          # '-'
    asm.jcc("z", "exe_idle")
    asm.inc_reg(ECX)
    asm.jmp("cmdline_scan")

    # -- '@': load the sibling DLL and call an export out of it --------------
    asm.label("exe_dll_roundtrip")
    asm.push_abs("str_dll_name")
    asm.call_import("KERNEL32.dll!LoadLibraryA")
    asm.test_reg_reg(EAX, EAX)
    asm.jcc("z", "exe_dll_load_failed")
    asm.push_abs("str_export_name")
    asm.push(EAX)
    asm.call_import("KERNEL32.dll!GetProcAddress")
    asm.test_reg_reg(EAX, EAX)
    asm.jcc("z", "exe_dll_export_missing")
    asm.mov_local_reg(-8, EAX)
    asm.push_imm32(len(BANNER))
    asm.push_abs("str_banner")
    asm.call_local(-8)
    asm.add_reg_imm32(ESP, 8)
    asm.push(EAX)
    asm.call_import("KERNEL32.dll!ExitProcess")
    asm.label("exe_dll_load_failed")
    asm.push_imm32(0x0E01)                   # distinguishable from any CRC
    asm.call_import("KERNEL32.dll!ExitProcess")
    asm.label("exe_dll_export_missing")
    asm.push_imm32(0x0E02)
    asm.call_import("KERNEL32.dll!ExitProcess")

    asm.label("exe_idle")
    asm.mov_local_imm32(-4, 0)
    asm.label("idle_loop")
    asm.cmp_local_imm32(-4, 180)
    asm.jcc("nb", "exe_finish")
    asm.push_imm32(1000)
    asm.call_import("KERNEL32.dll!Sleep")    # __stdcall: callee cleans up
    asm.inc_local(-4)
    asm.jmp("idle_loop")

    asm.label("exe_finish")
    asm.push_imm32(len(BANNER))
    asm.push_abs("str_banner")
    asm.call("calc_crc16")
    asm.add_reg_imm32(ESP, 8)
    asm.push(EAX)
    asm.call_import("KERNEL32.dll!ExitProcess")
    asm.int3(4)                              # ExitProcess does not return


# ---------------------------------------------------------------------------
# Image assembly
# ---------------------------------------------------------------------------

def _build_strings() -> tuple[bytes, dict[str, int]]:
    """The string blob for .rdata, plus each string's offset within it."""
    blob = bytearray()
    offsets: dict[str, int] = {}
    for symbol, text in NAMED_STRINGS + _filler_strings():
        offsets[symbol] = len(blob)
        blob += text.encode("ascii") + b"\0"
    while len(blob) % 4:
        blob += b"\0"
    return bytes(blob), offsets


def _build_data_section() -> tuple[bytes, dict[str, int]]:
    """The .data blob, plus each global's offset within it."""
    blob = bytearray()
    offsets: dict[str, int] = {}
    for symbol, size, value in GLOBALS:
        offsets[symbol] = len(blob)
        if size % 4:
            raise ValueError(f"global {symbol} must be a whole number of dwords")
        blob += (value & 0xFFFFFFFF).to_bytes(4, "little") * (size // 4)
    return bytes(blob), offsets


def build_image(kind: str) -> tuple[bytes, dict[str, int]]:
    """Assemble one image. ``kind`` is ``"dll"`` or ``"exe"``.

    Returns the image bytes and the map of function name -> virtual address.
    """
    if kind not in ("dll", "exe"):
        raise ValueError(f"unknown image kind {kind!r}")
    is_dll = kind == "dll"
    image_base = DLL_IMAGE_BASE if is_dll else EXE_IMAGE_BASE

    asm = Assembler()
    _emit_shared_functions(asm)
    if is_dll:
        _emit_dll_main(asm)
    else:
        _emit_exe_entry(asm)
    code_length = asm.offset

    strings_blob, string_offsets = _build_strings()
    data_blob, data_offsets = _build_data_section()

    # .rdata: strings, then the import directory, then the export directory.
    # The import directory's own RVA is one of its inputs, so its position has
    # to be fixed before it is serialised.
    import_rva = RDATA_RVA + len(strings_blob)
    import_blob, iat_slots, (iat_rva, iat_size) = pe32.build_import_directory(
        imports=IMPORTS, directory_rva=import_rva
    )
    export_rva = import_rva + len(import_blob)
    while export_rva % 4:
        export_rva += 1
    exports = [
        (name, TEXT_RVA + asm.labels[name]) for name in EXPORTED_FUNCTIONS
    ]
    export_blob = pe32.build_export_directory(
        dll_name=DLL_NAME if is_dll else EXE_NAME,
        exports=exports,
        directory_rva=export_rva,
    )
    rdata_blob = (
        strings_blob
        + import_blob
        + b"\0" * (export_rva - (import_rva + len(import_blob)))
        + export_blob
    )

    symbols: dict[str, int] = {}
    for symbol, offset in string_offsets.items():
        symbols[symbol] = RDATA_RVA + offset
    for symbol, offset in data_offsets.items():
        symbols[symbol] = DATA_RVA + offset
    symbols.update(iat_slots)

    code = asm.finalize(image_base, TEXT_RVA, symbols)
    assert len(code) == code_length

    entry_label = "DllMain" if is_dll else "exe_entry"
    sections = [
        pe32.Section(".text", TEXT_RVA, code, pe32.TEXT_CHARACTERISTICS),
        pe32.Section(".rdata", RDATA_RVA, rdata_blob, pe32.RDATA_CHARACTERISTICS),
        pe32.Section(".data", DATA_RVA, data_blob, pe32.DATA_CHARACTERISTICS),
    ]
    image = pe32.build_image(
        image_base=image_base,
        sections=sections,
        entry_rva=TEXT_RVA + asm.labels[entry_label],
        directories={
            pe32.DIRECTORY_EXPORT: (export_rva, len(export_blob)),
            pe32.DIRECTORY_IMPORT: (import_rva, 20 * (len(IMPORTS) + 1)),
            pe32.DIRECTORY_IAT: (iat_rva, iat_size),
        },
        is_dll=is_dll,
        subsystem=SUBSYSTEM_GUI if is_dll else SUBSYSTEM_CONSOLE,
    )
    addresses = {
        name: image_base + TEXT_RVA + offset
        for name, offset in sorted(asm.labels.items(), key=lambda kv: kv[1])
        if name in EXPORTED_FUNCTIONS or name == entry_label
    }
    return image, addresses


def build_manifest(dll: bytes, exe: bytes,
                   dll_addresses: dict[str, int],
                   exe_addresses: dict[str, int]) -> dict:
    """Provenance for the two committed binaries.

    The old fixture's manifest existed because two different toolchains
    produced byte-different binaries at the same image base, and the PE headers
    alone could not tell them apart. This one records a generator version and a
    digest instead, which is the same question with an answer that does not
    depend on what is installed.
    """
    return {
        "producer": "tests/fixtures/benchmark/make_fixture.py",
        "generator_version": GENERATOR_VERSION,
        "toolchain": "none - the image is emitted directly by the generator",
        "deterministic": True,
        "note": (
            "Regenerate with `python tests/fixtures/benchmark/make_fixture.py`. "
            "The output is a pure function of the generator source, so a "
            "changed digest means the generator changed. Function addresses "
            "are chosen by the generator, not observed from a build, and "
            "tests/unit/test_benchmark_fixture.py fails if regression/*.yaml "
            "disagrees with them."
        ),
        "images": {
            DLL_NAME: {
                "image_base": f"0x{DLL_IMAGE_BASE:08x}",
                "subsystem": "windows_gui",
                "size_bytes": len(dll),
                "sha256": hashlib.sha256(dll).hexdigest(),
                "entry_point": f"0x{dll_addresses['DllMain']:08x}",
                "functions": {
                    name: f"0x{address:08x}"
                    for name, address in dll_addresses.items()
                },
            },
            EXE_NAME: {
                "image_base": f"0x{EXE_IMAGE_BASE:08x}",
                "subsystem": "windows_console",
                "size_bytes": len(exe),
                "sha256": hashlib.sha256(exe).hexdigest(),
                "entry_point": f"0x{exe_addresses['exe_entry']:08x}",
                "functions": {
                    name: f"0x{address:08x}"
                    for name, address in exe_addresses.items()
                },
            },
        },
        "banner": BANNER,
        "banner_crc16": reference_crc16(BANNER.encode("ascii")),
        "exports": sorted(EXPORTED_FUNCTIONS),
        "imports": {dll.name: list(dll.functions) for dll in IMPORTS},
        "string_count": len(NAMED_STRINGS) + FILLER_COUNT,
    }


def generate() -> tuple[bytes, bytes, dict]:
    dll, dll_addresses = build_image("dll")
    exe, exe_addresses = build_image("exe")
    manifest = build_manifest(dll, exe, dll_addresses, exe_addresses)
    return dll, exe, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed files match a fresh generation; write nothing",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=FIXTURE_DIR,
        help="where to write (default: alongside the generator)",
    )
    args = parser.parse_args(argv)

    dll, exe, manifest = generate()
    manifest_text = json.dumps(manifest, indent=2) + "\n"
    outputs = {
        args.out_dir / DLL_NAME: dll,
        args.out_dir / EXE_NAME: exe,
        args.out_dir / "build_manifest.json": manifest_text.encode("utf-8"),
    }

    if args.check:
        problems = []
        for path, expected in outputs.items():
            if not path.is_file():
                problems.append(f"missing: {path}")
            elif path.read_bytes() != expected:
                problems.append(f"differs from a fresh generation: {path}")
        if problems:
            for problem in problems:
                print(f"FAIL {problem}", file=sys.stderr)
            print(
                "Regenerate with: python tests/fixtures/benchmark/make_fixture.py",
                file=sys.stderr,
            )
            return 1
        print("Benchmark fixture matches the generator.")
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for path, payload in outputs.items():
        path.write_bytes(payload)
        print(f"wrote {path} ({len(payload)} bytes)")
    print(f"banner crc16 = 0x{manifest['banner_crc16']:04x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

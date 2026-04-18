"""Unit tests for debugger/d2/conventions.py — calling conventions and value analysis."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from debugger.d2.conventions import (
    read_args,
    read_return_address,
    classify_value,
    analyze_arg_observations,
    parse_convention_from_prototype,
)


def _make_memory(mapping: dict):
    """Create a read_dword function from a {address: value} dict."""
    def read_dword(addr):
        if addr in mapping:
            return mapping[addr]
        raise RuntimeError(f"Unmapped address: 0x{addr:08X}")
    return read_dword


class TestReadArgs:
    def test_stdcall_4_args(self):
        regs = {"ESP": 0x1000, "ECX": 0xAAAA, "EDX": 0xBBBB}
        mem = _make_memory({
            0x1004: 0x11111111,
            0x1008: 0x22222222,
            0x100C: 0x33333333,
            0x1010: 0x44444444,
        })
        args = read_args(regs, mem, "__stdcall", 4)
        assert args == [0x11111111, 0x22222222, 0x33333333, 0x44444444]

    def test_stdcall_0_args(self):
        regs = {"ESP": 0x1000}
        args = read_args(regs, lambda a: 0, "__stdcall", 0)
        assert args == []

    def test_fastcall_4_args(self):
        regs = {"ESP": 0x1000, "ECX": 0xAAAA, "EDX": 0xBBBB}
        mem = _make_memory({
            0x1004: 0x33333333,
            0x1008: 0x44444444,
        })
        args = read_args(regs, mem, "__fastcall", 4)
        assert args == [0xAAAA, 0xBBBB, 0x33333333, 0x44444444]

    def test_fastcall_1_arg(self):
        regs = {"ESP": 0x1000, "ECX": 0xAAAA, "EDX": 0xBBBB}
        args = read_args(regs, lambda a: 0, "__fastcall", 1)
        assert args == [0xAAAA]

    def test_fastcall_2_args(self):
        regs = {"ESP": 0x1000, "ECX": 0xAAAA, "EDX": 0xBBBB}
        args = read_args(regs, lambda a: 0, "__fastcall", 2)
        assert args == [0xAAAA, 0xBBBB]

    def test_thiscall_3_args(self):
        regs = {"ESP": 0x1000, "ECX": 0x1A3B5C00, "EDX": 0x0}
        mem = _make_memory({
            0x1004: 0x00000024,
            0x1008: 0x00000003,
        })
        args = read_args(regs, mem, "__thiscall", 3)
        assert args == [0x1A3B5C00, 0x00000024, 0x00000003]

    def test_cdecl_same_as_stdcall(self):
        regs = {"ESP": 0x1000, "ECX": 0, "EDX": 0}
        mem = _make_memory({0x1004: 42, 0x1008: 99})
        args_stdcall = read_args(regs, mem, "__stdcall", 2)
        args_cdecl = read_args(regs, mem, "__cdecl", 2)
        assert args_stdcall == args_cdecl


class TestReturnAddress:
    def test_reads_from_esp(self):
        regs = {"ESP": 0x1000}
        mem = _make_memory({0x1000: 0xDEADBEEF})
        ret = read_return_address(regs, mem)
        assert ret == 0xDEADBEEF


class TestClassifyValue:
    def test_zero(self):
        assert classify_value(0) in ("zero", "boolean")

    def test_boolean(self):
        assert classify_value(1) == "boolean"

    def test_pointer_range(self):
        assert classify_value(0x1A3B5C00) == "pointer"
        assert classify_value(0x6FD60000) == "pointer"
        assert classify_value(0x10000) == "pointer"

    def test_small_enum(self):
        assert classify_value(0x24) == "enum_candidate"
        assert classify_value(0xFF) == "enum_candidate"

    def test_small_int(self):
        assert classify_value(0x100) == "small_int"
        assert classify_value(0xFFFF) == "small_int"

    def test_negative(self):
        # -1 as unsigned 32-bit
        assert classify_value(0xFFFFFFFF) == "negative"
        # -10
        assert classify_value(0xFFFFFFF6) == "negative"

    def test_large_int(self):
        # Value outside standard ranges
        assert classify_value(0x80010000) in ("large_int", "negative")


class TestAnalyzeObservations:
    def test_pointer_values(self):
        values = [0x1A3B5C00, 0x1C004200, 0x1A3B5C00, 0x1D000000]
        result = analyze_arg_observations(values)
        assert result["classification"] == "pointer"
        assert result["suggested_type"] == "void *"

    def test_enum_values(self):
        values = [6, 36, 54, 71, 36, 6, 54]
        result = analyze_arg_observations(values)
        assert result["classification"] == "enum_candidate"
        assert result.get("likely_enum") is True

    def test_boolean_values(self):
        values = [0, 1, 0, 0, 1, 1]
        result = analyze_arg_observations(values)
        assert result["suggested_type"] == "BOOL"

    def test_empty_values(self):
        result = analyze_arg_observations([])
        assert result["classification"] == "unknown"

    def test_sample_capped(self):
        values = list(range(100))
        result = analyze_arg_observations(values)
        assert len(result["sample"]) <= 10


class TestParseConvention:
    def test_stdcall(self):
        assert parse_convention_from_prototype(
            "int __stdcall CalcMissileVelocityParam(int a, int b)"
        ) == "__stdcall"

    def test_fastcall(self):
        assert parse_convention_from_prototype(
            "void __fastcall ProcessInput(int a)"
        ) == "__fastcall"

    def test_thiscall(self):
        assert parse_convention_from_prototype(
            "int __thiscall MyClass::Method(void)"
        ) == "__thiscall"

    def test_no_convention_defaults_cdecl(self):
        assert parse_convention_from_prototype(
            "undefined4 FUN_6fd50a30(void)"
        ) == "__cdecl"

    def test_case_insensitive(self):
        assert parse_convention_from_prototype(
            "int __STDCALL Func(void)"
        ) == "__stdcall"

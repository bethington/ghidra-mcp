"""
Diablo 2 calling convention handling and argument reading.

D2 binaries (MSVC 6.0 compiled, 32-bit x86) use three calling conventions:

- __stdcall: All args on stack. Callee cleans stack. Most ordinal exports.
- __fastcall: First 2 args in ECX/EDX, rest on stack. Some internal functions.
- __thiscall: 'this' in ECX, rest on stack. C++ member functions.
- __cdecl: All args on stack. Caller cleans stack. Variadic functions (printf etc).

At function entry (breakpoint), ESP points to the return address.
Arguments start at [ESP+4], [ESP+8], etc. for stack-based conventions.
"""

from __future__ import annotations

import logging
import struct
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# D2 DLLs that are typically loaded in Game.exe
D2_MODULES = [
    "D2Client.dll",
    "D2CMP.dll",
    "D2Common.dll",
    "D2DDraw.dll",
    "D2Direct3D.dll",
    "D2Game.dll",
    "D2Gdi.dll",
    "D2gfx.dll",
    "D2Glide.dll",
    "D2Lang.dll",
    "D2Launch.dll",
    "D2MCPClient.dll",
    "D2Multi.dll",
    "D2Net.dll",
    "D2sound.dll",
    "D2Win.dll",
    "Fog.dll",
    "Storm.dll",
    "Bnclient.dll",
]

# Conventions recognized by the arg reader
CONVENTIONS = {"__stdcall", "__fastcall", "__thiscall", "__cdecl"}


def read_args(registers: Dict[str, int],
              read_dword_fn,
              convention: str,
              count: int) -> List[int]:
    """Read function arguments at a breakpoint based on calling convention.

    Args:
        registers: Register dict with at least ESP, ECX, EDX.
        read_dword_fn: Callable(address) -> int that reads a 32-bit value.
        convention: One of __stdcall, __fastcall, __thiscall, __cdecl.
        count: Number of arguments to read.

    Returns:
        List of argument values (as unsigned 32-bit ints).
    """
    if count <= 0:
        return []

    esp = registers.get("ESP", 0)
    ecx = registers.get("ECX", 0)
    edx = registers.get("EDX", 0)

    if convention == "__fastcall":
        args = []
        if count >= 1:
            args.append(ecx)
        if count >= 2:
            args.append(edx)
        # Remaining args on stack starting at ESP+4
        for i in range(max(0, count - 2)):
            addr = esp + 4 + i * 4
            args.append(read_dword_fn(addr))
        return args[:count]

    elif convention == "__thiscall":
        args = [ecx]  # 'this' pointer
        for i in range(max(0, count - 1)):
            addr = esp + 4 + i * 4
            args.append(read_dword_fn(addr))
        return args[:count]

    else:
        # __stdcall, __cdecl — all args on stack
        args = []
        for i in range(count):
            addr = esp + 4 + i * 4
            args.append(read_dword_fn(addr))
        return args


def read_return_address(registers: Dict[str, int], read_dword_fn) -> int:
    """Read the return address from the top of the stack at function entry."""
    esp = registers.get("ESP", 0)
    return read_dword_fn(esp)


def classify_value(value: int) -> str:
    """Heuristic classification of a 32-bit value for type inference.

    Returns one of: "pointer", "small_int", "enum_candidate", "boolean",
                    "negative", "large_int", "zero", "flag_bits".
    """
    if value in (0, 1):
        return "boolean"
    if 0x10000 <= value <= 0x7FFFFFFF:
        return "pointer"
    if value >= 0x80000000:
        # Interpret as signed
        signed = value - 0x100000000
        if -1000 <= signed < 0:
            return "negative"
        if value >= 0xFF000000:
            return "negative"  # Small negative
        return "large_int"
    if value <= 0xFF:
        return "enum_candidate"
    if value <= 0xFFFF:
        return "small_int"
    # Check for flag-like patterns (few bits set)
    if bin(value).count("1") <= 4:
        return "flag_bits"
    return "large_int"


def analyze_arg_observations(values: List[int]) -> dict:
    """Analyze observed argument values to infer type.

    Returns dict with:
        - classification: dominant type
        - unique_count: number of unique values
        - min/max: range
        - sample: up to 10 unique values
        - suggested_type: Ghidra type suggestion
    """
    if not values:
        return {"classification": "unknown", "suggested_type": "int"}

    unique = sorted(set(values))
    classifications = [classify_value(v) for v in values]

    # Count classifications
    counts: Dict[str, int] = {}
    for c in classifications:
        counts[c] = counts.get(c, 0) + 1

    dominant = max(counts, key=counts.get)  # type: ignore

    result = {
        "classification": dominant,
        "unique_count": len(unique),
        "min": f"0x{min(values):08X}",
        "max": f"0x{max(values):08X}",
        "total_observations": len(values),
        "sample": [f"0x{v:08X}" for v in unique[:10]],
    }

    # Suggest Ghidra type
    if dominant == "pointer":
        result["suggested_type"] = "void *"
    elif dominant == "boolean":
        result["suggested_type"] = "BOOL"
    elif dominant == "enum_candidate":
        result["suggested_type"] = "int"  # Small values, likely enum
        result["likely_enum"] = True
    elif dominant == "negative":
        result["suggested_type"] = "int"
    elif dominant == "flag_bits":
        result["suggested_type"] = "uint"
        result["likely_flags"] = True
    elif dominant == "small_int":
        if all(v <= 0xFFFF for v in values):
            result["suggested_type"] = "short" if any(v > 0x7FFF for v in values) else "ushort"
        else:
            result["suggested_type"] = "int"
    else:
        result["suggested_type"] = "uint"

    return result


def parse_convention_from_prototype(prototype: str) -> str:
    """Extract calling convention from a Ghidra function prototype string.

    Examples:
        "int __stdcall CalcMissileVelocityParam(...)" -> "__stdcall"
        "void __fastcall ProcessInput(...)" -> "__fastcall"
        "undefined4 FUN_6fd50a30(...)" -> "__cdecl" (default)
    """
    prototype_lower = prototype.lower()
    for conv in ("__stdcall", "__fastcall", "__thiscall", "__cdecl"):
        if conv in prototype_lower:
            return conv
    return "__cdecl"  # Default

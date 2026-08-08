"""Offline tests for the benchmark's era-toolchain registry.

The registry decides which compiler and linker produce `Benchmark.dll`, and
therefore whether "period-correct build" is a true statement. It was only
half true until 2026-08-08: `vc6sp6` pairs VC6's COMPILER with VS2003's
LINKER, and that is not a stylistic choice — `VS7/Bin/cl.exe` could not run
at all, because `c1.dll` imports six `std::basic_string` symbols from
`MSVCP71.dll`, which was missing from the vendored tree. `link.exe` needed
only `mspdb71` + `msvcr71` and worked fine, so the linker half was genuine
while the compiler half was VC6 standing in for VS2003.

That distinction is load-bearing. Every shipped D2 binary names its own
compiler in its Rich header and they all agree: build **6030** = VS .NET
2003 SP1, with ZERO VC6 objects (VC6 SP6 is build 8804). Confirmed at the
byte level — all 103 FID-identified CRT functions in `Game.exe` are
byte-identical (relocations masked) to their objects in VS2003's
`libcmt.lib`, while VC6's `LIBCMT.LIB` matches 11/103, and those 11 are
tiny SEH/mbcs helpers genuinely shared by both toolchains.

These tests are structural on purpose: the toolchains themselves are
gitignored local media, so asserting that files exist would fail in CI and
teach everyone to ignore a red suite. What CAN be checked everywhere is
that the registry still says what it means.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


BENCHMARK_DIR = Path(__file__).resolve().parents[2] / "fun-doc" / "benchmark"
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

build = pytest.importorskip("build")


def test_every_toolchain_declares_a_compiler_and_a_linker():
    for name, tc in build.TOOLCHAINS.items():
        assert "description" in tc, f"{name} has no description"
        assert "cl_flags" in tc and "link_flags" in tc, f"{name} lacks flags"
        has_compiler = "cl_path" in tc or "vcvars" in tc
        assert has_compiler, f"{name} names neither cl_path nor vcvars"


def test_vs2003_entry_exists_and_uses_vs2003_for_both_halves():
    """The whole point of this entry: ONE toolchain, not a mixture.

    If `cl_path` ever drifts back to the VC6 root this silently becomes a
    second `vc6sp6` while still claiming to be the original toolchain —
    which is the exact confusion the entry was added to end.
    """
    tc = build.TOOLCHAINS["vs2003"]
    cl, link = Path(tc["cl_path"]), Path(tc["link_path"])
    assert cl.parent == link.parent, (
        "vs2003 must take BOTH compiler and linker from the same VS7 tree; "
        f"got cl={cl.parent} link={link.parent}"
    )
    assert "VS7" in str(cl), f"vs2003 cl_path is not in the VS7 tree: {cl}"
    assert "VC98" not in str(cl), (
        "vs2003 cl_path points at the VC6 tree — that is what vc6sp6 already is"
    )


def test_vs2003_include_prefers_vs7_headers_but_keeps_vc6_for_win32():
    """VS2003 Pro media ships no Platform SDK, so `windows.h` has to come
    from the VC6 tree — but VS7's own CRT headers must win the search
    order, or we compile VS2003 code against VC6's CRT declarations."""
    inc = build.TOOLCHAINS["vs2003"]["include"]
    assert len(inc) >= 2, "expected VS7 headers plus a Win32 header fallback"
    assert "VS7" in inc[0], f"VS7 headers must come first, got {inc[0]}"
    assert any("VC98" in p for p in inc), (
        "no VC6 Include on the path — windows.h would not resolve"
    )


def test_vc6sp6_is_still_a_mixture_and_says_so():
    """`vc6sp6` is kept deliberately, as a comparison point and historical
    baseline. It must keep being honest about being mixed rather than
    quietly becoming a synonym for the real thing."""
    tc = build.TOOLCHAINS["vc6sp6"]
    assert "VC98" in tc["cl_path"], "vc6sp6's compiler should be VC6's"
    assert "VS7" in tc["link_path"], "vc6sp6's linker should be VS2003's"
    assert Path(tc["cl_path"]).parent != Path(tc["link_path"]).parent


def test_vs2003_description_does_not_claim_to_be_sp1():
    """Two different facts, easy to conflate — and they were, in the first
    version of this entry.

    D2's binaries were built with VS2003 **SP1** (Rich header build 6030).
    The toolchain vendored here is **RTM** (`cl.exe` reports 13.10.3077);
    SP1 was a separate download and is not on the Pro media. RTM is
    byte-exact everywhere it has been checked — all 103 CRT functions and a
    hand-written authored function — so it is good enough to certify with.
    But the gap must stay visible, because "install SP1" is the one variable
    left to try when a function refuses to match for no other reason.
    """
    desc = build.TOOLCHAINS["vs2003"]["description"]
    assert "RTM" in desc, "the vs2003 entry must say which release it is"
    assert not (desc.startswith("Visual Studio .NET 2003 SP1")
                or "2003 SP1:" in desc), (
        "vs2003 describes itself as SP1, but the vendored compiler is RTM "
        "(13.10.3077). D2's binaries are SP1 (6030) — that is a fact about "
        "the binaries, not about this toolchain."
    )


def test_toolchain_names_are_cli_selectable():
    """`--toolchain` builds its choices from the registry keys, so a new
    entry is reachable from the CLI the moment it is added."""
    assert "vs2003" in sorted(build.TOOLCHAINS.keys())

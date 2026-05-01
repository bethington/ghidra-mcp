"""Build Benchmark.dll from src/*.c.

Walking skeleton uses modern MSVC 2022 (the only toolchain installed on this
machine today). The real target is MSVC 6.0 SP6 for compilation + VS2003 for
linking — that's what D2 1.13d was built with, confirmed empirically from
D2Common.dll's Rich header. Swap in via `--toolchain vc6sp6` once that's
installed; until then the skeleton proves the pipeline end-to-end with a
pragmatic stand-in.

Outputs (all under fun-doc/benchmark/build/):
  Benchmark.dll   — the compiled 32-bit PE DLL, stripped of PDB
  Benchmark.map   — the MSVC map file (function → address)
  Benchmark.lib   — import library (discarded after build but produced as a side-effect)
  Benchmark.exp   — export file (same)

Usage:
    python build.py                         # default toolchain
    python build.py --toolchain vc6sp6      # once VC6 is pinned in the repo
    python build.py --clean                 # wipe build/ first
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parent
SRC_DIR = BENCHMARK_DIR / "src"
BUILD_DIR = BENCHMARK_DIR / "build"

# VC6 SP6 toolchain root. Lives in the project tree (gitignored) so the
# benchmark is self-contained per machine; populated by
# `tools/bootstrap_vc6.py` from the user's licensed source media. See
# tools/vc6/README.md + tools/vc6/NOTICE.md for the redistribution posture.
# FUNDOC_VC6_ROOT env var overrides this if the user has VC6 installed
# elsewhere (e.g., a system install at C:\VC6\).
_DEFAULT_VC6_ROOT = BENCHMARK_DIR / "tools" / "vc6" / "VC98"
VC6_ROOT = Path(os.environ.get("FUNDOC_VC6_ROOT") or str(_DEFAULT_VC6_ROOT))

# VS 2003 linker root — D2 1.13d's Rich header shows VC6 SP6 compiler
# BUT VS 7.10 linker (OptionalHeader MajorLinkerVersion=7.10). The mixed
# toolchain is period-accurate: Blizzard upgraded their linker for
# better /OPT:ICF + large-binary handling while keeping VC6's compiler.
# Source media: D:\vs2003-pro\*.iso (Visual Studio .NET 2003 Professional).
# Linker padding byte: VS 7.10+ defaults to 0xCC (int 3 / trap) where
# VC6 link.exe defaults to 0x90 (nop) — a cosmetic detail but one that
# shows up in byte-level diffs of the resulting .text sections.
_DEFAULT_VS7_ROOT = BENCHMARK_DIR / "tools" / "vc6" / "VS7"
VS7_ROOT = Path(os.environ.get("FUNDOC_VS7_ROOT") or str(_DEFAULT_VS7_ROOT))


# Toolchain registry. Keys = logical toolchain name passed via --toolchain.
# Each entry describes enough to locate cl.exe + link.exe and produce an
# x86 DLL. Modern MSVC entries use vcvars32.bat to set PATH/INCLUDE/LIB;
# VC6 is a direct path to cl.exe + link.exe.
TOOLCHAINS = {
    "msvc2022": {
        "description": "Visual Studio 2022 Community (modern MSVC; walking-skeleton stand-in)",
        "vcvars": r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat",
        "cl_flags": [
            "/nologo",
            "/W3",
            "/O2",         # optimize for speed
            "/GF",         # string pooling
            "/MT",         # static CRT (matches D2: no MSVCRT import)
            "/GS-",        # disable buffer security cookie (VC6 didn't have it)
            "/Gy",         # function-level linking
            "/LD",         # build a DLL
        ],
        "link_flags": [
            "/NOLOGO",
            "/MACHINE:X86",
            "/SUBSYSTEM:WINDOWS,4.00",
            "/OPT:REF",
            "/OPT:ICF",
            "/MAP",
        ],
    },
    "vc6sp6": {
        "description": (
            "Mixed toolchain: VC6 SP6 cl.exe (compiler, build 6030) "
            "+ VS 2003 link.exe (linker, 7.10). Matches D2 1.13d's "
            "Rich header compiler products AND OptionalHeader linker "
            "version 7.10 AND 0xCC inter-function padding byte."
        ),
        # Compiler: VC6 SP6. Banner reads "Version 12.00.8804".
        # Lives at fun-doc/benchmark/tools/vc6/VC98/ (gitignored).
        # FUNDOC_VC6_ROOT overrides.
        "cl_path": str(VC6_ROOT / "Bin" / "cl.exe"),
        # Linker: VS 2003 (VC7.1). Banner reads "Version 7.10.3077".
        # Period-accurate to D2 1.13d. Lives at
        # fun-doc/benchmark/tools/vc6/VS7/Bin/. FUNDOC_VS7_ROOT overrides.
        "link_path": str(VS7_ROOT / "Bin" / "link.exe"),
        # The VS 2003 linker needs its own DLLs on PATH (mspdb71,
        # msdis140, msvcr71) — adding VS7/Bin to PATH picks them up.
        # cl.exe still uses its own mspdb60 from VC6/Bin.
        "extra_path": [str(VS7_ROOT / "Bin")],
        "include": [str(VC6_ROOT / "Include"), str(VC6_ROOT / "Atl" / "Include")],
        "lib": [str(VC6_ROOT / "Lib")],
        "cl_flags": [
            "/nologo",
            "/W3",
            "/O2",
            "/GF",
            "/MT",
            "/Gy",
            "/LD",
        ],
        "link_flags": [
            "/NOLOGO",
            "/MACHINE:IX86",
            # SUBSYSTEM:WINDOWS,4.00 — VC6 would warn; VS 2003 accepts
            # it silently and emits OS/Subsystem Version 4.00/4.00 in
            # the PE header (matches D2's 4.00/4.00 exactly).
            "/SUBSYSTEM:WINDOWS,4.00",
            # Match D2Common.dll's image base so our function addresses
            # land at 0x6FD5xxxx instead of 0x1000xxxx. This makes
            # cross-binary diffs easier (an address in our Benchmark.dll
            # sits in the same numeric range as its D2 inspiration) and
            # avoids Ghidra having to rebase on import.
            "/BASE:0x6FD50000",
            "/OPT:REF",
            # ICF is what Blizzard used the VS 2003 linker FOR — it's
            # the feature VC6 didn't have. Enable it to match D2's
            # COMDAT folding behavior.
            "/OPT:ICF",
            "/MAP",
        ],
    },
}


_SENTINEL = "___VCVARS_SENTINEL___"


def _probe_vcvars_env(vcvars_path: str) -> dict[str, str]:
    """Run vcvars32.bat and capture the resulting environment.

    Invokes cmd.exe passing the bat path as a separate argv entry
    (avoiding shell-quoting bugs around the space in the vcvars path),
    then prints a sentinel and dumps `set`. Parses every NAME=VALUE
    pair after the sentinel. vcvars32.bat prints noisy startup banners
    and may warn about missing vswhere.exe — all pre-sentinel noise is
    discarded.
    """
    p = Path(vcvars_path)
    if not p.is_file():
        raise FileNotFoundError(f"vcvars32.bat not found at {vcvars_path}")

    out = subprocess.check_output(
        ["cmd", "/c", "call", str(p), "&&", "echo", _SENTINEL, "&&", "set"],
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    _, _, after = out.partition(_SENTINEL)
    env = {}
    for line in after.splitlines():
        line = line.rstrip()
        if "=" not in line or line.startswith("="):
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v
    if not env:
        raise RuntimeError(
            f"vcvars32.bat produced no environment. Output was:\n{out}"
        )
    return env


def _make_env_for_toolchain(tc: dict) -> dict[str, str]:
    if "vcvars" in tc:
        return _probe_vcvars_env(tc["vcvars"])
    # VC6 style — explicit INCLUDE/LIB env
    env = os.environ.copy()
    if "include" in tc:
        env["INCLUDE"] = os.pathsep.join(tc["include"])
    if "lib" in tc:
        env["LIB"] = os.pathsep.join(tc["lib"])
    # PATH: cl.exe's directory first, then any `extra_path` dirs (for
    # mixed-toolchain setups where link.exe lives elsewhere and needs
    # its own DLLs), then the inherited PATH. Order matters — cl.exe's
    # dir must come first so cl.exe resolves its own MSPDB60.DLL, not
    # a newer mspdb71.dll from the linker's dir.
    path_parts = [str(Path(tc["cl_path"]).parent)]
    if tc.get("extra_path"):
        path_parts.extend(tc["extra_path"])
    path_parts.append(env.get("PATH", ""))
    env["PATH"] = os.pathsep.join(p for p in path_parts if p)
    return env


def _cl_executable(tc: dict) -> str:
    return tc.get("cl_path", "cl.exe")


def _run_command(command: list[str], env: dict[str, str], failure_label: str) -> None:
    print(f"[build][cmd]  {' '.join(command)}")
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"{failure_label} failed (exit {result.returncode}).")


def build(toolchain_name: str, clean: bool = False) -> Path:
    if toolchain_name not in TOOLCHAINS:
        raise ValueError(
            f"Unknown toolchain {toolchain_name!r}. Known: {', '.join(TOOLCHAINS)}"
        )
    tc = TOOLCHAINS[toolchain_name]

    if clean and BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    harness_source = SRC_DIR / "benchmark_debug.c"
    sources = sorted(s for s in SRC_DIR.glob("*.c") if s.name != harness_source.name)
    if not sources:
        raise RuntimeError(f"No .c sources found in {SRC_DIR}")

    env = _make_env_for_toolchain(tc)
    cl = _cl_executable(tc)

    # Resolve cl.exe to an absolute path up front. On Windows, CreateProcess
    # uses the PARENT's PATH (not env["PATH"]) to locate the executable, so
    # a bare "cl.exe" with a doctored env would still fail. Resolve via the
    # probed env's PATH which contains the VS bin dir.
    if not Path(cl).is_absolute():
        resolved = shutil.which(cl, path=env.get("PATH", ""))
        if resolved is None:
            raise RuntimeError(
                f"Could not resolve {cl} via toolchain PATH. "
                f"First PATH entries: {env.get('PATH', '').split(os.pathsep)[:3]}"
            )
        cl = resolved

    out_dll = BUILD_DIR / "Benchmark.dll"
    out_map = BUILD_DIR / "Benchmark.map"

    print(f"[build] toolchain={toolchain_name} ({tc['description']})")

    # If the toolchain specifies a separate link_path, do a two-step
    # compile-then-link so we can use a different linker than the one
    # cl.exe would pick up from its own Bin dir. This matches the
    # Blizzard pattern for D2 1.13d: VC6 cl.exe drives compilation,
    # VS 2003 link.exe does the link (producing OptionalHeader
    # LinkerVersion 7.10 and 0xCC inter-function padding).
    separate_linker = tc.get("link_path")

    # --- Step 1: compile every .c to .obj ---
    compile_cmd = [
        cl,
        *tc["cl_flags"],
        "/c",                        # compile only, no link
        f"/Fo{BUILD_DIR}\\",          # .obj output dir (trailing backslash required)
        *[str(s) for s in sources],
    ]
    # Drop /LD from compile-only cmd — it's a linker flag that cl.exe
    # passes through when linking; harmless but confusing in a /c cmd.
    compile_cmd = [x for x in compile_cmd if x != "/LD"]
    _run_command(compile_cmd, env, "Compile")

    # --- Step 2: link the .objs into the DLL ---
    objs = sorted(BUILD_DIR.glob("*.obj"))
    if not objs:
        raise RuntimeError(f"No .obj files produced in {BUILD_DIR}")

    if separate_linker:
        # Resolve link.exe absolute path (same CreateProcess PATH issue as cl.exe)
        link_exe = separate_linker
        if not Path(link_exe).is_absolute():
            link_exe = shutil.which(link_exe, path=env.get("PATH", "")) or link_exe
        if not Path(link_exe).is_file():
            raise RuntimeError(
                f"link.exe not found at {separate_linker}. Has tools/vc6/VS7/Bin/ "
                f"been populated? See tools/vc6/README.md."
            )
    else:
        # No separate linker — use link.exe from cl.exe's own Bin dir
        link_exe = str(Path(cl).parent / "link.exe")

    link_cmd = [
        link_exe,
        *tc["link_flags"],
        "/DLL",                       # output a DLL (replaces cl.exe's /LD)
        f"/OUT:{out_dll}",
        f"/MAP:{out_map}",
        # The default EntryPoint for a DLL is _DllMainCRTStartup@12;
        # link.exe picks it automatically when /DLL is set. We provide
        # DllMain ourselves in dllmain.c, so the CRT entry point is
        # happy to delegate. No /ENTRY override needed.
        *[str(o) for o in objs],
    ]
    _run_command(link_cmd, env, "Link")
    if not out_dll.is_file():
        raise RuntimeError(f"Link succeeded but {out_dll} not produced")

    out_exe = BUILD_DIR / "BenchmarkDebug.exe"
    if harness_source.is_file():
        exe_cmd = [
            cl,
            "/nologo",
            "/W3",
            "/O2",
            "/GF",
            "/MT",
            "/GS-",
            "/Gy",
            f"/Fe{out_exe}",
            str(harness_source),
            "/link",
            "/NOLOGO",
            "/MACHINE:X86",
            "/SUBSYSTEM:CONSOLE,4.00",
        ]
        _run_command(exe_cmd, env, "Debug harness build")
        if not out_exe.is_file():
            raise RuntimeError(f"Build succeeded but {out_exe} not produced")

    # Write a small manifest so downstream tools can read which toolchain
    # produced the binary — useful for the run record to include and for
    # CI to verify the binary was built with the expected toolchain.
    manifest = {
        "toolchain": toolchain_name,
        "description": tc["description"],
        "sources": [s.name for s in sources],
        "dll": out_dll.name,
        "debug_exe": out_exe.name if out_exe.is_file() else None,
        "map": out_map.name,
    }
    (BUILD_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"[build] ok — {out_dll} ({out_dll.stat().st_size} bytes)")
    if out_exe.is_file():
        print(f"[build] ok - {out_exe} ({out_exe.stat().st_size} bytes)")
    return out_dll


def main():
    ap = argparse.ArgumentParser(description="Build fun-doc benchmark DLL")
    ap.add_argument(
        "--toolchain",
        default="msvc2022",
        choices=sorted(TOOLCHAINS.keys()),
        help="Which toolchain to build with (default: msvc2022, the walking-skeleton stand-in)",
    )
    ap.add_argument("--clean", action="store_true", help="Wipe build/ before compiling")
    args = ap.parse_args()
    build(args.toolchain, clean=args.clean)


if __name__ == "__main__":
    main()

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
        "description": "Visual C++ 6.0 SP6 (target toolchain — matches D2 1.13d Rich header)",
        # These paths are placeholders; wire them up when VC6 is installed
        # (e.g. via the archive installer to C:\VC6). Leave unused until then.
        "cl_path": r"C:\VC6\VC98\Bin\cl.exe",
        "link_path": r"C:\VC6\VC98\Bin\link.exe",
        "include": [r"C:\VC6\VC98\Include", r"C:\VC6\VC98\ATL\Include"],
        "lib": [r"C:\VC6\VC98\Lib"],
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
            "/SUBSYSTEM:WINDOWS,4.00",
            "/OPT:REF",
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
    path_prefix = str(Path(tc["cl_path"]).parent)
    env["PATH"] = path_prefix + os.pathsep + env.get("PATH", "")
    return env


def _cl_executable(tc: dict) -> str:
    return tc.get("cl_path", "cl.exe")


def build(toolchain_name: str, clean: bool = False) -> Path:
    if toolchain_name not in TOOLCHAINS:
        raise ValueError(
            f"Unknown toolchain {toolchain_name!r}. Known: {', '.join(TOOLCHAINS)}"
        )
    tc = TOOLCHAINS[toolchain_name]

    if clean and BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    sources = sorted(SRC_DIR.glob("*.c"))
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

    # cl.exe with /LD builds a DLL and invokes the linker internally.
    # /Fe sets the output DLL name; /Fm the map file; /Fo the .obj dir.
    cmd = [
        cl,
        *tc["cl_flags"],
        f"/Fe{out_dll}",
        f"/Fm{out_map}",
        f"/Fo{BUILD_DIR}\\",
        *[str(s) for s in sources],
        "/link",
        *tc["link_flags"],
    ]
    print(f"[build] toolchain={toolchain_name} ({tc['description']})")
    print(f"[build] cmd: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(
            f"Build failed (exit {result.returncode}). See stderr above."
        )
    if not out_dll.is_file():
        raise RuntimeError(f"Build succeeded but {out_dll} not produced")

    # Write a small manifest so downstream tools can read which toolchain
    # produced the binary — useful for the run record to include and for
    # CI to verify the binary was built with the expected toolchain.
    manifest = {
        "toolchain": toolchain_name,
        "description": tc["description"],
        "sources": [s.name for s in sources],
        "dll": out_dll.name,
        "map": out_map.name,
    }
    (BUILD_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"[build] ok — {out_dll} ({out_dll.stat().st_size} bytes)")
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

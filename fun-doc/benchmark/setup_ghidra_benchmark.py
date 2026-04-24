"""One-time setup: import Benchmark.dll into the running Ghidra project.

Run this after `python build.py` if Benchmark.dll is not yet in Ghidra.
Idempotent — if the program already exists in the target folder, the
script exits successfully without re-importing.

Usage:
    python setup_ghidra_benchmark.py                         # default /benchmark/ folder
    python setup_ghidra_benchmark.py --folder /tests/
    python setup_ghidra_benchmark.py --force                  # re-import even if present

Environment:
    FUNDOC_BENCHMARK_PROGRAM   override the Ghidra path the benchmark
                               runner will use. If set, this script
                               imports Benchmark.dll to match.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from ghidra_bridge import GhidraBridgeError, _get, _post


BENCHMARK_DIR = Path(__file__).resolve().parent
BENCHMARK_DLL = BENCHMARK_DIR / "build" / "Benchmark.dll"


def _resolve_target_path() -> tuple[str, str]:
    """Return (ghidra_folder, ghidra_program_path) the script should target."""
    env = os.environ.get("FUNDOC_BENCHMARK_PROGRAM")
    if env:
        folder = str(Path(env).parent).replace("\\", "/")
        return folder, env
    return "/benchmark", "/benchmark/Benchmark.dll"


def _program_exists(program_path: str) -> bool:
    """Check whether Ghidra already has this program in the project.

    Uses list_open_programs + list_project_files. Any match is enough;
    we treat "in the project but not yet open" as "already imported".
    """
    try:
        open_ = _get("/list_open_programs")
        for p in (open_.get("programs") or []):
            if p.get("path") == program_path:
                return True
    except GhidraBridgeError:
        pass

    folder = str(Path(program_path).parent).replace("\\", "/")
    try:
        files = _get("/list_project_files", params={"folder": folder})
        for f in files.get("files") or []:
            fp = f.get("path") or (f"{folder}/{f.get('name')}" if f.get("name") else None)
            if fp == program_path:
                return True
    except GhidraBridgeError:
        pass
    return False


def setup(force: bool = False) -> None:
    folder, program_path = _resolve_target_path()

    if not BENCHMARK_DLL.is_file():
        raise RuntimeError(
            f"Benchmark.dll not built yet at {BENCHMARK_DLL}. "
            f"Run `python build.py` first."
        )

    if not force and _program_exists(program_path):
        print(f"[setup] already imported: {program_path} — nothing to do")
        return

    print(f"[setup] importing {BENCHMARK_DLL} -> Ghidra path {program_path}")
    resp = _post(
        "/import_file",
        params={},
        data={
            "file_path": str(BENCHMARK_DLL),
            "project_folder": folder,
            "language": "x86:LE:32:default",
            "compiler_spec": "windows",
            "auto_analyze": True,
        },
        timeout=120,
    )
    print(f"[setup] import response: {resp}")

    # Poll analysis_status until complete. Small binary (~85 KB) should
    # finish in seconds; cap at 90s for safety.
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            status = _get("/analysis_status", params={"program": program_path})
        except GhidraBridgeError:
            time.sleep(1)
            continue
        state = status.get("state") or status.get("status")
        if state in ("complete", "done", "idle", "finished"):
            print(f"[setup] analysis complete")
            return
        print(f"[setup] analysis state: {state}")
        time.sleep(2)
    print("[setup] WARNING: analysis did not report complete within 90s — continuing anyway")


def main():
    ap = argparse.ArgumentParser(description="Import Benchmark.dll into Ghidra for --real runs")
    ap.add_argument("--force", action="store_true", help="Re-import even if already present")
    args = ap.parse_args()
    setup(force=args.force)


if __name__ == "__main__":
    main()

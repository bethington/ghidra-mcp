"""Bootstrap the Visual C++ 6.0 SP6 toolchain into fun-doc/benchmark/tools/vc6/.

Automates the extraction procedure documented in docs/VC6_INSTALL.md. The
end user supplies source media they are licensed to use (typically
`D:\\vc6-sp6-ent\\` containing the CD1 ISO, SP6 self-extractor, and
vcpp5.exe for the Processor Pack). This script extracts + overlays them
under tools/vc6/VC98/. Nothing from the VC6 toolchain is redistributed
via this repository — see tools/vc6/NOTICE.md.

Steps performed (idempotent — skips each if the outputs already look right):

  1. Extract VC98/ + helper DLLs (MSPDB60, MSDIS110, MSOBJ10) from the
     CD1 ISO via 7-Zip.
  2. Copy the helper DLLs into VC98/Bin/ alongside cl.exe.
  3. Extract SP6's self-extractor + the four VS6sp6{1..4}.cab CABs.
  4. Overlay the SP6-patched bin/include/lib trees onto VC98/.
  5. Extract the Processor Pack and deploy its c2.dll — the workaround
     for SP6's notorious C1/C2 IL-version mismatch.
  6. Verify by invoking cl.exe and checking the compiler banner.

Usage:
    python bootstrap_vc6.py --source D:\\vc6-sp6-ent
    python bootstrap_vc6.py --source D:\\vc6-sp6-ent --force    # wipe + redo
    python bootstrap_vc6.py --verify                            # just check
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[1]
VC6_ROOT = BENCHMARK_DIR / "tools" / "vc6"
VC98_DIR = VC6_ROOT / "VC98"
BIN_DIR = VC98_DIR / "Bin"
VS7_BIN_DIR = VC6_ROOT / "VS7" / "Bin"


REQUIRED_SOURCE_FILES = {
    "cd1": "en_vs6_ent_cd1.iso",
    "sp6": "en_vs6_sp6.exe",
    "vcpp5": "vcpp5.exe",
}


# Optional VS 2003 pieces — D2 1.13d used VC6 cl.exe + VS 7.10 link.exe
# (mixed toolchain). Bootstrap this if present to get OptionalHeader
# LinkerVersion 7.10 matching D2 exactly. If the VS 2003 ISO isn't
# supplied the mixed toolchain is skipped and the build falls back to
# VC6's own link.exe (6.00).
VS7_SOURCE_GLOB = "Microsoft Visual Studio .NET 2003 Professional - Disc 1.iso"
VS7_FILES_IN_ISO = [
    ("Program Files/Microsoft Visual Studio .NET 2003/Vc7/bin/link.exe",   "link.exe"),
    ("Program Files/Microsoft Visual Studio .NET 2003/Vc7/bin/cvtres.exe", "cvtres.exe"),
    ("Program Files/Microsoft Visual Studio .NET 2003/Common7/IDE/mspdb71.dll",   "mspdb71.dll"),
    ("Program Files/Microsoft Visual Studio .NET 2003/Common7/IDE/msdis140.dll",  "msdis140.dll"),
    ("Program Files/Microsoft Visual Studio .NET 2003/Common7/IDE/msvcr71.dll",   "msvcr71.dll"),
]


def _check_7z_available() -> str:
    """Locate 7z.exe. Returns its path or exits with an error."""
    for candidate in ("7z", "7z.exe"):
        found = shutil.which(candidate)
        if found:
            return found
    # Common install locations if it's not on PATH
    for explicit in (
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\ProgramData\chocolatey\bin\7z.exe",
    ):
        if Path(explicit).is_file():
            return explicit
    print(
        "ERROR: 7z not found on PATH and not at common install locations.\n"
        "  Install 7-Zip (https://www.7-zip.org/) or chocolatey `choco install 7zip`.",
        file=sys.stderr,
    )
    sys.exit(2)


def _run_7z(sevenz: str, archive: Path, dest: Path, *patterns: str) -> None:
    """Invoke 7z x, extracting to dest. Patterns narrow what to pull out."""
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [sevenz, "x", str(archive), f"-o{dest}", "-y", *patterns]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: 7z failed on {archive.name}", file=sys.stderr)
        print(f"  stdout: {result.stdout[-500:]}", file=sys.stderr)
        print(f"  stderr: {result.stderr[-500:]}", file=sys.stderr)
        sys.exit(3)


def _copy_tree_overlay(src: Path, dst: Path) -> None:
    """Copy every file under src into the matching path under dst.

    Overwrites existing files. Used to overlay SP6-patched files onto
    the base VC98 install. Case-insensitive paths are accepted — the
    SP6 CAB uses lowercase `vc98/bin/` while the base ISO uses uppercase
    `VC98/Bin/`; both should land in the same place.
    """
    if not src.is_dir():
        return
    for child in src.rglob("*"):
        if child.is_file():
            rel = child.relative_to(src)
            out = dst / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(child, out)


def _verify() -> bool:
    """Run cl.exe and confirm the SP6 banner.

    cl.exe writes its version banner to stderr and the usage line to
    stdout, in an interleaving that's OS-dependent. We search all lines
    for the SP6 build marker rather than relying on line ordering.
    """
    cl = BIN_DIR / "cl.exe"
    if not cl.is_file():
        print(f"  [verify] cl.exe missing at {cl}", file=sys.stderr)
        return False
    try:
        result = subprocess.run(
            [str(cl)], capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        print(f"  [verify] cl.exe failed to execute: {e}", file=sys.stderr)
        return False
    combined = result.stdout + "\n" + result.stderr
    # Pull the first line that looks like the Microsoft banner.
    banner_line = next(
        (ln.strip() for ln in combined.splitlines() if "Optimizing Compiler" in ln),
        None,
    )
    if banner_line is None:
        print("  [verify] cl.exe produced no version banner", file=sys.stderr)
        return False
    print(f"  [verify] {banner_line}")
    if "Version 12.00.8804" not in banner_line:
        print(
            "  [verify] banner does not report SP6 build 8804 — install may be incomplete",
            file=sys.stderr,
        )
        return False
    return True


def bootstrap(source_dir: Path, force: bool = False) -> None:
    sevenz = _check_7z_available()

    # Locate source files
    for label, filename in REQUIRED_SOURCE_FILES.items():
        path = source_dir / filename
        if not path.is_file():
            print(
                f"ERROR: required source file {filename} not found in {source_dir}\n"
                f"  See tools/vc6/README.md for what source media is needed.",
                file=sys.stderr,
            )
            sys.exit(4)

    if VC98_DIR.exists() and not force:
        if _verify():
            print(
                f"  [bootstrap] {VC98_DIR} already populated and cl.exe works. "
                f"Use --force to re-extract."
            )
            return
        print(
            f"  [bootstrap] {VC98_DIR} exists but verification failed; "
            f"re-extracting over it.",
            file=sys.stderr,
        )
    elif VC98_DIR.exists() and force:
        print(f"  [bootstrap] --force: wiping {VC98_DIR}")
        shutil.rmtree(VC98_DIR)

    VC6_ROOT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fundoc_vc6_bootstrap_") as tmp_str:
        tmp = Path(tmp_str)
        print(f"  [bootstrap] working in {tmp}")

        # Step 1: Extract VC98 tree + helper DLLs from CD1
        cd1 = source_dir / REQUIRED_SOURCE_FILES["cd1"]
        print(f"  [1/5] extracting VC98 tree from {cd1.name} ...")
        _run_7z(
            sevenz,
            cd1,
            VC6_ROOT,
            "VC98",
            "COMMON/MSDEV98/BIN/MSPDB60.DLL",
            "COMMON/MSDEV98/BIN/MSDIS110.DLL",
            "COMMON/MSDEV98/BIN/MSOBJ10.DLL",
        )

        # Step 2: Copy helper DLLs into VC98/Bin
        print("  [2/5] staging helper DLLs into VC98/Bin/ ...")
        common_bin = VC6_ROOT / "COMMON" / "MSDEV98" / "BIN"
        for dll in ("MSPDB60.DLL", "MSDIS110.DLL", "MSOBJ10.DLL"):
            src = common_bin / dll
            if src.is_file():
                shutil.copy2(src, BIN_DIR / dll)

        # Step 3: Extract SP6 self-extractor, then its inner CABs
        sp6 = source_dir / REQUIRED_SOURCE_FILES["sp6"]
        sp6_outer = tmp / "sp6_outer"
        sp6_inner = tmp / "sp6_inner"
        print(f"  [3/5] extracting {sp6.name} (self-extractor + VS6sp6 CABs) ...")
        _run_7z(sevenz, sp6, sp6_outer)
        for n in (1, 2, 3, 4):
            cab = sp6_outer / f"VS6sp6{n}.cab"
            if cab.is_file():
                _run_7z(sevenz, cab, sp6_inner)

        # Step 4: Overlay SP6-patched files onto VC98/
        # SP6 CABs use lowercase paths (vc98/bin/, vc98/include/, vc98/lib/).
        # We overlay each onto the base's VC98/... regardless of case.
        print("  [4/5] overlaying SP6-patched files onto VC98/ ...")
        for sub in ("bin", "include", "lib", "atl"):
            _copy_tree_overlay(sp6_inner / "vc98" / sub, VC98_DIR / sub.title())

        # Step 5: Deploy Processor Pack c2.dll to fix SP6 C1/C2 mismatch
        vcpp5 = source_dir / REQUIRED_SOURCE_FILES["vcpp5"]
        vcpp5_dir = tmp / "vcpp5"
        print(f"  [5/5] extracting Processor Pack {vcpp5.name} for c2.dll ...")
        _run_7z(sevenz, vcpp5, vcpp5_dir)
        pp_c2 = vcpp5_dir / "c2.dll"
        if not pp_c2.is_file():
            print(
                "ERROR: vcpp5.exe did not contain c2.dll at its top level. "
                "Without this file SP6's C1 front-end cannot talk to its C2 "
                "back-end and compilation will fail with C1900 'Il mismatch'.",
                file=sys.stderr,
            )
            sys.exit(5)
        shutil.copy2(pp_c2, BIN_DIR / "C2.DLL")

    # Final verification
    print()
    if _verify():
        print(f"  [bootstrap] OK — VC6 SP6 ready at {VC98_DIR}")
    else:
        print(
            "  [bootstrap] install completed but verification failed. "
            "Inspect tools/vc6/VC98/Bin/ and docs/VC6_INSTALL.md.",
            file=sys.stderr,
        )
        sys.exit(6)


def bootstrap_vs7(vs7_source: Path) -> None:
    """Extract VS 2003 link.exe + dependencies into tools/vc6/VS7/Bin/.

    Optional — if vs7_source doesn't point at a valid VS 2003 install
    ISO, skip silently and the build falls back to VC6's linker.
    """
    if not vs7_source or not vs7_source.exists():
        print(
            f"  [vs7] source {vs7_source} not found; skipping VS 2003 linker. "
            f"Build will fall back to VC6 link.exe (OptionalHeader LinkerVersion 6.00)."
        )
        return

    # Locate the ISO in the source dir
    if vs7_source.is_dir():
        candidates = list(vs7_source.glob("*.iso"))
        iso = next((c for c in candidates if "2003" in c.name.lower()), None)
        if iso is None:
            print(
                f"  [vs7] no VS 2003 ISO found in {vs7_source}; skipping. "
                f"Expected a filename containing '2003'.",
                file=sys.stderr,
            )
            return
    elif vs7_source.is_file() and vs7_source.suffix.lower() == ".iso":
        iso = vs7_source
    else:
        print(f"  [vs7] unrecognized source {vs7_source}; skipping", file=sys.stderr)
        return

    sevenz = _check_7z_available()
    VS7_BIN_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fundoc_vs7_bootstrap_") as tmp_str:
        tmp = Path(tmp_str)
        print(f"  [vs7] extracting VS 2003 linker bits from {iso.name} ...")
        patterns = [src for src, _ in VS7_FILES_IN_ISO]
        _run_7z(sevenz, iso, tmp, *patterns)
        for src_rel, dest_name in VS7_FILES_IN_ISO:
            src_file = tmp / src_rel
            if src_file.is_file():
                shutil.copy2(src_file, VS7_BIN_DIR / dest_name)
            else:
                print(f"  [vs7] WARNING: {src_rel} not found in ISO", file=sys.stderr)

    link_exe = VS7_BIN_DIR / "link.exe"
    if not link_exe.is_file():
        print(f"  [vs7] ERROR: link.exe not staged at {link_exe}", file=sys.stderr)
        return
    try:
        result = subprocess.run(
            [str(link_exe)], capture_output=True, text=True, timeout=15
        )
        combined = result.stdout + "\n" + result.stderr
        banner = next(
            (ln.strip() for ln in combined.splitlines() if "Incremental Linker" in ln),
            None,
        )
        print(f"  [vs7] {banner or 'linker banner not captured'}")
    except Exception as e:
        print(f"  [vs7] WARNING: link.exe failed to run: {e}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description="Bootstrap VC6 SP6 into fun-doc/benchmark/tools/vc6/ from local source media."
    )
    ap.add_argument(
        "--source",
        type=Path,
        help="Directory containing en_vs6_ent_cd1.iso, en_vs6_sp6.exe, and vcpp5.exe "
        "(default: $FUNDOC_VC6_SOURCE or D:\\vc6-sp6-ent)",
    )
    ap.add_argument(
        "--vs7-source",
        type=Path,
        help="Directory or ISO for VS 2003 Professional (for link.exe 7.10). "
        "Optional — if present, the mixed VC6-compiler + VS7-linker toolchain is wired up "
        "to match D2 1.13d's OptionalHeader LinkerVersion exactly. "
        "(default: $FUNDOC_VS7_SOURCE or D:\\vs2003-pro)",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Wipe tools/vc6/VC98/ and VS7/ before extracting",
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="Skip extraction; just check the compiler banner",
    )
    args = ap.parse_args()

    if args.verify:
        sys.exit(0 if _verify() else 1)

    source = (
        args.source
        or Path(os.environ.get("FUNDOC_VC6_SOURCE", r"D:\vc6-sp6-ent"))
    )
    if not source.is_dir():
        print(
            f"ERROR: source directory {source} does not exist or is not a directory.\n"
            f"  Pass --source <path> or set FUNDOC_VC6_SOURCE.\n"
            f"  Required files: {', '.join(REQUIRED_SOURCE_FILES.values())}",
            file=sys.stderr,
        )
        sys.exit(1)

    bootstrap(source, force=args.force)

    # VS 2003 linker — optional, only if source provided or default exists.
    vs7_source = (
        args.vs7_source
        or Path(os.environ.get("FUNDOC_VS7_SOURCE", r"D:\vs2003-pro"))
    )
    if args.force and VS7_BIN_DIR.exists():
        shutil.rmtree(VS7_BIN_DIR)
    if vs7_source.exists():
        bootstrap_vs7(vs7_source)
    else:
        print(
            f"  [vs7] {vs7_source} not present; VS 2003 linker not bootstrapped. "
            f"Build will use VC6's link.exe (linker version 6.00 in the PE header). "
            f"To match D2's linker version 7.10, supply --vs7-source <path>."
        )


if __name__ == "__main__":
    main()

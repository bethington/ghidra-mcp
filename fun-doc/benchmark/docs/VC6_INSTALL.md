# Installing Visual C++ 6.0 SP6 for the benchmark toolchain

> **Status (2026-04-24):** This install is **complete** on this machine at
> `C:\VC6\`. `build.py --toolchain vc6sp6` produces a VC6 SP6 Benchmark.dll.
> The steps below document the portable-install procedure used; keep them
> for reproducibility on other machines.



The benchmark binary `Benchmark.dll` is built by the fast-tier walking skeleton with modern MSVC 2022 as a placeholder. D2 1.13d was actually compiled with **Visual C++ 6.0 SP6** (Rich-header evidence: product IDs 0x005C/0x005D/0x005E/0x005F, build 6030, dominant in D2Common.dll). Switching the benchmark toolchain to VC6 SP6 matters because MSVC's code-generation style drifted significantly between VC6 and modern compilers: different prologue/epilogue, different SEH emission, different switch-table layouts, different loop idioms. Benchmarking fun-doc's pattern-recognition against modern-MSVC decompile output grades the model on bytecode the production workers don't actually see.

## What you need

1. **Visual C++ 6.0** (the base compiler, SP0).
2. **Visual Studio 6.0 Service Pack 6** (patches the compiler to build 6030, the exact version D2 used).
3. Optional: **VS2003 `link.exe`** if you want byte-exact match to D2's mixed toolchain (D2's OptionalHeader says linker 7.10 despite the VC6 compiler). For our purposes VC6's own `link.exe` produces output that decompiles identically in Ghidra, so VS2003's linker is a nice-to-have, not a must-have.

## Where to download

Microsoft no longer publishes the VC6 installer. Legitimate sources:

- **MSDN subscribers**: available via the "MSDN Library Subscription Downloads" archive (requires an active MSDN subscription).
- **Volume License customers**: Microsoft Volume Licensing Service Center (VLSC) may still have it listed under legacy products.
- **Internet archives of original MSDN discs**: the `en_visual_cpp_6.0_msdn_library_oct_2001.iso` image circulates on archive.org — legal grey area for non-subscribers; check your situation.

For our walking-skeleton purposes the exact installer bits matter less than the resulting toolchain layout. Any install that gives you a working `C:\VC6\VC98\Bin\cl.exe` that emits "Microsoft (R) 32-bit C/C++ Optimizing Compiler Version 12.00.8804 for 80x86" (the SP6 build-6030 banner) is correct.

## Install steps

1. Mount / extract the VC6 installer (whatever media you have).
2. **Important**: install to a short path without spaces. VC6's installers are fragile around long paths and install-on-top-of-another-VS. Recommended target: `C:\VC6\` with subfolders `VC98\`, `Common\`, `Tools\`.
3. Installer phases: accept the license, choose "Visual C++ 6.0" (skip VB6, FoxPro), install to `C:\VC6`, skip MSDN install (you don't need it for command-line builds).
4. Run the SP6 installer next — point it at `C:\VC6\` so it patches the installed files in place. Verify afterwards that `cl.exe /nologo /?` banner says version 12.00.8804.
5. Re-test: open a fresh cmd.exe, set these env vars (VC6 doesn't ship a `vcvars32.bat` equivalent that Just Works on modern Windows):
   ```
   set INCLUDE=C:\VC6\VC98\Include;C:\VC6\VC98\MFC\Include
   set LIB=C:\VC6\VC98\Lib;C:\VC6\VC98\MFC\Lib
   set PATH=C:\VC6\VC98\Bin;C:\VC6\Common\MSDev98\Bin;%PATH%
   cl.exe
   ```
   You should see the banner.

## Portable install procedure actually used on this machine

Bypass the installer entirely — extract directly from the ISOs + SP6 self-extractor. This avoids the admin-required InstallShield flow and the MSJava registration failures on modern Windows.

Given the Ben-provided `D:\vc6-sp6-ent\` folder with `en_vs6_ent_cd1.iso` and `en_vs6_sp6.exe`:

```bash
# 1. Extract the VC98 tree + helper DLLs from CD1
mkdir -p /c/VC6 && cd /c/VC6
7z x /d/vc6-sp6-ent/en_vs6_ent_cd1.iso \
    "VC98" \
    "COMMON/MSDEV98/BIN/MSPDB60.DLL" \
    "COMMON/MSDEV98/BIN/MSDIS110.DLL" \
    "COMMON/MSDEV98/BIN/MSOBJ10.DLL" -y

# 2. Copy helper DLLs into VC98/Bin so cl.exe finds them alongside itself
cp /c/VC6/COMMON/MSDEV98/BIN/MSPDB60.DLL /c/VC6/VC98/Bin/
cp /c/VC6/COMMON/MSDEV98/BIN/MSDIS110.DLL /c/VC6/VC98/Bin/
cp /c/VC6/COMMON/MSDEV98/BIN/MSOBJ10.DLL /c/VC6/VC98/Bin/

# 3. Extract the SP6 self-extractor + its inner CABs
mkdir -p /c/tmp/sp6_extract
7z x /d/vc6-sp6-ent/en_vs6_sp6.exe -o/c/tmp/sp6_extract -y
mkdir -p /c/tmp/sp6_files
for n in 1 2 3 4; do
    7z x /c/tmp/sp6_extract/VS6sp6$n.cab -o/c/tmp/sp6_files -y
done

# 4. Overlay SP6-patched files onto C:\VC6\VC98\
cp -rf /c/tmp/sp6_files/vc98/bin/.     /c/VC6/VC98/Bin/
cp -rf /c/tmp/sp6_files/vc98/include/. /c/VC6/VC98/Include/
cp -rf /c/tmp/sp6_files/vc98/lib/.     /c/VC6/VC98/Lib/

# 5. CRITICAL: apply the Processor Pack C2.DLL to fix the SP6 C1/C2 mismatch
7z x /d/vc6-sp6-ent/vcpp5.exe -o/c/tmp/vcpp5 -y
cp /c/tmp/vcpp5/c2.dll /c/VC6/VC98/Bin/C2.DLL

# 6. Verify
/c/VC6/VC98/Bin/cl.exe   # should print "Version 12.00.8804 for 80x86"
```

### The SP6 C1/C2 mismatch bug

SP6 ships a patched **C1** front-end (dated 1999-10-26, IL version `19991026`) but **does NOT** ship a matching patched **C2** back-end. The base CD's C2.DLL is from 1998-06-17 (IL version `19970710`). Combining them produces:

```
fatal error C1900: Il mismatch between 'P1' version '19991026' and 'P2' version '19970710'
```

The fix Microsoft shipped for this is the **Visual C++ 6.0 Processor Pack** (distributed as `vcpp5.exe` in the Ben-provided folder), which contains a patched `c2.dll` dated 2000-11-09 that's IL-compatible with SP6's C1. Without it, SP6 compiles nothing. Step 5 above deploys it.

## Known gotchas on modern Windows

- **No admin required** for the portable install above — everything lands under `C:\VC6\` and nothing gets registered.
- **MSVCRT static** (`/MT`) is self-contained, so there's no runtime conflict with a modern MSVC also installed. Dynamic CRT (`/MD`) would link against MSVCR60.dll which modern Windows doesn't ship; avoid unless you install the VC6 runtime redistributable.
- **Path length errors during compile**: VC6's tools cap paths at 127 chars somewhere internally. Keep `C:\VC6\` and your source tree short.

## Verifying the install is benchmark-ready

```bash
# 1. cl.exe resolves to the VC6 compiler
$ cl.exe 2>&1 | head -1
Microsoft (R) 32-bit C/C++ Optimizing Compiler Version 12.00.8804 for 80x86

# 2. Rebuild Benchmark.dll with the VC6 toolchain
$ python fun-doc/benchmark/build.py --toolchain vc6sp6 --clean

# 3. Verify the Rich header now shows VC6 build 6030
$ python c:/tmp/probe_pe.py  # (the probe script we used earlier)
# Expected: product=0x005D build=6030 => C++ 6.0 (MSVC 6.0)
```

## Updating `build.py`

Once VC6 is at `C:\VC6\`, no code changes are needed — `build.py`'s `vc6sp6` toolchain entry is already wired with those paths. Pass `--toolchain vc6sp6` to switch.

If you install to a different path, override via env var:

```bash
export FUNDOC_VC6_DIR="D:\tools\VC6"     # not yet supported; file an issue if you need this
```

(For now the paths are hard-coded; we'll make them env-overridable the moment the first person wants to deviate.)

## When the swap is done

Rebuild the benchmark + regenerate ground truth, then re-run with `--mock` to verify the pipeline still works:

```bash
python fun-doc/benchmark/build.py --toolchain vc6sp6 --clean
python fun-doc/benchmark/extract_truth.py
python fun-doc/benchmark/run_benchmark.py --mock --tier fast --variant baseline
```

Scores on the mock path should be unchanged (the scoring rubric doesn't care which compiler produced the binary), but the `--real` path will now exercise fun-doc against bytecode idioms that match D2's production binaries — that's the whole point.

# Installing Visual C++ 6.0 SP6 for the benchmark toolchain

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

## Known gotchas on modern Windows

- **Admin-required installer**: VC6's setup writes to HKLM; run it elevated.
- **"Access denied" on MSJava**: one of the installer steps tries to register MSJava DLLs which Windows 10/11 refuse. Ignore the error and continue — the C/C++ toolchain installs fine.
- **MSVCRT mismatch** if you also have a modern MSVC installed: VC6's static CRT (`/MT`) is self-contained, so there's no conflict. Dynamic CRT (`/MD`) would link against MSVCR60.dll which modern Windows doesn't ship; avoid unless you install the VC6 runtime redistributable.
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

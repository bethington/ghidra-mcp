# Visual C++ 6.0 SP6 toolchain (local only)

**If you're reading this because `build.py --toolchain vc6sp6` failed with "cl.exe not found" or you see this directory is nearly empty — that's expected.** This directory holds the VC6 SP6 compiler toolchain on your local machine, but the binaries themselves are not committed to the repository.

See `NOTICE.md` in this directory for the legal reasoning. The short version: VC6 is proprietary Microsoft software; copyright runs to ~2093; there is no clean legal exemption that covers redistributing Microsoft binaries in a public GitHub repo for "preservation" or "archival" purposes. The bootstrap script + this README document the procedure without distributing the binaries themselves.

## How to populate this directory

You need your own licensed copy of **Visual Studio 6.0 Enterprise** (or Professional — Standard also works for our purposes) plus **SP6** plus the **Visual C++ 6.0 Processor Pack**. Sources:

- An original physical MSDN or Visual Studio 6.0 disc you purchased.
- An active MSDN subscription (legacy product downloads may still be listed).
- Your company's MS Volume Licensing archive.
- Public mirrors like the Internet Archive host the bits without takedowns, under their own § 108 / preservation posture. **Using those is between you and Microsoft** — this project takes no position on third-party mirrors.

### Option 1 — automated extraction from media you own

If your source files live at `D:\vc6-sp6-ent\` (`en_vs6_ent_cd1.iso`, `en_vs6_sp6.exe`, `vcpp5.exe`) and optionally `D:\vs2003-pro\` (the VS 2003 Pro ISO for the linker), the bootstrap script handles extraction end-to-end:

```bash
python fun-doc/benchmark/tools/bootstrap_vc6.py \
    --source D:\vc6-sp6-ent \
    --vs7-source D:\vs2003-pro        # optional but recommended — see below
```

The script:
1. Extracts `VC98\` tree and helper DLLs (MSPDB60 / MSDIS110 / MSOBJ10) from CD1 via 7-Zip
2. Extracts the SP6 self-extractor and its four inner CABs, overlays the patched files
3. Extracts the Processor Pack `c2.dll` (the SP6 C1/C2 mismatch workaround) and deploys it
4. **Optional**: extracts VS 2003 `link.exe` + `cvtres.exe` + its DLL dependencies (`mspdb71.dll`, `msdis140.dll`, `msvcr71.dll`) into `VS7/Bin/`. This is the mixed toolchain D2 1.13d actually used — VC6 SP6 compiler paired with VS 7.10 linker. If you skip this, the build falls back to VC6's own `link.exe` 6.00, which works but produces `OptionalHeader.MajorLinkerVersion = 6.00` instead of D2's `7.10`, and lacks the `/OPT:ICF` feature Blizzard relied on.

All output lands under `fun-doc/benchmark/tools/vc6/VC98/` (compiler) and `fun-doc/benchmark/tools/vc6/VS7/` (linker). Nothing in this directory is ever committed to git — the `.gitignore` in this folder enforces that.

### Option 2 — manual extraction

Follow the step-by-step procedure in `../../docs/VC6_INSTALL.md`. That document was written first and the bootstrap script is an automation of those same steps.

### Option 3 — point at an existing VC6 install elsewhere on disk

If you already have VC6 installed in the conventional `C:\Program Files\Microsoft Visual Studio\VC98\` location or a portable install elsewhere, set:

```bash
export FUNDOC_VC6_ROOT=C:\your\vc98\path     # contains Bin/, Include/, Lib/
```

`build.py` will honor that env var instead of the in-project path (TODO if not already wired — check `build.py`'s `vc6sp6` entry).

## Verifying the install

Once populated:

```bash
./tools/vc6/VC98/Bin/cl.exe
# expected: Microsoft (R) 32-bit C/C++ Optimizing Compiler Version 12.00.8804 for 80x86

python fun-doc/benchmark/build.py --toolchain vc6sp6 --clean
# expected: [build] ok ... Benchmark.dll (45KB)
```

## Why not just commit the binaries?

Three reasons, in order of seriousness:
1. **Legal**: VC6 is Microsoft-copyrighted through ~2093. No 17 USC § 108, § 1201, fair-use, or "abandonware" doctrine shields a public GitHub repo from a DMCA takedown for redistributing Microsoft's compiler binaries.
2. **Licensing responsibility stays with the end user**: if anyone cloning this repo uses VC6 without their own license, that's their liability to resolve — not ours via accidental redistribution.
3. **Repo size**: even trimmed, the toolchain is ~35-75 MB of binaries. Git doesn't love that.

## When this breaks

If `build.py --toolchain vc6sp6` fails after you've populated this directory:

- **"cl.exe not found"** — the binaries aren't where `build.py` expects. Verify `tools/vc6/VC98/Bin/cl.exe` exists.
- **"fatal error C1900: Il mismatch between P1 version '19991026' and P2 version '19970710'"** — SP6's C1 is paired with SP0's C2. You need the Processor Pack `c2.dll`. `bootstrap_vc6.py` handles this automatically; if you installed manually, see `../../docs/VC6_INSTALL.md` § "The SP6 C1/C2 mismatch bug".
- **"C1.DLL missing"** — SP6 didn't overlay correctly. Re-run the bootstrap.

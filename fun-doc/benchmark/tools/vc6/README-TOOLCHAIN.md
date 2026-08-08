# Era toolchains (gitignored — provenance + how to re-create)

This directory is named `vc6` for historical reasons. It now holds **two**
toolchains, and **VS2003 is the one that matters for D2**.

| Dir | What | Role |
| --- | --- | --- |
| `VS7/` | Visual Studio .NET 2003 (7.1) — `cl.exe` 13.10.3077, `link.exe` 7.10 | **Primary.** The compiler that actually built D2 1.13c. |
| `VC98/` | Visual C++ 6.0 SP6 — `cl.exe`, headers, libs | Fallback; also the only source of Win32 Platform SDK headers (`windows.h`, `winbase.h`) here. |
| `COMMON/` | shared VC6 bits | — |

## Why VS2003 is the right compiler (measured, not assumed)

Rich-header product IDs of the shipped binaries name their own compiler:

* `Game.exe` (PD2-S12): 89 × `Utc1310_C` build **6030**, 20 × masm 6030,
  2 × `Utc1310_CPP` 6030 — and **zero** VC6 (VC6 SP6 is build 8804).
* D2Common / D2Client / D2Game / Fog / Storm: same, all 710-series 6030.

Build 6030 = **VS .NET 2003 SP1**.

Corroborated by exact bytes: every one of the 103 FID-identified CRT
functions in `Game.exe` is byte-identical (relocations masked) to its object
in `VS7/Lib/libcmt.lib`. The same comparison against `VC98/LIB/LIBCMT.LIB`
matches only 11/103 (10.7%), and those 11 are tiny SEH/mbcs helpers that
happen to be identical in both toolchains.

## The `msvcp71.dll` gotcha (fixed 2026-08-08)

`VS7/Bin/cl.exe` spawns `c1.dll`, which imports six `std::basic_string`
symbols from **`MSVCP71.dll`**. That DLL was missing from this tree and from
the whole machine, so `cl.exe` failed with:

```
cl : Command line error D2027 : cannot execute '...\VS7\Bin\c1.dll'
```

`link.exe` was unaffected (it needs only `mspdb71` + `msvcr71`, both
present) — **which is exactly why `build.py`'s `vc6sp6` toolchain pairs
VC6's compiler with VS2003's linker.** That combination reproduces the PE /
Rich-header shape but *not* compiler codegen, so it cannot byte-match
authored D2 code.

Fixed by copying `msvcp71.dll` (+ `.pdb`) here from the VS2003 Pro
installation media. With it in place `cl.exe` runs and byte-matching works
(see below).

## Provenance — re-creating this tree

Source: Visual Studio .NET 2003 Professional ISOs, unarchived to
`D:\vs2003-pro` (2026-08-08).

| Here | From |
| --- | --- |
| `VS7/Bin`, `VS7/Include`, `VS7/Lib` | `…\Vc7\{bin,include,lib}` (already vendored; verified complete: include 151/151, lib 45/45) |
| `VS7/Bin/msvcp71.dll`, `.pdb` | `D:\vs2003-pro\Win\System\` |
| `VS7/crt-src/` | `…\Vc7\crt\src` — **813 files of VS2003 CRT source**, reference for CRT behaviour and for matching CRT code the `.lib` cannot supply |

No Platform SDK ships in this media set; use `VC98/Include` for `windows.h`
and friends when compiling with `VS7/Bin/cl.exe`.

## Verified byte-match recipe

`DATATBLS_FindConfigOptionIndex` @ `0x004078e0` in PD2-S12 `Game.exe`,
92 bytes / 1 relocation / 88 informative bytes — **exact match**:

```c
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
int __stdcall F(const char *s) {
    unsigned i;
    for (i = 0; i < ARRAY_SIZE(gaCmdArguments); i++)
        if (0 == strcmp(gaCmdArguments[i].szCommand, s)) return i;
    return -1;
}
```

`VS7/Bin/cl.exe /c /O2` (also matches under `/Ox`, `/O2 /Ob0`, `/O2 /Gy`,
`/O2 /GF`, `/O2 /Oa` — codegen is robust across those, so no fragile flag
archaeology is needed).

Two findings worth keeping:

* **The loop comparison must be UNSIGNED.** `for (int i = 0; i < 57; i++)`
  emits `JL` and is 96 bytes; the original emits `JB`. Any `ARRAY_SIZE`
  (sizeof-based, hence `size_t`) or an `unsigned` counter produces the
  match — and `int i < ARRAY_SIZE(...)` works too, because `i` promotes.
* **VC6 matched none of the variants**, at any flag setting. The compiler
  identity is not a detail.

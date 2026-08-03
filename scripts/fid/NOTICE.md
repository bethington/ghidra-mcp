# NOTICE — provenance of the committed Function ID databases

`vc6_vc98.fidb` and `vs2003_libcmt.fidb` are Ghidra Function ID databases
generated from Microsoft C runtime static libraries:

| Database | Generated from | Signatures |
| --- | --- | --- |
| `vc6_vc98.fidb` | Visual C++ 6.0 SP6 `LIBCMT.LIB` | 1,030 |
| `vs2003_libcmt.fidb` | Visual Studio .NET 2003 `libcmt.lib` | 1,049 |

## What a FID database contains — and does not

A `.fidb` is a signature index. Per function it stores a **hash** of the
instruction bytes (with operands that vary by link address masked out), the
**symbol name**, and library metadata — name, version, variant. It does **not**
contain the compiled functions, their instruction bytes, source code, headers,
or any part of the libraries themselves. It cannot be used to reconstruct or
link against the runtime; the hashes are one-way and deliberately lossy, which
is why `FAILS_MINIMUM_SHORTHASH_LENGTH` discards short functions outright (52
of them in the VS2003 build).

Its only function is recognition: given an unknown binary, decide whether a
function matches a known library routine and, if so, what it is called. That is
the same category of artifact as a virus signature or a FLIRT pattern file.

## Why they are committed rather than gitignored

The libraries they derive from are **not** in this repository. The toolchains
live outside it — `C:\VC6\`, `C:\VS2003\`, and the per-machine tree under
`fun-doc/benchmark/tools/vc6/` — all gitignored, and populated by the operator
from their own licensed media (see `fun-doc/benchmark/tools/vc6/NOTICE.md`).

Committing the databases lets a contributor reproduce and verify the analysis
results in this repo without needing that media, while the media itself is
never redistributed. `build-vc6-fiddb.ps1` regenerates either database from a
local install if you would rather build your own.

If you consider this posture wrong for your use, delete the two `.fidb` files
and regenerate them locally; nothing else in the repo depends on them being
checked in.

## Measured value — read before assuming these help

Neither database is a general win. Coverage depends entirely on whether the
target binary links the *same* CRT build:

    Benchmark.dll   (VC6-compiled)      12 -> 87 with vc6_vc98.fidb  (7x)
    D2Common.dll    (VS2003-compiled)  175 -> 204 with vs2003_libcmt.fidb
    D2Client.dll                       241 -> 241  (+0)
    D2Game.dll                         235 -> 235  (+0)
    Fog.dll                            273 -> 273  (+0)

Ghidra's stock `vsOlder_x86.fidbf` already covers most VS2003-era CRT, so the
VS2003 database adds little to binaries stock already handles. See
`README.md` in this directory for the full diagnosis.

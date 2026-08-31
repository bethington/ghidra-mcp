# Benchmark fixture

The subject of the deploy-regression tiers. `python -m tools.setup deploy
--test <tier>` imports these two binaries into the live Ghidra project at
`/testing/benchmark/` and asserts against them.

```text
make_fixture.py            the generator: emits both binaries and the manifest
x86.py                     a minimal 32-bit x86 assembler
pe32.py                    a minimal PE32 image writer
Benchmark.dll              generated, committed  (image base 0x10000000)
BenchmarkDebug.exe         generated, committed  (image base 0x00400000)
build_manifest.json        generated, committed  provenance + digests
regression/*.yaml          the value assertions the `release` tier runs
```

## Why it is generated, not compiled

The fixture this replaces was compiled from C by a pinned MSVC 6 / VS2003
toolchain that lived outside git, and the build outputs were gitignored. Three
consequences, all of which actually happened:

1. **It could not survive a directory move.** `fun-doc/` moved to the
   `d2-game-exe` repository on 2026-08-10 and took the fixture with it. Six of
   the eight deploy tiers — `release`, `benchmark-read`, `benchmark-write`,
   `multi-program`, `debugger-live`, `negative-contract` — raised in
   `reset_benchmark_fixture()` from that day until this one. `release` is the
   release-regression workflow's default tier and the gate the release
   checklist names.
2. **It could not be rebuilt without the media.** Anyone without a licensed VC6
   or VS2003 install had no fixture and therefore no gate.
3. **A toolchain change moved every address silently.** The old baseline says so
   in its own header: a 2026-08-08 switch from `vc6sp6` to `vs2003` moved
   `compute_gcd` by 0x70 and the entry point by 0x105 with the C sources
   untouched, and both toolchains link at the same base and report the same
   linker version, so the PE headers could not tell them apart.
   `build_manifest.json` was the only witness.

This generator has no inputs but its own source. It emits byte-identical images
on any machine with a Python interpreter and no compiler at all, and
`tests/unit/test_benchmark_fixture.py` regenerates them in CI and compares
byte-for-byte against what is committed.

## Regenerating

```text
python tests/fixtures/benchmark/make_fixture.py            # rewrite the binaries
python tests/fixtures/benchmark/make_fixture.py --check    # verify, write nothing
```

Any change to `make_fixture.py`, `x86.py` or `pe32.py` changes the output. When
that moves a function, `regression/*.yaml` must move with it —
`tests/unit/test_benchmark_fixture.py` fails offline, in seconds, with no Ghidra,
if the two disagree. That is the whole point of generating rather than observing:
the address-keyed baseline can still go stale, but it can no longer go stale
quietly and surface as a red deploy gate on release day.

## What is in the binaries

Eleven exported functions, laid out in `.text` in this order, plus an entry
point. Both images carry the same bodies at the same section offsets, so their
addresses differ only by image base.

| Function | Params | Basic blocks | Shape |
| --- | --- | --- | --- |
| `calc_crc16` | 2 | 10 | Nested loops, CRC-16/CCITT (`0x1021`, `0xFFFF`); five recovered variables |
| `compute_gcd` | 2 | 4 | Euclidean remainder loop; decompiles with a `%` |
| `compute_str_len` | 1 | 4 | Null-terminator scan |
| `advance_parser_state` | 2 | 20 | Five-state ladder; the structurally densest function here |
| `stat_list_add` | 4 | 4 | The widest signature; writes through a pointer, bumps a global |
| `get_stat_list_flags` | 1 | 4 | Field accessor with a null guard |
| `get_stat_list_layer` | 1 | 4 | Field accessor, shifted |
| `get_stat_list_owner_guid` | 1 | 4 | Field accessor |
| `get_stat_list_prev_link` | 1 | 4 | Field accessor |
| `benchmark_self_test` | 0 | 1 | The only non-leaf: calls three of the above and one import |
| `benchmark_describe` | 0 | 1 | Returns a pointer into `.rdata` |
| entry point | — | 3 / 21 | `DllMain` in the DLL; the whole program in the EXE |

`calc_crc16` is the anchor: `tools.setup.ghidra` looks it up by name
(`DEFAULT_BENCHMARK_FUNCTION`), and the `benchmark-write` tier renames and
re-types it. Its `crc`, `i` and `j` live in stack slots rather than registers on
purpose — the write tier needs a named, non-phantom local to operate on, and
Ghidra recovers exactly three (`local_8`, `local_c`, `local_10`) plus two
parameters.

`benchmark_self_test` exists so the others have inbound cross-references. Without
it every function would be reachable only from the export table and the xref and
callee assertions in `regression/` would be vacuous.

Also present, because the tiers query them: six `KERNEL32` imports, 66 strings,
six globals in `.data`, and the four sections `Headers`, `.text`, `.rdata`,
`.data`.

## How the fixture proves itself

`BenchmarkDebug.exe` is a real 32-bit console program with no CRT. It picks a
mode by scanning its own command line:

| Command line contains | Behaviour |
| --- | --- |
| `@` | `LoadLibraryA("Benchmark.dll")`, `GetProcAddress("calc_crc16")`, call it, exit with the result |
| `-` | Sleep for three minutes so a debugger can attach — the mode `run_debugger_live_test` gets, since it launches with `--seconds 180` |
| neither | Exit immediately with the banner CRC |

`tests/unit/test_benchmark_fixture.py` runs the first and third of those on
Windows and checks the exit code against a CRC computed in Python. A pass means
the Windows loader accepted both images, resolved the `KERNEL32` imports,
resolved `calc_crc16` through the DLL's *export table*, ran `DllMain`, and
executed the generated machine code correctly. It is a stronger statement about
the fixture than any structural check on the file, and it needs neither Ghidra
nor a 32-bit Python.

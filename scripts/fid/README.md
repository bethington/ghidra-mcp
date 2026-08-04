# Function ID tooling

Ghidra's Function ID (FID) analyzer recognises statically-linked library code by
hashing function bodies and looking them up in a signature database. It matters
here for one reason: **an FID match is both a correct classification and a
correct name, produced by an analyzer instead of a language model.** Where FID
fires, no LLM should be naming that function at all.

## What is in here

| File | What it is |
| --- | --- |
| `vc6_vc98.fidb` | 1,030 signatures built from VC6 `LIBCMT.LIB`, the multithreaded static CRT that Diablo II 1.13c links. Committed so it survives a temp-folder wipe. |
| `vc6_vc98_build_report.txt` | The populate run's own report: 1,100 functions visited, 1,030 added, 70 excluded (43 hash-too-short, 19 duplicate, 6 thunk, 2 unnamed). |
| `vs2003_libcmt.fidb` | 1,049 signatures built from **VS2003's `libcmt.lib`** — the CRT Diablo II actually links (see below). Its internal metadata reads `VisualStudio:VC6:/:libcmt` because it was built before `build-vc6-fiddb.ps1` took `-LibraryName`/`-LibraryVersion`; the signatures are right, the self-description is not. Rebuild with those params set if the provenance ever needs to be trustworthy. |
| `vs2003_libcmt_dupes.txt` | That build's report: 1,120 visited, 1,049 added, 71 excluded. |
| `build-vc6-fiddb.ps1` | Rebuilds the database from any static-library directory. |
| `CountFidMatches.java` | Counts FID matches in a program, so a database's value can be measured rather than assumed. |
| `ReportFidCoverage.java` | Splits coverage into authored vs library code on `Benchmark.dll`, where we wrote every game function. Reports library coverage AND false positives against our own code — the check that makes the D2 results trustworthy. |

## What it actually buys — measured

Controlled A/B on fresh imports, stock databases versus stock plus this one:

| Binary | Stock | Stock + VC6 db | Delta |
| --- | --- | --- | --- |
| `Benchmark.dll` (links **our** LIBCMT) | 12 | **87** | **+75** |
| `D2Common.dll` | 175 | 176 | +1 |
| `D2Client.dll` | 216 | 216 | +0 |

On the benchmark — the one binary here with **known ground truth**, because we
wrote every game function in it — `ReportFidCoverage.java` gives:

```
authored=9   authored_falsely_claimed=0
library=94   library_identified=87   library_missed=7   coverage_pct=92
```

92% of the runtime identified, and **zero false claims against our own code**.
Two of the 7 misses (`RtlUnwind`, `entry`) are an ntdll thunk and a
linker-generated stub, so neither is LIBCMT code — real coverage is ~95%.

That is the result that justifies trusting this tooling on the D2 binaries,
where no ground truth exists to check against.

## Why D2 sees no benefit — and why that is the interesting part

An earlier revision of this file read the D2 numbers as "the database buys
nothing" and declared extending FID coverage a dead avenue. **That was wrong.**
It generalised from two binaries to a conclusion the benchmark flatly refutes.

The database is not redundant with Ghidra's stock `vsOlder_x86.fidbf` — stock
finds only 12 of 151 functions in a binary built by this exact toolchain. D2
gains nothing for an entirely different reason: **D2's statically-linked CRT is
not this LIBCMT.** Same observation, different cause, and the cause is
actionable in a way "it's redundant" never was.

**The cause is now identified — it is not a service pack.** Two measurements:

1. **Byte comparison.** Known-CRT functions in D2Common were compared against
   the same symbols extracted from VC6's `LIBCMT.LIB`, with relocation sites
   masked: `_qsort` 6%, `_atol` 18%, `__stricmp` 15%, `_sprintf` 17% — noise.
   The same method run against `Benchmark.dll`, which links this LIBCMT, gives
   `_strlen` **100.0%** and `_memset` **100.0%**, so the method is sound and the
   D2 mismatch is real. A service-pack difference would look like 80–95%, not 6%.

2. **Rich headers.** Every shipped D2 binary (D2Common, D2Client, D2Game, Fog,
   Storm) contains **zero** VC6-compiler objects — no `Utc12_*` product IDs at
   all. Every entry is a 710-series product at build **6030**, i.e. Visual
   Studio .NET 2003 SP1 (7.10.6030). VC6 SP6 is build 8804.

**D2 is compiled and linked with VS2003 SP1, not VC6.** That is why a VC6 LIBCMT
database recognises 92% of the benchmark and ~0% of the game: it is the wrong
CRT entirely, not a near-miss.

### Outcome — measured, and mostly negative

The VS2003 `libcmt.lib` was extracted and a database built from it (1,049
signatures, `vs2003_libcmt.fidb`). The diagnosis held at the byte level:
D2Common's `_qsort`, `_atol` and `_sprintf` are **100.0% identical**
(relocation-masked) to VS2003's libcmt, against 6-18% for VC6's.

But identifying the right library did **not** translate into broad coverage:

| Binary | functions | stock | + vs2003 db | delta |
| --- | --- | --- | --- | --- |
| D2Common.dll | 2,355 | 175 | 204 | **+29** |
| D2Client.dll | 4,442 | 241 | 241 | +0 |
| D2Game.dll | 4,506 | 235 | 235 | +0 |
| Fog.dll | 1,007 | 273 | 273 | +0 |

One binary in four gained anything. The reason is that Ghidra's stock
`vsOlder_x86.fidbf` already covers most VS2003-era CRT — which is also why it
covered D2 (175) far better than it covered our VC6-built benchmark (12).

So the corpus-wide ceiling here is low, and an earlier estimate in this file of
"roughly 7x, 500-1,000 functions corpus-wide" was extrapolated from a single
binary and is wrong. The database is worth keeping — it is built, free to
attach, and D2Common's +29 is real — but it does not materially shrink the
documentation queue.

**The residual unidentified code is therefore mostly NOT stock CRT.** Whatever
is left in D2Client/D2Game/Fog after stock FID is either game code, inlined CRT
that hash-exact matching cannot reach, or a runtime component still
unaccounted for. Chasing it needs a different technique than more FID
databases.

### If you still want to close the remaining gap — read this first

**Building the VS2003 database is already done** (`vs2003_libcmt.fidb`, above),
and the answer it gave is the one in the table: +29 on one binary, +0 on three.
An earlier revision of this section sat here predicting that the benchmark's 7×
would transfer to the game binaries. It did not, and that prediction is exactly
the one-binary extrapolation this file has now made twice. Do not build a third
CRT database expecting a different answer.

What is genuinely still open is smaller and more specific:

1. **The databases are attached but the corpus was never re-analyzed.** Both
   `.fidb` files are registered in Ghidra's `FID.USER.ADDED` preference, which
   only affects analysis performed *after* attaching. The live PD2-S12 programs
   still carry stock-only results — D2Common shows exactly 175 `Function ID
   Analyzer` bookmarks against the 204 the A/B measured. Re-running the Function
   ID analyzer on already-documented programs is the step that banks the +29,
   and the step that can relabel work fun-doc already did; `fun-doc/scripts/
   restore_fid_names.py` is the inverse tool and has already had to undo 143.
2. **Techniques other than hash-exact matching.** What is left unidentified is
   game code, inlined CRT, or a runtime component still unaccounted for. BSim
   similarity reaches inlined and re-optimised code that FID's exact hashing
   structurally cannot.

## Measuring a database before trusting it

```powershell
# baseline: stock databases only
analyzeHeadless <proj> base -import <binary> `
    -scriptPath scripts/fid -postScript CountFidMatches.java

# with the candidate attached
analyzeHeadless <proj> withdb -import <binary> `
    -scriptPath scripts/fid -preScript AttachFidDatabase.java `
    -postScript CountFidMatches.java
```

`AttachFidDatabase.java` prompts, so headless runs need an
`AttachFidDatabase.properties` beside it **inside the Ghidra installation**:

```
Attach existing FidDb Attach = <absolute path to .fidb>
```

Remove that file afterwards — a stray `.properties` in the Ghidra install
silently answers prompts for every later headless run of that script.

## Headless traps encoded in the build script

1. `-recursive` needs an explicit depth in Ghidra 12; bare `-recursive` aborts
   with `Invalid recursion depth: null`.
2. Script property **keys** are the ask's title joined to its second argument
   (`Duplicate Results File OK`, not `Duplicate Results File`). The error message
   names the key it wanted — the only practical way to discover this.
3. **`analyzeHeadless` exits 0 even when a script throws.** Two runs reported
   success while producing an empty 671-byte `.fidb`. Scrape the log for
   `SCRIPT ERROR` *and* verify the artifact.
4. The `.fidb` must be attached in the **same JVM** that populates it;
   `CreateEmptyFidDatabase` registers it through user preferences, which do not
   survive into the next headless process.
5. `-processor`/`-cspec` are mandatory on import. Left to infer, the COFF loader
   assigns a compiler spec per object and picks `gcc` for some, and population
   then aborts on a mismatch *after* every object has already imported.

## Using a database against the corpus

Attach via *Tools → Function ID → Choose active FidDbs*, re-run the Function ID
analyzer, then check what changed:

```bash
python fun-doc/doc_lint.py --program /Mods/PD2-S12/D2Common.dll
```

`doc_lint` treats FID matches as tier 0 — read from `Function ID Analyzer`
bookmarks, which survive renames and therefore make an overwritten library name
recoverable rather than merely detectable.

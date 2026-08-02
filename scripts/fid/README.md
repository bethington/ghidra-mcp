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

Untested leads, in rough order of likelihood:

1. **A different VC6 service pack.** FID hashes need near-exact code equality,
   so an SP5-vs-SP6 `.obj` will not match even for identical source.
2. **A different CRT variant.** The measured runs used `-Libs LIBCMT` only;
   `LIBC.LIB` was never built. Note D2 *does* link a multithreaded CRT — its
   restored names include `__mtinitlocks` and `__lock_file2` — which argues for
   an SP-level difference over a single-threaded lib.

If either lands, expect the same order of improvement on the game binaries that
the benchmark shows: roughly 7×, which would take a large slice of D2's ~66,000
unidentified functions out of scope in one step.

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

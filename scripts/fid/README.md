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

## Read this before building another database

**The VC6 database was measured to buy essentially nothing.** Controlled A/B on
fresh imports, stock databases versus stock plus this one:

```
D2Common.dll   175 -> 176 FID matches   (+1)
D2Client.dll   216 -> 216 FID matches   (+0)
```

Ghidra already ships VC6-era coverage as
`Ghidra/Features/FunctionID/data/vsOlder_x86.fidbf`, alongside
vs2012/2015/2017/2019. Those files are `.fidbf` — **packed** — so searching for
`*.fidb` finds nothing and invents a coverage gap that does not exist. That is
exactly the mistake that produced this database.

The corollary is the useful part: **the low corpus-wide match rate (4,325 of
70,146 functions) is not a database gap.** Do not build a UCRT database
expecting a different outcome — `vs2019_x86.fidbf` already covers BH.dll and
ProjectDiablo.dll. FID hashing needs near-exact code equality, so inlined and
differently-optimised CRT cannot match whatever is loaded. PD2_EXT.dll is mostly
CRT and still matches only 184 of 468 (39%) for that reason.

The tooling is kept because the machinery is correct and reusable for a
toolchain Ghidra genuinely does not ship, and because the headless traps it
encodes are expensive to rediscover.

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

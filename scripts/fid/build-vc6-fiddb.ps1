<#
.SYNOPSIS
    Build a Ghidra Function ID database from a Visual C++ 6 installation.

.DESCRIPTION
    Builds a Function ID database from a set of static libraries.

    MEASURED RESULT: this database WORKS, dramatically, on any binary that
    links the same LIBCMT.LIB it was built from. Controlled A/B on fresh
    imports, stock databases vs stock + this one:

        Benchmark.dll   12 -> 87 FID matches   (+75, a 7x jump)
        D2Common.dll   175 -> 176              (+1)
        D2Client.dll   216 -> 216              (+0)

    On the benchmark binary -- compiled by this toolchain and statically linking
    this LIBCMT -- coverage of non-authored functions is 92% (87 of 94), with
    ZERO false claims against the 9 hand-written functions. Of the 7 misses,
    `RtlUnwind` is an ntdll import thunk and `entry` is linker-generated, so
    neither is LIBCMT code at all.

    READ THE D2 NUMBERS CORRECTLY. An earlier revision of this header concluded
    from them that the database "buys nothing" and that extending FID coverage
    was a dead avenue. That was wrong -- it generalised from the wrong binaries.
    The database is NOT redundant with Ghidra's stock `vsOlder_x86.fidbf`: stock
    finds only 12 of 151 functions in a binary built by this exact toolchain. It
    adds nothing to D2Common/D2Client for a different reason entirely -- **D2's
    statically-linked CRT is not this LIBCMT**. Same observation, completely
    different cause, and the cause is the actionable part: identify the CRT
    variant Blizzard actually linked and rebuild against that.

    Untested candidates for it: a different VC6 service pack, or LIBC.LIB
    (single-threaded) rather than LIBCMT.LIB. The -Libs default below includes
    LIBC so this can be tried; the runs above used `-Libs LIBCMT` only.
    Note D2 does use a multithreaded CRT (its restored names include
    `__mtinitlocks` and `__lock_file2`), which argues for an SP-level or build
    difference over a single-threaded lib.

    Measure any new database with ReportFidCoverage.java against Benchmark.dll
    before trusting it -- that is the only binary here with known ground truth.


    THREE STAGES, all headless and re-runnable:
      1. Import  -- each .lib is a COFF archive; Ghidra imports every .obj
                    member as a separate program and analyses it.
      2. Create  -- an empty .fidb.
      3. Populate-- CreateMultipleLibraries hashes the imported programs into
                    the database.

    Stage 3 uses Ghidra's own script, which prompts. Headless answers come from
    a `.properties` file that must sit NEXT TO the script inside the Ghidra
    installation -- this script writes it there and removes it afterwards.

.PARAMETER Vc6Lib
    VC6 library directory. Default C:\VC6\VC98\LIB.

.PARAMETER Libs
    Which archives to ingest. LIBCMT (multithreaded static CRT) is the one D2
    1.13c links; the others are cheap to add and harmless if unused.

.PARAMETER OutFidb
    Destination .fidb path.

.EXAMPLE
    ./scripts/fid/build-vc6-fiddb.ps1
    ./scripts/fid/build-vc6-fiddb.ps1 -Libs LIBCMT,LIBC -OutFidb C:\tmp\vc6.fidb
#>
[CmdletBinding()]
param(
    [string]$GhidraDir = 'F:\ghidra_12.1.2_PUBLIC',
    [string]$Vc6Lib    = 'C:\VC6\VC98\LIB',
    [string[]]$Libs    = @('LIBCMT', 'LIBC'),
    # Staging project for the imported .obj programs -- ~531 MB, scratch only,
    # deliberately NOT in the repo. Only the resulting .fidb is committed.
    [string]$ProjectDir  = 'C:\tmp\fidproj',
    [string]$ProjectName = 'vc6fid',
    # Lands next to this script so the database is a committed project asset
    # rather than something that evaporates with the temp folder.
    [string]$OutFidb   = "$PSScriptRoot\vc6_vc98.fidb",
    [string]$LanguageId = 'x86:LE:32:default',
    [string]$CompilerSpec = 'windows',
    [switch]$SkipImport
)

$ErrorActionPreference = 'Stop'
$headless  = Join-Path $GhidraDir 'support\analyzeHeadless.bat'
$fidScripts = Join-Path $GhidraDir 'Ghidra\Features\FunctionID\ghidra_scripts'
if (-not (Test-Path $headless))  { throw "analyzeHeadless not found: $headless" }
if (-not (Test-Path $fidScripts)){ throw "FID scripts not found: $fidScripts" }

# --- 1. import -------------------------------------------------------------
# CreateMultipleLibraries derives Library/Version/Variant from folder depth 3,
# so the project layout must be <root>/<Name>/<Version>/<Variant>/<programs>.
if (-not $SkipImport) {
    foreach ($lib in $Libs) {
        $archive = Join-Path $Vc6Lib "$lib.LIB"
        if (-not (Test-Path $archive)) { Write-Warning "missing: $archive"; continue }
        Write-Host "importing $lib ..."
        # -recursive needs an explicit depth in Ghidra 12; without it the
        # launcher dies with "Invalid recursion depth: null".
        #
        # -processor/-cspec are NOT optional here. Left to guess, the COFF
        # loader assigns a compiler spec per object and picks 'gcc' for some of
        # them; population then aborts on the first mismatch with "Program
        # rtti.obj has different compiler spec (windows) than already
        # established (gcc)" after the whole import has already run.
        & $headless $ProjectDir "$ProjectName/VisualStudio/VC6/$lib" `
            -import $archive -recursive 1 -analysisTimeoutPerFile 60 `
            -processor $LanguageId -cspec $CompilerSpec
        if ($LASTEXITCODE -ne 0) { throw "import of $lib failed ($LASTEXITCODE)" }
    }
}

# --- 2. create the empty database ------------------------------------------
if (Test-Path $OutFidb) {
    Write-Host "reusing existing $OutFidb"
} else {
    $props = Join-Path $fidScripts 'CreateEmptyFidDatabase.properties'
    Set-Content -Path $props -Encoding ASCII -Value @(
        "Create new FidDb file Create = $OutFidb"
    )
    try {
        # analyzeHeadless exits 0 even when a preScript throws, so the exit
        # code cannot be trusted -- scrape the log and check the artifact.
        $log = & $headless $ProjectDir $ProjectName -noanalysis `
            -preScript CreateEmptyFidDatabase.java 2>&1
        $log | Write-Verbose
        if ($log -match 'SCRIPT ERROR') {
            $log | Where-Object { $_ -match 'SCRIPT ERROR' } | Write-Host
            throw 'CreateEmptyFidDatabase failed -- see error above'
        }
        if (-not (Test-Path $OutFidb)) { throw "FidDb was not created: $OutFidb" }
    } finally { Remove-Item $props -ErrorAction SilentlyContinue }
}

# --- 3. populate ------------------------------------------------------------
# Duplicate detection is deliberately ON: a hash that matches several different
# library functions is worse than no match, because FID would then assert a
# name it cannot justify.
# Headless property KEYS are the ask's title joined to its second argument --
# the approve-button label for askFile, the question for askYesNo/askString,
# the message for askChoice. Using the bare title fails with
# "Error processing variable 'Duplicate Results File OK'", which names the key
# it actually wanted.
$dupes = $OutFidb -replace '\.fidb$', '_dupes.txt'

# The database must be ATTACHED in the same JVM that populates it.
# CreateEmptyFidDatabase registers it via addUserFidFile, but that registration
# lives in user preferences and does not survive into the next headless
# process -- populate then dies with "Could not find any fidb files that can be
# populated" while the .fidb sits right there on disk. Chaining
# AttachFidDatabase as an earlier -preScript in the SAME run fixes it.
$attachProps = Join-Path $fidScripts 'AttachFidDatabase.properties'
Set-Content -Path $attachProps -Encoding ASCII -Value @(
    "Attach existing FidDb Attach = $OutFidb"
)

$props = Join-Path $fidScripts 'CreateMultipleLibraries.properties'
Set-Content -Path $props -Encoding ASCII -Value @(
    "Duplicate Results File OK = $dupes",
    "Do Duplication Detection Do you want to detect duplicates = true",
    "Choose destination FidDB Please choose the destination FidDB for population = $(Split-Path $OutFidb -Leaf)",
    "Select root folder containing all libraries (at a depth of 3): = /",
    "Common symbols file (optional): OK = $dupes",
    "Enter LanguageID To Process Language ID:  = $LanguageId"
)
try {
    $log = & $headless $ProjectDir $ProjectName -noanalysis `
        -preScript AttachFidDatabase.java `
        -preScript CreateMultipleLibraries.java 2>&1
    $log | Write-Verbose
    if ($log -match 'SCRIPT ERROR') {
        $log | Where-Object { $_ -match 'SCRIPT ERROR' } | Write-Host
        throw 'CreateMultipleLibraries failed -- see error above'
    }
    $log | Where-Object { $_ -match 'Populating|Library:|added to database' } |
        Select-Object -Last 12 | Write-Host
} finally {
    Remove-Item $props -ErrorAction SilentlyContinue
    Remove-Item $attachProps -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "FID database: $OutFidb"
Write-Host 'Attach in the GUI via Tools -> Function ID -> Choose active FidDbs,'
Write-Host 'then re-run the Function ID analyzer on a program to pick up matches.'
Write-Host ''
Write-Host 'MEASURE the gain before trusting it -- for VC6 it was +1 and +0:'
Write-Host '  analyzeHeadless <proj> base  -import <bin> '
Write-Host '     -scriptPath scripts/fid -postScript CountFidMatches.java'
Write-Host '  analyzeHeadless <proj> withdb -import <bin> '
Write-Host '     -scriptPath scripts/fid -preScript AttachFidDatabase.java '
Write-Host '     -postScript CountFidMatches.java'

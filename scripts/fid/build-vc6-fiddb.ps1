<#
.SYNOPSIS
    Build a Ghidra Function ID database from a Visual C++ 6 installation.

.DESCRIPTION
    Diablo II 1.13c is a VC6-era build with the CRT statically linked, so its
    runtime code is scattered through every game DLL with no symbols. Ghidra's
    stock FID databases do not cover that toolchain: measured on this corpus,
    FID matched only 4,325 of 70,146 functions (6%). Everything it did NOT
    match is a function the documentation pipeline will happily hand to an LLM
    and name as though it were game logic -- which is exactly how
    `___acrt_locale_free_numeric` ended up called `DATATBLS_FreeUnitResourceArray`.

    Feeding VC6's own CRT libraries into a FID database closes that gap at the
    source: every additional match is both a correct classification AND a
    correct name, applied by an analyzer rather than a language model.

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
    [string]$ProjectDir  = 'C:\tmp\fidproj',
    [string]$ProjectName = 'vc6fid',
    [string]$OutFidb   = 'C:\tmp\vc6_vc98.fidb',
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
Write-Host 'Attach it in the GUI via Tools -> Function ID -> Choose active FidDbs,'
Write-Host 'then re-run the Function ID analyzer on a program to pick up new matches.'
Write-Host 'Verify the gain with: python fun-doc/doc_lint.py --program <path>'

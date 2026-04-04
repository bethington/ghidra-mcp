param(
    [string]$TodoFilePath = ".\FunctionsTodo.txt",
    [ValidateSet("haiku", "sonnet", "opus")]
    [string]$Model = "",
    [int]$MaxTurns = 25,
    [int]$MaxFunctions = 0,
    [switch]$DryRun,
    [Alias("m")][switch]$Manual
)

$moduleDir = "$PSScriptRoot\prompts"
$ghidraServer = "http://127.0.0.1:8089"

# ── Validate module directory ───────────────────────────────────────────────

$requiredModules = @(
    "core.md",
    "step-classify.md", "step-prototype.md", "step-type-audit.md",
    "step-comments.md", "step-verify.md",
    "fix-struct-access.md", "fix-undefined-types.md", "fix-hungarian.md",
    "fix-magic-numbers.md", "fix-globals.md", "fix-labels.md",
    "fix-plate-comment.md", "fix-prototype.md", "fix-ordinals.md"
)

foreach ($mod in $requiredModules) {
    if (-not (Test-Path "$moduleDir\$mod")) {
        Write-Host "ERROR: Missing module: $moduleDir\$mod" -ForegroundColor Red
        exit 1
    }
}

if (-not (Test-Path $TodoFilePath)) {
    Write-Host "ERROR: Todo file not found: $TodoFilePath" -ForegroundColor Red
    exit 1
}

# ── Category-to-module mapping ──────────────────────────────────────────────

$categoryToModule = @{
    "unresolved_struct_accesses"    = "fix-struct-access.md"
    "undefined_variables"           = "fix-undefined-types.md"
    "hungarian_notation_violations" = "fix-hungarian.md"
    "undocumented_magic_numbers"    = "fix-magic-numbers.md"
    "unrenamed_globals"             = "fix-globals.md"
    "unrenamed_labels"              = "fix-labels.md"
    "missing_plate_comment"         = "fix-plate-comment.md"
    "plate_comment_issues"          = "fix-plate-comment.md"
    "missing_prototype"             = "fix-prototype.md"
    "return_type_unresolved"        = "fix-prototype.md"
    "undocumented_ordinals"         = "fix-ordinals.md"
}

# ── Ghidra HTTP helpers ─────────────────────────────────────────────────────

function Invoke-Ghidra {
    param([string]$Method, [string]$Path, [hashtable]$Body)
    $uri = "$ghidraServer$Path"
    try {
        if ($Method -eq "POST") {
            $json = $Body | ConvertTo-Json -Compress
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $json -ContentType "application/json" -TimeoutSec 30
        } else {
            $resp = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 30
        }
        return $resp
    } catch {
        Write-Host "  WARNING: Ghidra call failed ($Path): $($_.Exception.Message)" -ForegroundColor DarkYellow
        return $null
    }
}

function Get-GhidraData {
    <#
    .SYNOPSIS
        Pre-fetch all data needed for prompt assembly: decompile, completeness, variables, analyze_for_documentation.
    #>
    param([string]$Program, [string]$Address, [string]$Mode)

    $data = @{
        Decompiled = $null
        Completeness = $null
        Variables = $null
        AnalyzeForDoc = $null
        Score = $null
        Deductions = @()
        FixableCategories = @()
    }

    # Switch program if needed
    if ($Program) {
        Write-Host "  Switching to $Program..." -ForegroundColor DarkGray -NoNewline
        $null = Invoke-Ghidra "GET" "/switch_program?name=$Program"
        Write-Host " done" -ForegroundColor DarkGray
    }

    # Navigate
    Write-Host "  Navigating to 0x$Address..." -ForegroundColor DarkGray -NoNewline
    $null = Invoke-Ghidra "POST" "/tool/goto_address" @{ address = "0x$Address" }
    Write-Host " done" -ForegroundColor DarkGray

    # Decompile
    Write-Host "  Decompiling..." -ForegroundColor DarkGray -NoNewline
    $data.Decompiled = Invoke-Ghidra "GET" "/decompile_function?address=0x$Address"
    Write-Host " done" -ForegroundColor DarkGray

    # Completeness
    Write-Host "  Checking completeness..." -ForegroundColor DarkGray -NoNewline
    $raw = Invoke-Ghidra "GET" "/analyze_function_completeness?function_address=0x$Address"
    if ($raw) {
        if ($raw -is [string]) {
            $data.Completeness = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        } else {
            $data.Completeness = $raw
        }
        if ($data.Completeness) {
            $data.Score = if ($null -ne $data.Completeness.effective_score) { [int]$data.Completeness.effective_score } else { $null }
            if ($data.Completeness.deduction_breakdown) {
                $data.Deductions = @($data.Completeness.deduction_breakdown)
                $data.FixableCategories = @($data.Deductions | Where-Object { $_.fixable } | ForEach-Object { $_.category })
            }
        }
    }

    if ($null -ne $data.Score) {
        $color = if ($data.Score -ge 90) { "Green" } elseif ($data.Score -ge 70) { "Yellow" } else { "Red" }
        Write-Host " $($data.Score)%" -ForegroundColor $color
        foreach ($d in $data.Deductions) {
            $fix = if ($d.fixable) { "fixable" } else { "unfixable" }
            Write-Host "    -$($d.points)pts [$fix] $($d.description)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host " unavailable" -ForegroundColor DarkYellow
    }

    # Variables
    Write-Host "  Fetching variables..." -ForegroundColor DarkGray -NoNewline
    $data.Variables = Invoke-Ghidra "GET" "/get_function_variables?function_name=$(if ($data.Completeness.function_name) { $data.Completeness.function_name } else { 'FUN_' + $Address })"
    Write-Host " done" -ForegroundColor DarkGray

    # Full analysis (for full docs mode)
    if ($Mode -eq "FULL") {
        Write-Host "  Running full analysis..." -ForegroundColor DarkGray -NoNewline
        $data.AnalyzeForDoc = Invoke-Ghidra "GET" "/analyze_for_documentation?address=0x$Address"
        Write-Host " done" -ForegroundColor DarkGray
    }

    return $data
}

# ── Prompt assembly ─────────────────────────────────────────────────────────

function Read-Module {
    param([string]$Name)
    return Get-Content "$moduleDir\$Name" -Raw
}

function Build-FixPrompt {
    param([string]$FuncName, [string]$Address, $GhidraData)

    $sections = @()

    # Core module
    $sections += Read-Module "core.md"
    $sections += ""

    # Inline data
    $sections += "## Current State"
    $sections += "Function: $FuncName at 0x$Address"
    $sections += "Current Score: $($GhidraData.Score)%"
    $sections += ""

    $sections += "## Decompiled Source (pre-fetched, do NOT re-fetch)"
    $sections += '```'
    $sections += $GhidraData.Decompiled
    $sections += '```'
    $sections += ""

    if ($GhidraData.Variables) {
        $sections += "## Variables (pre-fetched, refresh only after prototype changes)"
        $varJson = if ($GhidraData.Variables -is [string]) { $GhidraData.Variables } else { $GhidraData.Variables | ConvertTo-Json -Depth 5 -Compress }
        $sections += '```json'
        $sections += $varJson
        $sections += '```'
        $sections += ""
    }

    # Completeness JSON (trimmed - just deductions and remediation)
    $sections += "## Completeness Analysis"
    $sections += '```json'
    $trimmed = @{
        function_name = $GhidraData.Completeness.function_name
        completeness_score = $GhidraData.Completeness.completeness_score
        effective_score = $GhidraData.Completeness.effective_score
        deduction_breakdown = $GhidraData.Completeness.deduction_breakdown
        remediation_actions = $GhidraData.Completeness.remediation_actions
    }
    $sections += ($trimmed | ConvertTo-Json -Depth 5 -Compress)
    $sections += '```'
    $sections += ""

    # Issue-specific modules (only the relevant ones)
    $includedModules = @{}
    foreach ($cat in $GhidraData.FixableCategories) {
        $modFile = $categoryToModule[$cat]
        if ($modFile -and -not $includedModules[$modFile]) {
            $sections += Read-Module $modFile
            $sections += ""
            $includedModules[$modFile] = $true
        }
    }

    # Instructions
    $sections += "## Instructions"
    $sections += "Fix the issues listed in the Completeness Analysis above using the recipes provided."
    $sections += "Follow each recipe's tool sequence. Do NOT deviate to other tools."
    $sections += "After fixing, call `analyze_function_completeness` to verify."
    $sections += "Report: DONE: FunctionName, Score: N%"

    return $sections -join "`n"
}

function Build-FullDocPrompt {
    param([string]$FuncName, [string]$Address, $GhidraData)

    $sections = @()

    # Core module
    $sections += Read-Module "core.md"
    $sections += ""

    # Inline data
    $sections += "## Target Function"
    $sections += "Function: $FuncName at 0x$Address"
    if ($null -ne $GhidraData.Score) {
        $sections += "Current Score: $($GhidraData.Score)%"
    }
    $sections += ""

    if ($GhidraData.AnalyzeForDoc) {
        $sections += "## Full Analysis (pre-fetched, do NOT re-fetch)"
        $sections += '```'
        $sections += $(if ($GhidraData.AnalyzeForDoc -is [string]) { $GhidraData.AnalyzeForDoc } else { $GhidraData.AnalyzeForDoc | ConvertTo-Json -Depth 5 })
        $sections += '```'
        $sections += ""
    }

    $sections += "## Decompiled Source (pre-fetched, do NOT re-fetch)"
    $sections += '```'
    $sections += $GhidraData.Decompiled
    $sections += '```'
    $sections += ""

    if ($GhidraData.Variables) {
        $sections += "## Variables (pre-fetched, refresh only after prototype changes)"
        $varJson = if ($GhidraData.Variables -is [string]) { $GhidraData.Variables } else { $GhidraData.Variables | ConvertTo-Json -Depth 5 -Compress }
        $sections += '```json'
        $sections += $varJson
        $sections += '```'
        $sections += ""
    }

    # Step modules
    $sections += Read-Module "step-classify.md"
    $sections += ""
    $sections += Read-Module "step-prototype.md"
    $sections += ""
    $sections += Read-Module "step-type-audit.md"
    $sections += ""
    $sections += Read-Module "step-comments.md"
    $sections += ""
    $sections += Read-Module "step-verify.md"
    $sections += ""

    # Fix modules (reference only, for verify-fix loop)
    $sections += "---"
    $sections += "## Remediation Recipes (apply only during Step 5 verify-fix loop)"
    $sections += ""
    foreach ($modFile in ($categoryToModule.Values | Sort-Object -Unique)) {
        $sections += Read-Module $modFile
        $sections += ""
    }

    # Instructions
    $sections += "## Instructions"
    $sections += "Document the function above following Steps 1-5 in order."
    $sections += "All analysis data is provided inline - do NOT re-fetch it."
    $sections += "Report: DONE: FunctionName, Changes: [summary], Score: N%"

    return $sections -join "`n"
}

function Build-VerifyPrompt {
    param([string]$FuncName, [string]$Address, $GhidraData)

    $sections = @()
    $sections += "Quick semantic review of a fully-documented function in Ghidra."
    $sections += "This function scored 100% on structural completeness. Verify the documentation is semantically correct - do not redo it."
    $sections += ""
    $sections += "## Decompiled Source"
    $sections += '```'
    $sections += $GhidraData.Decompiled
    $sections += '```'
    $sections += ""
    $sections += "Check:"
    $sections += ""
    $sections += "1. Name accuracy: Does the PascalCase verb-first name describe what the function ACTUALLY does?"
    $sections += "2. Hungarian prefix consistency: Do prefixes match types? (p=pointer, dw=uint, n=int, b=byte, f=bool, sz=char*, w=ushort)"
    $sections += "3. Plate comment accuracy: Does the one-line summary match the decompiled behavior?"
    $sections += "4. Quick fixes: If obvious issues found, fix directly using rename_function_by_address, rename_variables, or batch_set_comments."
    $sections += ""
    $sections += "Report one of:"
    $sections += "- VERIFIED OK: FunctionName - no issues found"
    $sections += "- QUICK FIX: FunctionName - what you fixed"
    $sections += "- NEEDS REDO: FunctionName - reason (do NOT attempt a full redo, just flag it)"

    return $sections -join "`n"
}

# ── Model selection ─────────────────────────────────────────────────────────

function Select-Model {
    param([string]$PromptMode, [int]$Score, [string]$UserModel)

    # User override takes priority
    if ($UserModel) { return $UserModel }

    # Auto-select based on mode
    switch ($PromptMode) {
        "FIX"    { return "sonnet" }
        "VERIFY" { return "sonnet" }
        "FULL"   {
            # High-xref complex functions benefit from Opus
            # Default to Opus for full docs
            return "opus"
        }
        default  { return "opus" }
    }
}

# ── Claude CLI resolution ────────────────────────────────────────────────────

$claudeCmd = Get-Command "claude" -ErrorAction SilentlyContinue
if (-not $claudeCmd) {
    Write-Host "ERROR: 'claude' not found in PATH" -ForegroundColor Red
    exit 1
}
$claudePath = if ($claudeCmd.Source) { $claudeCmd.Source } else { $claudeCmd.Path }
$claudeIsScript = ($claudeCmd.CommandType -eq "ExternalScript" -or $claudePath -match '\.ps1$')
if ($claudeIsScript) {
    $startExe = "powershell.exe"
    $argPrefix = "-ExecutionPolicy Bypass -File `"$claudePath`""
} else {
    $startExe = $claudePath
    $argPrefix = ""
}
Write-Host "Claude CLI: $claudePath $(if ($claudeIsScript) { '(via powershell.exe)' })" -ForegroundColor DarkGray

# ── Run Claude on a prompt ───────────────────────────────────────────────────

function Invoke-Claude {
    param([string]$Prompt, [string]$SelectedModel)

    $tempIn  = [System.IO.Path]::GetTempFileName()
    $tempOut = [System.IO.Path]::GetTempFileName()
    $tempErr = [System.IO.Path]::GetTempFileName()

    try {
        [System.IO.File]::WriteAllText($tempIn, $Prompt)

        $claudeArgs = "--print --no-session-persistence --dangerously-skip-permissions --max-turns $MaxTurns --model $SelectedModel"
        $fullArgs = if ($argPrefix) { "$argPrefix $claudeArgs" } else { $claudeArgs }

        $proc = Start-Process $startExe -ArgumentList $fullArgs -NoNewWindow -PassThru `
            -RedirectStandardInput $tempIn `
            -RedirectStandardOutput $tempOut `
            -RedirectStandardError $tempErr

        $proc | Wait-Process -Timeout 600

        if ($proc.ExitCode -ne 0) {
            Write-Host "FAILED (exit code $($proc.ExitCode))" -ForegroundColor Red
            $errText = Get-Content $tempErr -Raw -ErrorAction SilentlyContinue
            if ($errText) { Write-Host $errText -ForegroundColor Red }
        }

        $output = Get-Content $tempOut -Raw -ErrorAction SilentlyContinue
        if ($output) {
            Write-Host $output
        } else {
            Write-Host "(no output)" -ForegroundColor DarkGray
        }
    } finally {
        Remove-Item $tempIn, $tempOut, $tempErr -Force -ErrorAction SilentlyContinue
    }
}

# ── Parse todo file ──────────────────────────────────────────────────────────

$patternNew = '^\[( )\]\s+(.+?)::(.+?)\s+@\s*([0-9a-fA-F]+)(?:\s+\(Score:\s*(\d+)\))?'
$patternOld = '^\[( )\]\s+([^:]+?)\s+@\s*([0-9a-fA-F]+)(?:\s+\(Score:\s*(\d+)\))?'

$functions = @()
foreach ($line in Get-Content $TodoFilePath) {
    if ($line -match $patternNew) {
        $functions += @{
            Program  = $Matches[2]
            Name     = $Matches[3]
            Address  = $Matches[4]
            Score    = if ($Matches[5]) { [int]$Matches[5] } else { $null }
        }
    } elseif ($line -match $patternOld) {
        $functions += @{
            Program  = $null
            Name     = $Matches[2]
            Address  = $Matches[3]
            Score    = if ($Matches[4]) { [int]$Matches[4] } else { $null }
        }
    }
}

Write-Host "Found $($functions.Count) pending functions" -ForegroundColor Cyan
if ($MaxFunctions -gt 0 -and $functions.Count -gt $MaxFunctions) {
    $functions = $functions[0..($MaxFunctions - 1)]
    Write-Host "Limited to first $MaxFunctions functions" -ForegroundColor Yellow
}

# ── Main loop ────────────────────────────────────────────────────────────────

$processed = 0
$completedCount = 0
$skippedCount = 0
$total = $functions.Count

foreach ($func in $functions) {
    $processed++
    $label = if ($func.Program) { "$($func.Program)::$($func.Name)" } else { $func.Name }
    $scoreStr = if ($null -ne $func.Score) { " (Score: $($func.Score))" } else { "" }

    Write-Host ""
    Write-Host "[$processed/$total] $label @ $($func.Address)$scoreStr" -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor DarkGray

    # Determine mode before fetching (decides whether to fetch analyze_for_documentation)
    # Use todo score for initial mode guess; live score refines it after fetch
    $guessMode = if ($null -ne $func.Score -and $func.Score -ge 100) { "VERIFY" }
                 elseif ($null -ne $func.Score -and $func.Score -ge 70) { "FIX" }
                 else { "FULL" }

    # Pre-fetch all Ghidra data
    $data = Get-GhidraData -Program $func.Program -Address $func.Address -Mode $guessMode
    $liveScore = $data.Score

    # Refine mode based on live score
    if ($null -ne $liveScore -and $liveScore -ge 100) {
        $promptMode = "VERIFY"
    } elseif ($null -ne $liveScore -and $liveScore -ge 70) {
        $promptMode = "FIX"
    } else {
        $promptMode = "FULL"

        # If we guessed wrong and didn't fetch analyze_for_documentation, fetch it now
        if ($guessMode -ne "FULL" -and -not $data.AnalyzeForDoc) {
            Write-Host "  Running full analysis (mode changed)..." -ForegroundColor DarkGray -NoNewline
            $data.AnalyzeForDoc = Invoke-Ghidra "GET" "/analyze_for_documentation?address=0x$($func.Address)"
            Write-Host " done" -ForegroundColor DarkGray
        }
    }

    $funcName = if ($data.Completeness.function_name) { $data.Completeness.function_name } else { $func.Name }

    # Select model
    $selectedModel = Select-Model -PromptMode $promptMode -Score $liveScore -UserModel $Model

    # Build prompt based on mode
    switch ($promptMode) {
        "VERIFY" {
            $prompt = Build-VerifyPrompt -FuncName $funcName -Address $func.Address -GhidraData $data
        }
        "FIX" {
            $prompt = Build-FixPrompt -FuncName $funcName -Address $func.Address -GhidraData $data
        }
        "FULL" {
            $prompt = Build-FullDocPrompt -FuncName $funcName -Address $func.Address -GhidraData $data
        }
    }

    if ($DryRun) {
        Write-Host "DRY RUN [$promptMode | $selectedModel]: Would invoke Claude" -ForegroundColor Yellow
        Write-Host "  Prompt size: $($prompt.Length) chars" -ForegroundColor Gray
        $moduleCount = ($prompt | Select-String -Pattern "^# (Fix|Step)" -AllMatches).Matches.Count
        Write-Host "  Modules included: $moduleCount" -ForegroundColor Gray
        continue
    }

    # ── Manual mode ──────────────────────────────────────────────────────

    if ($Manual) {
        Write-Host ""
        Write-Host "  Model: $selectedModel" -ForegroundColor DarkGray

        if ($promptMode -eq "VERIFY") {
            Write-Host "  [1] VERIFY (copied to clipboard)" -ForegroundColor Green
            Write-Host "      Quick semantic check - name, prefixes, plate comment" -ForegroundColor DarkGray
            Write-Host "  [2] FIX ISSUES" -ForegroundColor Yellow
            Write-Host "      Targeted fix with issue-specific recipes" -ForegroundColor DarkGray
            Write-Host "  [3] FULL REDO" -ForegroundColor White
            Write-Host "      Complete V6 documentation from scratch" -ForegroundColor DarkGray
            Set-Clipboard -Value $prompt
        } elseif ($promptMode -eq "FIX") {
            $fixCount = @($data.Deductions | Where-Object { $_.fixable }).Count
            Write-Host "  [1] FIX ISSUES (copied to clipboard)" -ForegroundColor Yellow
            Write-Host "      Fix $fixCount deduction(s) ($liveScore% -> higher)" -ForegroundColor DarkGray
            Write-Host "  [2] FULL REDO" -ForegroundColor White
            Write-Host "      Complete V6 documentation from scratch" -ForegroundColor DarkGray
            Set-Clipboard -Value $prompt
        } else {
            Write-Host "  [1] FULL REDO (copied to clipboard)" -ForegroundColor Red
            Write-Host "      Complete V6 documentation from scratch" -ForegroundColor DarkGray
            Set-Clipboard -Value (Build-FullDocPrompt -FuncName $funcName -Address $func.Address -GhidraData $data)
        }

        Write-Host ""
        $validChoices = switch ($promptMode) {
            "VERIFY" { @("1","2","3","c","s","q") }
            "FIX"    { @("1","2","c","s","q") }
            default  { @("1","c","s","q") }
        }
        $menuLine = switch ($promptMode) {
            "VERIFY" { "  [1/2/3] Copy   [C] Completed   [S] Skip   [Q] Quit" }
            "FIX"    { "  [1/2] Copy   [C] Completed   [S] Skip   [Q] Quit" }
            default  { "  [1] Copy   [C] Completed   [S] Skip   [Q] Quit" }
        }
        Write-Host $menuLine -ForegroundColor Green

        $choice = ""
        while ($choice -notin $validChoices) {
            Write-Host -NoNewline "  > " -ForegroundColor Green
            $choice = (Read-Host).Trim().ToLower()
        }

        switch ($choice) {
            "1" {
                Set-Clipboard -Value $prompt
                Write-Host "  Copied: $promptMode prompt" -ForegroundColor White
            }
            "2" {
                if ($promptMode -eq "VERIFY") {
                    # Build FIX prompt instead
                    $fixPrompt = Build-FixPrompt -FuncName $funcName -Address $func.Address -GhidraData $data
                    Set-Clipboard -Value $fixPrompt
                    Write-Host "  Copied: FIX ISSUES prompt" -ForegroundColor Yellow
                } else {
                    # Build FULL prompt
                    $fullPrompt = Build-FullDocPrompt -FuncName $funcName -Address $func.Address -GhidraData $data
                    Set-Clipboard -Value $fullPrompt
                    Write-Host "  Copied: FULL REDO prompt" -ForegroundColor White
                }
            }
            "3" {
                $fullPrompt = Build-FullDocPrompt -FuncName $funcName -Address $func.Address -GhidraData $data
                Set-Clipboard -Value $fullPrompt
                Write-Host "  Copied: FULL REDO prompt" -ForegroundColor White
            }
            "c" {
                $completedCount++
                Write-Host "  Marked completed." -ForegroundColor Green
            }
            "s" {
                $skippedCount++
                Write-Host "  Skipped." -ForegroundColor DarkGray
            }
            "q" {
                Write-Host ""
                Write-Host "Quit. Processed $processed functions ($completedCount completed, $skippedCount skipped)." -ForegroundColor Yellow
                exit 0
            }
        }
        continue
    }

    # ── Automated mode ───────────────────────────────────────────────────

    # 100% in automated mode: skip entirely
    if ($null -ne $liveScore -and $liveScore -ge 100) {
        Write-Host "  SKIP: 100% complete (use -m for semantic review)" -ForegroundColor DarkGreen
        continue
    }

    # Run the appropriate prompt
    Write-Host "  Mode: $promptMode | Model: $selectedModel | Prompt: $($prompt.Length) chars" -ForegroundColor Cyan
    Invoke-Claude -Prompt $prompt -SelectedModel $selectedModel
}

Write-Host ""
if ($Manual) {
    Write-Host "Done. Processed $processed functions ($completedCount completed, $skippedCount skipped)." -ForegroundColor Green
} else {
    Write-Host "Done. Processed $processed functions." -ForegroundColor Green
}

param(
    [switch]$Reverse,
    [switch]$Single,
    [string]$Function,
    [string]$Model = "claude-haiku-4-5-20251001",
    [switch]$Help,
    [int]$MaxRetries = 3,
    [int]$DelayBetweenFunctions = 2,
    [int]$MinScore = 0,
    [int]$MaxScore = 99,
    [switch]$DryRun,
    [switch]$SkipValidation,
    [int]$Workers = 1,
    [switch]$Coordinator,
    [int]$WorkerId = 0,
    [string]$GhidraServer = "http://127.0.0.1:8089"
)

# Constants
$STALE_LOCK_MINUTES = 30
$MAX_PROMPT_BYTES = 180000
$FUNCTION_BATCH_SIZE = 50

$todoFile = ".\FunctionsTodo.txt"
$promptFile = ".\docs\prompts\FUNCTION_DOC_WORKFLOW_V2.md"
$logFile = ".\logs\functions-process-worker$WorkerId-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$checkpointFile = ".\functions-progress-worker$WorkerId.json"
$outputDir = ".\output"
$lockDir = ".\locks"
$globalLockFile = ".\locks\.global.lock"

# Create directories if they don't exist
New-Item -ItemType Directory -Force -Path ".\logs" | Out-Null
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
New-Item -ItemType Directory -Force -Path $lockDir | Out-Null

# Check if prompt file exists, if not use a default prompt
if (-not (Test-Path $promptFile)) {
    Write-Host "WARNING: Prompt file not found at $promptFile" -ForegroundColor Yellow
    Write-Host "Using embedded default workflow prompt..." -ForegroundColor Yellow
    $defaultPrompt = $true
} else {
    $defaultPrompt = $false
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [Worker$WorkerId] [$Level] $Message"
    
    # Thread-safe file append with retry
    $retries = 3
    while ($retries -gt 0) {
        try {
            Add-Content $logFile $logEntry -ErrorAction Stop
            break
        } catch {
            $retries--
            Start-Sleep -Milliseconds 100
        }
    }
}

function Write-WorkerHost {
    param([string]$Message, [string]$Color = "White")
    $prefix = if ($Workers -gt 1) { "[W$WorkerId] " } else { "" }
    Write-Host "$prefix$Message" -ForegroundColor $Color
}

function Show-Help {
    Write-Host "functions-process.ps1 - Parallel Function Processing with MCP"
    Write-Host ""
    Write-Host "PARALLEL OPTIONS:"
    Write-Host "  -Workers <n>         Number of parallel Claude workers (default: 1)"
    Write-Host "  -Coordinator         Run as coordinator spawning workers"
    Write-Host "  -WorkerId <n>        Worker ID (used internally)"
    Write-Host ""
    Write-Host "PROCESSING OPTIONS:"
    Write-Host "  -Single              Process one function and stop"
    Write-Host "  -Function <name>     Process specific function"
    Write-Host "  -Reverse             Process from bottom to top"
    Write-Host "  -Model <model>       Claude model to use (default: claude-haiku-4-5-20251001)"
    Write-Host ""
    Write-Host "  Available models:"
    Write-Host "    claude-haiku-4-5-20251001    (fast, cost-effective)"
    Write-Host "    claude-sonnet-4-5-20250929   (balanced)"
    Write-Host "    claude-opus-4-5              (most capable)"
    Write-Host ""
    Write-Host "  -MaxRetries <n>      Maximum retry attempts (default: 3)"
    Write-Host "  -DelayBetweenFunctions <n>  Seconds between functions (default: 2)"
    Write-Host "  -MinScore <n>        Only process functions with score >= n (default: 0)"
    Write-Host "  -MaxScore <n>        Only process functions with score <= n (default: 99)"
    Write-Host "  -DryRun              Preview what will be processed without changes"
    Write-Host "  -SkipValidation      Skip post-processing validation checks"
    Write-Host "  -Help                Show this help"
    Write-Host ""
    Write-Host "EXAMPLES:"
    Write-Host "  .\functions-process.ps1 -Workers 6          # Run 6 parallel workers"
    Write-Host "  .\functions-process.ps1 -Workers 6 -MaxScore 50  # 6 workers on low-score functions"
    Write-Host "  .\functions-process.ps1 -Model claude-sonnet-4-5-20250929  # Use Sonnet"
    Write-Host "  .\functions-process.ps1 -GhidraServer http://localhost:8089  # Custom server"
    Write-Host "  .\functions-process.ps1                     # Single worker (original behavior)"
    Write-Host ""
    Write-Host "NOTES:"
    Write-Host "  - Each worker claims functions using lock files to prevent collisions"
    Write-Host "  - Workers automatically skip functions already claimed by others"
    Write-Host "  - Progress is tracked per-worker in separate log files"
    exit 0
}

function Get-FunctionLockFile {
    param([string]$funcName)
    $safeName = $funcName -replace '[^a-zA-Z0-9_]', '_'
    return Join-Path $lockDir "$safeName.lock"
}

function Try-ClaimFunction {
    param([string]$funcName, [string]$address)
    
    $lockFile = Get-FunctionLockFile $funcName
    
    # Try to atomically create the lock file
    try {
        # Use .NET to create file with exclusive access
        $fs = [System.IO.File]::Open($lockFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        
        # Write worker info to lock file
        $writer = New-Object System.IO.StreamWriter($fs)
        $writer.WriteLine("WorkerId: $WorkerId")
        $writer.WriteLine("Function: $funcName")
        $writer.WriteLine("Address: $address")
        $writer.WriteLine("ClaimedAt: $(Get-Date -Format 'o')")
        $writer.WriteLine("PID: $PID")
        $writer.Close()
        $fs.Close()
        
        Write-Log "Claimed function $funcName"
        return $true
    } catch [System.IO.IOException] {
        # Lock file already exists - another worker has claimed it
        Write-Log "Function $funcName already claimed by another worker"
        return $false
    } catch {
        Write-Log "Error claiming function ${funcName}: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Release-FunctionLock {
    param([string]$funcName)
    
    $lockFile = Get-FunctionLockFile $funcName
    
    if (Test-Path $lockFile) {
        try {
            Remove-Item $lockFile -Force -ErrorAction Stop
            Write-Log "Released lock for ${funcName}"
        } catch {
            Write-Log "Error releasing lock for ${funcName}: $($_.Exception.Message)" "WARN"
        }
    }
}

function Clear-StaleLocks {
    param([int]$MaxAgeMinutes = $STALE_LOCK_MINUTES)
    
    $staleTime = (Get-Date).AddMinutes(-$MaxAgeMinutes)
    
    Get-ChildItem $lockDir -Filter "*.lock" -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.LastWriteTime -lt $staleTime) {
            Write-Log "Removing stale lock: $($_.Name)"
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-GlobalLock {
    $retries = 50
    while ($retries -gt 0) {
        try {
            $fs = [System.IO.File]::Open($globalLockFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $fs.Close()
            return $true
        } catch {
            $retries--
            Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 200)
        }
    }
    return $false
}

function Release-GlobalLock {
    if (Test-Path $globalLockFile) {
        Remove-Item $globalLockFile -Force -ErrorAction SilentlyContinue
    }
}

function Update-TodoFile {
    param([string]$funcName, [string]$status)
    
    # Get global lock for atomic file update
    if (-not (Get-GlobalLock)) {
        Write-Log "Could not acquire global lock for todo update" "ERROR"
        return $false
    }
    
    try {
        $content = Get-Content $todoFile -Raw
        $escapedFuncName = [regex]::Escape($funcName)
        
        if ($status -eq "complete") {
            $updated = $content -replace "\[\s*\]\s+$escapedFuncName\s+@", "[X] $funcName @"
        } elseif ($status -eq "failed") {
            $updated = $content -replace "\[\s*\]\s+$escapedFuncName\s+@", "[!] $funcName @"
        } else {
            $updated = $content
        }
        
        Set-Content $todoFile $updated -NoNewline
        Write-Log "Updated todo file: $funcName -> $status"
        return $true
    } finally {
        Release-GlobalLock
    }
}

function Test-WorkflowCompliance {
    param([string]$output, [string]$funcName, [float]$initialScore)
    
    $issues = @()
    
    # Check if MCP tools were actually called
    $toolCallPatterns = @(
        'mcp_ghidra_decompile_function',
        'mcp_ghidra_get_function_variables',
        'mcp_ghidra_batch_rename',
        'mcp_ghidra_set_function_prototype',
        'mcp_ghidra_set_plate_comment',
        'mcp_ghidra_batch_set_comments'
    )
    
    $toolsCalled = $false
    foreach ($pattern in $toolCallPatterns) {
        if ($output -match $pattern) {
            $toolsCalled = $true
            break
        }
    }
    
    if (-not $toolsCalled) {
        $issues += "No MCP tool calls detected - may have only provided suggestions"
    }
    
    # Check for common anti-patterns
    if ($output -match "(?i)(you should|you could|consider|recommend|suggest)") {
        $issues += "Output contains suggestions rather than actions taken"
    }
    
    if ($output -match "(?i)(would|might|could be)") {
        $issues += "Output uses conditional language indicating no action taken"
    }
    
    # Check if workflow steps were mentioned
    if ($output -notmatch "(?i)(decompil|variable|prototype|plate comment|hungarian)") {
        $issues += "Output doesn't mention key workflow elements"
    }
    
    return $issues
}

function Process-Function {
    param([string]$funcName, [string]$address = "")
    
    if ($address) {
        Write-WorkerHost "Processing: $funcName @ $address" "Green"
    } else {
        Write-WorkerHost "Processing: $funcName" "Green"
    }
    
    Write-Log "Processing function: $funcName @ $address"
    
    # Check function completeness
    Write-WorkerHost "Checking function completeness..." "Cyan"
    $completenessInfo = ""
    $score = 0
    if ($address) {
        try {
            $completenessUrl = "$GhidraServer/analyze_function_completeness?function_address=0x$address"
            $completenessResponse = Invoke-RestMethod -Uri $completenessUrl -Method GET -TimeoutSec 10
            
            if ($completenessResponse) {
                $score = $completenessResponse.completeness_score
                $hasCustomName = $completenessResponse.has_custom_name
                $hasPrototype = $completenessResponse.has_prototype
                $hasCallingConvention = $completenessResponse.has_calling_convention
                $hasPlateComment = $completenessResponse.has_plate_comment
                $undefinedVars = $completenessResponse.undefined_variables
                
                $missingItems = @()
                if (-not $hasCustomName) { $missingItems += "Custom function name (currently has default FUN_ name)" }
                if (-not $hasPrototype) { $missingItems += "Function prototype with typed parameters" }
                if (-not $hasCallingConvention) { $missingItems += "Calling convention specification" }
                if (-not $hasPlateComment) { $missingItems += "Plate comment (function header documentation)" }
                if ($undefinedVars -gt 0) { $missingItems += "$undefinedVars undefined variable(s) need renaming" }
                
                $missingItemsText = if ($missingItems.Count -gt 0) {
                    "`n`nMissing Documentation Elements:`n" + ($missingItems | ForEach-Object { "  - $_" }) -join "`n"
                } else {
                    "`n`nAll core documentation elements are present."
                }
                
                $completenessInfo = @"

---

## FUNCTION COMPLETENESS ANALYSIS

**Current Completeness Score: $score/100**

Status Summary:
- Custom Name: $( if ($hasCustomName) { "[OK] Present" } else { "[X] MISSING" } )
- Function Prototype: $( if ($hasPrototype) { "[OK] Present" } else { "[X] MISSING" } )
- Calling Convention: $( if ($hasCallingConvention) { "[OK] Present" } else { "[X] MISSING" } )
- Plate Comment: $( if ($hasPlateComment) { "[OK] Present" } else { "[X] MISSING" } )
- Undefined Variables: $( if ($undefinedVars -eq 0) { "[OK] None" } else { "[X] $undefinedVars need attention" } )
$missingItemsText

**PRIORITY:** Focus on completing the missing elements above to achieve 100/100 completeness score.

---
"@
                $scoreColor = if ($score -ge 75) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" }
                Write-WorkerHost "  Completeness Score: $score/100" $scoreColor
                Write-Log "Initial completeness score: $score/100"
                
                if ($missingItems.Count -gt 0) {
                    Write-WorkerHost "  Missing: $($missingItems.Count) item(s)" "Yellow"
                    Write-Log "Missing items: $($missingItems -join ', ')"
                }
                
                if ($score -lt $MinScore -or $score -gt $MaxScore) {
                    Write-WorkerHost "  Skipping (score $score outside range $MinScore-$MaxScore)" "Yellow"
                    Write-Log "Skipped $funcName - score $score outside filter range"
                    return "skip"
                }
            }
        } catch {
            Write-WorkerHost "  Warning: Could not check completeness: $($_.Exception.Message)" "Yellow"
            Write-Log "Completeness check failed: $($_.Exception.Message)" "ERROR"
        }
    }
    
    # Load the optimized prompt template
    if ($defaultPrompt) {
        $basePrompt = @"
# FUNCTION DOCUMENTATION WORKFLOW V2

You are documenting functions in a Ghidra reverse engineering project using the GhidraMCP tools available to you.

## AVAILABLE MCP TOOLS

You have access to Ghidra MCP tools including:
- mcp_ghidra_decompile_function: Get decompiled code
- mcp_ghidra_get_function_variables: List all variables in a function
- mcp_ghidra_batch_rename_function_components: Rename function and variables atomically
- mcp_ghidra_batch_set_variable_types: Set types for multiple variables
- mcp_ghidra_batch_set_comments: Set multiple comments in one operation
- mcp_ghidra_set_function_prototype: Set function prototype
- And many more...

## WORKFLOW STEPS

For the target function specified below, execute these steps using the MCP tools:

1. **Decompile the function**: Call mcp_ghidra_decompile_function with the function name
2. **Get variables**: Call mcp_ghidra_get_function_variables to see all parameters and locals
3. **Analyze completeness**: Review the completeness analysis provided below
4. **Apply fixes for missing elements**:
   - If missing custom name: Rename function using batch_rename_function_components
   - If missing prototype: Set prototype with set_function_prototype
   - If missing calling convention: Include in prototype
   - If missing plate comment: Add using batch_set_comments
   - If undefined variables exist: Rename them using batch_rename_function_components
5. **Verify changes**: Call the appropriate tools to confirm changes were applied

## GUIDING PRINCIPLES

- Use descriptive, meaningful names that reflect purpose
- Document what the function does, not how it does it
- Focus on missing elements identified in the completeness analysis
- **IMPORTANT**: Actually call the MCP tools to make changes in Ghidra - don't just describe what should be done
- Use batch operations for efficiency
- **CRITICAL**: When writing plate comments, use actual newlines in the string, NOT escaped characters like \n or \t. The MCP tools handle proper formatting automatically.
"@
    } else {
        if (-not (Test-Path $promptFile)) {
            Write-WorkerHost "ERROR: Prompt file not found at $promptFile" "Red"
            return $false
        }
        $basePrompt = Get-Content $promptFile -Raw
    }
    
    $prompt = $basePrompt + "`n`n## TARGET FUNCTION TO DOCUMENT`n`nFunction Name: **$funcName**$(if ($address) { "`nFunction Address: **0x$address**" })$completenessInfo`n`n**BEGIN DOCUMENTATION:** Proceed with complete and thorough documentation of this function following the workflow above."
    
    $promptSize = [System.Text.Encoding]::UTF8.GetByteCount($prompt)
    Write-Log "Prompt size: $promptSize bytes"
    if ($promptSize -gt $MAX_PROMPT_BYTES) {
        Write-WorkerHost "  WARNING: Large prompt ($promptSize bytes), may hit context limits" "Yellow"
        Write-Log "Large prompt warning: $promptSize bytes" "WARN"
    }
    
    try {
        $env:NODE_OPTIONS = "--max-old-space-size=8192"
        Write-WorkerHost "Invoking Claude with MCP..." "Cyan"
        Write-Log "Invoking Claude for $funcName with model $Model"
        
        $retryCount = 0
        $backoffSeconds = 2
        $success = $false
        $output = ""
        
        while ($retryCount -lt $MaxRetries) {
            $output = echo $prompt | claude --model $Model 2>&1
            $exitCode = $LASTEXITCODE
            
            # Check for rate limit message (5-hour limit)
            $outputStr = $output -join "`n"
            if ($outputStr -match "5-hour limit|hour limit reached|resets \d+[ap]m|extra-usage") {
                Write-WorkerHost "Rate limit detected! Parsing reset time..." "Red"
                Write-Log "Rate limit hit: $outputStr" "WARN"
                
                # Try to parse the reset time from the message
                # Format: "resets 9am (America/Chicago)" or "resets 2pm (America/Chicago)"
                $resetHour = 9  # Default to 9 AM
                $resetTimezone = "Central Standard Time"  # Default
                
                if ($outputStr -match "resets\s+(\d+)(am|pm)\s*\(([^)]+)\)") {
                    $parsedHour = [int]$Matches[1]
                    $ampm = $Matches[2]
                    $tzName = $Matches[3]
                    
                    # Convert to 24-hour format
                    if ($ampm -eq "pm" -and $parsedHour -ne 12) {
                        $resetHour = $parsedHour + 12
                    } elseif ($ampm -eq "am" -and $parsedHour -eq 12) {
                        $resetHour = 0
                    } else {
                        $resetHour = $parsedHour
                    }
                    
                    Write-WorkerHost "Parsed reset time: $parsedHour$ampm ($tzName)" "Yellow"
                    
                    # Map timezone name to Windows timezone ID
                    $tzMap = @{
                        "America/Chicago" = "Central Standard Time"
                        "America/New_York" = "Eastern Standard Time"
                        "America/Los_Angeles" = "Pacific Standard Time"
                        "America/Denver" = "Mountain Standard Time"
                        "America/Phoenix" = "US Mountain Standard Time"
                        "Europe/London" = "GMT Standard Time"
                        "Europe/Paris" = "Romance Standard Time"
                        "Asia/Tokyo" = "Tokyo Standard Time"
                        "UTC" = "UTC"
                    }
                    
                    if ($tzMap.ContainsKey($tzName)) {
                        $resetTimezone = $tzMap[$tzName]
                    } else {
                        Write-WorkerHost "Unknown timezone '$tzName', using Central" "Yellow"
                    }
                } elseif ($outputStr -match "resets\s+(\d+)(am|pm)") {
                    # Simpler format without timezone
                    $parsedHour = [int]$Matches[1]
                    $ampm = $Matches[2]
                    
                    if ($ampm -eq "pm" -and $parsedHour -ne 12) {
                        $resetHour = $parsedHour + 12
                    } elseif ($ampm -eq "am" -and $parsedHour -eq 12) {
                        $resetHour = 0
                    } else {
                        $resetHour = $parsedHour
                    }
                    
                    Write-WorkerHost "Parsed reset time: $parsedHour$ampm (assuming Chicago)" "Yellow"
                }
                
                # Calculate wait time
                try {
                    $targetTZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($resetTimezone)
                } catch {
                    Write-WorkerHost "Could not find timezone '$resetTimezone', using Central" "Yellow"
                    $targetTZ = [System.TimeZoneInfo]::FindSystemTimeZoneById("Central Standard Time")
                }
                
                $nowInTZ = [System.TimeZoneInfo]::ConvertTimeFromUtc([DateTime]::UtcNow, $targetTZ)
                
                # Target reset time + 5 minutes buffer
                $target = $nowInTZ.Date.AddHours($resetHour).AddMinutes(5)
                if ($nowInTZ -ge $target) {
                    # Already past reset time today, wait until tomorrow
                    $target = $target.AddDays(1)
                }
                
                $waitTime = $target - $nowInTZ
                $waitMinutes = [Math]::Ceiling($waitTime.TotalMinutes)
                $waitHours = [Math]::Floor($waitTime.TotalHours)
                $remainingMins = $waitMinutes - ($waitHours * 60)
                
                Write-WorkerHost "Current time: $($nowInTZ.ToString('h:mm tt'))" "Yellow"
                Write-WorkerHost "Waiting until $($target.ToString('h:mm tt')) (~$waitHours h $remainingMins m)..." "Yellow"
                Write-WorkerHost "Will resume at: $($target.ToString('M/d/yyyy h:mm tt'))" "Cyan"
                Write-Log "Waiting $waitMinutes minutes until $($target.ToString('h:mm tt'))"
                
                # Wait in 1-minute intervals so we can show progress
                $waitEnd = (Get-Date).AddMinutes($waitMinutes)
                while ((Get-Date) -lt $waitEnd) {
                    $remaining = $waitEnd - (Get-Date)
                    $remHours = [Math]::Floor($remaining.TotalHours)
                    $remMins = [Math]::Floor($remaining.TotalMinutes) % 60
                    Write-Host "`r[RATE LIMITED] Resuming in $remHours h $remMins m...    " -NoNewline -ForegroundColor DarkYellow
                    Start-Sleep -Seconds 60
                }
                Write-Host ""
                Write-WorkerHost "Rate limit should be reset. Resuming..." "Green"
                Write-Log "Resuming after rate limit wait"
                
                # Reset retry counter and try again
                $retryCount = 0
                $backoffSeconds = 2
                continue
            }
            
            if ($exitCode -eq 0) {
                $success = $true
                break
            }
            
            $retryCount++
            if ($retryCount -lt $MaxRetries) {
                Write-WorkerHost "  Retry $retryCount/$MaxRetries after $backoffSeconds seconds..." "Yellow"
                Write-Log "Retry attempt $retryCount after failure" "WARN"
                Start-Sleep -Seconds $backoffSeconds
                $backoffSeconds *= 2
            }
        }
        
        if ($success) {
            Write-WorkerHost "Success!" "Green"
            Write-Log "Successfully processed $funcName"
            
            $outputFile = Join-Path $outputDir "$funcName-worker$WorkerId-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
            $output | Out-File $outputFile -Encoding UTF8
            Write-WorkerHost "  Output saved to: $outputFile" "Gray"
            
            $complianceIssues = Test-WorkflowCompliance -output $output -funcName $funcName -initialScore $score
            if ($complianceIssues.Count -gt 0) {
                Write-WorkerHost "  WORKFLOW COMPLIANCE ISSUES:" "Yellow"
                foreach ($issue in $complianceIssues) {
                    Write-WorkerHost "    - $issue" "Yellow"
                    Write-Log "Compliance issue for ${funcName}: $issue" "WARN"
                }
            }
            
            Write-Host $output
            
            if (-not $SkipValidation -and $address) {
                Write-WorkerHost "  Validating changes..." "Cyan"
                Start-Sleep -Seconds 2
                
                try {
                    $newResponse = Invoke-RestMethod -Uri "$GhidraServer/analyze_function_completeness?function_address=0x$address" -Method GET -TimeoutSec 10
                    $newScore = $newResponse.completeness_score
                    
                    if ($newScore -gt $score) {
                        $improvement = $newScore - $score
                        Write-WorkerHost "  Improved: $score -> $newScore (+$improvement)" "Green"
                        Write-Log "Score improved from $score to $newScore for $funcName"
                    } elseif ($newScore -eq $score) {
                        Write-WorkerHost "  No change: Score remains $score" "Yellow"
                        Write-Log "No score improvement for $funcName (remains $score)" "WARN"
                    } else {
                        Write-WorkerHost "  WARNING: Score decreased: $score -> $newScore" "Red"
                        Write-Log "Score decreased from $score to $newScore for $funcName" "ERROR"
                    }
                } catch {
                    Write-WorkerHost "  Could not validate changes: $($_.Exception.Message)" "Yellow"
                    Write-Log "Validation failed: $($_.Exception.Message)" "WARN"
                }
            }
            
            $checkpoint = @{
                LastProcessed = $funcName
                Address = $address
                Timestamp = Get-Date -Format "o"
                InitialScore = $score
                Model = $Model
                WorkerId = $WorkerId
            }
            $checkpoint | ConvertTo-Json | Set-Content $checkpointFile
            
            return $true
        } else {
            Write-WorkerHost "Failed after $MaxRetries attempts" "Red"
            Write-Host $output
            Write-Log "Failed to process $funcName after $MaxRetries attempts" "ERROR"
            Write-Log "Error output: $output" "ERROR"
            return $false
        }
    }
    finally {
        $env:NODE_OPTIONS = $null
    }
}

function Start-Coordinator {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Starting Parallel Function Processor" -ForegroundColor Cyan
    Write-Host "Workers: $Workers" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Clear stale locks from previous runs
    Clear-StaleLocks -MaxAgeMinutes $STALE_LOCK_MINUTES
    
    # Count pending functions
    $content = Get-Content $todoFile
    $pending = $content | Where-Object { $_ -match '^\[ \] (.+?) @ ([0-9a-fA-F]+)' }
    
    if ($pending.Count -eq 0) {
        Write-Host "No pending functions to process" -ForegroundColor Green
        exit 0
    }
    
    Write-Host "Found $($pending.Count) pending functions" -ForegroundColor Cyan
    Write-Host "Spawning $Workers worker processes..." -ForegroundColor Cyan
    Write-Host ""
    
    # Build common arguments string - DO NOT pass -Workers to prevent recursive coordinator spawning
    $commonArgs = ""
    if ($Reverse) { $commonArgs += " -Reverse" }
    if ($SkipValidation) { $commonArgs += " -SkipValidation" }
    $commonArgs += " -Model `"$Model`""
    $commonArgs += " -MaxRetries $MaxRetries"
    $commonArgs += " -DelayBetweenFunctions $DelayBetweenFunctions"
    $commonArgs += " -MinScore $MinScore"
    $commonArgs += " -MaxScore $MaxScore"
    $commonArgs += " -GhidraServer `"$GhidraServer`""
    # Note: We intentionally do NOT pass -Workers to spawned processes
    # This ensures they run in worker mode, not coordinator mode
    
    # Start worker processes in new windows
    $processes = @()
    $scriptPath = $PSCommandPath
    $scriptDir = Split-Path -Parent $scriptPath
    $scriptName = Split-Path -Leaf $scriptPath
    
    for ($i = 0; $i -lt $Workers; $i++) {
        $workerArgs = "$commonArgs -WorkerId $i"
        
        Write-Host "Starting Worker $i in new window..." -ForegroundColor Yellow
        
        # Start a new PowerShell window for each worker
        $proc = Start-Process powershell.exe -ArgumentList "-NoExit -Command `"Set-Location '$scriptDir'; .\$scriptName $workerArgs`"" -PassThru
        
        $processes += $proc
        
        # Stagger worker starts to reduce lock contention
        Start-Sleep -Milliseconds 1000
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "All $Workers workers started in separate windows!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Each worker will:" -ForegroundColor White
    Write-Host "  - Pick an unclaimed function from the todo list" -ForegroundColor Gray
    Write-Host "  - Process it with Claude" -ForegroundColor Gray
    Write-Host "  - Move to the next unclaimed function" -ForegroundColor Gray
    Write-Host "  - Continue until all functions are done" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Press Ctrl+C to stop all workers and exit." -ForegroundColor Yellow
    Write-Host ""
    
    # Monitor progress in this window
    Write-Host "Monitoring progress..." -ForegroundColor Cyan
    Write-Host ""
    
    try {
        while ($true) {
            # Check how many workers are still running
            $runningCount = ($processes | Where-Object { -not $_.HasExited }).Count
            
            # Get current pending count
            $content = Get-Content $todoFile
            $remaining = ($content | Where-Object { $_ -match '^\[ \] ' }).Count
            $completedFuncs = ($content | Where-Object { $_ -match '^\[X\] ' }).Count
            $failedFuncs = ($content | Where-Object { $_ -match '^\[!\] ' }).Count
            
            Write-Host "`r[$(Get-Date -Format 'HH:mm:ss')] Workers: $runningCount running | Completed: $completedFuncs | Remaining: $remaining | Failed: $failedFuncs    " -NoNewline
            
            # Exit if all workers have finished
            if ($runningCount -eq 0) {
                Write-Host ""
                Write-Host ""
                Write-Host "All workers have finished!" -ForegroundColor Green
                break
            }
            
            Start-Sleep -Seconds 10
        }
    } finally {
        Write-Host ""
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Stopping all workers..." -ForegroundColor Yellow
        
        # Kill all spawned worker processes
        foreach ($proc in $processes) {
            if (-not $proc.HasExited) {
                try {
                    Write-Host "  Stopping Worker (PID: $($proc.Id))..." -ForegroundColor Gray
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                } catch {
                    # Process may have already exited
                }
            }
        }
        
        # Give processes a moment to terminate
        Start-Sleep -Milliseconds 500
        
        # Clean up lock files
        Get-ChildItem $lockDir -Filter "*.lock" -ErrorAction SilentlyContinue | Remove-Item -Force
        
        # Final summary
        $content = Get-Content $todoFile
        $completed = ($content | Where-Object { $_ -match '^\[X\] ' }).Count
        $remaining = ($content | Where-Object { $_ -match '^\[ \] ' }).Count
        $failed = ($content | Where-Object { $_ -match '^\[!\] ' }).Count
        
        Write-Host ""
        Write-Host "Final Summary:" -ForegroundColor Cyan
        Write-Host "  Completed: $completed" -ForegroundColor Green
        Write-Host "  Remaining: $remaining" -ForegroundColor Yellow
        Write-Host "  Failed: $failed" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Cyan
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if ($Help) { Show-Help }

# Only become coordinator if:
# 1. Workers > 1 (user wants parallel processing)
# 2. WorkerId is still default 0 (not explicitly set as a worker)
# 3. Not already marked as coordinator
# 4. Workers param was explicitly passed (not default)
# When spawned as a worker, WorkerId is set explicitly, so this won't trigger
if ($Workers -gt 1 -and $PSBoundParameters.ContainsKey('Workers') -and -not $PSBoundParameters.ContainsKey('WorkerId')) {
    $Coordinator = $true
}

if ($Coordinator) {
    Start-Coordinator
    exit 0
}

# Worker mode
Write-Log "Worker $WorkerId started with parameters: Reverse=$Reverse, Model=$Model, MinScore=$MinScore, MaxScore=$MaxScore, GhidraServer=$GhidraServer"

# Validate todo file exists
if (-not (Test-Path $todoFile)) {
    Write-WorkerHost "ERROR: Todo file not found at $todoFile" "Red"
    Write-Log "Todo file not found: $todoFile" "ERROR"
    exit 1
}

# Clear stale locks on startup
Clear-StaleLocks -MaxAgeMinutes $STALE_LOCK_MINUTES

# Check for previous checkpoint
if (Test-Path $checkpointFile) {
    $lastCheckpoint = Get-Content $checkpointFile | ConvertFrom-Json
    Write-WorkerHost "Last checkpoint: $($lastCheckpoint.LastProcessed) @ $($lastCheckpoint.Address)" "Cyan"
    Write-Log "Resuming from checkpoint: $($lastCheckpoint.LastProcessed)"
}

if ($Function) {
    if ($DryRun) {
        Write-WorkerHost "DRY RUN: Would process function $Function" "Cyan"
        exit 0
    }
    
    if (Try-ClaimFunction $Function "") {
        try {
            $success = Process-Function $Function
            if ($success) {
                Update-TodoFile $Function "complete"
            }
        } finally {
            Release-FunctionLock $Function
        }
    } else {
        Write-WorkerHost "Function $Function is being processed by another worker" "Yellow"
    }
    exit 0
}

# Main processing loop
$processedCount = 0
$successCount = 0
$failCount = 0
$skipCount = 0

while ($true) {
    $content = Get-Content $todoFile
    $pending = $content | Where-Object { $_ -match '^\[ \] (.+?) @ ([0-9a-fA-F]+)' }
    
    if ($pending.Count -eq 0) { 
        Write-WorkerHost "No more pending functions" "Green"
        break 
    }
    
    # Find next unclaimed function
    $claimed = $false
    $funcName = ""
    $address = ""
    
    # Get functions in order based on -Reverse flag
    $orderedPending = if ($Reverse) { 
        $pending | Select-Object -Last ([Math]::Min($FUNCTION_BATCH_SIZE, $pending.Count))
    } else { 
        $pending | Select-Object -First ([Math]::Min($FUNCTION_BATCH_SIZE, $pending.Count))
    }
    
    # Add some randomization for workers to spread out
    if ($Workers -gt 1) {
        $orderedPending = $orderedPending | Get-Random -Count $orderedPending.Count
    }
    
    foreach ($line in $orderedPending) {
        $lineMatch = [regex]::Match($line, '^\[ \] (.+?) @ ([0-9a-fA-F]+)')
        $testFunc = $lineMatch.Groups[1].Value
        $testAddr = $lineMatch.Groups[2].Value
        
        if (Try-ClaimFunction $testFunc $testAddr) {
            $funcName = $testFunc
            $address = $testAddr
            $claimed = $true
            break
        }
    }
    
    if (-not $claimed) {
        # All visible functions are claimed, wait and retry
        Write-WorkerHost "All functions currently claimed, waiting..." "Gray"
        Start-Sleep -Seconds (3 + (Get-Random -Maximum 5))
        continue
    }
    
    try {
        Write-WorkerHost "$($pending.Count) remaining" "Yellow"
        $result = Process-Function $funcName $address
        
        $processedCount++
        if ($result -eq "skip") {
            $skipCount++
            Update-TodoFile $funcName "complete"
            Write-WorkerHost "  Marked as complete (skipped)" "Gray"
        } elseif ($result) {
            $successCount++
            Update-TodoFile $funcName "complete"
        } else {
            $failCount++
            Update-TodoFile $funcName "failed"
        }
    } finally {
        Release-FunctionLock $funcName
    }
    
    if ($Single) { break }
    
    if ($pending.Count -gt 1) {
        $delay = $DelayBetweenFunctions + (Get-Random -Maximum 2)
        Write-WorkerHost "Waiting $delay seconds before next function..." "Gray"
        Start-Sleep -Seconds $delay
    }
}

# Worker summary
Write-Host ""
Write-WorkerHost "========================================" "Cyan"
Write-WorkerHost "Worker $WorkerId Summary" "Cyan"
Write-WorkerHost "========================================" "Cyan"
Write-WorkerHost "Processed: $processedCount" "White"
Write-WorkerHost "Successful: $successCount" "Green"
Write-WorkerHost "Skipped: $skipCount" "Yellow"
Write-WorkerHost "Failed: $failCount" "Red"
Write-WorkerHost "Log file: $logFile" "Gray"
Write-WorkerHost "========================================" "Cyan"

Write-Log "Worker completed: $processedCount processed, $successCount successful, $skipCount skipped, $failCount failed"

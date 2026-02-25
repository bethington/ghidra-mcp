param(
    [Alias("r")][switch]$Reverse,
    [Alias("1")][switch]$Single,
    [Alias("f")][string]$Function,
    [ValidateSet("haiku", "sonnet", "opus")]
    [Alias("m")][string]$Model = "opus",
    [Alias("h", "?")][switch]$Help,
    [int]$MaxRetries = 3,
    [Alias("Delay")][int]$DelayBetweenFunctions = 0,
    [int]$MinScore = 0,
    [int]$MaxScore = 99,
    [Alias("n", "Max")][int]$MaxFunctions = 0,
    [Alias("Dry")][switch]$DryRun,
    [Alias("NoValidate")][switch]$SkipValidation,
    [Alias("Compact", "C")][switch]$CompactPrompt,
    [switch]$Subagent,
    [Alias("w", "j")][int]$Workers = 1,
    [switch]$Coordinator,
    [int]$WorkerId = 0,
    [Alias("Server")][string]$GhidraServer = "http://127.0.0.1:8089",
    [Alias("Rescan")][switch]$ReEvaluate,
    [Alias("Cleanup")][switch]$CleanupScripts,
    [Alias("L")][switch]$Log,  # Enable logging, output files, checkpoints
    [Alias("Pick", "Threshold")][switch]$PickThreshold,  # Show popup to pick minimum completeness threshold
    # Path overrides  -  useful for CI/CD or non-standard project layouts
    [string]$TodoFilePath = ".\FunctionsTodo.txt",
    [string]$LockDirPath = ".\locks",
    [string]$OutputDirPath = ".\output",
    # External binary priority order file (one binary name per line, # comments allowed)
    # If not provided, the built-in Diablo2 order is used as a fallback
    [string]$BinaryOrderFile = "",
    # Skip pre-flight validation checks (claude in PATH, Ghidra health, prompt file)
    [switch]$SkipPreFlight,
    # Show INFO-level diagnostic messages on console without writing a log file.
    # More granular than -Log (which writes everything to a file).
    # Combine with -Log to get both console diagnostics AND the log file.
    [Alias("D")][switch]$Diagnostic,
    # Record timing for every major operation and print a breakdown at the end.
    # Use with -DryRun to measure pre-processing overhead without calling Claude.
    [Alias("P")][switch]$Profile
)

# Fast mode is default unless -Log is specified
$Fast = -not $Log

# Log buffer for batch writes (reduces file I/O)
$script:LogBuffer = [System.Collections.Generic.List[string]]::new()
$script:LogFlushInterval = 10  # Flush every 10 entries

# Error/warn accumulator  -  always populated regardless of -Log/-Diagnostic.
# Printed as a "Problems this run" summary at end of worker execution.
$script:ErrorEvents = [System.Collections.Generic.List[string]]::new()

# Timing accumulator for -Profile mode.
$script:Timings = [System.Collections.Generic.List[hashtable]]::new()

# Todo file parse cache  -  avoids re-parsing on every loop iteration when unchanged.
$script:TodoCacheMtime = $null
$script:TodoCacheData  = $null

function Measure-Op {
    <#
    .SYNOPSIS
        Time a block of code and record it when -Profile is active.
    .DESCRIPTION
        When -Profile is not set this is a thin wrapper with no overhead.
        Pass -PassThru to get the scriptblock return value back to the caller.
    #>
    param(
        [string]$Name,
        [scriptblock]$Block,
        [switch]$PassThru
    )
    if (-not $Profile) {
        if ($PassThru) { return (& $Block) } else { & $Block | Out-Null; return }
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = & $Block
    $sw.Stop()
    [void]$script:Timings.Add(@{ Op = $Name; Ms = [Math]::Round($sw.Elapsed.TotalMilliseconds, 1) })
    if ($PassThru) { return $result }
}

# Model name - CLI accepts simple aliases directly
$FullModelName = $Model

# Constants
$STALE_LOCK_MINUTES = 30
$MAX_PROMPT_BYTES = 180000
$FUNCTION_BATCH_SIZE = 50

# Regex patterns for parsing todo file
# New format: [ ] ProgramName::FunctionName @ Address (Score: N) [Issues]
# Old format: [ ] FunctionName @ Address
$FUNC_PATTERN_NEW = '^\[(.)\]\s+(.+?)::(.+?)\s+@\s*([0-9a-fA-F]+)(?:\s+\(Score:\s*(\d+)\))?(?:\s+\[([^\]]+)\])?'
$FUNC_PATTERN_OLD = '^\[(.)\]\s+([^:]+?)\s+@\s*([0-9a-fA-F]+)(?:\s+\(Score:\s*(\d+)\))?(?:\s+\[([^\]]+)\])?'

# Track current program and version for switching
$script:CurrentProgram = $null
$script:ProjectFolder = $null
$script:GameVersion = $null

$todoFile = $TodoFilePath
$promptFile = if ($Subagent) {
    ".\\docs\\prompts\\FUNCTION_DOC_WORKFLOW_V5_BATCH.md"
} elseif ($CompactPrompt) {
    ".\\docs\\prompts\\FUNCTION_DOC_WORKFLOW_V5.md"
} else {
    ".\\docs\\prompts\\FUNCTION_DOC_WORKFLOW_V5.md"
}
$logFile = ".\\logs\\functions-process-worker$WorkerId-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$checkpointFile = ".\\functions-progress-worker$WorkerId.json"
$outputDir = $OutputDirPath
$lockDir = $LockDirPath
$globalLockFile = Join-Path $lockDir ".global.lock"

# Create directories if they don't exist
New-Item -ItemType Directory -Force -Path ".\\logs" | Out-Null
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
New-Item -ItemType Directory -Force -Path $lockDir | Out-Null

# Prompt file is required  -  fail fast if missing
if (-not (Test-Path $promptFile)) {
    Write-Host "ERROR: Prompt file not found at $promptFile" -ForegroundColor Red
    Write-Host "Use -Subagent or -CompactPrompt to select an alternate prompt, or create the missing file." -ForegroundColor Red
    exit 1
}
$promptSize = (Get-Content $promptFile -Raw).Length
$workflowType = if ($Subagent) { "V4-SUBAGENT" } elseif ($CompactPrompt) { "V4-COMPACT" } else { "V4" }
Write-Host "Using workflow $workflowType prompt ($promptSize chars, ~$([math]::Round($promptSize/4)) tokens)" -ForegroundColor Green

# Display active configuration summary (skip for coordinator spawned workers)
if (-not $Coordinator -or $WorkerId -eq 0) {
    Write-Host ""
    Write-Host "=== CONFIGURATION ===" -ForegroundColor Cyan
    
    # Show prompt file prominently
    $promptFileName = Split-Path $promptFile -Leaf
    if ($CompactPrompt) {
        Write-Host "Prompt: $promptFileName " -NoNewline -ForegroundColor White
        Write-Host "[COMPACT MODE - 60% smaller]" -ForegroundColor Green
    } elseif ($Subagent) {
        Write-Host "Prompt: $promptFileName [SUBAGENT MODE]" -ForegroundColor Magenta
    } else {
        Write-Host "Prompt: $promptFileName" -ForegroundColor White
    }
    
    # Build options list
    $opts = @()
    $opts += "Model: $Model"
    $opts += "Workers: $Workers"
    if ($MinScore -gt 0 -or $MaxScore -lt 99) { $opts += "Score: $MinScore-$MaxScore" }
    if ($MaxFunctions -gt 0) { $opts += "Max: $MaxFunctions" }
    if ($DryRun) { $opts += "DRY-RUN" }
    if ($SkipValidation) { $opts += "NoValidate" }
    if ($Reverse) { $opts += "Reverse" }
    if ($Single) { $opts += "Single" }
    if ($Function) { $opts += "Target: $Function" }
    if ($Log) { 
        $opts += "LOGGING" 
    }
    
    Write-Host ($opts -join " | ") -ForegroundColor Gray
    if ($Log) {
        Write-Host "Note: Logging mode saves output files and checkpoints (slightly slower)" -ForegroundColor DarkYellow
    }
    Write-Host "Server: $GhidraServer" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")

    # Fast-exit for INFO in default mode — hot path, called many times per function
    if ($Level -eq "INFO" -and $Fast -and -not $Diagnostic) { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [Worker$WorkerId] [$Level] $Message"

    # ERROR and WARN always echo to console  -  never silently dropped
    switch ($Level) {
        "ERROR" {
            Write-Host $logEntry -ForegroundColor Red
            [void]$script:ErrorEvents.Add($logEntry)
        }
        "WARN" {
            Write-Host $logEntry -ForegroundColor Yellow
        }
        default {
            # INFO: show on console only when -Diagnostic is set
            if ($Diagnostic) {
                Write-Host $logEntry -ForegroundColor DarkGray
            }
        }
    }

    # Write to file when -Log is enabled (existing behavior, unchanged)
    if (-not $Fast) {
        $script:LogBuffer.Add($logEntry)
        if ($script:LogBuffer.Count -ge $script:LogFlushInterval) {
            Flush-LogBuffer
        }
    }
}

function Flush-LogBuffer {
    if ($script:LogBuffer.Count -eq 0) { return }
    try {
        $script:LogBuffer -join "`n" | Add-Content $logFile -ErrorAction SilentlyContinue
        $script:LogBuffer.Clear()
    } catch { }
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
    Write-Host "  -Workers, -w, -j <n>   Number of parallel Claude workers (default: 1)"
    Write-Host "  -Coordinator           Run as coordinator spawning workers"
    Write-Host ""
    Write-Host "PROCESSING OPTIONS:"
    Write-Host "  -Single, -1            Process one function and stop"
    Write-Host "  -Function, -f <name>   Process specific function"
    Write-Host "  -Reverse, -r           Process from bottom to top"
    Write-Host "  -Model, -m <model>     Claude model: haiku|sonnet|opus (default: opus)"
    Write-Host "  -MaxFunctions, -n <n>  Stop after N functions (0 = unlimited)"
    Write-Host "  -MinScore <n>          Only process functions with score >= n"
    Write-Host "  -MaxScore <n>          Only process functions with score <= n"
    Write-Host "  -Delay <n>             Seconds between functions (default: 2)"
    Write-Host "  -DryRun, -Dry          Preview without changes"
    Write-Host "  -NoValidate            Skip post-processing validation"
    Write-Host "  -Compact, -C           Use compact prompt (~60% smaller)"
    Write-Host "  -Log, -L               Enable logging, output files, checkpoints"
    Write-Host "  -Diagnostic, -D        Show INFO diagnostics on console (no log file)"
    Write-Host "                         Combine with -Log to get both console + file"
    Write-Host "  -Profile, -P           Record timing for every major operation."
    Write-Host "                         Use -DryRun -Profile to benchmark without Claude."
    Write-Host "  -Subagent              Opus orchestrator + Haiku subagents"
    Write-Host "  -Rescan                Re-scan scores without Claude processing"
    Write-Host "  -Cleanup               Remove auto-generated Ghidra scripts"
    Write-Host "  -PickThreshold, -Pick  Show popup to select minimum completeness threshold"
    Write-Host "                         Functions below threshold added to reprocess list"
    Write-Host "  -Server <url>          Ghidra server URL (default: http://127.0.0.1:8089)"
    Write-Host "  -SkipPreFlight         Skip startup validation checks"
    Write-Host "  -Help, -h, -?          Show this help"
    Write-Host ""
    Write-Host "OUTPUT VERBOSITY:"
    Write-Host "  Default    Errors/warnings always shown; progress on console"
    Write-Host "  -D         + INFO diagnostics on console (retry attempts, API calls, etc.)"
    Write-Host "  -L         + full log written to .\logs\functions-process-workerN-*.log"
    Write-Host "  -D -L      Both console diagnostics and log file"
    Write-Host ""
    Write-Host "EXAMPLES:"
    Write-Host "  .\functions-process.ps1 -w 6              # 6 parallel workers"
    Write-Host "  .\functions-process.ps1 -w 4 -C           # 4 workers, compact prompt"
    Write-Host "  .\functions-process.ps1 -w 4 -C -L        # 4 workers with logging"
    Write-Host "  .\functions-process.ps1 -w 4 -D           # 4 workers with console diagnostics"
    Write-Host "  .\functions-process.ps1 -n 10 -m haiku    # 10 functions with Haiku"
    Write-Host "  .\functions-process.ps1 -1 -f FUN_6fab0  # Single specific function"
    Write-Host "  .\functions-process.ps1 -Rescan           # Re-scan scores only"
    Write-Host "  .\functions-process.ps1 -Cleanup          # Remove generated scripts"
    Write-Host "  .\functions-process.ps1 -Pick             # Pick threshold for reprocess list"
    Write-Host ""
    Write-Host "COST OPTIMIZATION:"
    Write-Host "  -m haiku is 10-20x cheaper than opus"
    Write-Host "  -C (compact) reduces prompt by ~60%"
    Write-Host ""
    Write-Host "NOTES:"
    Write-Host "  Workers claim functions via lock files to prevent collisions"
    Write-Host "  Progress tracked in completeness-tracking.json"
    Write-Host "  Errors and MCP failures always shown regardless of verbosity flags"
    exit 0
}

function Invoke-CleanupScripts {
    <#
    .SYNOPSIS
        Remove auto-generated Ghidra scripts created during function documentation.
    .DESCRIPTION
        Claude creates address-specific scripts (RecreateFunction*.java, FixFUN_*.java, etc.)
        when it encounters problematic functions. These are one-time use and can be cleaned up.
        Note: FixFunctionParameters.java and FixFunctionParametersHeadless.java are preserved.
    #>
    
    $scriptsDir = ".\ghidra_scripts"
    
    # Patterns for auto-generated scripts (matches .gitignore patterns)
    # Note: These patterns specifically target address-suffixed files (e.g., 6fc*, 6fa*)
    $patterns = @(
        "RecreateFunction*.java",
        "RecreateFUN_*.java",
        "RecreateFun*.java",
        "RecreateFunc*.java",
        "Recreate_*.java",
        "FixFunction6*.java",  # Address-specific only (preserves FixFunctionParameters.java)
        "FixFUN_*.java",
        "FixFun6*.java",       # Address-specific only
        "FixFunc6*.java",      # Address-specific only
        "Fix6fc*.java",
        "CreateFunctionAt*.java",
        "SimpleDisasm*.java",
        "SimpleFix*.java",
        "SimpleRecreate*.java",
        "AggressiveFix*.java",
        "ClearAndRecreate*.java",
        "ExpandFunc*.java",
        "ExpandFunction*.java",
        "CheckInstr*.java",
        "Debug6*.java",        # Address-specific debug scripts only
        "DisassembleAt*.java",
        "InspectAddress*.java",
        "InspectListing*.java",
        "MinimalFix*.java",
        "QuickFix*.java",
        "TestSimple.java"
    )
    
    Write-Host "Scanning for auto-generated Ghidra scripts..." -ForegroundColor Cyan
    
    $totalRemoved = 0
    $totalBytes = 0
    
    foreach ($pattern in $patterns) {
        $files = Get-ChildItem -Path $scriptsDir -Filter $pattern -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $totalBytes += $file.Length
            $totalRemoved++
            Write-Host "  Removing: $($file.Name)" -ForegroundColor Yellow
            Remove-Item $file.FullName -Force
        }
    }
    
    if ($totalRemoved -eq 0) {
        Write-Host "No auto-generated scripts found to clean up." -ForegroundColor Green
    } else {
        $sizeKB = [math]::Round($totalBytes / 1024, 1)
        Write-Host ""
        Write-Host "Cleanup complete:" -ForegroundColor Green
        Write-Host "  Removed: $totalRemoved scripts" -ForegroundColor Green
        Write-Host "  Freed: $sizeKB KB" -ForegroundColor Green
    }
}

function Get-FunctionLockFile {
    param([string]$funcName, [string]$programName = "")
    # Include program name in lock file to prevent cross-binary collisions
    $safeName = if ($programName) {
        ($programName -replace '[^a-zA-Z0-9_]', '_') + "__" + ($funcName -replace '[^a-zA-Z0-9_]', '_')
    } else {
        $funcName -replace '[^a-zA-Z0-9_]', '_'
    }
    return Join-Path $lockDir "$safeName.lock"
}

function Initialize-TodoFileContext {
    <#
    .SYNOPSIS
        Parse the todo file header to extract project folder and version.
    .DESCRIPTION
        Reads header comments from FunctionsTodo.txt to get:
        - Project Folder (e.g., /LoD/1.07)
        - Game Version (e.g., 1.07)
    #>
    param([string]$todoFilePath = $todoFile)

    if (-not (Test-Path $todoFilePath)) { return }

    $headerLines = Get-Content $todoFilePath -TotalCount 20

    foreach ($line in $headerLines) {
        # Parse: # Project Folder: /LoD/1.07
        if ($line -match '^#\s*Project\s*Folder:\s*(.+)$') {
            $script:ProjectFolder = $Matches[1].Trim()

            # Extract version from folder path (e.g., /LoD/1.07 -> 1.07)
            if ($script:ProjectFolder -match '/([^/]+)$') {
                $script:GameVersion = $Matches[1]
            }

            Write-Host "Project Folder: $($script:ProjectFolder)" -ForegroundColor Cyan
            Write-Host "Game Version: $($script:GameVersion)" -ForegroundColor Cyan
            break
        }
    }
}

function Parse-TodoLine {
    <#
    .SYNOPSIS
        Parse a todo line and return structured data.
    .DESCRIPTION
        Handles both new format (ProgramName::FunctionName @ Address (Score: N) [Issues])
        and old format (FunctionName @ Address).
    #>
    param([string]$line)

    # Try new format first: [ ] ProgramName::FunctionName @ Address (Score: N) [Issues]
    if ($line -match $FUNC_PATTERN_NEW) {
        return @{
            Status = $Matches[1]
            ProgramName = $Matches[2]
            FunctionName = $Matches[3]
            Address = $Matches[4]
            Score = if ($Matches[5]) { [int]$Matches[5] } else { $null }
            Issues = if ($Matches[6]) { $Matches[6] } else { $null }
            FullName = "$($Matches[2])::$($Matches[3])"
        }
    }
    # Fall back to old format: [ ] FunctionName @ Address [Issues]
    elseif ($line -match $FUNC_PATTERN_OLD) {
        return @{
            Status = $Matches[1]
            ProgramName = $null
            FunctionName = $Matches[2]
            Address = $Matches[3]
            Score = if ($Matches[4]) { [int]$Matches[4] } else { $null }
            Issues = if ($Matches[5]) { $Matches[5] } else { $null }
            FullName = $Matches[2]
        }
    }

    return $null
}

function Invoke-GhidraApi {
    <#
    .SYNOPSIS
        Invoke a Ghidra MCP endpoint with automatic retry on transient errors.
    .PARAMETER Uri
        Full URI to call.
    .PARAMETER Method
        HTTP method (GET or POST). Defaults to GET.
    .PARAMETER Body
        Optional hashtable body for POST requests (serialized to JSON).
    .PARAMETER TimeoutSec
        Per-attempt timeout in seconds. Defaults to 30.
    .PARAMETER MaxAttempts
        Total attempts before giving up. Defaults to 3.
    #>
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [object]$Body = $null,
        [int]$TimeoutSec = 30,
        [int]$MaxAttempts = 3
    )

    $delay = 500
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $params = @{
                Uri         = $Uri
                Method      = $Method
                TimeoutSec  = $TimeoutSec
                ErrorAction = 'Stop'
            }
            if ($null -ne $Body) {
                $params.Body        = ($Body | ConvertTo-Json -Compress)
                $params.ContentType = "application/json"
            }
            return Invoke-RestMethod @params
        } catch {
            $isTransient = $_.Exception.Message -match "(timeout|refused|reset|503|502|500)"
            if ($attempt -lt $MaxAttempts -and $isTransient) {
                Write-Log "Ghidra API call failed (attempt $attempt/$MaxAttempts): $($_.Exception.Message)  -  retrying in ${delay}ms" "WARN"
                Start-Sleep -Milliseconds $delay
                $delay = [Math]::Min($delay * 2, 10000)
            } else {
                throw
            }
        }
    }
}

function Switch-GhidraProgram {
    <#
    .SYNOPSIS
        Switch the active program in Ghidra if needed.
    .DESCRIPTION
        Calls the Ghidra MCP switch_program endpoint to change the active binary.
        If the program isn't already open, uses open_program to open it first.
        Uses the project folder/version context to build the full path.
    #>
    param([string]$programName)

    if (-not $programName) { return $true }
    if ($script:CurrentProgram -eq $programName) { return $true }

    # Build full path using project folder if available
    # e.g., "/LoD/1.07" + "D2Client.dll" = "/LoD/1.07/D2Client.dll"
    $switchPath = if ($script:ProjectFolder) {
        "$($script:ProjectFolder)/$programName"
    } else {
        $programName
    }

    $versionInfo = if ($script:GameVersion) { " (v$($script:GameVersion))" } else { "" }
    Write-WorkerHost "Switching to program: $programName$versionInfo" "Cyan"
    Write-Log "Switching Ghidra program to: $switchPath"

    try {
        # First try switch_program (for already-open programs)
        $response = Invoke-GhidraApi -Uri "$GhidraServer/switch_program?name=$([uri]::EscapeDataString($switchPath))" -TimeoutSec 30

        if ($response.success -or $response -match "success") {
            $script:CurrentProgram = $programName
            Write-WorkerHost "  Switched to: $programName" "Green"
            Write-Log "Successfully switched to program: $switchPath"
            return $true
        }
    } catch {
        # switch_program failed (likely 404 = not open), try open_program
        Write-Log "switch_program failed, trying open_program: $switchPath"
    }

    # Try open_program to open a program from the project
    try {
        Write-WorkerHost "  Opening program from project..." "Gray"
        $response = Invoke-GhidraApi -Uri "$GhidraServer/open_program?path=$([uri]::EscapeDataString($switchPath))" -TimeoutSec 60

        if ($response.success -or $response -match "success") {
            $script:CurrentProgram = $programName
            Write-WorkerHost "  Opened: $programName" "Green"
            Write-Log "Successfully opened program: $switchPath"
            return $true
        }
    } catch {
        Write-Log "open_program with full path failed: $($_.Exception.Message)"
    }

    # Fallback: try with just program name
    try {
        Write-Log "Trying program name only: $programName"
        $response = Invoke-GhidraApi -Uri "$GhidraServer/switch_program?name=$([uri]::EscapeDataString($programName))" -TimeoutSec 30

        if ($response.success -or $response -match "success") {
            $script:CurrentProgram = $programName
            Write-WorkerHost "  Switched to: $programName (name-only match)" "Green"
            Write-Log "Successfully switched to program (name-only): $programName"
            return $true
        }
    } catch {
        # Ignore, will report failure below
    }

    Write-WorkerHost "  Failed to switch/open: $programName" "Red"
    Write-Log "Failed to switch or open program: $switchPath" "ERROR"
    return $false
}

function Try-ClaimFunction {
    param([string]$funcName, [string]$address, [string]$programName = "")

    $lockFile = Get-FunctionLockFile $funcName $programName

    # Try to atomically create the lock file
    try {
        # Use .NET to create file with exclusive access
        $fs = [System.IO.File]::Open($lockFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

        # Write worker info to lock file
        $writer = New-Object System.IO.StreamWriter($fs)
        $writer.WriteLine("WorkerId: $WorkerId")
        $writer.WriteLine("Program: $programName")
        $writer.WriteLine("Function: $funcName")
        $writer.WriteLine("Address: $address")
        $writer.WriteLine("ClaimedAt: $(Get-Date -Format 'o')")
        $writer.WriteLine("PID: $PID")
        $writer.Close()
        $fs.Close()

        $displayName = if ($programName) { "${programName}::$funcName" } else { $funcName }
        Write-Log "Claimed function $displayName"
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
    param([string]$funcName, [string]$programName = "")

    $lockFile = Get-FunctionLockFile $funcName $programName

    if (Test-Path $lockFile) {
        try {
            Remove-Item $lockFile -Force -ErrorAction Stop
            $displayName = if ($programName) { "${programName}::$funcName" } else { $funcName }
            Write-Log "Released lock for $displayName"
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
    param([int]$TimeoutSeconds = 30)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $delay = 100  # Start at 100ms, double each attempt up to 5s

    while ((Get-Date) -lt $deadline) {
        try {
            $fs = [System.IO.File]::Open($globalLockFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $fs.Close()
            return $true
        } catch {
            Start-Sleep -Milliseconds $delay
            $delay = [Math]::Min($delay * 2, 5000)
        }
    }

    Write-Log "Global lock timeout after $TimeoutSeconds seconds" "ERROR"
    return $false
}

function Release-GlobalLock {
    if (Test-Path $globalLockFile) {
        Remove-Item $globalLockFile -Force -ErrorAction SilentlyContinue
    }
}

function Update-TodoFile {
    param(
        [string]$funcName,
        [string]$status,
        [string]$programName = "",
        [string]$address = ""
    )

    # Get global lock for atomic file update
    if (-not (Get-GlobalLock)) {
        Write-Log "Could not acquire global lock for todo update" "ERROR"
        return $false
    }

    try {
        $content = Get-Content $todoFile -Raw
        $escapedFuncName = [regex]::Escape($funcName)
        $escapedAddress = if ($address) { [regex]::Escape($address) } else { "[0-9a-fA-F]+" }

        # Build the pattern to match - handle both old and new formats
        # IMPORTANT: Match by BOTH function name AND address to handle duplicate names (e.g., Ordinal_220)
        if ($programName) {
            $escapedProgram = [regex]::Escape($programName)
            $matchPattern = "\[\s*\]\s+$escapedProgram::$escapedFuncName\s+@\s*$escapedAddress"
            $replaceWith = if ($status -eq "complete") { "[X] ${programName}::$funcName @ $address" } else { "[!] ${programName}::$funcName @ $address" }
        } else {
            $matchPattern = "\[\s*\]\s+$escapedFuncName\s+@\s*$escapedAddress"
            $replaceWith = if ($status -eq "complete") { "[X] $funcName @ $address" } else { "[!] $funcName @ $address" }
        }

        if ($status -eq "complete" -or $status -eq "failed") {
            $updated = $content -replace $matchPattern, $replaceWith
        } else {
            $updated = $content
        }

        Set-Content $todoFile $updated -NoNewline
        $displayName = if ($programName) { "${programName}::$funcName" } else { $funcName }
        Write-Log "Updated todo file: $displayName @ $address -> $status"
        return $true
    } finally {
        Release-GlobalLock
    }
}

# Completeness tracking database
$trackingFile = ".\completeness-tracking.json"

function Update-CompletenessTracking {
    param(
        [string]$funcName,
        [string]$address,
        [float]$initialScore,
        [float]$finalScore,
        [object]$completenessData = $null
    )
    
    if (-not (Get-GlobalLock)) {
        Write-Log "Could not acquire global lock for tracking update" "WARN"
        return $false
    }
    
    try {
        # Load existing tracking data
        if (Test-Path $trackingFile) {
            $tracking = Get-Content $trackingFile -Raw | ConvertFrom-Json
        } else {
            $tracking = @{
                metadata = @{
                    version = "1.0"
                    created = Get-Date -Format "o"
                    last_updated = $null
                    description = "Tracks completeness scores for documented functions"
                }
                functions = @{}
            }
        }
        
        # Create entry for this function
        $entry = @{
            address = "0x$address"
            initial_score = $initialScore
            current_score = $finalScore
            improvement = $finalScore - $initialScore
            last_processed = Get-Date -Format "o"
            model_used = $Model
            worker_id = $WorkerId
        }
        
        # Add detailed completeness data if provided
        if ($completenessData) {
            $entry.unrenamed_globals_count = if ($completenessData.unrenamed_globals) { $completenessData.unrenamed_globals.Count } else { 0 }
            $entry.undocumented_ordinals_count = if ($completenessData.undocumented_ordinals) { $completenessData.undocumented_ordinals.Count } else { 0 }
            $entry.comment_density = if ($completenessData.comment_density) { $completenessData.comment_density } else { 0 }
            $entry.undefined_vars_count = if ($completenessData.undefined_vars) { $completenessData.undefined_vars.Count } else { 0 }
        }
        
        # Track history
        if ($tracking.functions.$funcName) {
            $existing = $tracking.functions.$funcName
            if (-not $existing.history) {
                $existing | Add-Member -NotePropertyName history -NotePropertyValue @() -Force
            }
            $historyEntry = @{
                score = $existing.current_score
                timestamp = $existing.last_processed
            }
            $existing.history += $historyEntry
            
            # Update with new data
            foreach ($key in $entry.Keys) {
                $existing | Add-Member -NotePropertyName $key -NotePropertyValue $entry[$key] -Force
            }
        } else {
            $tracking.functions | Add-Member -NotePropertyName $funcName -NotePropertyValue $entry -Force
        }
        
        $tracking.metadata.last_updated = Get-Date -Format "o"
        
        # Save back
        $tracking | ConvertTo-Json -Depth 10 | Set-Content $trackingFile
        Write-Log "Updated completeness tracking for $funcName : $initialScore -> $finalScore"
        return $true
    } catch {
        Write-Log "Failed to update tracking: $($_.Exception.Message)" "ERROR"
        return $false
    } finally {
        Release-GlobalLock
    }
}

function Invoke-ReEvaluate {
    Write-Host "=== RE-EVALUATION MODE ===" -ForegroundColor Cyan
    Write-Host "Scanning functions for updated completeness scores (no Claude processing)" -ForegroundColor Cyan
    Write-Host ""

    # Load todo file to get function list
    if (-not (Test-Path $todoFile)) {
        Write-Host "ERROR: Todo file not found at $todoFile" -ForegroundColor Red
        return
    }

    # Initialize context from todo file header (project folder, version)
    Initialize-TodoFileContext
    Write-Host ""
    
    # Load existing tracking data for previous scores
    $previousScores = @{}
    if (Test-Path $trackingFile) {
        try {
            $tracking = Get-Content $trackingFile -Raw | ConvertFrom-Json
            foreach ($prop in $tracking.functions.PSObject.Properties) {
                $previousScores[$prop.Name] = $prop.Value.current_score
            }
            Write-Host "Loaded $($previousScores.Count) previous scores from tracking database" -ForegroundColor Gray
        } catch {
            Write-Host "Warning: Could not load tracking database" -ForegroundColor Yellow
        }
    }
    
    $lines = Get-Content $todoFile

    $total = 0
    $improved = 0
    $regressed = 0
    $unchanged = 0
    $errors = 0

    $results = @()

    foreach ($line in $lines) {
        $parsed = Parse-TodoLine $line
        if (-not $parsed) { continue }

        # Skip if not marked complete
        if ($parsed.Status -ne 'X') { continue }

        $funcName = $parsed.FunctionName
        $address = $parsed.Address
        $programName = $parsed.ProgramName

        # Switch program if needed
        if ($programName) {
            if (-not (Switch-GhidraProgram $programName)) {
                Write-Host "  Failed to switch to $programName, skipping" -ForegroundColor Red
                $errors++
                continue
            }
        }

        # Get previous score from tracking database, default to 0 if not found
        $displayName = if ($programName) { "${programName}::$funcName" } else { $funcName }
        $oldScore = if ($previousScores.ContainsKey($funcName)) { [int]$previousScores[$funcName] } else { 0 }

        $total++

        try {
            Write-Host "  Re-evaluating $displayName..." -NoNewline

            $response = Invoke-RestMethod -Uri "$GhidraServer/analyze_function_completeness?function_address=0x$address" -Method GET -TimeoutSec 15
            $newScore = [int]$response.completeness_score

            $result = @{
                name = $displayName
                address = $address
                program = $programName
                old_score = $oldScore
                new_score = $newScore
                difference = $newScore - $oldScore
                unrenamed_globals = if ($response.unrenamed_globals) { $response.unrenamed_globals.Count } else { 0 }
                undocumented_ordinals = if ($response.undocumented_ordinals) { $response.undocumented_ordinals.Count } else { 0 }
                comment_density = if ($response.comment_density) { $response.comment_density } else { 0 }
            }
            $results += $result

            if ($newScore -gt $oldScore) {
                Write-Host " $oldScore -> $newScore (+$($newScore - $oldScore))" -ForegroundColor Green
                $improved++
            } elseif ($newScore -lt $oldScore) {
                Write-Host " $oldScore -> $newScore ($($newScore - $oldScore))" -ForegroundColor Red
                $regressed++
            } else {
                Write-Host " $oldScore (no change)" -ForegroundColor Gray
                $unchanged++
            }

            # Update tracking database
            Update-CompletenessTracking -funcName $funcName -address $address -initialScore $oldScore -finalScore $newScore -completenessData $response | Out-Null

        } catch {
            Write-Host " ERROR: $($_.Exception.Message)" -ForegroundColor Red
            $errors++
        }

        Start-Sleep -Milliseconds 100  # Rate limiting
    }
    
    # Summary
    Write-Host ""
    Write-Host "=== RE-EVALUATION SUMMARY ===" -ForegroundColor Cyan
    Write-Host "  Total functions: $total" -ForegroundColor White
    Write-Host "  Improved: $improved" -ForegroundColor Green
    Write-Host "  Regressed: $regressed" -ForegroundColor Red
    Write-Host "  Unchanged: $unchanged" -ForegroundColor Gray
    Write-Host "  Errors: $errors" -ForegroundColor Yellow
    Write-Host ""
    
    # Show functions needing attention (DAT_* or Ordinals remaining)
    $needsWork = $results | Where-Object { $_.unrenamed_globals -gt 0 -or $_.undocumented_ordinals -gt 0 }
    if ($needsWork.Count -gt 0) {
        Write-Host "Functions needing attention:" -ForegroundColor Yellow
        foreach ($f in $needsWork | Sort-Object -Property @{Expression={$_.unrenamed_globals + $_.undocumented_ordinals}; Descending=$true} | Select-Object -First 10) {
            Write-Host "  $($f.name): $($f.unrenamed_globals) DAT_* globals, $($f.undocumented_ordinals) undocumented ordinals, density $($f.comment_density)" -ForegroundColor Yellow
        }
    }
    
    # Save detailed report
    $reportFile = ".\logs\reevaluate-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    @{
        timestamp = Get-Date -Format "o"
        summary = @{
            total = $total
            improved = $improved
            regressed = $regressed
            unchanged = $unchanged
            errors = $errors
        }
        functions = $results
    } | ConvertTo-Json -Depth 5 | Set-Content $reportFile
    Write-Host "Detailed report saved to: $reportFile" -ForegroundColor Cyan
}

function Show-ThresholdPicker {
    <#
    .SYNOPSIS
        Shows a Windows Forms popup to pick minimum completeness threshold.
    .DESCRIPTION
        Displays a dialog with a slider to select the minimum completeness score.
        Functions below this threshold will be included in the reprocessing list.
        Default is 80%.
    .RETURNS
        The selected threshold (0-100), or -1 if cancelled.
    #>

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Select Minimum Completeness Threshold"
    $form.Size = New-Object System.Drawing.Size(450, 280)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    # Instructions label
    $instructionLabel = New-Object System.Windows.Forms.Label
    $instructionLabel.Location = New-Object System.Drawing.Point(20, 20)
    $instructionLabel.Size = New-Object System.Drawing.Size(400, 40)
    $instructionLabel.Text = "Functions with completeness scores BELOW this threshold will be included in the todo list for reprocessing."
    $form.Controls.Add($instructionLabel)

    # Threshold label
    $thresholdLabel = New-Object System.Windows.Forms.Label
    $thresholdLabel.Location = New-Object System.Drawing.Point(20, 70)
    $thresholdLabel.Size = New-Object System.Drawing.Size(150, 20)
    $thresholdLabel.Text = "Minimum Score:"
    $form.Controls.Add($thresholdLabel)

    # Value display label
    $valueLabel = New-Object System.Windows.Forms.Label
    $valueLabel.Location = New-Object System.Drawing.Point(330, 100)
    $valueLabel.Size = New-Object System.Drawing.Size(60, 30)
    $valueLabel.Text = "80%"
    $valueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($valueLabel)

    # TrackBar (slider)
    $slider = New-Object System.Windows.Forms.TrackBar
    $slider.Location = New-Object System.Drawing.Point(20, 95)
    $slider.Size = New-Object System.Drawing.Size(300, 45)
    $slider.Minimum = 0
    $slider.Maximum = 100
    $slider.Value = 80
    $slider.TickFrequency = 10
    $slider.LargeChange = 10
    $slider.SmallChange = 5
    $slider.Add_ValueChanged({
        $valueLabel.Text = "$($slider.Value)%"
    })
    $form.Controls.Add($slider)

    # Quick preset buttons
    $presetLabel = New-Object System.Windows.Forms.Label
    $presetLabel.Location = New-Object System.Drawing.Point(20, 145)
    $presetLabel.Size = New-Object System.Drawing.Size(100, 20)
    $presetLabel.Text = "Quick presets:"
    $form.Controls.Add($presetLabel)

    $btn50 = New-Object System.Windows.Forms.Button
    $btn50.Location = New-Object System.Drawing.Point(120, 140)
    $btn50.Size = New-Object System.Drawing.Size(50, 25)
    $btn50.Text = "50%"
    $btn50.Add_Click({ $slider.Value = 50 })
    $form.Controls.Add($btn50)

    $btn70 = New-Object System.Windows.Forms.Button
    $btn70.Location = New-Object System.Drawing.Point(175, 140)
    $btn70.Size = New-Object System.Drawing.Size(50, 25)
    $btn70.Text = "70%"
    $btn70.Add_Click({ $slider.Value = 70 })
    $form.Controls.Add($btn70)

    $btn80 = New-Object System.Windows.Forms.Button
    $btn80.Location = New-Object System.Drawing.Point(230, 140)
    $btn80.Size = New-Object System.Drawing.Size(50, 25)
    $btn80.Text = "80%"
    $btn80.Add_Click({ $slider.Value = 80 })
    $form.Controls.Add($btn80)

    $btn90 = New-Object System.Windows.Forms.Button
    $btn90.Location = New-Object System.Drawing.Point(285, 140)
    $btn90.Size = New-Object System.Drawing.Size(50, 25)
    $btn90.Text = "90%"
    $btn90.Add_Click({ $slider.Value = 90 })
    $form.Controls.Add($btn90)

    $btn100 = New-Object System.Windows.Forms.Button
    $btn100.Location = New-Object System.Drawing.Point(340, 140)
    $btn100.Size = New-Object System.Drawing.Size(50, 25)
    $btn100.Text = "100%"
    $btn100.Add_Click({ $slider.Value = 100 })
    $form.Controls.Add($btn100)

    # OK button
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(120, 190)
    $okButton.Size = New-Object System.Drawing.Size(90, 30)
    $okButton.Text = "Generate List"
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    # Cancel button
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(230, 190)
    $cancelButton.Size = New-Object System.Drawing.Size(90, 30)
    $cancelButton.Text = "Cancel"
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $slider.Value
    } else {
        return -1
    }
}

function Invoke-ThresholdFilter {
    <#
    .SYNOPSIS
        Filter functions by completeness threshold and generate todo list.
    .DESCRIPTION
        Shows a popup to pick the minimum threshold, then scans all completed
        functions and adds those below the threshold back to the todo list
        for reprocessing.
    #>

    Write-Host "=== THRESHOLD FILTER MODE ===" -ForegroundColor Cyan
    Write-Host ""

    # Show the popup to get threshold
    $threshold = Show-ThresholdPicker

    if ($threshold -eq -1) {
        Write-Host "Cancelled by user." -ForegroundColor Yellow
        return
    }

    Write-Host "Selected threshold: $threshold%" -ForegroundColor Cyan
    Write-Host "Functions scoring below $threshold% will be added to the reprocess list." -ForegroundColor Cyan
    Write-Host ""

    # Initialize context from todo file header (project folder, version)
    Initialize-TodoFileContext
    Write-Host ""

    # Load existing tracking data for scores
    $functionScores = @{}
    if (Test-Path $trackingFile) {
        try {
            $tracking = Get-Content $trackingFile -Raw | ConvertFrom-Json
            foreach ($prop in $tracking.functions.PSObject.Properties) {
                $functionScores[$prop.Name] = @{
                    Score = $prop.Value.current_score
                    Address = $prop.Value.address
                }
            }
            Write-Host "Loaded $($functionScores.Count) function scores from tracking database" -ForegroundColor Gray
        } catch {
            Write-Host "Warning: Could not load tracking database" -ForegroundColor Yellow
        }
    }

    # Also check the todo file for completed functions and their scores
    if (-not (Test-Path $todoFile)) {
        Write-Host "ERROR: Todo file not found at $todoFile" -ForegroundColor Red
        return
    }

    $lines = Get-Content $todoFile
    $belowThreshold = @()
    $atOrAboveThreshold = @()
    $noScore = @()

    foreach ($line in $lines) {
        $parsed = Parse-TodoLine $line
        if (-not $parsed) { continue }

        # Check both pending [ ] and completed [X] functions
        $funcName = $parsed.FunctionName
        $address = $parsed.Address
        $programName = $parsed.ProgramName
        $displayName = if ($programName) { "${programName}::$funcName" } else { $funcName }

        # Get score from parsed line or tracking database
        $score = $parsed.Score
        if ($score -eq $null -and $functionScores.ContainsKey($funcName)) {
            $score = $functionScores[$funcName].Score
        }

        if ($score -eq $null) {
            # No score available - query Ghidra if possible
            if ($programName) {
                Switch-GhidraProgram $programName | Out-Null
            }
            try {
                $response = Invoke-RestMethod -Uri "$GhidraServer/analyze_function_completeness?function_address=0x$address" -Method GET -TimeoutSec 10
                $score = [int]$response.completeness_score
            } catch {
                $noScore += @{
                    Name = $displayName
                    Address = $address
                    Program = $programName
                    Line = $line
                }
                continue
            }
        }

        if ($score -lt $threshold) {
            $belowThreshold += @{
                Name = $displayName
                FuncName = $funcName
                Address = $address
                Program = $programName
                Score = $score
                Status = $parsed.Status
                Issues = $parsed.Issues
            }
        } else {
            $atOrAboveThreshold += @{
                Name = $displayName
                Score = $score
            }
        }
    }

    # Display results
    Write-Host ""
    Write-Host "=== THRESHOLD FILTER RESULTS ===" -ForegroundColor Cyan
    Write-Host "Threshold: $threshold%" -ForegroundColor White
    Write-Host ""
    Write-Host "Functions BELOW threshold (need reprocessing): $($belowThreshold.Count)" -ForegroundColor Yellow
    Write-Host "Functions AT OR ABOVE threshold: $($atOrAboveThreshold.Count)" -ForegroundColor Green
    if ($noScore.Count -gt 0) {
        Write-Host "Functions with no score data: $($noScore.Count)" -ForegroundColor Gray
    }
    Write-Host ""

    if ($belowThreshold.Count -eq 0) {
        Write-Host "All functions meet or exceed the $threshold% threshold!" -ForegroundColor Green
        return
    }

    # Show functions below threshold
    Write-Host "Functions below $threshold% threshold:" -ForegroundColor Yellow
    Write-Host "-" * 60 -ForegroundColor DarkGray

    $sortedBelow = $belowThreshold | Sort-Object -Property Score
    foreach ($func in $sortedBelow) {
        $statusIcon = if ($func.Status -eq 'X') { "[COMPLETED]" } elseif ($func.Status -eq '!') { "[FAILED]" } else { "[PENDING]" }
        $issuesText = if ($func.Issues) { " [$($func.Issues)]" } else { "" }
        Write-Host "  $($func.Score.ToString().PadLeft(3))%  $($func.Name) @ 0x$($func.Address) $statusIcon$issuesText" -ForegroundColor $(if ($func.Score -lt 50) { "Red" } elseif ($func.Score -lt 70) { "Yellow" } else { "White" })
    }
    Write-Host ""

    # Ask user what to do
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  1. Update todo file - Mark these functions as [ ] pending for reprocessing" -ForegroundColor White
    Write-Host "  2. Export to file - Save list to reprocess-functions.txt" -ForegroundColor White
    Write-Host "  3. Both - Update todo and export" -ForegroundColor White
    Write-Host "  4. Cancel - Exit without changes" -ForegroundColor White
    Write-Host ""

    $choice = Read-Host "Enter choice (1-4)"

    switch ($choice) {
        "1" {
            Update-TodoForReprocessing $belowThreshold
        }
        "2" {
            Export-ReprocessList $belowThreshold $threshold
        }
        "3" {
            Update-TodoForReprocessing $belowThreshold
            Export-ReprocessList $belowThreshold $threshold
        }
        default {
            Write-Host "Cancelled." -ForegroundColor Yellow
        }
    }
}

function Update-TodoForReprocessing {
    param([array]$functions)

    if (-not (Get-GlobalLock)) {
        Write-Host "Could not acquire lock for todo file update" -ForegroundColor Red
        return
    }

    try {
        $content = Get-Content $todoFile -Raw
        $updatedCount = 0

        foreach ($func in $functions) {
            # Only update completed [X] functions back to pending [ ]
            if ($func.Status -eq 'X') {
                $escapedFuncName = [regex]::Escape($func.FuncName)

                if ($func.Program) {
                    $escapedProgram = [regex]::Escape($func.Program)
                    $matchPattern = "\[X\]\s+$escapedProgram::$escapedFuncName\s+@"
                    $replaceWith = "[ ] $($func.Program)::$($func.FuncName) @"
                } else {
                    $matchPattern = "\[X\]\s+$escapedFuncName\s+@"
                    $replaceWith = "[ ] $($func.FuncName) @"
                }

                $newContent = $content -replace $matchPattern, $replaceWith
                if ($newContent -ne $content) {
                    $content = $newContent
                    $updatedCount++
                }
            }
        }

        Set-Content $todoFile $content -NoNewline
        Write-Host "Updated $updatedCount functions to pending status in todo file" -ForegroundColor Green
    } finally {
        Release-GlobalLock
    }
}

function Export-ReprocessList {
    param([array]$functions, [int]$threshold)

    $outputFile = ".\reprocess-functions-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    $content = @"
# Functions Below $threshold% Completeness Threshold
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Total: $($functions.Count) functions
#
# Format: [ ] ProgramName::FunctionName @ Address (Score: N) [Issues]
#

"@

    foreach ($func in ($functions | Sort-Object -Property Score)) {
        $issuesText = if ($func.Issues) { " [$($func.Issues)]" } else { "" }
        if ($func.Program) {
            $content += "[ ] $($func.Program)::$($func.FuncName) @ $($func.Address) (Score: $($func.Score))$issuesText`n"
        } else {
            $content += "[ ] $($func.FuncName) @ $($func.Address) (Score: $($func.Score))$issuesText`n"
        }
    }

    Set-Content $outputFile $content
    Write-Host "Exported $($functions.Count) functions to: $outputFile" -ForegroundColor Green
}

function Get-McpErrors {
    param([string]$output)
    
    $errors = @()
    
    # Common MCP error patterns
    $errorPatterns = @(
        # Patterns must be specific to avoid matching Claude's explanatory text
        # Require patterns to start with error indicators or be at line start
        @{ Pattern = '(?im)^\s*error[:\s]+.*?(?:failed|unable|cannot|could not|timeout|connection refused)'; Type = 'General Error' },
        @{ Pattern = '(?i)mcp_ghidra_\w+.*?(?:failed|error|exception)'; Type = 'MCP Tool Failure' },
        @{ Pattern = '(?i)GhidraValidationError[:\s]+(.+?)(?:\n|$)'; Type = 'Validation Error' },
        @{ Pattern = '(?im)^\s*(?:connection|socket).*?(?:refused|failed|timeout|error)'; Type = 'Connection Error' },
        @{ Pattern = '(?i)HTTP\s*(?:error|status)[:\s]*(?:404|500|502|503)'; Type = 'HTTP Error' },
        @{ Pattern = '(?im)^\s*(?:Error|Failed).*?variable.*?not found'; Type = 'Variable Not Found' },
        @{ Pattern = '(?im)^\s*(?:Error|Failed).*?function.*?not found'; Type = 'Function Not Found' },
        @{ Pattern = '(?i)(?:rename|set_type|set_prototype).*?failed'; Type = 'Rename/Type Failure' },
        @{ Pattern = '(?im)^\s*timeout.*?(?:waiting|exceeded|expired)'; Type = 'Timeout' },
        @{ Pattern = '(?im)^\s*(?:Error|Invalid).*?(?:address|parameter|argument|type)'; Type = 'Invalid Parameter' },
        @{ Pattern = '(?i)tool\s+(?:call|invocation)\s+(?:failed|error)'; Type = 'Tool Call Error' },
        @{ Pattern = '(?i)\bexception[:\s]+\w+Exception'; Type = 'Exception' }
    )
    
    foreach ($ep in $errorPatterns) {
        $matches = [regex]::Matches($output, $ep.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $matches) {
            $errorText = $m.Value.Trim()
            # Truncate long error messages
            if ($errorText.Length -gt 150) {
                $errorText = $errorText.Substring(0, 147) + "..."
            }
            $errors += @{
                Type = $ep.Type
                Message = $errorText
            }
        }
    }
    
    # Deduplicate errors by message
    $uniqueErrors = @()
    $seenMessages = @{}
    foreach ($err in $errors) {
        $key = $err.Message.ToLower()
        if (-not $seenMessages.ContainsKey($key)) {
            $seenMessages[$key] = $true
            $uniqueErrors += $err
        }
    }
    
    return $uniqueErrors
}

function Get-WorkflowMilestones {
    param([string]$output)
    
    $milestones = @()
    
    # Workflow milestone patterns - ordered by typical workflow sequence
    # Using ASCII-safe icons for PowerShell compatibility
    $milestonePatterns = @(
        @{ Pattern = '(?i)mcp_ghidra_decompile_function|decompil(?:ed|ing)\s+(?:function|code)'; Milestone = 'Decompiled function'; Icon = '[DECOMPILE]' },
        @{ Pattern = '(?i)mcp_ghidra_get_function_variables|(?:got|retrieved|listing)\s+variables'; Milestone = 'Retrieved variables'; Icon = '[VARS]' },
        @{ Pattern = '(?i)mcp_ghidra_analyze_function_completeness|completeness.*?(\d+)'; Milestone = 'Analyzed completeness'; Icon = '[SCORE]' },
        @{ Pattern = '(?i)mcp_ghidra_get_xrefs|cross.?references|xrefs?\s+(?:to|from)'; Milestone = 'Analyzed cross-references'; Icon = '[XREFS]' },
        @{ Pattern = '(?i)mcp_ghidra_(?:rename_function|batch_rename)|function.*?renamed|renamed.*?function.*?to\s+(\w+)'; Milestone = 'Renamed function'; Icon = '[RENAME]' },
        @{ Pattern = '(?i)mcp_ghidra_set_function_prototype|prototype.*?set|set.*?prototype'; Milestone = 'Set function prototype'; Icon = '[PROTO]' },
        @{ Pattern = '(?i)mcp_ghidra_(?:rename_variables|batch_rename).*?variable|variable.*?renamed|renamed.*?(?:local|param)'; Milestone = 'Renamed variables'; Icon = '[VARS]' },
        @{ Pattern = '(?i)mcp_ghidra_(?:set_variable_type|batch_set_variable)|variable.*?type.*?set|set.*?type.*?(?:int|char|void|DWORD|struct)'; Milestone = 'Set variable types'; Icon = '[TYPES]' },
        @{ Pattern = '(?i)mcp_ghidra_set_plate_comment|plate\s*comment.*?(?:set|added|created)'; Milestone = 'Added plate comment'; Icon = '[PLATE]' },
        @{ Pattern = '(?i)mcp_ghidra_(?:set_decompiler_comment|batch_set_comments)|(?:inline|decompiler)\s*comment.*?(?:set|added)'; Milestone = 'Added inline comments'; Icon = '[COMMENT]' },
        @{ Pattern = '(?i)mcp_ghidra_(?:create_label|batch_create_labels)|label.*?(?:created|added)|created.*?label'; Milestone = 'Created labels'; Icon = '[LABEL]' },
        @{ Pattern = '(?i)mcp_ghidra_rename_global|global.*?renamed|DAT_.*?(?:renamed|->)'; Milestone = 'Renamed globals'; Icon = '[GLOBAL]' },
        @{ Pattern = '(?i)ordinal.*?(?:\d+|#\d+)|(?:resolved|looked up).*?ordinal'; Milestone = 'Resolved ordinals'; Icon = '[ORDINAL]' },
        @{ Pattern = '(?i)(?:100\s*[%/]|score.*?100|completeness.*?100)'; Milestone = 'Achieved 100% completeness'; Icon = '[100%]' }
    )
    
    foreach ($mp in $milestonePatterns) {
        if ($output -match $mp.Pattern) {
            $detail = ""
            # Extract additional detail from capture groups if available
            if ($Matches[1]) {
                $detail = " ($($Matches[1]))"
            }
            $milestones += @{
                Milestone = $mp.Milestone
                Icon = $mp.Icon
                Detail = $detail
            }
        }
    }
    
    return $milestones
}

function Test-WorkflowCompliance {
    param([string]$output, [string]$funcName, [float]$initialScore)
    
    $issues = @()
    
    # Check if MCP tools were actually called - look for evidence in the output
    # The output may contain tool call names OR evidence of actions taken
    $actionPatterns = @(
        'mcp_ghidra_',
        'renamed.*(to|=>)',
        'Renamed.*from.*to',
        'Function Renamed',
        'Prototype Set',
        'Variable.*Renamed',
        'Variable.*Typed',
        'Plate Comment',
        'Comments Added',
        'Labels Created',
        'Completeness Score.*100',
        'Score.*100/100',
        '100%'
    )
    
    $actionsTaken = $false
    foreach ($pattern in $actionPatterns) {
        if ($output -match $pattern) {
            $actionsTaken = $true
            break
        }
    }
    
    if (-not $actionsTaken) {
        $issues += "No MCP actions detected - may have only provided suggestions"
    }
    
    # Check for common anti-patterns (only if no actions were detected)
    if (-not $actionsTaken) {
        if ($output -match "(?i)(you should|you could|consider doing|I recommend|I suggest)") {
            $issues += "Output contains suggestions rather than actions taken"
        }
    }
    
    # Check if workflow steps were mentioned
    if ($output -notmatch "(?i)(decompil|variable|prototype|plate comment|hungarian)") {
        $issues += "Output doesn't mention key workflow elements"
    }
    
    return $issues
}

function Process-Function {
    param(
        [string]$funcName,
        [string]$address = "",
        [string]$programName = "",
        [string]$issues = ""
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host ""
    $displayName = if ($programName) { "${programName}::$funcName" } else { $funcName }
    if ($address) {
        Write-WorkerHost "=== $displayName @ $address ===" "Green"
    } else {
        Write-WorkerHost "=== $displayName ===" "Green"
    }

    Write-Log "Processing function: $displayName @ $address"

    # Switch to the correct program if needed
    if ($programName) {
        if (-not (Switch-GhidraProgram $programName)) {
            Write-WorkerHost "Failed to switch to program $programName, skipping function" "Red"
            $stopwatch.Stop()
            return $false
        }
    }
    
    # Validate prompt file exists (guard against deletion during a long run)
    if (-not (Test-Path $promptFile)) {
        Write-WorkerHost "ERROR: Prompt file not found at $promptFile" "Red"
        $stopwatch.Stop()
        return $false
    }
    
    # Build minimal user message (workflow is now sent via --system-prompt-file)
    # Include issues list if available so Claude knows what to fix
    $issuesSection = ""
    if ($issues) {
        $issuesSection = @"

**Known Issues (from completeness analysis):**
$($issues -replace '; ', "`n- ")

Focus on fixing these specific issues to reach 100% completeness.
"@
    }

    $userMessage = @"
Use the attached workflow document to document $funcName$(if ($address) { " at 0x$address" }).$issuesSection
"@
    
    $promptSize = [System.Text.Encoding]::UTF8.GetByteCount($userMessage)
    if (-not $Fast) {
        Write-Log "Prompt size: $promptSize bytes"
        if ($promptSize -gt $MAX_PROMPT_BYTES) {
            Write-WorkerHost "  WARNING: Large prompt ($promptSize bytes), may hit context limits" "Yellow"
            Write-Log "Large prompt warning: $promptSize bytes" "WARN"
        }
    }
    
    try {
        $modelInfo = if ($FullModelName) { "model $FullModelName" } else { "default model" }
        
        Write-Log "Invoking Claude for $funcName with $modelInfo"
        
        $retryCount = 0
        $backoffSeconds = 2
        $success = $false
        $output = ""
        
        while ($retryCount -lt $MaxRetries) {
            # Invoke Claude exactly like the fast working command:
            # echo "message" | claude --system-prompt-file "path" 2>&1
            # Temporarily unset CLAUDECODE so nested claude invocations are allowed
            $savedClaudeCode = $env:CLAUDECODE
            $env:CLAUDECODE = $null
            if ($FullModelName) {
                $output = echo $userMessage | claude --system-prompt-file $promptFile --model $FullModelName 2>&1
            } else {
                $output = echo $userMessage | claude --system-prompt-file $promptFile 2>&1
            }
            $exitCode = $LASTEXITCODE
            $env:CLAUDECODE = $savedClaudeCode
            
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
            # Extract output for analysis
            $outputStr = $output -join "`n"
            
            # Check for SKIP response first (function intentionally skipped by Claude)
            if ($outputStr -match "SKIP:\s*([^\n]+)(?:\n+Reason:\s*(.+))?") {
                $skipFunc = $Matches[1].Trim()
                $skipReason = if ($Matches[2]) { $Matches[2].Trim() } else { "No reason provided" }
                Write-WorkerHost "SKIPPED: $skipFunc" "Yellow"
                Write-WorkerHost "  Reason: $skipReason" "Yellow"
                Write-Log "Function $funcName intentionally skipped: $skipReason" "WARN"
                
                # Save output file with SKIP prefix
                $outputFile = Join-Path $outputDir "SKIP-$funcName-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
                $output | Out-File $outputFile -Encoding UTF8
                
                $checkpoint = @{
                    LastProcessed = $funcName
                    Address = $address
                    Timestamp = Get-Date -Format "o"
                    InitialScore = $score
                    Model = $Model
                    WorkerId = $WorkerId
                    Status = "Skipped"
                    SkipReason = $skipReason
                }
                $checkpoint | ConvertTo-Json | Set-Content $checkpointFile
                
                $stopwatch.Stop()
                Write-WorkerHost "Skipped in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s\" \"DarkGray\"
                return $true  # Still counts as successful (intentionally skipped)
            }
            
            Write-Log "Successfully processed $funcName"
            
            # Look for our concise DONE format first to get the new function name
            $newFuncName = $funcName  # Default to original name
            
            # Pattern 1: DONE with arrow format (e.g., "DONE: FUN_xxx → NewName")
            if ($outputStr -match "DONE:\s*(?:FUN_[a-fA-F0-9]+\s*[→\->]+\s*)?([A-Z][A-Za-z0-9_]+)") {
                $newFuncName = $Matches[1].Trim()
                Write-Host "  DONE: $newFuncName" -ForegroundColor Green
                
                # Try to extract score and changes from subsequent lines
                if ($outputStr -match "Score:\s*([^\n]+)") {
                    Write-Host "  Score: $($Matches[1].Trim())" -ForegroundColor Cyan
                }
                if ($outputStr -match "Changes:\s*([^\n]+)") {
                    $changesText = $Matches[1].Trim() -replace '[^\x00-\x7F]+', ' -> '
                    Write-Host "  Changes: $changesText" -ForegroundColor Gray
                }
            }
            # Pattern 2: Standard multi-line DONE format
            elseif ($outputStr -match "(?s)DONE:\s*([^`n]+)[`n]+Score:\s*([^`n]+)[`n]+Changes:\s*([^`n]+)") {
                $newFuncName = $Matches[1].Trim()
                # Sanitize arrow characters for readable console output
                $changesText = $Matches[3].Trim() -replace '[^\x00-\x7F]+', ' -> '
                Write-Host "  DONE: $newFuncName" -ForegroundColor Green
                Write-Host "  Score: $($Matches[2].Trim())" -ForegroundColor Cyan
                Write-Host "  Changes: $changesText" -ForegroundColor Gray
            } else {
                # Fallback: extract key info from verbose output
                if ($outputStr -match "Function.*?renamed.*?to.*?[`"']?([A-Z][A-Za-z0-9_]+)[`"']?") { 
                    $newFuncName = $Matches[1] 
                } elseif ($outputStr -match "rename_function.*?new_name.*?[`"']([A-Z][A-Za-z0-9_]+)[`"']") {
                    $newFuncName = $Matches[1]
                }
                $scoreMatch = "?"
                if ($outputStr -match "(\d+(?:\.\d+)?)\s*[%/]?\s*complete|complete[^\d]*(\d+(?:\.\d+)?)") {
                    $scoreMatch = if ($Matches[1]) { $Matches[1] } elseif ($Matches[2]) { $Matches[2] } else { "?" }
                }
                Write-Host "  Completed: $newFuncName (Score: $scoreMatch%)" -ForegroundColor Green
            }
            
            # MCP error detection: two-tier approach.
            # Fast check (always): single regex catches the most common failures.
            # Full scan (-D or -L only): 12 multiline patterns on large output is expensive.
            $fastMcpHit = $outputStr -match 'GhidraValidationError|mcp_ghidra_\w+\s+(?:failed|error)|tool\s+(?:call|invocation)\s+(?:failed|error)'
            if ($fastMcpHit) {
                Write-WorkerHost "  MCP ERROR detected (run with -D for details)" "Red"
                Write-Log "MCP error signal detected for ${funcName}" "ERROR"
            }
            if (-not $Fast -or $Diagnostic) {
                $mcpErrors = Get-McpErrors -output $outputStr
                if ($mcpErrors.Count -gt 0) {
                    Write-WorkerHost "  MCP ERRORS ($($mcpErrors.Count)):" "Red"
                    foreach ($err in $mcpErrors) {
                        Write-WorkerHost "    [$($err.Type)] $($err.Message)" "Red"
                        Write-Log "MCP Error for ${funcName}: [$($err.Type)] $($err.Message)" "ERROR"
                    }
                }
            }

            if (-not $Fast) {
                # Save output file named after the NEW function name (not FUN_xxx)
                $outputFile = Join-Path $outputDir "$newFuncName-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
                $output | Out-File $outputFile -Encoding UTF8
                Write-WorkerHost "  Output saved to: $outputFile" "Gray"

                # Display workflow milestones achieved
                $milestones = Get-WorkflowMilestones -output $outputStr
                if ($milestones.Count -gt 0) {
                    Write-WorkerHost "  WORKFLOW MILESTONES:" "Cyan"
                    foreach ($ms in $milestones) {
                        Write-WorkerHost "    $($ms.Icon) $($ms.Milestone)$($ms.Detail)" "Cyan"
                    }
                    Write-Log "Milestones for ${funcName}: $(($milestones | ForEach-Object { $_.Milestone }) -join ', ')"
                } else {
                    Write-WorkerHost "  WARNING: No workflow milestones detected" "Yellow"
                    Write-Log "No milestones detected for $funcName" "WARN"
                }
                
                $complianceIssues = Test-WorkflowCompliance -output $output -funcName $funcName -initialScore $score
                if ($complianceIssues.Count -gt 0) {
                    Write-WorkerHost "  WORKFLOW COMPLIANCE ISSUES:" "Yellow"
                    foreach ($issue in $complianceIssues) {
                        Write-WorkerHost "    - $issue" "Yellow"
                        Write-Log "Compliance issue for ${funcName}: $issue" "WARN"
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
            }
            
            $stopwatch.Stop()
            Write-WorkerHost "Completed in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s" "Cyan"
            Write-Log "Function $funcName completed in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) seconds"
            return $true
        } else {
            $stopwatch.Stop()
            Write-WorkerHost "Failed after $MaxRetries attempts ($([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s)" "Red"
            Write-Log "Failed to process $funcName after $MaxRetries attempts" "ERROR"

            # Show the tail of the output  -  enough context to diagnose without flooding the console.
            # In -Diagnostic mode show more lines; in default mode show just the last 5.
            $outputLines = ($output -join "`n") -split "`n" | Where-Object { $_ -match '\S' }
            $tailCount = if ($Diagnostic) { 20 } else { 5 }
            $tail = $outputLines | Select-Object -Last $tailCount
            Write-WorkerHost "  Last output ($tailCount lines):" "DarkGray"
            foreach ($line in $tail) {
                Write-WorkerHost "    $line" "DarkGray"
            }

            # Full output goes to log file when -Log is active
            Write-Log "Error output: $($output -join ' | ')" "ERROR"
            return $false
        }
    }
    catch {
        Write-WorkerHost "Exception in Process-Function ${funcName}: $($_.Exception.Message)" "Red"
        Write-Log "Unhandled exception processing ${funcName}: $($_.Exception.Message)`n$($_.ScriptStackTrace)" "ERROR"
        return $false
    }
}

function Start-Coordinator {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Starting Parallel Function Processor" -ForegroundColor Cyan
    Write-Host "Workers: $Workers" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Initialize context from todo file header (project folder, version)
    Initialize-TodoFileContext
    Write-Host ""

    # Clear stale locks from previous runs
    Clear-StaleLocks -MaxAgeMinutes $STALE_LOCK_MINUTES

    # Count pending functions - works with both old and new formats
    $content = Get-Content $todoFile
    $pending = $content | Where-Object { $_ -match '^\[ \] ' }

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
    if ($Subagent) { $commonArgs += " -Subagent" }
    if ($CompactPrompt) { $commonArgs += " -CompactPrompt" }
    if ($Log) { $commonArgs += " -Log" }
    if ($Diagnostic) { $commonArgs += " -Diagnostic" }
    if ($Profile)    { $commonArgs += " -Profile" }
    $commonArgs += " -SkipPreFlight"  # Coordinator already validated; workers skip redundant checks
    if ($Model) { $commonArgs += " -Model `"$Model`"" }
    $commonArgs += " -MaxRetries $MaxRetries"
    $commonArgs += " -DelayBetweenFunctions $DelayBetweenFunctions"
    $commonArgs += " -MinScore $MinScore"
    $commonArgs += " -MaxScore $MaxScore"
    if ($MaxFunctions -gt 0) { $commonArgs += " -MaxFunctions $MaxFunctions" }
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
        Start-Sleep -Milliseconds 250
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

            # Get current pending count - works with both old and new formats
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

function Invoke-PreFlight {
    <#
    .SYNOPSIS
        Validate runtime prerequisites before starting any processing.
    .DESCRIPTION
        Checks: GhidraServer URL format, claude CLI in PATH, Ghidra /health endpoint,
        and todo file existence. Exits with code 1 on any hard failure.
        Skip with -SkipPreFlight for CI environments that handle these externally.
    #>
    if ($SkipPreFlight) {
        Write-Log "Pre-flight checks skipped (-SkipPreFlight)"
        return
    }

    $failures = @()

    # 1. Validate GhidraServer URL format
    try {
        $uri = [System.Uri]$GhidraServer
        if ($uri.Scheme -notin @("http", "https")) {
            $failures += "GhidraServer '$GhidraServer' must use http:// or https://"
        }
    } catch {
        $failures += "GhidraServer '$GhidraServer' is not a valid URL: $($_.Exception.Message)"
    }

    # 2. Check claude CLI is available
    $claudeCmd = Get-Command "claude" -ErrorAction SilentlyContinue
    if (-not $claudeCmd) {
        $failures += "'claude' not found in PATH  -  install Claude CLI before running this script"
    }

    # 3. Ping Ghidra via /get_version (lightweight, always registered by the plugin)
    try {
        $ver = Invoke-RestMethod -Uri "$GhidraServer/get_version" -Method GET -TimeoutSec 5 -ErrorAction Stop
        Write-Log "Ghidra reachable: $($ver | ConvertTo-Json -Compress)"
    } catch {
        $failures += "Ghidra is not reachable at $GhidraServer - is the plugin running? ($($_.Exception.Message))"
    }

    # 4. Validate todo file (worker mode only  -  coordinator spawns workers that check this)
    if (-not $Coordinator -and -not (Test-Path $todoFile)) {
        $failures += "Todo file not found: $todoFile (use -TodoFilePath to specify an alternate path)"
    }

    if ($failures.Count -gt 0) {
        Write-Host ""
        Write-Host "=== PRE-FLIGHT FAILED ===" -ForegroundColor Red
        foreach ($msg in $failures) {
            Write-Host "  [FAIL] $msg" -ForegroundColor Red
        }
        Write-Host ""
        exit 1
    }

    Write-Log "Pre-flight checks passed"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if ($Help) { Show-Help }

# Cleanup mode - remove auto-generated Ghidra scripts
if ($CleanupScripts) {
    Invoke-CleanupScripts
    exit 0
}

# Re-evaluate mode - scan existing functions without Claude processing
if ($ReEvaluate) {
    Invoke-ReEvaluate
    exit 0
}

# Threshold picker mode - show popup to pick minimum completeness threshold
if ($PickThreshold) {
    Invoke-ThresholdFilter
    exit 0
}

Measure-Op "PreFlight" { Invoke-PreFlight }

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
$modelLog = if ($FullModelName) { $FullModelName } else { "(default)" }
Write-Log "Worker $WorkerId started with parameters: Reverse=$Reverse, Model=$modelLog, MinScore=$MinScore, MaxScore=$MaxScore, GhidraServer=$GhidraServer"

# Validate todo file exists
if (-not (Test-Path $todoFile)) {
    Write-WorkerHost "ERROR: Todo file not found at $todoFile" "Red"
    Write-Log "Todo file not found: $todoFile" "ERROR"
    exit 1
}

# Initialize context from todo file header (project folder, version)
Initialize-TodoFileContext

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

# Binary processing order  -  lower index = higher priority (processed first)
# Load from -BinaryOrderFile if provided (one binary name per line, # comments allowed)
# Falls back to the built-in Diablo2/PD2 order when no file is specified
if ($BinaryOrderFile -and (Test-Path $BinaryOrderFile)) {
    Write-Host "Loading binary order from: $BinaryOrderFile" -ForegroundColor Cyan
    $BINARY_ORDER = Get-Content $BinaryOrderFile |
        Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } |
        ForEach-Object { $_.Trim() }
    Write-Host "  Loaded $($BINARY_ORDER.Count) entries" -ForegroundColor Gray
} elseif ($BinaryOrderFile) {
    Write-Host "WARNING: -BinaryOrderFile '$BinaryOrderFile' not found, using built-in order" -ForegroundColor Yellow
    $BINARY_ORDER = @()
} else {
    $BINARY_ORDER = @()
}

if ($BINARY_ORDER.Count -eq 0) {
    # Built-in Diablo2 / Project Diablo 2 dependency order
    $BINARY_ORDER = @(
        "Storm.dll",              # 1  - Foundation
        "Fog.dll",                # 2  - Foundation
        "D2Lang.dll",             # 3  - Core Services
        "D2CMP.dll",              # 4  - Core Services
        "D2Common.dll",           # 5  - Game Foundation (CRITICAL)
        "D2Sound.dll",            # 6  - Subsystems
        "D2Win.dll",              # 7  - Subsystems
        "D2Gfx.dll",              # 8  - Subsystems
        "D2Gdi.dll",              # 9  - Subsystems
        "D2Net.dll",              # 10 - Subsystems
        "D2Multi.dll",            # 11 - High-Level
        "Bnclient.dll",           # 12 - Battle.net
        "D2MCPClient.dll",        # 13 - Battle.net
        "D2Game.dll",             # 14 - High-Level (Server)
        "D2Client.dll",           # 15 - High-Level (Client)
        "D2DDraw.dll",            # 16 - Render Backend
        "D2Direct3D.dll",         # 17 - Render Backend
        "D2Glide.dll",            # 18 - Render Backend
        "D2Launch.dll",           # 24 - Entry Point
        "Game.exe",               # 25 - Entry Point
        "BH.dll",                 # 26 - Battle.net Helper
        "PD2_EXT.dll",            # 27 - PD2 Extensions
        "SGD2FreeRes.dll",        # 28 - PD2 Extensions
        "SGD2FreeDisplayFix.dll"  # 29 - PD2 Extensions
    )
}

function Get-BinaryPriority {
    param([string]$binaryName)
    $index = $BINARY_ORDER.IndexOf($binaryName)
    if ($index -ge 0) { return $index }
    return 9999  # Unknown binaries go last
}

function Get-FunctionsGroupedByBinary {
    <#
    .SYNOPSIS
        Parse todo file and group pending functions by binary/program.
    .DESCRIPTION
        Returns a hashtable where keys are program names and values are arrays
        of parsed function data. Programs are ordered by BINARY_ORDER priority.
        Uses a last-write-time cache so the file is only re-parsed when it actually
        changed on disk  -  eliminates redundant I/O in the hot loop.
    #>
    param([string]$todoFilePath = $todoFile)

    # Cache: skip re-parse if the file hasn't changed since the last call
    $item  = Get-Item $todoFilePath -ErrorAction SilentlyContinue
    $mtime = if ($item) { $item.LastWriteTimeUtc } else { $null }
    if ($script:TodoCacheMtime -and $mtime -and $mtime -eq $script:TodoCacheMtime -and $script:TodoCacheData) {
        return $script:TodoCacheData
    }

    $content = Get-Content $todoFilePath
    $pending = $content | Where-Object { $_ -match '^\[ \] ' }

    # Group functions by program
    $byProgram = @{}

    foreach ($line in $pending) {
        $parsed = Parse-TodoLine $line
        if (-not $parsed) { continue }
        if ($parsed.Status -ne ' ') { continue }

        # Apply score filter
        if ($parsed.Score -ne $null) {
            if ($parsed.Score -lt $MinScore -or $parsed.Score -gt $MaxScore) {
                continue
            }
        }

        $progName = if ($parsed.ProgramName) { $parsed.ProgramName } else { "_default_" }

        if (-not $byProgram.ContainsKey($progName)) {
            $byProgram[$progName] = @()
        }
        $byProgram[$progName] += $parsed
    }

    # Sort programs by binary order priority
    $orderedPrograms = $byProgram.Keys | Sort-Object { Get-BinaryPriority $_ }

    # If -Reverse flag, reverse the program order
    if ($Reverse) {
        [array]::Reverse($orderedPrograms)
    }

    $result = @{
        Programs = $orderedPrograms
        FunctionsByProgram = $byProgram
    }
    # Store in cache keyed by file mtime
    $script:TodoCacheMtime = $mtime
    $script:TodoCacheData  = $result
    return $result
}

# Main processing loop - processes one binary at a time
$processedCount = 0
$successCount = 0
$failCount = 0
$skipCount = 0
$currentBinaryProcessed = 0
$failedPrograms = [System.Collections.Generic.HashSet[string]]::new()

# Get initial grouping
$groupedData = Measure-Op "InitialTodoParse" { Get-FunctionsGroupedByBinary } -PassThru
$programQueue = [System.Collections.Generic.Queue[string]]::new([string[]]@($groupedData.Programs))

Write-WorkerHost "=== Binary Processing Order ===" "Cyan"
$totalPending = 0
foreach ($prog in $groupedData.Programs) {
    $count = $groupedData.FunctionsByProgram[$prog].Count
    $totalPending += $count
    $priority = Get-BinaryPriority $prog
    $priorityStr = if ($priority -lt 9999) { "Priority $($priority + 1)" } else { "Unranked" }
    Write-WorkerHost "  $prog : $count functions ($priorityStr)" "Gray"
}
Write-WorkerHost "  Total: $totalPending pending functions" "White"
Write-WorkerHost "" "White"

while ($programQueue.Count -gt 0 -or $script:CurrentProgram) {
    # Check for cancellation
    if ($processedCount -gt 0 -and (Test-Path "$lockDir\.stop")) {
        Write-WorkerHost "Stop signal detected, exiting..." "Yellow"
        break
    }

    # Refresh the grouped data to get latest state
    $groupedData = Measure-Op "TodoParse" { Get-FunctionsGroupedByBinary } -PassThru

    # If no pending functions in any program, we're done
    $totalRemaining = 0
    foreach ($prog in $groupedData.Programs) {
        $totalRemaining += $groupedData.FunctionsByProgram[$prog].Count
    }

    if ($totalRemaining -eq 0) {
        Write-WorkerHost "No more pending functions" "Green"
        break
    }

    # Pick the current binary to work on
    # Priority: continue with current if it has work, otherwise pick next in order
    $targetProgram = $null

    if ($script:CurrentProgram -and $groupedData.FunctionsByProgram.ContainsKey($script:CurrentProgram)) {
        $funcsInCurrent = $groupedData.FunctionsByProgram[$script:CurrentProgram]
        if ($funcsInCurrent.Count -gt 0) {
            $targetProgram = $script:CurrentProgram
        }
    }

    # If current program has no more work, find next program with work
    if (-not $targetProgram) {
        foreach ($prog in $groupedData.Programs) {
            # Skip programs that failed to switch
            if ($failedPrograms.Contains($prog)) { continue }
            if ($groupedData.FunctionsByProgram[$prog].Count -gt 0) {
                $targetProgram = $prog
                break
            }
        }
    }

    if (-not $targetProgram) {
        Write-WorkerHost "No more programs with pending functions" "Green"
        break
    }

    # Switch to target program if needed
    if ($targetProgram -ne "_default_" -and $targetProgram -ne $script:CurrentProgram) {
        $funcsInBinary = $groupedData.FunctionsByProgram[$targetProgram].Count
        Write-WorkerHost "" "White"
        Write-WorkerHost "=== Switching to $targetProgram ($funcsInBinary functions) ===" "Cyan"
        $currentBinaryProcessed = 0

        $switched = Measure-Op "SwitchProgram:$targetProgram" { Switch-GhidraProgram $targetProgram } -PassThru
        if (-not $switched) {
            Write-WorkerHost "Failed to switch to $targetProgram, skipping this binary" "Red"
            # Add to failed programs so we don't keep retrying
            [void]$failedPrograms.Add($targetProgram)
            continue
        }
    }

    # Get functions for the current binary
    $binaryFunctions = $groupedData.FunctionsByProgram[$targetProgram]

    if ($binaryFunctions.Count -eq 0) {
        continue
    }

    # Sort functions within binary by score (lowest first = most work needed)
    $sortedFunctions = $binaryFunctions | Sort-Object { $_.Score }

    # If reverse, process highest scores first within the binary
    if ($Reverse) {
        [array]::Reverse($sortedFunctions)
    }

    # Try to claim and process a function from this binary
    $claimed = $false
    $funcName = ""
    $address = ""
    $programName = ""
    $issues = ""

    # Add some randomization for workers to spread out within the binary
    $candidateFunctions = $sortedFunctions
    if ($Workers -gt 1) {
        # Take a batch and randomize within it to reduce lock contention
        $batchSize = [Math]::Min($FUNCTION_BATCH_SIZE, $sortedFunctions.Count)
        $batch = $sortedFunctions | Select-Object -First $batchSize
        $candidateFunctions = $batch | Get-Random -Count $batch.Count
    }

    foreach ($parsed in $candidateFunctions) {
        if (Measure-Op "ClaimFunction" { Try-ClaimFunction $parsed.FunctionName $parsed.Address $parsed.ProgramName } -PassThru) {
            $funcName = $parsed.FunctionName
            $address = $parsed.Address
            $programName = $parsed.ProgramName
            $issues = $parsed.Issues
            $claimed = $true
            break
        }
    }

    if (-not $claimed) {
        # All functions in this binary are claimed by other workers
        # Check if there are other binaries with unclaimed functions
        $otherBinaryHasWork = $false
        foreach ($prog in $groupedData.Programs) {
            if ($prog -eq $targetProgram) { continue }
            if ($groupedData.FunctionsByProgram[$prog].Count -gt 0) {
                $otherBinaryHasWork = $true
                break
            }
        }

        if ($otherBinaryHasWork) {
            # Move to next binary instead of waiting, but add to skipped set temporarily
            Write-WorkerHost "All functions in $targetProgram claimed, waiting 10s before checking other binaries..." "Gray"
            Start-Sleep -Seconds 10
            $script:CurrentProgram = $null  # Force re-evaluation
            continue
        } else {
            # All functions across all binaries are claimed, wait and retry
            Write-WorkerHost "All functions currently claimed, waiting 10s..." "Gray"
            Start-Sleep -Seconds 10
            continue
        }
    }

    try {
        # DryRun: show what would be processed without invoking Claude
        if ($DryRun) {
            Write-WorkerHost "  DRY RUN: Would process $funcName @ $address ($programName)" "Cyan"
            $processedCount++
            $currentBinaryProcessed++
            $successCount++
        } else {
            $result = Measure-Op "ProcessFunction:$funcName" { Process-Function $funcName $address $programName $issues } -PassThru

            $processedCount++
            $currentBinaryProcessed++

            # Handle array results - take the last value (the actual return)
            if ($result -is [array]) {
                $result = $result[-1]
            }

            # Check for string "skip" explicitly (PowerShell coerces types in -eq comparisons)
            if ($result -is [string] -and $result -eq "skip") {
                $skipCount++
                Measure-Op "UpdateTodo:skip" { Update-TodoFile $funcName "complete" $programName $address | Out-Null }
                Write-WorkerHost "  Skipped (outside score filter)" "Gray"
            } elseif ($result -eq $true) {
                $successCount++
                Measure-Op "UpdateTodo:complete" { Update-TodoFile $funcName "complete" $programName $address | Out-Null }
            } else {
                $failCount++
                Measure-Op "UpdateTodo:failed" { Update-TodoFile $funcName "failed" $programName $address | Out-Null }
            }
        }

        # Show progress summary with binary context
        $binaryRemaining = $binaryFunctions.Count - 1
        Write-WorkerHost "  [${targetProgram}: $currentBinaryProcessed done, $binaryRemaining left] [Total: $successCount success / $skipCount skipped / $failCount fail]" "DarkGray"

        # Periodically sweep for stale locks left by crashed workers
        if ($processedCount % 10 -eq 0) {
            Measure-Op "StaleLockSweep" { Clear-StaleLocks -MaxAgeMinutes $STALE_LOCK_MINUTES }
        }
    } finally {
        Release-FunctionLock $funcName $programName
    }

    if ($Single) { break }

    # Check if we've hit the max functions limit
    if ($MaxFunctions -gt 0 -and $processedCount -ge $MaxFunctions) {
        Write-WorkerHost "Reached MaxFunctions limit ($MaxFunctions), stopping worker." "Yellow"
        Write-Log "Stopped after processing $processedCount functions (MaxFunctions=$MaxFunctions)"
        break
    }

    if ($DelayBetweenFunctions -gt 0) {
        Start-Sleep -Milliseconds ($DelayBetweenFunctions * 1000)
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
if ($Log) { Write-WorkerHost "Log file: $logFile" "Gray" }
Write-WorkerHost "========================================" "Cyan"

# Print all collected errors/warnings so they're easy to find after a long run
if ($script:ErrorEvents.Count -gt 0) {
    Write-Host ""
    Write-Host "=== PROBLEMS THIS RUN ($($script:ErrorEvents.Count)) ===" -ForegroundColor Red
    foreach ($evt in $script:ErrorEvents) {
        Write-Host "  $evt" -ForegroundColor Red
    }
    Write-Host "========================================" -ForegroundColor Red
}

# Profile report  -  printed when -Profile is active
if ($Profile -and $script:Timings.Count -gt 0) {
    Write-Host ""
    Write-Host "=== PROFILE REPORT ===" -ForegroundColor Magenta

    # Aggregate by operation prefix (e.g. "ProcessFunction:*" -> "ProcessFunction")
    $agg = @{}
    foreach ($t in $script:Timings) {
        $key = ($t.Op -split ':')[0]
        if (-not $agg.ContainsKey($key)) {
            $agg[$key] = @{ Count = 0; TotalMs = 0.0; MaxMs = 0.0 }
        }
        $agg[$key].Count++
        $agg[$key].TotalMs += $t.Ms
        if ($t.Ms -gt $agg[$key].MaxMs) { $agg[$key].MaxMs = $t.Ms }
    }

    $totalMs = 0.0; foreach ($t in $script:Timings) { $totalMs += $t.Ms }
    Write-Host ("  {0,-30} {1,6} {2,10} {3,10} {4,8}" -f "Operation", "Calls", "Total(ms)", "Max(ms)", "% Time") -ForegroundColor Cyan
    Write-Host ("  {0}" -f ("-" * 70)) -ForegroundColor DarkGray

    $agg.GetEnumerator() | Sort-Object { $_.Value.TotalMs } -Descending | ForEach-Object {
        $pct = if ($totalMs -gt 0) { [Math]::Round($_.Value.TotalMs / $totalMs * 100, 1) } else { 0 }
        Write-Host ("  {0,-30} {1,6} {2,10} {3,10} {4,7}%" -f `
            $_.Key, $_.Value.Count,
            [Math]::Round($_.Value.TotalMs, 1),
            [Math]::Round($_.Value.MaxMs, 1),
            $pct)
    }

    Write-Host ("  {0}" -f ("-" * 70)) -ForegroundColor DarkGray
    Write-Host ("  {0,-30} {1,6} {2,10}" -f "TOTAL", $script:Timings.Count, [Math]::Round($totalMs, 1)) -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Magenta
}

Write-Log "Worker completed: $processedCount processed, $successCount successful, $skipCount skipped, $failCount failed"
Flush-LogBuffer  # Ensure all buffered logs are written

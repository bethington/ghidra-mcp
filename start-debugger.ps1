<#
.SYNOPSIS
    Start the standalone GhidraMCP debugger server (elevated).

.DESCRIPTION
    Runs `python -m debugger` from this repo's own venv. Exists as its own
    launcher (rather than inlining the command into the scheduled task
    action) for the same reason start-dashboard.ps1 does: a single, testable
    entry point that behaves identically whether invoked by hand or by the
    task.

    -Foreground is LOAD-BEARING, not a debugging leftover -- see
    install-debugger-scheduled-task.ps1's own note on this. Without it the
    launcher spawns python and exits immediately, so the scheduled task
    completes right away and never owns the running server; Stop-ScheduledTask
    then has nothing real to stop. Running it in the foreground keeps the
    server inside the task's own process tree.

.PARAMETER Port
    Debugger server port. Default 8099 (the project's own default).

.PARAMETER Foreground
    Run python -m debugger in this process and block until it exits, instead
    of spawning it detached. Used by the scheduled task; you would not
    normally pass this by hand.
#>
[CmdletBinding()]
param(
    [int]$Port = 8099,
    [switch]$Foreground
)

$ErrorActionPreference = 'Stop'
$Repo = $PSScriptRoot
$Python = Join-Path $Repo '.venv\Scripts\python.exe'

if (-not (Test-Path $Python)) {
    Write-Error "venv python not found: $Python  (run 'uv sync --group debugger' in $Repo)"
    exit 1
}

# Refuse to stack a second server on the same port -- mirrors
# start-dashboard.ps1's own port check, same rationale: a task pointing at an
# already-occupied port either fails confusingly or (worse) appears to
# succeed while talking to the wrong instance.
$listening = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($listening) {
    Write-Host "Debugger server already listening on port $Port -- not starting a second one."
    exit 0
}

$LogDir = Join-Path $Repo 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$Log = Join-Path $LogDir 'debugger-server.log'

if ($Foreground) {
    # The debugger server logs INFO lines to stderr. With ErrorActionPreference
    # 'Stop' (set above), PowerShell wraps each native-process stderr line as a
    # terminating ErrorRecord -- so the very first log line ("dbgeng COM
    # initialized...") killed the whole launcher before it ever attached to
    # anything. Relax to Continue for just this call so stderr is ordinary
    # output, not an abort signal.
    $ErrorActionPreference = 'Continue'
    & $Python -m debugger --port $Port *>> $Log
    exit $LASTEXITCODE
} else {
    Start-Process -FilePath $Python -ArgumentList "-m debugger --port $Port" `
        -WorkingDirectory $Repo -WindowStyle Hidden `
        -RedirectStandardOutput $Log -RedirectStandardError $Log
    Write-Host "Debugger server starting on port $Port (log: $Log)"
}

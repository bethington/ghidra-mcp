<#
.SYNOPSIS
    Start the fun-doc dashboard ELEVATED, which is what unattended oracle
    recovery requires.

.DESCRIPTION
    PD2 self-elevates (LaunchPD2-Oracle.bat), so a normal-integrity dashboard
    cannot `taskkill` a wedged Game.exe -- the kill comes back "Access is
    denied" and OracleHealthMonitor's auto-recovery stalls on a UAC prompt
    waiting for a human. Measured 2026-07-30: a D2 "Halt / Unrecoverable
    internal error" box left the game alive-but-dead, every live prove
    candidate short-circuited to oracle_unavailable, and a 12-worker fleet
    drained its pools into skips.

    Started this way, the first taskkill succeeds and recovery is fully
    unattended.

    Self-elevates via UAC if not already running elevated, so it is safe to
    launch from a normal shell. Logs rotate as logs/web_r<N>.{out,err}.log,
    continuing the existing numbering.

.PARAMETER Port
    Dashboard port. Default 5000.

.PARAMETER Foreground
    Run in this window instead of detaching. Useful for debugging startup.

.EXAMPLE
    ./fun-doc/start-dashboard.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 5000,
    [switch]$Foreground
)

$ErrorActionPreference = 'Stop'
$FunDoc = $PSScriptRoot
$Python = Join-Path $FunDoc '.venv\Scripts\python.exe'
$LogDir = Join-Path $FunDoc 'logs'

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- re-launch self elevated -------------------------------------------------
if (-not (Test-Elevated)) {
    Write-Host 'Not elevated -- requesting UAC so oracle auto-recovery can run unattended...'
    $self = $MyInvocation.MyCommand.Path
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$self`"",
        '-Port', $Port
    )
    if ($Foreground) { $argList += '-Foreground' }
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs
    } catch {
        Write-Error ("UAC was declined or unavailable. The dashboard was NOT started. " +
                     "Without elevation, recovery from a wedged game needs a manual " +
                     "UAC click -- see fun-doc/oracle_health.py.")
        exit 1
    }
    exit 0
}

# --- from here on we are ELEVATED, in a window that vanishes on exit ---------
# Everything below therefore logs to disk. An elevated relaunch that fails
# silently is indistinguishable from one that never ran (learned the hard way:
# the first run of this script died after the UAC prompt and took its own error
# message with it when the window closed).
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$BootLog = Join-Path $LogDir 'start-dashboard.log'
function Write-Boot([string]$msg) {
    "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))  $msg" |
        Add-Content -Path $BootLog -Encoding utf8
}
Write-Boot "--- elevated start requested (port $Port) ---"
trap {
    Write-Boot "FATAL: $_"
    Write-Boot $_.ScriptStackTrace
    exit 1
}

# --- preflight ---------------------------------------------------------------
if (-not (Test-Path $Python)) {
    Write-Boot "venv python not found: $Python"
    Write-Error "venv python not found: $Python  (run 'uv sync --group fun-doc' in fun-doc/)"
    exit 1
}
# Refuse to double-launch. The dashboard has its own single-instance guard, but
# a second process that loses the port race sits there half-alive and confusing;
# better to say so here.
$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
    Write-Boot "port $Port already listening (PID $($busy[0].OwningProcess)) -- refusing"
    Write-Error ("port $Port is already listening (PID $($busy[0].OwningProcess)) -- " +
                 "the dashboard is already running. Stop it first.")
    exit 1
}

# --- log rotation: continue the existing web_r<N> numbering ------------------
$next = 1
$existing = Get-ChildItem -Path $LogDir -Filter 'web_r*.out.log' -ErrorAction SilentlyContinue
if ($existing) {
    $nums = $existing | ForEach-Object {
        if ($_.BaseName -match '^web_r(\d+)\.out$') { [int]$Matches[1] } else { 0 }
    }
    if ($nums) { $next = (($nums | Measure-Object -Maximum).Maximum + 1) }
}
$outLog = Join-Path $LogDir "web_r$next.out.log"
$errLog = Join-Path $LogDir "web_r$next.err.log"

Write-Host "Starting fun-doc dashboard (elevated) on port $Port"
Write-Host "  stdout -> $outLog"
Write-Host "  stderr -> $errLog"

Push-Location $FunDoc
try {
    if ($Foreground) {
        & $Python 'fun_doc.py' '--web' '--web-port' $Port
    } else {
        # Redirect via Start-Process, NOT via `cmd /c "..."`. cmd strips the
        # outermost quote pair when the command both begins and ends with a
        # quote, which silently mangled the redirection into a broken command
        # line -- the process "spawned" and produced no log files at all. We
        # are already elevated here, so -Verb is not needed and
        # -RedirectStandard* is available.
        Write-Boot "launching: $Python fun_doc.py --web --web-port $Port"
        $proc = Start-Process -FilePath $Python `
            -ArgumentList 'fun_doc.py', '--web', '--web-port', $Port `
            -WorkingDirectory $FunDoc `
            -RedirectStandardOutput $outLog -RedirectStandardError $errLog `
            -WindowStyle Hidden -PassThru
        Write-Boot "spawned PID $($proc.Id); logs -> $outLog / $errLog"
        Write-Host "Started. Watch it come up with:  Get-Content -Wait `"$errLog`""
    }
} finally {
    Pop-Location
}

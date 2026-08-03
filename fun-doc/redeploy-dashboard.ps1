<#
.SYNOPSIS
    Restart the fun-doc dashboard to pick up code changes -- WITHOUT a UAC
    prompt in the normal case.

.DESCRIPTION
    The dashboard runs ELEVATED, because unattended oracle recovery has to be
    able to taskkill a self-elevated PD2 (see oracle_health.py). The awkward
    consequence: a normal shell cannot stop it. `Stop-Process` returns "Access
    is denied", so every code deploy used to need an interactive UAC click --
    the exact thing an unattended pipeline cannot wait on.

    Registering the Scheduled Task does NOT solve this on its own. That removes
    UAC from *starting* the dashboard; stopping an already-running elevated one
    still crosses a privilege boundary.

    So this script prefers, in order:

      1. POST /api/admin/restart -- the dashboard restarts ITSELF. It is
         already elevated, so the replacement it spawns inherits that token and
         no prompt appears. This is the normal path and needs no privileges
         here at all.
      2. Scheduled Task stop/start, if the task is registered AND owns the
         running instance.
      3. Elevated kill + relaunch (one UAC prompt) -- only when the dashboard
         is unreachable over HTTP, i.e. already wedged.

    If nothing is listening it just starts one.

.PARAMETER Port
    Dashboard port. Default 5000.

.PARAMETER TimeoutSec
    How long to wait for the dashboard to come back. Default 180.

.PARAMETER Force
    Skip the HTTP path and go straight to the elevated kill (UAC). For a
    dashboard that is listening but not responding.

.PARAMETER InstallTask
    While we are elevated anyway, also register the "FunDoc Dashboard"
    scheduled task. Piggy-backing costs nothing and makes the one unavoidable
    prompt do double duty -- worth doing on the FIRST redeploy, because a
    dashboard that predates /api/admin/restart cannot restart itself and that
    prompt is otherwise pure overhead.

.PARAMETER Pause
    Pause the worker fleet and WAIT for it to drain before restarting, then let
    the new instance come back paused. Use this for a code deploy while workers
    are running: without it the restart kills whatever candidate each worker
    happened to be mid-way through.

    The pause persists across the restart, so the fleet returns PARKED rather
    than either lost or immediately spending tokens. Click Resume (or POST
    /api/worker/resume) when ready.

.PARAMETER DrainTimeoutSec
    How long to wait for workers to park. Default 600. An in-flight provider
    call routinely runs several minutes; past the timeout the restart proceeds
    anyway and the orphaned candidate is re-admitted on the next pass.

.EXAMPLE
    ./fun-doc/redeploy-dashboard.ps1

.EXAMPLE
    ./fun-doc/redeploy-dashboard.ps1 -Pause

.EXAMPLE
    ./fun-doc/redeploy-dashboard.ps1 -InstallTask

.EXAMPLE
    ./fun-doc/redeploy-dashboard.ps1 -Force
#>
[CmdletBinding()]
param(
    [int]$Port = 5000,
    [int]$TimeoutSec = 180,
    [switch]$Force,
    [switch]$InstallTask,
    [switch]$Pause,
    [int]$DrainTimeoutSec = 600
)

$ErrorActionPreference = 'Stop'
$FunDoc = $PSScriptRoot
$Launcher = Join-Path $FunDoc 'start-dashboard.ps1'
$Base = "http://127.0.0.1:$Port"

function Invoke-PauseAndDrain {
    # Best-effort: an unreachable dashboard is exactly the case -Force handles,
    # and refusing to redeploy because the pause call failed would be worse than
    # redeploying without it.
    try {
        $body = @{ reason = 'dashboard redeploy'; drain = $true;
                   drain_timeout = $DrainTimeoutSec } | ConvertTo-Json
        Write-Host "[pause] parking workers (up to ${DrainTimeoutSec}s)..."
        $r = Invoke-RestMethod -Uri "$Base/api/worker/pause" -Method POST `
                -Body $body -ContentType 'application/json' `
                -TimeoutSec ($DrainTimeoutSec + 30)
        if ($r.drained) {
            Write-Host "[pause] all workers parked -- safe to restart."
        } else {
            Write-Warning "[pause] drain timed out; a candidate may be orphaned (non-terminal, re-admitted next pass)."
        }
    } catch {
        Write-Warning "[pause] could not pause before restart: $($_.Exception.Message)"
    }
}

if ($Pause) { Invoke-PauseAndDrain }

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ListenerPid {
    (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1).OwningProcess
}

function Wait-Healthy([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-RestMethod -Uri "$Base/api/health/all" -TimeoutSec 5
            if ($r.ok) { return $true }
        } catch { }
        Start-Sleep -Seconds 3
    }
    return $false
}

# Wait for the LISTENER PID to actually change, then for the new one to answer.
#
# A fixed sleep is not enough and gave a false negative that made things worse:
# /api/admin/restart stops the workers FIRST (stop_timeout 45s), so with a few
# port workers running the old process is still up and perfectly healthy five
# seconds later. The old flow slept 5s, saw a healthy dashboard on the SAME
# pid, declared "the PID did not change", and fell through to the scheduled
# task -- firing a second restart on top of one already in flight, and
# reporting a version that had not been deployed yet.
function Wait-PidChange([int]$Seconds, $OldPid) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $now = Get-ListenerPid
        if ($now -and $now -ne $OldPid) { return $now }
        Start-Sleep -Seconds 2
    }
    return $null
}

$before = Get-ListenerPid

if ($InstallTask) { $Force = $true }   # task registration needs elevation anyway

if (-not $before) {
    Write-Host "Nothing listening on $Port -- starting a dashboard."
    if ($InstallTask) {
        & (Join-Path $FunDoc 'install-scheduled-task.ps1') -Port $Port -StartNow
    } else {
        & $Launcher -Port $Port
    }
    if (Wait-Healthy $TimeoutSec) { Write-Host "Dashboard is up." ; exit 0 }
    Write-Error "Dashboard did not come up within ${TimeoutSec}s."
    exit 1
}

Write-Host "Dashboard is running (PID $before)."

# --- path 1: ask it to restart itself (no UAC) --------------------------------
if (-not $Force) {
    try {
        $resp = Invoke-RestMethod -Uri "$Base/api/admin/restart" -Method Post -TimeoutSec 15
        if ($resp.ok) {
            Write-Host "Self-restart accepted (no elevation needed). Waiting..."
            # It stops workers first (stop_timeout 45s), so the handover can be
            # well over a minute with a busy fleet. Watch the PID, not the clock.
            $after = Wait-PidChange ($TimeoutSec + 60) $before
            if ($after) {
                if (Wait-Healthy $TimeoutSec) {
                    Write-Host "Dashboard restarted (PID $before -> $after)."
                    exit 0
                }
                Write-Warning "New dashboard (PID $after) bound the port but never answered."
            } else {
                Write-Warning "Dashboard never released the port; PID is still $before."
            }
        }
    } catch {
        Write-Warning "Self-restart unavailable ($($_.Exception.Message))."
        Write-Warning "That is expected if the RUNNING dashboard predates /api/admin/restart."
    }
}

# --- path 2: scheduled task ---------------------------------------------------
$task = Get-ScheduledTask -TaskName 'FunDoc Dashboard' -ErrorAction SilentlyContinue
if ($task -and -not $Force) {
    try {
        Write-Host "Trying the scheduled task..."
        $beforeTask = Get-ListenerPid
        Stop-ScheduledTask  -TaskName 'FunDoc Dashboard' -ErrorAction Stop
        Start-Sleep -Seconds 3
        Start-ScheduledTask -TaskName 'FunDoc Dashboard' -ErrorAction Stop
        # Same trap as path 1: "it answers" is not "it restarted". This path
        # used to report success purely on Wait-Healthy, so a task that failed
        # to take over the port announced a deploy that had not happened.
        $afterTask = Wait-PidChange $TimeoutSec $beforeTask
        if ($afterTask -and (Wait-Healthy $TimeoutSec)) {
            Write-Host "Dashboard restarted via scheduled task (PID $beforeTask -> $afterTask)."
            exit 0
        }
        Write-Warning "Scheduled task did not take over the port (PID still $beforeTask)."
    } catch {
        Write-Warning "Scheduled-task restart failed ($($_.Exception.Message))."
    }
}

# --- path 3: elevated kill + relaunch (ONE UAC prompt) ------------------------
Write-Host ""
Write-Host "Falling back to an elevated restart -- this needs ONE UAC approval."
$pidNow = Get-ListenerPid
if (-not $pidNow) {
    & $Launcher -Port $Port
} else {
    $installLine = ''
    if ($InstallTask) {
        $installLine = "& '$(Join-Path $FunDoc 'install-scheduled-task.ps1')' -Port $Port"
    }
    $inner = @"
Stop-Process -Id $pidNow -Force -ErrorAction SilentlyContinue
for (`$i = 0; `$i -lt 60; `$i++) {
    if (-not (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 500
}
$installLine
# Start through the TASK when one is registered: its action runs the launcher
# in-foreground, so the dashboard lands inside the task's process tree and
# future Stop/Start-ScheduledTask actually control it -- that is the no-UAC
# restart path. Starting the launcher directly here would detach it again and
# leave the task owning nothing.
if (Get-ScheduledTask -TaskName 'FunDoc Dashboard' -ErrorAction SilentlyContinue) {
    Start-ScheduledTask -TaskName 'FunDoc Dashboard'
} else {
    & '$Launcher' -Port $Port
}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    try {
        Start-Process powershell -Verb RunAs -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
    } catch {
        Write-Error "UAC was declined. The dashboard was NOT restarted."
        exit 1
    }
    # Start-Process -Verb RunAs is ASYNCHRONOUS, and -Wait cannot be used with
    # it reliably here. Without waiting for the OLD pid to go first, Wait-Healthy
    # immediately answers "healthy" from the process we are trying to replace
    # and the script reports a successful restart that never happened -- it
    # printed "PID 367556 -> 367556" on 2026-07-31 and the operator reasonably
    # believed the deploy was live.
    Write-Host "Waiting for PID $pidNow to exit..."
    $goneBy = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $goneBy -and (Get-Process -Id $pidNow -ErrorAction SilentlyContinue)) {
        Start-Sleep -Milliseconds 500
    }
    if (Get-Process -Id $pidNow -ErrorAction SilentlyContinue) {
        Write-Error "PID $pidNow is still running -- UAC was likely declined. NOT restarted."
        exit 1
    }
}

if (Wait-Healthy $TimeoutSec) {
    $after = Get-ListenerPid
    if ($after -eq $before) {
        Write-Error "Dashboard is healthy but still PID $before -- the restart did NOT happen."
        exit 1
    }
    Write-Host "Dashboard restarted (PID $before -> $after)."
    exit 0
}
Write-Error "Dashboard did not come back within ${TimeoutSec}s. Check fun-doc/logs/."
exit 1

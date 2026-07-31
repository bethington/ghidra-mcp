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

.EXAMPLE
    ./fun-doc/redeploy-dashboard.ps1

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
    [switch]$InstallTask
)

$ErrorActionPreference = 'Stop'
$FunDoc = $PSScriptRoot
$Launcher = Join-Path $FunDoc 'start-dashboard.ps1'
$Base = "http://127.0.0.1:$Port"

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
            # It stops workers first, so allow for that before it drops the port.
            Start-Sleep -Seconds 5
            if (Wait-Healthy $TimeoutSec) {
                $after = Get-ListenerPid
                if ($after -and $after -ne $before) {
                    Write-Host "Dashboard restarted (PID $before -> $after)."
                    exit 0
                }
                # Same PID means it never actually went down.
                Write-Warning "Dashboard answered but the PID did not change ($after)."
            } else {
                Write-Warning "Dashboard did not come back within ${TimeoutSec}s."
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
        Stop-ScheduledTask  -TaskName 'FunDoc Dashboard' -ErrorAction Stop
        Start-Sleep -Seconds 3
        Start-ScheduledTask -TaskName 'FunDoc Dashboard' -ErrorAction Stop
        if (Wait-Healthy $TimeoutSec) { Write-Host "Dashboard restarted via scheduled task." ; exit 0 }
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

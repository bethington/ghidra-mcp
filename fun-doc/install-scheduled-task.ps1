<#
.SYNOPSIS
    Register (or refresh) the Scheduled Task that keeps the fun-doc dashboard
    running elevated, across logon and across crashes.

.DESCRIPTION
    The dashboard is the single point of failure for the whole unattended
    pipeline: it hosts the oracle health monitor, the Ghidra health monitor,
    the worker fleet and the roster. If it dies, nothing else recovers --
    including the things whose entire job is recovery.

    start-dashboard.ps1 remains the manual entry point and still self-elevates
    via UAC. This task is the unattended one, and it is better in one specific
    way that matters at 3am: a task registered with "Run with highest
    privileges" starts ELEVATED WITH NO UAC PROMPT. The self-elevating script
    cannot do that -- from a non-elevated shell it must ask, and an unattended
    restart that stops on a consent dialog has not restarted.

    Why elevation is load-bearing and not a nicety: PD2 self-elevates
    (LaunchPD2-Oracle.bat), so a normal-integrity dashboard cannot taskkill a
    wedged Game.exe. The kill returns "Access is denied" and unattended oracle
    recovery stalls waiting for a human. See oracle_health.py.

    Deliberately an INTERACTIVE task (-LogonType Interactive), not SYSTEM or
    S4U. Session 0 has no desktop, and recovery has to launch Game.exe and
    dismiss its error dialog on the real one. A task that "runs whether the
    user is logged on or not" would come up in a session where the game
    cannot render -- healthy by every check this repo makes, and useless.

    Idempotent: re-running replaces the registration in place. It never starts
    a second dashboard -- start-dashboard.ps1 refuses when the port is already
    listening.

.PARAMETER Port
    Dashboard port. Default 5000. Must match what you browse to.

.PARAMETER TaskName
    Scheduled Task name. Default "FunDoc Dashboard".

.PARAMETER RestartCount
    Automatic restarts after an unexpected exit. Default 3.

.PARAMETER RestartIntervalMinutes
    Gap between those restarts. Default 2.

.PARAMETER Remove
    Unregister the task and exit.

.PARAMETER StartNow
    Also start the task immediately after registering.

.EXAMPLE
    ./fun-doc/install-scheduled-task.ps1 -StartNow

.EXAMPLE
    ./fun-doc/install-scheduled-task.ps1 -Remove
#>
[CmdletBinding()]
param(
    [int]$Port = 5000,
    [string]$TaskName = 'FunDoc Dashboard',
    [int]$RestartCount = 3,
    [int]$RestartIntervalMinutes = 2,
    [switch]$Remove,
    [switch]$StartNow
)

$ErrorActionPreference = 'Stop'
$FunDoc = $PSScriptRoot
$Launcher = Join-Path $FunDoc 'start-dashboard.ps1'

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Registering a highest-privileges task is itself a privileged operation.
if (-not (Test-Elevated)) {
    Write-Host 'Not elevated -- requesting UAC to register the scheduled task...'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
                 '-Port', $Port, '-TaskName', "`"$TaskName`"",
                 '-RestartCount', $RestartCount,
                 '-RestartIntervalMinutes', $RestartIntervalMinutes)
    if ($Remove)   { $argList += '-Remove' }
    if ($StartNow) { $argList += '-StartNow' }
    try {
        $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -PassThru -Wait
        exit $p.ExitCode
    } catch {
        Write-Error 'UAC was declined. The scheduled task was NOT registered.'
        exit 1
    }
}

if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "No scheduled task named '$TaskName' -- nothing to remove."
    }
    exit 0
}

if (-not (Test-Path $Launcher)) {
    Write-Error "launcher not found: $Launcher"
    exit 1
}

# Fail here rather than at 3am: a task pointing at a missing venv registers
# fine and only reveals itself as a silent no-op when you need it.
$Python = Join-Path $FunDoc '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) {
    Write-Error "venv python not found: $Python  (run 'uv sync --group fun-doc' in fun-doc/)"
    exit 1
}

$identity = "$env:USERDOMAIN\$env:USERNAME"

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    # -WindowStyle Hidden so a logon-triggered start does not park a console
    # on the desktop. The launcher logs to logs/start-dashboard.log, so nothing
    # is lost by hiding it.
    #
    # -Foreground is load-bearing, not a debugging leftover. Without it the
    # launcher SPAWNS python and exits, so the task completes immediately and
    # never owns the running dashboard -- `Stop-ScheduledTask` then has nothing
    # to stop and reports success while the dashboard keeps running (observed
    # 2026-07-31, which is why a redeploy still needed an elevated kill).
    # Running it in the foreground makes the dashboard part of the task's
    # process tree, so Stop/Start-ScheduledTask genuinely control it -- and
    # that is the whole no-UAC restart path.
    '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Port {1} -Foreground' -f $Launcher, $Port
) -WorkingDirectory $FunDoc

# At logon covers reboots. The task is also the thing you start by hand after
# an intentional stop, which is what -StartNow / Start-ScheduledTask are for.
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity

# Interactive + Highest: elevated, on the real desktop, no consent prompt.
$principal = New-ScheduledTaskPrincipal -UserId $identity `
    -LogonType Interactive -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount $RestartCount `
    -RestartInterval (New-TimeSpan -Minutes $RestartIntervalMinutes) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -MultipleInstances IgnoreNew

# ExecutionTimeLimit 0 = no limit. The default is 3 DAYS, after which the
# Scheduler kills the task -- which for a long-lived dashboard is a silent
# death with no crash and no log entry, the hardest kind to diagnose.
# MultipleInstances IgnoreNew is a second guard against stacking dashboards,
# on top of the port check inside start-dashboard.ps1.

$desc = ("Keeps the fun-doc dashboard running elevated on port {0}. " -f $Port) +
        'Elevated so unattended oracle recovery can close a wedged, ' +
        'self-elevated PD2 without a UAC prompt. Interactive logon type ' +
        'because recovery must launch Game.exe on the real desktop.'

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "Replacing existing scheduled task '$TaskName'..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description $desc | Out-Null

Write-Host ""
Write-Host "Registered scheduled task '$TaskName'."
Write-Host "  runs      : $Launcher -Port $Port"
Write-Host "  as        : $identity (Interactive, RunLevel=Highest -- no UAC prompt)"
Write-Host "  triggers  : at logon"
Write-Host "  on failure: up to $RestartCount restart(s), $RestartIntervalMinutes min apart"
Write-Host ""
Write-Host "Manage it with:"
Write-Host "  Start-ScheduledTask  -TaskName '$TaskName'"
Write-Host "  Stop-ScheduledTask   -TaskName '$TaskName'"
Write-Host "  Get-ScheduledTaskInfo -TaskName '$TaskName'"
Write-Host "  ./fun-doc/install-scheduled-task.ps1 -Remove"

if ($StartNow) {
    $busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($busy) {
        Write-Host ""
        Write-Host "Port $Port is already listening (PID $($busy[0].OwningProcess)) -- " -NoNewline
        Write-Host "a dashboard is already running, not starting a second."
    } else {
        Start-ScheduledTask -TaskName $TaskName
        Write-Host ""
        Write-Host "Started. Watch it come up: Get-Content -Wait (Get-ChildItem '$FunDoc\logs\web_r*.err.log' | Sort-Object LastWriteTime | Select-Object -Last 1).FullName"
    }
}

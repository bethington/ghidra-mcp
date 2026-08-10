<#
.SYNOPSIS
    Register (or remove) a highest-privilege, on-demand scheduled task that
    runs the standalone GhidraMCP debugger server.

.DESCRIPTION
    Solves the same problem fun-doc/install-scheduled-task.ps1 solves for the
    dashboard: the debugger server must run elevated to attach to Game.exe
    (which runs elevated), but nobody wants a UAC prompt every single time
    the debugger is needed
    (memory: reference_debugger_server_needs_elevation).

    Registering a scheduled task is itself a privileged operation, so this
    script self-elevates ONCE via a single interactive UAC prompt. After
    that, starting the debugger server is `Start-ScheduledTask -TaskName
    'GhidraMCP Debugger Server'` (or `schtasks /run /tn "..."`) -- silent,
    no further prompts, ever.

    Deliberately its OWN task, separate from "FunDoc Dashboard" -- different
    lifecycle (on-demand vs always-on) and different failure domain; bundling
    them means a debugger crash takes down dashboard auto-restart bookkeeping
    and vice versa.

    Deliberately NO trigger (no -AtLogOn, nothing under Get-ScheduledTask
    .Triggers) -- the debugger server has no business running unless an
    agent or the user actually wants to attach to something. Registering
    with zero triggers leaves the task dormant until explicitly started;
    Task Scheduler is fine with a triggerless task, it just never fires on
    its own.

.PARAMETER Port
    Debugger server port. Default 8099.

.PARAMETER TaskName
    Scheduled task name. Default 'GhidraMCP Debugger Server'.

.PARAMETER Remove
    Unregister the task instead of creating it.

.PARAMETER StartNow
    After registering, immediately start the task once (useful for the
    first-ever run so you don't need a second manual Start-ScheduledTask).
#>
[CmdletBinding()]
param(
    [int]$Port = 8099,
    [string]$TaskName = 'GhidraMCP Debugger Server',
    [switch]$Remove,
    [switch]$StartNow
)

$ErrorActionPreference = 'Stop'
$Repo = $PSScriptRoot
$Launcher = Join-Path $Repo 'start-debugger.ps1'

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Registering a highest-privileges task is itself a privileged operation --
# this is the ONE UAC prompt. Everything after this block, forever, is silent.
if (-not (Test-Elevated)) {
    Write-Host 'Not elevated -- requesting UAC to register the scheduled task...'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
                 '-Port', $Port, '-TaskName', "`"$TaskName`"")
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

# From here on we're elevated.

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "Removing existing task '$TaskName'..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

if ($Remove) {
    Write-Host "Task '$TaskName' removed."
    exit 0
}

if (-not (Test-Path $Launcher)) {
    Write-Error "Launcher not found: $Launcher"
    exit 1
}

$Python = Join-Path $Repo '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) {
    Write-Error "venv python not found: $Python  (run 'uv sync --group debugger' in $Repo)"
    exit 1
}

$identity = "$env:USERDOMAIN\$env:USERNAME"

# -Foreground keeps python -m debugger inside THIS task's process tree, so
# Stop-ScheduledTask actually stops it instead of orphaning a detached
# process (same lesson as fun-doc's dashboard task).
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Port {1} -Foreground' -f $Launcher, $Port
) -WorkingDirectory $Repo

# No trigger: on-demand only. Task is created dormant.
$principal = New-ScheduledTaskPrincipal -UserId $identity `
    -LogonType Interactive -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action `
    -Principal $principal -Settings $settings `
    -Description 'On-demand elevated GhidraMCP debugger server (python -m debugger). Start with: Start-ScheduledTask -TaskName "GhidraMCP Debugger Server"' `
    | Out-Null

Write-Host "Task '$TaskName' registered (no auto-trigger -- start it with Start-ScheduledTask)."

if ($StartNow) {
    Write-Host "Starting '$TaskName' now..."
    Start-ScheduledTask -TaskName $TaskName
}

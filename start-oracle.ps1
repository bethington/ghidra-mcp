<#
  start-oracle.ps1 -- one-shot elevated launcher for the PD2-S12 conformance oracle.

  Does the privileged setup, then hands off to Claude:
    1. Self-elevates (a single UAC prompt).
    2. Ensures PD2 Game.exe is running (windowed), so D2Common is loaded.
    3. Injects ScyllaHide (HookLibraryx86) into Game.exe -- defeats the API-based
       anti-debug (IsDebuggerPresent / NtQueryInformationProcess / code-checksum
       breakpoint detection) so software breakpoints actually STICK. Setting
       breakpoints was the real pain point, and call_function itself relies on a
       return-catch breakpoint, so this matters.
    4. Starts the ghidra-mcp debugger server on :DEBUGGER_PORT with SeDebugPrivilege.

  ScyllaHide handles the API/breakpoint-detection anti-debug; the debugger's
  /debugger/pass_exceptions (Claude toggles it after attach) handles the separate
  INT3 exception flood. Both defend different tricks -- keep both.

  Config comes from .env in this folder (see .env.template):
    PD2_GAME_EXE    = C:\Diablo2\ProjectD2\Game.exe
    SCYLLAHIDE_DIR  = (default: this repo's tools\scyllahide)
    DEBUGGER_PORT   = 8099
  ...with sensible fallbacks, so .env is optional.

  Run in a normal (non-admin) PowerShell:
      powershell -ExecutionPolicy Bypass -File <repo>\start-oracle.ps1
#>
param(
    [switch]$NoGame,      # skip launching the game (you launch it yourself)
    [switch]$NoScylla,    # skip ScyllaHide (NOT recommended -- breakpoints may not stick)
    [string]$GameExe   = '',
    [string]$ScyllaDir = '',
    [int]   $Port      = 0
)
$ErrorActionPreference = 'Stop'
$Repo = $PSScriptRoot

# ---- config: param > .env > default ----
function Read-DotEnv([string]$p) {
    $h = @{}
    if (Test-Path $p) {
        foreach ($ln in Get-Content -LiteralPath $p) {
            $t = $ln.Trim()
            if ($t -and -not $t.StartsWith('#') -and $t.Contains('=')) {
                $i = $t.IndexOf('='); $h[$t.Substring(0, $i).Trim()] = $t.Substring($i + 1).Trim()
            }
        }
    }
    return $h
}
$dotenv = Read-DotEnv (Join-Path $Repo '.env')
function EnvOr([string]$key, [string]$def) {
    if ($dotenv.ContainsKey($key) -and $dotenv[$key]) { return $dotenv[$key] } else { return $def }
}
if (-not $GameExe)   { $GameExe   = EnvOr 'PD2_GAME_EXE'   'C:\Diablo2\ProjectD2\Game.exe' }
if (-not $ScyllaDir) { $ScyllaDir = EnvOr 'SCYLLAHIDE_DIR' (Join-Path $Repo 'tools\scyllahide') }
if (-not $Port)      { $Port      = [int](EnvOr 'DEBUGGER_PORT' '8099') }

# ---- self-elevate: relaunch as admin if we aren't already ----
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Requesting elevation -- approve the UAC prompt...' -ForegroundColor Yellow
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File', "`"$PSCommandPath`"")
    if ($NoGame)   { $a += '-NoGame' }
    if ($NoScylla) { $a += '-NoScylla' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    return
}

Write-Host '=== ELEVATED: PD2-S12 conformance oracle setup ===' -ForegroundColor Green
Write-Host ("  game={0}  scylla={1}  port={2}" -f $GameExe, $ScyllaDir, $Port)

function Get-Game { Get-Process -Name 'Game' -ErrorAction SilentlyContinue | Select-Object -First 1 }

# ---- 1. ensure Game.exe is running ----
$game = Get-Game
if ($game) {
    Write-Host ("Game.exe already running (PID {0})." -f $game.Id)
} elseif (-not $NoGame) {
    Write-Host ("Launching {0} -w ..." -f $GameExe)
    Start-Process -FilePath $GameExe -ArgumentList '-w' -WorkingDirectory (Split-Path $GameExe)
    Write-Host '  Waiting for the game process...'
    for ($i = 0; $i -lt 25 -and -not $game; $i++) { Start-Sleep 1; $game = Get-Game }
} else {
    Write-Host 'Skipping game launch (-NoGame). PD2 must be running before injection/attach.' -ForegroundColor Cyan
}

# ---- 2. inject ScyllaHide (so breakpoints stick) ----
if (-not $NoScylla) {
    $inj  = Join-Path $ScyllaDir 'InjectorCLIx86.exe'
    $hook = Join-Path $ScyllaDir 'HookLibraryx86.dll'
    if (-not $game) {
        Write-Host 'No Game.exe process -- cannot inject ScyllaHide. Launch PD2, then re-run (or -NoScylla).' -ForegroundColor Red
    } elseif (-not (Test-Path $inj) -or -not (Test-Path $hook)) {
        Write-Host ("ScyllaHide not found under {0} -- set SCYLLAHIDE_DIR in .env, pass -ScyllaDir, or -NoScylla." -f $ScyllaDir) -ForegroundColor Red
    } else {
        Write-Host ("Injecting ScyllaHide (HookLibraryx86) into Game.exe PID {0}..." -f $game.Id)
        Push-Location $ScyllaDir   # cwd so InjectorCLI reads scylla_hide.ini
        # pipe a keystroke so InjectorCLI's 'press any key' can't hang the launcher
        & cmd /c ('echo.| "{0}" pid:{1} "{2}"' -f $inj, $game.Id, $hook) 2>&1 | ForEach-Object { Write-Host "  $_" }
        Pop-Location
        Write-Host '  If injection failed: run PD2 windowed (not exclusive fullscreen) and retry.' -ForegroundColor Cyan
    }
} else {
    Write-Host 'Skipping ScyllaHide (-NoScylla) -- breakpoints may be detected/stripped by PD2 anti-debug.' -ForegroundColor Yellow
}
Write-Host '  -> Bring PD2 to the MAIN MENU (D2Common loads there); keep the window focused during capture.' -ForegroundColor Cyan

# ---- 3. ensure pybag, then start the debugger server on :$Port ----
$py = Join-Path $Repo '.venv\Scripts\python.exe'
if (-not (Test-Path $py)) { throw "venv python not found at $py" }
& $py -m pip show pybag *> $null
if ($LASTEXITCODE -ne 0) { Write-Host 'Installing pybag 2.2.16 ...'; & $py -m pip install pybag==2.2.16 }

function Test-Server { param($p)
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$p/debugger/status" -TimeoutSec 2 | Out-Null; return $true }
    catch { return $false }
}

if (Test-Server $Port) {
    Write-Host ":$Port debugger server already running." -ForegroundColor Green
} else {
    Write-Host ("Starting debugger server on :{0} (its own window)..." -f $Port)
    Start-Process -FilePath $py -ArgumentList '-m','debugger.server','--port',"$Port" -WorkingDirectory $Repo
    $up = $false
    for ($i = 0; $i -lt 20; $i++) { Start-Sleep 1; if (Test-Server $Port) { $up = $true; break } }
    if (-not $up) {
        Write-Host ("=== debugger server not responding on :{0} -- check its window for errors ===" -f $Port) -ForegroundColor Red
        Read-Host 'Press Enter to close'; return
    }
}

Write-Host ''
Write-Host ("=== READY. :{0} up (SeDebugPrivilege); ScyllaHide injected. ===" -f $Port) -ForegroundColor Green
Write-Host 'Leave the debugger-server window OPEN. Get PD2 to the main menu, then tell Claude to attach.'
Write-Host ''
Read-Host 'This setup window can be closed with Enter (game + server keep running)'

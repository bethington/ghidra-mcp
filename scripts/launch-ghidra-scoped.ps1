#!/usr/bin/env pwsh
# launch-ghidra-scoped.ps1
#
# Launches Ghidra with the GHIDRA_MCP_PROJECT_FOLDER env var set to scope
# all MCP getProgram() calls to a specific project folder. Use this for
# focused work on one binary set (e.g. a D2 mod) so accidental wrong-folder
# program references get rejected at the plugin layer instead of silently
# writing to the wrong binary.
#
# Default scope is /Mods/PD2-S12 (the diablo2 PD2 Season 12 mod folder).
# Override with -Scope or by setting $env:GHIDRA_MCP_PROJECT_FOLDER yourself
# before invoking ghidraRun.bat.
#
# Do NOT use this wrapper for deploy/benchmark runs — the regression suite
# operates on /testing/benchmark/* which would be rejected by the scope guard.
# Plain `ghidraRun.bat` (no env var) keeps the default unscoped behavior.

param(
    [string]$GhidraPath = "F:\ghidra_12.1_PUBLIC",
    [string]$Scope      = "/Mods/PD2-S12"
)

$ghidraRun = Join-Path $GhidraPath "ghidraRun.bat"
if (-not (Test-Path $ghidraRun)) {
    Write-Error "ghidraRun.bat not found at $ghidraRun"
    exit 1
}

$env:GHIDRA_MCP_PROJECT_FOLDER = $Scope
Write-Host "Launching Ghidra with project-folder scope: $Scope" -ForegroundColor Green
Write-Host "  ghidraRun: $ghidraRun"
Write-Host "  All MCP getProgram() calls will reject paths outside this scope."
Write-Host ""
& $ghidraRun

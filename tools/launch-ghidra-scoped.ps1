#!/usr/bin/env pwsh
# launch-ghidra-scoped.ps1
#
# Launches Ghidra with the GHIDRA_MCP_PROJECT_FOLDER env var set to scope
# all MCP getProgram() calls to a specific project folder. Use this for
# focused work on one binary set (e.g. one product version) so accidental
# wrong-folder program references get rejected at the plugin layer instead
# of silently writing to the wrong binary.
#
# Usage:
#   ./tools/launch-ghidra-scoped.ps1 -Scope /MyProduct/v1.0 -GhidraPath F:\ghidra_12.1.4_PUBLIC
#
# -Scope is required. -GhidraPath falls back to $env:GHIDRA_INSTALL_DIR,
# then $env:GHIDRA_PATH; there is no hard-coded default, because a stale
# version-stamped path silently starts the wrong Ghidra.
#
# Do NOT use this wrapper for deploy/benchmark runs — the regression suite
# operates on /testing/benchmark/* which would be rejected by the scope guard.
# Plain `ghidraRun.bat` (no env var) keeps the default unscoped behavior.

param(
    [Parameter(Mandatory = $true)]
    [string]$Scope,
    [string]$GhidraPath = $(if ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR } else { $env:GHIDRA_PATH })
)

if ([string]::IsNullOrWhiteSpace($GhidraPath)) {
    Write-Error "No Ghidra installation given. Pass -GhidraPath or set GHIDRA_INSTALL_DIR."
    exit 1
}

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

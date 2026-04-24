#Requires -Version 5.1

# Convenience runner for the Pester suite covering ghidra-mcp-setup.ps1.
# Installs Pester 5+ to CurrentUser scope when the bundled 3.4 is the only
# version available, then runs the suite with detailed output.

[CmdletBinding()]
param(
    [switch]$CI
)

$ErrorActionPreference = 'Stop'

$pesterMinVersion = [version]'5.5.0'
$installed = Get-Module -ListAvailable -Name Pester |
    Where-Object { [version]$_.Version -ge $pesterMinVersion } |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $installed) {
    Write-Host "Pester >= $pesterMinVersion not found. Installing to CurrentUser..." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module -Name Pester -MinimumVersion $pesterMinVersion `
        -Scope CurrentUser -Force -SkipPublisherCheck -AllowClobber
    $installed = Get-Module -ListAvailable -Name Pester |
        Where-Object { [version]$_.Version -ge $pesterMinVersion } |
        Sort-Object Version -Descending |
        Select-Object -First 1
}

$manifest = Get-ChildItem -LiteralPath $installed.ModuleBase -Filter 'Pester.psd1' -File |
    Select-Object -First 1
if (-not $manifest) { throw "Pester.psd1 not found under $($installed.ModuleBase)" }
Import-Module $manifest.FullName -Force

$config = New-PesterConfiguration
$config.Run.Path              = $PSScriptRoot
$config.Output.Verbosity      = 'Detailed'
$config.Run.Exit              = [bool]$CI
$config.TestResult.Enabled    = [bool]$CI
$config.TestResult.OutputPath = Join-Path $PSScriptRoot 'pester-results.xml'

Invoke-Pester -Configuration $config

# GhidraMCP Deployment Script
# Automatically builds, installs, and configures the GhidraMCP plugin
# Target: Ghidra 12.0.3

<#
.SYNOPSIS
Unified automation tool for GhidraMCP setup, build, deploy, and cleanup.

.DESCRIPTION
Provides a single PowerShell entry point for the common GhidraMCP workflows:
-SetupDeps, -BuildOnly, -Deploy, and -Clean.

Default behavior (no action specified) is -Deploy.

Version safety checks enforce consistency between:
- pom.xml ghidra.version
- -GhidraVersion (if provided)
- version inferred from -GhidraPath (if present)

.EXAMPLE
.\ghidra-mcp-setup.ps1 -Deploy -GhidraPath "C:\ghidra_12.0.3_PUBLIC"

.EXAMPLE
.\ghidra-mcp-setup.ps1 -SetupDeps -GhidraPath "C:\ghidra_12.0.3_PUBLIC"

.EXAMPLE
.\ghidra-mcp-setup.ps1 -BuildOnly

.EXAMPLE
.\ghidra-mcp-setup.ps1 -Help
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Alias("h", "?")]
    [switch]$Help = $false,
    [switch]$SetupDeps = $false,
    [switch]$BuildOnly = $false,
    [switch]$Deploy = $false,
    [switch]$Clean = $false,
    [switch]$Preflight = $false,
    [switch]$StrictPreflight = $false,
    [string]$GhidraPath = "",
    [string]$GhidraVersion = "",
    [switch]$SkipBuild = $false,
    [switch]$SkipRestart = $false,
    [switch]$NoAutoPrereqs = $false,
    [switch]$DryRun = $false,
    [switch]$Force = $false
)

# Color output functions
function Write-LogSuccess { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-LogInfo { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-LogWarning { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-LogError { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

# Configuration
$DefaultGhidraVersion = "12.0.3"
$PluginVersion = "2.0.0"

function Show-Usage {
    Write-Host ""
    Write-Host "GhidraMCP Setup - Usage" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Actions (choose one):"
    Write-Host "  -SetupDeps       Install required Ghidra JARs into local Maven repository (Maven deps only)"
    Write-Host "  -BuildOnly       Build project artifacts only"
    Write-Host "  -Deploy          Full end-user flow: Python deps + Maven deps + build + deploy"
    Write-Host "  -Clean           Remove build output, local extension cache, and local Ghidra Maven jars"
    Write-Host "  -Preflight       Validate environment and prerequisites without making changes"
    Write-Host ""
    Write-Host "Common options:"
    Write-Host "  -GhidraPath      Path to Ghidra install (e.g., C:\ghidra_12.0.3_PUBLIC)"
    Write-Host "  -GhidraVersion   Explicit Ghidra version (must match pom.xml/path version)"
    Write-Host "  -StrictPreflight Fail preflight on network checks (Maven Central/PyPI reachability)"
    Write-Host "  -NoAutoPrereqs   Disable automatic prerequisite setup during deploy"
    Write-Host "  -SkipBuild       Deploy existing artifact without rebuilding"
    Write-Host "  -SkipRestart     Do not restart Ghidra after deployment"
    Write-Host "  -Force           Reinstall dependencies even if already present"
    Write-Host "  -DryRun          Print actions without executing commands"
    Write-Host "  -Verbose         Verbose logging"
    Write-Host "  -WhatIf          Preview changes without executing state-changing operations"
    Write-Host "  -Confirm         Prompt for confirmation before state-changing operations"
    Write-Host "  -Help            Show this help text"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\ghidra-mcp-setup.ps1 -Deploy -GhidraPath 'C:\ghidra_12.0.3_PUBLIC'"
    Write-Host "  .\ghidra-mcp-setup.ps1 -SetupDeps -GhidraPath 'C:\ghidra_12.0.3_PUBLIC'"
    Write-Host "  .\ghidra-mcp-setup.ps1 -Preflight -GhidraPath 'C:\ghidra_12.0.3_PUBLIC'"
    Write-Host "  .\ghidra-mcp-setup.ps1 -BuildOnly"
    Write-Host "  .\ghidra-mcp-setup.ps1 -Clean"
    Write-Host ""
    Write-Host "Tip: For comment-based help, run: Get-Help .\ghidra-mcp-setup.ps1 -Detailed"
    Write-Host ""
}

if ($Help) {
    Show-Usage
    exit 0
}

function Get-PomGhidraVersion {
    $pomPath = Join-Path $PSScriptRoot "pom.xml"
    if (-not (Test-Path $pomPath)) {
        return $null
    }

    try {
        [xml]$pom = Get-Content $pomPath
        $value = "$($pom.project.properties.'ghidra.version')".Trim()
        if ($value) { return $value }
        return $null
    } catch {
        return $null
    }
}

function Get-VersionFromGhidraProperties {
    param([string]$PathValue)
    if (-not $PathValue) { return $null }

    $propsPath = Join-Path $PathValue "Ghidra\application.properties"
    if (-not (Test-Path -LiteralPath $propsPath)) {
        return $null
    }

    try {
        $line = Get-Content -LiteralPath $propsPath | Where-Object {
            $_ -match '^\s*application\.version\s*='
        } | Select-Object -First 1

        if (-not $line) { return $null }

        $version = (($line -split '=', 2)[1]).Trim()
        if ($version) { return $version }
        return $null
    } catch {
        return $null
    }
}

function Get-VersionFromGhidraPath {
    param([string]$PathValue)
    if (-not $PathValue) { return $null }

    if ($PathValue -match 'ghidra_([0-9]+(?:\.[0-9]+){1,3})_PUBLIC') {
        return $Matches[1]
    }

    return $null
}

# Manual parameter-set style action selection
$actionCount = @($SetupDeps, $BuildOnly, $Deploy, $Clean, $Preflight) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
if ($actionCount -gt 1) {
    Write-LogError "Choose only one action: -SetupDeps, -BuildOnly, -Deploy, -Clean, or -Preflight."
    exit 1
}

# Load .env file if it exists (local environment config)
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim()
            if ($val) {
                [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
                Write-Verbose "Loaded from .env: $key"
            }
        }
    }
}

$pomGhidraVersion = Get-PomGhidraVersion
if (-not $GhidraVersion) {
    $envGhidraVersion = [System.Environment]::GetEnvironmentVariable("GHIDRA_VERSION", "Process")
    if ($envGhidraVersion) {
        $GhidraVersion = $envGhidraVersion.Trim()
    }
}
if (-not $GhidraVersion) {
    if ($pomGhidraVersion) {
        $GhidraVersion = $pomGhidraVersion
    } else {
        $GhidraVersion = $DefaultGhidraVersion
    }
}

if ($pomGhidraVersion -and $GhidraVersion -ne $pomGhidraVersion) {
    Write-LogError "Version mismatch: selected GhidraVersion '$GhidraVersion' does not match pom.xml ghidra.version '$pomGhidraVersion'."
    Write-LogInfo "Update pom.xml or pass matching -GhidraVersion."
    exit 1
}

# If GhidraPath not provided via parameter, try .env, then common locations
if (-not $GhidraPath) {
    $GhidraPath = [System.Environment]::GetEnvironmentVariable("GHIDRA_PATH", "Process")
}
if (-not $GhidraPath) {
    # Auto-detect from common installation paths
    $commonPaths = @(
        "C:\ghidra_${GhidraVersion}_PUBLIC",
        "$env:USERPROFILE\ghidra_${GhidraVersion}_PUBLIC",
        "$env:ProgramFiles\ghidra_${GhidraVersion}_PUBLIC",
        "D:\ghidra_${GhidraVersion}_PUBLIC",
        "F:\ghidra_${GhidraVersion}_PUBLIC"
    )
    foreach ($path in $commonPaths) {
        if (Test-Path "$path\ghidraRun.bat") {
            $GhidraPath = $path
            Write-LogInfo "Auto-detected Ghidra at: $GhidraPath"
            break
        }
    }
}

$pathGhidraVersion = Get-VersionFromGhidraProperties -PathValue $GhidraPath
if (-not $pathGhidraVersion) {
    $pathGhidraVersion = Get-VersionFromGhidraPath -PathValue $GhidraPath
}
if ($pathGhidraVersion -and $pathGhidraVersion -ne $GhidraVersion) {
    Write-LogError "Version mismatch: GhidraPath implies version '$pathGhidraVersion', but selected/pom version is '$GhidraVersion'."
    Write-LogInfo "Use a matching -GhidraPath or update pom.xml ghidra.version."
    exit 1
}

if (-not $GhidraPath -and ($SetupDeps -or -not $BuildOnly -and -not $Clean)) {
    Write-LogError "Ghidra installation not found."
    Write-LogInfo "Set GHIDRA_PATH in .env file, or pass -GhidraPath parameter:"
    Write-Host "  .\ghidra-mcp-setup.ps1 -Deploy -GhidraPath 'C:\path\to\ghidra_${GhidraVersion}_PUBLIC'"
    Write-Host ""
    Write-LogInfo "Or create a .env file from the template:"
    Write-Host "  Copy-Item .env.template .env"
    Write-Host "  # Edit .env and set GHIDRA_PATH"
    exit 1
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Magenta
Write-Host "  GhidraMCP Automation Script v2.0   " -ForegroundColor Magenta
Write-Host "  Target: Ghidra $GhidraVersion       " -ForegroundColor Magenta
Write-Host "======================================" -ForegroundColor Magenta
Write-Host ""

# Function to find all Ghidra processes
function Get-GhidraProcesses {
    $ghidraProcs = @()
    
    # Method 1: Check for javaw/java processes with Ghidra in window title
    $javaProcs = Get-Process -Name javaw, java -ErrorAction SilentlyContinue | Where-Object {
        $_.MainWindowTitle -match "Ghidra"
    }
    if ($javaProcs) { $ghidraProcs += $javaProcs }
    
    # Method 2: Check for processes started from Ghidra directory
    $allProcs = Get-Process -Name javaw, java -ErrorAction SilentlyContinue | Where-Object {
        try {
            $_.Path -and $_.Path -match "ghidra"
        } catch { $false }
    }
    foreach ($proc in $allProcs) {
        if ($proc.Id -notin $ghidraProcs.Id) {
            $ghidraProcs += $proc
        }
    }
    
    # Method 3: Check command line for ghidra references (requires admin for full access)
    try {
        $wmiProcs = Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction SilentlyContinue
        foreach ($wmiProc in $wmiProcs) {
            if ($wmiProc.CommandLine -match "ghidra") {
                $proc = Get-Process -Id $wmiProc.ProcessId -ErrorAction SilentlyContinue
                if ($proc -and $proc.Id -notin $ghidraProcs.Id) {
                    $ghidraProcs += $proc
                }
            }
        }
    } catch { }
    
    return $ghidraProcs
}

# Function to close Ghidra gracefully
function Close-Ghidra {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$Force)
    
    $ghidraProcesses = Get-GhidraProcesses
    if (-not $ghidraProcesses) {
        return $false
    }
    
    Write-LogInfo "Detected $($ghidraProcesses.Count) Ghidra process(es) running"
    
    foreach ($ghidraProcess in $ghidraProcesses) {
        $procInfo = "PID $($ghidraProcess.Id)"
        if ($ghidraProcess.MainWindowTitle) {
            $procInfo = "'$($ghidraProcess.MainWindowTitle)' ($procInfo)"
        }
        
        Write-LogInfo "Closing Ghidra $procInfo..."
        try {
            # Try graceful close first
            if ($ghidraProcess.MainWindowHandle -ne 0) {
                $ghidraProcess.CloseMainWindow() | Out-Null
                
                # Wait up to 5 seconds for graceful close
                $waited = 0
                while (!$ghidraProcess.HasExited -and $waited -lt 5) {
                    Start-Sleep -Milliseconds 500
                    $waited += 0.5
                    $ghidraProcess.Refresh()
                }
            }
            
            # Force kill if still running
            if (!$ghidraProcess.HasExited) {
                if ($Force) {
                    Write-LogWarning "Force terminating Ghidra $procInfo..."
                    if ($PSCmdlet.ShouldProcess($procInfo, "Stop Ghidra process")) {
                        Stop-Process -Id $ghidraProcess.Id -Force -ErrorAction SilentlyContinue
                    }
                } else {
                    Write-LogWarning "Ghidra $procInfo did not close gracefully. Use -Force to terminate."
                }
            } else {
                Write-LogSuccess "Closed Ghidra $procInfo"
            }
        } catch {
            Write-LogWarning "Could not close Ghidra $procInfo : $($_.Exception.Message)"
        }
    }
    
    # Wait for processes to fully terminate
    Start-Sleep -Seconds 2
    return $true
}

function Invoke-CommandChecked {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($DryRun) {
        Write-LogInfo "[DRY RUN] $Description"
        Write-Host "          $Command $($Arguments -join ' ')"
        return
    }

    if ($VerbosePreference -eq 'Continue') {
        Write-LogInfo "$Description"
        Write-Host "          $Command $($Arguments -join ' ')"
    }

    $target = "$Command $($Arguments -join ' ')"
    if (-not $PSCmdlet.ShouldProcess($target, $Description)) {
        Write-Verbose "Skipped: $Description"
        return
    }

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $Command (exit code $LASTEXITCODE)"
    }
}

function Install-GhidraDependencies {
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedGhidraPath,
        [Parameter(Mandatory = $true)][string]$MavenPath
    )

    $deps = @(
        @{ Artifact = "Base";             RelPath = "Ghidra\Features\Base\lib\Base.jar" },
        @{ Artifact = "Decompiler";       RelPath = "Ghidra\Features\Decompiler\lib\Decompiler.jar" },
        @{ Artifact = "Docking";          RelPath = "Ghidra\Framework\Docking\lib\Docking.jar" },
        @{ Artifact = "Generic";          RelPath = "Ghidra\Framework\Generic\lib\Generic.jar" },
        @{ Artifact = "Project";          RelPath = "Ghidra\Framework\Project\lib\Project.jar" },
        @{ Artifact = "SoftwareModeling"; RelPath = "Ghidra\Framework\SoftwareModeling\lib\SoftwareModeling.jar" },
        @{ Artifact = "Utility";          RelPath = "Ghidra\Framework\Utility\lib\Utility.jar" },
        @{ Artifact = "Gui";              RelPath = "Ghidra\Framework\Gui\lib\Gui.jar" },
        @{ Artifact = "FileSystem";       RelPath = "Ghidra\Framework\FileSystem\lib\FileSystem.jar" },
        @{ Artifact = "Graph";            RelPath = "Ghidra\Framework\Graph\lib\Graph.jar" },
        @{ Artifact = "DB";               RelPath = "Ghidra\Framework\DB\lib\DB.jar" },
        @{ Artifact = "Emulation";        RelPath = "Ghidra\Framework\Emulation\lib\Emulation.jar" },
        @{ Artifact = "PDB";              RelPath = "Ghidra\Features\PDB\lib\PDB.jar" },
        @{ Artifact = "FunctionID";       RelPath = "Ghidra\Features\FunctionID\lib\FunctionID.jar" }
    )

    foreach ($dep in $deps) {
        $jarPath = Join-Path $ResolvedGhidraPath $dep.RelPath
        if (-not (Test-Path $jarPath)) {
            throw "Missing JAR: $jarPath"
        }

        $m2Jar = Join-Path $env:USERPROFILE ".m2\repository\ghidra\$($dep.Artifact)\$GhidraVersion\$($dep.Artifact)-$GhidraVersion.jar"
        if ((Test-Path $m2Jar) -and -not $Force) {
            Write-LogInfo "Already installed, skipping: $($dep.Artifact)"
            continue
        }

        $installArgs = @(
            "install:install-file",
            "-Dfile=$jarPath",
            "-DgroupId=ghidra",
            "-DartifactId=$($dep.Artifact)",
            "-Dversion=$GhidraVersion",
            "-Dpackaging=jar",
            "-DgeneratePom=true"
        )
        if ($VerbosePreference -ne 'Continue') {
            $installArgs = @("-q") + $installArgs
        }

        Invoke-CommandChecked -Command $MavenPath -Arguments $installArgs -Description "Installing Ghidra dependency: $($dep.Artifact)"
    }

    Write-LogSuccess "Ghidra dependencies are installed in local Maven repository."
}

function Invoke-CleanAction {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $targetDir = Join-Path $PSScriptRoot "target"
    if (Test-Path $targetDir) {
        if ($DryRun) {
            Write-LogInfo "[DRY RUN] Would remove: $targetDir"
        } else {
            if ($PSCmdlet.ShouldProcess($targetDir, "Remove target directory")) {
                Remove-Item $targetDir -Recurse -Force
                Write-LogSuccess "Removed target directory."
            }
        }
    }

    $ghidraUserBase = "$env:USERPROFILE\AppData\Roaming\ghidra"
    if (Test-Path $ghidraUserBase) {
        Get-ChildItem -Path $ghidraUserBase -Directory -Filter "ghidra_*" | ForEach-Object {
            $extPath = Join-Path $_.FullName "Extensions\GhidraMCP"
            if (Test-Path $extPath) {
                if ($DryRun) {
                    Write-LogInfo "[DRY RUN] Would remove: $extPath"
                } else {
                    if ($PSCmdlet.ShouldProcess($extPath, "Remove cached GhidraMCP extension")) {
                        Remove-Item -Recurse -Force $extPath -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }

    # Remove locally installed Ghidra dependencies from Maven cache for this version
    $artifacts = @(
        "Base",
        "Decompiler",
        "Docking",
        "Generic",
        "Project",
        "SoftwareModeling",
        "Utility",
        "Gui",
        "FileSystem",
        "Graph",
        "DB",
        "Emulation",
        "PDB",
        "FunctionID"
    )

    $m2Root = Join-Path $env:USERPROFILE ".m2\repository\ghidra"
    $removedM2 = 0
    foreach ($artifact in $artifacts) {
        $artifactVersionDir = Join-Path $m2Root "$artifact\$GhidraVersion"
        if (Test-Path $artifactVersionDir) {
            if ($DryRun) {
                Write-LogInfo "[DRY RUN] Would remove: $artifactVersionDir"
            } else {
                if ($PSCmdlet.ShouldProcess($artifactVersionDir, "Remove local Maven Ghidra dependency folder")) {
                    Remove-Item -Recurse -Force $artifactVersionDir -ErrorAction SilentlyContinue
                    $removedM2++
                }
            }
        }
    }

    if ($removedM2 -gt 0) {
        Write-LogInfo "Removed $removedM2 local Maven Ghidra dependency folder(s) for version $GhidraVersion."
    }

    Write-LogSuccess "Cleanup completed."
}

function Get-MavenPath {
    $mavenPaths = @(
        "$env:USERPROFILE\tools\apache-maven-3.9.6\bin\mvn.cmd",
        "C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.1.1.1\plugins\maven\lib\maven3\bin\mvn.cmd",
        (Get-Command mvn -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    )

    foreach ($path in $mavenPaths) {
        if ($path -and (Test-Path $path)) {
            return $path
        }
    }

    throw "Maven not found on PATH"
}

function Get-PythonCommand {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd -and (Test-Path $pythonCmd.Source)) {
        return @{ Command = $pythonCmd.Source; PrefixParameters = @() }
    }

    $pyCmd = Get-Command py -ErrorAction SilentlyContinue
    if ($pyCmd -and (Test-Path $pyCmd.Source)) {
        return @{ Command = $pyCmd.Source; PrefixParameters = @() }
    }

    throw "Python executable not found on PATH"
}

function Install-PythonPackages {
    $requirementsPath = Join-Path $PSScriptRoot "requirements.txt"
    if (-not (Test-Path $requirementsPath)) {
        Write-LogWarning "requirements.txt not found, skipping Python dependency installation."
        return
    }

    $py = Get-PythonCommand
    $pipParameters = @($py.PrefixParameters) + @("-m", "pip", "install")
    if ($VerbosePreference -ne 'Continue') {
        $pipParameters += @("-q", "--disable-pip-version-check")
    }
    $pipParameters += @("-r", $requirementsPath)
    Invoke-CommandChecked -Command $py.Command -Arguments $pipParameters -Description "Ensuring Python dependencies"
    Write-LogSuccess "Python dependencies are ready."
}

function Test-WriteAccess {
    param([Parameter(Mandatory = $true)][string]$PathToTest)

    try {
        if (-not (Test-Path $PathToTest)) {
            New-Item -ItemType Directory -Path $PathToTest -Force | Out-Null
        }
        $probe = Join-Path $PathToTest ".ghidra-mcp-write-test"
        Set-Content -Path $probe -Value "ok" -ErrorAction Stop
        Remove-Item -Path $probe -Force -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Invoke-PreflightChecks {
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedGhidraPath,
        [Parameter(Mandatory = $true)][string]$ResolvedGhidraVersion,
        [switch]$Strict
    )

    Write-LogInfo "Running preflight checks..."
    $issues = [System.Collections.Generic.List[string]]::new()

    # Maven
    try {
        $mavenPath = Get-MavenPath
        Write-LogSuccess "Maven found: $mavenPath"
    } catch {
        $issues.Add("Maven not found on PATH.")
    }

    # Python + pip
    try {
        $py = Get-PythonCommand
        Write-LogSuccess "Python found: $($py.Command)"
        & $py.Command @($py.PrefixParameters) -m pip --version *> $null
        if ($LASTEXITCODE -ne 0) {
            $issues.Add("pip is not available for the selected Python interpreter.")
        } else {
            Write-LogSuccess "pip is available."
        }
    } catch {
        $issues.Add("Python executable not found on PATH.")
    }

    # Java
    $javaCmd = Get-Command java -ErrorAction SilentlyContinue
    if (-not $javaCmd) {
        $issues.Add("Java not found on PATH (JDK 21 recommended).")
    } else {
        Write-LogSuccess "Java found: $($javaCmd.Source)"
    }

    # Ghidra layout and required jars
    if (-not (Test-Path "$ResolvedGhidraPath\ghidraRun.bat")) {
        $issues.Add("Ghidra executable not found at: $ResolvedGhidraPath")
    } else {
        Write-LogSuccess "Ghidra path looks valid."
        $requiredJarPaths = @(
            "Ghidra\Features\Base\lib\Base.jar",
            "Ghidra\Features\Decompiler\lib\Decompiler.jar",
            "Ghidra\Framework\Docking\lib\Docking.jar",
            "Ghidra\Framework\Generic\lib\Generic.jar",
            "Ghidra\Framework\Project\lib\Project.jar",
            "Ghidra\Framework\SoftwareModeling\lib\SoftwareModeling.jar",
            "Ghidra\Framework\Utility\lib\Utility.jar",
            "Ghidra\Framework\Gui\lib\Gui.jar",
            "Ghidra\Framework\FileSystem\lib\FileSystem.jar",
            "Ghidra\Framework\Graph\lib\Graph.jar",
            "Ghidra\Framework\DB\lib\DB.jar",
            "Ghidra\Framework\Emulation\lib\Emulation.jar",
            "Ghidra\Features\PDB\lib\PDB.jar",
            "Ghidra\Features\FunctionID\lib\FunctionID.jar"
        )
        foreach ($rel in $requiredJarPaths) {
            $full = Join-Path $ResolvedGhidraPath $rel
            if (-not (Test-Path $full)) {
                $issues.Add("Missing required Ghidra dependency: $full")
            }
        }
    }

    # Write access checks
    $extensionsDir = "$ResolvedGhidraPath\Extensions\Ghidra"
    if (-not (Test-WriteAccess -PathToTest $extensionsDir)) {
        $issues.Add("No write access to Ghidra extensions directory: $extensionsDir")
    } else {
        Write-LogSuccess "Write access OK: $extensionsDir"
    }

    $userExtDir = "$env:USERPROFILE\AppData\Roaming\ghidra\ghidra_$ResolvedGhidraVersion`_PUBLIC\Extensions"
    if (-not (Test-WriteAccess -PathToTest $userExtDir)) {
        $issues.Add("No write access to user extension directory: $userExtDir")
    } else {
        Write-LogSuccess "Write access OK: $userExtDir"
    }

    # Optional strict network checks
    if ($Strict) {
        foreach ($url in @("https://repo.maven.apache.org", "https://pypi.org")) {
            try {
                Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -ErrorAction Stop | Out-Null
                Write-LogSuccess "Reachable: $url"
            } catch {
                $issues.Add("Network check failed: $url")
            }
        }
    }

    if ($issues.Count -gt 0) {
        Write-LogError "Preflight checks failed:"
        foreach ($issue in $issues) {
            Write-Host "  - $issue" -ForegroundColor Red
        }
        throw "Preflight failed."
    }

    Write-LogSuccess "Preflight checks passed."
}

if ($Clean) {
    Invoke-CleanAction
    exit 0
}

if ($Preflight) {
    try {
        Invoke-PreflightChecks -ResolvedGhidraPath $GhidraPath -ResolvedGhidraVersion $GhidraVersion -Strict:$StrictPreflight
        exit 0
    } catch {
        exit 1
    }
}

if ($BuildOnly) {
    $mavenPath = Get-MavenPath
    Invoke-CommandChecked -Command $mavenPath -Arguments @("clean", "package", "assembly:single", "-DskipTests") -Description "Building GhidraMCP extension"
    Write-LogSuccess "Build-only action completed."
    exit 0
}

if ($SetupDeps) {
    if (-not (Test-Path "$GhidraPath\ghidraRun.bat")) {
        Write-LogError "Ghidra not found at: $GhidraPath"
        Write-LogInfo "Please specify the correct path: .\ghidra-mcp-setup.ps1 -SetupDeps -GhidraPath 'C:\path\to\ghidra'"
        exit 1
    }

    $mavenPath = Get-MavenPath
    Install-GhidraDependencies -ResolvedGhidraPath $GhidraPath -MavenPath $mavenPath
    exit 0
}

if ($actionCount -eq 0) {
    $Deploy = $true
}

# Validate Ghidra path first
if (-not (Test-Path "$GhidraPath\ghidraRun.bat")) {
    Write-LogError "Ghidra not found at: $GhidraPath"
    Write-LogInfo "Please specify the correct path: .\ghidra-mcp-setup.ps1 -GhidraPath 'C:\path\to\ghidra'"
    exit 1
}
Write-LogSuccess "Found Ghidra at: $GhidraPath"

try {
    Invoke-PreflightChecks -ResolvedGhidraPath $GhidraPath -ResolvedGhidraVersion $GhidraVersion -Strict:$StrictPreflight
} catch {
    exit 1
}

if (-not $NoAutoPrereqs) {
    Write-LogInfo "Auto-prerequisite mode enabled: ensuring dependencies before deploy..."
    try {
        Install-PythonPackages
        $mavenPath = Get-MavenPath
        Install-GhidraDependencies -ResolvedGhidraPath $GhidraPath -MavenPath $mavenPath
    } catch {
        Write-LogError "Prerequisite setup failed: $($_.Exception.Message)"
        Write-LogInfo "You can use -NoAutoPrereqs to skip auto setup and manage prerequisites manually."
        exit 1
    }
} else {
    Write-LogInfo "Auto-prerequisite mode disabled (-NoAutoPrereqs)."
}

# Check if Ghidra is running BEFORE deployment (files may be locked)
$ghidraWasRunning = $false
$preDeployProcesses = Get-GhidraProcesses
if ($preDeployProcesses) {
    Write-LogWarning "Ghidra is currently running - files may be locked"
    if (-not $SkipRestart) {
        Write-LogInfo "Closing Ghidra before deployment..."
        $ghidraWasRunning = Close-Ghidra -Force
        if ($ghidraWasRunning) {
            Write-LogSuccess "Ghidra closed successfully"
        }
    } else {
        Write-LogWarning "Ghidra is running but -SkipRestart specified. Some files may fail to copy."
    }
}

# Clean up ALL cached GhidraMCP extensions from all Ghidra versions
$ghidraUserBase = "$env:USERPROFILE\AppData\Roaming\ghidra"
if (Test-Path $ghidraUserBase) {
    $cleanedCount = 0
    Get-ChildItem -Path $ghidraUserBase -Directory -Filter "ghidra_*" | ForEach-Object {
        $extPath = Join-Path $_.FullName "Extensions\GhidraMCP"
        if (Test-Path $extPath) {
            try {
                if ($PSCmdlet.ShouldProcess($extPath, "Remove cached GhidraMCP extension")) {
                    Remove-Item -Recurse -Force $extPath -ErrorAction Stop
                    $cleanedCount++
                }
            } catch {
                Write-LogWarning "Could not clean: $extPath - $($_.Exception.Message)"
            }
        }
    }
    if ($cleanedCount -gt 0) {
        Write-LogInfo "Cleaned $cleanedCount cached GhidraMCP extension(s)"
    }
}

# Build the extension (unless skipped)
if (-not $SkipBuild) {
    Write-LogInfo "Building GhidraMCP extension..."
    try {
        $mavenPath = Get-MavenPath
        Write-LogInfo "Found Maven at: $mavenPath"
        Invoke-CommandChecked -Command $mavenPath -Arguments @("clean", "package", "assembly:single", "-DskipTests") -Description "Building GhidraMCP extension"
        Write-LogSuccess "Build completed successfully"
    } catch {
        Write-LogError "Build failed: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-LogInfo "Skipping build (using existing artifact)"
}

# Detect version from pom.xml
$pomPath = "$PSScriptRoot\pom.xml"
if (Test-Path $pomPath) {
    try {
        [xml]$pom = Get-Content $pomPath
        $version = $pom.project.version
        Write-LogSuccess "Detected version: $version"
    } catch {
        Write-LogWarning "Could not parse version from pom.xml, using default: $PluginVersion"
        $version = $PluginVersion
    }
} else {
    Write-LogWarning "pom.xml not found, using default version: $PluginVersion"
    $version = $PluginVersion
}

# Find latest build artifact
$artifactPath = "$PSScriptRoot\target\GhidraMCP-$version.zip"

if (-not (Test-Path $artifactPath)) {
    # Support non-versioned artifact name as well
    $nonVersionedArtifact = "$PSScriptRoot\target\GhidraMCP.zip"
    if (Test-Path $nonVersionedArtifact) {
        $artifactPath = $nonVersionedArtifact
    }
}

if (-not (Test-Path $artifactPath)) {
    # Auto-detect latest artifact if direct names not found
    $artifacts = Get-ChildItem -Path "$PSScriptRoot\target" -Filter "GhidraMCP*.zip" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending
    if ($artifacts) {
        $artifactPath = $artifacts[0].FullName
        Write-LogInfo "Auto-detected latest artifact: $($artifacts[0].Name)"
    } else {
        Write-LogError "No build artifacts found in target/"
        Write-LogInfo "Please run the build first: mvn clean package assembly:single"
        exit 1
    }
}

Write-LogSuccess "Using artifact: $(Split-Path $artifactPath -Leaf) ($version)"

# Find Ghidra Extensions directory
$extensionsDir = "$GhidraPath\Extensions\Ghidra"
if (-not (Test-Path $extensionsDir)) {
    Write-LogInfo "Extensions directory doesn't exist, creating: $extensionsDir"
    if ($PSCmdlet.ShouldProcess($extensionsDir, "Create extensions directory")) {
        New-Item -ItemType Directory -Path $extensionsDir -Force | Out-Null
    }
}

# Remove existing installations
$existingPlugins = Get-ChildItem -Path $extensionsDir -Filter "GhidraMCP*.zip" -ErrorAction SilentlyContinue

if ($existingPlugins) {
    Write-LogInfo "Removing existing GhidraMCP installations..."
    foreach ($plugin in $existingPlugins) {
        if ($PSCmdlet.ShouldProcess($plugin.FullName, "Remove existing GhidraMCP plugin archive")) {
            Remove-Item $plugin.FullName -Force
            Write-LogSuccess "Removed: $($plugin.Name)"
        }
    }
}

# Copy new plugin
try {
    $artifactName = Split-Path $artifactPath -Leaf
    $destinationPath = Join-Path $extensionsDir $artifactName
    if ($PSCmdlet.ShouldProcess($destinationPath, "Copy plugin archive to Ghidra Extensions")) {
        Copy-Item $artifactPath $destinationPath -Force
        Write-LogSuccess "Installed: $artifactName → $extensionsDir"
    }
} catch {
    Write-LogError "Failed to copy plugin: $($_.Exception.Message)"
    exit 1
}

# Also copy JAR to user's local Extensions directory for development/debugging
$jarSourcePath = "$PSScriptRoot\target\GhidraMCP.jar"
if (-not (Test-Path $jarSourcePath)) {
    $versionedJarPath = "$PSScriptRoot\target\GhidraMCP-$version.jar"
    if (Test-Path $versionedJarPath) {
        $jarSourcePath = $versionedJarPath
    }
}
if (Test-Path $jarSourcePath) {
    # Detect Ghidra version from installation path
    $ghidraVersionDir = $null
    $ghidraUserBase = "$env:USERPROFILE\AppData\Roaming\ghidra"

    if (Test-Path $ghidraUserBase) {
        # Find the most recent ghidra version directory using semantic version sorting
        # (String sorting incorrectly puts "12.0_" before "12.0.3_" because "_" > "." in ASCII)
        $ghidraVersionDirs = Get-ChildItem -Path $ghidraUserBase -Directory -Filter "ghidra_*" |
            ForEach-Object {
                # Extract version numbers for proper numerical sorting
                if ($_.Name -match "ghidra_([0-9]+)\.([0-9]+)(?:\.([0-9]+))?") {
                    [PSCustomObject]@{
                        Name = $_.Name
                        Major = [int]$Matches[1]
                        Minor = [int]$Matches[2]
                        Patch = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
                    }
                }
            } |
            Sort-Object Major, Minor, Patch -Descending
        
        if ($ghidraVersionDirs) {
            $ghidraVersionDir = $ghidraVersionDirs[0].Name
            Write-LogInfo "Detected Ghidra user config version: $ghidraVersionDir"
        }
    }

    if (-not $ghidraVersionDir) {
        # Fallback: extract version from Ghidra installation path
        if ($GhidraPath -match "ghidra_([0-9.]+)") {
            $ghidraVersionDir = "ghidra_$($Matches[1])_PUBLIC"
        } else {
            $ghidraVersionDir = "ghidra_12.0.3_PUBLIC"
        }
        Write-LogInfo "Using Ghidra version dir: $ghidraVersionDir"
    }

    $userExtensionsDir = "$ghidraUserBase\$ghidraVersionDir\Extensions\GhidraMCP\lib"

    if (-not (Test-Path $userExtensionsDir)) {
        Write-LogInfo "Creating user Extensions directory: $userExtensionsDir"
        if ($PSCmdlet.ShouldProcess($userExtensionsDir, "Create user extension library directory")) {
            New-Item -ItemType Directory -Path $userExtensionsDir -Force | Out-Null
        }
    }

    try {
        $jarDestinationPath = Join-Path $userExtensionsDir "GhidraMCP.jar"
        if ($PSCmdlet.ShouldProcess($jarDestinationPath, "Copy plugin JAR to user extension directory")) {
            Copy-Item $jarSourcePath $jarDestinationPath -Force
            Write-LogSuccess "Installed: GhidraMCP.jar → $userExtensionsDir"
        }
    } catch {
        Write-LogWarning "Failed to copy JAR to user Extensions: $($_.Exception.Message)"
        Write-LogInfo "JAR copy is optional - plugin will work without it"
    }
} else {
    Write-LogWarning "JAR file not found: $jarSourcePath"
}

# Copy Python MCP bridge to Ghidra root
$bridgeSourcePath = "$PSScriptRoot\bridge_mcp_ghidra.py"
$requirementsSourcePath = "$PSScriptRoot\requirements.txt"

if (Test-Path $bridgeSourcePath) {
    try {
        $bridgeDestinationPath = Join-Path $GhidraPath "bridge_mcp_ghidra.py"
        
        # Remove existing bridge if it exists
        if (Test-Path $bridgeDestinationPath) {
            if ($PSCmdlet.ShouldProcess($bridgeDestinationPath, "Remove existing Python bridge")) {
                Remove-Item $bridgeDestinationPath -Force
                Write-LogSuccess "Removed existing bridge"
            }
        }
        
        if ($PSCmdlet.ShouldProcess($bridgeDestinationPath, "Copy Python bridge to Ghidra root")) {
            Copy-Item $bridgeSourcePath $bridgeDestinationPath -Force
            Write-LogSuccess "Installed: bridge_mcp_ghidra.py → $GhidraPath"
        }
        
        # Also copy requirements.txt for convenience
        if (Test-Path $requirementsSourcePath) {
            $requirementsDestinationPath = Join-Path $GhidraPath "requirements.txt"
            if ($PSCmdlet.ShouldProcess($requirementsDestinationPath, "Copy requirements.txt to Ghidra root")) {
                Copy-Item $requirementsSourcePath $requirementsDestinationPath -Force
                Write-LogSuccess "Installed: requirements.txt → $GhidraPath"
            }
        }
        
    } catch {
        Write-LogWarning "Failed to copy Python bridge: $($_.Exception.Message)"
        Write-LogInfo "You can manually copy bridge_mcp_ghidra.py to your Ghidra installation"
    }
} else {
    Write-LogWarning "Python bridge not found: $bridgeSourcePath"
}

# Check for user preferences directory
$userDir = "$env:USERPROFILE\.ghidra"
if (Test-Path $userDir) {
    # Try to find and update plugin preferences
    $prefsPattern = "$userDir\*\preferences\*\plugins.xml"
    $prefsFiles = Get-ChildItem -Path $prefsPattern -Recurse -ErrorAction SilentlyContinue
    
    if ($prefsFiles) {
        Write-LogInfo "Found Ghidra preferences files, attempting to enable plugin..."
        foreach ($prefsFile in $prefsFiles) {
            try {
                [xml]$xmlContent = Get-Content $prefsFile.FullName
                $pluginNode = $xmlContent.SelectSingleNode("//PLUGIN[@NAME='GhidraMCPPlugin']")
                
                if ($pluginNode) {
                    $pluginNode.SetAttribute("ENABLED", "true")
                    if ($PSCmdlet.ShouldProcess($prefsFile.FullName, "Update plugin enabled setting in preferences")) {
                        $xmlContent.Save($prefsFile.FullName)
                        Write-LogSuccess "Enabled GhidraMCP plugin in: $($prefsFile.Name)"
                    }
                } else {
                    Write-Verbose "GhidraMCP plugin not found in: $($prefsFile.Name)"
                }
            } catch {
                Write-Verbose "Could not modify preferences file: $($prefsFile.Name)"
            }
        }
    }
}

# Create quick reference message
Write-Host ""
Write-LogSuccess "GhidraMCP v$version Successfully Deployed!"
Write-Host ""
Write-LogInfo "Installation Locations:"
Write-Host "   Plugin: $destinationPath"
if ($userExtensionsDir) {
    Write-Host "   JAR: $jarDestinationPath"
}
Write-Host "   Python Bridge: $GhidraPath\bridge_mcp_ghidra.py"
Write-Host "   Requirements: $GhidraPath\requirements.txt"
Write-Host ""
Write-LogInfo "Next Steps:"
if ($NoAutoPrereqs) {
    Write-Host "1. If needed (first time only), install Python dependencies: pip install -r requirements.txt"
} else {
    Write-Host "1. Python dependencies were auto-checked/installed."
}
Write-Host "2. Start Ghidra"
Write-Host "3. If plugin isn't automatically enabled:"
Write-Host "      - In CodeBrowser: File > Configure > Configure All Plugins > GhidraMCP"
Write-Host "      - Check the checkbox to enable"
Write-Host "      - Click OK and restart Ghidra"
Write-Host "4. To configure the server port:"
Write-Host "      - In CodeBrowser: Edit > Tool Options > GhidraMCP HTTP Server"
Write-Host ""
Write-LogInfo "Usage:"
Write-Host "   Ghidra: Tools > GhidraMCP > Start MCP Server"
Write-Host "   Python: python bridge_mcp_ghidra.py (from project root or Ghidra directory)"
Write-Host ""
Write-LogInfo "Default Server: http://127.0.0.1:8089/"
Write-Host ""

# Show version-specific release notes
if ($version -match "^2\.") {
    Write-LogInfo "New in v2.0.0 - Major Release:"
    Write-Host "   + 133 total endpoints (was 132)"
    Write-Host "   + Ghidra 12.0.3 support"
    Write-Host "   + Malware analysis: IOC extraction, behavior detection, anti-analysis detection"
    Write-Host "   + Function similarity analysis with CFG comparison"
    Write-Host "   + Control flow complexity analysis (cyclomatic complexity)"
    Write-Host "   + Enhanced call graph: cycle detection, path finding, SCC analysis"
    Write-Host "   + API call chain threat pattern detection"
    Write-Host ""
} else {
    Write-LogInfo "For release notes, see: docs/releases/ or CHANGELOG.md"
}
Write-Host ""

# Verify installation
if (Test-Path $destinationPath) {
    $fileSize = (Get-Item $destinationPath).Length
    Write-LogSuccess "Installation verified: $([math]::Round($fileSize/1KB, 2)) KB"
    
    if (-not $SkipRestart) {
        # Check if any Ghidra is still running (shouldn't be if we closed it earlier)
        $remainingProcesses = Get-GhidraProcesses
        if ($remainingProcesses) {
            Write-LogWarning "Ghidra processes still detected, attempting to close..."
            Close-Ghidra -Force
            Start-Sleep -Seconds 2
        }
        
        # Start Ghidra
        Write-LogInfo "Starting Ghidra..."
        if ($PSCmdlet.ShouldProcess("$GhidraPath\ghidraRun.bat", "Start Ghidra")) {
            Start-Process "$GhidraPath\ghidraRun.bat" -WorkingDirectory $GhidraPath
        }
        
        # Wait a moment and verify it started
        Start-Sleep -Seconds 3
        $newProcs = Get-GhidraProcesses
        if ($newProcs) {
            Write-LogSuccess "Ghidra started successfully! (PID: $($newProcs[0].Id))"
            Write-LogSuccess "The updated plugin (v$version) is now available."
        } else {
            Write-LogInfo "Ghidra launch initiated - it may take a moment to fully start."
        }
    } else {
        if ($ghidraWasRunning) {
            Write-LogWarning "Ghidra was closed but -SkipRestart specified. Start Ghidra manually."
        } else {
            Write-LogInfo "Skipping Ghidra restart (use without -SkipRestart to auto-restart)"
        }
    }
} else {
    Write-LogError "Installation verification failed!"
    exit 1
}

Write-Host ""
Write-LogSuccess "Deployment completed successfully!"
Write-Host ""
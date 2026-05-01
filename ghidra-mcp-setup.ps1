# GhidraMCP Deployment Script
# Automatically builds, installs, and configures the GhidraMCP plugin
# Target: Ghidra 12.0.4

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
.\ghidra-mcp-setup.ps1 -Deploy -GhidraPath "F:\ghidra_12.0.4_PUBLIC"

.EXAMPLE
.\ghidra-mcp-setup.ps1 -SetupDeps -GhidraPath "F:\ghidra_12.0.4_PUBLIC"

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
    [switch]$Force = $false,
    [string]$AutoOpen = "",
    [string]$ServerPassword = ""
)

# Color output functions
function Write-LogSuccess { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-LogInfo { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-LogWarning { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-LogError { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

# Configuration
$DefaultGhidraVersion = "12.0.4"
$PluginVersion = "5.2.0"

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
    Write-Host "  -GhidraPath      Path to Ghidra install (e.g., F:\ghidra_12.0.4_PUBLIC)"
    Write-Host "  -GhidraVersion   Explicit Ghidra version (must match pom.xml/path version)"
    Write-Host "  -StrictPreflight Fail preflight on network checks (Maven Central/PyPI reachability)"
    Write-Host "  -NoAutoPrereqs   Disable automatic prerequisite setup during deploy"
    Write-Host "  -SkipBuild       Deploy existing artifact without rebuilding"
    Write-Host "  -SkipRestart     Do not restart Ghidra after deployment"
    Write-Host "  -AutoOpen        Auto-open program on restart (e.g., 'F:\GhidraProjects\diablo2|/LoD/1.00/D2Common.dll')"
    Write-Host "  -ServerPassword  Auto-fill Ghidra server password dialog on startup"
    Write-Host "  -Force           Reinstall dependencies even if already present"
    Write-Host "  -DryRun          Print actions without executing commands"
    Write-Host "  -Verbose         Verbose logging"
    Write-Host "  -WhatIf          Preview changes without executing state-changing operations"
    Write-Host "  -Confirm         Prompt for confirmation before state-changing operations"
    Write-Host "  -Help            Show this help text"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\ghidra-mcp-setup.ps1 -Deploy -GhidraPath 'F:\ghidra_12.0.4_PUBLIC'"
    Write-Host "  .\ghidra-mcp-setup.ps1 -SetupDeps -GhidraPath 'F:\ghidra_12.0.4_PUBLIC'"
    Write-Host "  .\ghidra-mcp-setup.ps1 -Preflight -GhidraPath 'F:\ghidra_12.0.4_PUBLIC'"
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

$installDebuggerDepsValue = [System.Environment]::GetEnvironmentVariable("INSTALL_DEBUGGER_DEPS", "Process")
if (-not $installDebuggerDepsValue) {
    $installDebuggerDepsValue = ""
}
$InstallDebuggerDeps = @("1", "true", "yes", "on") -contains $installDebuggerDepsValue.Trim().ToLowerInvariant()

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
    # Extract major.minor for compatibility check
    $pathMajorMinor = ($pathGhidraVersion -split '\.')[0..1] -join '.'
    $selectedMajorMinor = ($GhidraVersion -split '\.')[0..1] -join '.'
    if ($pathMajorMinor -eq $selectedMajorMinor) {
        Write-LogWarning "GhidraPath version '$pathGhidraVersion' differs from build version '$GhidraVersion' (patch mismatch)."
        Write-LogInfo "Extensions are generally compatible across patch versions. Continuing."
    } else {
        Write-LogError "Version mismatch: GhidraPath implies version '$pathGhidraVersion', but selected/pom version is '$GhidraVersion'."
        Write-LogInfo "Use a matching -GhidraPath or update pom.xml ghidra.version."
        exit 1
    }
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
        @{ Artifact = "FunctionID";       RelPath = "Ghidra\Features\FunctionID\lib\FunctionID.jar" },
        @{ Artifact = "Help";             RelPath = "Ghidra\Framework\Help\lib\Help.jar" },
        @{ Artifact = "Debugger-api";          RelPath = "Ghidra\Debug\Debugger-api\lib\Debugger-api.jar" },
        @{ Artifact = "Framework-TraceModeling"; RelPath = "Ghidra\Debug\Framework-TraceModeling\lib\Framework-TraceModeling.jar" },
        @{ Artifact = "Debugger-rmi-trace";    RelPath = "Ghidra\Debug\Debugger-rmi-trace\lib\Debugger-rmi-trace.jar" }
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

function Test-TruthyValue {
    param([string]$Value)

    if (-not $Value) { return $false }
    return @("1", "true", "yes", "on") -contains $Value.Trim().ToLowerInvariant()
}

function Install-PythonRequirementsFile {
    param(
        [Parameter(Mandatory = $true)]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$RequirementsPath,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not (Test-Path $RequirementsPath)) {
        Write-LogWarning "$RequirementsPath not found, skipping $Description."
        return
    }

    $pipParameters = @($PythonCommand.PrefixParameters) + @("-m", "pip", "install")
    if ($VerbosePreference -ne 'Continue') {
        $pipParameters += @("-q", "--disable-pip-version-check")
    }
    $pipParameters += @("-r", $RequirementsPath)
    Invoke-CommandChecked -Command $PythonCommand.Command -Arguments $pipParameters -Description $Description
}

function Install-PythonPackages {
    $requirementsPath = Join-Path $PSScriptRoot "requirements.txt"
    if (-not (Test-Path $requirementsPath)) {
        Write-LogWarning "requirements.txt not found, skipping Python dependency installation."
        return
    }

    $py = Get-PythonCommand
    Install-PythonRequirementsFile -PythonCommand $py -RequirementsPath $requirementsPath -Description "Ensuring Python dependencies"
    if ($InstallDebuggerDeps) {
        $debuggerRequirementsPath = Join-Path $PSScriptRoot "requirements-debugger.txt"
        Install-PythonRequirementsFile -PythonCommand $py -RequirementsPath $debuggerRequirementsPath -Description "Ensuring debugger Python dependencies"
        Write-LogSuccess "Debugger Python dependencies are ready."
    }
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
            "Ghidra\Features\FunctionID\lib\FunctionID.jar",
            "Ghidra\Framework\Help\lib\Help.jar"
        )
        foreach ($rel in $requiredJarPaths) {
            $full = Join-Path $ResolvedGhidraPath $rel
            if (-not (Test-Path $full)) {
                $issues.Add("Missing required Ghidra dependency: $full")
            }
        }
    }

    if ($InstallDebuggerDeps) {
        $debuggerRequirementsPath = Join-Path $PSScriptRoot "requirements-debugger.txt"
        if (-not (Test-Path $debuggerRequirementsPath)) {
            $issues.Add("Debugger requirements file not found: $debuggerRequirementsPath")
        } else {
            Write-LogSuccess "Debugger requirements file found."
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

# Extract extension ZIP to user's local Extensions directory.
# Ghidra considers an extension "installed" when its directory (with extension.properties)
# exists under the user Extensions dir. Without this, users must manually activate via
# File > Install Extensions after every deploy.
$ghidraVersionDir = $null
$ghidraUserBase = "$env:USERPROFILE\AppData\Roaming\ghidra"

if (Test-Path $ghidraUserBase) {
    # Extract version from GhidraPath (e.g., "F:\ghidra_12.0.4_PUBLIC" -> "12.0.4")
    $targetVersion = $null
    if ($GhidraPath -match "ghidra_([0-9.]+)") {
        $targetVersion = $Matches[1]
    }

    if ($targetVersion) {
        $matchingDirs = Get-ChildItem -Path $ghidraUserBase -Directory -Filter "ghidra_${targetVersion}*"
        if ($matchingDirs) {
            $publicDir = $matchingDirs | Where-Object { $_.Name -match "PUBLIC" } | Select-Object -First 1
            $ghidraVersionDir = if ($publicDir) { $publicDir.Name } else { $matchingDirs[0].Name }
            Write-LogInfo "Detected Ghidra user config version: $ghidraVersionDir (matching $targetVersion)"
        }
    }

    if (-not $ghidraVersionDir) {
        $ghidraVersionDirs = Get-ChildItem -Path $ghidraUserBase -Directory -Filter "ghidra_*" |
            ForEach-Object {
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
            Write-LogInfo "Using highest Ghidra user config version: $ghidraVersionDir"
        }
    }
}

if (-not $ghidraVersionDir) {
    if ($GhidraPath -match "ghidra_([0-9.]+)") {
        $ghidraVersionDir = "ghidra_$($Matches[1])_PUBLIC"
    } else {
        $ghidraVersionDir = "ghidra_12.0.4_PUBLIC"
    }
    Write-LogInfo "Using Ghidra version dir: $ghidraVersionDir"
}

$userExtensionsBase = "$ghidraUserBase\$ghidraVersionDir\Extensions"
$userExtensionsDir = "$userExtensionsBase\GhidraMCP"

try {
    if ($PSCmdlet.ShouldProcess($userExtensionsDir, "Extract extension ZIP to user Extensions directory")) {
        # v5.4.2: purge any stale versioned JARs before extraction. Expand-Archive
        # -Force only overwrites same-named files; if the version number in the
        # JAR name changed (e.g. GhidraMCP-5.3.2.jar -> GhidraMCP-5.4.1.jar) the
        # old JAR would linger in lib/ and Ghidra's classloader would load
        # whichever one it found first. That caused upgraders from v5.3.x to
        # silently keep running the old code.
        $libDir = "$userExtensionsDir\lib"
        if (Test-Path $libDir) {
            $staleJars = @(Get-ChildItem -Path $libDir -Filter "GhidraMCP*.jar" -ErrorAction SilentlyContinue)
            if ($staleJars.Count -gt 0) {
                foreach ($stale in $staleJars) {
                    try {
                        Remove-Item -Path $stale.FullName -Force -ErrorAction Stop
                        Write-LogInfo "Removed stale plugin JAR: $($stale.Name)"
                    } catch {
                        Write-LogWarning "Could not remove $($stale.Name) - is Ghidra still running? $($_.Exception.Message)"
                    }
                }
            }
        }

        # Extract ZIP contents to user Extensions dir (GhidraMCP/ subfolder is inside the ZIP)
        Expand-Archive -Path $artifactPath -DestinationPath $userExtensionsBase -Force
        Write-LogSuccess "Installed: extension extracted to $userExtensionsDir"
    }
} catch {
    Write-LogWarning "Failed to extract extension to user Extensions: $($_.Exception.Message)"
    Write-LogInfo "Falling back to JAR-only copy..."
    # Fallback: at minimum copy the JAR so the plugin classes are available
    $jarSourcePath = "$PSScriptRoot\target\GhidraMCP.jar"
    if (-not (Test-Path $jarSourcePath)) {
        $versionedJarPath = "$PSScriptRoot\target\GhidraMCP-$version.jar"
        if (Test-Path $versionedJarPath) { $jarSourcePath = $versionedJarPath }
    }
    if (Test-Path $jarSourcePath) {
        $libDir = "$userExtensionsDir\lib"
        New-Item -ItemType Directory -Path $libDir -Force | Out-Null
        Copy-Item $jarSourcePath "$libDir\GhidraMCP.jar" -Force
    }
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

# Auto-activate GhidraMCP in FrontEnd (Project Manager) configuration
# v4.1: Plugin loads in FrontEnd via the Utility package (ApplicationLevelPlugin)
# Patches FrontEndTool.xml to explicitly include the plugin class in the Utility package
$ghidraUserDir = "$env:APPDATA\ghidra"
if (Test-Path $ghidraUserDir) {
    $pluginClass = "com.xebyte.GhidraMCPPlugin"

    # --- Step 1: Patch FrontEndTool.xml to auto-load GhidraMCPPlugin ---
    $frontEndFiles = Get-ChildItem -Path "$ghidraUserDir\*\FrontEndTool.xml" -ErrorAction SilentlyContinue

    foreach ($feFile in $frontEndFiles) {
        try {
            $feContent = Get-Content $feFile.FullName -Raw -Encoding UTF8
            $modified = $false

            # Clean up stale Developer/GhidraMCP package entries (from earlier versions)
            foreach ($stalePkg in @('Developer', 'GhidraMCP')) {
                if ($feContent -match "PACKAGE NAME=`"$stalePkg`"") {
                    # Remove self-closing form: <PACKAGE NAME="X" />
                    $feContent = $feContent -replace "\s*<PACKAGE NAME=`"$stalePkg`"\s*/>\s*", "`n"
                    # Remove block form: <PACKAGE NAME="X">...</PACKAGE>
                    $feContent = $feContent -replace "(?s)\s*<PACKAGE NAME=`"$stalePkg`">\s*.*?</PACKAGE>\s*", "`n"
                    $modified = $true
                    Write-LogInfo "Cleaned stale $stalePkg package entry from FrontEnd config"
                }
            }

            # Check if plugin is already included in the Utility package
            if ($feContent -match [regex]::Escape($pluginClass)) {
                Write-LogSuccess "GhidraMCPPlugin already configured in FrontEnd: $($feFile.FullName)"
            } elseif ($feContent -match '<PACKAGE NAME="Utility"\s*/>') {
                # Utility package exists as self-closing tag - expand it with INCLUDE
                $feContent = $feContent -replace '<PACKAGE NAME="Utility"\s*/>', @"
<PACKAGE NAME="Utility">
                <INCLUDE CLASS="$pluginClass" />
            </PACKAGE>
"@
                $modified = $true
                Write-LogSuccess "Added GhidraMCPPlugin to FrontEnd Utility package: $($feFile.FullName)"
            } elseif ($feContent -match '<PACKAGE NAME="Utility">') {
                # Utility package exists as block - add INCLUDE inside it
                $feContent = $feContent -replace '(<PACKAGE NAME="Utility">)', "`$1`n                <INCLUDE CLASS=`"$pluginClass`" />"
                $modified = $true
                Write-LogSuccess "Added GhidraMCPPlugin to existing FrontEnd Utility block: $($feFile.FullName)"
            } else {
                # No Utility package at all (unusual) - add the whole block
                $feContent = $feContent -replace '(<ROOT_NODE)', @"
<PACKAGE NAME="Utility">
                <INCLUDE CLASS="$pluginClass" />
            </PACKAGE>
            `$1
"@
                $modified = $true
                Write-LogSuccess "Added Utility package with GhidraMCPPlugin to FrontEnd config: $($feFile.FullName)"
            }

            if ($modified) {
                if ($PSCmdlet.ShouldProcess($feFile.FullName, "Patch FrontEnd config for GhidraMCPPlugin")) {
                    Set-Content -Path $feFile.FullName -Value $feContent -Encoding UTF8 -NoNewline
                }
            }
        } catch {
            Write-LogWarning "Could not patch FrontEnd config: $($_.Exception.Message)"
            Write-LogInfo "Enable manually: File > Configure > Utility > check GhidraMCP"
        }
    }

    # --- Step 2: Remove from CodeBrowser TCD (no longer needed there) ---
    $tcdFiles = Get-ChildItem -Path "$ghidraUserDir\*\tools\_code_browser.tcd" -ErrorAction SilentlyContinue

    foreach ($tcdFile in $tcdFiles) {
        try {
            $tcdContent = Get-Content $tcdFile.FullName -Raw -Encoding UTF8

            if ($tcdContent -match [regex]::Escape($pluginClass)) {
                # Remove the GhidraMCP PACKAGE block from CodeBrowser
                $removePattern = '\s*<PACKAGE NAME="GhidraMCP">\s*<INCLUDE CLASS="com\.xebyte\.GhidraMCPPlugin"\s*/>\s*</PACKAGE>'
                $newContent = $tcdContent -replace $removePattern, ''

                if ($newContent -ne $tcdContent) {
                    if ($PSCmdlet.ShouldProcess($tcdFile.FullName, "Remove GhidraMCP from CodeBrowser (now in FrontEnd)")) {
                        Set-Content -Path $tcdFile.FullName -Value $newContent -Encoding UTF8 -NoNewline
                        Write-LogSuccess "Removed GhidraMCP from CodeBrowser (now loads from FrontEnd): $($tcdFile.FullName)"
                    }
                }
            }
        } catch {
            Write-LogWarning "Could not clean CodeBrowser config: $($_.Exception.Message)"
        }
    }
} else {
    Write-Verbose "Ghidra user directory not found at: $ghidraUserDir"
}

# Create quick reference message
Write-Host ""
Write-LogSuccess "GhidraMCP v$version Successfully Deployed!"
Write-Host ""
Write-LogInfo "Installation Locations:"
Write-Host "   Plugin ZIP: $destinationPath"
if ($userExtensionsDir) {
    Write-Host "   User Extension: $userExtensionsDir"
}
Write-Host "   Python Bridge: $GhidraPath\bridge_mcp_ghidra.py"
Write-Host "   Requirements: $GhidraPath\requirements.txt"
Write-Host ""
Write-LogInfo "Next Steps:"
if ($NoAutoPrereqs) {
    Write-Host "1. If needed (first time only), install Python dependencies: pip install -r requirements.txt"
    if ($InstallDebuggerDeps) {
        Write-Host "   Debugger deps enabled: pip install -r requirements-debugger.txt"
    }
} else {
    Write-Host "1. Python dependencies were auto-checked/installed."
    if ($InstallDebuggerDeps) {
        Write-Host "   Optional debugger dependencies were auto-checked/installed."
    }
}
Write-Host "2. Start Ghidra (plugin is auto-activated in CodeBrowser)"
Write-Host "3. If plugin isn't loaded after a fresh Ghidra install:"
Write-Host "      - In CodeBrowser: File > Configure > Configure All Plugins > GhidraMCP"
Write-Host "      - Check the checkbox to enable"
Write-Host "4. To configure the server port:"
Write-Host "      - In CodeBrowser: Edit > Tool Options > GhidraMCP HTTP Server"
Write-Host ""
Write-LogInfo "Usage:"
Write-Host "   Ghidra: Tools > GhidraMCP > Start MCP Server"
Write-Host "   Python: python bridge_mcp_ghidra.py (from project root or Ghidra directory)"
if ($InstallDebuggerDeps) {
    Write-Host "   Debugger: python -m debugger (from project root)"
}
Write-Host ""
Write-LogInfo "Default Server: http://127.0.0.1:8089/"
Write-Host ""

# Show version-specific release notes
if ($version -match "^2\.") {
    Write-LogInfo "New in v2.0.0 - Major Release:"
    Write-Host "   + 133 total endpoints (was 132)"
    Write-Host "   + Ghidra 12.0.4 support"
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

        # If AutoOpen specified, inject RUNNING_TOOL into projectState before launch.
        # This makes Ghidra restore CodeBrowser with the target program on startup.
        # Format: "ProjectDir\ProjectName|/folder/file"
        # Example: "F:\GhidraProjects\diablo2|/LoD/1.00/D2Common.dll"
        if ($AutoOpen -and $AutoOpen.Contains("|")) {
            $parts = $AutoOpen.Split("|", 2)
            $projectPath = $parts[0]
            $filePath = $parts[1]
            $projectStateFile = "$projectPath.rep\projectState"

            if (Test-Path $projectStateFile) {
                try {
                    [xml]$projectState = Get-Content $projectStateFile -Encoding UTF8
                    $workspace = $projectState.SelectSingleNode("//WORKSPACE[@NAME='Workspace']")
                    if ($workspace -and -not $workspace.SelectSingleNode("RUNNING_TOOL")) {
                        $runningTool = $projectState.CreateElement("RUNNING_TOOL")
                        $runningTool.SetAttribute("TOOL_NAME", "CodeBrowser")

                        $dataState = $projectState.CreateElement("DATA_STATE")
                        $openFile = $projectState.CreateElement("OPEN_FILE")
                        $openFile.SetAttribute("NAME", $filePath)
                        $openFile.SetAttribute("TOOL_INSTANCE", "")
                        $dataState.AppendChild($openFile) | Out-Null
                        $runningTool.AppendChild($dataState) | Out-Null
                        $workspace.AppendChild($runningTool) | Out-Null

                        if ($PSCmdlet.ShouldProcess($projectStateFile, "Inject CodeBrowser auto-open for $filePath")) {
                            $projectState.Save($projectStateFile)
                            Write-LogSuccess "Injected auto-open: CodeBrowser with $filePath"
                        }
                    }
                } catch {
                    Write-LogWarning "Could not inject auto-open: $($_.Exception.Message)"
                }
            }
        }

        # Programmatic server authentication via env var.
        # Password resolution order: -ServerPassword param > GHIDRA_SERVER_PASSWORD env var > .ghidra-cred file
        # The GhidraMCPPlugin constructor reads GHIDRA_SERVER_PASSWORD and registers a
        # ClientAuthenticator that handles server auth without GUI dialogs.
        $resolvedPassword = $ServerPassword
        if (-not $resolvedPassword) {
            $resolvedPassword = $env:GHIDRA_SERVER_PASSWORD
        }
        if (-not $resolvedPassword) {
            $credFile = Join-Path $PSScriptRoot ".ghidra-cred"
            if (Test-Path $credFile) {
                $resolvedPassword = (Get-Content $credFile -Raw -ErrorAction SilentlyContinue).Trim()
            }
        }
        if ($resolvedPassword) {
            $env:GHIDRA_SERVER_PASSWORD = $resolvedPassword
            Write-LogInfo "Server credentials configured via GHIDRA_SERVER_PASSWORD (auth dialog will be bypassed)"
        }

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

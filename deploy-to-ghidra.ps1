# GhidraMCP Deployment Script
# Automatically builds, installs, and configures the GhidraMCP plugin
# Target: Ghidra 12.0.2

param(
    [string]$GhidraPath = "",
    [switch]$SkipBuild = $false,
    [switch]$SkipRestart = $false,
    [switch]$Verbose = $false
)

# Configuration
$GhidraVersion = "12.0.2"
$PluginVersion = "2.0.0"

# Load .env file if it exists (local environment config)
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim()
            if ($val) {
                [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
                if ($Verbose) { Write-Info "Loaded from .env: $key" }
            }
        }
    }
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
            Write-Info "Auto-detected Ghidra at: $GhidraPath"
            break
        }
    }
}
if (-not $GhidraPath) {
    Write-Error "Ghidra installation not found."
    Write-Info "Set GHIDRA_PATH in .env file, or pass -GhidraPath parameter:"
    Write-Host "  .\deploy-to-ghidra.ps1 -GhidraPath 'C:\path\to\ghidra_${GhidraVersion}_PUBLIC'"
    Write-Host ""
    Write-Info "Or create a .env file from the template:"
    Write-Host "  Copy-Item .env.template .env"
    Write-Host "  # Edit .env and set GHIDRA_PATH"
    exit 1
}

# Color output functions
function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warning { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "======================================" -ForegroundColor Magenta
Write-Host "  GhidraMCP Deployment Script v2.0   " -ForegroundColor Magenta
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
    param([switch]$Force)
    
    $ghidraProcesses = Get-GhidraProcesses
    if (-not $ghidraProcesses) {
        return $false
    }
    
    Write-Info "Detected $($ghidraProcesses.Count) Ghidra process(es) running"
    
    foreach ($ghidraProcess in $ghidraProcesses) {
        $procInfo = "PID $($ghidraProcess.Id)"
        if ($ghidraProcess.MainWindowTitle) {
            $procInfo = "'$($ghidraProcess.MainWindowTitle)' ($procInfo)"
        }
        
        Write-Info "Closing Ghidra $procInfo..."
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
                    Write-Warning "Force terminating Ghidra $procInfo..."
                    Stop-Process -Id $ghidraProcess.Id -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Warning "Ghidra $procInfo did not close gracefully. Use -Force to terminate."
                }
            } else {
                Write-Success "Closed Ghidra $procInfo"
            }
        } catch {
            Write-Warning "Could not close Ghidra $procInfo : $($_.Exception.Message)"
        }
    }
    
    # Wait for processes to fully terminate
    Start-Sleep -Seconds 2
    return $true
}

# Validate Ghidra path first
if (-not (Test-Path "$GhidraPath\ghidraRun.bat")) {
    Write-Error "Ghidra not found at: $GhidraPath"
    Write-Info "Please specify the correct path: .\deploy-to-ghidra.ps1 -GhidraPath 'C:\path\to\ghidra'"
    exit 1
}
Write-Success "Found Ghidra at: $GhidraPath"

# Check if Ghidra is running BEFORE deployment (files may be locked)
$ghidraWasRunning = $false
$preDeployProcesses = Get-GhidraProcesses
if ($preDeployProcesses) {
    Write-Warning "Ghidra is currently running - files may be locked"
    if (-not $SkipRestart) {
        Write-Info "Closing Ghidra before deployment..."
        $ghidraWasRunning = Close-Ghidra -Force
        if ($ghidraWasRunning) {
            Write-Success "Ghidra closed successfully"
        }
    } else {
        Write-Warning "Ghidra is running but -SkipRestart specified. Some files may fail to copy."
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
                Remove-Item -Recurse -Force $extPath -ErrorAction Stop
                $cleanedCount++
            } catch {
                Write-Warning "Could not clean: $extPath - $($_.Exception.Message)"
            }
        }
    }
    if ($cleanedCount -gt 0) {
        Write-Info "Cleaned $cleanedCount cached GhidraMCP extension(s)"
    }
}

# Build the extension (unless skipped)
if (-not $SkipBuild) {
    Write-Info "Building GhidraMCP extension..."

    # Try multiple Maven locations
    $mavenPaths = @(
        "$env:USERPROFILE\tools\apache-maven-3.9.6\bin\mvn.cmd",
        "C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.1.1.1\plugins\maven\lib\maven3\bin\mvn.cmd",
        (Get-Command mvn -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    )

$mavenPath = $null
foreach ($path in $mavenPaths) {
    if ($path -and (Test-Path $path)) {
        $mavenPath = $path
        Write-Info "Found Maven at: $mavenPath"
        break
    }
}

    if (-not $mavenPath) {
        Write-Error "Maven not found. Tried:"
        foreach ($path in $mavenPaths) {
            if ($path) { Write-Host "  - $path" }
        }
        Write-Info "Please ensure Maven is installed or add it to PATH"
        Write-Info "Or use -SkipBuild if you already have a built artifact"
        exit 1
    }

    try {
        $buildOutput = & $mavenPath clean package assembly:single -DskipTests -q 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Build failed with exit code: $LASTEXITCODE"
            Write-Host $buildOutput
            exit 1
        }
        Write-Success "Build completed successfully"
    } catch {
        Write-Error "Build failed: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Info "Skipping build (using existing artifact)"
}

# Detect version from pom.xml
$pomPath = "$PSScriptRoot\pom.xml"
if (Test-Path $pomPath) {
    try {
        [xml]$pom = Get-Content $pomPath
        $version = $pom.project.version
        Write-Success "Detected version: $version"
    } catch {
        Write-Warning "Could not parse version from pom.xml, using default: $PluginVersion"
        $version = $PluginVersion
    }
} else {
    Write-Warning "pom.xml not found, using default version: $PluginVersion"
    $version = $PluginVersion
}

# Find latest build artifact
$artifactPath = "$PSScriptRoot\target\GhidraMCP-$version.zip"

if (-not (Test-Path $artifactPath)) {
    # Auto-detect latest artifact if version-specific not found
    $artifacts = Get-ChildItem -Path "$PSScriptRoot\target" -Filter "GhidraMCP-*.zip" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending
    if ($artifacts) {
        $artifactPath = $artifacts[0].FullName
        Write-Info "Auto-detected latest artifact: $($artifacts[0].Name)"
    } else {
        Write-Error "No build artifacts found in target/"
        Write-Info "Please run the build first: mvn clean package assembly:single"
        exit 1
    }
}

Write-Success "Using artifact: $(Split-Path $artifactPath -Leaf) ($version)"

# Find Ghidra Extensions directory
$extensionsDir = "$GhidraPath\Extensions\Ghidra"
if (-not (Test-Path $extensionsDir)) {
    Write-Info "Extensions directory doesn't exist, creating: $extensionsDir"
    New-Item -ItemType Directory -Path $extensionsDir -Force | Out-Null
}

# Remove existing installations
$existingPlugins = Get-ChildItem -Path $extensionsDir -Filter "GhidraMCP*.zip" -ErrorAction SilentlyContinue

if ($existingPlugins) {
    Write-Info "Removing existing GhidraMCP installations..."
    foreach ($plugin in $existingPlugins) {
        Remove-Item $plugin.FullName -Force
        Write-Success "Removed: $($plugin.Name)"
    }
}

# Copy new plugin
try {
    $artifactName = Split-Path $artifactPath -Leaf
    $destinationPath = Join-Path $extensionsDir $artifactName
    Copy-Item $artifactPath $destinationPath -Force
    Write-Success "Installed: $artifactName → $extensionsDir"
} catch {
    Write-Error "Failed to copy plugin: $($_.Exception.Message)"
    exit 1
}

# Also copy JAR to user's local Extensions directory for development/debugging
$jarSourcePath = "$PSScriptRoot\target\GhidraMCP.jar"
if (Test-Path $jarSourcePath) {
    # Detect Ghidra version from installation path
    $ghidraVersionDir = $null
    $ghidraUserBase = "$env:USERPROFILE\AppData\Roaming\ghidra"

    if (Test-Path $ghidraUserBase) {
        # Find the most recent ghidra version directory
        $ghidraVersionDirs = Get-ChildItem -Path $ghidraUserBase -Directory -Filter "ghidra_*" |
                             Sort-Object Name -Descending
        if ($ghidraVersionDirs) {
            $ghidraVersionDir = $ghidraVersionDirs[0].Name
            Write-Info "Detected Ghidra user config version: $ghidraVersionDir"
        }
    }

    if (-not $ghidraVersionDir) {
        # Fallback: extract version from Ghidra installation path
        if ($GhidraPath -match "ghidra_([0-9.]+)") {
            $ghidraVersionDir = "ghidra_$($Matches[1])_PUBLIC"
        } else {
            $ghidraVersionDir = "ghidra_12.0.2_PUBLIC"
        }
        Write-Info "Using Ghidra version dir: $ghidraVersionDir"
    }

    $userExtensionsDir = "$ghidraUserBase\$ghidraVersionDir\Extensions\GhidraMCP\lib"

    if (-not (Test-Path $userExtensionsDir)) {
        Write-Info "Creating user Extensions directory: $userExtensionsDir"
        New-Item -ItemType Directory -Path $userExtensionsDir -Force | Out-Null
    }

    try {
        $jarDestinationPath = Join-Path $userExtensionsDir "GhidraMCP.jar"
        Copy-Item $jarSourcePath $jarDestinationPath -Force
        Write-Success "Installed: GhidraMCP.jar → $userExtensionsDir"
    } catch {
        Write-Warning "Failed to copy JAR to user Extensions: $($_.Exception.Message)"
        Write-Info "JAR copy is optional - plugin will work without it"
    }
} else {
    Write-Warning "JAR file not found: $jarSourcePath"
}

# Copy Python MCP bridge to Ghidra root
$bridgeSourcePath = "$PSScriptRoot\bridge_mcp_ghidra.py"
$requirementsSourcePath = "$PSScriptRoot\requirements.txt"

if (Test-Path $bridgeSourcePath) {
    try {
        $bridgeDestinationPath = Join-Path $GhidraPath "bridge_mcp_ghidra.py"
        
        # Remove existing bridge if it exists
        if (Test-Path $bridgeDestinationPath) {
            Remove-Item $bridgeDestinationPath -Force
            Write-Success "Removed existing bridge"
        }
        
        Copy-Item $bridgeSourcePath $bridgeDestinationPath -Force
        Write-Success "Installed: bridge_mcp_ghidra.py → $GhidraPath"
        
        # Also copy requirements.txt for convenience
        if (Test-Path $requirementsSourcePath) {
            $requirementsDestinationPath = Join-Path $GhidraPath "requirements.txt"
            Copy-Item $requirementsSourcePath $requirementsDestinationPath -Force
            Write-Success "Installed: requirements.txt → $GhidraPath"
        }
        
    } catch {
        Write-Warning "Failed to copy Python bridge: $($_.Exception.Message)"
        Write-Info "You can manually copy bridge_mcp_ghidra.py to your Ghidra installation"
    }
} else {
    Write-Warning "Python bridge not found: $bridgeSourcePath"
}

# Check for user preferences directory
$userDir = "$env:USERPROFILE\.ghidra"
if (Test-Path $userDir) {
    # Try to find and update plugin preferences
    $prefsPattern = "$userDir\*\preferences\*\plugins.xml"
    $prefsFiles = Get-ChildItem -Path $prefsPattern -Recurse -ErrorAction SilentlyContinue
    
    if ($prefsFiles) {
        Write-Info "Found Ghidra preferences files, attempting to enable plugin..."
        foreach ($prefsFile in $prefsFiles) {
            try {
                [xml]$xmlContent = Get-Content $prefsFile.FullName
                $pluginNode = $xmlContent.SelectSingleNode("//PLUGIN[@NAME='GhidraMCPPlugin']")
                
                if ($pluginNode) {
                    $pluginNode.SetAttribute("ENABLED", "true")
                    $xmlContent.Save($prefsFile.FullName)
                    Write-Success "Enabled GhidraMCP plugin in: $($prefsFile.Name)"
                } else {
                    if ($Verbose) {
                        Write-Info "GhidraMCP plugin not found in: $($prefsFile.Name)"
                    }
                }
            } catch {
                if ($Verbose) {
                    Write-Warning "Could not modify preferences file: $($prefsFile.Name)"
                }
            }
        }
    }
}

# Create quick reference message
Write-Host ""
Write-Success "GhidraMCP v$version Successfully Deployed!"
Write-Host ""
Write-Info "Installation Locations:"
Write-Host "   Plugin: $destinationPath"
if ($userExtensionsDir) {
    Write-Host "   JAR: $jarDestinationPath"
}
Write-Host "   Python Bridge: $GhidraPath\bridge_mcp_ghidra.py"
Write-Host "   Requirements: $GhidraPath\requirements.txt"
Write-Host ""
Write-Info "Next Steps:"
Write-Host "1. Install Python dependencies: pip install -r requirements.txt"
Write-Host "2. Start Ghidra"
Write-Host "3. If plugin isn't automatically enabled:"
Write-Host "      - Go to File > Configure..."
Write-Host "      - Navigate to Miscellaneous > GhidraMCP"
Write-Host "      - Check the checkbox to enable"
Write-Host "      - Click OK and restart Ghidra"
Write-Host ""
Write-Info "Usage:"
Write-Host "   Ghidra: Tools > GhidraMCP > Start MCP Server"
Write-Host "   Python: python bridge_mcp_ghidra.py (from project root or Ghidra directory)"
Write-Host ""
Write-Info "Default Server: http://127.0.0.1:8089/"
Write-Host ""

# Show version-specific release notes
if ($version -match "^2\.") {
    Write-Info "New in v2.0.0 - Major Release:"
    Write-Host "   + 133 total endpoints (was 132)"
    Write-Host "   + Ghidra 12.0.2 support"
    Write-Host "   + Malware analysis: IOC extraction, behavior detection, anti-analysis detection"
    Write-Host "   + Function similarity analysis with CFG comparison"
    Write-Host "   + Control flow complexity analysis (cyclomatic complexity)"
    Write-Host "   + Enhanced call graph: cycle detection, path finding, SCC analysis"
    Write-Host "   + API call chain threat pattern detection"
    Write-Host ""
} else {
    Write-Info "For release notes, see: docs/releases/ or CHANGELOG.md"
}
Write-Host ""

# Verify installation
if (Test-Path $destinationPath) {
    $fileSize = (Get-Item $destinationPath).Length
    Write-Success "Installation verified: $([math]::Round($fileSize/1KB, 2)) KB"
    
    if (-not $SkipRestart) {
        # Check if any Ghidra is still running (shouldn't be if we closed it earlier)
        $remainingProcesses = Get-GhidraProcesses
        if ($remainingProcesses) {
            Write-Warning "Ghidra processes still detected, attempting to close..."
            Close-Ghidra -Force
            Start-Sleep -Seconds 2
        }
        
        # Start Ghidra
        Write-Info "Starting Ghidra..."
        Start-Process "$GhidraPath\ghidraRun.bat" -WorkingDirectory $GhidraPath
        
        # Wait a moment and verify it started
        Start-Sleep -Seconds 3
        $newProcs = Get-GhidraProcesses
        if ($newProcs) {
            Write-Success "Ghidra started successfully! (PID: $($newProcs[0].Id))"
            Write-Success "The updated plugin (v$version) is now available."
        } else {
            Write-Info "Ghidra launch initiated - it may take a moment to fully start."
        }
    } else {
        if ($ghidraWasRunning) {
            Write-Warning "Ghidra was closed but -SkipRestart specified. Start Ghidra manually."
        } else {
            Write-Info "Skipping Ghidra restart (use without -SkipRestart to auto-restart)"
        }
    }
} else {
    Write-Error "Installation verification failed!"
    exit 1
}

Write-Host ""
Write-Success "Deployment completed successfully!"
Write-Host ""Write-Success "Deployment completed successfully!"
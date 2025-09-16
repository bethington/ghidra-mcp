# GhidraMCP Deployment Script
# Automatically installs and configures the GhidraMCP plugin

param(
    [string]$GhidraPath = "",
    [switch]$Verbose = $false
)

# Color output functions
function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warning { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

Write-Info "GhidraMCP v1.1.2 Deployment Script"
Write-Info "===================================="

# Find Ghidra installation
$possiblePaths = @(
    "C:\ghidra",
    "C:\Program Files\ghidra",
    "C:\Program Files (x86)\ghidra",
    "C:\tools\ghidra",
    "F:\ghidra_11.4.2_PUBLIC",
    "$env:USERPROFILE\ghidra",
    "$env:USERPROFILE\tools\ghidra"
)

if (-not $GhidraPath) {
    Write-Info "Searching for Ghidra installation..."
    foreach ($path in $possiblePaths) {
        if (Test-Path "$path\ghidraRun.bat") {
            $GhidraPath = $path
            Write-Success "Found Ghidra at: $GhidraPath"
            break
        }
    }
    
    if (-not $GhidraPath) {
        Write-Warning "Ghidra installation not found automatically."
        $GhidraPath = Read-Host "Please enter your Ghidra installation path"
        if (-not (Test-Path "$GhidraPath\ghidraRun.bat")) {
            Write-Error "Invalid Ghidra path. ghidraRun.bat not found."
            exit 1
        }
    }
}

# Verify build artifact exists
$artifactPath = "$PSScriptRoot\target\GhidraMCP-1.1.2.zip"
if (-not (Test-Path $artifactPath)) {
    Write-Error "Build artifact not found: $artifactPath"
    Write-Info "Please run the build first: mvn clean package assembly:single"
    exit 1
}

Write-Success "Found build artifact: $artifactPath"

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
    $destinationPath = Join-Path $extensionsDir "GhidraMCP-1.1.2.zip"
    Copy-Item $artifactPath $destinationPath -Force
    Write-Success "Installed: GhidraMCP-1.1.2.zip → $extensionsDir"
} catch {
    Write-Error "Failed to copy plugin: $($_.Exception.Message)"
    exit 1
}

# Also copy JAR to user's local Extensions directory for development/debugging
$jarSourcePath = "$PSScriptRoot\target\GhidraMCP.jar"
if (Test-Path $jarSourcePath) {
    $userExtensionsDir = "$env:USERPROFILE\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\Extensions\GhidraMCP\lib"
    
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
Write-Success "GhidraMCP v1.1.2 Successfully Deployed!"
Write-Host ""
Write-Info "Installation Locations:"
Write-Host "   Plugin: $destinationPath"
Write-Host "   JAR: $env:USERPROFILE\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\Extensions\GhidraMCP\lib\GhidraMCP.jar"
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
Write-Host "   Python: python bridge_mcp_ghidra.py (from Ghidra root directory)"
Write-Host ""
Write-Info "Default Server: http://127.0.0.1:8089/"
Write-Host ""
Write-Info "New in v1.1.2:"
Write-Host "   + get_function_callgraph - Analyze function calls"
Write-Host "   + find_byte_patterns - Pattern matching with wildcards"
Write-Host "   + create_label - Programmatic label creation"
Write-Host "   + get_program_stats - Comprehensive program statistics"
Write-Host "   + get_data_references - Enhanced cross-reference analysis"
Write-Host "   + list_data_types - Enumerate available data types"
Write-Host "   + create_struct - Define custom structure types"
Write-Host "   + create_enum - Define enumeration types"
Write-Host "   + apply_data_type - Apply types to memory locations"
Write-Host ""
Write-Info "For detailed usage instructions, see: INSTALLATION.md"



# Verify installation
if (Test-Path $destinationPath) {
    $fileSize = (Get-Item $destinationPath).Length
    Write-Success "Installation verified: $([math]::Round($fileSize/1KB, 2)) KB"
    
    # Offer to start Ghidra
    $startGhidra = Read-Host "Would you like to start Ghidra now? (y/N)"
    if ($startGhidra -match '^[Yy]') {
        Write-Info "Starting Ghidra..."
        Start-Process "$GhidraPath\ghidraRun.bat"
        Write-Success "Ghidra started! The plugin should be available after restart if needed."
    }
} else {
    Write-Error "Installation verification failed!"
    exit 1
}

Write-Success "Deployment completed successfully!"
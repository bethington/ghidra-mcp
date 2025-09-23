# Enhanced Ghidra Plugin Development Process

## Overview

The enhanced `ghidra_dev_cycle.py` script provides a comprehensive 7-step development cycle for the GhidraMCP plugin, based on patterns from `deploy-to-ghidra.ps1`.

## Enhanced Features

### 1. **Improved Ghidra Installation Detection**
- Searches multiple common installation paths
- Checks environment variables (`GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, `GHIDRA_PATH`)
- Uses glob patterns to find installations across drive roots
- Validates `ghidraRun.bat` exists before confirming installation

### 2. **Enhanced Build System**
- Tries multiple Maven locations including user tools directory
- Validates Maven availability before attempting build
- Skips tests during development cycle (`-DskipTests`)
- Verifies build artifacts exist and have reasonable file sizes
- Reports detailed build artifact information

### 3. **Comprehensive Deployment**
- **Artifact Validation**: Checks file existence and minimum sizes before deployment
- **Clean Installation**: Removes existing GhidraMCP installations first
- **Multi-Location Deployment**:
  - Main plugin ZIP to `Ghidra/Extensions/Ghidra/`
  - JAR to user extensions directory for development
  - Python bridge to Ghidra root directory
  - Requirements.txt for convenience
  - JAR to Ghidra root for quick access
- **Preferences Management**: Attempts to enable plugin in Ghidra preferences automatically
- **Enhanced Error Handling**: Better error messages and validation

### 4. **Improved Ghidra Process Management**
- **Graceful Shutdown**: Attempts to close Ghidra windows first
- **Comprehensive Cleanup**: Kills all Ghidra-related processes
- **Port Verification**: Ensures port 8089 is free before continuing
- **Process Verification**: Confirms all processes are closed before deployment

### 5. **Advanced Project/Binary Loading**
- **Path Validation**: Verifies project (.gpr) and binary files exist
- **Smart Command Building**: Constructs appropriate ghidraRun command
- **Flexible Loading**: Supports project-only, binary-only, or no-project modes
- **Adaptive Timing**: Adjusts wait times based on loading complexity

### 6. **Enhanced Monitoring and Validation**
- **CodeBrowser Detection**: Uses PowerShell to detect if CodeBrowser window is open
- **Plugin Readiness**: Waits for HTTP server to be available on port 8089
- **Detailed Progress Reporting**: Clear step-by-step progress indicators
- **Comprehensive Results**: Reports success/failure with detailed context

## 7-Step Enhanced Process

### Step 1: Build Plugin Changes
- Detects and validates Maven installation
- Builds with `-DskipTests` for faster development cycles
- Validates build artifacts (ZIP and JAR files)
- Reports file sizes and success status

### Step 2: Close ALL Existing Ghidra Processes
- Gracefully closes Ghidra windows using PowerShell
- Force-kills remaining processes if needed
- Waits for proper shutdown
- Verifies all processes are closed

### Step 3: Deploy Plugin (Enhanced)
- Removes existing GhidraMCP installations
- Deploys to multiple locations for compatibility
- Copies Python bridge and requirements
- Attempts to enable plugin in preferences
- Validates all deployments successful

### Step 4: Start Fresh Ghidra
- Validates Ghidra executable exists
- Validates project/binary files if provided
- Constructs appropriate startup command
- Starts Ghidra with proper timing
- Reports process ID and command executed

### Step 5: Check CodeBrowser Window
- Uses PowerShell to detect CodeBrowser window
- Reports window status for debugging
- Continues even if not detected (non-blocking)

### Step 6: Wait for Plugin Ready
- Tests HTTP endpoint availability
- Waits up to 60 seconds for plugin to load
- Provides progress indicators
- Reports plugin readiness status

### Step 7: Test Data Types
- Runs comprehensive data type creation tests
- Tests structs, enums, and unions
- Reports detailed test results
- Provides success/failure summary

## Usage Examples

### Full Enhanced Development Cycle
```bash
python ghidra_dev_cycle.py --test-all
```

### Load with Project and Binary
```bash
python ghidra_dev_cycle.py --project-path "F:\GhidraProjects\PD2.gpr" --binary-path "D:\binaries\target.exe" --test-all
```

### Individual Operations
```bash
# Build only
python ghidra_dev_cycle.py --build-only

# Deploy only (assumes build complete)
python ghidra_dev_cycle.py --deploy-only

# Test only (assumes plugin running)
python ghidra_dev_cycle.py --test-only
```

## Enhanced Validation and Error Handling

### Build Phase
- ✅ Maven detection across multiple paths
- ✅ Build artifact validation (size and existence)
- ✅ Detailed error reporting with stdout/stderr

### Deployment Phase  
- ✅ Pre-deployment artifact validation
- ✅ Clean removal of existing installations
- ✅ Multi-location deployment verification
- ✅ Preferences modification (best effort)

### Startup Phase
- ✅ Executable path validation
- ✅ Project/binary file validation
- ✅ Process ID tracking
- ✅ Adaptive timing based on load complexity

### Plugin Loading
- ✅ HTTP endpoint availability testing
- ✅ CodeBrowser window detection
- ✅ Comprehensive readiness verification

## First-Time Setup Notes

1. **Plugin Enable**: First time running, you may need to manually enable the plugin:
   - Go to File > Configure...
   - Navigate to Miscellaneous > GhidraMCP
   - Check the checkbox to enable
   - Click OK and restart Ghidra

2. **CodeBrowser Window**: For testing, ensure CodeBrowser is open:
   - In Ghidra, go to Tools > Code Browser
   - Or open a project with a binary

3. **Port 8089**: Ensure no other applications are using port 8089

## Comparison with deploy-to-ghidra.ps1

The enhanced process incorporates all the best practices from `deploy-to-ghidra.ps1`:

- ✅ **Multi-path Ghidra detection** (enhanced beyond PowerShell version)
- ✅ **Artifact validation** (size and existence checks)
- ✅ **Clean installation** (remove existing first)
- ✅ **Multi-location deployment** (main + user extensions)
- ✅ **Python bridge deployment** with requirements.txt
- ✅ **Preferences management** (automatic plugin enabling)
- ✅ **Comprehensive error handling** and validation
- ✅ **Detailed progress reporting** and success confirmation

## Development Cycle Benefits

1. **Reliability**: Comprehensive validation at each step
2. **Speed**: Optimized build with test skipping during development
3. **Completeness**: Full cleanup and deployment automation
4. **Debugging**: Clear progress indicators and detailed error messages
5. **Flexibility**: Support for various project/binary loading scenarios
6. **Integration**: Seamless integration with existing deployment patterns

The enhanced process provides a production-ready development environment that handles edge cases, provides detailed feedback, and integrates all the best practices from the manual deployment script.
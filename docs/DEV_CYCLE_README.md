# Ghidra Plugin Development Cycle

This directory contains automation scripts for the complete Ghidra plugin development cycle: build → deploy → restart → test.

## 🚀 Quick Start

### Option 1: PowerShell Script (Recommended for Windows)
```powershell
# Full development cycle (build, deploy, restart, test)
.\ghidra-dev-cycle.ps1

# Specify Ghidra installation path
.\ghidra-dev-cycle.ps1 -GhidraPath "C:\ghidra_11.1.2_PUBLIC"

# Just test the current plugin
.\ghidra-dev-cycle.ps1 -TestOnly

# Just build
.\ghidra-dev-cycle.ps1 -BuildOnly
```

### Option 2: Python Script (Cross-platform)
```bash
# Full development cycle
python ghidra_dev_cycle.py

# Specify Ghidra path
python ghidra_dev_cycle.py --ghidra-path "C:\ghidra_11.1.2_PUBLIC"

# Just test
python ghidra_dev_cycle.py --test-only

# Just build
python ghidra_dev_cycle.py --build-only
```

### Option 3: Batch Script (Simple Windows)
```batch
# Full development cycle
ghidra-dev-cycle.bat

# Just build
ghidra-dev-cycle.bat --build-only

# Just test
ghidra-dev-cycle.bat --test-only
```

## 📋 What the Scripts Do

### Full Development Cycle
1. **Build Plugin** - Compiles Java code using Maven
2. **Stop Ghidra** - Terminates any running Ghidra processes
3. **Deploy Plugin** - Copies files to Ghidra installation:
   - `GhidraMCP-1.2.0.zip` → `Extensions/Ghidra/`
   - `bridge_mcp_ghidra.py` → Ghidra root
   - `GhidraMCP.jar` → Ghidra root (for convenience)
4. **Start Ghidra** - Launches Ghidra with updated plugin
5. **Wait for Plugin** - Monitors for HTTP server on port 8089
6. **Test Data Types** - Validates struct, enum, and union creation

### Individual Operations
- **Build Only**: Just compiles the plugin without deployment
- **Deploy Only**: Assumes plugin is built, just deploys and restarts
- **Test Only**: Tests the currently running plugin

## 🔧 Configuration

### Ghidra Installation Detection
Scripts automatically detect Ghidra in these locations:
- `C:\ghidra_11.1.2_PUBLIC`
- `C:\ghidra_11.1.1_PUBLIC`
- `C:\ghidra_11.1_PUBLIC`
- `C:\ghidra_11.0_PUBLIC`
- `C:\Program Files\ghidra_11.1.2_PUBLIC`
- `%GHIDRA_INSTALL_DIR%` (environment variable)

### Maven Configuration
Scripts expect Maven at: `%USERPROFILE%\tools\apache-maven-3.9.6\bin\mvn.cmd`

## 📊 Test Results

After running the full cycle, you'll see test results like:
```
🧪 Testing Data Type Creation...
==================================================
Testing Struct Creation...
Struct: ✅ (200)
Response: Successfully created structure 'TestStruct_1234567' with 2 fields...

Testing Enum Creation...
Enum: ✅ (200)
Response: Successfully created enumeration 'TestEnum_1234567'...

Testing Union Creation...
Union: ✅ (200)
Response: Union 'TestUnion_1234567' created successfully with 2 fields...

📊 Test Results: 3/3 (100.0%) working
```

## 🛠️ Usage Examples

### During Development
```powershell
# Make code changes to GhidraMCPPlugin.java
# Then run full cycle to test changes
.\ghidra-dev-cycle.ps1
```

### Testing Union Fix
```powershell
# After implementing union creation fix
.\ghidra-dev-cycle.ps1
# Should show Union: ✅ in test results
```

### Quick Testing
```powershell
# Just test current plugin without rebuilding
.\ghidra-dev-cycle.ps1 -TestOnly
```

### Build Verification
```powershell
# Just build to check for compilation errors
.\ghidra-dev-cycle.ps1 -BuildOnly
```

## 🔍 Troubleshooting

### Common Issues

**"Ghidra installation not found"**
- Specify path: `.\ghidra-dev-cycle.ps1 -GhidraPath "C:\your\ghidra\path"`
- Set environment variable: `$env:GHIDRA_INSTALL_DIR = "C:\your\ghidra\path"`

**"Maven not found"**
- Install Maven to `%USERPROFILE%\tools\apache-maven-3.9.6\`
- Or update script paths to match your Maven installation

**"Plugin not ready after 60 seconds"**
- Ghidra may be taking longer to load
- Check if Ghidra opened successfully
- Verify no firewall blocking port 8089

**"Build failed"**
- Check Java version (requires Java 8 or compatible)
- Verify Ghidra JARs are in `lib/` directory
- Run `mvn clean` manually to clear cache

### Manual Verification

Check if plugin loaded successfully:
```bash
curl http://localhost:8089/get_metadata
```

Should return program information if plugin is active.

## 📁 File Structure

```
ghidra-mcp/
├── ghidra_dev_cycle.py      # Python automation script
├── ghidra-dev-cycle.ps1     # PowerShell automation script  
├── ghidra-dev-cycle.bat     # Batch automation script
├── target/
│   ├── GhidraMCP.jar        # Compiled plugin JAR
│   └── GhidraMCP-1.2.0.zip  # Plugin distribution
├── src/main/java/           # Java source code
└── bridge_mcp_ghidra.py     # MCP bridge script
```

## ⚡ Performance Tips

- Use `--test-only` for rapid testing during development
- Use `--build-only` to check compilation without full restart
- Keep Ghidra project loaded to reduce startup time
- Use SSD storage for faster Maven builds

## 🎯 Integration with VS Code

These scripts integrate with VS Code tasks. You can:
1. Run from integrated terminal
2. Create custom tasks in `tasks.json`
3. Use as build/test commands in launch configurations

The automation ensures consistent, repeatable development cycles and catches issues early in the development process.
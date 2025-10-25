# Ghidra Scripts

This directory contains scripts that run **directly inside Ghidra** (not via MCP bridge).

## Script Types

### Java Scripts
- **ClearCallReturnOverrides.java** - Clears incorrect CALL_RETURN flow overrides that prevent proper control flow analysis
- **DocumentFunctionWithClaude.java** - Documents the current function by calling Claude AI with comprehensive plate comment prompt (Keybinding: Ctrl+Shift+D)

## How to Use These Scripts

### Method 1: Ghidra Script Manager (Recommended)
1. Open Ghidra
2. Go to **Window → Script Manager**
3. Click the **"Manage Script Directories"** button (folder icon)
4. Add this directory: `<repo>/ghidra_scripts`
5. Click **Refresh** in Script Manager
6. Scripts will appear in the list - double-click to run

### Method 2: Copy to Ghidra Installation
```powershell
# Copy scripts to Ghidra's user scripts directory
Copy-Item ".\ghidra_scripts\*.java" "$env:USERPROFILE\ghidra_scripts\" -Force
```

Then refresh the Script Manager in Ghidra.

## Script Annotations

Ghidra scripts use special annotations:
- `@author` - Script author
- `@category` - Category in Script Manager (e.g., Analysis, Data)
- `@keybinding` - Optional keyboard shortcut
- `@menupath` - Menu location (e.g., Tools.Clear CALL_RETURN Overrides)
- `@toolbar` - Adds toolbar button

## Development Notes

### Java Scripts
Must extend `GhidraScript` class and have these imports:
```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
```

### Python Scripts (Jython)
Ghidra uses Jython 2.7, not Python 3. Scripts must use:
```python
from ghidra.app.script import GhidraScript
```

## Difference from /scripts Directory

- **`/ghidra_scripts`** - Run inside Ghidra GUI (this directory)
- **`/scripts`** - Run via MCP bridge from external Python/PowerShell

## Resources

- [Ghidra Script Development Guide](https://ghidra.re/courses/GhidraClass/Intermediate/Scripting.html)
- [GhidraScript API Documentation](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html)

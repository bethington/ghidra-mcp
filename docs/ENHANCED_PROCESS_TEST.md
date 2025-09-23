## Enhanced Ghidra Development Cycle - Test Instructions

### What We've Built
The enhanced `ghidra_dev_cycle.py` now implements the complete 7-step process you requested:

1. **Build changes** - Compile the plugin with Maven
2. **Close ALL existing Ghidra processes** - Graceful shutdown using PowerShell window management
3. **Deploy plugin** - Copy files to Ghidra installation
4. **Start fresh Ghidra with binary** - Launch with project and binary parameters
5. **Check CodeBrowser window** - Verify CodeBrowser window is open
6. **Test data types** - Run comprehensive struct/enum/union tests
7. **Report results** - Detailed status reporting

### New Features Added

#### Graceful Process Management
- `close_ghidra()` method uses PowerShell to gracefully close windows
- `CloseMainWindow()` instead of force killing
- Enhanced process verification

#### Project & Binary Loading
- Support for `--project-path` and `--binary-path` parameters
- Automatic project and binary loading on Ghidra startup
- Example: `python ghidra_dev_cycle.py --project-path "F:\GhidraProjects\PD2.gpr" --binary-path "D2Game.dll"`

#### CodeBrowser Detection
- `check_codebrowser_window()` method
- PowerShell-based window title checking
- Verification that CodeBrowser is properly loaded

### Usage Examples

#### Basic Development Cycle
```bash
python ghidra_dev_cycle.py
```

#### With Project and Binary
```bash
python ghidra_dev_cycle.py --project-path "F:\GhidraProjects\PD2.gpr" --binary-path "D2Game.dll"
```

#### Build and Deploy Only
```bash
python ghidra_dev_cycle.py --deploy-only --project-path "F:\GhidraProjects\PD2.gpr" --binary-path "D2Game.dll"
```

### Test the Enhanced Process
Let's run a test to see the new graceful shutdown and CodeBrowser detection in action!
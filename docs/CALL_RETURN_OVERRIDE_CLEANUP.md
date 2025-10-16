# Fixing CALL_RETURN Flow Override Issues in Ghidra

## The Problem

Ghidra's decompiler sometimes misinterprets function calls and creates `CALL_RETURN` flow overrides that indicate execution returns to the caller immediately after a function call, even when the called function actually returns normally and execution continues. This causes:

- **Incomplete decompilation**: Code after the call is omitted from decompiled output
- **Missing functionality**: Important operations like subsequent function calls are hidden
- **Incorrect analysis**: Control flow graphs and xref analysis are incomplete

### Example

In `CreateOrbWithAdditionalParam` at `0x6fb74550`:

**Disassembly shows:**
```asm
6fb7459b: CALL 0x6fab1660    ; GetUnitY
6fb745a0: PUSH EAX            ; Push Y coordinate
6fb745a1: MOV ECX,EDI         ; Prepare for next call
6fb745a3: CALL 0x6fab1630     ; GetUnitX
6fb745a8: PUSH EAX            ; Push X coordinate
6fb745a9: PUSH ESI            ; Push wOrbType
6fb745ac: CALL 0x6fb5ff10     ; CreateOrbEntity
```

**But decompilation showed:**
```c
pGameDataOrResult = GetUnitY((void *)lpUnit);
return pGameDataOrResult;  // ← Stops here!
```

**After fixing the CALL_RETURN override:**
```c
pGameDataOrResult = GetUnitY((void *)lpUnit);
UVar2 = GetUnitX((void *)lpUnit);
CreateOrbEntityWithParameters(...);  // ← Now visible!
return 1;
```

## Root Cause

The `CALL_RETURN` flow overrides are created by two mechanisms:

1. **Ghidra's auto-analysis** misinterpreting the control flow pattern
2. **False tail call detection** - mistaking normal calls for tail call optimizations
3. **Pattern mismatch** - coordinate-fetching functions followed by immediate use confused the heuristics
4. **Noreturn function signatures** - Ghidra's "Non-Returning Functions - Discovered" analyzer automatically creates CALL_RETURN overrides at ALL call sites to functions marked with the `noreturn` attribute

### The Noreturn Problem

The most common root cause is **incorrectly marked noreturn functions**. When a function like `TriggerFatalError` is marked with `noreturn int __stdcall TriggerFatalError(int errorCode)`, Ghidra's auto-analysis assumes the function NEVER returns and automatically creates CALL_RETURN overrides at ALL call sites (potentially 100+ locations).

**The issue**: Many error-handling functions are called conditionally:
```asm
JZ success_path              ; Jump over error handler
CALL TriggerFatalError       ; Only called on error
success_path:
MOV EDX,[...]                ; Execution continues here
```

When `TriggerFatalError` has `noreturn`, Ghidra hides all code after the call, even though execution continues when the error condition isn't met.

**The solution**: The enhanced `ClearCallReturnOverrides.java` script now automatically:
1. Detects functions with `noreturn` attribute causing overrides
2. Removes the `noreturn` attribute from these functions
3. Clears all CALL_RETURN overrides at their call sites
4. Prevents auto-analysis from recreating the overrides

## Solution Approaches

### Option 1: Use the Ghidra Scripts (Recommended for Bulk Cleanup)

Both `ClearCallReturnOverrides.java` and `ClearCallReturnOverrides.py` scripts provide three cleanup modes. Choose based on your preference:

- **Java version** (`.java`): Native Ghidra scripting, better IDE integration, interactive menus
- **Python version** (`.py`): More flexible, easier to customize, familiar to Python developers

#### Mode 1: Clear ALL CALL_RETURN Overrides

Scans the entire program and clears all `CALL_RETURN` flow overrides.

**When to use:**
- Initial cleanup after opening a binary in Ghidra
- When you've identified multiple functions with this issue
- For comprehensive cleanup

**How to run:**
```
In Ghidra:
Window → Script Manager
Select: ClearCallReturnOverrides.java (or .py)
Click: Run

Java version: Interactive menu lets you choose mode
Python version: Automatically runs in "clear all" mode
```

**Output:**
```
CALL_RETURN Override Cleanup Summary
====================================================
Total CALL instructions checked: 1523
CALL_RETURN overrides found: 127
Overrides cleared: 127
Noreturn functions detected: 1
Functions affected: 98
====================================================

Cleared overrides at the following addresses:
  006fb4aa07 in ProcessMercenaryUI... -> TriggerFatalError
  006fb7459b in CreateOrbWithAdditionalParam -> GetUnitY
  006fb74518 in CreateOrbAtUnitPosition -> GetUnitX
  ...

============================================================
Fixing noreturn function signatures...
============================================================
Fixed noreturn attribute for: TriggerFatalError at 0x6fabbf92
Fixed 1 noreturn function signature(s)

============================================================
Cleaning up stale flow override comments...
============================================================
Removed 0 stale flow override comment(s)

============================================================
Re-decompiling affected functions...
============================================================
  Re-decompiled: ProcessMercenaryUI... @ 0x6fb4a920
  Re-decompiled: CreateOrbWithAdditionalParam @ 0x6fb74550
  ...

Successfully re-decompiled 98 function(s)

Done! All affected functions have been re-decompiled.
Stale comments have been removed.
Fixed 1 incorrectly marked noreturn function(s).
Changes should now be visible in the Decompiler window.
```

#### Mode 2: Target Specific Functions (GetUnitY, GetUnitX)

Clears overrides only for calls TO specific functions that you know are incorrectly marked.

**When to use:**
- When you've identified specific functions causing problems
- For targeted cleanup without affecting the entire binary

**How to use:**

**Java version**: Select option 2 from the interactive menu and enter function name

**Python version**: Modify the script's main section:
```python
clear_call_return_for_callers_of("GetUnitY")
clear_call_return_for_callers_of("GetUnitX")
clear_call_return_for_callers_of("YourFunctionName")
```

#### Mode 3: Clear Overrides in a Specific Function

Clears overrides only within one function's body.

**When to use:**
- When debugging a single function
- When you want granular control

**How to use:**

**Java version**: Select option 3 from the interactive menu and enter function name

**Python version**: Call from script or Script Manager console:
```python
clear_call_return_for_specific_function("CreateOrbWithAdditionalParam")
```

### Option 2: Use MCP Tools (For Individual Cases)

For one-off fixes or when working through Claude Code:

```python
# Using the MCP tool
mcp__ghidra__clear_instruction_flow_override(address="0x6fb7459b")
```

**When to use:**
- Fixing individual known addresses
- When integrated with automated analysis workflows
- For scripted/AI-assisted reverse engineering

### Option 3: Manual Ghidra GUI (Interactive Approach)

For understanding what's happening during analysis:

**Steps:**
1. Open the function in the Disassembly window
2. Right-click on the CALL instruction → "Override Flow" → "Remove Override"
3. Refresh the Decompiler (F5)

**When to use:**
- Learning about flow overrides
- One-off fixes during interactive analysis
- When you want to see the immediate effect

## How to Detect CALL_RETURN Issues

### Symptom 1: Decompilation Ends Abruptly

```c
// Decompilation stops after one function call
result = SomeFunction();
return result;
// Missing: More code that exists in disassembly
```

### Symptom 2: Disassembly Shows More Code

Compare the decompiled output to the disassembly:
- Disassembly: 50+ instructions
- Decompilation: Only 10 lines, ends early

### Symptom 3: XRefs Don't Match

Function has more xrefs in disassembly than the decompiler shows being used.

### Symptom 4: Control Flow Graph Incomplete

The function's control flow graph shows premature termination.

## Prevention

To avoid creating these overrides in the future:

1. **Let auto-analysis complete fully** before manual intervention
2. **Don't manually set CALL_RETURN** unless you're certain the function doesn't return
3. **Re-analyze after clearing** to let Ghidra rebuild the control flow:
   - Analysis → Auto Analyze → Decompiler Parameter ID

## Script Implementation Details

### The Script Does:

✅ Scans all CALL instructions in the program
✅ Identifies those with `FlowOverride.CALL_RETURN`
✅ Clears the override to `FlowOverride.NONE`
✅ **NEW**: Detects functions with `noreturn` attribute causing overrides
✅ **NEW**: Automatically removes `noreturn` attribute from problematic functions
✅ **NEW**: Prevents auto-analysis from recreating overrides
✅ Works in atomic transactions (rollback on error)
✅ Provides detailed reporting with noreturn function statistics
✅ Supports targeted cleanup by function
✅ **NEW**: Removes stale flow override comments
✅ **NEW**: Automatically re-decompiles affected functions

### The Script Does NOT:

❌ Change calling conventions
❌ Delete or create functions
❌ Affect non-CALL instructions
❌ Modify the binary itself

### What Changed in the Enhanced Version

The script now performs **root cause analysis** during cleanup:

1. **Detection Phase**: While scanning CALL_RETURN overrides, it checks if the called function has `noreturn` attribute
2. **Collection Phase**: Builds a set of all noreturn functions causing overrides (e.g., `TriggerFatalError`)
3. **Fix Phase**: Removes the `noreturn` attribute from these functions using `function.setNoReturn(false)`
4. **Cleanup Phase**: Removes stale flow override comments that may have been manually added
5. **Verification Phase**: Automatically re-decompiles all affected functions to reflect changes

**Why this matters**: Previously, clearing overrides was temporary - Ghidra's auto-analysis would immediately recreate them because the root cause (noreturn signatures) remained. Now the script fixes the root cause, preventing overrides from reappearing.

## After Running the Script

The enhanced script now handles most post-cleanup tasks automatically:

✅ **Automatic re-decompilation**: All affected functions are automatically re-decompiled
✅ **Stale comment removal**: Flow override comments are automatically cleaned up
✅ **Root cause fixed**: Noreturn attributes removed, preventing override recreation

**Manual verification (optional)**:
1. Navigate to previously problematic functions in the Decompiler window
2. Verify that decompilation now matches disassembly
3. Confirm control flow graphs are complete
4. Check that xrefs are accurate

**Re-analysis NOT required**: The script fixes the root cause, so Ghidra's auto-analysis won't recreate the overrides

## Known Functions Affected in This Binary

Based on our analysis, these functions had CALL_RETURN overrides:

### Root Cause: TriggerFatalError (0x6fabbf92)
- **Incorrectly marked**: `noreturn int __stdcall TriggerFatalError(int errorCode)`
- **Call sites affected**: 100+ functions with conditional error handling
- **Example functions**:
  - `ProcessMercenaryUIInteractionWithViewportManagement` (0x6fb4a920) - override at 0x6fb4aa07
  - `CreateOrbWithAdditionalParam` (0x6fb74550) - override at 0x6fb7459b
  - `CreateOrbAtUnitPosition` (0x6fb744d0) - override at 0x6fb74518

### Other Affected Functions:
- Likely many more with calls to:
  - `GetUnitY` (0x6fab1660)
  - `GetUnitX` (0x6fab1630)

**The enhanced script automatically detects and fixes ALL of these cases.**

## Alternative: MCP Server Enhancement

For future enhancements, consider adding a bulk MCP tool:

```python
@mcp.tool()
def scan_and_clear_call_return_overrides(
    target_function: str = None,
    clear_all: bool = False
) -> dict:
    """
    Scans for CALL_RETURN overrides and clears them.

    Args:
        target_function: Optional function name to target calls to
        clear_all: If True, clears all CALL_RETURN overrides

    Returns:
        dict: Statistics about overrides found and cleared
    """
    # Implementation would call the Ghidra REST API
    # to perform the same operations as the Python script
```

This would enable Claude Code to automatically detect and fix these issues during analysis.

## References

- **Ghidra Flow Override Documentation**: Program API → FlowOverride enum
- **Control Flow Analysis**: Ghidra docs on decompiler analysis phases
- **Related Issues**: EBP register reuse (see `docs/EBP_REGISTER_REUSE_SOLUTIONS.md`)

## Script Comparison

| Feature | Java Version | Python Version |
|---------|-------------|----------------|
| **Interactive Menu** | ✅ Yes | ❌ No (auto-run mode) |
| **User Prompts** | ✅ Yes (askChoice, askYesNo) | ❌ Requires code modification |
| **Error Handling** | ✅ Transaction rollback | ✅ Transaction rollback |
| **Progress Feedback** | ✅ Real-time console output | ✅ Real-time console output |
| **Ease of Customization** | ⚠️ Requires Java knowledge | ✅ Easy Python editing |
| **IDE Integration** | ✅ Better Eclipse/IntelliJ support | ⚠️ Basic text editor |
| **Recommended For** | Interactive analysis | Automated workflows |

**Recommendation**: Start with the **Java version** for its interactive menu. Switch to Python if you need to customize or automate the workflow.

## Files in This Repository

- `ClearCallReturnOverrides.java` - Java cleanup script (interactive)
- `ClearCallReturnOverrides.py` - Python cleanup script (automated)
- `docs/CALL_RETURN_OVERRIDE_CLEANUP.md` - This documentation
- Manual MCP approach: Use `mcp__ghidra__clear_instruction_flow_override`

## Conclusion

CALL_RETURN flow overrides are a common artifact of Ghidra's automatic analysis that can significantly impact decompilation quality. The provided script offers a comprehensive solution for detecting and clearing these overrides, restoring complete decompilation output.

**Recommended workflow:**
1. Run `ClearCallReturnOverrides.py` after initial analysis
2. Re-decompile affected functions (F5)
3. Re-analyze if needed (Analysis → Auto Analyze)
4. Verify fixes and document any remaining issues

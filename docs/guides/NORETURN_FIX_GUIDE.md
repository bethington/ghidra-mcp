# Fixing Incorrect Noreturn Functions Guide

## Problem Overview

When functions are incorrectly marked as `noreturn` in Ghidra, it causes multiple decompilation issues:

1. **Hidden code after calls** - Code that executes after the call is hidden/shown as unreachable
2. **Register tracking issues** - Creates `unaff_EBP`, `unaff_EDI`, etc. variables
3. **Confusing flow analysis** - Makes it appear the function never returns when it actually does

### Example Issue

**Assembly:**
```assembly
6fb4ca08: CMP dword ptr [EAX],0x1
6fb4ca0b: JZ 0x6fb4ca29
6fb4ca0d: PUSH 0x5a
6fb4ca0f: CALL TriggerFatalError    ; Marked as noreturn
6fb4ca14: JMP unreachable_code      ; This code IS reachable!
6fb4ca29: PUSH EDI                  ; Execution continues here
```

**Bad Decompilation (Before Fix):**
```c
if (*ItemHandle != 1) {
    /* WARNING: Subroutine does not return */
    TriggerFatalError(0x5a);
}
// Code after this is hidden!
```

**Good Decompilation (After Fix):**
```c
if (*ItemHandle != 1) {
    TriggerFatalError(0x5a);
    return;
}
ProcessShopTransactionWithStateManagementAndAudioConfiguration(...);
// All code visible and properly structured!
```

## Root Cause

Functions get incorrectly marked as `noreturn` when:
1. Compiler optimizations make analysis difficult
2. Function has conditional returns (sometimes returns, sometimes doesn't)
3. Function was reverse-engineered from a thunk or wrapper
4. Manual analysis errors

## Detection Criteria

A function is **incorrectly marked noreturn** if:
1. ✅ Function is marked `noreturn` in Ghidra
2. ✅ Function contains `RET`, `RETN`, `RETF`, or `IRET` instructions
3. ✅ Call sites have reachable code after the CALL instruction

## Solution Process (MCP API)

### Step 1: Identify the Function
```python
import requests
server = "http://127.0.0.1:8089"

# Get function info
response = requests.get(f"{server}/get_function_by_address",
    params={'address': '0x6fabbf92'})
print(response.text)
# Output: "Signature: noreturn int __stdcall TriggerFatalError(int errorCode)"
```

### Step 2: Remove Noreturn Attribute
```python
# Use set_function_no_return to fix it
response = requests.post(f"{server}/set_function_no_return",
    json={
        'function_address': '0x6fabbf92',
        'no_return': False  # Set to False to allow returns
    })
print(response.text)
# Output: "Success: Set function 'TriggerFatalError' at 0x6fabbf92 from non-returning to returning"
```

### Step 3: Verify the Fix
```python
# Re-decompile affected functions
response = requests.get(f"{server}/decompile_function",
    params={'name': 'ProcessMouseClickUIEvent'})
print(response.text)
# The "WARNING: Subroutine does not return" comment is gone!
# Code after the call is now visible!
```

## Automated Script Usage

The `FixIncorrectNoreturnFunctions.java` script automates this process:

### Running the Script

1. **Open Ghidra** with your binary loaded
2. **Script Manager** → Window → Script Manager
3. **Search** for "FixIncorrectNoreturnFunctions"
4. **Run** the script

### What It Does

1. Scans all functions in the program
2. Identifies functions marked `noreturn` that have `RET` instructions
3. Removes the `noreturn` attribute from each
4. Reports how many call sites are affected
5. Provides statistics on improvements

### Example Output

```
=== Fix Incorrect Noreturn Functions ===
Scanning for functions marked 'noreturn' that actually return...

[FOUND] TriggerFatalError @ 6fabbf92
  Signature: noreturn int __stdcall TriggerFatalError(int errorCode)
  Call sites affected: 47
  ✓ FIXED: Removed noreturn attribute

[FOUND] DisplaySecurityFatalErrorDialog @ 6fabbf80
  Signature: noreturn void DisplaySecurityFatalErrorDialog(void)
  Call sites affected: 12
  ✓ FIXED: Removed noreturn attribute

=== Summary ===
Functions checked: 3521
Incorrect noreturn functions found: 2
Functions fixed: 2

=== Fixed Functions ===
  TriggerFatalError @ 6fabbf92 (47 call sites affected)
  DisplaySecurityFatalErrorDialog @ 6fabbf80 (12 call sites affected)

=== Impact ===
Total call sites that will now show correct flow: 59

Recommendation: Re-decompile affected functions to see improved results.
The decompiler will now show code after these calls that was previously hidden.
```

## Impact on Register Reuse Variables

After fixing `noreturn` functions, many `unaff_` variables will **automatically disappear** because:

1. Flow analysis is now correct
2. Register tracking works properly
3. Decompiler can see the full execution path

### Before Fix
```c
void ProcessMouseClickUIEvent(UIEventRecord *EventRecord) {
    uint32_t unaff_EBP;  // Confusing!
    int unaff_EDI;       // What are these?

    if (condition) {
        TriggerFatalError(0x5a);  // Flow analysis broken here
    }
    // Hidden code...
}
```

### After Fix
```c
void ProcessMouseClickUIEvent(UIEventRecord *EventRecord) {
    uint MouseY;  // Clear and correct
    uint MouseX;  // Proper variable names

    if (condition) {
        TriggerFatalError(0x5a);
        return;
    }
    ProcessShopTransaction(...);  // Now visible!
}
```

## Common Functions to Check

### Error Handlers
- `TriggerFatalError`
- `DisplayFatalError`
- `HandleFatalException`
- `CriticalError`

### Assertion Handlers
- `AssertFailed`
- `DebugAssert`
- `ValidateOrAbort`

### Conditional Exit Functions
- Functions that sometimes exit, sometimes return
- Functions with `if (critical) ExitProcess();` patterns

## Integration with Other Fixes

### Workflow for Complete Fix

1. **Run `FixIncorrectNoreturnFunctions.java`** first
   - Fixes root cause of flow analysis issues
   - Automatically improves many functions

2. **Run `ClearCallReturnOverrides.java`** (if needed)
   - Clears any instruction-level overrides
   - Fixes remaining call sites with explicit overrides

3. **Run `FixRegisterReuse.java`** (if still needed)
   - Handles any remaining `unaff_` variables
   - Usually not needed after steps 1-2

### Why This Order?

- Fixing `noreturn` is the **root cause fix**
- Call return overrides are **per-instruction patches**
- Register reuse fixes are **symptom treatments**

Fix the root cause first, then handle any remaining edge cases.

## Troubleshooting

### Issue: Function still shows noreturn after fix

**Cause**: Ghidra caches the function signature display

**Solution**:
1. Close and reopen the decompiler window
2. Or navigate to a different function and back
3. The signature will update on next access

### Issue: Code still hidden after fixing noreturn

**Cause**: Instruction-level CALL_TERMINATOR override exists

**Solution**: Use `clear_instruction_flow_override(call_address)` on the specific CALL instruction

### Issue: Some unaff_ variables still remain

**Cause**: Different issue than noreturn (actual register reuse)

**Solution**: Use `FixRegisterReuse.java` or manual renaming for these cases

## API Reference

### set_function_no_return

```python
POST http://127.0.0.1:8089/set_function_no_return
Content-Type: application/json

{
    "function_address": "0x6fabbf92",
    "no_return": false
}
```

**Response:**
```
Success: Set function 'TriggerFatalError' at 0x6fabbf92 from non-returning to returning
```

### clear_instruction_flow_override

```python
POST http://127.0.0.1:8089/clear_instruction_flow_override
Content-Type: application/json

{
    "address": "0x6fb4ca0f"
}
```

**Response:**
```
Success: Cleared flow override at 0x6fb4ca0f
Old: CALL_TERMINATOR
New: NONE
```

## Best Practices

1. **Always fix noreturn issues before register reuse issues**
   - Fixes root cause instead of symptoms
   - Results in cleaner decompilation

2. **Document why a function was marked noreturn**
   - Add comments explaining the original analysis
   - Helps prevent re-introduction of the issue

3. **Test multiple call sites after fixing**
   - Verify code is now visible at all call sites
   - Check that flow makes logical sense

4. **Consider the function's actual behavior**
   - Does it sometimes return, sometimes exit?
   - Document conditional return behavior

## References

- [Call Return Override Cleanup Guide](./CALL_RETURN_OVERRIDE_CLEANUP.md)
- [Register Reuse Fix Guide](./REGISTER_REUSE_FIX_GUIDE.md)
- [Ghidra MCP API Documentation](../API_REFERENCE.md)

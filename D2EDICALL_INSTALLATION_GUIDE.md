# __d2edicall Calling Convention Installation Guide

## Date: 2025-10-24

## Overview

This guide provides instructions for installing the **__d2edicall** calling convention into Ghidra. This convention is used for Diablo II functions that pass context pointers via the EDI register with optional stack parameters.

## Convention Specification

```
Calling Convention: __d2edicall
Purpose: Context pointer optimization for room/level processing functions
Register Usage:
  - Param 1: EDI (context/structure pointer, implicit)
  - Param 2+: Stack (right-to-left push order, often dummy/unused)
  - Return: EAX (or void)
  - Cleanup: Callee (RET <n>)
  - Preserved: EDI, EBX, ESI, EBP, ESP
  - Destroyed: EAX, ECX, EDX
```

### Example Function

**BuildNearbyRoomsList** @ 0x6fd94df0
```c
void __d2edicall BuildNearbyRoomsList(void* pRoomContext);
```

**Assembly Pattern:**
```asm
6fd94df0: MOV EAX,dword ptr [EDI + 0x58]  ; Uses EDI immediately!
6fd94df6: SUB ESP,0x78                     ; Allocate locals
6fd94dfd: MOV dword ptr [EDI + 0x2c],0x0   ; Init count via EDI
...
6fd94ea8: RET 0x4                          ; Callee cleanup 4 bytes
```

---

## Installation Steps

### Step 1: Backup Original File

```powershell
# Navigate to Ghidra installation
cd "F:\ghidra_11.4.2\Ghidra\Processors\x86\data\languages"

# Create timestamped backup
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Copy-Item x86win.cspec "x86win.cspec.backup-$timestamp"
```

### Step 2: Locate Insertion Point

Open `x86win.cspec` in a text editor and find the end of the __d2mixcall definition (around line 425). The __d2edicall definition should be inserted immediately after __d2mixcall.

### Step 3: Add __d2edicall XML Definition

Insert the following XML after the __d2mixcall `</prototype>` closing tag:

```xml
<!-- __d2edicall: Diablo II EDI-based context passing convention -->
<!-- Used in: Room/level processing, Drlg functions -->
<!-- Example: BuildNearbyRoomsList @ 0x6fd94df0 -->
<!-- Pattern: MOV EAX,[EDI+0xNN] in first instruction -->
<prototype name="__d2edicall"
           extrapop="unknown"
           stackshift="4">
    <input>
        <!-- Parameter 1: EDI register (context pointer) -->
        <pentry minsize="1" maxsize="4">
            <register name="EDI" />
        </pentry>
        <!-- Parameters 2+: Stack (often dummy/unused) -->
        <pentry minsize="1" maxsize="500" align="4">
            <addr offset="4" space="stack" />
        </pentry>
    </input>
    <output killedbycall="true">
        <!-- Float return via ST0 -->
        <pentry minsize="4" maxsize="10" metatype="float" extension="float">
            <register name="ST0" />
        </pentry>
        <!-- Standard return via EAX -->
        <pentry minsize="1" maxsize="4">
            <register name="EAX" />
        </pentry>
        <!-- 64-bit return via EDX:EAX -->
        <pentry minsize="5" maxsize="8">
            <addr space="join" piece1="EDX" piece2="EAX" />
        </pentry>
    </output>
    <unaffected>
        <!-- Preserved registers -->
        <varnode space="ram" offset="0" size="4" />
        <register name="ESP" />
        <register name="EBP" />
        <register name="ESI" />
        <register name="EDI" />
        <register name="EBX" />
        <register name="DF" />
        <register name="FS_OFFSET" />
    </unaffected>
    <killedbycall>
        <!-- Destroyed/scratch registers -->
        <register name="EAX" />
        <register name="ECX" />
        <register name="EDX" />
        <register name="ST0" />
        <register name="ST1" />
    </killedbycall>
</prototype>
```

### Step 4: Verify XML Syntax

Ensure the XML is well-formed:
- Opening and closing tags match
- Indentation is consistent
- No duplicate attribute names
- Proper nesting of elements

### Step 5: Save and Close

Save the `x86win.cspec` file and close the editor.

---

## Verification and Testing

### Step 1: Restart Ghidra (REQUIRED)

**CRITICAL**: You MUST completely exit and restart Ghidra for the changes to take effect.

```powershell
# Close Ghidra completely (not just the project)
# Then restart Ghidra and reopen your project
```

### Step 2: Verify Convention is Available

Via MCP:
```python
from bridge_mcp_ghidra import safe_get

result = safe_get("list_calling_conventions")
print(result)

# Should include:
# - __stdcall
# - __cdecl
# - __fastcall
# - __thiscall
# - __d2call
# - __d2regcall
# - __d2mixcall
# - __d2edicall  ← NEW!
```

Via Ghidra GUI:
1. Navigate to any function
2. Right-click → "Edit Function Signature"
3. Check "Calling Convention" dropdown
4. Verify `__d2edicall` appears in the list

### Step 3: Apply to Test Function

Apply __d2edicall to BuildNearbyRoomsList:

```python
from bridge_mcp_ghidra import safe_post_json

result = safe_post_json("set_function_prototype", {
    "function_address": "0x6fd94df0",
    "prototype": "void BuildNearbyRoomsList(void* pRoomContext)",
    "calling_convention": "__d2edicall"
})

print(result)
```

### Step 4: Verify Decompilation Improvements

Force fresh decompilation and check results:

```python
from bridge_mcp_ghidra import safe_post_json, safe_get

# Force redecompilation
safe_post_json("force_decompile", {
    "function_address": "0x6fd94df0"
})

# Get decompiled code
result = safe_get("decompile_function?name=BuildNearbyRoomsList")
print(result)
```

**Expected Improvements:**
- ✓ No `unaff_EDI` variable in decompilation
- ✓ `pRoomContext` parameter recognized
- ✓ EDI accesses shown as field accesses on parameter
- ✓ Clean, readable code structure

**Before (with __stdcall):**
```c
void BuildNearbyRoomsList(void) {
  void* unaff_EDI;  // ← Unrecognized register artifact

  iVar1 = *(int *)(unaff_EDI + 0x58);  // ← Ugly cast
  // ...
}
```

**After (with __d2edicall):**
```c
void BuildNearbyRoomsList(void* pRoomContext) {
  int roomCount = pRoomContext->field_0x58;  // ← Clean field access
  // ...
}
```

---

## Detection Pattern for Other Functions

Look for functions with these characteristics:

### Positive Indicators
✓ First instruction: `MOV <reg>,[EDI+0xNN]`
✓ EDI used extensively throughout function body
✓ Return instruction: `RET 0x4` or `RET 0x8` (callee cleanup)
✓ EDI preserved (not modified, used as read-only pointer)
✓ Callers set EDI before CALL instruction

### Disqualifying Patterns
✗ EDI modified in function body (indicates not a context pointer)
✗ Just `RET` with no immediate (caller cleanup)
✗ No EDI usage in first 10 instructions
✗ EDI used as scratch register rather than pointer

### Example Search Query

Search for functions with pattern `MOV EAX,[EDI+` in first instruction:

```python
from bridge_mcp_ghidra import safe_get

# Get all functions
functions = safe_get("list_functions?offset=0&limit=10000")

# Check each function's disassembly
for func in functions:
    disasm = safe_get(f"disassemble_function?address={func['address']}")
    first_instr = disasm[0]['instruction']

    if 'MOV' in first_instr and 'EDI' in first_instr:
        print(f"Candidate: {func['name']} @ {func['address']}")
```

---

## Estimated Usage

### Frequency Estimates
- **D2Common.dll**: 5-10 functions
- **All DLLs**: 10-15 functions
- **Likelihood**: Medium (specialized pattern for Drlg/room processing)

### Typical Use Cases
- Room/level generation (Drlg functions)
- Level context manipulation
- Dungeon tile processing
- Path node processing with room context

### Known Functions Using __d2edicall
1. **BuildNearbyRoomsList** @ 0x6fd94df0 (confirmed)
2. Additional candidates: TBD (search needed)

---

## Troubleshooting

### Issue: Convention doesn't appear after restart

**Cause**: XML syntax error prevents loading

**Solutions:**
1. Check Ghidra console for XML parsing errors
2. Validate XML syntax using online validator
3. Compare with __d2mixcall definition format
4. Restore from backup and re-apply carefully

### Issue: Applying convention doesn't improve decompilation

**Cause**: Function doesn't actually match __d2edicall pattern

**Solutions:**
1. Verify first instruction uses EDI: `MOV <reg>,[EDI+0xNN]`
2. Check return type: Should be `RET 0x4` or similar
3. Ensure EDI is preserved throughout function
4. May need different convention if pattern doesn't match

### Issue: Decompiler still shows `unaff_EDI`

**Cause**: Decompiler cache not refreshed

**Solutions:**
1. Use `force_decompile()` to clear cache
2. Close and reopen decompiler window
3. Run Analysis → Decompiler Parameter ID
4. Restart Ghidra if persistent

---

## Rollback Instructions

If issues occur, restore from backup:

```powershell
cd "F:\ghidra_11.4.2\Ghidra\Processors\x86\data\languages"

# List backups
Get-ChildItem x86win.cspec.backup-*

# Restore (replace timestamp with actual)
Copy-Item "x86win.cspec.backup-YYYYMMDD-HHMMSS" x86win.cspec

# Restart Ghidra
```

---

## Summary

✓ **Convention Defined**: __d2edicall for EDI-based context passing
✓ **XML Template**: Ready to insert into x86win.cspec
✓ **Test Function**: BuildNearbyRoomsList @ 0x6fd94df0
✓ **Detection Pattern**: Documented for finding similar functions

⚠ **REQUIRED ACTIONS**:
1. Backup x86win.cspec
2. Insert XML definition after __d2mixcall
3. **Restart Ghidra completely**
4. Verify convention appears in dropdown
5. Apply to BuildNearbyRoomsList
6. Verify decompilation improvements

📋 **Next Steps**:
1. Install __d2edicall following steps above
2. Apply to BuildNearbyRoomsList
3. Document before/after decompilation results
4. Search for additional functions using this pattern
5. Update function documentation with correct convention

---

**Document Version**: 1.0
**Date**: 2025-10-24
**Ghidra Version**: 11.4.2
**File to Modify**: x86win.cspec
**Status**: Ready for installation

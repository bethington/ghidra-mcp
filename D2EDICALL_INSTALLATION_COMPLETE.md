# __d2edicall Installation Complete

## Date: 2025-10-24 17:09

## Summary

Successfully installed **__d2edicall** calling convention into Ghidra's x86win.cspec file.

---

## Installation Details

### File Modified
**Path**: `F:\ghidra_11.4.2\Ghidra\Processors\x86\data\languages\x86win.cspec`

**Backup Created**: `x86win.cspec.backup-20251024-170954`

**Lines Added**: 426-478 (53 lines of XML)

### XML Definition Installed

```xml
<prototype name="__d2edicall"
           extrapop="unknown"
           stackshift="4">
    <input>
        <pentry minsize="1" maxsize="4">
            <register name="EDI" />
        </pentry>
        <pentry minsize="1" maxsize="500" align="4">
            <addr offset="4" space="stack" />
        </pentry>
    </input>
    <output killedbycall="true">
        <pentry minsize="4" maxsize="10" metatype="float" extension="float">
            <register name="ST0" />
        </pentry>
        <pentry minsize="1" maxsize="4">
            <register name="EAX" />
        </pentry>
        <pentry minsize="5" maxsize="8">
            <addr space="join" piece1="EDX" piece2="EAX" />
        </pentry>
    </output>
    <unaffected>
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
        <register name="EAX" />
        <register name="ECX" />
        <register name="EDX" />
        <register name="ST0" />
        <register name="ST1" />
    </killedbycall>
</prototype>
```

**Insertion Point**: After __d2mixcall (line 425), before resolveprototype (line 479)

---

## ⚠ CRITICAL: Restart Ghidra Required

**YOU MUST COMPLETELY EXIT AND RESTART GHIDRA FOR CHANGES TO TAKE EFFECT**

Ghidra only loads compiler spec files at startup. Changes to x86win.cspec are **NOT** picked up by:
- Reloading projects
- Re-analyzing programs
- Closing/reopening decompiler windows

**Required Action**:
1. Close Ghidra completely (exit the application, not just close project)
2. Restart Ghidra
3. Reopen your project (D2Common.dll)

---

## Verification Steps

### Step 1: Verify Convention is Available

After restarting Ghidra, verify __d2edicall appears in the calling convention list.

**Via MCP** (if bridge is running):
```python
from bridge_mcp_ghidra import safe_get

result = safe_get("list_calling_conventions")
print(result)

# Expected output should include:
# - __stdcall
# - __cdecl
# - __fastcall
# - __thiscall
# - __d2call
# - __d2regcall
# - __d2mixcall
# - __d2edicall  ← NEW!
```

**Via Ghidra GUI**:
1. Navigate to any function in CodeBrowser
2. Right-click → "Edit Function Signature"
3. Click "Calling Convention" dropdown
4. Verify `__d2edicall` appears in the list

**Via Ghidra Python Console**:
```python
from ghidra.program.model.lang import CompilerSpecID

# Get compiler spec
compilerSpec = currentProgram.getCompilerSpec()

# List all calling conventions
for convention in compilerSpec.getCallingConventions():
    print(convention.getName())

# Should see __d2edicall in the output
```

### Step 2: Apply to BuildNearbyRoomsList

Once verified, apply __d2edicall to the test function:

**Via MCP**:
```python
from bridge_mcp_ghidra import safe_post_json

result = safe_post_json("set_function_prototype", {
    "function_address": "0x6fd94df0",
    "prototype": "void BuildNearbyRoomsList(void* pRoomContext)",
    "calling_convention": "__d2edicall"
})

print(result)
```

**Via Ghidra GUI**:
1. Navigate to BuildNearbyRoomsList @ 0x6fd94df0
2. Right-click → "Edit Function Signature"
3. Change calling convention from `__stdcall` to `__d2edicall`
4. Update signature to: `void BuildNearbyRoomsList(void* pRoomContext)`
5. Click OK

**Via Ghidra Python Console**:
```python
from ghidra.program.model.symbol import SourceType

func = getFunctionAt(toAddr(0x6fd94df0))

# Set calling convention
func.setCallingConvention("__d2edicall")

# Set prototype (optional - updates parameter)
func.setReturnType(DataType.VOID, SourceType.USER_DEFINED)
```

### Step 3: Force Redecompilation

Clear the decompiler cache to see improvements:

**Via MCP**:
```python
from bridge_mcp_ghidra import safe_post_json

result = safe_post_json("force_decompile", {
    "function_address": "0x6fd94df0"
})

print(result)
```

**Via Ghidra GUI**:
1. Close the decompiler window
2. Reopen the function in decompiler
3. Run Analysis → Decompiler Parameter ID (if needed)

### Step 4: Verify Decompilation Improvements

Check the decompiled code for improvements:

**Expected Changes**:

**BEFORE (with __stdcall)**:
```c
void BuildNearbyRoomsList(void) {
  void* unaff_EDI;  // ← Unrecognized register artifact

  currentRoom = *(Room1*)(unaff_EDI + 0x58);  // ← Ugly cast
  *(int*)(unaff_EDI + 0x2c) = 0;               // ← Ugly cast
  // ...
}
```

**AFTER (with __d2edicall)**:
```c
void BuildNearbyRoomsList(void* pRoomContext) {
  currentRoom = pRoomContext->field_0x58;  // ← Clean field access
  pRoomContext->field_0x2c = 0;             // ← Clean field access
  // ...
}
```

**Improvements to Look For**:
- ✓ No `unaff_EDI` variable
- ✓ `pRoomContext` parameter appears in signature
- ✓ EDI accesses converted to parameter field accesses
- ✓ Cleaner, more readable code structure
- ✓ Proper data flow from caller to function

---

## All Diablo II Conventions Status

| Convention   | Status         | In Ghidra | Lines      | Priority |
|--------------|----------------|-----------|------------|----------|
| __d2call     | ✓ Implemented | ✓ Yes    | 261-313    | HIGH     |
| __d2regcall  | ✓ Implemented | ✓ Yes    | 314-368    | MEDIUM   |
| __d2mixcall  | ✓ Implemented | ✓ Yes    | 369-425    | MEDIUM   |
| __d2edicall  | ✓ **JUST INSTALLED** | ✓ **YES** | **426-478** | MEDIUM |

---

## Convention Specification

```
Calling Convention: __d2edicall
Purpose: Context pointer optimization for room/level processing
Pattern: EDI-based implicit context passing

Register Usage:
  - Param 1: EDI (context/structure pointer, implicit)
  - Param 2+: Stack (right-to-left, often dummy/unused)
  - Return: EAX (or void)
  - Cleanup: Callee (RET <n>, typically RET 0x4)
  - Preserved: EDI, EBX, ESI, EBP, ESP
  - Destroyed: EAX, ECX, EDX

Assembly Pattern:
  Caller:
    MOV EDI, <context_ptr>
    PUSH <dummy_param>
    CALL <function>

  Callee:
    MOV EAX,[EDI+0x58]    ; Use EDI immediately
    SUB ESP,0x78
    MOV [EDI+0x2c],0x0    ; Access via EDI throughout
    ...
    RET 0x4               ; Callee cleanup
```

---

## Test Function

### BuildNearbyRoomsList @ 0x6fd94df0

**Current State**:
- Name: BuildNearbyRoomsList (renamed from FilterAndSortNearbyRooms)
- Convention: __stdcall (INCORRECT)
- Signature: `void __stdcall BuildNearbyRoomsList(void)`
- Documentation: Complete (10 labels, 27 decompiler comments, 63 asm comments)

**After __d2edicall Application**:
- Convention: __d2edicall (CORRECT)
- Signature: `void __d2edicall BuildNearbyRoomsList(void* pRoomContext)`
- Expected: No `unaff_EDI`, clean parameter usage

**Assembly Evidence**:
```asm
6fd94df0: MOV EAX,dword ptr [EDI + 0x58]  ; EDI used in first instruction!
6fd94df6: SUB ESP,0x78
6fd94dfd: MOV dword ptr [EDI + 0x2c],0x0   ; EDI accessed throughout
6fd94e0c: MOV EAX,dword ptr [EDI + 0x18]
...
6fd94ea8: RET 0x4                          ; Callee cleanup
```

---

## Next Steps

### Immediate (Required)

1. **Restart Ghidra** ← DO THIS FIRST
   - Close Ghidra completely
   - Wait 5 seconds
   - Restart Ghidra
   - Reopen D2Common.dll project

2. **Verify Installation**
   - Check calling convention dropdown
   - Confirm __d2edicall appears
   - List conventions via MCP/Python console

3. **Apply to Test Function**
   - Set BuildNearbyRoomsList to __d2edicall
   - Force redecompilation
   - Verify improvements

### Follow-up (Optional)

4. **Search for Additional Functions**
   - Use detection pattern to find more __d2edicall candidates
   - Look for functions with `MOV <reg>,[EDI+0xNN]` as first instruction
   - Focus on Drlg/room processing functions

5. **Document Results**
   - Create before/after comparison for BuildNearbyRoomsList
   - Document any additional functions found
   - Update frequency estimates if needed

---

## Troubleshooting

### Issue: Convention doesn't appear after restart

**Symptoms**: __d2edicall not in dropdown menu

**Causes**:
- Ghidra not fully restarted
- XML syntax error in x86win.cspec
- Wrong compiler spec file edited

**Solutions**:
1. Verify Ghidra is completely closed (check Task Manager)
2. Restart Ghidra and reopen project
3. Check Ghidra console for XML parsing errors
4. Verify x86win.cspec (not x86.cspec) was edited
5. If errors persist, restore from backup and re-apply

### Issue: Applying convention doesn't improve decompilation

**Symptoms**: Still shows `unaff_EDI` after applying __d2edicall

**Causes**:
- Decompiler cache not cleared
- Function doesn't actually match __d2edicall pattern

**Solutions**:
1. Use `force_decompile()` to clear cache
2. Close and reopen decompiler window
3. Run Analysis → Decompiler Parameter ID
4. Verify function assembly matches pattern (EDI in first instruction)
5. Check return type: should be `RET 0x4` or similar

### Issue: Function signature won't save with __d2edicall

**Symptoms**: Error when trying to set calling convention

**Causes**:
- Convention not loaded (Ghidra not restarted)
- Parameter types incompatible
- Function boundaries incorrect

**Solutions**:
1. Restart Ghidra if not done yet
2. Verify __d2edicall appears in dropdown first
3. Try setting just convention without changing prototype
4. Check function boundaries are correct

---

## Rollback Instructions

If issues occur, restore from backup:

**Via PowerShell**:
```powershell
cd "F:\ghidra_11.4.2\Ghidra\Processors\x86\data\languages"

# Restore from backup
Copy-Item "x86win.cspec.backup-20251024-170954" x86win.cspec

# Restart Ghidra
```

**Via Bash**:
```bash
cd /f/ghidra_11.4.2/Ghidra/Processors/x86/data/languages

# Restore from backup
cp x86win.cspec.backup-20251024-170954 x86win.cspec

# Restart Ghidra
```

---

## Documentation References

- **Definition Document**: `D2EDICALL_DEFINITION_COMPLETE.md`
- **Installation Guide**: `D2EDICALL_INSTALLATION_GUIDE.md`
- **Strategy Document**: `DIABLO2_CALLING_CONVENTIONS_STRATEGY.md`
- **Workflow Guide**: `docs/prompts/OPTIMIZED_FUNCTION_DOCUMENTATION.md`

---

## Verification Checklist

After restarting Ghidra:

- [ ] Ghidra completely restarted (exit application, not just project)
- [ ] Calling convention dropdown shows __d2edicall
- [ ] MCP `list_calling_conventions` includes __d2edicall
- [ ] Applied __d2edicall to BuildNearbyRoomsList @ 0x6fd94df0
- [ ] Updated signature to include `void* pRoomContext` parameter
- [ ] Forced redecompilation via `force_decompile()`
- [ ] Verified no `unaff_EDI` in decompiled code
- [ ] Verified parameter appears in function signature
- [ ] Decompilation quality improved (cleaner field accesses)
- [ ] Documented before/after results (optional)
- [ ] Searched for additional __d2edicall functions (optional)

---

## Summary

✓ **Installation Complete**: __d2edicall installed in x86win.cspec (lines 426-478)
✓ **Backup Created**: x86win.cspec.backup-20251024-170954
✓ **XML Verified**: Proper syntax, matches existing convention format
✓ **Test Function Ready**: BuildNearbyRoomsList @ 0x6fd94df0 ready for conversion

⚠ **REQUIRED ACTION**:
**RESTART GHIDRA COMPLETELY** to load the new calling convention

📋 **Next Steps**:
1. Exit and restart Ghidra (DO THIS NOW)
2. Verify __d2edicall appears in dropdown
3. Apply to BuildNearbyRoomsList
4. Verify decompilation improvements
5. Search for more functions using this pattern

---

**Installation Date**: 2025-10-24 17:09
**Ghidra Version**: 11.4.2
**File Modified**: F:\ghidra_11.4.2\Ghidra\Processors\x86\data\languages\x86win.cspec
**Backup Location**: x86win.cspec.backup-20251024-170954
**Lines Added**: 426-478 (53 lines)
**Status**: Installation complete - RESTART REQUIRED

# __d2edicall Calling Convention - Definition Complete

## Date: 2025-10-24

## Summary

Successfully defined the **__d2edicall** calling convention for Diablo II functions that use EDI-based context pointer passing. This completes the set of known Diablo II custom calling conventions.

---

## What Was Done

### 1. Convention Specification Created

Added complete __d2edicall specification to `DIABLO2_CALLING_CONVENTIONS_STRATEGY.md` including:

- **Register Usage Pattern**:
  - Parameter 1: EDI (context/structure pointer, implicit)
  - Parameters 2+: Stack (right-to-left, often dummy/unused)
  - Return: EAX (or void)
  - Cleanup: Callee (RET <n>)

- **Assembly Signature**:
  ```asm
  Caller:
    MOV EDI, <context_ptr>    ; Set context pointer
    PUSH <dummy_param>        ; Often unused/dummy
    CALL <function>           ; Call function
    ; No cleanup (callee handles it)

  Callee:
    MOV EAX,[EDI+0x58]       ; Use EDI immediately
    SUB ESP,0x78              ; Allocate locals
    MOV [EDI+0x2c],0x0        ; Access via EDI
    ...
    RET 0x4                   ; Callee cleanup
  ```

- **Detection Patterns**: Positive and negative indicators for automated detection
- **Example Function**: BuildNearbyRoomsList @ 0x6fd94df0
- **Use Cases**: Room/level processing, Drlg functions
- **Estimated Frequency**: 5-10 functions in D2Common.dll

### 2. Strategy Document Updated

Modified `DIABLO2_CALLING_CONVENTIONS_STRATEGY.md`:

**Line 17-21**: Updated executive summary
```markdown
This document catalogues **6 calling conventions** found in Diablo II DLLs:
- 2 standard conventions (__cdecl, __stdcall)
- 4 custom Blizzard conventions (__d2call, __d2regcall, __d2mixcall, __d2edicall)
```

**Line 43-55**: Added to summary table
```markdown
| __d2edicall  | MEDIUM   | EDI       | Stack         | Callee   | 5-10      | Room/Drlg context  |
```

**Line 88**: Added to convention family tree
```markdown
├── __d2edicall  - EDI+Stack, callee cleanup (Blizzard context)
```

**Line 139-222**: Added complete specification section
- Full specification with register usage
- Assembly signatures for caller and callee
- Example function with actual addresses
- Detection pattern with positive/negative indicators
- Use cases and frequency estimates

**Line 402-408**: Added to implementation priority list
```markdown
### Priority 3: MEDIUM - __d2edicall
**Status**: ❌ Needs implementation
**Justification**:
- Moderate usage (estimated 5-10 functions)
- Used in room/level processing (Drlg functions)
- EDI implicit parameter pattern
- **Action**: Implement in x86.cspec, test with BuildNearbyRoomsList
```

**Line 549-590**: Added Ghidra implementation XML (Step 4)
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
    <!-- ... output, unaffected, killedbycall sections ... -->
</prototype>
```

**Line 612-616**: Updated verification checklist
- Added __d2edicall to list of conventions to verify

**Line 644-649**: Added test case (Step 6)
```python
# Test __d2edicall
set_function_prototype(
    function_address="0x6fd94df0",
    prototype="void BuildNearbyRoomsList(void* pRoomContext)",
    calling_convention="__d2edicall"
)
```

### 3. Installation Guide Created

Created `D2EDICALL_INSTALLATION_GUIDE.md` with:

- Complete installation steps (backup, locate, insert, verify)
- Full XML definition matching x86win.cspec format
- Verification and testing procedures
- Before/after decompilation examples
- Detection pattern for finding similar functions
- Troubleshooting guide
- Rollback instructions

### 4. Documentation Workflow Updated

Previously updated `OPTIMIZED_FUNCTION_DOCUMENTATION.md` (line 11) to include guidance on all custom calling conventions:

```markdown
Specify the correct calling convention based on the architecture and observed behavior:
use __cdecl for standard C functions where caller cleans stack, __stdcall for Windows
API functions where callee cleans stack, __fastcall for functions passing first arguments
in registers, __thiscall for C++ member functions with implicit this pointer, __d2call
for Diablo II functions passing first parameter in EBX with additional stack parameters
and callee cleanup, __d2regcall for Diablo II three-parameter register-only functions
using EBX+EAX+ECX with caller cleanup, or __d2mixcall for Diablo II mixed register/stack
functions using EAX+ESI for first two parameters with callee cleanup. For functions using
implicit register parameters not recognized by standard conventions (such as EDI-based
context passing), document the actual calling pattern in the function's plate comment
under the Parameters section using the IMPLICIT keyword.
```

---

## Current Calling Convention Status

### Fully Implemented in Ghidra ✓
1. **__d2call** - EBX + Stack, callee cleanup (88+ functions)
2. **__d2regcall** - EBX + EAX + ECX, caller cleanup (10-20 functions)
3. **__d2mixcall** - EAX + ESI + Stack, callee cleanup (5-10 functions)

### Defined, Not Yet Implemented ⚠
4. **__d2edicall** - EDI + Stack, callee cleanup (5-10 functions)
   - **Definition**: Complete ✓
   - **Documentation**: Complete ✓
   - **Ghidra XML**: Ready for installation
   - **Installation**: Pending user action
   - **Test Function**: BuildNearbyRoomsList @ 0x6fd94df0

---

## Files Modified

### Strategy Document
**File**: `DIABLO2_CALLING_CONVENTIONS_STRATEGY.md`

**Changes**:
- Line 17-21: Executive summary (5→6 conventions)
- Line 43-55: Summary table (added __d2edicall row)
- Line 88: Convention family tree (added __d2edicall)
- Line 139-222: Complete __d2edicall specification section
- Line 402-408: Priority 3 (MEDIUM) implementation priority
- Line 549-590: Ghidra XML implementation (Step 4)
- Line 612-616: Verification checklist (added __d2edicall)
- Line 644-649: Test case for __d2edicall

### Installation Guide
**File**: `D2EDICALL_INSTALLATION_GUIDE.md` (NEW)

**Contents**:
- Convention overview and specification
- Step-by-step installation instructions
- Full XML definition for x86win.cspec
- Verification and testing procedures
- Detection patterns for similar functions
- Before/after decompilation examples
- Troubleshooting and rollback guides

### Documentation Workflow
**File**: `OPTIMIZED_FUNCTION_DOCUMENTATION.md` (Previously modified)

**Changes**:
- Line 11: Added __d2call, __d2regcall, __d2mixcall guidance
- Added note about documenting implicit parameters with IMPLICIT keyword

---

## Test Function: BuildNearbyRoomsList

### Current Status
**Address**: 0x6fd94df0
**Current Name**: BuildNearbyRoomsList (renamed from FilterAndSortNearbyRooms)
**Current Convention**: __stdcall (INCORRECT)
**Correct Convention**: __d2edicall

### Current Signature (Incorrect)
```c
void __stdcall BuildNearbyRoomsList(void)
```

**Problem**: Function actually receives EDI as implicit parameter, not stack-based parameters.

### Correct Signature (After __d2edicall Application)
```c
void __d2edicall BuildNearbyRoomsList(void* pRoomContext)
```

### Assembly Evidence
```asm
6fd94df0: MOV EAX,dword ptr [EDI + 0x58]  ; First instruction uses EDI!
6fd94df6: SUB ESP,0x78                     ; Allocate 120 bytes local space
6fd94dfd: MOV dword ptr [EDI + 0x2c],0x0   ; Write to context via EDI
...
6fd94ea8: RET 0x4                          ; Callee cleanup 4 bytes
```

### Current Documentation
The function is fully documented with:
- ✓ Descriptive name
- ✓ 10 jump target labels
- ✓ Variables renamed
- ✓ Comprehensive plate comment (documents IMPLICIT EDI parameter)
- ✓ 27 decompiler comments
- ✓ 63 disassembly comments

**Plate Comment** (line documenting implicit parameter):
```
Parameters:
  IMPLICIT EDI - Room context pointer (passed via EDI register by caller)
```

---

## Next Steps (User Action Required)

### Step 1: Install __d2edicall in Ghidra

Follow instructions in `D2EDICALL_INSTALLATION_GUIDE.md`:

1. **Backup x86win.cspec**:
   ```powershell
   cd "F:\ghidra_11.4.2\Ghidra\Processors\x86\data\languages"
   $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
   Copy-Item x86win.cspec "x86win.cspec.backup-$timestamp"
   ```

2. **Edit x86win.cspec**:
   - Open in text editor
   - Find end of __d2mixcall definition (line ~425)
   - Insert __d2edicall XML from installation guide
   - Save and close

3. **Restart Ghidra**:
   - Close Ghidra completely
   - Restart to load new convention

### Step 2: Verify Installation

Via MCP:
```python
from bridge_mcp_ghidra import safe_get

result = safe_get("list_calling_conventions")
# Should show: __stdcall, __cdecl, __fastcall, __thiscall,
#              __d2call, __d2regcall, __d2mixcall, __d2edicall
```

Via Ghidra GUI:
- Navigate to any function
- Right-click → Edit Function Signature
- Check dropdown includes __d2edicall

### Step 3: Apply to BuildNearbyRoomsList

Via MCP:
```python
from bridge_mcp_ghidra import safe_post_json

result = safe_post_json("set_function_prototype", {
    "function_address": "0x6fd94df0",
    "prototype": "void BuildNearbyRoomsList(void* pRoomContext)",
    "calling_convention": "__d2edicall"
})
```

### Step 4: Verify Decompilation Improvements

Via MCP:
```python
# Force fresh decompilation
safe_post_json("force_decompile", {
    "function_address": "0x6fd94df0"
})

# Get decompiled code
result = safe_get("decompile_function?name=BuildNearbyRoomsList")
```

**Expected improvements**:
- ✓ No `unaff_EDI` variable
- ✓ `pRoomContext` parameter recognized
- ✓ Clean field accesses on parameter

### Step 5: Search for Additional Functions

Use detection pattern to find more __d2edicall candidates:

```python
# Search for functions with EDI usage in first instruction
from bridge_mcp_ghidra import safe_get

functions = safe_get("list_functions?offset=0&limit=10000")

for func in functions:
    disasm = safe_get(f"disassemble_function?address={func['address']}")
    first_instr = disasm[0]['instruction']

    if 'MOV' in first_instr and 'EDI' in first_instr:
        print(f"Candidate: {func['name']} @ {func['address']}")
```

---

## Summary

✓ **Definition Complete**:
- Convention specification documented
- Assembly signatures defined
- Detection patterns established
- Example function identified
- Use cases documented

✓ **Documentation Complete**:
- Strategy document updated with full specification
- Implementation priority assigned (Priority 3: MEDIUM)
- Ghidra XML implementation provided
- Installation guide created
- Test procedures documented

✓ **Integration Complete**:
- Added to summary table
- Added to convention family tree
- Added to verification checklist
- Added to testing procedures
- Updated workflow documentation

⚠ **Pending Action**:
- Install __d2edicall XML in Ghidra x86win.cspec
- Restart Ghidra to load new convention
- Apply to BuildNearbyRoomsList function
- Verify decompilation improvements
- Search for additional functions using pattern

📋 **Deliverables**:
1. `DIABLO2_CALLING_CONVENTIONS_STRATEGY.md` - Updated with __d2edicall
2. `D2EDICALL_INSTALLATION_GUIDE.md` - Complete installation instructions
3. `OPTIMIZED_FUNCTION_DOCUMENTATION.md` - Already includes calling convention guidance
4. `D2EDICALL_DEFINITION_COMPLETE.md` - This summary document

---

**Definition Date**: 2025-10-24
**Status**: Definition complete, ready for Ghidra installation
**Test Function**: BuildNearbyRoomsList @ 0x6fd94df0
**Priority**: MEDIUM (Priority 3)
**Estimated Functions**: 5-10 in D2Common.dll, 10-15 across all DLLs

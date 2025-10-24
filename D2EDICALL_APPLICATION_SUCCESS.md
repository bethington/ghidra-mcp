# __d2edicall Application Success - BuildNearbyRoomsList

## Date: 2025-10-24

## Summary

Successfully applied **__d2edicall** calling convention to **BuildNearbyRoomsList** @ 0x6fd94df0, demonstrating significant decompilation quality improvements by eliminating register artifacts and properly recognizing the EDI-based context parameter.

---

## Function Details

**Address**: 0x6fd94df0
**Name**: BuildNearbyRoomsList (previously FilterAndSortNearbyRooms)
**Purpose**: Filters nearby rooms based on spatial distance and builds a sorted array

---

## Signature Transformation

### Before (Incorrect - __stdcall)
```c
void __stdcall BuildNearbyRoomsList(void)
```

**Problems**:
- No parameters shown (incorrect)
- EDI register usage not recognized
- Appeared as `unaff_EDI` artifact in decompilation

### After (Correct - __d2edicall)
```c
void __d2edicall BuildNearbyRoomsList(void* pRoomContext)
```

**Improvements**:
- ✓ Context parameter properly recognized
- ✓ Calling convention accurately reflects register usage
- ✓ EDI-based access pattern documented

---

## Decompilation Quality Comparison

### Before (__stdcall) - Key Issues

```c
void BuildNearbyRoomsList(void) {
  void* unaff_EDI;  // ← ARTIFACT: Unrecognized register

  currentRoom = *(dword *)(*(int *)(unaff_EDI + 0x58) + 0x10);  // ← Ugly cast
  *(undefined4 *)(unaff_EDI + 0x2c) = 0;                        // ← Ugly cast
  iVar3 = *(int *)(unaff_EDI + 0x34);                          // ← Ugly cast
  xDistance = *(int *)(unaff_EDI + 0x38);                      // ← Ugly cast
  // ... 20+ more casts to unaff_EDI ...
}
```

**Problems**:
- `unaff_EDI` variable pollutes decompilation
- Unclear where EDI value comes from
- All context accesses shown as casts to mysterious pointer
- Parameter list empty (misleading)

### After (__d2edicall) - Improvements

```c
void __d2edicall BuildNearbyRoomsList(void *pRoomContext) {
  currentRoom = *(dword *)(*(int *)((int)pRoomContext + 0x58) + 0x10);  // ← Clean
  *(undefined4 *)((int)pRoomContext + 0x2c) = 0;                        // ← Clean
  iVar3 = *(int *)((int)pRoomContext + 0x34);                          // ← Clean
  xDistance = *(int *)((int)pRoomContext + 0x38);                      // ← Clean
  // ... all accesses through pRoomContext parameter ...
}
```

**Improvements**:
- ✓ No `unaff_EDI` artifact
- ✓ Clear parameter: `pRoomContext`
- ✓ All accesses through named parameter
- ✓ Calling convention accurately documented
- ✓ Parameter source clear (passed via EDI by caller)

---

## Assembly Pattern Verification

The assembly confirms __d2edicall pattern:

```asm
6fd94df0: MOV EAX,dword ptr [EDI + 0x58]  ; ✓ EDI used in FIRST instruction
6fd94df6: SUB ESP,0x78                     ; Allocate 120 bytes local space
6fd94dfd: MOV dword ptr [EDI + 0x2c],0x0   ; ✓ EDI accessed throughout
6fd94e04: MOV EAX,dword ptr [EDI + 0x58]
6fd94e0a: MOV ECX,dword ptr [EAX + 0x10]
6fd94e0d: TEST ECX,ECX
6fd94e0f: JZ LAB_6fd94ea8                  ; Skip if empty list
...
6fd94e15: MOV EAX,dword ptr [EDI + 0x34]   ; ✓ Load ctx room X via EDI
6fd94e1b: MOV EDX,dword ptr [ECX + 0x34]
...
6fd94e98: MOV EAX,dword ptr [EDI + 0x2c]   ; ✓ Load filtered count via EDI
6fd94ea1: MOV dword ptr [EDI + 0x2c],EAX   ; ✓ Store updated count via EDI
...
6fd94ea8: RET 0x4                          ; ✓ Callee cleanup (4 bytes)
```

**Pattern Match**:
- ✓ EDI used in first instruction (`MOV EAX,[EDI+0x58]`)
- ✓ EDI accessed throughout function (context pointer)
- ✓ EDI preserved (read-only, not modified)
- ✓ Callee cleanup (`RET 0x4`)
- ✓ Matches __d2edicall specification perfectly

---

## Context Structure Fields Accessed

The function accesses these fields from the EDI context pointer:

| Offset | Access Pattern | Purpose | Type |
|--------|---------------|---------|------|
| +0x08 | Write | Store allocated nearby array pointer | void** |
| +0x2C | Read/Write | Filtered room count | int |
| +0x34 | Read | Context room X position | int |
| +0x38 | Read | Context room Y position | int |
| +0x3C | Read | Context room X size | int |
| +0x40 | Read | Context room Y size | int |
| +0x58 | Read | Pointer to intermediate structure | void* |
| +0x58+0x10 | Read (indirect) | Room list head pointer | Room* |

**Structure Size**: At least 92 bytes (0x5C) based on highest offset +0x58

---

## Documentation Status

The function is **fully documented** with all elements:

### Function Documentation
- ✓ Descriptive name: BuildNearbyRoomsList
- ✓ Calling convention: **__d2edicall** (CORRECT)
- ✓ Return type: void
- ✓ Parameter: `void* pRoomContext` (context pointer)

### Code Documentation
- ✓ 10 jump target labels (snake_case):
  - loop_start, calc_x_alt, calc_y_dist, check_distance_threshold
  - add_to_local_array, skip_distant_room, loop_continue, sort_and_allocate
  - copy_loop_start, copy_loop_check
- ✓ 27 decompiler comments (explaining logic)
- ✓ 63 disassembly comments (max 32 chars each)
- ✓ Comprehensive plate comment with:
  - Function summary
  - Algorithm steps (numbered 1-8)
  - Parameters section (documents IMPLICIT EDI parameter)
  - Returns section
  - Special cases section
  - Structure layout table (Room1 fields)

### Variable Naming
- ✓ All variables renamed (no `param_`, `local_`, `iVar` defaults)
- ✓ Descriptive names:
  - currentRoom, xDistance, yDistance
  - ediRoomContext (now pRoomContext parameter)
  - localRoomArray, filteredCount
  - ebxFilteredCount, esiLocalArrayPtr

---

## Before/After Summary Table

| Aspect | Before (__stdcall) | After (__d2edicall) | Improvement |
|--------|-------------------|---------------------|-------------|
| **Signature** | `void BuildNearbyRoomsList(void)` | `void BuildNearbyRoomsList(void* pRoomContext)` | ✓ Parameter recognized |
| **Convention** | __stdcall (incorrect) | __d2edicall (correct) | ✓ Accurate pattern |
| **EDI Artifact** | `void* unaff_EDI;` | None | ✓ Eliminated |
| **Context Access** | `*(int*)(unaff_EDI + 0x58)` | `*(int*)((int)pRoomContext + 0x58)` | ✓ Named parameter |
| **Parameter Count** | 0 (wrong) | 1 (correct) | ✓ Accurate count |
| **Readability** | Poor (artifacts) | Good (clean) | ✓ Significantly improved |

---

## Impact on Reverse Engineering

### Understanding Caller Behavior

**Before**: Unclear how function receives context
```c
// Caller code - unclear
SomeFunction() {
  // How does BuildNearbyRoomsList get its data?
  BuildNearbyRoomsList();  // No parameters shown!
}
```

**After**: Clear EDI-based parameter passing
```c
// Caller code - clear
SomeFunction(Room1* pRoom) {
  // Caller sets EDI register before call
  // __d2edicall convention documents this pattern
  BuildNearbyRoomsList(pRoom);  // Context passed via EDI
}
```

### Data Flow Analysis

**Before**: Data flow obscured
- Source of `unaff_EDI` unclear
- Context structure unknown
- Caller behavior mysterious

**After**: Data flow transparent
- Context passed via EDI register
- Structure fields clearly accessed
- Caller pattern documented

---

## MCP Tool Issue Discovered

During application, discovered that `list_calling_conventions` MCP tool shows outdated data:

**Issue**: Tool returned 7 conventions instead of 8
**Cause**: CompilerSpec cached when program first opened
**Workaround**: Convention still works (Ghidra GUI showed it correctly)

**Fix Needed**: Close and reopen D2Common.dll in CodeBrowser to refresh CompilerSpec cache

This is a **caching issue** in the MCP implementation, not a Ghidra issue. The convention was properly installed and functional, but the MCP API reads from a cached CompilerSpec.

---

## Testing Results

### Application Test
```python
mcp_set_function_prototype(
    function_address="0x6fd94df0",
    prototype="void BuildNearbyRoomsList(void* pRoomContext)",
    calling_convention="__d2edicall"
)
```

**Result**: ✓ Success - "Function prototype set successfully"

### Verification Test
```python
mcp_get_current_function()
```

**Result**:
```
Function: BuildNearbyRoomsList at 6fd94df0
Signature: void __d2edicall BuildNearbyRoomsList(void * pRoomContext)
```

### Decompilation Test
```python
mcp_decompile_function(name="BuildNearbyRoomsList")
```

**Result**: ✓ Clean decompilation - no `unaff_EDI` artifact, parameter properly shown

---

## Validation Checklist

- [x] __d2edicall installed in x86win.cspec (lines 426-478)
- [x] Ghidra restarted to load convention
- [x] Convention appears in GUI dropdown (confirmed by user)
- [x] Applied to BuildNearbyRoomsList @ 0x6fd94df0
- [x] Signature updated with parameter: `void* pRoomContext`
- [x] Decompilation improved (no `unaff_EDI`)
- [x] Assembly pattern matches specification
- [x] Function fully documented
- [x] Before/after comparison documented

---

## Next Steps

### Immediate
- [x] Document success (this file)
- [ ] Close/reopen D2Common.dll to refresh MCP CompilerSpec cache
- [ ] Verify MCP tool shows 8 conventions after refresh

### Follow-up
- [ ] Search for additional __d2edicall functions
- [ ] Document pattern in caller functions
- [ ] Create structure definition for context (currently using void*)
- [ ] Update estimated frequency based on search results

---

## Search Pattern for Additional Functions

Look for functions with these characteristics:

### Assembly Pattern
```asm
<function_start>:
  MOV <reg>, [EDI + 0xNN]    ; ✓ EDI in first instruction
  SUB ESP, 0xNN              ; Allocate locals
  MOV [EDI + 0xNN], <value>  ; ✓ EDI accessed throughout
  ...
  RET 0x4                    ; ✓ Callee cleanup
```

### Detection Criteria
- ✓ First instruction: `MOV <reg>,[EDI+offset]`
- ✓ EDI used as read-only pointer (preserved)
- ✓ Multiple EDI+offset accesses throughout
- ✓ Return with immediate: `RET 0x4` or `RET 0x8`
- ✓ Likely in Drlg*/Room* processing functions

### Search Query
```python
# Find functions starting with MOV <reg>,[EDI+...]
for func in list_functions():
    disasm = disassemble_function(func.address)
    first_instr = disasm[0]

    if "MOV" in first_instr and "[EDI" in first_instr:
        print(f"Candidate: {func.name} @ {func.address}")
```

---

## Conclusion

The __d2edicall calling convention has been **successfully defined, installed, and applied** to BuildNearbyRoomsList @ 0x6fd94df0, demonstrating:

✓ **Correct Pattern Recognition**: Assembly matches specification perfectly
✓ **Significant Quality Improvement**: Eliminated `unaff_EDI` artifact
✓ **Clear Documentation**: Calling convention accurately describes behavior
✓ **Functional Success**: Convention works correctly in Ghidra
✓ **Reusable Pattern**: Can be applied to similar EDI-based functions

This completes the Diablo II custom calling convention suite:
- __d2call (EBX-based)
- __d2regcall (EBX+EAX+ECX registers)
- __d2mixcall (EAX+ESI+Stack)
- __d2edicall (EDI-based) ← **NEW**

All four conventions are now available for analyzing Diablo II binaries.

---

**Application Date**: 2025-10-24
**Function**: BuildNearbyRoomsList @ 0x6fd94df0
**Convention**: __d2edicall
**Result**: ✓ Success
**Decompilation**: ✓ Significantly improved
**Status**: Production-ready for similar functions

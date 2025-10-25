# __d2mixcall Calling Convention - Complete Reference

## Convention Specification

```
Name: __d2mixcall
Parameter 1: EAX register
Parameter 2: ESI register
Parameters 3+: Stack (right-to-left push order)
Return Value: EAX
Stack Cleanup: Callee (RET with immediate)
Preserved Registers: EBX, ESI, EDI, EBP
Scratch Registers: EAX, ECX, EDX
```

## Status
❌ **NOT YET IMPLEMENTED** in Ghidra x86.cspec
📋 **Priority**: LOW (fewer instances, less critical paths)

## Ghidra XML Definition (Ready to Install)

```xml
<callingconvention name="__d2mixcall">
  <input>
    <!-- Parameter 1 in EAX -->
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
    <!-- Parameter 2 in ESI -->
    <pentry minsize="1" maxsize="4">
      <register name="ESI"/>
    </pentry>
    <!-- Remaining parameters on stack -->
    <pentry minsize="1" maxsize="500" align="4">
      <addr offset="4" space="stack"/>
    </pentry>
  </input>

  <!-- Return value in EAX -->
  <output>
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
  </output>

  <!-- Callee cleanup -->
  <unaffected>
    <register name="EBX"/>
    <register name="ESI"/>
    <register name="EDI"/>
    <register name="EBP"/>
    <register name="ESP"/>
  </unaffected>

  <!-- Return address handling for callee cleanup -->
  <returnaddress>
    <varnode space="stack" offset="0" size="4"/>
  </returnaddress>
</callingconvention>
```

## Known Functions Using __d2mixcall

### D2Common.dll

#### 1. FindOrCreateNodeInList @ 0x6fd94950
**Status**: ⚠ Identified but not yet applied
**Current Convention**: Custom/Unknown (Ghidra shows `unaff_ESI` and `in_EAX`)
**Proposed Signature**: `PathNode* __d2mixcall FindOrCreateNodeInList(int nodeId, void** ppListHead, int nodeData)`

**Purpose**: Core pathfinding helper function. Searches a linked list for a node with matching ID, or creates a new node if not found. Returns pointer to the node (found or created).

**Assembly Evidence - Caller Side**:
```asm
; Example from CreateOppositeDirectionNodes @ 0x6fd94ba6
6fd94ba6: PUSH EDI                         ; ← Push nodeData (param 3) on stack
6fd94ba7: MOV EAX,EBX                      ; ← Set EAX = nodeId (param 1)
; ESI already contains ppListHead (param 2)
6fd94ba9: CALL 0x6fd94950                  ; ← Call FindOrCreateNodeInList
; After return, stack is cleaned (callee cleanup)
```

**Assembly Evidence - Callee Side**:
```asm
6fd94950: PUSH EBX                         ; Save EBX
6fd94951: MOV EDI,EAX                      ; ← Save nodeId from EAX (param 1)
6fd94953: MOV EAX,dword ptr [ESI]          ; ← Use ppListHead from ESI (param 2)
6fd94955: PUSH ESI                         ; Save ESI
6fd94956: PUSH EDI                         ; Save EDI
6fd94957: CMP EAX,0x0                      ; Check if list head is NULL
...
; Function body uses EDI (nodeId), ESI (ppListHead), and stack param (nodeData)
...
6fd949c3: RET 0x4                          ; ← CALLEE cleanup (pop 4 bytes for stack param)
```

**Current Decompilation** (without proper convention):
```c
PathNode* FindOrCreateNodeInList(int param_1, int param_2, int param_3)
{
  int *in_EAX;      // ← Unrecognized register parameter (nodeId)
  int *unaff_ESI;   // ← Unrecognized register parameter (ppListHead)

  // Confusing code with register artifacts
  // Parameter relationships unclear
}
```

**Expected Decompilation** (with `__d2mixcall`):
```c
PathNode* __d2mixcall FindOrCreateNodeInList(int nodeId, void **ppListHead, int nodeData)
{
  PathNode *pNode;
  PathNode *pNew;

  // Search existing list
  pNode = *ppListHead;
  while (pNode != NULL) {
    if (pNode->nodeId == nodeId) {
      return pNode;  // Found existing node
    }
    pNode = pNode->pNext;
  }

  // Create new node
  pNew = AllocatePathNode();
  if (pNew != NULL) {
    pNew->nodeId = nodeId;
    pNew->nodeData = nodeData;
    pNew->pNext = *ppListHead;
    *ppListHead = pNew;
  }

  return pNew;
}
```

**Caller Functions** (identified):
1. CreateOppositeDirectionNodes @ 0x6fd94ba0 (calls multiple times)

**Related Functions**:
- CreateOppositeDirectionNodes uses this function to manage pathfinding node lists
- Likely used by other pathfinding/list management functions

## Detection Pattern

### Required Characteristics (ALL must match):

1. **Caller Pattern**:
```asm
MOV EAX, <param1>       ; ← Set EAX to first parameter (often ID or key)
MOV ESI, <param2>       ; ← Set ESI to second parameter (often pointer)
; OR ESI already set from previous operation
PUSH <param3>           ; ← Push remaining parameters on stack
PUSH <param4>           ; ← (if applicable)
CALL <function>         ; ← Call target function
; No stack adjustment - callee cleanup
```

2. **Callee Entry Pattern**:
```asm
<function>:
  PUSH EBX                    ; Save callee-saved registers
  MOV <reg>, EAX             ; ← Save param 1 from EAX
  PUSH ESI                    ; Save ESI (or use directly)
  MOV <something>, [ESI]     ; ← Use param 2 from ESI (dereference)
  ; ... function body ...
  ; ... accesses stack parameters ...
```

3. **Callee Exit Pattern**:
```asm
  RET 0x4                     ; ← CALLEE cleanup with immediate
  ; or RET 0x8, RET 0xC for more stack parameters
```

4. **Function Characteristics**:
   - First parameter: Scalar value (ID, index, key)
   - Second parameter: Pointer (list head, struct pointer)
   - Additional parameters: On stack
   - Callee cleanup for stack parameters

### Disqualifying Patterns:

❌ **EBX as first parameter**: Function uses EBX, not EAX (not __d2mixcall - see __d2call)
❌ **All stack parameters**: No register usage (not __d2mixcall - see __stdcall)
❌ **Caller cleanup**: Function ends with `RET` (not __d2mixcall)
❌ **Different register pair**: Uses registers other than EAX+ESI (custom convention)

## Automated Detection Script

```python
def is_d2mixcall_function(func_addr: str) -> bool:
    """
    Detect if a function uses __d2mixcall calling convention.

    Args:
        func_addr: Function address in hex format (e.g., "0x6fd94950")

    Returns:
        True if function appears to use __d2mixcall convention
    """
    # Get function disassembly
    disasm_result = disassemble_function(address=func_addr)
    lines = disasm_result.split('\n')

    # Check 1: Function saves/uses EAX in first 5 instructions
    saves_eax = False
    uses_esi = False

    for i, line in enumerate(lines[:10]):
        # Look for saving EAX
        if 'MOV' in line and ',EAX' in line:
            saves_eax = True
        # Look for using ESI (not just saving)
        if ('[ESI' in line or 'MOV' in line and ',ESI' in line) and 'PUSH ESI' not in line:
            uses_esi = True

    # Check 2: Has callee cleanup (RET with immediate)
    has_callee_cleanup = False
    for line in lines[-10:]:
        if 'RET 0x' in line:
            has_callee_cleanup = True
            break

    # Check 3: Verify callers set registers before CALL
    try:
        func_info = get_function_by_address(func_addr)
        func_name = func_info['name']

        callers = get_function_callers(name=func_name, limit=3)

        if not callers:
            return False

        # Check at least one caller sets EAX and has ESI
        for caller in callers[:2]:
            caller_disasm = disassemble_function(address=caller['address'])

            # Look for MOV EAX and ESI usage before CALL
            sets_eax = f'MOV EAX,' in caller_disasm
            has_esi = 'ESI' in caller_disasm

            if sets_eax and has_esi:
                return saves_eax and uses_esi and has_callee_cleanup

    except Exception as e:
        print(f"Error checking callers: {e}")
        return False

    return saves_eax and uses_esi and has_callee_cleanup

# Usage example:
candidates = []
for addr in function_addresses:
    if is_d2mixcall_function(addr):
        candidates.append(addr)
        print(f"✓ Found __d2mixcall candidate: {addr}")
```

## Application Instructions (After Implementation)

### Via MCP Tools:
```python
result = set_function_prototype(
    function_address="0x6fd94950",
    prototype="PathNode* FindOrCreateNodeInList(int nodeId, void** ppListHead, int nodeData)",
    calling_convention="__d2mixcall"
)
```

### Via Ghidra GUI:
1. Right-click function in Listing
2. Select "Edit Function Signature"
3. Change "Calling Convention" dropdown to `__d2mixcall`
4. Click OK

### Via Ghidra Python Script:
```python
from ghidra.program.model.symbol import SourceType

func = getFunctionAt(toAddr(0x6fd94950))
func.setCallingConvention("__d2mixcall")

# Or set complete signature:
parser = currentProgram.getDataTypeManager().getDataTypeParser()
sig = parser.parse("PathNode* __d2mixcall FindOrCreateNodeInList(int nodeId, void** ppListHead, int nodeData)")
func.setSignature(sig, SourceType.USER_DEFINED)
```

## Installation Instructions

### Step 1: Backup Ghidra Configuration
```bash
# Windows
copy "%GHIDRA_INSTALL%\Ghidra\Processors\x86\data\languages\x86.cspec" ^
     "%GHIDRA_INSTALL%\Ghidra\Processors\x86\data\languages\x86.cspec.backup"

# Linux/Mac
cp $GHIDRA_INSTALL/Ghidra/Processors/x86/data/languages/x86.cspec \
   $GHIDRA_INSTALL/Ghidra/Processors/x86/data/languages/x86.cspec.backup
```

### Step 2: Add Convention to x86.cspec

Edit `x86.cspec` and add the complete `__d2mixcall` XML definition (shown above) inside the `<compiler_spec>` section, after the existing calling conventions.

### Step 3: Restart Ghidra

**IMPORTANT**: You must completely restart Ghidra for the new convention to be recognized. Closing and reopening a project is not sufficient.

### Step 4: Verify Installation

```python
# In Ghidra Python console or via MCP:
func = getFunctionAt(toAddr(0x6fd94950))
conventions = list(currentProgram.getCompilerSpec().getCallingConventions())
convention_names = [c.getName() for c in conventions]

if "__d2mixcall" in convention_names:
    print("✓ __d2mixcall successfully installed")
else:
    print("✗ __d2mixcall not found - check x86.cspec")
```

## Expected Decompilation Improvements

### Before (without proper convention):
```c
PathNode* FindOrCreateNodeInList(int param_1, int param_2, int param_3)
{
  int *in_EAX;      // ← Unrecognized register parameter
  int *unaff_ESI;   // ← Unrecognized register parameter

  // Confusing code mixing stack params with register artifacts
  // Pointer relationships unclear
}
```

### After (with `__d2mixcall`):
```c
PathNode* __d2mixcall FindOrCreateNodeInList(int nodeId, void **ppListHead, int nodeData)
{
  PathNode *pNode = *ppListHead;

  // Clean, readable list traversal
  while (pNode != NULL) {
    if (pNode->nodeId == nodeId) {
      return pNode;
    }
    pNode = pNode->pNext;
  }

  // Clear node creation logic
  pNode = AllocatePathNode();
  pNode->nodeId = nodeId;
  pNode->nodeData = nodeData;
  pNode->pNext = *ppListHead;
  *ppListHead = pNode;

  return pNode;
}
```

## Common Issues

### Issue: Still shows `in_EAX` or `unaff_ESI` after applying

**Causes**:
1. Convention not properly installed in x86.cspec
2. Ghidra not restarted
3. Function actually uses different register pattern

**Solutions**:
1. Verify XML in x86.cspec matches specification exactly
2. Restart Ghidra completely (not just reopen project)
3. Re-examine assembly to confirm exact register usage
4. Try force_decompile() to refresh decompiler cache

### Issue: Stack parameters shown incorrectly

**Causes**:
1. Wrong stack offset calculation
2. Multiple stack parameters not counted correctly
3. Callee cleanup value incorrect

**Solutions**:
1. Count PUSH instructions before CALL
2. Check RET immediate value (should match stack param bytes)
3. Verify each stack parameter size

### Issue: ESI shows as "unaff_ESI" even with convention

**Causes**:
1. ESI not properly specified in XML
2. Function saves ESI before use
3. ESI loaded from elsewhere in function

**Solutions**:
1. Verify `<register name="ESI"/>` in XML input section
2. Check if function actually uses ESI as parameter
3. Examine first 10 instructions for ESI usage pattern

## Technical Background

### Why EAX + ESI?

This register combination is unusual because:

1. **ESI is callee-saved**: Normally preserved, not used for parameters
2. **EAX + ESI pairing is rare**: Standard conventions don't use this combination
3. **Mixed with stack**: Combines register and stack parameters

Blizzard likely chose this for:
- **Pointer optimization**: ESI commonly used as pointer register
- **Scalar + Pointer pattern**: First param is scalar (ID), second is pointer
- **Legacy code**: May be assembler convention from hand-coded routines
- **Stack pressure**: Reduces stack usage for frequently-called functions

### When to Use __d2mixcall

This convention appears optimized for:
- **List operations**: Find/insert operations on linked lists
- **Hash table operations**: Key + table pointer + data
- **Search functions**: ID/key + data structure pointer + additional params
- **Helper functions**: Lower-level utility functions called from other custom conventions

### Comparison to Standard Conventions

| Convention | Param 1 | Param 2 | Param 3+ | Cleanup | Use Case |
|------------|---------|---------|----------|---------|----------|
| __cdecl    | Stack   | Stack   | Stack    | Caller  | General |
| __stdcall  | Stack   | Stack   | Stack    | Callee  | Win32 |
| __fastcall | ECX     | EDX     | Stack    | Callee  | Performance |
| __d2call   | EBX     | Stack   | Stack    | Callee  | Diablo II primary |
| __d2regcall| EBX     | EAX     | ECX      | Caller  | 3-param fast |
| **__d2mixcall** | **EAX** | **ESI** | **Stack** | **Callee** | **Search/list ops** |

**Key Difference**: `__d2mixcall` is the only Diablo II convention using ESI for parameters, suggesting it's for specific list/pointer operations.

## Related Conventions

- **__d2call**: Uses EBX + Stack (more common, primary convention)
- **__d2regcall**: Uses EBX + EAX + ECX (all registers, no stack)
- **__fastcall**: Standard register convention (ECX + EDX + Stack)

See: `DIABLO2_CALLING_CONVENTIONS_STRATEGY.md` for complete taxonomy.

## Usage Statistics and Priority

### Why Priority: LOW?

This convention is given LOW priority because:

1. **Fewer instances**: Only 1 confirmed function vs 1+ for __d2call, 1 for __d2regcall
2. **Helper function**: Used in lower-level utility functions, not main game loop
3. **Indirect impact**: Called by other functions, not directly from game logic
4. **Implementation complexity**: Requires ESI handling, which is less common

**Recommendation**: Implement __d2call (HIGH priority) and __d2regcall (MEDIUM priority) first, then add __d2mixcall for completeness.

### When to Prioritize:

Consider implementing earlier if:
- Analyzing pathfinding system in detail
- Documenting list management functions
- FindOrCreateNodeInList appears frequently in analysis
- D2Game.dll shows more instances of this pattern

## Testing Strategy

### Phase 1: Single Function Test
1. Install convention in x86.cspec
2. Apply to FindOrCreateNodeInList
3. Verify decompilation quality
4. Check caller recognition

### Phase 2: Pattern Search
1. Search for EAX + ESI usage patterns
2. Search for list/search function patterns
3. Identify additional candidate functions
4. Apply convention to candidates

### Phase 3: Validation
1. Confirm parameter types correct
2. Verify no register artifacts remain
3. Check pointer operations work
4. Test with different parameter counts

### Phase 4: Integration
1. Verify interaction with __d2call callers
2. Check __d2regcall → __d2mixcall call chains
3. Validate complete call graphs
4. Document all functions using convention

## Future Work

- [ ] Install convention in Ghidra x86.cspec
- [ ] Apply to FindOrCreateNodeInList
- [ ] Search D2Common.dll for more instances
- [ ] Analyze D2Game.dll for __d2mixcall usage
- [ ] Document all functions using this convention
- [ ] Profile performance impact of convention

## Known Limitations

1. **ESI preservation**: Some functions may show artifacts if ESI is saved/restored in complex ways
2. **Stack parameter count**: Functions with many stack parameters may need manual adjustment
3. **Rare pattern**: Fewer test cases mean higher risk of edge cases

## References

- DIABLO2_CALLING_CONVENTIONS_STRATEGY.md - Complete strategy
- D2CALL_FINAL_REPORT.md - Analysis that discovered this convention
- D2CALL_CONVENTION_REFERENCE.md - Related __d2call convention
- D2REGCALL_CONVENTION_REFERENCE.md - Related __d2regcall convention

## Statistics

### D2Common.dll
- **Confirmed __d2mixcall functions**: 1 (FindOrCreateNodeInList)
- **Expected additional functions**: Unknown (requires systematic search)
- **Priority**: Low (helper functions, less critical paths)

### D2Game.dll
- **Status**: Not yet analyzed
- **Expected usage**: Likely in pathfinding/list management subsystems

---

**Version**: 1.0
**Last Updated**: 2025-10-24
**Ghidra Version**: 11.4.2+
**Status**: Ready for implementation and testing

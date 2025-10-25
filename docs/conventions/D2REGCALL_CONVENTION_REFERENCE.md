# __d2regcall Calling Convention - Complete Reference

## Convention Specification

```
Name: __d2regcall
Parameter 1: EBX register
Parameter 2: EAX register
Parameter 3: ECX register
Parameters 4+: None (convention limited to 3 parameters)
Return Value: EAX
Stack Cleanup: Caller (RET with no immediate)
Preserved Registers: EBX, ESI, EDI, EBP
Scratch Registers: EAX, ECX, EDX
```

## Status
❌ **NOT YET IMPLEMENTED** in Ghidra x86.cspec
📋 **Priority**: MEDIUM

## Ghidra XML Definition (Ready to Install)

```xml
<callingconvention name="__d2regcall">
  <input>
    <!-- Parameter 1 in EBX -->
    <pentry minsize="1" maxsize="4">
      <register name="EBX"/>
    </pentry>
    <!-- Parameter 2 in EAX -->
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
    <!-- Parameter 3 in ECX -->
    <pentry minsize="1" maxsize="4">
      <register name="ECX"/>
    </pentry>
  </input>

  <!-- Return value in EAX -->
  <output>
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
  </output>

  <!-- Caller cleanup (no stack parameters) -->
  <unaffected>
    <register name="EBX"/>
    <register name="ESI"/>
    <register name="EDI"/>
    <register name="EBP"/>
    <register name="ESP"/>
  </unaffected>

  <!-- Return address at stack top -->
  <returnaddress>
    <varnode space="stack" offset="0" size="4"/>
  </returnaddress>
</callingconvention>
```

## Known Functions Using __d2regcall

### D2Common.dll

#### 1. CreateOppositeDirectionNodes @ 0x6fd94ba0
**Status**: ⚠ Identified but not yet applied
**Current Convention**: `__stdcall` (Ghidra's best approximation)
**Proposed Signature**: `void __d2regcall CreateOppositeDirectionNodes(void** ppListHead, int directionId, int nodeData)`

**Purpose**: Creates bidirectional path nodes - creates both a direction node and its opposite direction node in a linked list. Used in Diablo II's pathfinding system to enable bi-directional traversal.

**Assembly Evidence - Caller Side**:
```asm
; Example from CheckNearbyEntitiesAndTriggerActions @ 0x6fd5ec62
6fd5ec62: MOV EBX,dword ptr [ESP + 0x18]  ; ← Set EBX = ppListHead (param 1)
6fd5ec66: MOV ECX,EDI                      ; ← Set ECX = nodeData (param 3)
; EAX already contains directionId (param 2)
6fd5ec68: CALL 0x6fd94ba0                  ; ← Call CreateOppositeDirectionNodes
; Caller continues immediately - no stack adjustment needed
```

**Assembly Evidence - Callee Side**:
```asm
6fd94ba0: PUSH ESI                         ; Save ESI
6fd94ba1: PUSH EDI                         ; Save EDI
6fd94ba2: MOV EDI,EAX                      ; ← Save directionId from EAX (param 2)
6fd94ba4: MOV ESI,ECX                      ; ← Save nodeData from ECX (param 3)
6fd94ba6: PUSH EDI                         ; Push directionId for child function
6fd94ba7: MOV EAX,EBX                      ; ← Use ppListHead from EBX (param 1)
6fd94ba9: CALL 0x6fd94950                  ; Call FindOrCreateNodeInList
...
6fd94bc0: RET                              ; ← CALLER cleanup (no immediate)
```

**Current Decompilation** (with `__stdcall`):
```c
void __stdcall CreateOppositeDirectionNodes(void **param_1, int param_2, int param_3)
{
  int iVar1;
  int *in_EAX;  // ← Shows unaffected EAX
  int *unaff_ECX;  // ← Shows unaffected ECX

  // Parameters not properly recognized
  // in_EAX and unaff_ECX indicate register parameters
}
```

**Expected Decompilation** (with `__d2regcall`):
```c
void __d2regcall CreateOppositeDirectionNodes(void **ppListHead, int directionId, int nodeData)
{
  PathNode *pNode;
  PathNode *pOpposite;

  // Should cleanly recognize all three parameters
  pNode = FindOrCreateNodeInList(ppListHead, directionId, nodeData);
  pOpposite = FindOrCreateNodeInList(ppListHead, OppositeDirection(directionId), nodeData);

  if (pNode != NULL && pOpposite != NULL) {
    LinkBidirectionalNodes(pNode, pOpposite);
  }
}
```

**Caller Functions** (identified):
1. CheckNearbyEntitiesAndTriggerActions @ 0x6fd5eb80

## Detection Pattern

### Required Characteristics (ALL must match):

1. **Caller Pattern**:
```asm
MOV EBX, <param1>       ; ← Set EBX to first parameter
MOV EAX, <param2>       ; ← Set EAX to second parameter (or already in EAX)
MOV ECX, <param3>       ; ← Set ECX to third parameter
CALL <function>         ; ← Call target function
; Continues immediately - no stack cleanup needed
```

2. **Callee Entry Pattern**:
```asm
<function>:
  PUSH ESI                    ; Save callee-saved registers
  PUSH EDI
  MOV <reg>, EAX             ; ← Save param 2 from EAX
  MOV <reg>, ECX             ; ← Save param 3 from ECX
  MOV <reg>, EBX             ; ← Use param 1 from EBX
  ; OR use registers directly
  ; ... function body ...
```

3. **Callee Exit Pattern**:
```asm
  RET                         ; ← CALLER cleanup (no immediate)
```

4. **Function Characteristics**:
   - Exactly 3 parameters (no more, no less)
   - All parameters are 4 bytes (DWORD/pointer)
   - No stack parameters needed
   - Fast execution path (performance-critical)

### Disqualifying Patterns:

❌ **Stack parameters**: `PUSH <value>` before CALL (not __d2regcall - see __d2call or __d2mixcall)
❌ **Callee cleanup**: Function ends with `RET 0xN` (not __d2regcall - see __d2call)
❌ **More than 3 parameters**: Function uses stack in addition to registers (not pure __d2regcall)
❌ **Different registers**: Uses registers other than EBX+EAX+ECX (custom convention)

## Automated Detection Script

```python
def is_d2regcall_function(func_addr: str) -> bool:
    """
    Detect if a function uses __d2regcall calling convention.

    Args:
        func_addr: Function address in hex format (e.g., "0x6fd94ba0")

    Returns:
        True if function appears to use __d2regcall convention
    """
    # Get function disassembly
    disasm_result = disassemble_function(address=func_addr)
    lines = disasm_result.split('\n')

    # Check 1: Function saves EAX and ECX in first 10 instructions
    saves_eax = False
    saves_ecx = False
    uses_ebx = False

    for i, line in enumerate(lines[:10]):
        # Look for saving EAX and ECX
        if 'MOV' in line and ',EAX' in line:
            saves_eax = True
        if 'MOV' in line and ',ECX' in line:
            saves_ecx = True
        if ('MOV' in line or '[EBX' in line) and 'EBX' in line:
            uses_ebx = True

    # Check 2: Has caller cleanup (RET with no immediate)
    has_caller_cleanup = False
    for line in lines[-10:]:
        if line.strip().endswith('RET') and 'RET 0x' not in line:
            has_caller_cleanup = True
            break

    # Check 3: Verify callers set registers before CALL
    try:
        func_info = get_function_by_address(func_addr)
        func_name = func_info['name']

        callers = get_function_callers(name=func_name, limit=3)

        if not callers:
            return False

        # Check at least one caller sets multiple registers
        for caller in callers[:2]:
            caller_disasm = disassemble_function(address=caller['address'])

            # Look for multiple MOV reg patterns before CALL
            sets_ebx = f'MOV EBX,' in caller_disasm
            sets_ecx = f'MOV ECX,' in caller_disasm

            if sets_ebx and sets_ecx:
                return saves_eax and saves_ecx and uses_ebx and has_caller_cleanup

    except Exception as e:
        print(f"Error checking callers: {e}")
        return False

    return saves_eax and saves_ecx and uses_ebx and has_caller_cleanup

# Usage example:
candidates = []
for addr in function_addresses:
    if is_d2regcall_function(addr):
        candidates.append(addr)
        print(f"✓ Found __d2regcall candidate: {addr}")
```

## Application Instructions (After Implementation)

### Via MCP Tools:
```python
result = set_function_prototype(
    function_address="0x6fd94ba0",
    prototype="void CreateOppositeDirectionNodes(void** ppListHead, int directionId, int nodeData)",
    calling_convention="__d2regcall"
)
```

### Via Ghidra GUI:
1. Right-click function in Listing
2. Select "Edit Function Signature"
3. Change "Calling Convention" dropdown to `__d2regcall`
4. Click OK

### Via Ghidra Python Script:
```python
from ghidra.program.model.symbol import SourceType

func = getFunctionAt(toAddr(0x6fd94ba0))
func.setCallingConvention("__d2regcall")

# Or set complete signature:
parser = currentProgram.getDataTypeManager().getDataTypeParser()
sig = parser.parse("void __d2regcall CreateOppositeDirectionNodes(void** ppListHead, int directionId, int nodeData)")
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

Edit `x86.cspec` and add the complete `__d2regcall` XML definition (shown above) inside the `<compiler_spec>` section, after the existing calling conventions.

### Step 3: Restart Ghidra

**IMPORTANT**: You must completely restart Ghidra for the new convention to be recognized. Closing and reopening a project is not sufficient.

### Step 4: Verify Installation

```python
# In Ghidra Python console or via MCP:
func = getFunctionAt(toAddr(0x6fd94ba0))
conventions = list(currentProgram.getCompilerSpec().getCallingConventions())
convention_names = [c.getName() for c in conventions]

if "__d2regcall" in convention_names:
    print("✓ __d2regcall successfully installed")
else:
    print("✗ __d2regcall not found - check x86.cspec")
```

## Expected Decompilation Improvements

### Before (with `__stdcall`):
```c
void __stdcall CreateOppositeDirectionNodes(void **param_1, int param_2, int param_3)
{
  int *in_EAX;      // ← Unrecognized register parameter
  int *unaff_ECX;   // ← Unrecognized register parameter

  // Confusing code with register artifacts
}
```

### After (with `__d2regcall`):
```c
void __d2regcall CreateOppositeDirectionNodes(void **ppListHead, int directionId, int nodeData)
{
  PathNode *pNode;
  PathNode *pOpposite;

  // Clean, readable code
  pNode = FindOrCreateNodeInList(ppListHead, directionId, nodeData);
  pOpposite = FindOrCreateNodeInList(ppListHead, OppositeDirection(directionId), nodeData);

  LinkBidirectionalNodes(pNode, pOpposite);
}
```

## Common Issues

### Issue: Still shows `in_EAX` or `unaff_ECX` after applying

**Causes**:
1. Convention not properly installed in x86.cspec
2. Ghidra not restarted
3. Function actually uses different register pattern

**Solutions**:
1. Verify XML in x86.cspec matches specification exactly
2. Restart Ghidra completely (not just reopen project)
3. Re-examine assembly to confirm exact register usage

### Issue: Ghidra shows parameters in wrong order

**Causes**:
1. Registers used in different order than convention specifies
2. Function uses hybrid convention

**Solutions**:
1. Check exact MOV order in function entry
2. May need to swap parameter order in prototype
3. Consider if function needs custom convention

## Technical Background

### Why EBX + EAX + ECX?

This register combination is unusual because:

1. **EBX is callee-saved**: Normally not used for parameters
2. **EAX is return value**: Using for parameter is non-standard
3. **No EDX**: Standard `__fastcall` uses ECX+EDX, not EBX+EAX+ECX

Blizzard likely chose this for:
- **Maximum registers**: All 3 general-purpose registers used
- **No stack access**: Fastest possible calling convention
- **Specific use case**: Pathfinding functions with exactly 3 parameters
- **EBX optimization**: First parameter is often a list head pointer

### When to Use __d2regcall

This convention appears optimized for:
- **Pathfinding algorithms**: Fast node creation/traversal
- **List operations**: Operations on linked lists
- **Tight loops**: Performance-critical inner loops
- **Fixed parameter count**: Functions that always take exactly 3 parameters

### Comparison to Standard Conventions

| Convention | Param 1 | Param 2 | Param 3 | Cleanup | Speed |
|------------|---------|---------|---------|---------|-------|
| __cdecl    | Stack   | Stack   | Stack   | Caller  | Slow |
| __stdcall  | Stack   | Stack   | Stack   | Callee  | Slow |
| __fastcall | ECX     | EDX     | Stack   | Callee  | Medium |
| **__d2regcall** | **EBX** | **EAX** | **ECX** | **Caller** | **Fast** |

**Performance Advantage**: No stack frame needed, no memory access for parameters, minimal function prologue/epilogue.

## Related Conventions

- **__d2call**: Uses EBX + Stack (more common, supports variable parameters)
- **__d2mixcall**: Uses EAX + ESI + Stack (mixed approach)
- **__fastcall**: Standard register convention (ECX + EDX + Stack)

See: `DIABLO2_CALLING_CONVENTIONS_STRATEGY.md` for complete taxonomy.

## Testing Strategy

### Phase 1: Single Function Test
1. Install convention in x86.cspec
2. Apply to CreateOppositeDirectionNodes
3. Verify decompilation quality
4. Check caller recognition

### Phase 2: Pattern Search
1. Search for similar assembly patterns
2. Identify additional candidate functions
3. Apply convention to candidates
4. Measure decompilation improvements

### Phase 3: Validation
1. Confirm parameter types correct
2. Verify no register artifacts remain
3. Check struct field access works
4. Test with different parameter types

## Future Work

- [ ] Install convention in Ghidra x86.cspec
- [ ] Apply to CreateOppositeDirectionNodes
- [ ] Search D2Common.dll for more instances
- [ ] Analyze D2Game.dll for __d2regcall usage
- [ ] Document all functions using this convention
- [ ] Create performance comparison vs __stdcall

## References

- DIABLO2_CALLING_CONVENTIONS_STRATEGY.md - Complete strategy
- D2CALL_FINAL_REPORT.md - Analysis that discovered this convention
- D2CALL_CONVENTION_REFERENCE.md - Related __d2call convention

## Statistics

### D2Common.dll
- **Confirmed __d2regcall functions**: 1 (CreateOppositeDirectionNodes)
- **Expected additional functions**: Unknown (requires systematic search)
- **Priority**: Medium (pathfinding/list operations)

### D2Game.dll
- **Status**: Not yet analyzed

---

**Version**: 1.0
**Last Updated**: 2025-10-24
**Ghidra Version**: 11.4.2+
**Status**: Ready for implementation and testing

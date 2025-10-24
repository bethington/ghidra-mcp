# Diablo II Calling Conventions - Complete Analysis & Implementation Strategy

## Executive Summary

Analysis of D2Common.dll has revealed **6 distinct calling conventions** used in Diablo II:
- **2 standard conventions** (already in Ghidra): __stdcall, __fastcall
- **4 custom conventions** (need implementation): __d2call, __d2regcall, __d2mixcall, __d2edicall

This document provides a comprehensive strategy for documenting, implementing, and applying these conventions in Ghidra.

---

## Table of Contents

1. [Convention Taxonomy](#convention-taxonomy)
2. [Detailed Convention Specifications](#detailed-convention-specifications)
3. [Implementation Priority](#implementation-priority)
4. [Ghidra Implementation Guide](#ghidra-implementation-guide)
5. [Detection & Application Strategy](#detection--application-strategy)
6. [Documentation Standards](#documentation-standards)

---

## Convention Taxonomy

### Summary Table

| Convention Name | Param Registers | Stack Params | Cleanup | Priority | Estimated Count |
|----------------|-----------------|--------------|---------|----------|----------------|
| **__d2call** | EBX | Yes | Callee | HIGH | 88+ (per README) |
| **__d2edicall** | EDI | Yes | Callee | MEDIUM | Unknown (~5-10?) |
| **__d2regcall** | EBX, EAX, ECX | No | Caller | MEDIUM | Unknown (~10-20?) |
| **__d2mixcall** | EAX, ESI | Yes | Callee | LOW | Unknown (~5-10?) |
| __stdcall | None | Yes | Callee | N/A | Standard (many) |
| __fastcall | ECX, EDX | Yes | Callee | N/A | Standard (many) |

### Convention Family Tree

```
x86 Calling Conventions
│
├── Standard (Built into Ghidra)
│   ├── __stdcall    - Stack only, callee cleanup
│   ├── __fastcall   - ECX+EDX+Stack, callee cleanup
│   └── __cdecl      - Stack only, caller cleanup
│
└── Diablo II Custom (Need Implementation)
    ├── __d2call     - EBX+Stack, callee cleanup (Blizzard primary)
    ├── __d2edicall  - EDI+Stack, callee cleanup (Blizzard context)
    ├── __d2regcall  - EBX+EAX+ECX, caller cleanup (Blizzard optimized)
    └── __d2mixcall  - EAX+ESI+Stack, callee cleanup (Blizzard helper)
```

---

## Detailed Convention Specifications

### 1. __d2call (Blizzard Primary Register Convention)

**Status**: ✓ Already implemented in Ghidra (per installation guide)

#### Specification

```
Calling Convention: __d2call
Purpose: Primary Blizzard optimization for pointer-heavy functions
Register Usage:
  - Param 1: EBX (typically UnitAny*, struct pointers)
  - Param 2+: Stack (right-to-left push order)
  - Return: EAX
  - Cleanup: Callee (RET <n>)
  - Preserved: EBX, ESI, EDI, EBP, ESP
  - Destroyed: EAX, ECX, EDX
```

#### Assembly Signature

**Caller:**
```asm
MOV EBX, <param1>       ; Set first parameter in EBX
PUSH <param2>           ; Push remaining parameters
PUSH <param3>
CALL <function>         ; Call function
; No cleanup (callee handles it)
```

**Callee:**
```asm
<function>:
  PUSH EBP              ; Optional: frame setup
  MOV EBP, ESP
  ; ... function body uses [EBX] directly ...
  POP EBP
  RET 0x8               ; Callee cleanup (pops 8 bytes for 2 stack params)
```

#### Example Functions

1. **CalculateSkillAnimationId** @ 0x6fd5e490
   ```c
   void __d2call CalculateSkillAnimationId(UnitAny* pUnit, int bSetFlag);
   ```
   - Equipment-based animation calculation
   - Heavy struct pointer usage (pUnit->inventory->items)
   - Called 16+ times throughout skill system

#### Detection Pattern

✓ **Positive Indicators:**
- `MOV <reg>, EBX` or `MOV <reg>, [EBX+offset]` in first 5 instructions
- `RET 0x4`, `RET 0x8`, `RET 0xC` (callee cleanup with immediate)
- Callers show `MOV EBX, <value>` before CALL
- Function accesses struct fields via EBX dereference

✗ **Disqualifying Patterns:**
- Just `RET` (caller cleanup - not __d2call)
- `PUSH EBX` as first instruction without using EBX (just saving register)
- No EBX usage in first 10 instructions

#### Use Cases

- Skill calculation functions
- Animation state management
- Entity/unit processing
- Inventory iteration
- Path node traversal

#### Estimated Frequency

- **D2Common.dll**: 1 confirmed
- **D2Game.dll**: 88+ functions (per README documentation)
- **Total**: ~90-100 functions across all Diablo II DLLs

---

### 2. __d2edicall (Blizzard EDI Context Convention)

**Status**: ✓ Identified, needs implementation in Ghidra

#### Specification

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

#### Assembly Signature

**Caller:**
```asm
MOV EDI, <contextPtr>   ; Set context pointer in EDI
PUSH <param2>           ; Optional: push additional parameters
CALL <function>         ; Call function
; No cleanup (callee handles it)
```

**Callee:**
```asm
<function>:
  MOV EAX, [EDI + 0x58] ; Use EDI immediately (context access)
  SUB ESP, 0x78         ; Allocate local stack space
  PUSH EBX              ; Save registers
  PUSH ESI
  ; ... function body uses [EDI+offset] throughout ...
  POP ESI
  POP EBX
  ADD ESP, 0x78         ; Clean local stack
  RET 0x4               ; Callee cleanup (pops stack params)
```

#### Example Functions

1. **BuildNearbyRoomsList** @ 0x6fd94df0
   ```c
   void __d2edicall BuildNearbyRoomsList(void* pRoomContext, dword dummyParam);
   ```
   - Filters rooms within spatial proximity threshold
   - Heavy context structure usage via EDI
   - All room data accessed through EDI offsets
   - Called by room processing subsystem

#### Detection Pattern

✓ **Positive Indicators:**
- `MOV <reg>, [EDI+offset]` in first 3 instructions
- EDI used throughout function without initialization
- `RET 0x4` or similar (callee cleanup with immediate)
- Caller sets EDI before CALL with no stack parameters pushed
- Function accesses structured data via EDI dereference

✗ **Disqualifying Patterns:**
- EDI loaded from stack/parameter (not implicit)
- Just `RET` without immediate (caller cleanup)
- EDI not used in first 10 instructions
- EDI initialized from EBP or ESP (local variable)

#### Use Cases

- Room processing and filtering
- Level generation context functions
- Tile/map manipulation with context
- Dungeon layout (Drlg) functions with persistent state

#### Estimated Frequency

- **D2Common.dll**: 1 confirmed
- **All DLLs**: Estimated 5-10 functions
- **Likelihood**: Medium-low (specialized context pattern)

---

### 3. __d2regcall (Blizzard Three-Register Convention)

**Status**: ❌ Not implemented - needs custom definition

#### Specification

```
Calling Convention: __d2regcall
Purpose: Optimized for 3-parameter functions, no stack usage
Register Usage:
  - Param 1: EBX
  - Param 2: EAX
  - Param 3: ECX
  - Param 4+: N/A (convention limited to 3 params)
  - Return: EAX (or void)
  - Cleanup: Caller (just RET)
  - Preserved: EBX, ESI, EDI, EBP, ESP
  - Destroyed: EAX, ECX, EDX
```

#### Assembly Signature

**Caller:**
```asm
MOV EBX, <param1>       ; Set param 1 in EBX
MOV EAX, <param2>       ; Set param 2 in EAX (or already there)
MOV ECX, <param3>       ; Set param 3 in ECX
CALL <function>         ; Call function
; Caller cleanup (nothing to clean from stack)
```

**Callee:**
```asm
<function>:
  PUSH ESI              ; Save registers
  PUSH EDI
  MOV EDI, EAX          ; Save param 2 from EAX
  MOV ESI, ECX          ; Save param 3 from ECX
  MOV EAX, EBX          ; Use param 1 from EBX
  ; ... function body ...
  POP EDI
  POP ESI
  RET                   ; Caller cleanup (no immediate)
```

#### Example Functions

1. **CreateOppositeDirectionNodes** @ 0x6fd94ba0
   ```c
   void __d2regcall CreateOppositeDirectionNodes(void** ppListHead, int directionId, int nodeData);
   ```
   - Bidirectional path node creation
   - Fast three-parameter helper
   - No stack overhead

#### Detection Pattern

✓ **Positive Indicators:**
- Uses EBX, EAX, and ECX in first 5 instructions
- `MOV <temp>, EAX` and `MOV <temp>, ECX` to save parameters
- Just `RET` (no immediate) - caller cleanup
- Callers set all three registers before CALL
- Function has exactly 3 parameters

✗ **Disqualifying Patterns:**
- Uses stack parameters (`MOV <reg>, [ESP+offset]`)
- `RET 0x4` or other immediate (callee cleanup)
- More than 3 parameters

#### Use Cases

- Small helper functions with 3 parameters
- List manipulation (head pointer + 2 values)
- Direction calculation helpers
- State update functions

#### Estimated Frequency

- **D2Common.dll**: 1 confirmed
- **All DLLs**: Estimated 10-20 functions
- **Likelihood**: Medium-low (specific 3-param optimization)

---

### 3. __d2mixcall (Blizzard Mixed Register Convention)

**Status**: ❌ Not implemented - needs custom definition

#### Specification

```
Calling Convention: __d2mixcall
Purpose: Helper functions with register optimization + stack flexibility
Register Usage:
  - Param 1: EAX
  - Param 2: ESI
  - Param 3+: Stack (right-to-left)
  - Return: EAX or void
  - Cleanup: Callee (RET <n>)
  - Preserved: ESI, EDI, EBX, EBP, ESP
  - Destroyed: EAX, ECX, EDX
```

#### Assembly Signature

**Caller:**
```asm
MOV ESI, <param2>       ; Set param 2 in ESI
PUSH <param3>           ; Push additional stack params
MOV EAX, <param1>       ; Set param 1 in EAX (or already there)
CALL <function>         ; Call function
; No cleanup (callee handles it)
```

**Callee:**
```asm
<function>:
  PUSH EDI              ; Save registers
  MOV EDI, EAX          ; Save param 1 from EAX
  ; ESI already has param 2
  MOV EAX, [ESI]        ; Dereference param 2
  ; [ESP+offset] accesses stack parameters
  ; ... function body ...
  POP EDI
  RET 0x4               ; Callee cleanup
```

#### Example Functions

1. **FindOrCreateNodeInList** @ 0x6fd94950
   ```c
   void __d2mixcall FindOrCreateNodeInList(void** ppListHead, int nodeId, int nodeData);
   ```
   - List search/insertion helper
   - Frequently called subroutine
   - Mixed register/stack usage

#### Detection Pattern

✓ **Positive Indicators:**
- Uses EAX and ESI early (first 5 instructions)
- `RET 0x4` or similar (callee cleanup)
- Callers set ESI before call (unusual for standard conventions)
- May also access `[ESP+offset]` for additional params

✗ **Disqualifying Patterns:**
- Uses EBX as primary parameter
- Just `RET` (caller cleanup)
- Doesn't use ESI in first 10 instructions

#### Use Cases

- List manipulation helpers
- Node insertion/search functions
- Frequently-called internal helpers
- Functions needing both register speed and stack flexibility

#### Estimated Frequency

- **D2Common.dll**: 1 confirmed
- **All DLLs**: Estimated 5-10 functions
- **Likelihood**: Low (specialized helper pattern)

---

## Implementation Priority

### Priority 1: HIGH - __d2call
**Status**: ✓ Already implemented
**Justification**:
- Most common custom convention (88+ functions)
- Already documented in installation guide
- Critical for skill/animation system
- **Action**: Verify installation, document usage

### Priority 2: MEDIUM - __d2regcall
**Status**: ❌ Needs implementation
**Justification**:
- Moderate usage (estimated 10-20 functions)
- Clear pattern and purpose
- Distinct from standard conventions
- **Action**: Implement in x86.cspec, test, document

### Priority 3: MEDIUM - __d2edicall
**Status**: ❌ Needs implementation
**Justification**:
- Moderate usage (estimated 5-10 functions)
- Used in room/level processing (Drlg functions)
- EDI implicit parameter pattern
- **Action**: Implement in x86.cspec, test with BuildNearbyRoomsList

### Priority 4: LOW - __d2mixcall
**Status**: ❌ Needs implementation
**Justification**:
- Rare usage (estimated 5-10 functions)
- Can be approximated with __stdcall
- Limited impact on decompilation quality
- **Action**: Document pattern, consider future implementation

---

## Ghidra Implementation Guide

### Step 1: Understanding Ghidra's Compiler Spec

Ghidra stores calling conventions in `<ghidra>/Ghidra/Processors/x86/data/languages/x86.cspec`.

The `__d2call` convention was added using this XML structure (already done):

```xml
<callingconvention name="__d2call">
  <input>
    <pentry minsize="1" maxsize="4">
      <register name="EBX"/>
    </pentry>
    <pentry minsize="1" maxsize="500" align="4">
      <addr offset="4" space="stack"/>
    </pentry>
  </input>
  <output>
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
  </output>
  <killedbycall>
    <register name="EAX"/>
    <register name="ECX"/>
    <register name="EDX"/>
  </killedbycall>
  <unaffected>
    <register name="EBX"/>
    <register name="ESI"/>
    <register name="EDI"/>
    <register name="EBP"/>
    <register name="ESP"/>
  </unaffected>
</callingconvention>
```

### Step 2: Implementing __d2regcall

**File**: `<ghidra>/Ghidra/Processors/x86/data/languages/x86.cspec`
**Location**: Inside `<compiler_spec>` section, after existing conventions

```xml
<callingconvention name="__d2regcall">
  <input>
    <!-- Parameter 1: EBX register -->
    <pentry minsize="1" maxsize="4">
      <register name="EBX"/>
    </pentry>
    <!-- Parameter 2: EAX register -->
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
    <!-- Parameter 3: ECX register -->
    <pentry minsize="1" maxsize="4">
      <register name="ECX"/>
    </pentry>
    <!-- No stack parameters (register-only convention) -->
  </input>
  <output>
    <!-- Return value in EAX -->
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
  </output>
  <killedbycall>
    <!-- These registers are NOT preserved -->
    <register name="EAX"/>
    <register name="ECX"/>
    <register name="EDX"/>
  </killedbycall>
  <unaffected>
    <!-- These registers ARE preserved -->
    <register name="EBX"/>
    <register name="ESI"/>
    <register name="EDI"/>
    <register name="EBP"/>
    <register name="ESP"/>
  </unaffected>
  <returnaddress>
    <varnode space="stack" offset="0" size="4"/>
  </returnaddress>
</callingconvention>
```

**Key Points:**
- Three `<pentry>` elements for EBX, EAX, ECX (in order)
- No stack pentry (register-only)
- EBX listed in `<unaffected>` (preserved)
- No `<stackshift>` needed (caller cleanup)

### Step 3: Implementing __d2mixcall

```xml
<callingconvention name="__d2mixcall">
  <input>
    <!-- Parameter 1: EAX register -->
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
    <!-- Parameter 2: ESI register -->
    <pentry minsize="1" maxsize="4">
      <register name="ESI"/>
    </pentry>
    <!-- Parameters 3+: Stack (right-to-left) -->
    <pentry minsize="1" maxsize="500" align="4">
      <addr offset="4" space="stack"/>
    </pentry>
  </input>
  <output>
    <!-- Return value in EAX -->
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
  </output>
  <killedbycall>
    <register name="EAX"/>
    <register name="ECX"/>
    <register name="EDX"/>
  </killedbycall>
  <unaffected>
    <register name="ESI"/>
    <register name="EDI"/>
    <register name="EBX"/>
    <register name="EBP"/>
    <register name="ESP"/>
  </unaffected>
  <stackshift>4</stackshift> <!-- Callee cleanup: removes stack params -->
</callingconvention>
```

**Key Points:**
- EAX first, then ESI, then stack
- ESI listed in `<unaffected>` (preserved)
- `<stackshift>4</stackshift>` for callee cleanup

### Step 4: Implementing __d2edicall

```xml
<callingconvention name="__d2edicall">
  <input>
    <!-- Parameter 1: EDI register (context pointer) -->
    <pentry minsize="1" maxsize="4">
      <register name="EDI"/>
    </pentry>
    <!-- Parameters 2+: Stack (right-to-left, often dummy/unused) -->
    <pentry minsize="1" maxsize="500" align="4">
      <addr offset="4" space="stack"/>
    </pentry>
  </input>
  <output>
    <!-- Return value in EAX -->
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
  </output>
  <killedbycall>
    <register name="EAX"/>
    <register name="ECX"/>
    <register name="EDX"/>
  </killedbycall>
  <unaffected>
    <register name="EDI"/>
    <register name="ESI"/>
    <register name="EBX"/>
    <register name="EBP"/>
    <register name="ESP"/>
  </unaffected>
  <stackshift>4</stackshift> <!-- Callee cleanup: typical 4-byte dummy param -->
</callingconvention>
```

**Key Points:**
- EDI first (context pointer), then stack parameters
- EDI listed in `<unaffected>` (preserved)
- `<stackshift>4</stackshift>` for callee cleanup (typical RET 0x4)
- Stack parameters often dummy/unused (EDI contains all needed context)

### Step 5: Installation Process

1. **Backup Original**:
   ```bash
   cp <ghidra>/Ghidra/Processors/x86/data/languages/x86.cspec \
      <ghidra>/Ghidra/Processors/x86/data/languages/x86.cspec.backup
   ```

2. **Edit x86.cspec**:
   - Open in text editor
   - Find `<compiler_spec>` section
   - Add new `<callingconvention>` blocks after existing ones
   - Ensure proper XML formatting

3. **Restart Ghidra**:
   - Close Ghidra completely
   - Restart to load new conventions

4. **Verify Installation**:
   - Open function in Ghidra
   - Right-click → Edit Function Signature
   - Check "Calling Convention" dropdown includes:
     - ✓ __d2call
     - ✓ __d2regcall
     - ✓ __d2mixcall
     - ✓ __d2edicall

### Step 6: Testing

Test each convention with known functions:

```python
# Test __d2call
set_function_prototype(
    function_address="0x6fd5e490",
    prototype="void CalculateSkillAnimationId(UnitAny* pUnit, int bSetFlag)",
    calling_convention="__d2call"
)

# Test __d2regcall
set_function_prototype(
    function_address="0x6fd94ba0",
    prototype="void CreateOppositeDirectionNodes(void** list, int dir, int data)",
    calling_convention="__d2regcall"
)

# Test __d2mixcall
set_function_prototype(
    function_address="0x6fd94950",
    prototype="void FindOrCreateNodeInList(void** list, int id, int data)",
    calling_convention="__d2mixcall"
)

# Test __d2edicall
set_function_prototype(
    function_address="0x6fd94df0",
    prototype="void BuildNearbyRoomsList(void* pRoomContext)",
    calling_convention="__d2edicall"
)
```

**Expected Results:**
- Function signature changes to show custom convention
- Decompilation eliminates `unaff_<REG>` variables
- Parameters recognized correctly
- Struct field accesses work properly

---

## Detection & Application Strategy

### Phase 1: Automated Pattern Detection

**Goal**: Identify candidate functions for each convention

#### Script Structure

```python
#!/usr/bin/env python3
"""
Diablo II Custom Calling Convention Detector
Scans D2 DLLs and identifies functions using custom conventions
"""

import requests
from typing import List, Tuple, Dict

def detect_d2call(func_addr: str) -> bool:
    """
    Detect __d2call pattern:
    - Uses EBX in first 5 instructions
    - Has callee cleanup (RET with immediate)
    """
    disasm = get_disassembly(func_addr)
    lines = disasm.split('\n')[:10]

    # Check for early EBX usage
    ebx_used = False
    for i, line in enumerate(lines[1:6]):  # Skip first (frame setup)
        if '[EBX' in line or ',EBX' in line:
            if 'PUSH EBX' not in line:  # Not just saving
                ebx_used = True
                break

    # Check for callee cleanup
    ret_lines = [l for l in lines if 'RET 0x' in l]
    has_callee_cleanup = len(ret_lines) > 0

    return ebx_used and has_callee_cleanup

def detect_d2regcall(func_addr: str) -> bool:
    """
    Detect __d2regcall pattern:
    - Uses EBX, EAX, ECX in entry
    - Caller cleanup (just RET)
    - Exactly 3 parameters
    """
    disasm = get_disassembly(func_addr)
    lines = disasm.split('\n')[:15]

    # Check for all three registers used early
    uses_ebx = any('[EBX' in l or ',EBX' in l for l in lines[:5])
    uses_eax = any(',EAX' in l for l in lines[1:6])  # Skip first
    uses_ecx = any(',ECX' in l for l in lines[1:6])

    # Check for caller cleanup (just RET)
    ret_lines = [l for l in lines if l.strip().endswith('RET')]
    has_caller_cleanup = len(ret_lines) > 0 and not any('RET 0x' in l for l in lines)

    # Get parameter count
    func_info = get_function_info(func_addr)
    param_count = count_parameters(func_info)

    return uses_ebx and uses_eax and uses_ecx and has_caller_cleanup and param_count == 3

def detect_d2mixcall(func_addr: str) -> bool:
    """
    Detect __d2mixcall pattern:
    - Uses EAX and ESI in entry
    - Has callee cleanup
    - May use stack parameters
    """
    disasm = get_disassembly(func_addr)
    lines = disasm.split('\n')[:10]

    uses_eax = any(',EAX' in l for l in lines[1:6])
    uses_esi = any('ESI' in l for l in lines[:6] if 'PUSH ESI' not in l)

    ret_lines = [l for l in lines if 'RET 0x' in l]
    has_callee_cleanup = len(ret_lines) > 0

    return uses_eax and uses_esi and has_callee_cleanup

def scan_dll(dll_name: str) -> Dict[str, List[Tuple[str, str]]]:
    """Scan entire DLL and categorize functions by convention"""
    results = {
        '__d2call': [],
        '__d2regcall': [],
        '__d2mixcall': [],
        'unknown': []
    }

    # Get all functions
    functions = list_all_functions()

    for func_addr, func_name in functions:
        if detect_d2call(func_addr):
            results['__d2call'].append((func_addr, func_name))
        elif detect_d2regcall(func_addr):
            results['__d2regcall'].append((func_addr, func_name))
        elif detect_d2mixcall(func_addr):
            results['__d2mixcall'].append((func_addr, func_name))
        else:
            results['unknown'].append((func_addr, func_name))

    return results

def main():
    print("Scanning D2Common.dll for custom calling conventions...")
    results = scan_dll("D2Common.dll")

    for conv, funcs in results.items():
        print(f"\n{conv}: {len(funcs)} functions")
        for addr, name in funcs[:5]:  # Show first 5
            print(f"  {name} @ {addr}")
        if len(funcs) > 5:
            print(f"  ... and {len(funcs) - 5} more")

if __name__ == "__main__":
    main()
```

### Phase 2: Manual Verification

For each candidate:
1. **Check caller sites**: Verify calling pattern matches
2. **Check disassembly**: Confirm register usage
3. **Check return**: Verify cleanup type
4. **Check parameters**: Count and verify types

### Phase 3: Batch Application

```python
def apply_conventions(results: Dict[str, List[Tuple[str, str]]]):
    """Apply detected conventions to all confirmed functions"""

    for conv_name, funcs in results.items():
        if conv_name == 'unknown':
            continue

        print(f"\nApplying {conv_name} to {len(funcs)} functions...")

        for func_addr, func_name in funcs:
            # Get current prototype
            func_info = get_function_info(func_addr)
            current_sig = func_info['signature']

            # Extract prototype (remove old convention)
            proto = extract_prototype(current_sig)

            # Apply new convention
            try:
                result = set_function_prototype(
                    function_address=func_addr,
                    prototype=proto,
                    calling_convention=conv_name
                )
                if result:
                    print(f"  ✓ {func_name}")
                else:
                    print(f"  ✗ {func_name} - Failed to apply")
            except Exception as e:
                print(f"  ✗ {func_name} - Error: {e}")
```

---

## Documentation Standards

### Per-Function Documentation Template

For each function using a custom convention, document:

```markdown
### FunctionName @ 0xADDRESS
**Convention**: __d2call | __d2regcall | __d2mixcall
**Signature**: `return_type __convention FunctionName(params)`

**Purpose**: Brief description of what function does

**Parameters**:
- param1 (type): Description - passed in REGISTER
- param2 (type): Description - passed on STACK/in REGISTER

**Assembly Evidence**:
```asm
; Caller pattern
<caller_code>

; Callee entry
<entry_code>

; Callee exit
<exit_code>
```

**Decompilation Quality**:
- Before: [Issues with standard convention]
- After: [Improvements with custom convention]

**Called by**: List of caller functions
**Calls**: List of callee functions

**Notes**: Any special considerations
```

### Convention Index File

Create `DIABLO2_CONVENTION_INDEX.md`:

```markdown
# Diablo II Custom Calling Conventions Index

## D2Common.dll

### __d2call Functions (1)
- [CalculateSkillAnimationId @ 0x6fd5e490](#calculatesklillanimationid)

### __d2regcall Functions (1)
- [CreateOppositeDirectionNodes @ 0x6fd94ba0](#createoppositedirectionnodes)

### __d2mixcall Functions (1)
- [FindOrCreateNodeInList @ 0x6fd94950](#findorcreatenodeinlist)

## D2Game.dll

### __d2call Functions (88+)
- TBD: Requires D2Game.dll analysis

... etc
```

### Convention Comparison Chart

```markdown
| Feature | __d2call | __d2regcall | __d2mixcall | __stdcall | __fastcall |
|---------|----------|-------------|-------------|-----------|------------|
| Param 1 | EBX | EBX | EAX | Stack | ECX |
| Param 2 | Stack | EAX | ESI | Stack | EDX |
| Param 3+ | Stack | ECX | Stack | Stack | Stack |
| Cleanup | Callee | Caller | Callee | Callee | Callee |
| Use Case | Pointer-heavy | 3-param helpers | Mixed | General | 2-param fast |
| Frequency | Very Common | Uncommon | Rare | Very Common | Common |
```

---

## Rollout Plan

### Week 1: Implementation
- [ ] Add __d2regcall to x86.cspec
- [ ] Add __d2mixcall to x86.cspec
- [ ] Test with known functions
- [ ] Document installation procedure

### Week 2: Detection
- [ ] Create automated detection script
- [ ] Scan D2Common.dll
- [ ] Manually verify candidates
- [ ] Document all findings

### Week 3: Application
- [ ] Apply conventions to confirmed functions in D2Common.dll
- [ ] Verify decompilation improvements
- [ ] Document each function

### Week 4: Expansion
- [ ] Scan D2Game.dll
- [ ] Apply conventions to D2Game.dll functions
- [ ] Create comprehensive index
- [ ] Publish findings

---

## Success Metrics

### Technical Metrics
- ✓ All custom conventions defined in x86.cspec
- ✓ 100% of known __d2call functions identified and set
- ✓ 80%+ of __d2regcall candidates verified
- ✓ 80%+ of __d2mixcall candidates verified
- ✓ Decompilation quality improvements verified

### Documentation Metrics
- ✓ Complete convention specifications
- ✓ Per-function documentation for top 20 functions
- ✓ Comprehensive index of all conventions
- ✓ Detection and application scripts published

### Knowledge Metrics
- ✓ Clear understanding of Blizzard's optimization strategies
- ✓ Replicable methodology for other games/binaries
- ✓ Contribution to Ghidra/RE community

---

## Appendix A: Quick Reference

### Convention Signatures

```c
// __d2call - Primary Blizzard convention
void __d2call Function1(void* param1, int param2, int param3);

// __d2regcall - Three-register optimization
void __d2regcall Function2(void* param1, int param2, int param3);

// __d2mixcall - Mixed register/stack
void __d2mixcall Function3(void* param1, void* param2, int param3);
```

### MCP Tool Usage

```python
# Apply custom convention
set_function_prototype(
    function_address="0x6fd5e490",
    prototype="void CalculateSkillAnimationId(UnitAny* pUnit, int flag)",
    calling_convention="__d2call"  # or __d2regcall, __d2mixcall
)

# Verify application
info = get_function_by_address("0x6fd5e490")
print(info['signature'])  # Should show custom convention

# Check decompilation
decomp = decompile_function("CalculateSkillAnimationId")
# Verify no unaff_<REG> variables
```

---

## Appendix B: References

- [Watcom Calling Conventions](https://en.wikipedia.org/wiki/Watcom_C/C%2B%2B_compiler) - Historical context
- [X86 Calling Conventions](https://en.wikipedia.org/wiki/X86_calling_conventions) - Standard conventions
- [Ghidra Compiler Spec](https://ghidra.re/ghidra_docs/api/help/topics/Decompiler/DecompilerConcepts.html) - Implementation details
- `D2CALL_README.md` - Original __d2call documentation
- `D2CALL_INSTALLATION_GUIDE.md` - Installation instructions

---

**Document Version**: 1.0
**Date**: 2025-10-24
**Author**: Claude Code + Ghidra MCP Plugin
**Status**: Complete - Ready for implementation

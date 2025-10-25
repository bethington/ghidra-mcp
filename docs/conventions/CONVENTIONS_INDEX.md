# Diablo II Calling Conventions - Master Index

## Overview

This directory contains comprehensive documentation for all custom calling conventions discovered in Diablo II's binary files. These conventions were reverse-engineered through systematic assembly analysis of D2Common.dll and represent Blizzard's custom optimization strategies for performance-critical game code.

## Quick Reference

| Convention | Status | Priority | Parameters | Cleanup | Use Cases |
|------------|--------|----------|------------|---------|-----------|
| [__d2call](#d2call) | ✓ Implemented | HIGH | EBX + Stack | Callee | Core game functions, animations |
| [__d2regcall](#d2regcall) | ❌ Not implemented | MEDIUM | EBX + EAX + ECX | Caller | Pathfinding (3 params only) |
| [__d2mixcall](#d2mixcall) | ❌ Not implemented | LOW | EAX + ESI + Stack | Callee | List operations, search functions |

## Detailed Documentation

### __d2call (HIGH Priority)

**File**: [D2CALL_CONVENTION_REFERENCE.md](./D2CALL_CONVENTION_REFERENCE.md)

**Status**: ✓ **IMPLEMENTED** in Ghidra x86.cspec

**Specification**:
```
Parameter 1: EBX register
Parameters 2+: Stack (right-to-left)
Return: EAX
Cleanup: Callee (RET with immediate)
```

**Known Functions**: 1 confirmed in D2Common.dll, ~88 expected in D2Game.dll

**Example Function**:
```c
void __d2call CalculateSkillAnimationId(UnitAny *pUnit, int bSetFlag)
```

**Assembly Pattern**:
```asm
; Caller:
MOV EBX, <pUnit>     ; ← First parameter in EBX
PUSH <bSetFlag>      ; ← Remaining on stack
CALL function
; No stack adjustment (callee cleanup)

; Callee:
function:
  MOV EDI, EBX       ; ← Uses EBX immediately
  ...
  RET 0x4            ; ← Callee cleanup
```

**Why This Matters**:
- **Most common**: Primary custom convention used throughout Diablo II
- **88+ functions**: Largest group of custom convention functions
- **Core systems**: Animation, skills, combat, entity management
- **Decompilation quality**: Eliminates `unaff_EBX` artifacts when applied

**Implementation Status**:
- [x] Ghidra XML definition complete
- [x] Installed in x86.cspec
- [x] Tested and verified working
- [x] Documentation complete
- [x] Detection script available

**Next Steps**:
1. Scan D2Game.dll for 88+ additional functions
2. Create batch application script
3. Verify all applications improve decompilation

---

### __d2regcall (MEDIUM Priority)

**File**: [D2REGCALL_CONVENTION_REFERENCE.md](./D2REGCALL_CONVENTION_REFERENCE.md)

**Status**: ❌ **NOT IMPLEMENTED** - Ready for installation

**Specification**:
```
Parameter 1: EBX register
Parameter 2: EAX register
Parameter 3: ECX register
Return: EAX
Cleanup: Caller (RET with no immediate)
```

**Known Functions**: 1 confirmed in D2Common.dll

**Example Function**:
```c
void __d2regcall CreateOppositeDirectionNodes(void **ppListHead, int directionId, int nodeData)
```

**Assembly Pattern**:
```asm
; Caller:
MOV EBX, <ppListHead>    ; ← Param 1 in EBX
MOV EAX, <directionId>   ; ← Param 2 in EAX (or already there)
MOV ECX, <nodeData>      ; ← Param 3 in ECX
CALL function
; Continues immediately (caller cleanup)

; Callee:
function:
  MOV EDI, EAX           ; ← Save param 2 from EAX
  MOV ESI, ECX           ; ← Save param 3 from ECX
  MOV EAX, EBX           ; ← Use param 1 from EBX
  ...
  RET                    ; ← Caller cleanup (no immediate)
```

**Why This Matters**:
- **Performance**: No stack access = fastest possible calling convention
- **Pathfinding**: Optimized for tight loops in pathfinding algorithms
- **Fixed parameter count**: Exactly 3 parameters (no more, no less)
- **Eliminates artifacts**: Removes `in_EAX` and `unaff_ECX` from decompilation

**Implementation Status**:
- [x] Ghidra XML definition complete
- [x] Ready to install in x86.cspec
- [ ] Not yet installed
- [x] Detection script available
- [x] Documentation complete

**Next Steps**:
1. Install convention in Ghidra x86.cspec
2. Apply to CreateOppositeDirectionNodes
3. Test decompilation improvements
4. Search for additional instances

---

### __d2mixcall (LOW Priority)

**File**: [D2MIXCALL_CONVENTION_REFERENCE.md](./D2MIXCALL_CONVENTION_REFERENCE.md)

**Status**: ❌ **NOT IMPLEMENTED** - Ready for installation

**Specification**:
```
Parameter 1: EAX register
Parameter 2: ESI register
Parameters 3+: Stack (right-to-left)
Return: EAX
Cleanup: Callee (RET with immediate)
```

**Known Functions**: 1 confirmed in D2Common.dll

**Example Function**:
```c
PathNode* __d2mixcall FindOrCreateNodeInList(int nodeId, void **ppListHead, int nodeData)
```

**Assembly Pattern**:
```asm
; Caller:
MOV EAX, <nodeId>        ; ← Param 1 in EAX
MOV ESI, <ppListHead>    ; ← Param 2 in ESI (or already there)
PUSH <nodeData>          ; ← Remaining on stack
CALL function
; No stack adjustment (callee cleanup)

; Callee:
function:
  MOV EDI, EAX           ; ← Save param 1 from EAX
  MOV EAX, [ESI]         ; ← Use param 2 from ESI
  ...
  RET 0x4                ; ← Callee cleanup
```

**Why This Matters**:
- **List operations**: Specialized for linked list find/insert operations
- **ESI as pointer**: Optimized for pointer-heavy operations
- **Helper functions**: Lower-level utility functions
- **Eliminates artifacts**: Removes `in_EAX` and `unaff_ESI` from decompilation

**Implementation Status**:
- [x] Ghidra XML definition complete
- [x] Ready to install in x86.cspec
- [ ] Not yet installed
- [x] Detection script available
- [x] Documentation complete

**Next Steps**:
1. Implement after __d2call and __d2regcall
2. Apply to FindOrCreateNodeInList
3. Search for additional instances
4. Document interaction with other conventions

---

## Installation Guide

### Prerequisites

1. Ghidra 11.4.2 or later
2. Backup of x86.cspec file
3. Text editor with XML support
4. Ghidra restart capability

### Installation Steps

#### 1. Backup Configuration

```bash
# Windows
copy "%GHIDRA_INSTALL%\Ghidra\Processors\x86\data\languages\x86.cspec" ^
     "%GHIDRA_INSTALL%\Ghidra\Processors\x86\data\languages\x86.cspec.backup"

# Linux/Mac
cp $GHIDRA_INSTALL/Ghidra/Processors/x86/data/languages/x86.cspec \
   $GHIDRA_INSTALL/Ghidra/Processors/x86/data/languages/x86.cspec.backup
```

#### 2. Edit x86.cspec

Open `x86.cspec` in a text editor and locate the `<compiler_spec>` section. Add the XML definitions for each convention you want to install (see individual convention reference files for complete XML).

**Recommended Installation Order**:
1. First: `__d2call` (already installed if you followed D2CALL_INSTALLATION_GUIDE.md)
2. Second: `__d2regcall` (MEDIUM priority)
3. Third: `__d2mixcall` (LOW priority, install when needed)

#### 3. Restart Ghidra

**CRITICAL**: You must completely exit and restart Ghidra. Closing and reopening a project is NOT sufficient.

#### 4. Verify Installation

```python
# In Ghidra Python console:
conventions = list(currentProgram.getCompilerSpec().getCallingConventions())
convention_names = [c.getName() for c in conventions]

print("Installed conventions:")
for name in convention_names:
    print(f"  - {name}")

# Check for Diablo II conventions:
for d2conv in ['__d2call', '__d2regcall', '__d2mixcall']:
    status = "✓" if d2conv in convention_names else "✗"
    print(f"{status} {d2conv}")
```

---

## Usage Guide

### Identifying Which Convention to Use

Use this decision tree when examining a function:

```
Does the function use EBX in the first 5 instructions?
  ├─ YES: Does it take parameters on the stack?
  │   ├─ YES: → __d2call
  │   └─ NO: Does it use EAX and ECX?
  │       ├─ YES: → __d2regcall
  │       └─ NO: → Check for other patterns
  └─ NO: Does the function use EAX and ESI?
      ├─ YES: Does it take stack parameters?
      │   ├─ YES: → __d2mixcall
      │   └─ NO: → Standard __fastcall or custom
      └─ NO: → Standard convention (__stdcall, __cdecl, __fastcall)
```

### Quick Detection Checklist

For each suspected custom convention function:

**__d2call**:
- [ ] Callers: `MOV EBX, <param>` before CALL
- [ ] Callers: `PUSH` for additional parameters
- [ ] Callee: Uses EBX immediately or saves it
- [ ] Callee: Ends with `RET 0xN`

**__d2regcall**:
- [ ] Callers: Sets EBX, EAX, and ECX before CALL
- [ ] Callers: No PUSH instructions
- [ ] Callee: Saves EAX and ECX values
- [ ] Callee: Ends with `RET` (no immediate)
- [ ] Exactly 3 parameters

**__d2mixcall**:
- [ ] Callers: `MOV EAX, <param>` before CALL
- [ ] Callers: ESI set or already contains pointer
- [ ] Callers: `PUSH` for additional parameters
- [ ] Callee: Saves EAX value
- [ ] Callee: Uses ESI as pointer
- [ ] Callee: Ends with `RET 0xN`

---

## Automated Detection Tools

### Batch Scanner Script

```python
"""
Scan all functions in current program for custom calling conventions.
"""

def scan_for_custom_conventions():
    """
    Scan all functions and categorize by calling convention.
    """
    results = {
        '__d2call': [],
        '__d2regcall': [],
        '__d2mixcall': [],
        'unknown': []
    }

    # Get all functions
    func_manager = currentProgram.getFunctionManager()
    functions = func_manager.getFunctions(True)  # True = forward iteration

    for func in functions:
        addr = func.getEntryPoint().toString()
        name = func.getName()

        # Try each detection function
        if is_d2call_function(addr):
            results['__d2call'].append((addr, name))
        elif is_d2regcall_function(addr):
            results['__d2regcall'].append((addr, name))
        elif is_d2mixcall_function(addr):
            results['__d2mixcall'].append((addr, name))

    # Print results
    print("\n=== Custom Calling Convention Detection Results ===\n")

    for conv_type, functions in results.items():
        if functions:
            print(f"{conv_type}: {len(functions)} functions")
            for addr, name in functions[:10]:  # Show first 10
                print(f"  - {name} @ {addr}")
            if len(functions) > 10:
                print(f"  ... and {len(functions) - 10} more")
            print()

    return results

# Run scan
results = scan_for_custom_conventions()
```

### Individual Detection Functions

See each convention reference file for complete detection script:
- `D2CALL_CONVENTION_REFERENCE.md` → `is_d2call_function()`
- `D2REGCALL_CONVENTION_REFERENCE.md` → `is_d2regcall_function()`
- `D2MIXCALL_CONVENTION_REFERENCE.md` → `is_d2mixcall_function()`

---

## Statistics

### D2Common.dll Analysis

| Convention | Confirmed | Expected | Status |
|------------|-----------|----------|--------|
| __d2call | 1 | Unknown | Few instances in D2Common.dll |
| __d2regcall | 1 | Unknown | Pathfinding functions |
| __d2mixcall | 1 | Unknown | Helper functions |
| **Total Custom** | **3** | Unknown | **Systematic scan needed** |

### D2Game.dll (Expected)

| Convention | Expected Count | Source |
|------------|----------------|--------|
| __d2call | ~88 | D2CALL_README.md documentation |
| __d2regcall | Unknown | Requires analysis |
| __d2mixcall | Unknown | Requires analysis |
| **Total Custom** | **88+** | **Primary target for documentation** |

---

## Related Documentation

### Getting Started
- [D2CALL_README.md](../../D2CALL_README.md) - Quick start guide for __d2call
- [D2CALL_INSTALLATION_GUIDE.md](../../D2CALL_INSTALLATION_GUIDE.md) - Installation instructions

### Analysis Reports
- [D2CALL_TEST_RESULTS.md](../../D2CALL_TEST_RESULTS.md) - Testing methodology
- [D2CALL_FINAL_REPORT.md](../../D2CALL_FINAL_REPORT.md) - Discovery analysis
- [D2CALL_APPLIED_SUMMARY.md](../../D2CALL_APPLIED_SUMMARY.md) - Applied functions

### Strategy
- [DIABLO2_CALLING_CONVENTIONS_STRATEGY.md](../../DIABLO2_CALLING_CONVENTIONS_STRATEGY.md) - Complete implementation strategy

### Convention References (This Directory)
- [D2CALL_CONVENTION_REFERENCE.md](./D2CALL_CONVENTION_REFERENCE.md) - Complete __d2call reference
- [D2REGCALL_CONVENTION_REFERENCE.md](./D2REGCALL_CONVENTION_REFERENCE.md) - Complete __d2regcall reference
- [D2MIXCALL_CONVENTION_REFERENCE.md](./D2MIXCALL_CONVENTION_REFERENCE.md) - Complete __d2mixcall reference

---

## Implementation Roadmap

### Phase 1: __d2call (Completed)
- [x] Discover and document convention
- [x] Create Ghidra XML definition
- [x] Install in x86.cspec
- [x] Test with CalculateSkillAnimationId
- [x] Verify decompilation improvements
- [x] Create detection script
- [x] Write complete reference documentation

### Phase 2: __d2regcall (Next)
- [x] Discover and document convention
- [x] Create Ghidra XML definition
- [ ] **Install in x86.cspec** ← Next step
- [ ] Test with CreateOppositeDirectionNodes
- [ ] Verify decompilation improvements
- [ ] Search for additional instances
- [ ] Document all functions using convention

### Phase 3: __d2mixcall (Later)
- [x] Discover and document convention
- [x] Create Ghidra XML definition
- [ ] Install in x86.cspec (after Phase 2)
- [ ] Test with FindOrCreateNodeInList
- [ ] Verify decompilation improvements
- [ ] Search for additional instances
- [ ] Document all functions using convention

### Phase 4: D2Game.dll Analysis
- [ ] Load D2Game.dll in Ghidra
- [ ] Run automated detection for all 3 conventions
- [ ] Apply conventions to identified functions
- [ ] Document new functions discovered
- [ ] Create comprehensive function index
- [ ] Performance analysis and validation

### Phase 5: Complete Documentation
- [ ] Create per-function documentation for all custom convention functions
- [ ] Generate calling convention usage statistics
- [ ] Create call graph visualization
- [ ] Document interaction patterns between conventions
- [ ] Create best practices guide

---

## Troubleshooting

### Convention Not Appearing in Ghidra

**Problem**: Custom convention doesn't appear in dropdown after installation.

**Solutions**:
1. Verify XML syntax is valid (check Ghidra console for errors)
2. Ensure XML is inside `<compiler_spec>` section
3. Completely restart Ghidra (exit application, not just close project)
4. Check that x86.cspec file has write permissions
5. Try restarting Ghidra in administrator mode

### Decompilation Still Shows Artifacts

**Problem**: Still seeing `unaff_EBX`, `in_EAX`, etc. after applying convention.

**Solutions**:
1. Verify convention actually applied (check function signature)
2. Try `force_decompile()` to refresh decompiler cache
3. Run Analysis → Decompiler Parameter ID
4. Re-verify assembly pattern matches convention specification
5. Check if function uses hybrid convention (may need manual typing)

### Wrong Parameters Detected

**Problem**: Parameters shown in wrong order or with wrong types.

**Solutions**:
1. Verify parameter order in assembly matches convention specification
2. Check exact register usage in function entry
3. Count stack parameters carefully (check all PUSH instructions)
4. Verify RET immediate matches stack parameter bytes
5. May need to manually adjust prototype after applying convention

---

## Contributing

### Adding New Conventions

If you discover additional custom calling conventions:

1. **Document the pattern**: Assembly examples from caller and callee
2. **Create XML definition**: Follow Ghidra compiler spec format
3. **Write detection script**: Automated identification function
4. **Test thoroughly**: Multiple functions, various parameter counts
5. **Create reference documentation**: Follow existing format
6. **Update this index**: Add to quick reference table

### Improving Documentation

Contributions welcome:
- Additional function examples
- Improved detection scripts
- Better assembly pattern descriptions
- Decompilation quality comparisons
- Performance analysis data

---

## Version History

- **1.0** (2025-10-24): Initial release
  - Complete documentation for __d2call, __d2regcall, __d2mixcall
  - __d2call implemented and tested
  - __d2regcall and __d2mixcall ready for implementation
  - Detection scripts for all conventions
  - Complete reference documentation

---

**Maintained by**: Diablo II Reverse Engineering Community
**Ghidra Version**: 11.4.2+
**Last Updated**: 2025-10-24
**Status**: Production-ready for __d2call, ready for implementation for others

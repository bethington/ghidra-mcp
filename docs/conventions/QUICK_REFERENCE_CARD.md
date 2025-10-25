# Diablo II Calling Conventions - Quick Reference Card

## At a Glance

```
┌────────────────────────────────────────────────────────────────────────────┐
│ Diablo II Custom Calling Conventions                                       │
├──────────────┬─────────────┬─────────────┬─────────────┬──────────────────┤
│ Convention   │ Param 1     │ Param 2     │ Param 3+    │ Cleanup          │
├──────────────┼─────────────┼─────────────┼─────────────┼──────────────────┤
│ __d2call     │ EBX         │ Stack       │ Stack       │ Callee (RET 0xN) │
│ __d2regcall  │ EBX         │ EAX         │ ECX         │ Caller (RET)     │
│ __d2mixcall  │ EAX         │ ESI         │ Stack       │ Callee (RET 0xN) │
├──────────────┼─────────────┼─────────────┼─────────────┼──────────────────┤
│ __stdcall    │ Stack       │ Stack       │ Stack       │ Callee (RET 0xN) │
│ __fastcall   │ ECX         │ EDX         │ Stack       │ Callee (RET 0xN) │
│ __cdecl      │ Stack       │ Stack       │ Stack       │ Caller (RET)     │
└──────────────┴─────────────┴─────────────┴─────────────┴──────────────────┘
```

## Recognition Patterns

### __d2call (HIGH Priority)
```asm
Caller:                          Callee:
MOV EBX, <param1>     →         function:
PUSH <param2>                     MOV EDI, EBX      ← Uses EBX
PUSH <param3>                     ...
CALL function                     RET 0x4           ← Callee cleanup
```
**Key**: EBX parameter + stack + callee cleanup
**Status**: ✓ Implemented
**Use**: Core game functions, animations, skills

### __d2regcall (MEDIUM Priority)
```asm
Caller:                          Callee:
MOV EBX, <param1>     →         function:
MOV EAX, <param2>                 MOV EDI, EAX      ← Saves EAX
MOV ECX, <param3>                 MOV ESI, ECX      ← Saves ECX
CALL function                     MOV EAX, EBX      ← Uses EBX
                                  ...
                                  RET               ← Caller cleanup
```
**Key**: All registers (EBX+EAX+ECX) + caller cleanup + exactly 3 params
**Status**: ❌ Not implemented
**Use**: Pathfinding, tight loops (3 parameters only)

### __d2mixcall (LOW Priority)
```asm
Caller:                          Callee:
MOV EAX, <param1>     →         function:
MOV ESI, <param2>                 MOV EDI, EAX      ← Saves EAX
PUSH <param3>                     MOV EAX, [ESI]    ← Uses ESI
CALL function                     ...
                                  RET 0x4           ← Callee cleanup
```
**Key**: EAX + ESI + stack + callee cleanup
**Status**: ❌ Not implemented
**Use**: List operations, search functions

## Quick Identification Decision Tree

```
Start: Examine function assembly
│
├─ Uses EBX in first 5 instructions?
│  ├─ YES → Stack parameters?
│  │  ├─ YES → Callee cleanup (RET 0xN)?
│  │  │  ├─ YES → __d2call ✓
│  │  │  └─ NO  → Other convention
│  │  └─ NO  → Uses EAX + ECX?
│  │     ├─ YES → Exactly 3 params + caller cleanup?
│  │     │  ├─ YES → __d2regcall
│  │     │  └─ NO  → Other convention
│  │     └─ NO  → Other pattern
│  │
│  └─ NO  → Uses EAX in first 5 instructions?
│     ├─ YES → Uses ESI?
│     │  ├─ YES → Stack params + callee cleanup?
│     │  │  ├─ YES → __d2mixcall
│     │  │  └─ NO  → Other convention
│     │  └─ NO  → Check standard conventions
│     │
│     └─ NO  → Likely standard convention (__stdcall, __fastcall, __cdecl)
```

## Known Functions Reference

### __d2call
```
✓ CalculateSkillAnimationId @ 0x6fd5e490 (D2Common.dll)
  void __d2call CalculateSkillAnimationId(UnitAny *pUnit, int bSetFlag)

Expected: ~88 more in D2Game.dll
```

### __d2regcall
```
? CreateOppositeDirectionNodes @ 0x6fd94ba0 (D2Common.dll)
  void __d2regcall CreateOppositeDirectionNodes(void **ppListHead, int directionId, int nodeData)
```

### __d2mixcall
```
? FindOrCreateNodeInList @ 0x6fd94950 (D2Common.dll)
  PathNode* __d2mixcall FindOrCreateNodeInList(int nodeId, void **ppListHead, int nodeData)
```

## Verification Checklist

After applying a custom convention, verify:

```
General:
☐ Function signature shows correct convention
☐ Decompilation has improved readability
☐ Parameters recognized in correct order
☐ No unexpected register artifacts

__d2call Specific:
☐ No "unaff_EBX" in decompilation
☐ First parameter properly typed
☐ Stack cleanup matches parameter count
☐ Callers set EBX before CALL

__d2regcall Specific:
☐ No "in_EAX" or "unaff_ECX" in decompilation
☐ Exactly 3 parameters
☐ Caller cleanup (no stack adjustment)
☐ All 3 registers saved in function entry

__d2mixcall Specific:
☐ No "in_EAX" or "unaff_ESI" in decompilation
☐ ESI used as pointer
☐ Stack parameters correct
☐ Callee cleanup matches stack params
```

## Application Commands

### Via MCP Tools (Python):
```python
# __d2call
set_function_prototype(
    function_address="0x6fd5e490",
    prototype="void CalculateSkillAnimationId(UnitAny *pUnit, int bSetFlag)",
    calling_convention="__d2call"
)

# __d2regcall (after installation)
set_function_prototype(
    function_address="0x6fd94ba0",
    prototype="void CreateOppositeDirectionNodes(void **ppListHead, int directionId, int nodeData)",
    calling_convention="__d2regcall"
)

# __d2mixcall (after installation)
set_function_prototype(
    function_address="0x6fd94950",
    prototype="PathNode* FindOrCreateNodeInList(int nodeId, void **ppListHead, int nodeData)",
    calling_convention="__d2mixcall"
)
```

### Via Ghidra GUI:
```
1. Right-click function in Listing view
2. Select "Edit Function Signature"
3. Choose calling convention from dropdown
4. Click OK
```

### Via Ghidra Python Script:
```python
func = getFunctionAt(toAddr(0x6fd5e490))
func.setCallingConvention("__d2call")
```

## Disqualifying Patterns

### Not __d2call if:
```asm
❌ MOV EBX, [ESP+offset]     ; EBX loaded from stack (not parameter)
❌ RET                        ; Caller cleanup (should be RET 0xN)
❌ No EBX usage in first 5    ; Doesn't use EBX as parameter
```

### Not __d2regcall if:
```asm
❌ PUSH <value>              ; Uses stack parameters
❌ RET 0x4                   ; Callee cleanup (should be just RET)
❌ 4+ parameters             ; Only works with exactly 3
```

### Not __d2mixcall if:
```asm
❌ MOV EBX, <value>          ; Uses EBX (not EAX)
❌ RET                       ; Caller cleanup (should be RET 0xN)
❌ No ESI usage              ; Doesn't use ESI
```

## Installation Status

```
Ghidra x86.cspec Conventions:
  ✓ __d2call     - INSTALLED and TESTED
  ❌ __d2regcall  - Ready to install (XML available)
  ❌ __d2mixcall  - Ready to install (XML available)

To install missing conventions:
  1. Edit: <Ghidra>/Processors/x86/data/languages/x86.cspec
  2. Add XML definitions (see convention reference files)
  3. Restart Ghidra completely
```

## Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `unaff_EBX` still appears | Convention not applied | Check signature, force re-decompile |
| `in_EAX` still appears | Convention not installed | Install __d2regcall or __d2mixcall |
| Wrong parameter order | Wrong convention used | Re-examine assembly pattern |
| Convention not in dropdown | Not installed in x86.cspec | Add XML and restart Ghidra |
| Parameters show as stack | Ghidra guessed wrong | Manually set correct convention |

## Detection Script Snippets

### Quick EBX Check:
```python
disasm = disassemble_function(address=func_addr)
lines = disasm.split('\n')[:5]
uses_ebx = any('[EBX' in line or ',EBX' in line for line in lines)
```

### Quick Cleanup Check:
```python
has_callee_cleanup = 'RET 0x' in disasm
has_caller_cleanup = disasm.strip().endswith('RET') and 'RET 0x' not in disasm
```

### Quick Caller Check:
```python
callers = get_function_callers(name=func_name, limit=5)
for caller in callers:
    caller_disasm = disassemble_function(address=caller['address'])
    if f'MOV EBX,' in caller_disasm:
        print(f"✓ Caller {caller['name']} sets EBX")
```

## Performance Impact

```
Convention Speed (fastest to slowest):
1. __d2regcall  - All registers, no stack access
2. __d2call     - One register, stack for rest
3. __d2mixcall  - Two registers, stack for rest
4. __fastcall   - Two registers, stack for rest
5. __stdcall    - All stack, callee cleanup
6. __cdecl      - All stack, caller cleanup
```

## Priority Matrix

```
┌────────────────────────────────────────────────┐
│ Implementation Priority                        │
├──────────────┬──────────────┬──────────────────┤
│ Priority     │ Convention   │ Reason           │
├──────────────┼──────────────┼──────────────────┤
│ HIGH         │ __d2call     │ 88+ functions    │
│              │              │ Core game logic  │
│              │              │ Already done ✓   │
├──────────────┼──────────────┼──────────────────┤
│ MEDIUM       │ __d2regcall  │ Pathfinding      │
│              │              │ Performance      │
│              │              │ 1+ known         │
├──────────────┼──────────────┼──────────────────┤
│ LOW          │ __d2mixcall  │ Helper functions │
│              │              │ Less frequent    │
│              │              │ 1 known          │
└──────────────┴──────────────┴──────────────────┘
```

## Complete Documentation Links

- **Master Index**: [CONVENTIONS_INDEX.md](./CONVENTIONS_INDEX.md)
- **__d2call Reference**: [D2CALL_CONVENTION_REFERENCE.md](./D2CALL_CONVENTION_REFERENCE.md)
- **__d2regcall Reference**: [D2REGCALL_CONVENTION_REFERENCE.md](./D2REGCALL_CONVENTION_REFERENCE.md)
- **__d2mixcall Reference**: [D2MIXCALL_CONVENTION_REFERENCE.md](./D2MIXCALL_CONVENTION_REFERENCE.md)
- **Implementation Strategy**: [../DIABLO2_CALLING_CONVENTIONS_STRATEGY.md](../../DIABLO2_CALLING_CONVENTIONS_STRATEGY.md)

---

## Pro Tips

1. **Always check callers first** - Easiest way to identify convention
2. **Look for EBX** - If EBX is used, it's likely a D2 custom convention
3. **Count parameters** - Exactly 3 params with all registers = __d2regcall
4. **Check cleanup** - Callee cleanup (RET 0xN) vs caller cleanup (RET)
5. **Use force_decompile()** - After applying convention, refresh decompiler cache
6. **Batch similar functions** - Once you find one, look for similar patterns nearby

---

**Print this card for quick reference during reverse engineering sessions**

**Version**: 1.0 | **Last Updated**: 2025-10-24 | **For**: Ghidra 11.4.2+

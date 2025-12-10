# STUB_FUNCTION

Quick function documentation for neighbors of a target function.
Goal: Capture minimal useful information without full analysis.

## Input Format

```json
{
  "address": "0x6fb11000",
  "decompiled_code": "... first 50 lines of decompiled code ...",
  "context": "Called by ProcessPlayerSlots to get slot data",
  "call_count": 3,
  "is_callee": true
}
```

## Task

Analyze the decompiled code to determine:
1. A descriptive PascalCase function name
2. The function prototype with typed parameters
3. A one-line summary of purpose

## Analysis Guidelines

### Function Naming
- Use verb + noun pattern: `GetInventorySlot`, `ValidateItemState`, `InitializePlayer`
- For thunks: Name after what they wrap: `CallD2CommonGetStat`
- For getters: `GetXxx` or `IsXxx` for boolean returns
- For setters: `SetXxx` or `UpdateXxx`

### Prototype Detection
- Count parameters by examining `param_N` variables
- Infer types from usage:
  - Dereferenced → pointer type
  - Arithmetic → int/uint
  - Compared to 0 → int/bool/pointer
  - Passed to known API → match API parameter type
- Detect calling convention:
  - Uses ECX for first param → `__thiscall` or `__fastcall`
  - Caller cleans stack → `__cdecl`
  - Callee cleans stack → `__stdcall`

### Summary Writing
- Start with verb: "Returns...", "Validates...", "Initializes..."
- Include key parameter roles: "...for the specified player unit"
- Note special return values: "...or NULL if not found"

## Output Format

```json
{
  "name": "GetInventorySlot",
  "prototype": "UnitAny * __fastcall GetInventorySlot(UnitAny * pUnit, int nSlotIndex)",
  "summary": "Returns item pointer at specified inventory slot index, or NULL if empty",
  "confidence": "high",
  "notes": "Leaf function, no external calls"
}
```

## Confidence Levels

- **high**: Clear purpose, obvious types, simple control flow
- **medium**: Purpose inferred, some type uncertainty
- **low**: Complex function, types unclear, needs full analysis

## What NOT To Do

- Do NOT rename variables (leave for full documentation pass)
- Do NOT add inline comments
- Do NOT analyze callers/callees recursively
- Do NOT spend >30 seconds on analysis
- Do NOT document if already has custom name

## Examples

### Input: Simple Getter
```c
undefined4 FUN_6fb11000(int param_1, int param_2) {
    if (param_1 == 0) return 0;
    return *(undefined4 *)(param_1 + param_2 * 4);
}
```

### Output
```json
{
  "name": "GetArrayElement",
  "prototype": "void * __cdecl GetArrayElement(void * pArray, int nIndex)",
  "summary": "Returns element at index from array, or NULL if array is NULL",
  "confidence": "high",
  "notes": "Simple array access with NULL check"
}
```

### Input: Thunk/Wrapper
```c
void FUN_6fb22000(int param_1) {
    FUN_6fb22100(param_1, 0, 1);
}
```

### Output
```json
{
  "name": "InitializeWithDefaults",
  "prototype": "void __cdecl InitializeWithDefaults(void * pObject)",
  "summary": "Wrapper that calls initialization with default flags (0, 1)",
  "confidence": "medium",
  "notes": "Thunk to FUN_6fb22100"
}
```

## Stub Plate Comment Format

The orchestrator will create the plate comment as:
```
[STUB] <summary>
Called by: <context_function>
Needs: Full variable analysis, inline comments
```

This marks the function for future full documentation while providing immediate utility.

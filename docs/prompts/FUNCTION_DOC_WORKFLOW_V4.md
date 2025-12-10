# FUNCTION_DOC_WORKFLOW_V4

Orchestrator workflow for Ghidra function documentation using model delegation.
Opus handles reasoning; Haiku handles extraction and formatting.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OPUS (Orchestrator)                      │
│  • Function classification    • Type inference              │
│  • Control flow analysis      • Semantic naming             │
│  • Algorithm extraction       • MCP tool execution          │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   HAIKU     │    │   HAIKU     │    │   HAIKU     │
│  Extract    │    │  Generate   │    │  Format     │
│  Variables  │    │  Names      │    │  Comments   │
└─────────────┘    └─────────────┘    └─────────────┘
```

---

## Phase 1: Initialize & Extract

### 1.1 Get Function Data (Opus)
```
get_current_selection() → analyze_function_complete()
```

### 1.2 Delegate Extraction (Haiku)
**Call subagent** with `subtasks/EXTRACT_VARIABLES.md`:
- Input: Decompiled code + disassembly from analyze_function_complete
- Output: JSON extraction result

Expected output format:
```json
{
  "variables": [
    {"name": "param_1", "type": "undefined4", "category": "param"},
    {"name": "local_c", "type": "undefined4", "category": "local"},
    {"name": "iVar1", "type": "int", "category": "ssa"}
  ],
  "globals": [
    {"name": "DAT_6fbf42a0", "address": "0x6fbf42a0"},
    {"name": "s_Error_6fbe1234", "address": "0x6fbe1234"}
  ],
  "ordinals": [
    {"call": "Ordinal_10342", "address": "0x6fb12340"}
  ],
  "undefined_count": 5
}
```

---

## Phase 2: Analysis (Opus)

Using Haiku's extraction, perform semantic analysis:

1. **Classify function**: Leaf | Worker | Thunk | Init | Cleanup | Callback | API | Internal
2. **Analyze callers**: Argument patterns, return value usage
3. **Map control flow**: Returns, branches, loops (verify bounds vs assembly)
4. **Detect decompiler errors**: JZ/JNZ inversion, spurious casts, wrong stride

For each undefined variable, determine correct type:
- Arithmetic operations → int/uint
- Bit operations/flags → uint  
- Dereferenced → pointer type
- Loop counter → int/uint
- Array index scaling → infer element size

---

## Phase 3: Delegate Naming (Haiku)

**Call subagent** with `subtasks/GENERATE_HUNGARIAN_NAMES.md`:
- Input: Variables with resolved types from Phase 2
- Output: Hungarian notation names

Input format:
```json
{
  "variables": [
    {"name": "param_1", "resolved_type": "UnitAny *"},
    {"name": "local_c", "resolved_type": "uint"},
    {"name": "iVar1", "resolved_type": "int"}
  ],
  "globals": [
    {"name": "DAT_6fbf42a0", "resolved_type": "uint", "purpose": "flags"},
    {"name": "s_Error_6fbe1234", "resolved_type": "char *", "purpose": "error message"}
  ]
}
```

Expected output:
```json
{
  "variable_renames": [
    {"old": "param_1", "new": "pUnit", "type": "UnitAny *"},
    {"old": "local_c", "new": "dwFlags", "type": "uint"},
    {"old": "iVar1", "new": "nIndex", "type": "int"}
  ],
  "global_renames": [
    {"old": "DAT_6fbf42a0", "new": "g_dwFlags"},
    {"old": "s_Error_6fbe1234", "new": "szErrorMessage"}
  ]
}
```

---

## Phase 4: Delegate Ordinal Lookup (Haiku)

**Call subagent** with `subtasks/LOOKUP_ORDINALS.md`:
- Input: List of ordinal calls from Phase 1
- Output: API mappings from KNOWN_ORDINALS.md

Expected output:
```json
{
  "mappings": [
    {"ordinal": "Ordinal_10342", "api": "D2Common.GetUnitStat", "params": "(pUnit, nStatId)"},
    {"ordinal": "Ordinal_10918", "api": "D2Common.RandSeed", "params": "(pSeed)"}
  ],
  "unknown": ["Ordinal_99999"]
}
```

---

## Phase 5: Apply Changes (Opus)

Execute MCP tools with Haiku's generated names:

```
1. rename_function_by_address(address, "PascalCaseName")
2. set_function_prototype(name, "return_type __conv func(params)")
3. For each variable:
   - set_local_variable_type(func_addr, old_name, new_type)
   - rename_variables(func_addr, {old: new, ...})
4. For each global:
   - rename_data(address, new_name) or rename_global_variable()
5. batch_create_labels() for any code labels
```

---

## Phase 6: Delegate Documentation (Haiku)

**Call subagent** with `subtasks/FORMAT_PLATE_COMMENT.md`:
- Input: Analysis results from Phase 2
- Output: Formatted plate comment

Input format:
```json
{
  "function_name": "ProcessPlayerSlots",
  "summary": "Iterates player inventory slots and validates each item",
  "algorithm_steps": [
    "Get inventory pointer from player unit",
    "Loop through slots 0 to max_slots",
    "For each slot, check if item exists",
    "Validate item state flags",
    "Return count of valid items"
  ],
  "parameters": [
    {"name": "pUnit", "type": "UnitAny *", "desc": "Player unit pointer"},
    {"name": "dwFlags", "type": "uint", "desc": "Validation flags"}
  ],
  "returns": {"type": "int", "desc": "Count of valid items, -1 on error"},
  "special_cases": ["Returns 0 if inventory is NULL"],
  "calling_convention": "__fastcall"
}
```

Expected output: Formatted plate comment text ready for set_plate_comment().

---

## Phase 7: Finalize (Opus)

1. Apply plate comment: `set_plate_comment(address, haiku_output)`
2. Add inline comments for complex logic: `batch_set_comments()`
3. Add ordinal comments from Phase 4 mappings

---

## Checklist

- [ ] Haiku extraction completed
- [ ] Opus classification done
- [ ] Types resolved for all undefined
- [ ] Haiku naming generated
- [ ] Haiku ordinal lookup done
- [ ] MCP tools applied
- [ ] Haiku documentation formatted
- [ ] Comments applied

---

## Output

```
DONE: FunctionName
Completed: Yes
Delegation: 3 Haiku calls (extract, name, format)
Changes: [summary]
```

---

## Subtask Reference

| Subtask | Model | Purpose |
|---------|-------|---------|
| `subtasks/EXTRACT_VARIABLES.md` | Haiku | Pattern extraction from code |
| `subtasks/GENERATE_HUNGARIAN_NAMES.md` | Haiku | Apply naming rules |
| `subtasks/LOOKUP_ORDINALS.md` | Haiku | Reference table lookup |
| `subtasks/FORMAT_PLATE_COMMENT.md` | Haiku | Template-based formatting |

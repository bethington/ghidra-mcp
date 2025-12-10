# EXTRACT_VARIABLES (Haiku Subtask)

Extract all variables, globals, and ordinal calls from Ghidra function output.
This is a pattern-matching task - no semantic analysis required.

## Input

You will receive decompiled code and/or disassembly from `analyze_function_complete()`.

## Task

Scan the code and extract:

### 1. Variables
Find ALL variable names matching these patterns:
- `param_N` - parameters
- `local_XX` - stack locals (hex offset)
- `iVar`, `uVar`, `dVar`, `fVar`, `pVar` - SSA temporaries
- `in_EAX`, `in_EBX`, etc. - register inputs
- `extraout_*` - implicit return values
- `in_stack_*` - stack parameters
- `auVar`, `abVar` - array variables
- Any variable with `undefined` type

For each, record:
- `name`: exact variable name
- `type`: current type (e.g., "undefined4", "int", "void *")
- `category`: "param" | "local" | "ssa" | "register" | "extraout" | "array"

### 2. Globals
Find ALL global references:
- `DAT_XXXXXXXX` - unnamed data
- `s_*` - auto-detected strings
- `PTR_*` - pointer data

For each:
- `name`: exact name
- `address`: hex address (extract from name)

### 3. Ordinal Calls
Find ALL ordinal function calls:
- `Ordinal_NNNNN(...)` pattern

For each:
- `call`: full ordinal name (e.g., "Ordinal_10342")
- `address`: call site address if visible

### 4. Counts
- `undefined_count`: total variables with "undefined" in their type

## Output Format

Return valid JSON:

```json
{
  "variables": [
    {"name": "param_1", "type": "undefined4", "category": "param"},
    {"name": "local_c", "type": "undefined4", "category": "local"},
    {"name": "iVar1", "type": "int", "category": "ssa"},
    {"name": "in_EAX", "type": "undefined4", "category": "register"},
    {"name": "extraout_EAX", "type": "undefined4", "category": "extraout"}
  ],
  "globals": [
    {"name": "DAT_6fbf42a0", "address": "0x6fbf42a0"},
    {"name": "s_Error_message_6fbe1234", "address": "0x6fbe1234"}
  ],
  "ordinals": [
    {"call": "Ordinal_10342", "address": "unknown"},
    {"call": "Ordinal_10918", "address": "unknown"}
  ],
  "undefined_count": 5
}
```

## Rules

1. Extract ALL matches - do not filter or skip any
2. Preserve exact names as they appear in code
3. Types should be exact Ghidra types (undefined4, not "undefined 4")
4. If address not visible, use "unknown"
5. Do NOT analyze or interpret - just extract patterns

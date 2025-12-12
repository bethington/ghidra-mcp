# FUNCTION_DOC_WORKFLOW_V4_COMPACT

Document functions in Ghidra using MCP tools.

## Initialization

Use get_current_selection() for target function. Verify boundaries with get_function_by_address; recreate if incorrect. Call analyze_function_complete for decompiled code, xrefs, callees, callers, disassembly, and variables.

## Function Naming and Prototype

Rename with rename_function_by_address using **PascalCase** verb-first names (GetPlayerHealth, ProcessInputEvent, ValidateItemSlot).

**Avoid**: snake_case prefixes, lowercase start, single words without verbs, ALL_CAPS, generic numbered suffixes.

Set return type from EAX. Use set_function_prototype with proper struct types and Hungarian-prefixed camelCase parameter names. Verify calling convention from register usage.

## Local Variable Renaming

Get ALL variables with get_function_variables including SSA temporaries, register inputs, implicit returns, and assembly-only variables.

1. **Set Types**: Use set_local_variable_type with normalized types (undefined4→uint/int/float/pointer)
2. **Rename**: Apply standard Hungarian notation prefixes

For failed renames, add PRE_COMMENT. For assembly-only variables, add EOL_COMMENT.

## Global Data Renaming

Rename ALL DAT_* and s_* globals. Use list_data_items_by_xrefs for high-impact globals. Set type with apply_data_type, rename with g_ prefix using rename_or_label.

For external/ordinal calls, add inline comments documenting behavior and reference docs/KNOWN_ORDINALS.md.

## Plate Comment

Use set_plate_comment with plain text only (Ghidra adds borders automatically). Use 2-space indentation, blank line after each section header. Include:
- One-line summary (first line)
- Algorithm: numbered steps with magic numbers in hex (e.g., "0x4e (78)")
- Parameters: 2-space indent, include register if passed via register
- Returns: all return paths (success, failure, NULL, etc.)
- Special Cases: edge cases, boundary conditions, error handling
- Structure Layout table if accessing structs (Offset|Size|Field|Type|Description)

## Inline Comments

PRE_COMMENT for decompiler: context, purpose, magic numbers, algorithm step references.
EOL_COMMENT for disassembly: concise (max 32 chars), match to assembly offsets not decompiler lines.

## Output

```
DONE: FunctionName
Changes: [brief summary]
```

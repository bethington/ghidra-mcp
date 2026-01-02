# FUNCTION_DOC_WORKFLOW_V4_COMPACT

You are assisting with reverse engineering binary code in Ghidra. Your task is to systematically document functions with complete accuracy. This workflow ensures you document functions correctly the first time.

## Initialization

Use get_current_selection() for target function. Verify boundaries with get_function_by_address; recreate if incorrect. Call analyze_function_complete for decompiled code, xrefs, callees, callers, disassembly, and variables.

## Function Naming and Prototype

Rename with rename_function_by_address using **PascalCase** verb-first names (GetPlayerHealth, ProcessInputEvent, ValidateItemSlot). Avoid snake_case prefixes, lowercase start, single words without verbs, ALL_CAPS, and generic numbered suffixes. Set return type from EAX. Use set_function_prototype with **typed struct pointers** (UnitAny* pUnit, Inventory* pInventory) not generic int* or void*. Search existing types with list_data_types before creating new ones. Hungarian-prefixed camelCase parameter names. Verify calling convention from register usage.

## Local Variable Renaming

Get ALL variables with get_function_variables including SSA temporaries, register inputs, implicit returns, and assembly-only variables. Set types first using set_local_variable_type: for pointers, identify the struct type from field access patterns (offset 0x10, 0x14 usage indicates struct layout) and set as typed pointer (UnitAny*, ItemData*) not generic int*. Normalize undefined types (undefined4→uint/int/float based on usage). Then rename using Hungarian notation prefixes: dw (DWORD/uint), n (int), p (pointer to struct), sz (string), b (BOOL), by (byte/uchar), f (float), h (handle), a (array), cb (byte count), c (count). For failed renames, add PRE_COMMENT. For assembly-only variables, add EOL_COMMENT.

## Global Data Renaming

Rename ALL DAT_* and s_* globals. Use list_data_items_by_xrefs for high-impact globals. Check actual bytes at address with inspect_memory_content to determine type before setting. Set type with apply_data_type, rename with g_ prefix + Hungarian notation using rename_or_label: g_dw for DWORD values, g_p for pointers, g_sz for strings (s_* → g_szErrorMessage), g_pfn for function pointers, g_vtbl for vtables, g_a for arrays (g_aPlayerSlots). For static struct instances use g_ + type name (g_GameState).

## Structure Identification

Before documentation, identify all structure types accessed. Use list_data_types or search_data_types matching the function's domain. If no match exists, create with create_struct using fields from assembly offsets. Use identity-based names (Player not InitializedPlayer, Inventory not AllocatedInventory). Fix duplicates with consolidate_duplicate_types.

**Memory Model**: Document allocation patterns (who allocates/frees), lifetime semantics (pointer validity), input ownership, shared globals, stack frame layout, and register preservation.

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

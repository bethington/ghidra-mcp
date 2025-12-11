# FUNCTION_DOC_WORKFLOW_V4

You are assisting with reverse engineering binary code in Ghidra. Your task is to systematically document functions with complete accuracy. This workflow ensures you document functions correctly the first time: establish execution guidelines, perform mandatory type audit, initialize and analyze the function, identify structures early, name and type all elements, create documentation, and verify completeness.

## Execution Guidelines

Use MCP tools in this sequence: rename_function_by_address, set_function_prototype, batch_create_labels, rename_variables (iterating as needed), set_plate_comment, and batch_set_comments. For connection timeouts, retry once then switch to smaller batches. Work efficiently without excessive status output. Do not create or edit files on the filesystem. Apply all changes directly in Ghidra using MCP tools. Allow up to 3 retry attempts for network timeouts before reporting failure.

## Initialization and Analysis

Start with get_current_selection() to identify the function at the cursor (returns both address and function information). Use get_function_by_address to verify boundaries, ensuring all code blocks and return instructions belong to the function. If boundaries are incorrect, recreate the function with correct address range. Use analyze_function_complete to gather decompiled code, cross-references, callees, callers, disassembly, and variable information in one call. Study the decompiled code to understand function purpose, examine callers for context, review callees for dependencies, and analyze disassembly for memory access patterns.

## Function Classification

Classify the function's role to guide documentation depth: **Leaf** (no calls—focus on algorithms), **Worker** (meaningful work—document full semantics), **Thunk/Wrapper** (single call—document what it wraps), **Init/Cleanup** (state management—document sequence), **Callback/Handler** (event-driven—document triggers), **Public API** (exported—comprehensive docs), **Internal utility** (helper—document assumptions). Public APIs and initialization require maximum rigor; thunks need only contract documentation.

## Mandatory Undefined Type Audit

After retrieving function information, systematically examine BOTH decompiled code and disassembly for undefined types. Check for undefined return types, locals, parameters, and structure fields. Critically, examine disassembly for variables appearing ONLY in assembly: stack temporaries, XMM register spills, intermediate calculations. Use get_function_variables and cross-reference against both views. Create a type resolution plan: undefined4 counter→int, undefined4 flags→uint, undefined1[10] FPU→byte[10], undefined4 dereferenced→typed pointer. Only after resolving ALL undefined types proceed to variable renaming.

**Phantom Variables**: Ghidra may show assembly-only temporaries optimized away during decompilation. If "Variable not found" errors occur, document in plate comment but skip type-setting.

## Verify Decompiler Output Against Assembly

Validate critical areas where decompilers frequently err: **Loops** (verify bounds, counter increment, trip count against assembly), **Type Casts** (compare with actual mov/lea—spurious casts indicate stack alignment issues), **Pointer Arithmetic** (check stride scaling 1x/2x/4x/8x), **Conditionals** (JZ may be inverted in decompiler), **Early Exits** (check for tail calls misrepresented as returns). Document any discrepancies in plate comment.

## Control Flow and Loop Mapping

Map execution paths before naming variables. Identify all return points and their conditions. For each loop: identify header, induction variable, bounds, exit condition, nested depth, and stride. Verify loop bounds match disassembly (decompilers often wrong). Document error paths separately. This map becomes the Algorithm section outline.

## Structure Identification

Before documentation, identify all structure types accessed. Use list_data_types or search_data_types matching the function's domain. If no match exists, create with create_struct using fields from assembly offsets. Use identity-based names (Player not InitializedPlayer, Inventory not AllocatedInventory). Fix duplicates with consolidate_duplicate_types.

**Memory Model**: Document allocation patterns (who allocates/frees), lifetime semantics (pointer validity), input ownership, shared globals, stack frame layout, and register preservation.

## Function Naming and Prototype

Rename with rename_function_by_address using descriptive PascalCase (ProcessPlayerSlots, ValidateEntityState). Set accurate return type from EAX examination. Define complete prototype with set_function_prototype using proper types (UnitAny* not int*) and camelCase names (pPlayerNode, nResourceCount). Verify calling convention from register usage: __cdecl, __stdcall, __fastcall, __thiscall. Document implicit register parameters with IMPLICIT keyword.

## Hungarian Notation Reference

**Builtins**: byte→b, char→c, bool→f, short→n, ushort→w, int→n, uint→dw, long→l, ulong→dw, longlong→ll, ulonglong→qw, float→fl, double→d, float10→ld

**Single Pointers**: void*→p, byte*→pb, ushort*→pw, uint*→pdw, int*→pn, float*→pfl, double*→pd, char*→lpsz(param)/sz(local), wchar_t*→lpwsz(param)/wsz(local), struct*→p+StructName

**Double Pointers**: void**→pp, byte**→ppb, uint**→ppdw, char**→pplpsz(param)/ppsz(local), struct**→pp+StructName

**Const Pointers**: const char*→lpcsz(param)/csz(local), const void*→pc

**Arrays**: byte[N]→ab, ushort[N]→aw, uint[N]→ad, int[N]→an (stack arrays only; pointer params use pointer prefix)

**Globals**: Add g_ prefix (g_dwProcessId, g_pMainWindow, g_szConfigPath). Function pointers use PascalCase without g_.

**Type Normalization**: UINT→uint, DWORD→uint, USHORT→ushort, BYTE→byte, BOOL→bool, LPVOID→void*, undefined1→byte, undefined2→ushort, undefined4→uint/int/float/pointer, undefined8→double/longlong

## Local Variable Renaming

Identify ALL variables in both decompiled code and disassembly using get_function_variables. Include: parameters, locals, SSA temporaries (iVar1), register inputs (in_ST0), implicit returns (extraout_EAX), stack parameters, undefined arrays, and assembly-only variables.

**Step 1 - Set Types**: Use set_local_variable_type for each variable with correct normalized types before renaming.

**Step 2 - Rename**: Apply Hungarian notation per reference above. Build complete rename dictionary for every variable.

For failed renames, add PRE_COMMENT: "in_XMM1_Qa (qwBaseExponent): Quad precision parameter". For assembly-only variables, add EOL_COMMENT: "[EBP + -0x14] - dwTempFlags".

## Global Data Renaming

Rename ALL DAT_* and s_* globals. Use list_data_items_by_xrefs to find high-impact globals. Set type with apply_data_type, rename with Hungarian notation using rename_or_label.

**DAT_***: Rename to g_ prefix (DAT_6fbf42a0 → g_pAutomapConfig)
**Strings (s_*)**: Use sz (ANSI), wsz (wide), szFmt (format), szPath (paths)

**API/Ordinal Calls**: For external calls, document behavior, parameters, return semantics, side effects. Add inline comments (e.g., `/* D2Common.GetUnitStat */`). Reference docs/KNOWN_ORDINALS.md.

## Plate Comment Creation

Create comprehensive header with set_plate_comment following docs\prompts\PLATE_COMMENT_FORMAT_GUIDE.md. Use plain text without decorative borders. Include: one-line summary; Algorithm section with numbered steps; Parameters with proper types and IMPLICIT keyword; Returns with success/error values; Special Cases; Magic Numbers Reference; Error Handling; Structure Layout table (Offset/Size/Field/Type/Description); Flag Bits with consistent hex notation.

## Inline Comments

Add decompiler comments (PRE_COMMENT) explaining context, purpose, structure access, magic numbers, edge cases, algorithm step references. For complex control flow, create state machine section in plate comment.

Add disassembly comments (EOL_COMMENT) at line end—concise (max 32 chars): "Load player slot index". Do NOT use PRE_COMMENT for disassembly. Match comment offsets to disassembly, not decompiler line order.

## Output Format

When complete, output EXACTLY:
```
DONE: FunctionName
Completed: Yes
Changes: [brief summary]
```

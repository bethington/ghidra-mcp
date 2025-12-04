# FUNCTION_DOC_WORKFLOW_V2

Document Ghidra functions via MCP tools only. Retry timeouts once, then use smaller batches. No filesystem edits.

## Phase 1: Analysis

1. **Get Context**: get_current_selection() → analyze_function_complete() for decompiled code, xrefs, callees, callers, disassembly, variables
2. **Type Audit**: Run analyze_function_completeness() → fix state-based types (InitializedX → X) with consolidate_duplicate_types()
3. **Undefined Type Resolution**: Check BOTH decompiled code AND disassembly for undefined types. Many exist only in assembly (XMM spills, stack temps). Resolve ALL before proceeding: undefined1→byte, undefined2→ushort, undefined4→uint/int/pointer, undefined8→double/longlong
4. **Phantom Variables**: Variables with is_phantom=true or "No HighVariable found" errors cannot be typed—skip them

## Phase 2: Structure Identification

Search existing structures with search_data_types(). Create with create_struct() if none match, verifying size against stride/allocation.

**Naming**: Use identity-based names (Player, Inventory, Skill) not state-based (InitializedPlayer, AllocatedBuffer). Prefer domain-specific names (UnitAny, QuestRecord, MapTile) over generic (GameObject, DataObject).

## Phase 3: Function Naming and Prototype

1. **Name**: rename_function_by_address with PascalCase (ProcessPlayerSlots, ValidateEntityState)
2. **Prototype**: set_function_prototype with typed params (UnitAny* not int*), camelCase names (pPlayerNode, nCount)
3. **Return type**: void, int/uint (status), bool, or pointer based on EAX usage
4. **Calling conventions**: __cdecl (caller cleanup), __stdcall (callee cleanup), __fastcall (ECX/EDX), __thiscall (ECX=this)
   - D2: __d2call (EBX), __d2regcall (EBX/EAX/ECX), __d2mixcall (EAX/ESI), __d2edicall (EDI)
5. Use get_decompiled_code(refresh_cache=True) ONLY after structural changes (create_struct, set_function_prototype)

## Phase 4: Hungarian Notation

**Type normalization** (always use lowercase builtins): UINT/DWORD→uint, USHORT/WORD→ushort, BYTE→byte, BOOL→bool, LPVOID/PVOID→void*

**Prefix mapping**:
| Type | Prefix | Global | Example |
|------|--------|--------|---------|
| byte | b/by | g_b | bFlags, g_bMode |
| char | c/ch | g_c | cDelimiter |
| bool | f | g_f | fEnabled, g_fInitialized |
| short | n/s | g_n | nIndex |
| ushort | w | g_w | wPort, g_wVersion |
| int | n/i | g_n | nCount, g_nOffset |
| uint | dw | g_dw | dwFlags, g_dwProcessId |
| longlong | ll | g_ll | llTimestamp |
| ulonglong | qw | g_qw | qwSize |
| float | fl | g_fl | flDelta |
| double | d | g_d | dPrecision |
| float10 | ld | g_ld | ldExtended |
| void* | p | g_p | pData, g_pConfig |
| byte* | pb | g_pb | pbBuffer |
| uint* | pdw | g_pdw | pdwFlags |
| char* | sz/lpsz | g_sz | szPath (local), lpszFile (param) |
| wchar_t* | wsz/lpwsz | g_wsz | wszName (local), lpwszUser (param) |
| struct* | pName | g_pName | pUnitAny, g_pPlayer |
| void** | pp | g_pp | ppData |
| struct** | ppName | g_ppName | ppUnitAny |
| byte[N] | ab | g_ab | abKey |
| uint[N] | ad | g_ad | adTable |
| HANDLE | h | g_h | hProcess |
| func ptr | pfn | (PascalCase) | pfnCallback |

## Phase 5: Variable Renaming

**Step 1 - Set Types**: Use set_local_variable_type for ALL variables before renaming. Use complete declarations ("uint *" not "pointer").

**Step 2 - Rename**: Apply Hungarian notation via rename_variables. Prefix MUST match Ghidra type.

## Phase 6: Global Data Renaming

Rename ALL globals with Hungarian notation using rename_or_label:

| Pattern | Action |
|---------|--------|
| DAT_* | analyze_data_region → g_[prefix]Name (g_dwFlags, g_pConfig) |
| s_* strings | sz/wsz + descriptive name (s_%s\path → szFormatPath) |

**Inline Comments**: Do NOT add PRE_COMMENT, POST_COMMENT, or EOL_COMMENT unless absolutely necessary to convey critical non-obvious information. The plate comment and proper naming should be sufficient.

## Phase 7: Plate Comment

Use set_plate_comment following docs/prompts/PLATE_COMMENT_FORMAT_GUIDE.md:

```
One-line summary.

Algorithm:
1. First step
2. Second step...

Parameters:
- pUnit (UnitAny*): Description
- IMPLICIT: EBX contains context pointer

Returns:
- 1 on success, 0 on failure

Magic Numbers:
- 0x24 (36): Structure stride
- 0x80: Binary mode flag
```

Optional sections: Special Cases, Structure Layout (table format), Flag Bits, Related Functions.

Use consistent hex notation (0x80, not 128). Verify algorithm steps match actual code logic—especially bitwise conditions where semantics can invert.

## Phase 8: Verification

Run analyze_function_completeness() and fix ALL reported issues:
- plate_comment_issues, hungarian_notation_violations, undefined_variables
- type_quality_issues, undefined_type_globals, unnamed_globals

Iterate until 100% score. After 3 failed attempts with different strategies, document blockers and proceed.

**Orphaned Functions**: After completion, check for executable code after RET with no xrefs—use create_function if found.

## Output

```
DONE: FunctionName
Score: XX%
Changes: [summary]
```
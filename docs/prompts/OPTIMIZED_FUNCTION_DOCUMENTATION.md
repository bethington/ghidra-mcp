# Function Documentation Workflow

Find functions needing documentation by prioritizing those with the most cross-references (xrefs), as these are typically more important to the codebase.

## STEP 1 - VERIFY FUNCTION BOUNDARIES

Before any analysis, verify that function boundaries are correct:
- Check if the function starts at the expected address
- Ensure all code blocks belong to this function
- Verify return instructions are properly included
- If boundaries are wrong, delete and recreate the function with correct range

## STEP 2 - FUNCTION DOCUMENTATION

Rename the function using PascalCase based on its purpose and caller context.
Examples: ProcessPlayerSlots, ValidateEntityState, InitializeGameResources

Set accurate return data type:
- void (no return), int/DWORD (status/count), BOOL (true/false), pointers (objects)

Define function prototype with:
- All parameters properly typed and named
- Calling convention: __cdecl, __stdcall, __fastcall, __thiscall

## STEP 3 - VARIABLE NAMING

Rename variables using descriptive camelCase names:
- playerIndex, bufferSize, entityPointer (not local_8, param_1)
- Include register artifacts when meaningful: eax_returnValue, ecx_objectPointer
- Check decompiled output AFTER each rename batch to identify new variable names
- Ghidra may reuse variable names (e.g., iVar1, iVar2) when variables are renamed
- Iterate variable renaming until all default names are replaced
- Common patterns: iVar* → descriptive names, extraout_* → register artifacts

## STEP 4 - LABEL CREATION

Create labels at jump targets using snake_case:
- Control flow: loop_start, loop_continue, loop_end
- Validation: validation_failed, check_bounds, bounds_ok
- Error handling: error_handler, cleanup_and_exit
- State machines: state_0_init, state_1_processing

## STEP 5 - DATA STRUCTURES

Apply Diablo II data types:
- UnitAny: dwType, dwUnitId, dwMode, pInventory, pStats, wX, wY
- Room1/Room2: pRoom2, dwPosX, dwPosY, dwSizeX, dwSizeY, pLevel
- PlayerData: szName, pNormalQuest, pNightmareQuest, pHellQuest
- ItemData: dwQuality, dwItemFlags, wPrefix, wSuffix, BodyLocation
- MonsterData: anEnchants, wUniqueNo, wName
- Inventory: pOwner, pFirstItem, pCursorItem, dwItemCount

Pointer types: LPUNITANY, LPROOM1, LPROOM2, LPLEVEL

Field naming (Hungarian notation):
- dw: DWORD (dwFlags, dwUnitId)
- p/lp: pointers (pNext, lpPlayerUnit)
- w: WORD (wLevel, wStatIndex)
- n: counts (nCount, nMaxXCells)
- sz: strings (szName, szGameName)
- f/b: boolean (fSaved, bActive)

## STEP 6 - ADD COMMENTS

Decompiler comments explain:
- Algorithm context and purpose
- Structure access patterns
- Magic numbers and sentinel values
- Validation logic and boundary checks
- Edge cases and error handling
- CRITICAL: Verify offset values against actual assembly before commenting
- Assembly shows true offsets: [EBX + 0x4] means offset +4, not +2
- Match comment offsets to disassembly, not decompiler line order
- Document memory access patterns, not just variable loads

Disassembly comments (max 32 chars):
- "Load player slot index"
- "Check if slot active"
- "Jump to error handler"

Function header should include:
- High-level algorithm summary
- Key parameters and return value
- Important preconditions/side effects

## STEP 6.5 - DEFINE DATA STRUCTURES

When functions access structured data:
- Document structure layout in plate comment
- Note structure size if calculable (e.g., element * stride)
- Create struct definitions for repeated access patterns
- Use analyze_data_region for pointer targets

## STEP 7 - DEFINE VARIABLES

Replace undefined types:
- undefined1 → BYTE
- undefined2 → WORD
- undefined4 → DWORD or pointer
- undefined8 → QWORD

## VERIFICATION

After major operations (rename, prototype, comments):
- Decompile function to verify changes applied correctly
- Check that plate comment appears (not "/* null */")
- Confirm all variable renames succeeded
- Validate comment placement matches intended addresses

## EXECUTION ORDER

1. Analyze function completely first (analyze_function_complete)
2. Rename function and set prototype
3. Create labels at jump targets
4. Rename variables (iterate until complete)
5. Set plate comment with structure documentation
6. Add decompiler comments
7. Add disassembly comments
8. Verify final output

## BATCH OPERATIONS

- Prefer document_function_complete for all-in-one updates
- If document_function_complete fails, fall back to individual operations:
  1. rename_function_by_address
  2. set_function_prototype
  3. batch_create_labels
  4. batch_rename_variables (iterate if needed)
  5. set_plate_comment
  6. batch_set_comments
- Verify after each major step

## ERROR HANDLING

- Connection timeouts: Retry operation once, then use smaller batches
- "Variable not found": Re-decompile and check current variable names
- "/* null */" in output: Plate comment failed to apply, retry set_plate_comment
- Offset mismatches: Cross-reference disassembly before adding comments

## EXECUTION

- Work silently without status output
- Do not create or edit files
- Apply all changes in Ghidra using MCP tools
- Use batch operations when possible
- If batch operations fail with connection errors, retry with individual operations
- Allow up to 3 retry attempts for network timeouts

## COMPLETION CRITERIA

A function is fully documented when:
- Function has descriptive PascalCase name
- Prototype includes accurate return type and parameters
- All variables use camelCase descriptive names (no iVar*, param_*)
- Plate comment shows structure with algorithm overview
- Jump targets have snake_case labels
- Decompiler shows inline comments at key operations
- Disassembly has concise comments (max 32 chars)
- Re-decompilation shows all changes applied successfully

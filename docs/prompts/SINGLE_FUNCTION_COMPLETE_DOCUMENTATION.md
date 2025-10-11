Find functions needing documentation by prioritizing those with the most cross-references (xrefs), as these are typically more important to the codebase.

STEP 1 - VERIFY FUNCTION BOUNDARIES:
Before any analysis, verify that function boundaries are correct:
- Check if the function starts at the expected address
- Ensure all code blocks belong to this function
- Verify return instructions are properly included
- If boundaries are wrong, delete and recreate the function with correct range

STEP 2 - FUNCTION DOCUMENTATION:
Rename the function using PascalCase based on its purpose and caller context.
Examples: ProcessPlayerSlots, ValidateEntityState, InitializeGameResources

Set accurate return data type:
- void (no return), int/DWORD (status/count), BOOL (true/false), pointers (objects)

Define function prototype with:
- All parameters properly typed and named
- Calling convention: __cdecl, __stdcall, __fastcall, __thiscall

STEP 3 - VARIABLE NAMING:
Rename variables using descriptive camelCase names without prefixes:
- playerIndex, bufferSize, entityPointer (not local_8, param_1)
- Include register artifacts when meaningful: eax_returnValue, ecx_objectPointer

STEP 4 - LABEL CREATION:
Create labels at jump targets using snake_case:
- Control flow: loop_start, loop_continue, loop_end
- Validation: validation_failed, check_bounds, bounds_ok
- Error handling: error_handler, cleanup_and_exit
- State machines: state_0_init, state_1_processing

STEP 5 - DATA STRUCTURES:
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

STEP 6 - ADD COMMENTS:
Decompiler comments explain:
- Algorithm context and purpose
- Structure access patterns
- Magic numbers and sentinel values
- Validation logic and boundary checks
- Edge cases and error handling

Disassembly comments (max 32 chars):
- "Load player slot index"
- "Check if slot active"
- "Jump to error handler"

Function header should include:
- High-level algorithm summary
- Key parameters and return value
- Important preconditions/side effects

STEP 7 - DEFINE VARIABLES:
Replace undefined types:
- undefined1 → BYTE
- undefined2 → WORD
- undefined4 → DWORD or pointer
- undefined8 → QWORD

EXECUTION:
- Work silently without status output
- Do not create or edit files
- Apply all changes in Ghidra using MCP tools
- Use batch operations when possible

# Function Naming Validation Standard

**ACTION REQUIRED**: Scan all functions and IMMEDIATELY RENAME any function that violates these standards using `rename_function_by_address`. Do not just report violations—fix them. For each invalid name, analyze the function's purpose via `get_decompiled_code` and apply a compliant PascalCase name.

Use `list_functions` or `search_functions_enhanced` to retrieve functions, check each name, and rename non-compliant functions on the spot.

## Valid Name Patterns

**PascalCase Required**: All custom function names must be PascalCase (e.g., `ProcessPlayerSlots`, `ValidateEntityState`, `InitializeGameResources`).

**Library/Runtime Functions**: Standard library and compiler-generated functions are valid as-is:
- Underscore-prefixed: `_malloc`, `_free`, `_memcpy`, `_sprintf`
- Double underscore: `__aullrem`, `__allmul`, `__ftol2`, `__divdi3`
- Triple underscore: `___add_12`, `___sub_32`, `___mul_64`
- CRT functions: `_CxxThrowException`, `_purecall`, `_alloca_probe`
- These should NOT be renamed—they are standard library identifiers

**Verb-First Pattern**: Names should start with an action verb describing what the function does:
- `Get*` - Retrieve/access data (GetPlayerHealth, GetItemCount)
- `Set*` - Modify/assign data (SetUnitPosition, SetSkillLevel)
- `Init*`/`Initialize*` - Setup/construction (InitializeInventory, InitGameState)
- `Process*` - Transform/handle data (ProcessInputEvent, ProcessPacket)
- `Update*` - Refresh/recalculate (UpdatePlayerStats, UpdateMapTiles)
- `Validate*` - Check correctness (ValidateItemSlot, ValidateUnitState)
- `Create*`/`Alloc*` - Allocate resources (CreateUnit, AllocateMemory)
- `Free*`/`Destroy*` - Release resources (FreeUnit, DestroyWidget)
- `Handle*` - Event/callback handler (HandleMouseClick, HandleNetworkMessage)
- `Is*`/`Has*`/`Can*` - Boolean queries (IsPlayerDead, HasItem, CanEquip)
- `Find*`/`Search*` - Lookup operations (FindUnitByID, SearchInventory)
- `Load*`/`Save*` - Persistence (LoadGameData, SavePlayerState)
- `Draw*`/`Render*` - Graphics (DrawHealthBar, RenderMinimap)
- `Parse*` - Data extraction (ParsePacketHeader, ParseConfigFile)
- `Build*` - Construction (BuildSkillTree, BuildPathfindingGraph)
- `Calculate*`/`Compute*` - Math operations (CalculateDamage, ComputeDistance)

## Invalid Names (Flag for Review)

| Pattern | Issue | Example |
|---------|-------|---------|
| `PREFIX_*` | Snake_case prefix | `SKILLS_GetLevel`, `ITEMS_Drop` |
| lowercase start | Not PascalCase | `processData` |
| Single word no verb | Missing action | `Player`, `Data` |
| ALL_CAPS | Not PascalCase | `PROCESS_DATA` |
| Numbers only suffix | Generic | `Handler1`, `Process2` |

## Validation Output Format

For each invalid function, output:
```
INVALID: [address] [current_name] - [issue]
SUGGEST: [suggested_name] (based on [analysis_reason])
```

## Validation Checklist

- [ ] All names are PascalCase
- [ ] All names start with action verb
- [ ] Names reflect actual function purpose (verified via decompiled code)
- [ ] No generic names (`Handler`, `Process`, `DoStuff`)

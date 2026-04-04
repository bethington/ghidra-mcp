# Fix: Unresolved Struct Accesses

**Category**: `unresolved_struct_accesses`
**Trigger**: Raw pointer+offset dereferences (e.g., `*(ptr + 0x150)`, `param_1[0x2C]`)

## Allowed Tools
- `get_struct_layout`
- `search_data_types` (required before `create_struct`)
- `create_struct`
- `modify_struct_field`
- `add_struct_field`
- `set_local_variable_type`
- `set_parameter_type`

## Struct Creation Gate

**Do NOT call `create_struct` until you have checked for reusable existing structs.**

1. Check if the base pointer variable is already typed as a known struct -- `get_struct_layout`
2. Search for existing structs with compatible offsets -- `search_data_types` with a likely name
3. Check common D2 structs that match the offset pattern (UnitAny, Room, DrlgRoom, ItemData, etc.)

**Only create a new struct if:**
- No existing struct covers the accessed offsets, AND
- You have at least 3 validated fields (not just one offset), AND
- The struct is accessed from 2+ code paths in the function

**If only 1-2 offsets are accessed:** use EOL comments instead (`/* +0x5C: field */`). This is always the safer choice and satisfies the scorer.

## Recipe

1. **Identify the base pointer** -- which variable is being dereferenced? What's its current type?
2. **Check existing structs** (reuse-first):
   - `get_struct_layout(struct_name)` if the variable is already typed as a struct pointer
   - `search_data_types(name_pattern)` to find structs with matching names or known patterns
   - If a compatible struct exists: apply it via `set_local_variable_type(var, "ExistingStruct *")`
3. **Create new struct only if gate conditions are met**:
   - Fields must be a JSON array:
     ```json
     [{"offset": 0, "name": "dwField00", "type": "uint", "size": 4},
      {"offset": 4, "name": "pField04", "type": "void *", "size": 4}]
     ```
     Do NOT use `name:type` string format -- it will fail silently.
4. **Wire the types together**:
   - `modify_struct_field(struct, "offset:16", new_type="uint", new_name="dwField10")` for unnamed fields
   - `set_local_variable_type(var, "BaseStruct *")` to apply the struct type
5. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Naming Confidence

**Struct names**: Use `FunctionNameCtx`, `FunctionNameNode`, or `FunctionNameEntry` unless the struct's role is directly proven. Do NOT use generic domain names like `TileData` or `RoomInfo` based on inference alone.

**Field names**: Use `dwField04`, `pField20`, `nField1D0` for fields whose purpose is not directly proven. Only use semantic names (`dwTileCount`, `pNextNode`) when justified by:
- The field is compared against a known constant
- The field is passed to a function with typed parameters
- The field controls a loop or branch with clear semantics

**Name collisions**: If a candidate struct name already exists with an incompatible layout, create a function-specific struct (e.g., `InitRoomTilesCtx`) rather than modifying the existing shared struct.

## Skip Conditions (prefer these over struct creation)
- If only 1-2 offsets are accessed: use EOL comments (`/* +0x10: flags */`) instead of creating a struct
- If the offset pattern doesn't match any known struct and creating one would be speculative: comment-only fallback
- Prefer a correct EOL comment over a speculative struct with wrong field names
- If a recipe step fails or doesn't apply (e.g., struct already exists, field already typed correctly), skip it

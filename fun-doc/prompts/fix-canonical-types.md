# Fix: Non-Canonical Types

**Category**: `non_canonical_type`
**Trigger**: A parameter, local, or return value that is TYPED but not with a canonical D2MOO
type — a `void *` that should be a specific D2 struct pointer, or a named struct/enum that is
not part of D2MOO's vocabulary (a community/Ghidra name that has a D2 equivalent, e.g. `UnitAny`
→ `D2UnitStrc`, `Room` → `D2RoomStrc`).

## Allowed Tools
- `get_function_variables`
- `search_data_types` (find the canonical D2MOO type — filter for `D2` names)
- `set_variables` (atomic type + rename — **strongly preferred** for ≥2 variables)
- `set_parameter_type` / `set_local_variable_type` (single fallback)
- `set_function_prototype` (return type)

## Recipe

1. **Review the flagged items** (in the deduction's `items` list) — each names the variable, its
   current type, and why it's non-canonical.
2. **Resolve the real D2MOO type from usage.** Read the decompiled source: what fields are read
   off the pointer, what function consumes it, what the offsets imply. Then find the canonical
   D2MOO struct with `search_data_types` (pattern `D2`) — the type vocabulary was loaded from the
   D2MOO headers, so the correct struct (`D2UnitStrc`, `D2ItemsTxt`, `D2RoomStrc`, `D2GameStrc`, …)
   is present in the type manager.
3. **Prefer the D2MOO name over a community name.** If a variable is `UnitAny *`, `Room *`,
   `Inventory *`, retype it to the D2MOO equivalent (`D2UnitStrc *`, `D2RoomStrc *`,
   `D2InventoryStrc *`). Matching D2MOO's actual C vocabulary is the goal.
4. **Apply all changes in ONE atomic `set_variables` call** when touching ≥2 variables — each
   individual `set_*_type` re-decompiles and renumbers SSA variables, invalidating names from the
   earlier snapshot.
5. Scoring is handled externally — do not call `analyze_function_completeness`.

## What is NOT flagged (do not "fix")
- **Scalar width types** (`uint`, `int`, `byte`, `ushort`, `ulonglong`, `char`, `bool`): these are
  Ghidra's faithful representation of D2MOO's `uint32_t`/`uint8_t`/etc. Ghidra collapses the stdint
  typedefs back to these builtins on display, so "retyping `uint` → `uint32_t`" does not stick and
  is NOT required. Leave scalar-width types alone.
- **`undefined*` types**: handled by the separate `undefined_variables` fix — not here.

## Skip Conditions
- `__thiscall` `void*` `this` (ECX auto-param): cannot be retyped via the API. Document the intended
  D2MOO struct in the plate comment's Parameters section instead.
- Register-only / phantom variables (`is_phantom: true`, `in_*`, `extraout_*`): if a `set_*_type`
  call fails, document the intended type via PRE_COMMENT instead.
- A genuine `void *` that is truly opaque (a raw buffer, an allocator return with no struct
  identity): leave as `void *` and note it in the plate comment — do not invent a struct.

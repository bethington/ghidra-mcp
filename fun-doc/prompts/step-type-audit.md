# Step 3: Type Audit + Variable Renaming

## Allowed Tools
- `get_function_variables` (refresh after prototype changes in Step 2)
- `set_variables` (atomic type + rename in one call — **strongly preferred**)
- `set_local_variable_type` (single-variable fallback only)
- `set_parameter_type` (single-parameter fallback only)
- `rename_variables` (batch rename only, if types already resolved)
- `set_function_prototype` (only if this-pointer type needs fixing)

## Instructions

**If prototype was changed in Step 2**: Call `get_function_variables(address=...)` once to refresh — pass the function's address (not its name; names can race against in-flight renames). The inline variable list may be stale due to SSA variable creation.

**Skip condition**: All variables have custom names AND resolved storage types (no `undefined` in type field) -> skip to Step 4.

**Required approach**: Use **one** `set_variables` call covering EVERY type and rename change. Do NOT issue individual `set_local_variable_type` / `set_parameter_type` calls in sequence — each one triggers a fresh decompilation pass that renumbers SSA variables (`iVar3` becomes `iVar4`, `psVar5` becomes `psVar4`, etc.). Variable names you planned from the original decompile output go stale after the very first individual call, and subsequent calls will fail with `Variable '<name>' not found in decompiled function`. The atomic `set_variables` transaction sets everything before re-decompiling, so it never sees that race. **Skip the call entirely if you have no type changes AND no renames** — calling `set_variables` with an empty `variables` map is a wasted round-trip even though the server treats it as a no-op success.

**Type audit** -- walk EVERY parameter and local variable:

1. For each variable where type contains `undefined`: determine correct type based on usage context
2. For each parameter where name has pointer prefix (`p`, `pp`, `lpsz`) but type is `int`/`uint`: fix type to a pointer
3. **Known limitation: `__thiscall` ECX `this` pointer** -- Ghidra's ECX auto-param for `__thiscall` functions cannot be retyped via `set_function_prototype`. Including a typed `this` in the prototype either gets ignored (still shows `void *`) or creates a spurious extra stack parameter. Do NOT attempt to type the `this` pointer. Instead, document the intended type in the plate comment Parameters section: `this: TreasureCtx * - (ECX auto-param, type not settable via API)`. The completeness scorer treats this as structural/unfixable.
4. Skip phantoms (`is_phantom: true`, `extraout_*`, `in_*`, and stack-frame-only `local_*` entries that are not visible in the decompiled source). These are not retypable via API. Do not call `set_local_variable_type` on them. Document the intended role via `PRE_COMMENT` or the plate comment if useful. The completeness scorer excludes them from fixable penalty.

**Naming confidence**: Apply the Naming Confidence Rules from Core Rules. Before renaming any variable:
- Can you justify the name from direct read/write behavior, control-flow role, or constant comparison?
- If YES: use the descriptive Hungarian name (e.g., `dwItemCount` for a counter compared against record count)
- If NO: use a conservative placeholder (`dwUnknown04`, `pUnk20`, `nValue0C`)
- NEVER name a field semantically when the meaning is inferred from a single comparison or indirect evidence

**After all type changes**: Issue a single `rename_variables` call covering ALL variables with Hungarian names matching their NOW-RESOLVED types. Or use `set_variables` for the combined operation.

**Register/ECX variables**: When `set_local_variable_type()` fails for a register variable, document the type via `PRE_COMMENT` in Step 4. The completeness scorer excludes these from penalty.

**`unaff_` variables** (e.g., `unaff_ESI`, `unaff_EBX`): These are callee-saved registers the decompiler detected as unaffected. When renaming:
- If the register is used as a pointer: use `p` + struct/context name (e.g., `pCtx`, `pBoundsCtx`)
- If the register is used as an integer: use `n` + role (e.g., `nSavedCount`)
- If unclear: use the register name as suffix (e.g., `pUnkESI`, `nUnkEBX`)

**SSA variable churn**: Every `set_function_prototype` or `set_local_variable_type` call triggers re-decompilation, which may create new SSA variables (iVar1, uVar1, etc.). Budget one final rename pass after ALL type changes are complete. If a rename fails due to name collision from SSA churn, skip it. Using `set_variables` minimizes this issue.

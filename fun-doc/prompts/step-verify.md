# Step 5: Consistency Check + Report

Do NOT call `analyze_function_completeness` -- scoring is handled externally after this prompt completes.

## Consistency Checklist (required before reporting DONE)

Before finalizing, verify these alignments:

1. **Function name vs plate comment summary**: If you renamed the function, does the plate comment's first line (summary) still match? Update if stale.
2. **Function name vs plate comment Returns/Parameters**: Do the Returns and Parameters sections use terminology consistent with the new name?
3. **Prototype vs plate comment Parameters**: Do the parameter names and types in the plate comment match the actual prototype?
4. **Module prefix vs Source line**: If the function has a module prefix, does the Source: line reference a matching .cpp file?
5. **Name vs behavior contradiction**: Does the function name describe the ACTUAL behavior? If the name says "Head" but the code inserts at "tail" (or vice versa), rename the function to match the real behavior.
6. **Magic number coverage**: If the code contains hex constants (flags, type IDs, offsets), verify they have EOL comments at their instruction addresses via `batch_set_comments` with `disassembly_comments`.

If any mismatch is found: fix it via `batch_set_comments` (plate comment update) or `rename_function_by_address` before reporting DONE.

## Variable Reconciliation (required before reporting DONE)

Call `get_function_variables(address=...)` one final time using the function's
address (not its name — names can race against in-flight renames). Check:

1. **No generic names remaining**: Every variable still named `[a-z]Var[0-9]+` or `local_*` must be renamed via `rename_variables()` or listed in Unresolved with justification.
2. **Prefix matches type**: Every renamed variable's Hungarian prefix must match its Ghidra type:
   - `p` prefix → must be a pointer type (ends with `*`)
   - `dw` prefix → must be `uint` or `ulong`
   - `n` prefix → must be `int` or `short`
   - `w` prefix → must be `ushort`
   - `sz` prefix → must be `char *`
   If a mismatch exists, fix the type with `set_local_variable_type()` OR fix the name with `rename_variables()`.
3. **Plate comment references applied**: If your plate comment's Special Cases or Parameters section names a variable differently from what's in the `get_function_variables(address=...)` response, apply the rename. Do not document names you didn't actually set.

## Report Format

```
DONE: FunctionName
Changes: [brief summary of what you changed]
Proven: [changes backed by callers, constants, or typed APIs]
Inferred: [names/types based on internal usage only -- not verified at call sites]
Unresolved: [structural limitations, phantom variables, unfixable items]
Consistency: [PASS or list of fixes applied]
```

## Known Unfixable Items (do not attempt)

If you encountered any of these during Steps 1-4, note them in your report but do not retry:
- Phantom variables (`extraout_*`, `in_*`) -- documented in plate comment
- Register-only SSA variables -- type set via PRE_COMMENT
- `__thiscall` ECX `this` pointer -- cannot be retyped via API, documented in plate comment
- void* on exported/thunk functions -- structural limitation

# Step 5: Consistency Check + Report

Do NOT call `analyze_function_completeness` -- scoring is handled externally after this prompt completes.

## Consistency Checklist (required before reporting DONE)

Before finalizing, verify these alignments:

1. **Function name vs plate comment summary**: If you renamed the function, does the plate comment's first line (summary) still match? Update if stale.
2. **Function name vs plate comment Returns/Parameters**: Do the Returns and Parameters sections use terminology consistent with the new name?
3. **Prototype vs plate comment Parameters**: Do the parameter names and types in the plate comment match the actual prototype?
4. **Module prefix vs Source line**: If the function has a module prefix, does the Source: line reference a matching .cpp file?

If any mismatch is found: fix it via `batch_set_comments` (plate comment update) before reporting DONE.

## Report Format

```
DONE: FunctionName
Changes: [brief summary of what you changed]
Consistency: [PASS or list of fixes applied]
```

## Known Unfixable Items (do not attempt)

If you encountered any of these during Steps 1-4, note them in your report but do not retry:
- Phantom variables (`extraout_*`, `in_*`) -- documented in plate comment
- Register-only SSA variables -- type set via PRE_COMMENT
- `__thiscall` ECX `this` pointer -- cannot be retyped via API, documented in plate comment
- void* on exported/thunk functions -- structural limitation

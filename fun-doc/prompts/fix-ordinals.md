# Fix: Undocumented Ordinals

**Category**: `undocumented_ordinals`
**Trigger**: References to unnamed ordinal functions (e.g., Ordinal_10024) in the decompiled code

## Allowed Tools
- `batch_set_comments`
- `rename_function_by_address` (if the ordinal function itself needs naming)

## Recipe

1. **Review the evidence list** -- each entry identifies the ordinal number and where it's referenced
2. **Check if the ordinal has a known name**:
   - Look in the decompiled source context for clues about what the ordinal does
   - Cross-reference with the plate comment's existing ordinal documentation
   - If the ordinal's function is already named elsewhere in the program, use that name
3. **Document via comments**: Add EOL_COMMENT at the call site with the ordinal's purpose
   - Format: `/* Ordinal_10024: LogArchiveError */`
4. **If the ordinal function itself is unnamed**: `rename_function_by_address` to give it a descriptive name
5. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Skip Conditions
- IAT thunks that just forward to another DLL: document as `/* thunk -> DLL.Function */` and move on

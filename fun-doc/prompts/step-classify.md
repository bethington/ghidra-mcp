# Step 1: Classify Function

## Allowed Tools
- `analyze_for_documentation` (only if not provided inline)
- `rename_function_by_address` (if boundaries need recreating)
- `create_function` (if function needs to be defined)

## Instructions

From the inline `analyze_for_documentation` output:

1. **Verify function boundaries** -- recreate with correct range if incorrect
2. **Check `return_type_resolved`** -- if false, verify EAX at each RET instruction. Check `wrapper_hint`.
3. **Validate existing name** -- even custom names may be wrong. Verify the name describes what the function actually does.
4. **Classify for routing**:
   - **Thunks/wrappers** (single call, no logic): fast path -- skip to Step 2 (rename only) then Step 4 (minimal plate comment) then Step 5 (verify). Skip Steps 3.
   - **Everything else**: full workflow Steps 2-5.

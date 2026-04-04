# Fix: Unrenamed Labels

**Category**: `unrenamed_labels`
**Trigger**: LAB_* references in decompiled code

## Allowed Tools
- `rename_or_label`

## Recipe

1. **Review the evidence list** -- each entry identifies the label address and current LAB_* name
2. **Determine purpose from context**:
   - Loop headers: `loop_processItems`, `loop_scanEntries`
   - Error handlers: `err_nullPointer`, `err_invalidParam`
   - Branch targets: `skip_validation`, `done_cleanup`
   - Switch cases: `case_playerType`, `case_monsterType`
3. **Rename each label**: `rename_or_label(address, descriptive_name)` -- use snake_case for labels
4. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Skip Conditions
- Labels that only appear in the disassembly but not the decompiled code are lower priority

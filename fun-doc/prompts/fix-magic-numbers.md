# Fix: Undocumented Magic Numbers

**Category**: `undocumented_magic_numbers`
**Trigger**: Hex/numeric constants in decompiled code without explanatory comments

## Allowed Tools
- `batch_set_comments`

## Recipe

1. **Review the evidence list** -- each entry identifies an address and the magic number
2. **Determine the meaning** from context in the decompiled source:
   - Struct offsets: `+0x14` -> document the field name
   - Type IDs: `== 0x0` -> "PLAYER type", `== 0x1` -> "MONSTER type"
   - Flags/masks: `& 0xFF` -> "low byte mask"
   - Table indices, sizes, sentinel values
3. **Apply via single `batch_set_comments` call**:
   - Use `EOL_COMMENT` at the instruction address for each magic number
   - Max 32 chars per EOL comment
   - Format: `0x4E = 78 (quest flag)` or `type == PLAYER`
4. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Skip Conditions
- Common obvious constants (0, 1, -1, NULL) typically don't need comments unless the scorer flags them

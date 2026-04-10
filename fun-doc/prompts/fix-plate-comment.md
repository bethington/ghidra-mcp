# Fix: Missing or Incomplete Plate Comment

**Category**: `missing_plate_comment`
**Trigger**: Function has no plate comment, or plate comment is missing required sections

## Allowed Tools
- `batch_set_comments`

## Recipe

1. **Check what's missing** from the completeness evidence -- it may be the entire plate comment or specific sections
2. **Write the plate comment** following this format (plain text only):

```
One-line function summary.

Algorithm:
1. [Step with hex magic numbers, e.g., "check type == 0x4E (78)"]
2. [Each step is one clear action]

Parameters:
  paramName: Type - purpose description [IMPLICIT EDX if register-passed]

Returns:
  type: meaning. Success=non-zero, Failure=0/NULL. [all return paths]

Special Cases:
  - [Edge cases, phantom variables, decompiler discrepancies]
  - [Magic number explanations, sentinel values]

Structure Layout: (only if function accesses structs)
  Offset | Size | Field     | Type  | Description
  +0x00  | 4    | dwType    | uint  | ...
```

**REQUIRED sections**: Summary (first line), Source, Parameters, Returns. These must ALWAYS be present.
Derive Source from module prefix (e.g., ROOM_ → DrlgRoom.cpp, PATH_ → Path.cpp). If unknown, use `Source: Unknown`.

3. **Apply**: Single `batch_set_comments` call with `plate_comment` parameter. Can include PRE and EOL comments in the same call.
4. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Inference Labeling

In the Parameters and Returns sections, distinguish proven facts from inferences:
- **Proven** (from callers, constants, typed APIs): state directly. Example: `nUnitType: int - unit type (0=player, 1=monster, 5=item) from UnitAny+0x00`
- **Probable** (inferred from internal usage only, not verified at call sites): prefix with `Probable:`. Example: `nCostMode: int - Probable: cost calculation mode (0/1/2 switch observed) -- not verified at call sites`

Do NOT present inferred parameter roles as settled facts. A readable plate comment with wrong semantics is worse than a conservative one.

## Important
- `set_function_prototype` wipes plate comments. NEVER set prototype after writing the plate comment.
- Use actual multi-line text in the plate_comment parameter. `\n` escape sequences create literal text, NOT newlines.

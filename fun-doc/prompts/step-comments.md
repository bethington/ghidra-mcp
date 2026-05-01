# Step 4: Comments

## Allowed Tools
- `batch_set_comments` (plate + PRE + EOL in ONE call)
- `rename_or_label` (for DAT_*/s_* globals, with g_ prefix)
- `apply_data_type` (to set type on globals)

**IMPORTANT**: This step must be AFTER all naming/prototype/type changes are complete.

### `batch_set_comments` exact schema
```json
{
  "address": "0x6fd6e920",
  "plate_comment": "Full plate text here...",
  "decompiler_comments": [
    {"address": "0x6fd6e920", "comment": "PRE comment text"}
  ],
  "disassembly_comments": [
    {"address": "0x6fd6e925", "comment": "EOL comment text"}
  ]
}
```
- `address`: Function entry address for the plate comment target and batch anchor.
- `plate_comment`: Full plate text. Omit to leave existing plate untouched. Empty string clears it.
- `decompiler_comments`: Array of `{address, comment}` objects for PRE_COMMENTs.
- `disassembly_comments`: Array of `{address, comment}` objects for EOL_COMMENTs.
- Pass real arrays/objects for comment lists. Do not JSON-stringify nested comment payloads.
- `program`: Pass as query parameter, NOT in JSON body.

## Instructions

1. **Rename globals**: Any DAT_*/s_* references visible in decompiled code -- `apply_data_type` to set type, `rename_or_label` with g_ prefix + Hungarian notation.

2. **Use `batch_set_comments`** with `plate_comment` parameter to set everything in ONE call:

### Plate Comment Format (plain text only)

```
One-line function summary.
Source: ..\Source\Module\File.cpp

Algorithm:
1. [Step with hex magic numbers, e.g., "check type == 0x4E (78)"]
2. [Each step is one clear action]

Parameters:
  paramName: Type - purpose description [IMPLICIT EDX if register-passed]

Returns:
  type: meaning. Success=non-zero, Failure=0/NULL. [all return paths]

Special Cases:
  - [Edge cases, phantom variables, decompiler discrepancies]
  - [Mark tentative names: "dwField1D0: Tentative: may be tile limit"]
  - [Mark hypotheses: "pField20: Hypothesis: node list pointer"]

Structure Layout: (if accessing structs)
  Offset | Size | Field     | Type  | Description
  +0x00  | 4    | dwType    | uint  | ...
```

**REQUIRED sections**: Summary (first line), Source, Parameters, Returns. These must ALWAYS be present.
**Conditional sections**: Algorithm (if >3 steps), Special Cases (if any), Structure Layout (if struct accesses).
**Source line**: Derive from module prefix (e.g., ROOM_ → DrlgRoom.cpp, PATH_ → Path.cpp). If unknown, use `Source: Unknown`.

### Inline Comments

- **Decompiler PRE_COMMENTs**: At block-start addresses -- context, purpose, algorithm step references. Max ~60 chars.
  - **Safe anchor**: The function entry address is always a valid PRE_COMMENT target.
  - Use addresses from the decompiled source (e.g., addresses visible in `LAB_*` labels or `goto` targets).
  - Without disassembly data, avoid guessing mid-block addresses -- prefer block-start addresses from the decompiled control flow.
- **Disassembly EOL_COMMENTs**: At instruction addresses -- concise, max 32 chars. Include hex/numeric constants that explain behavior.
  - Use addresses from the work items section (magic numbers include exact instruction addresses).

### Comment Quality Rules

- Document each constant family **once** at first use. Do not repeat the same comment at every occurrence unless later uses differ in meaning.
- Do NOT comment stack frame sizes, compiler-lowered arithmetic (multiply-by-shift, division-by-magic), or RNG constants unless they explain domain behavior.
- Do NOT add EOL comments just to satisfy the scorer. Every comment should help a human reader understand the code.
- Struct offsets referenced in the code should be documented in the plate comment's Structure Layout table, NOT as individual EOL comments at every dereference.

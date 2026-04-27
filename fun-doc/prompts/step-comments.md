# Step 4: Comments

## Allowed Tools
- `batch_set_comments` (plate + PRE + EOL in ONE call)
- `set_global` (for DAT_*/s_* globals — atomic name+type+plate-comment in ONE call; see `step-globals.md`)
- `audit_globals_in_function` (one call lists every global the function references with per-global issues)

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
- `address`: **A single hex string** (the function's entry address), not an array.
  This is the plate-comment target AND the batch anchor. Per-line PRE/EOL
  addresses go inside `decompiler_comments` / `disassembly_comments`, not
  here. If you have a list of addresses to comment, do NOT collect them into
  `address`; put them in the inner arrays as `{address, comment}` objects.
- `plate_comment`: Full plate text. Omit to leave existing plate untouched. Empty string clears it.
- `decompiler_comments`: Array of `{address, comment}` objects for PRE_COMMENTs.
- `disassembly_comments`: Array of `{address, comment}` objects for EOL_COMMENTs.
- Pass real arrays/objects for comment lists. Do not JSON-stringify nested comment payloads.
- `program`: Pass as query parameter, NOT in JSON body.

## Instructions

1. **Document globals**: Any DAT_*/s_* references visible in decompiled code — call
   `audit_globals_in_function` once, then one `set_global` call per global with
   `name` + `type_name` + `plate_comment`. **Do not** use the broken-up
   `apply_data_type` → `rename_or_label` → `batch_set_comments` chain — the v5.7.0
   validator hard-rejects most names sent through `rename_or_label` (missing `g_`,
   prefix mismatch, short descriptor, auto-gen remnant), and the chain is not
   atomic. See `step-globals.md` for the full naming + plate-comment rules.

2. **Use `batch_set_comments`** with `plate_comment` parameter for the function's
   own plate + PRE/EOL comments in ONE call:

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

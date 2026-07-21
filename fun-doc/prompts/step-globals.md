# Step: Global Variable Documentation

When a function references global variables, those globals are part of the
function's documentation surface. This step covers the rules and the
canonical workflow.

## When to apply

Run this step whenever the function being documented references one or more
globals — anything that decompiles as `DAT_xxx`, `PTR_DAT_xxx`, `g_*`, or
named/typed data at a fixed address. Skip when the function references only
local stack variables, parameters, and structure fields.

## The bar (8-axis rubric, severity-tiered)

A global is "fully documented" when no **hard** or **medium** issues remain.
**Soft** issues surface as warnings but don't block completion — they're
notes for a human reviewer, not work the worker must do. The audit
returns `severity_summary: {hard, medium, soft}` and an `applicable_axes`
hint per global so you know which sections are semantically relevant
for THIS global.

### HARD (must hold for every global)

1. **Name** — `g_` prefix + Hungarian prefix matching the type + ≥2 chars of descriptor. No IDA-reserved prefixes (`sub_`, `loc_`, `byte_`, `dword_`, `unk_`, `var_`, `arg_` etc. — those are sentinels for "untouched" symbols and reusing them breaks downstream tools).
2. **Type** — a real type (not `undefined1/2/4/8`). Pointer-to-struct when applicable.
3. **Plate present** — the address has a plate comment.

### MEDIUM (must hold when applicable)

4. **Bytes formatted** — when the type implies a specific layout, the data must match: arrays specify `array_length`, ASCII regions applied as `string`/`unicode`, struct fields laid out. Soft `bytes_size_unknown` fires when an array type has only one element typed but >1 xref.
5. **Plate quality** — first line is a meaningful ≥4-word summary.
6. **Xref summary** (when xref count > 5) — the plate names ≥1 writer or count of readers. Use `Set by:`, `Read by:`, `Used by:`, or `Modified by:` sections, OR mention specific function names. The community treats this as the *substance* of global documentation — knowing who writes vs reads it.
7. **Bitfield decomposition** (when name contains `Flags`/`Bits`/`Mask`/`State`/`Mode` and type is integer) — plate must include a `Bitfield:` section or per-bit table.
8. **Callback signature** (when name starts with `g_pfn` or type is a function pointer) — plate describes what calls through, with arg list.

### SOFT (warnings only, won't block "completed")

- **`generic_descriptor`** — descriptor is a low-information word like `Data`, `Buffer`, `Flag`, `Value`, `Result`, `Status`, `Handle`, `Context`, or gibberish like `Foo`/`Test`/`Sample`. Placeholder convention exempt: `Field1D0`, `Unk20`, `Value04` are still considered the *correct* name when semantic role is uncertain.
- **`bytes_size_unknown`** — single-element array with multiple xrefs.

### Exempt from all checks

- **OS-canonical labels** (`ExceptionList`, `StackBase`, `Teb*`, `Peb*`, `KUSER_SHARED_DATA`, `_acmdln`, `_environ`, IAT thunk targets). The audit short-circuits these as `os_canonical: true, fully_documented: true`. Microsoft's name IS the canonical convention; renaming to `g_*` would destroy cross-binary recognizability.
- **Code addresses** (function entries, branch targets). The audit short-circuits these as `is_code_address: true`. They're not data globals.

`set_global` rejects any write that violates rules 1, 2, or 5 (hard naming, hard typing, plate ≥4 words). Other rules are checked at audit time.

## Canonical workflow

**Always start with `audit_globals_in_function` first.** It walks the function's instructions, collects every unique data-reference target, audits each one, and returns a single result with both per-global details and a summary histogram. One call instead of N — much cheaper than iterating `audit_global` per xref:

```
audit_globals_in_function(address="0x6fcab220", program="...")
→ {
    "function": {"address": "6fcab220", "name": "SendStateUpdateCommand"},
    "globals": [
      {"address": "6fdf64d8", "name": "DAT_6fdf64d8", "type": "undefined4",
       "issues": ["generic_name", "untyped", "missing_plate_comment"], ...},
      {"address": "6fdf65a0", "name": "g_pUnitList", "type": "UnitAny *",
       "issues": [], "fully_documented": true, ...},
      ...
    ],
    "summary": {
      "total": 7,
      "fully_documented": 3,
      "with_issues": 4,
      "issue_histogram": {"untyped": 2, "missing_plate_comment": 4, "generic_name": 2}
    }
  }
```

If the function has no global xrefs (`summary.total == 0`), skip the rest of this step — there's nothing to fix. Otherwise, work through the `globals` array and call `set_global` on each one with `issues`.

For deeper inspection of a single global mid-fix, use `audit_global(address)` — same per-global shape as the entries inside `audit_globals_in_function.globals`.

Then **fix everything in one `set_global` call** per global:

```
set_global(
  address="0x6fdf64d8",
  name="g_pDifficultyLevelsBIN",
  type_name="DifficultyLevels *",
  plate_comment="Pointer to the DifficultyLevels.bin table loaded at startup. Stride 0x58, count at g_dwDifficultyLevelsBINCount.",
  program="..."
)
→ {"status": "success", "applied": ["type", "name", "plate_comment"]}
```

Use `array_length` when documenting a fixed-size array:

```
set_global(
  address="0x6fdf6358",
  name="g_anItemMaxStack",
  type_name="uint",
  array_length=512,
  plate_comment="Per-item-id maximum stack size. Indexed by item ID from ItemTypes.bin.",
)
```

## Naming rules

The full Hungarian prefix → type table lives in **`hungarian-table.md`**
(single source of truth for all scopes). Globals = `g_` outer marker
plus the prefix from that table plus a descriptor — e.g.,
`g_dwActiveQuestState`, `g_pUnitList`, `g_szPlayerName`,
`g_pfnDispatchHandler`.

The descriptor part must:
- Start with an uppercase letter (PascalCase after the Hungarian prefix).
- Be ≥2 chars (`g_dwId` ok, `g_dwX` not).
- Not match auto-generated patterns (`g_DAT_*`, `g_PTR_*`, `g_FUN_*`, `g_LAB_*`, `g_SUB_*`, `g_<prefix>_<hex>`).

Conservative placeholders are explicitly allowed when the global's purpose is genuinely unknown:
- `g_dwField1D0` — type known, semantic role uncertain
- `g_pUnk20` — pointer at offset 20 of a struct, unknown target type

This is the same "underclaim with placeholder" convention used for variables — `dwUnknown1D0`, `pUnk20`. A correct neutral name beats a confident wrong one.

**Placeholders are a last resort, not a shortcut.** If the global lives
inside or points into a struct Ghidra already has a type for, resolve the
real field name at that offset with `get_struct_layout` before settling
for `g_dwFieldXX` — the loaded D2 struct definitions are
community-canonical and usually have the answer.

**Names must be unique within the program.** Never apply a name that
already exists at another address (824 duplicate pile-ups measured in
production, worst `g_dwLastError` × 60 in one binary). Never fall back to
generic catch-alls (`g_dwLastError`, `g_dwFlags`, `g_dwData`, `g_pBuffer`)
— scope the descriptor by subsystem + role, or use the placeholder
convention above.

**Overwriting an existing meaningful (non-auto-generated) name requires
evidence** from xrefs you actually examined, and the evidence goes in the
plate comment. Established names are load-bearing; an unjustified rename
is worse than none.

## Plate-comment format (Win32-derived template)

The community-standard structure (Microsoft Win32 function-header
template adapted for globals; ReactOS, Wine, and D2MOO all converge on
this shape):

```
<Purpose: one-line semantic summary (mandatory, ≥4 words)>

Type:       <declared type + interpretation, e.g. "DWORD bitfield of UNIT_FLAG_*">
Range:      <valid values / sentinels / units, e.g. "0..255, -1 = invalid">
Set by:     <function(s) that write it; init site>
Read by:    <function(s) that consume it (or "N readers, see xrefs")>
Related:    <sibling globals, parallel arrays, owning struct>
Source:     <PDB / header / sibling-version / BSim / inferred-from-string>
Notes:      <thread-safety, lifetime, gotchas>
Bitfield:   <bit-by-bit table, only for Flags/Bits/Mask globals>
  0x0001 = QUEST_DENOFEVIL
  0x0002 = QUEST_SISTERS_BURIAL
```

**Mandatory:** the first-line `Purpose` summary.

**Skip empty sections rather than padding with "N/A".** A section that
isn't applicable is just absent from the plate. Don't write
`Set by: N/A` or `Range: none` — that's an anti-pattern called out by
every RE style guide that touches global documentation.

**Wrap long lines to ≤70 characters.** Ghidra's listing column clips
pre-comment lines past ~80 chars with a truncation ellipsis, so an
unwrapped `Set by: FooFn, BarFn, BazFn, ...` (19 names) renders as
`Set by: FooFn, BarFn, BazFn, Pro.` in the listing — the stored text
is intact but the most common reading surface becomes lossy. Hard-wrap
lines that would exceed 70 chars; for comma-joined lists, put the
section header on its own line and break the names with two-space
indented continuations:

```
Set by:
  SNetCreateLadderGame, SetActiveGameUnitContext,
  ProcessEntityStateChangeEvents
Read by:
  SNetCreateLadderGame, BroadcastGameStateToPlayers,
  ProcessEntityStateChangeEvents, RetrieveDataByTypeWithBuffer
```

The audit emits a soft `plate_line_too_long` issue when any line
exceeds 80 chars — soft means it doesn't block completion, but the
next worker pass on this global will see it and you should fix it
opportunistically when you visit nearby code. When the xref count is
high enough that the comma-list still feels noisy after wrapping,
prefer a one-line summary instead — e.g. `Read by: 14 readers across
the SNet/Net layer; hot path is BroadcastGameStateToPlayers`.

**Use `applicable_axes` from the audit response** to decide which
sections to fill. The audit tells you per-global which of
`xref_summary`, `bitfield_decomp`, `callback_sig`, `value_semantics`
are relevant for this address. Anything flagged false → skip that
section entirely.

### Example: low-xref global (most common case)

```
Pointer to the DifficultyLevels.bin table loaded at startup. Stride 0x58.
```

That's the entire plate. One line, mandatory `Purpose` only, no sections needed.

### Example: high-xref bitfield with known source

```
Bitmap of currently-active quests for the player; bit N = quest N active.

Set by: ProcessQuestUpdate, InitQuestState
Read by: RenderQuestLog, IsQuestActive (and 14 other readers)
Source: QuestC.cpp:0x14
Bitfield:
  0x0001 = QUEST_DENOFEVIL
  0x0002 = QUEST_SISTERS_BURIAL
```

Sectioned details are warranted because xref_count > 5 (community
expects a writer/reader summary), name pattern triggers
`bitfield_undocumented` (must enumerate bits), and the source is known.

### Example: high-xref network global (wrapped)

This is the shape that gets clipped if you don't wrap — 19 xrefs across
several long-named functions. Indented continuation lines keep every
line under 70 chars:

```
Stored game version used for network protocol compatibility checks.

Set by:
  SNetCreateLadderGame, SetActiveGameUnitContext,
  ProcessEntityStateChangeEvents
Read by:
  SNetCreateLadderGame, BroadcastGameStateToPlayers,
  ProcessEntityStateChangeEvents, RetrieveDataByTypeWithBuffer,
  NET_ShutdownGameAndCleanupResources
```

Note the section headers (`Set by:`, `Read by:`) sit alone on their
line so the comma list can wrap without ambiguity.

### Example: function pointer (callback)

```
Damage handler invoked from CombatTick when a unit takes hit damage.

Set by: CombatInit (during module load)
Called by: CombatTick — invoked as g_pfnDamageHandler(pAttacker, pTarget, dwAmount)
```

Triggers `callback_signature_missing` if the call signature isn't documented.

## Handling rejections

`set_global` returns `{"status": "rejected", "error": ..., "issue": ..., "suggestion": ...}` on any rule violation. The function/global is unchanged on rejection. Common errors:

- `name_quality` / `missing_g_prefix` — prepend `g_`.
- `name_quality` / `auto_generated_remnant` — name still looks like the original DAT_/PTR_ symbol; pick a meaningful descriptor.
- `name_quality` / `missing_hungarian_prefix` — add `dw`/`p`/`sz`/etc. between `g_` and the descriptor.
- `name_quality` / `prefix_type_mismatch` — Hungarian prefix doesn't match `type_name`. Either fix the prefix or correct the type.
- `unknown_type` — the type isn't in the program's data type manager. Use `create_struct` / `create_array_type` first, then retry.
- `undefined_type_rejected` — passed `undefined4`/`undefined1`/etc. Pick a real type.
- `plate_comment_too_short` — first line has fewer than 4 words. Replace with a meaningful summary.

## Audit-time issue codes (not write-blockers)

These come back from `audit_global` in the `issues` array, each tagged
in `severity_summary`. Hard + medium block `fully_documented`; soft do
not.

| Code | Severity | What to fix |
|---|---|---|
| `untyped` | hard | Apply a real type via `set_global`. |
| `missing_plate_comment` | hard | Add a one-line ≥4-word summary. |
| `ida_reserved_prefix` | hard | Rename — never reuse `sub_`/`loc_`/`byte_`/`dword_`/`unk_`/`var_`/`arg_` as a global name. |
| `name_*` (any) | hard | See rejection list above. |
| `generic_name` | hard | Name is auto-generated (DAT_*, etc.); pick a meaningful descriptor. |
| `plate_comment_too_short` | medium | Expand to ≥4 words. |
| `unformatted_bytes_length_mismatch` | medium | Re-apply type with correct `array_length`. |
| `unformatted_bytes_should_be_string` | medium | Re-apply as `string` / `unicode`. |
| `xref_summary_missing` | medium | Add `Set by:` / `Read by:` / `Used by:` sections (xref_count > 5). |
| `bitfield_undocumented` | medium | Add `Bitfield:` section enumerating bits (name implies flags). |
| `callback_signature_missing` | medium | Add call signature to the plate (`g_pfn*` or function-pointer type). |
| `generic_descriptor` | **soft** | Replace generic descriptor (Data/Buffer/Flag/Result/etc.). Doesn't block completion. |
| `bytes_size_unknown` | **soft** | Document the array length when single-element array has multiple xrefs. |

## What NOT to do

- **Don't chain `apply_data_type` → `rename_data` → `batch_set_comments`** for globals. Use `set_global` instead — it's atomic, single-transaction, and partial application is structurally impossible.
- **Don't pass `undefined4` to `apply_data_type` on a global.** It "works" but leaves the global in a worse state than before (the existing real type, if any, gets clobbered).
- **Don't rename a global without setting its type first**, unless the type is already correct. The Hungarian-vs-type check uses the current type, so renaming first then changing type can leave a Hungarian/type mismatch you have to fix later.
- **Don't write filler plate comments** like "global counter" or "this is a flag." The ≥4-word check passes those, but they add no information. The reader gets no value.

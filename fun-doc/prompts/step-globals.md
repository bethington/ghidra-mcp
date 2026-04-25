# Step: Global Variable Documentation

When a function references global variables, those globals are part of the
function's documentation surface. This step covers the rules and the
canonical workflow.

## When to apply

Run this step whenever the function being documented references one or more
globals — anything that decompiles as `DAT_xxx`, `PTR_DAT_xxx`, `g_*`, or
named/typed data at a fixed address. Skip when the function references only
local stack variables, parameters, and structure fields.

## The bar (HARD-ENFORCED)

A global is "properly documented" when **all four** of these hold:

1. **Name** — `g_` prefix + Hungarian prefix matching the type + ≥2 chars of descriptor.
2. **Type** — a real type (not `undefined1/2/4/8`). Pointer-to-struct when applicable.
3. **Bytes formatted** — the data at the address is applied as that type, with the right length:
   - Arrays must specify `array_length` (not just the first element typed).
   - ASCII null-terminated regions should be applied as `string` / `unicode`, not raw `char[]`.
   - Struct types lay out their fields automatically.
4. **Plate comment** — the address has a plate comment whose first line is a meaningful ≥4-word summary.

`set_global` rejects any write that violates rule 1, 2, or 4. Rule 3 is checked at audit time.

## Canonical workflow

**Always start with `audit_global` to see the state**, never with a write. The audit response shows exactly what's missing:

```
audit_global(address="0x6fdf64d8", program="...")
→ {
    "address": "6fdf64d8",
    "name": "DAT_6fdf64d8",
    "type": "undefined4",
    "length": 4,
    "plate_comment": "",
    "xref_count": 17,
    "issues": ["generic_name", "untyped", "missing_plate_comment"],
    "fully_documented": false
  }
```

Then **fix everything in one `set_global` call**:

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

| Hungarian | Type | Example |
|---|---|---|
| `g_dw` | `uint` / `dword` | `g_dwActiveQuestState` |
| `g_n` | `int` / `short` | `g_nPlayerCount` |
| `g_p` | pointer-to-anything | `g_pUnitList`, `g_pCurrentRoom` |
| `g_pp` | double-pointer | `g_ppRoomTable` |
| `g_sz` | `char *` | `g_szPlayerName` |
| `g_wsz` | `wchar_t *` | `g_wszLocalizedTitle` |
| `g_ab` | `byte[]` | `g_abPaletteData` |
| `g_an` | `int[]` | `g_anItemMaxStack` |
| `g_ad` | `uint[]` | `g_adXpThresholds` |
| `g_pfn` | function pointer | `g_pfnDispatchHandler` |
| `g_b` / `g_f` | bool | `g_bIsConnected` / `g_fHostMode` |

The descriptor part must:
- Start with an uppercase letter (PascalCase after the Hungarian prefix).
- Be ≥2 chars (`g_dwId` ok, `g_dwX` not).
- Not match auto-generated patterns (`g_DAT_*`, `g_PTR_*`, `g_FUN_*`, `g_LAB_*`, `g_SUB_*`, `g_<prefix>_<hex>`).

Conservative placeholders are explicitly allowed when the global's purpose is genuinely unknown:
- `g_dwField1D0` — type known, semantic role uncertain
- `g_pUnk20` — pointer at offset 20 of a struct, unknown target type

This is the same "underclaim with placeholder" convention used for variables — `dwUnknown1D0`, `pUnk20`. A correct neutral name beats a confident wrong one.

## Plate-comment format

Required: a one-line meaningful summary as the first line (≥4 words). What the global represents and how it's used.

Optional structured details when applicable:

```
Bitmap of currently-active quests for the player; bit N = quest N active.

Used by: ProcessQuestUpdate, RenderQuestLog, IsQuestActive
Layout: 32 bits, low 16 = act 1-2 quests, high 16 = act 3-5
Source: QuestC.cpp:0x14
Bitfield:
  0x0001 = QUEST_DENOFEVIL
  0x0002 = QUEST_SISTERS_BURIAL
  ...
```

Most globals only need the one-liner. Reserve sectioned details for:
- Tables with a documented stride/count
- Bitmaps where each bit has a known meaning
- Globals derived from a known source file

## Handling rejections

`set_global` returns `{"status": "rejected", "error": ..., "issue": ..., "suggestion": ...}` on any rule violation. The function/global is unchanged on rejection. Common errors:

- `name_quality` / `missing_g_prefix` — prepend `g_`.
- `name_quality` / `auto_generated_remnant` — name still looks like the original DAT_/PTR_ symbol; pick a meaningful descriptor.
- `name_quality` / `missing_hungarian_prefix` — add `dw`/`p`/`sz`/etc. between `g_` and the descriptor.
- `name_quality` / `prefix_type_mismatch` — Hungarian prefix doesn't match `type_name`. Either fix the prefix or correct the type.
- `unknown_type` — the type isn't in the program's data type manager. Use `create_struct` / `create_array_type` first, then retry.
- `undefined_type_rejected` — passed `undefined4`/`undefined1`/etc. Pick a real type.
- `plate_comment_too_short` — first line has fewer than 4 words. Replace with a meaningful summary.

## What NOT to do

- **Don't chain `apply_data_type` → `rename_data` → `batch_set_comments`** for globals. Use `set_global` instead — it's atomic, single-transaction, and partial application is structurally impossible.
- **Don't pass `undefined4` to `apply_data_type` on a global.** It "works" but leaves the global in a worse state than before (the existing real type, if any, gets clobbered).
- **Don't rename a global without setting its type first**, unless the type is already correct. The Hungarian-vs-type check uses the current type, so renaming first then changing type can leave a Hungarian/type mismatch you have to fix later.
- **Don't write filler plate comments** like "global counter" or "this is a flag." The ≥4-word check passes those, but they add no information. The reader gets no value.

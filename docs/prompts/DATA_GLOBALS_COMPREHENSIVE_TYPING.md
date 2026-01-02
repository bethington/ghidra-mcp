# Global Data Comprehensive Typing Workflow

Your task is to type and rename ALL global data items in the .data/.rdata sections, ensuring each item consumes its full byte range with no gaps.

## Quick Start: Automated Script

For most binaries, use the comprehensive automation script:

```bash
python comprehensive_data_typing.py \
    --rdata-start 0x6ff7e000 --rdata-end 0x6ff7ffff \
    --data-start 0x6ff80000 --data-end 0x6ffa2cc7
```

This script handles all steps automatically:
1. Fixes `undefined` typed items
2. Fills gaps between items
3. Renames strings with `sz*` pattern + padding absorption
4. Renames all generic items with Hungarian notation
5. Detects and types pointer arrays
6. Verifies 100% coverage

## Core Principle: No Gaps, No Orphan Bytes, No Undefined Types

Every byte from segment start to segment end must belong to a **typed** item. Three categories of issues must be resolved:

1. **Gaps**: Undefined bytes (`??`) between items
2. **Undefined Types**: Items with names but `undefined` as their type
3. **Generic Names**: Items with `DAT_*`, `g_Data_*`, `PTR_*`, or `ADDR_*` prefixes

## Step 1: Get Segment Boundaries

Use `list_segments` to identify .data and .rdata ranges:
- Record start_address and end_address for each segment
- These define the scope of work

## Step 2: Fix Undefined Types (Critical - Often Missed!)

**Problem**: `list_data_items` returns items that have labels but `undefined` as their type. These show as:
```
g_nTimeout @ 6ff87010 [undefined] (4 bytes)
g_dwLastCleanupTick @ 6ff87014 [undefined] (4 bytes)
```

These items exist in Ghidra's database with names, but lack proper data types.

**Detection**:
```python
undefined_items = [i for i in items if "undefined" in i["type"].lower()]
```

**Fix**: Apply appropriate type based on size:
| Size | Type |
|------|------|
| 1 byte | `byte` |
| 2 bytes | `word` |
| 4 bytes | `dword` |
| 8 bytes | `qword` |
| N bytes (N % 4 == 0) | `dword[N/4]` |
| N bytes (N % 2 == 0) | `word[N/2]` |
| N bytes | `byte[N]` |

```python
apply_data_type(address="0x6ff87010", type_name="dword")
```

## Step 3: Fill Gaps Between Items

**Problem**: Bytes between defined items that have no data definition at all.

**Detection**: Calculate gaps between consecutive items:
```python
for i in range(len(items) - 1):
    curr_end = int(items[i]["addr"], 16) + items[i]["size"]
    next_start = int(items[i + 1]["addr"], 16)
    gap = next_start - curr_end
    if gap > 0:
        # Found a gap - needs filling
```

**Fix**: Apply type and create label for each gap:
```python
apply_data_type(address=gap_addr, type_name="dword[N]")
rename_or_label(address=gap_addr, name="g_adwGap_ADDR")
```

## Step 4: String Handling

For string types where `true_size > string_length + 1`:

1. Use `inspect_memory_content(address, length=true_size)` to see actual bytes
2. If trailing bytes are all 0x00 (null padding for alignment):
   - Apply `char[true_size]` instead of bare `string` type
   - This absorbs padding into the string array
3. Name with `sz` prefix: `szConfigName` not `s_configname_addr`

Example:
```
Address: 0x6fde7b7c
Content: "box2left\0\0\0\0"  (9 bytes content + 3 padding = 12 bytes to next item)
Action: apply_data_type(address="0x6fde7b7c", type_name="char[12]")
        rename_or_label(address="0x6fde7b7c", name="szBoxCfg_Box2Left")
```

## Step 5: Rename ALL Generic Items (Critical - Often Missed!)

**Problem**: Items may have multiple generic naming patterns that need Hungarian notation:

| Generic Pattern | Description |
|-----------------|-------------|
| `DAT_*` | Ghidra default data label |
| `g_Data_*` | Previously renamed but wrong type prefix |
| `PTR_*` | Pointer to function/data |
| `ADDR_*` | Address reference |

**Special Type Handling**:

| Ghidra Type | Hungarian Prefix | Example |
|-------------|------------------|---------|
| `ImageBaseOffset32` | `g_pfnRva_` | Function pointer RVA |
| `pointer` | `g_pData_` or `g_pfn*` | Pointer to data/function |
| `dword` | `g_dwData_` | 32-bit value |
| `word` | `g_wData_` | 16-bit value |
| `byte` | `g_bData_` | 8-bit value |
| `dword[N]` | `g_adwData_` | Array of DWORDs |

**PTR_ Special Handling**:
```python
# PTR_GetUserNameA_6ff7e000 -> g_pfnGetUserNameA
if name.startswith("PTR_") and type == "pointer":
    func_name = extract_function_name(name)
    new_name = f"g_pfn{func_name}"
```

## Step 6: Pointer Array Detection

Consecutive pointers with similar naming patterns indicate string pointer arrays.

**Detection Pattern:**
```
PTR_s_*      @ addr+0   [pointer]  -> string
g_pData_*    @ addr+4   [pointer]  -> string
g_pData_*    @ addr+8   [pointer]  -> string
...
```

**Common Pointer Array Types:**
- Locale data: day names (7), month names (12), AM/PM (2), format strings
- Lookup tables: error messages, status strings, command names
- Configuration: file paths, registry keys

**Action:**
1. Count consecutive pointer items pointing to strings
2. Look for semantic grouping (days=7, months=12, etc.)
3. Check for NULL terminator at end (indicates C-style array)
4. Apply `char *[N]` type to entire block
5. Name with `g_apsz` prefix (array of pointers to strings)

**Example - Locale Time Strings:**
```
Address: 0x6ff86c60
Pattern: 43 pointers to day/month/format strings + NULL terminator
Action: apply_data_type(address="0x6ff86c60", type_name="char *[44]")
        rename_or_label(address="0x6ff86c60", name="g_apszLocaleTimeStrings")
```

**Cleaning Up Orphan Labels:**
When you apply an array type to a region that was previously labeled individually, those orphan labels persist inside the array.

Use `batch_delete_labels` to remove them:
```python
labels_to_delete = [{"address": hex(0x6ff86c60 + i*4)} for i in range(1, 44)]
batch_delete_labels(labels_to_delete)
```

## Step 7: Naming Convention

| Type | Prefix | Example |
|------|--------|---------|
| ANSI string | sz | szConfigName |
| Wide string | wsz | wszDisplayText |
| Pointer | p/pp | pUnitData, ppItemList |
| Function pointer | pfn | pfnCallback |
| Function pointer RVA | pfnRva | g_pfnRva_6ff7fc30 |
| DWORD/uint | dw | dwFlags |
| WORD/ushort | w | wIndex |
| BYTE/uchar | b | bEnabled |
| QWORD | qw | qwTimestamp |
| Array | a+type | abBuffer, adwTable |
| Padding/alignment | Pad | g_bPad_*, g_dwPad_*, g_abPad_* |
| String pointer array | apsz | apszDayNames, apszErrorMessages |
| Global prefix | g_ | g_szConfigName, g_apszLocaleStrings |

Remove address suffixes from names when semantic meaning is known (e.g., `_6fde7b7c`).

## Step 8: Validation Checklist

After processing, verify:
- [ ] **Zero undefined types**: No `[undefined]` in type column
- [ ] **Zero gaps**: No `??` bytes between items
- [ ] **Zero generic names**: No `DAT_*`, `g_Data_*`, `PTR_*`, `ADDR_*` remaining
- [ ] **100% coverage**: Covered bytes equals section size

Validation query:
```python
# Check for remaining issues
undefined_count = sum(1 for i in items if "undefined" in i["type"].lower())
generic_count = sum(1 for i in items if any(i["name"].startswith(p)
                    for p in ("DAT_", "g_Data_", "PTR_", "ADDR_")))
```

## Step 9: Output Summary

Report:
- Total items processed
- Undefined types fixed
- Gaps filled
- Strings padded (char[N] applied)
- Items renamed
- Pointer arrays detected
- Final coverage percentage

## Common Pitfalls

### 1. Missing Undefined Types
`list_data_items` returns items with `undefined` type that have labels but no data type. These are easy to miss because they have names.

**Solution**: Always filter for `undefined` in type and apply proper types first.

### 2. Missing g_Data_* Items
After initial DAT_* renaming, items get `g_Data_*` names but may need type-specific prefixes (e.g., `g_pfnRva_*` for ImageBaseOffset32).

**Solution**: Check for ALL generic prefixes, not just `DAT_*`.

### 3. ImageBaseOffset32 Type
This Ghidra-specific type for RVA pointers needs special handling - use `g_pfnRva_*` prefix.

### 4. PTR_ Items Pointing to Functions
`PTR_GetUserNameA_addr` should become `g_pfnGetUserNameA`, not `g_pPtr_addr`.

**Solution**: Extract function name from PTR_ prefix and use `g_pfn*` naming.

### 5. Gap-Filled Items Not Renamed
When `fill_gaps()` creates items to fill undefined byte regions, they initially get `g_abGap_*`, `g_dwGap_*` names. These need to be renamed to padding notation (`g_bPad_*`, `g_dwPad_*`).

**Solution**: The script now automatically:
1. Creates gap items with `g_*Pad_*` names directly
2. Renames any existing `g_*Gap_*` items to `g_*Pad_*` notation
3. Include gap prefixes in the generic items rename phase

## Error Handling

- If `apply_data_type` fails, the type may not exist - use `create_array_type` first
- If renaming fails, check if name already exists or contains invalid characters
- If gaps remain after typing, inspect memory to determine if it's truly padding or missed data
- HTTP 500 errors with `rename_or_label`: Use URL-encoded form data, not JSON body

## Automated Script Reference

The `comprehensive_data_typing.py` script in the repository root handles all steps:

```bash
python comprehensive_data_typing.py \
    --rdata-start 0xADDR --rdata-end 0xADDR \
    --data-start 0xADDR --data-end 0xADDR
```

Steps executed:
1. Fix undefined items (apply dword/word/byte types)
2. Fill gaps (apply types + create labels with `g_*Pad_*` names)
3. Rename strings (s_* -> sz* with padding absorption)
4. Rename generic items (DAT_*, g_Data_*, PTR_*, ADDR_*, g_*Gap_*, BYTE_* -> Hungarian notation)
5. Detect pointer arrays (consecutive pointers -> void*[N])
6. Final verification (coverage report)

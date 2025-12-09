# Hash-Based Function Renaming: Unify Ordinal Names

## Problem
- Version 1.07: calls `SMemAlloc` (0x6ffcb6b0)
- Version 1.08+: calls `Ordinal_401` (0x6ffcbd60)
- Same function, different names → prevents propagation

## Solution
Use hash-based matching to rename all `Ordinal_*` functions to the best real name found across versions.

## Quick Start

### Step 1: Ensure Index is Current
```
Run: BuildHashIndex_ProjectFolder.java
- This captures all function names across all versions
- Creates hash index with callees data
```

### Step 2: Apply UnifyOrdinalNames to Each Version
For each Storm.dll version:

1. **Open version in Ghidra** (e.g., 1.07, 1.08, 1.09, etc.)
2. **Run the script**: 
   - Window → Script Manager
   - Search for `UnifyOrdinalNames_ProjectFolder`
   - Click green ▶ button
3. **Script will:**
   - Find all `Ordinal_*` functions
   - Compute their hashes
   - Look up best name from index (prioritize real names)
   - Rename automatically
   - Save the program
4. **Monitor console** for output like:
   ```
   Renamed: Ordinal_401 -> SMemAlloc @ 0x6ffcbd60
   Functions renamed: 15
   ```

### Step 3: Rebuild Hash Index
```
Run: BuildHashIndex_ProjectFolder.java again
- Now all versions have consistent names
- Index has unified function names
```

### Step 4: Propagate Documentation
```
Run: BatchPropagateToAllVersions_ProjectFolder.java
- Select "All Binaries in Project"
- Callees like SMemAlloc will propagate correctly
- All versions get consistent naming
```

## Expected Results After Completion

**Before:** (in AllocateConnectionRecord)
- 1.07: calls SMemAlloc @ 0x6ffcb6b0
- 1.08: calls Ordinal_401 @ 0x6ffcbd60
- 1.09: calls Ordinal_401 @ 0x6ffbe830
- ❌ Can't propagate - different names

**After:** (same function with unified name)
- 1.07: calls SMemAlloc @ 0x6ffcb6b0 (unchanged)
- 1.08: calls SMemAlloc @ 0x6ffcbd60 (renamed from Ordinal_401)
- 1.09: calls SMemAlloc @ 0x6ffbe830 (renamed from Ordinal_401)
- ✅ Can propagate - consistent names

## Technical Details

### How UnifyOrdinalNames Works

1. **Hash Computation**: For each Ordinal_* function:
   - Compute SHA-256 hash of normalized opcodes
   - Normalized: addresses → offsets, immediates → categories

2. **Index Lookup**: 
   - Look up hash in function index
   - Find all versions of same function
   - Collect all names used (SMemAlloc, Ordinal_401, etc.)

3. **Best Name Selection** (priority order):
   1. Real names (non-FUN_, non-Ordinal_)
   2. If only Ordinal_* names exist, use first one
   3. If no matches in index, keep current name

4. **Application**:
   - Only renames if better name found
   - Skips functions already named well
   - Creates proper USER_DEFINED symbols

### What Names Get Renamed

✅ **Will be renamed** (if better name found):
- `Ordinal_401` → `SMemAlloc`
- `Ordinal_123` → `GetUnitX`
- Any `Ordinal_*` with matching hash to a documented function

❌ **Won't be renamed** (even if Ordinal_):
- Already has real name (`SMemAlloc`, `GetUnit`, etc.)
- No matching hash in index
- Hash matches only other `Ordinal_*` names

## Troubleshooting

### "0 functions renamed"
- **Cause**: All Ordinal_* functions already have real names OR no matches in index
- **Fix**: Ensure BuildHashIndex was run recently on all versions

### "Index file not found"
- **Cause**: Missing `~/ghidra_function_hash_index.json`
- **Fix**: Run `BuildHashIndex_ProjectFolder.java` first

### Script crashes with hash computation error
- **Cause**: Function has unusual instruction set
- **Fix**: Script handles exceptions - check console for which function failed

## Integration with Propagation System

Once all names are unified:

```
UnifyOrdinalNames → BuildHashIndex → BatchPropagate
   (rename)         (index names)   (spread docs)
      ↓                 ↓                ↓
  Ordinal_401      All versions      All versions
   → SMemAlloc     have SMemAlloc    get SMemAlloc
   (all versions)  in index         in callees
```

**Result**: Full documentation cascade across versions with consistent naming.

## Files Created

- `UnifyOrdinalNames_ProjectFolder.java` - Main unification script
- `batch-unify-ordinals.bat` - Batch processing helper (manual)

## Next Steps

1. Copy `UnifyOrdinalNames_ProjectFolder.java` to Ghidra scripts folder
2. Run against each Storm.dll version
3. Rebuild hash index
4. Run propagation script

That's it! Your function names will be unified across all versions.

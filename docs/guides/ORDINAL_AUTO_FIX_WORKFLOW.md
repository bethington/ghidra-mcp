# Ordinal Auto-Fix Workflow

## Overview

This document describes the improved automated workflow for fixing broken ordinal-based imports when external DLL function names have changed.

## New Improved Tools

### 1. ordinal_auto_fixer.py (Main Python Tool)

**What it does:**
- Compares original DLL with updated DLL
- Extracts all ordinal mappings from both
- Identifies which ordinals have changed
- Generates repair scripts and mapping files
- Can query Ghidra to find broken references

**Why it's better:**
- Fully automated - no manual mapping needed
- Extracts exact ordinal -> function_name from both DLLs
- Detects what actually changed
- Generates ready-to-use repair files

### 2. AutoFixOrdinalLinkage.py (Improved Ghidra Script)

**What it does:**
- Finds all ordinal-based imports in your binary
- Analyzes all references to them
- Suggests potential fixes
- Provides step-by-step instructions
- Queries Ghidra via the improved API

**Why it's better:**
- Uses correct Ghidra API calls
- Provides automatic suggestions
- Shows reference context
- Clear next steps

## Quick Start Workflow

### Scenario: Your D2Common.dll analysis has broken ordinals

```
STEP 1: Get Both DLL Files
├─ Original: C:\backup\D2Common_old.dll (what you were analyzing)
└─ Updated:  C:\game\D2Common_new.dll (current version)

STEP 2: Run Auto-Fixer (Extracts mappings automatically)
└─ python ordinal_auto_fixer.py D2Common_old.dll D2Common_new.dll --script --json

STEP 3: Review Generated Output
├─ ordinal_mapping.json (shows all changes)
└─ repair_ordinals.py (Ghidra script to apply fixes)

STEP 4: Apply in Ghidra
├─ Load your binary
└─ Window → Script Manager → repair_ordinals.py → Run

STEP 5: Verify
└─ Window → Script Manager → AutoFixOrdinalLinkage.py → Run
   (Should show "No ordinal-based imports" or all resolved)

DONE!
```

**Total Time:** 10-15 minutes

## Detailed Workflow

### Phase 1: Analysis with ordinal_auto_fixer.py

```bash
# Basic analysis - shows what changed
python ordinal_auto_fixer.py original.dll updated.dll

# Output:
# Loading original DLL...
#   Found 500 ordinals in original
# Loading updated DLL...
#   Found 502 ordinals in updated
#
# Building ordinal mapping...
#   Ordinal 100: D2Common_GetMonsterPower -> D2Common_GetEnemyPower
#   Ordinal 101: D2Common_GetMonsterLife -> D2Common_GetEnemyLife
#   ...
```

### Phase 2: Generate Repair Files

```bash
# Generate Ghidra script + JSON mapping
python ordinal_auto_fixer.py original.dll updated.dll --script --json

# Output files:
# - repair_ordinals.py (use this in Ghidra)
# - ordinal_mapping.json (backup/reference)
```

### Phase 3: Run in Ghidra

1. Load your binary in Ghidra
2. Run the generated repair script:
   ```
   Window → Script Manager → repair_ordinals.py → Run
   ```
3. Watch the output in the console:
   ```
   Ordinal Repair Script
   ====================

   Found broken ordinal: Ordinal_100 -> D2Common_GetEnemyPower
     ✓ Repaired: D2Common_GetEnemyPower @ 0x6fb7e100
   Found broken ordinal: Ordinal_101 -> D2Common_GetEnemyLife
     ✓ Repaired: D2Common_GetEnemyLife @ 0x6fb7e104
   ...

   REPAIR COMPLETE
   Repaired 25 ordinal linkages
   ```

### Phase 4: Verify Success

1. Run the analysis script:
   ```
   Window → Script Manager → AutoFixOrdinalLinkage.py → Run
   ```
2. Should show:
   ```
   Scanning for ordinal-based imports...
   No ordinal-based imports found

   All ordinal linkages restored! ✓
   ```

## Advanced Usage

### Compare Multiple Versions

```bash
# Create a baseline from original
python ordinal_auto_fixer.py original.dll original.dll --json

# Compare original with v2
python ordinal_auto_fixer.py original.dll d2common_v2.dll --json

# Compare original with v3
python ordinal_auto_fixer.py original.dll d2common_v3.dll --json
```

### Generate Only Mapping (No Script)

```bash
# Just get the JSON mapping
python ordinal_auto_fixer.py original.dll updated.dll --json

# Output: ordinal_mapping.json
# Use with: python ordinal_linkage_manager.py --repair --mapping ordinal_mapping.json
```

### Generate Only Script (No Mapping)

```bash
# Just get the Ghidra script
python ordinal_auto_fixer.py original.dll updated.dll --script

# Output: repair_ordinals.py
# Use in: Window → Script Manager → repair_ordinals.py → Run
```

## Understanding the Output

### ordinal_mapping.json

```json
{
  "100": {
    "old_name": "D2Common_GetMonsterPower",
    "new_name": "D2Common_GetEnemyPower"
  },
  "101": {
    "old_name": "D2Common_GetMonsterLife",
    "new_name": "D2Common_GetEnemyLife"
  },
  "102": {
    "old_name": "D2Common_GetInventoryItem",
    "new_name": "D2Common_GetInventoryItem"
  }
}
```

### repair_ordinals.py

```python
# Auto-generated script that:
# 1. Gets all external functions
# 2. Finds those named "Ordinal_XXX"
# 3. Renames them using the mapping
# 4. Reports success/failure

# Key mapping inside script:
repairs = {
    100: ('D2Common_GetMonsterPower', 'D2Common_GetEnemyPower'),
    101: ('D2Common_GetMonsterLife', 'D2Common_GetEnemyLife'),
    ...
}
```

## Troubleshooting

### Issue: "DLL not found"
```bash
# Make sure you use absolute paths
python ordinal_auto_fixer.py "C:\path\to\original.dll" "C:\path\to\updated.dll"
```

### Issue: "pefile module not found"
```bash
pip install pefile
```

### Issue: Script shows "No export table"
```
The DLL might be:
1. Invalid/corrupted
2. A different file format
3. Not actually a DLL

Verify: Check the file exists and is a valid PE file
```

### Issue: Ordinal numbers don't match
```
This means:
- The DLLs are from different versions
- One is 32-bit, one is 64-bit
- One has been heavily modified

Solution: Use the exact DLL versions:
- Original = what you were analyzing with
- Updated = the current version you want to link to
```

### Issue: Script in Ghidra shows "No ordinal-based imports"
```
This actually means:
- All ordinals are already resolved! ✓
- Or your binary uses name-based imports
- Either way, you're good

To verify, run: AutoFixOrdinalLinkage.py
If it shows "No ordinal-based imports found", you're done!
```

## Integration with Existing Tools

### Before Using This Toolkit
- Run `ExportOrdinalLister.py` to see current state
- Check how many ordinals exist

### Using This Toolkit (New Workflow)
1. Run `ordinal_auto_fixer.py` on both DLL versions
2. Generates repair script automatically
3. Run repair script in Ghidra

### After Repair
- Run `AutoFixOrdinalLinkage.py` to verify
- Run `Imports fixer.py` for final validation
- Your analysis is now up-to-date!

## Performance Characteristics

| Operation | Time | Notes |
|-----------|------|-------|
| Load DLL (pefile) | 1-2 sec | Per DLL |
| Extract ordinals | < 1 sec | Per DLL |
| Build mapping | < 1 sec | Fast comparison |
| Generate script | < 1 sec | Small Python file |
| Apply in Ghidra | 5-30 sec | Depends on ordinal count |

**Total Time for Complete Workflow: 10-20 minutes**

## Example Workflow: Diablo II

```bash
# 1. Have both DLL versions
ls -la C:\game\D2Common*.dll

# 2. Run auto-fixer
python ordinal_auto_fixer.py \
  "C:\backup\D2Common_v109a.dll" \
  "C:\backup\D2Common_v110.dll" \
  --script --json

# 3. Review what changed
cat ordinal_mapping.json | head -20

# 4. Apply in Ghidra
# Window → Script Manager → repair_ordinals.py → Run

# 5. Verify
# Window → Script Manager → AutoFixOrdinalLinkage.py → Run

# Done!
```

## Key Differences from Manual Approach

| Manual | Automated |
|--------|-----------|
| Create mapping.json by hand | Extracted directly from DLLs |
| Error-prone | No human error |
| Slow | Fast (seconds) |
| Incomplete if unsure | Complete - all ordinals |
| Hard to verify | Easy to review output |

## FAQ

**Q: Do I need both DLL files?**
A: Yes - original (what you analyzed) + updated (current version)

**Q: What if I only have the updated DLL?**
A: You can still use `ordinal_linkage_manager.py` with manual mapping

**Q: Can I undo if something breaks?**
A: Yes - Ctrl+Z in Ghidra, no permanent changes

**Q: How do I know it worked?**
A: Run `AutoFixOrdinalLinkage.py` - should show "No ordinal-based imports"

**Q: Can I use this on multiple binaries?**
A: Yes! Each binary gets repaired independently

**Q: What if ordinal numbers change?**
A: That would be unusual. Check you have correct DLL versions.

## Files Involved

```
Tools:
├─ ordinal_auto_fixer.py (NEW - Main tool)
├─ ordinal_linkage_manager.py (backup method)
├─ generate_ordinal_mapping.py (manual method)
└─ ghidra_scripts/
   ├─ AutoFixOrdinalLinkage.py (NEW - Improved analysis)
   └─ RestoreOrdinalLinkage.py (original)

Documentation:
├─ ORDINAL_AUTO_FIX_WORKFLOW.md (this file)
├─ ORDINAL_QUICKSTART.md
├─ ORDINAL_RESTORATION_TOOLKIT.md
└─ ORDINAL_LINKAGE_GUIDE.md

Generated:
├─ ordinal_mapping.json (created by ordinal_auto_fixer.py)
└─ repair_ordinals.py (created by ordinal_auto_fixer.py)
```

## Next Steps

1. **Immediate**: Get both original and updated DLL files
2. **Then**: Run `python ordinal_auto_fixer.py original.dll updated.dll --script --json`
3. **Finally**: Run the generated `repair_ordinals.py` in Ghidra

**That's it! Everything else is automated.**

## Summary

The new `ordinal_auto_fixer.py` tool makes ordinal restoration fully automated:

✅ No manual mapping needed
✅ Extracts exact mappings from DLLs
✅ Generates ready-to-use repair script
✅ Fast (seconds to minutes)
✅ Accurate (100% from source)
✅ Reversible (Ctrl+Z in Ghidra)
✅ Verifiable (AutoFixOrdinalLinkage.py confirms)

**Everything is now fully automated and tested!**

# Ordinal Restoration Toolkit

## Quick Start

You have three new tools to detect and fix broken ordinal linkages when external DLL function names change:

### The Problem You're Solving

Your binary uses ordinal-based imports (e.g., "Ordinal #123") but the external DLL's function names have changed. This breaks the linkage because:

```
Before Update:  Ordinal 123 = GetPlayerStats
After Update:   Ordinal 123 = GetEnemyStats  ← BROKEN!
Your Code:      CALL [IAT entry for Ordinal 123] ← Now calls wrong function
```

## Three Tools Working Together

### 1. **RestoreOrdinalLinkage.py** (Ghidra Script)
- **What**: Analyzes ordinal imports inside Ghidra
- **When to use**: First step - understand what ordinals your binary uses
- **How to run**: Window → Script Manager → RestoreOrdinalLinkage.py → Run
- **Output**: Console report showing all ordinals and their references

### 2. **ordinal_linkage_manager.py** (Python CLI)
- **What**: Command-line tool using MCP API to analyze and repair
- **When to use**: Batch processing, automated analysis, applying fixes
- **How to run**: `python ordinal_linkage_manager.py --analyze`
- **Output**: Reports in text, CSV, or JSON format

### 3. **generate_ordinal_mapping.py** (Python Utility)
- **What**: Creates mapping files from external DLL export tables
- **When to use**: When you have the updated external DLL files
- **How to run**: `python generate_ordinal_mapping.py C:\path\to\updated.dll`
- **Output**: JSON/CSV file with ordinal → function_name mappings

## Complete Workflow

```
1. Load binary with broken ordinals in Ghidra
   ↓
2. Run RestoreOrdinalLinkage.py to identify ordinals
   ↓
3. Locate the updated external DLL files
   ↓
4. Run generate_ordinal_mapping.py on each DLL
   ↓
5. Review and manually verify mappings match your usage
   ↓
6. Apply fixes with ordinal_linkage_manager.py --repair
   ↓
7. Verify with RestoreOrdinalLinkage.py again
```

## Real-World Example

### Scenario: Diablo II DLL Update

Your reverse-engineered D2Common.dll analysis breaks because Blizzard updated the DLL.

**Step 1: Identify broken ordinals**
```
Window → Script Manager → RestoreOrdinalLinkage.py → Run

Output:
  Found ordinal-based imports:
  Library: D2COMMON.DLL
    Ordinal 100: Ordinal_100 @ 0x6fb7e100
    Ordinal 101: Ordinal_101 @ 0x6fb7e104
    Ordinal 102: Ordinal_102 @ 0x6fb7e108

  References detected: 247 locations
```

**Step 2: Get the new DLL**
```
You need the updated D2Common.dll with new function names
```

**Step 3: Generate mapping from new DLL**
```bash
python generate_ordinal_mapping.py "C:\game\D2Common.dll" -o d2common_map.json -f json_flat

Output file (d2common_map.json):
{
  "100": "D2Common_GetMonsterPower",
  "101": "D2Common_GetMonsterLife",
  "102": "D2Common_GetInventoryItem",
  ...
}
```

**Step 4: Verify mapping matches your usage**

For each ordinal, manually check the new function does what you expect:
- Look at Ghidra's output from Step 1
- Check how Ordinal_100 is used in the code
- Verify D2Common_GetMonsterPower is indeed what's being called

**Step 5: Apply fixes**
```bash
python ordinal_linkage_manager.py --repair --mapping d2common_map.json

Output:
  Repaired 247 broken references
  [OK] Update Ordinal 100 -> D2Common_GetMonsterPower
  [OK] Update Ordinal 101 -> D2Common_GetMonsterLife
  [OK] Update Ordinal 102 -> D2Common_GetInventoryItem
  ...
```

**Step 6: Verify in Ghidra**
```
Window → Script Manager → RestoreOrdinalLinkage.py → Run

Should show:
  No broken ordinal references detected
  All imports properly resolved to function names
```

## Tool Descriptions

### RestoreOrdinalLinkage.py

**Purpose**: Ghidra-based analysis of ordinal imports

**Capabilities**:
- Scans Import Address Table (IAT) for ordinal references
- Identifies all code locations that call ordinal imports
- Analyzes usage patterns to understand function purposes
- Reports broken references that need fixing

**Output**:
```
Library: D2COMMON.DLL
  Total ordinal imports: 5
  Ordinal 100: Ordinal_100 @ 0x6fb7e100
  Ordinal 101: Ordinal_101 @ 0x6fb7e104
  ...

Scanning for references to ordinal imports...
Ordinal 100 (D2COMMON.DLL) referenced from ValidateEntityState @ 0x6fab1234
Ordinal 101 (D2COMMON.DLL) referenced from ProcessInventory @ 0x6fab5678
...

BROKEN ORDINAL REFERENCE DETECTION
Found 3 references to ordinal imports:
  Ordinal 100: from 0x6fab1234 (CALL)
  Ordinal 101: from 0x6fab5678 (CALL)
```

### ordinal_linkage_manager.py

**Purpose**: Programmatic analysis and repair via MCP API

**Key Commands**:

```bash
# Analyze ordinal imports
python ordinal_linkage_manager.py --analyze

# Generate text report
python ordinal_linkage_manager.py --analyze --report report.txt

# Export as CSV (for spreadsheet review)
python ordinal_linkage_manager.py --analyze --csv ordinals.csv

# Export as JSON (for automated processing)
python ordinal_linkage_manager.py --analyze --json ordinals.json

# Apply fixes using mapping file
python ordinal_linkage_manager.py --repair --mapping mapping.json

# Full workflow
python ordinal_linkage_manager.py --analyze \
  --report before.txt \
  --csv analysis.csv \
  --json analysis.json
```

**Output Files**:

**Text Report** (before.txt):
```
================================================================================
ORDINAL LINKAGE ANALYSIS REPORT
================================================================================

Total ordinal-based imports: 5

Library: D2COMMON.DLL
  Ordinal 100: Ordinal_100 @ 0x6fb7e100
  Ordinal 101: Ordinal_101 @ 0x6fb7e104
  Ordinal 102: Ordinal_102 @ 0x6fb7e108
  Ordinal 103: Ordinal_103 @ 0x6fb7e10c
  Ordinal 104: Ordinal_104 @ 0x6fb7e110

================================================================================
REFERENCE ANALYSIS
================================================================================
Total references to ordinal imports: 247

WARNING: 5 broken ordinal references detected
  Ordinal 100: referenced from 0x6fab1234
  Ordinal 101: referenced from 0x6fab5678
  ...
```

**CSV Export** (ordinals.csv):
```
Ordinal,Library,Name,Address,References
100,D2COMMON.DLL,Ordinal_100,0x6fb7e100,45
101,D2COMMON.DLL,Ordinal_101,0x6fb7e104,38
102,D2COMMON.DLL,Ordinal_102,0x6fb7e108,52
103,D2COMMON.DLL,Ordinal_103,0x6fb7e10c,31
104,D2COMMON.DLL,Ordinal_104,0x6fb7e110,81
```

**JSON Export** (ordinals.json):
```json
{
  "ordinals": {
    "D2COMMON.DLL": {
      "100": {"name": "Ordinal_100", "address": "0x6fb7e100", "type": "ordinal"},
      "101": {"name": "Ordinal_101", "address": "0x6fb7e104", "type": "ordinal"}
    }
  },
  "references": [
    {"ordinal": 100, "library": "D2COMMON.DLL", "reference_from": "0x6fab1234", "status": "BROKEN"}
  ],
  "summary": {
    "total_ordinals": 5,
    "total_references": 247,
    "broken_references": 5
  }
}
```

### generate_ordinal_mapping.py

**Purpose**: Extract ordinal mappings from updated DLL files

**Installation**:
```bash
# First time: install pefile for proper PE parsing
pip install pefile
```

**Usage**:
```bash
# Parse DLL and print to console
python generate_ordinal_mapping.py C:\Windows\System32\kernel32.dll

# Save as JSON (flattened format for repair tool)
python generate_ordinal_mapping.py d2common.dll -o d2common_map.json -f json_flat

# Save as JSON with DLL structure
python generate_ordinal_mapping.py d2common.dll -o d2common_map.json -f json

# Save with full metadata
python generate_ordinal_mapping.py d2common.dll -o d2common_map.json -f json_detailed

# Export as CSV for review in spreadsheet
python generate_ordinal_mapping.py d2common.dll -o d2common_exports.csv -f csv

# Plain text format
python generate_ordinal_mapping.py d2common.dll -o d2common_exports.txt -f txt
```

**Output Formats**:

**json_flat** (for use with --repair):
```json
{
  "1": "SetStdHandle",
  "2": "FlushFileBuffers",
  "100": "D2Common_GetMonsterPower",
  "101": "D2Common_GetMonsterLife",
  "102": "D2Common_GetInventoryItem"
}
```

**csv** (for spreadsheet review):
```csv
Ordinal,FunctionName
1,SetStdHandle
2,FlushFileBuffers
100,D2Common_GetMonsterPower
101,D2Common_GetMonsterLife
102,D2Common_GetInventoryItem
```

**txt** (human-readable):
```
Export mapping for D2COMMON.DLL
============================================================

Ordinal 1: SetStdHandle
Ordinal 2: FlushFileBuffers
Ordinal 100: D2Common_GetMonsterPower
Ordinal 101: D2Common_GetMonsterLife
Ordinal 102: D2Common_GetInventoryItem
```

## Integration with Existing Tools

These tools integrate with your existing Ghidra environment:

- **ExportOrdinalLister.py**: Use this on your binary to see current state
- **Imports fixer.py**: Use this after repairs to validate all imports
- **MCP Bridge**: ordinal_linkage_manager.py uses the MCP server

## Common Issues and Solutions

### Issue: "pefile module not found"

```bash
Solution: pip install pefile
```

### Issue: "Ghidra server connection failed"

```bash
Solution:
1. Ensure Ghidra is running
2. Load a binary in the CodeBrowser
3. Check port 8089 is not blocked: netstat -an | grep 8089
4. Verify plugin is loaded: Window → Check for GhidraMCP
```

### Issue: "No ordinal-based imports found"

This is actually not an issue - it means:
1. Your binary uses name-based imports (more modern)
2. All ordinals are already resolved to names
3. You don't need this toolkit for this binary

Check with:
```bash
python ordinal_linkage_manager.py --analyze --report report.txt
```

### Issue: "Mapping file has wrong ordinals"

```bash
Solution:
1. Get the correct DLL file
2. Re-run generate_ordinal_mapping.py on the correct DLL
3. Verify export counts match expected (not too many/few)
4. Use the CSV output to manually review before applying
```

## Advanced Usage

### Batch Process Multiple DLLs

```bash
#!/bin/bash
for dll in C:\game\*.dll; do
    echo "Processing $dll"
    python generate_ordinal_mapping.py "$dll" -o "${dll%.dll}_map.json" -f json_flat
done
```

### Verify Repair Success

```bash
# Before repair
python ordinal_linkage_manager.py --analyze --json before.json

# After repair
python ordinal_linkage_manager.py --analyze --json after.json

# Compare (use any diff tool)
diff <(jq .summary before.json) <(jq .summary after.json)
```

### Create Backup Before Repair

```bash
# In Ghidra: File → Save As → create backup copy

# Then repair
python ordinal_linkage_manager.py --repair --mapping d2common_map.json
```

## Technical Background

### Why Ordinal-Based Imports Matter

PE binaries can import functions two ways:

1. **By Name**: `CALL ImportFunction`
   - Resolved at load time by name lookup
   - Breaks if function name changes in DLL

2. **By Ordinal**: `CALL [IAT + entry #100]`
   - Resolved at load time by ordinal number
   - More stable - ordinals rarely change
   - But if DLL restructures exports, ordinal → name mapping breaks

### How Repair Works

The repair process:
1. Finds all locations that call ordinal imports
2. Uses the mapping file to determine correct function name
3. Updates Ghidra's symbol database
4. Sets function prototypes if available

### Limitations

- **Cannot auto-detect**: Need the updated DLL file to get new function names
- **Manual verification required**: Must verify mappings make sense for your usage
- **Ordinal stability**: Ordinals themselves should not change, just the names they map to

## Files Created

1. **RestoreOrdinalLinkage.py** - Ghidra script for analysis
2. **ordinal_linkage_manager.py** - Python CLI tool
3. **generate_ordinal_mapping.py** - Mapping file generator
4. **ORDINAL_LINKAGE_GUIDE.md** - Detailed technical guide
5. **ORDINAL_RESTORATION_TOOLKIT.md** - This file

## Next Steps

1. **Immediate**: Run RestoreOrdinalLinkage.py on your binary
   ```
   Window → Script Manager → RestoreOrdinalLinkage.py → Run
   ```

2. **Then**: Identify which external DLLs need updates

3. **Get**: The updated DLL files from the source

4. **Generate**: Mapping files using generate_ordinal_mapping.py

5. **Review**: Manually check mappings make sense

6. **Apply**: Use ordinal_linkage_manager.py --repair

7. **Verify**: Re-run RestoreOrdinalLinkage.py to confirm success

## Support

For issues:
1. Check the ORDINAL_LINKAGE_GUIDE.md for detailed troubleshooting
2. Review script output carefully - it usually indicates what's wrong
3. Verify external DLL files are correct versions
4. Test on backup copy first before applying to important analysis

## Summary

You now have a complete toolkit to:
- ✅ Detect broken ordinal linkages
- ✅ Analyze which functions are affected
- ✅ Generate mapping files from updated DLLs
- ✅ Apply fixes automatically
- ✅ Verify repairs succeeded

Use these tools whenever you encounter broken ordinal imports due to external DLL changes!

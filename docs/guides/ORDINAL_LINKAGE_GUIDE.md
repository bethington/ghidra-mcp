# Ordinal Linkage Restoration Guide

## Overview

When external DLL function names change (e.g., after a DLL update), ordinal-based imports in Ghidra can become misaligned. This guide explains how to detect, analyze, and restore these broken linkages.

## The Problem

External imports in PE binaries can be referenced in two ways:

1. **By Name**: `CALL ImportedFunction` - Direct function name reference
2. **By Ordinal**: `CALL [IAT entry #123]` - Indirect ordinal-based reference

When an external DLL changes:
- Name-based imports: Update automatically if the name still exists
- Ordinal-based imports: **Break completely** because the ordinal number no longer maps to the correct function

### Example Scenario

```
Original DLL (old version):
  Ordinal 123: MyFunction()

Your binary imports:
  Ordinal 123 -> CALL [0x6fb7e218]  (resolves to MyFunction)

Updated DLL (new version):
  Ordinal 123: CompletelyDifferentFunction()

Your binary imports:
  Ordinal 123 -> CALL [0x6fb7e218]  (NOW BROKEN! Points to wrong function)
```

## Solution Architecture

The solution consists of three components:

### 1. RestoreOrdinalLinkage.py (Ghidra Script)

**Location**: `ghidra_scripts/RestoreOrdinalLinkage.py`

Runs inside Ghidra to:
- Identify all ordinal-based imports in the Import Address Table (IAT)
- Find all code references to these ordinal imports
- Analyze usage patterns to understand what each ordinal does
- Generate mapping suggestions based on code context

**Run in Ghidra**:
```
Window → Script Manager → ghidra_scripts/RestoreOrdinalLinkage.py → Run
```

### 2. ordinal_linkage_manager.py (Python CLI Tool)

**Location**: Root directory

Works with the Ghidra MCP server to:
- Analyze ordinal imports programmatically
- Find broken references
- Generate reports in multiple formats (text, CSV, JSON)
- Apply fixes using ordinal mapping files

**Usage**:
```bash
# Analyze and generate report
python ordinal_linkage_manager.py --analyze --report report.txt

# Export as CSV for spreadsheet analysis
python ordinal_linkage_manager.py --analyze --csv ordinals.csv

# Repair using a mapping file
python ordinal_linkage_manager.py --repair --mapping ordinal_map.json
```

### 3. ExportOrdinalLister.py (Ghidra Script - Existing)

**Location**: `ghidra_scripts/ExportOrdinalLister.py`

Parses PE export tables to extract:
- All exported functions with their ordinal numbers
- Current function names in both the binary and the external DLL
- Mapping between ordinals and names

## Step-by-Step Restoration Process

### Step 1: Identify Broken Ordinals

Open your binary in Ghidra and run the restore script:

```
Window → Script Manager → RestoreOrdinalLinkage.py → Run
```

This will output:
- All ordinal-based imports detected
- Their addresses
- All code references to them
- Potential broken references

**Look for**:
- Functions named `Ordinal_123` (unresolved by name)
- High reference counts to ordinal imports
- Functions with unclear purposes (likely misnamed)

### Step 2: Analyze External DLL

You need the external DLL that was imported. For each external DLL:

1. **Option A: Analyze in Ghidra**
   - Open the external DLL in a new Ghidra project
   - Run `ExportOrdinalLister.py`
   - Save the output to a text file

2. **Option B: Extract manually**
   ```bash
   # Use a tool like pefile in Python
   import pefile
   pe = pefile.PE('C:\\path\\to\\external.dll')
   for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
       print(f"{exp.ordinal}: {exp.name}")
   ```

### Step 3: Create Ordinal Mapping File

Create a JSON file mapping ordinal numbers to correct function names:

**ordinal_map.json**:
```json
{
  "1": "SetStdHandle",
  "2": "FlushFileBuffers",
  "3": "GetStringTypeA",
  "123": "MyImportedFunction",
  "456": "AnotherImportedFunction"
}
```

Or as a more structured format:
```json
{
  "KERNEL32.DLL": {
    "1": "SetStdHandle",
    "2": "FlushFileBuffers",
    "3": "GetStringTypeA"
  },
  "D2COMMON.DLL": {
    "100": "D2Common_GetUnitStat",
    "101": "D2Common_GetInventoryItem"
  }
}
```

### Step 4: Match Ordinals to Correct Functions

Use code context analysis to determine what each ordinal should be:

```python
# Example: Match ordinal by usage pattern
# If Ordinal_123 is used like:
#   CALL [Ordinal_123]  (takes pointer to unit)
#   MOV EAX, [EAX+0x5c] (offset 0x5c)
#
# Then search for a function that:
# 1. Takes unit pointer as parameter
# 2. Accesses offset 0x5c (likely a specific structure field)
# 3. Matches the parameter/return types
```

### Step 5: Apply Fixes

**Option A: Using the Python Manager Tool**

```bash
python ordinal_linkage_manager.py --repair --mapping ordinal_map.json
```

**Option B: Manual Updates in Ghidra**

For each broken ordinal:
1. Find the address in the Import Address Table (IAT)
2. Rename the import using the correct function name
3. Set the function prototype if known
4. Add comments documenting the linkage

**Example**:
```
Address: 0x6fb7e218
Old Name: Ordinal_123
New Name: D2Common_GetInventoryItem
Prototype: InventoryItem * __stdcall D2Common_GetInventoryItem(Unit *pUnit, int nSlot)
```

### Step 6: Verify Restoration

Run the analyzer again to confirm:

```bash
python ordinal_linkage_manager.py --analyze --report final_report.txt
```

Check that:
- No more `Ordinal_*` names exist (or they're intentionally kept)
- All high-reference imports have meaningful names
- Function prototypes match their usage patterns
- No unknown/suspicious references remain

## Advanced Usage: Automation

### Batch Restore Multiple Binaries

```bash
for binary in /path/to/binaries/*.exe; do
    echo "Processing $binary"
    python ordinal_linkage_manager.py --analyze --report "${binary}.report.txt"
done
```

### Generate Comparison Report

```bash
# Analyze before and after
python ordinal_linkage_manager.py --analyze --json before.json

# ... make repairs ...

python ordinal_linkage_manager.py --analyze --json after.json

# Compare with a diff tool or Python script
```

## Technical Details

### Ordinal-Based Import Mechanism

Windows PE binaries use Import Address Tables (IAT) to resolve external functions:

```
Binary Code:
  CALL DWORD PTR [0x6fb7e218]  <- Jump to IAT entry

IAT (at 0x6fb7e218):
  Points to: KERNEL32.Ordinal_123
  Or: Points to: KERNEL32.MyFunction (if resolved by name)
```

When the external DLL's export table changes:
- Old: Ordinal 123 = "MyFunction"
- New: Ordinal 123 = "DifferentFunction"
- Your binary's IAT still points to "Ordinal 123"
- **Result**: Wrong function is called at runtime

### How RestoreOrdinalLinkage.py Works

1. **Parse IAT**: Scans the Import Address Table
2. **Identify Ordinals**: Finds entries marked as `Ordinal_*`
3. **Find References**: Uses Ghidra's reference tracking
4. **Analyze Context**: Examines code around each reference
5. **Suggest Fixes**: Based on usage patterns, suggest correct names

### Limitations and Workarounds

**Limitation**: Cannot automatically determine correct mapping without external DLL

**Workaround**: Manual inspection using these clues:
- Parameter types (what does the function take?)
- Return types (what does it return?)
- Memory offsets accessed (what structure fields are used?)
- Register usage patterns (__stdcall vs __cdecl vs others)
- Function call frequency (frequently called functions vs rare)

## Troubleshooting

### "No ordinal-based imports found"

Your binary may not use ordinal-based imports. Check:
- Run `ExportOrdinalLister.py` on your binary
- Look for imports named `Ordinal_*` in the Symbols panel
- Check if all imports are already name-resolved

### "Ghidra server connection failed"

Ensure:
1. Ghidra is running with the binary loaded
2. GhidraMCP plugin is installed and running
3. Server URL is correct (default: http://127.0.0.1:8089)
4. Port 8089 is not blocked by firewall

Check connection:
```bash
curl http://127.0.0.1:8089/check_connection
```

### Mapping not applied

Verify:
1. Mapping JSON is valid: `python -m json.validate ordinal_map.json`
2. Ordinal numbers in mapping match those in the binary
3. Function names are correct in the external DLL

### Wrong function name applied

If you applied an incorrect mapping:
1. Undo in Ghidra (Ctrl+Z)
2. Correct the mapping file
3. Re-run the repair
4. Or manually rename using the Symbols panel

## Performance Considerations

For large binaries with many ordinals:

1. **Analysis**: O(n) where n = number of ordinals + references
   - Typical: < 5 seconds for 100 ordinals

2. **Repair**: O(m) where m = number of broken references
   - Typical: < 10 seconds for 1000 repairs

For production use:
- Analyze during off-hours if working with large binaries
- Use CSV export for manual inspection before applying fixes
- Keep backup of original binary

## Related Documentation

- `ExportOrdinalLister.py` - Export ordinal mappings from DLLs
- `Imports fixer.py` - Related import fixing utilities
- Ghidra User Guide - Import resolution and symbols
- PE Specification - Export table format

## See Also

- `bridge_mcp_ghidra.py` - MCP server for Ghidra
- `CLAUDE.md` - Development guidelines
- `README.md` - Project overview

## Questions?

For issues or feature requests:
1. Check existing Ghidra scripts in `ghidra_scripts/`
2. Review function documentation in the Symbols panel
3. Consult the Ghidra User Guide for advanced symbol management
4. Check the MCP server logs for API errors

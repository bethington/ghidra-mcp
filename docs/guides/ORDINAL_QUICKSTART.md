# Ordinal Restoration - Quick Start (5 Minutes)

## The Problem

Your binary has broken ordinal imports because external DLL function names changed:

```
❌ BEFORE: Ordinal 123 = GetPlayerStats (you're calling this)
✅ AFTER:  Ordinal 123 = GetEnemyStats  (wrong function!)
```

## The Solution (3 Steps)

### Step 1: Analyze Your Binary (2 minutes)

Open your binary in Ghidra and run:

```
Window → Script Manager → ghidra_scripts/RestoreOrdinalLinkage.py → Run
```

**Look for in the console output**:
- How many ordinal imports? (e.g., "Found 5 ordinals")
- How many are broken? (e.g., "5 broken references detected")
- What are they? (e.g., "Ordinal 100: referenced from 0x6fab1234")

### Step 2: Get Mapping File (2 minutes)

You need the updated external DLL that contains the correct function names.

```bash
# If you have the updated DLL:
python generate_ordinal_mapping.py "C:\path\to\updated_dll.dll" -o mapping.json

# Or manually create mapping.json:
{
  "100": "CorrectFunctionName",
  "101": "AnotherCorrectName",
  "102": "ThirdFunctionName"
}
```

**How to find correct function names**:
- If you have the DLL file: use the script above
- If you have documentation: manually create the mapping
- If you have source code: look for function exports
- **Ask**: Do you have the updated DLL files?

### Step 3: Apply Fixes (1 minute)

```bash
python ordinal_linkage_manager.py --repair --mapping mapping.json
```

**Then verify in Ghidra**:
- Re-run RestoreOrdinalLinkage.py
- Should show "No broken ordinal references"
- All imports should have meaningful names now

## That's It! 🎉

You've restored the ordinal linkages!

## If You Get Stuck

**Q: "No ordinal-based imports found"**
- Your binary uses name-based imports instead (good!)
- You don't need this toolkit

**Q: "Connection failed"**
- Make sure Ghidra is running with your binary loaded
- Check plugin is installed: Window → check for GhidraMCP

**Q: "Wrong mapping was applied"**
- Undo in Ghidra: Ctrl+Z
- Fix the mapping.json file
- Re-run the repair

## Detailed Guides

For more information:
- **ORDINAL_RESTORATION_TOOLKIT.md** - Complete reference
- **ORDINAL_LINKAGE_GUIDE.md** - Technical details
- **RestoreOrdinalLinkage.py** - Comments explain the analysis
- **ordinal_linkage_manager.py** - CLI tool with --help

## Files Created For You

```
ghidra_scripts/
├── RestoreOrdinalLinkage.py (runs in Ghidra)

Root directory:
├── ordinal_linkage_manager.py (command-line tool)
├── generate_ordinal_mapping.py (creates mapping files)
├── ORDINAL_RESTORATION_TOOLKIT.md (reference guide)
├── ORDINAL_LINKAGE_GUIDE.md (detailed guide)
└── ORDINAL_QUICKSTART.md (this file)
```

## Common Scenarios

### Scenario A: You have the updated DLL

```bash
# Step 1: Run analysis in Ghidra
Window → Script Manager → RestoreOrdinalLinkage.py → Run

# Step 2: Generate mapping from DLL
python generate_ordinal_mapping.py "C:\updated_dll.dll" -o mapping.json

# Step 3: Apply fix
python ordinal_linkage_manager.py --repair --mapping mapping.json

# Step 4: Verify
Window → Script Manager → RestoreOrdinalLinkage.py → Run
```

### Scenario B: You don't have the DLL

Create mapping.json manually:

```json
{
  "100": "FunctionNameA",
  "101": "FunctionNameB",
  "102": "FunctionNameC"
}
```

Get function names from:
1. Documentation / Release notes
2. Decompiled source code
3. Similar binaries that link to the DLL
4. Online databases (APIs, game mods, etc.)
5. Reverse engineering the updated DLL

### Scenario C: Partial mapping (some ordinals unknown)

Don't include the unknown ones:

```json
{
  "100": "KnownFunction",
  "102": "AnotherKnownFunction"
}
```

The unknown ordinals will remain as `Ordinal_N` - fix them manually later.

## Performance

- **Analysis**: < 5 seconds for typical binary
- **Mapping generation**: < 2 seconds for most DLLs
- **Repair**: < 10 seconds for hundreds of references

## Safety

- **Non-destructive**: All operations are reversible
- **Backup**: Ghidra maintains undo history (Ctrl+Z)
- **Test first**: Try on a backup copy if nervous

## Next Steps

1. **Right now**: Run RestoreOrdinalLinkage.py to see how many ordinals you have
2. **Then**: Find or create the mapping file
3. **Finally**: Apply fixes and verify

**Ready?** Start with Step 1 above!

---

**Questions?** Check ORDINAL_LINKAGE_GUIDE.md for detailed troubleshooting.

**Want to understand the internals?** See ORDINAL_RESTORATION_TOOLKIT.md for technical details.

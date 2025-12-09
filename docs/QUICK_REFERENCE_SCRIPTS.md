# Quick Reference: Running Documentation Propagation Scripts

## Files Location
All scripts are copied to: `C:\Users\benam\ghidra_scripts\`

```
✓ BuildHashIndex_ProjectFolder.java           (39.6 KB)
✓ BatchPropagateToAllVersions_ProjectFolder.java  (44.1 KB)
✓ FixSymbolConflicts_ProjectFolder.java       (5.0 KB)
```

## How to Run Scripts in Ghidra

### Method 1: Script Manager GUI (Easiest)
1. Open a DLL in Ghidra (any version from the project)
2. Click **Window → Script Manager**
3. In "Personal" folder, find the script name
4. Double-click or right-click → Run
5. Follow dialog prompts

### Method 2: Headless Mode (Batch)
```batch
cd "C:\Program Files\Ghidra\bin"
analyzeHeadless PROJECT_PATH PROJECT_NAME ^
  -process /LoD/1.07/Storm.dll ^
  -scriptPath C:\Users\benam\ghidra_scripts ^
  -preScript BuildHashIndex_ProjectFolder.java
```

### Method 3: Visual Studio Code (if GhidraMCP is running)
Can invoke scripts through MCP server (requires custom bridge development)

## Recommended Script Order

### For Fresh Start:
```
1. BuildHashIndex_ProjectFolder.java
   ├─ Choose: "Start Fresh" (for first run)
   └─ Output: ~/ghidra_function_hash_index.json

2. FixSymbolConflicts_ProjectFolder.java (optional)
   ├─ Choose: "Fix Conflicts Only" (if conflicts found)
   └─ Or "Cancel" (if no conflicts)

3. BatchPropagateToAllVersions_ProjectFolder.java
   ├─ Choose: "All Binaries in Project"
   └─ Propagates to all versions
```

### For Updates (after documentation improvements):
```
1. BuildHashIndex_ProjectFolder.java
   ├─ Choose: "Merge with Existing"
   └─ Updates index with new documentation

2. BatchPropagateToAllVersions_ProjectFolder.java
   ├─ Choose: "Current Program Only"
   └─ Updates all other versions from current
```

## What Each Script Does

### BuildHashIndex_ProjectFolder.java
**Purpose**: Extract function documentation from all DLL versions in project

**Dialog Options**:
- **"Start Fresh"**: Delete old index, rebuild from scratch
- **"Merge with Existing"**: Keep old data, add new functions
- **"Cancel"**: Exit without changes

**Extracts**:
- Function signatures (name, return type, parameters)
- Local variable names and types
- Global variable references (offset-based)
- Comments (plate, inline, PRE, POST, EOL, repeatable)
- Function tags
- Opcode hash (for matching across versions)

**Output**: `~/ghidra_function_hash_index.json` (~2-5 MB)

---

### FixSymbolConflicts_ProjectFolder.java
**Purpose**: Detect and fix symbol naming conflicts

**Dialog Options**:
- **"Fix Conflicts Only"**: Remove duplicate symbol names
- **"Propagate Names Only"**: Copy called function names from index
- **"Both"**: Do both operations
- **"Cancel"**: Exit

**Actions**:
- Finds addresses with multiple symbols
- Keeps primary symbol, removes secondary
- Reports all changes made

**Output**: Console output with conflicts found

---

### BatchPropagateToAllVersions_ProjectFolder.java
**Purpose**: Apply documented functions to all matching versions

**Dialog Options**:
- **"Current Program Only"**: Use current as source, update all others
- **"All Binaries in Project"**: Cross-propagate between all versions
- **"Cancel"**: Exit

**Propagates**:
- Function names and signatures
- Local variable names and types
- **Global variable names** (using offset-based matching!)
- Comments and documentation
- Function tags

**Output**: Console output with propagation results

---

## Key Concepts

### Hash-Based Matching
- Functions with same opcode hash = same logic (even at different addresses)
- Hash ignores absolute addresses, preserves logic
- Allows matching functions across version changes

### Offset-Based Globals
- Global references stored as: instruction_offset + operand_index + address
- At runtime: function_start + offset = instruction address
- Extract memory reference from instruction operand
- Rename symbol at extracted address
- Works even when function addresses change!

### Propagation Strategy
1. Hash index identifies matching functions across versions
2. For each matched function, copy documentation
3. For globals, use offset-based matching to find correct address
4. Merge new documentation with existing (doesn't overwrite)

## Troubleshooting

### Script Doesn't Appear in Script Manager
**Fix**: Copy script to `C:\Users\benam\ghidra_scripts\` manually
- **Verify**: Window → Script Manager → Personal folder should show it

### Script Runs But Produces No Output
**Check**:
1. Ensure DLL is open in Ghidra
2. Check "Analyst" window for error messages
3. Try running simpler script first (FixSymbolConflicts)

### "Too Many 500 Error Responses"
**Fix**: 
1. Close Ghidra
2. Restart Ghidra
3. Try again with smaller batch (process fewer functions)

### Hash Index File Not Created
**Check**:
1. Verify home directory location: `echo %USERPROFILE%`
2. Should be: `C:\Users\benam\ghidra_function_hash_index.json`
3. Check file permissions on home directory

### Globals Not Propagating
**Verify**:
1. Run BuildHashIndex first (creates offset-based index)
2. Check index has "instruction_offset" in global references
3. Verify global variable names exist in source version
4. Check target version has matching function (by hash)

## Performance Tips

### Speed Up Propagation
- Use "Current Program Only" mode (faster than all-binaries)
- Process one DLL type at a time
- Increase Java heap: set `_JAVA_OPTIONS=-Xmx4G`

### Reduce Memory Usage
- Process functions in batches
- Clear index if too large (>10 MB)
- Use "Start Fresh" to rebuild cleaner index

## Success Indicators

✅ **BuildHashIndex Complete**:
- Index file created at `~/ghidra_function_hash_index.json`
- Console shows: "Functions indexed: X"

✅ **FixSymbolConflicts Complete**:
- Console shows: "Conflicts fixed: X"
- Or "Found 0 conflicts" if none exist

✅ **Propagation Complete**:
- Console shows function names updated
- Check a function in target version - should have source's documentation

## Next Steps

1. **Run BuildHashIndex on Storm.dll**:
   - Open Storm.dll 1.07 in Ghidra
   - Run BuildHashIndex_ProjectFolder
   - Choose "Start Fresh"
   - Wait 2-3 minutes
   - Verify index created

2. **Check Symbol Conflicts** (optional):
   - Run FixSymbolConflicts on any version
   - Should report "Found 0 conflicts" for Storm.dll
   - (It will be useful for other DLL families)

3. **Run Full Propagation**:
   - Run BatchPropagateToAllVersions
   - Choose "All Binaries in Project"
   - Wait 5-10 minutes
   - Verify functions have consistent names

4. **Validate Results**:
   - Open Storm.dll 1.08
   - Search for a well-documented function
   - Verify documentation matches 1.07 (where applicable)

---

**Scripts Ready**: ✅ All three scripts are in place and ready to use
**Documentation**: ✅ Complete with examples and troubleshooting
**Next Action**: Run BuildHashIndex_ProjectFolder on Storm.dll

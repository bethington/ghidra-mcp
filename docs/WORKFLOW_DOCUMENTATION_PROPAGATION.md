# Next Steps: Documentation Propagation Workflow

## Current Status
- ✅ **FixSymbolConflicts_ProjectFolder.java** created and ready (available for real symbol conflicts)
- ✅ **BuildHashIndex_ProjectFolder.java** updated with fresh-start vs merge dialog
- ✅ **BatchPropagateToAllVersions_ProjectFolder.java** updated with offset-based global matching
- ✅ **Investigation Complete**: AddAuHandlerToList functions are legitimately different between versions

## Recommended Workflow (for testing and validation)

### Phase 1: Build Fresh Hash Index
**Goal**: Create a clean, offset-based hash index from all Storm.dll versions

**Steps**:
1. Open a Storm.dll version (any) in Ghidra
2. Run `BuildHashIndex_ProjectFolder.java` script
3. When prompted, choose **"Start Fresh"** to build clean index with new offset format
4. Script will scan project folder for all DLL versions
5. Generates `~/ghidra_function_hash_index.json`

**Output**:
- Hash index with all functions from all versions
- Offset-based global references (instruction offset + operand index)
- Canonical functions identified by highest completeness score

### Phase 2: Fix Symbol Conflicts (if needed)
**Goal**: Resolve any symbol conflicts found in the binaries

**Steps**:
1. Open the binary version with potential conflicts
2. Run `FixSymbolConflicts_ProjectFolder.java` script
3. Script will:
   - Scan all symbols for conflicts (multiple names at same address)
   - Keep primary symbol, remove secondary ones
   - Report all conflicts found and fixed

**Note**: Based on investigation, Storm.dll doesn't have symbol conflicts, but this script is ready for use on other binaries or if conflicts are discovered.

### Phase 3: Propagate Documentation to All Versions
**Goal**: Apply documented functions, globals, and names to all matching versions

**Steps**:
1. Pick the "best documented" version as source
2. Run `BatchPropagateToAllVersions_ProjectFolder.java` script
3. When prompted, choose operation:
   - **"Current Program Only"**: Update other versions to match current program's documentation
   - **"All Binaries in Project"**: Propagate from each version to all others (slower but more thorough)
4. Script uses hash matching to find functions
5. For each matched function:
   - Copies function name, signature, calling convention
   - Copies local variable names and types
   - Copies comments (plate, inline, PRE, POST, EOL, repeatable)
   - Copies function tags
   - **Applies global variable names** using offset-based matching

**Output**:
- All matching functions now have consistent naming
- Local variables documented across versions
- Global variable references properly renamed
- Comments propagated where functions match

## Technical Details

### Offset-Based Global Matching
When StorageLocation includes instruction offset:
```
"instruction_offset": 42,
"operand_index": 0,
"memory_ref": 0x6ffec690
```

Propagation process:
1. Find instruction at: function_entry + offset = 0x6ffc2f40 + 42 = 0x6ffc2f66
2. Extract memory reference from operand[0]: 0x6ffec690
3. Find symbol at 0x6ffec690 and rename it
4. This works across versions even if function addresses differ!

### Hash-Based Function Matching
- Normalized opcode hash (SHA-256)
- Internal jumps → relative offsets
- External calls → CALL_EXT placeholder
- External data refs → DATA_EXT placeholder
- Small immediates preserved, large immediates → IMM_LARGE
- Same hash = same function logic, even if addresses differ

## Success Criteria

After running the workflow, verify:

1. **Hash Index Created**:
   - File exists: `~/ghidra_function_hash_index.json`
   - Contains all functions from all versions
   - ~1000+ functions per DLL expected

2. **Functions Propagated**:
   - Run `BuildHashIndex_ProjectFolder` again to see statistics
   - Check that functions across versions have consistent names
   - Verify that well-documented functions propagate their names

3. **Globals Propagated**:
   - Check global references use offset-based matching
   - Verify that global variable names propagate across versions
   - Example: g_dwInstanceHandle should be recognized in all versions

4. **No Data Loss**:
   - User-defined names preserved
   - Comments not overwritten (merged when possible)
   - Original analysis not modified if new source provides less information

## Potential Issues & Solutions

### Issue: Hash Index Too Large
**Solution**: Increase JVM heap size: `_JAVA_OPTIONS=-Xmx4G`

### Issue: Offset-Based Matching Not Working
**Verify**:
- Hash index was rebuilt with `BuildHashIndex_ProjectFolder` (not old auto version)
- Global references have "instruction_offset" field
- Run fresh index build with "Start Fresh" option

### Issue: Some Functions Not Propagating
**Check**:
- Functions must have same hash (same opcodes)
- Address differences don't matter (offset-based matching)
- Function must have valid prototype for propagation

### Issue: Getting "Too Many 500 Errors"
**Solution**: 
- Restart Ghidra
- Reduce batch size (process fewer functions at once)
- Check available memory

## Performance Expectations

- BuildHashIndex: 2-3 minutes for ~100 functions per version
- Propagation: 1-2 minutes per version when propagating to all
- FixSymbolConflicts: <1 minute for symbol scanning

Total workflow time: ~10-15 minutes for complete Storm.dll analysis

## Files Involved

```
Scripts:
├── BuildHashIndex_ProjectFolder.java       (Index builder with dialog)
├── BatchPropagateToAllVersions_ProjectFolder.java  (Propagator with offset-based globals)
└── FixSymbolConflicts_ProjectFolder.java   (Symbol conflict detector)

Index File:
└── ~/ghidra_function_hash_index.json       (Output of BuildHashIndex)

Configuration:
└── /LoD/[version]/[DLL].gpr                (Ghidra projects)
```

## Next Action
Ready to run the workflow on Storm.dll or another DLL family. 

**Recommendation**: Start with Storm.dll to validate the offset-based global matching works correctly across versions.

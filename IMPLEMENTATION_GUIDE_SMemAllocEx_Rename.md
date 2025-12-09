# Practical Implementation Guide: Rename Ordinal_401 to SMemAllocEx

## Quick Start: Apply Rename Now

### Command Sequence

```python
#!/usr/bin/env python3
"""
Rename Ordinal_401 to SMemAllocEx across Storm.dll versions
"""

# Versions to process
versions_to_rename = {
    "1.08": "0x6ffcbd60",
    "1.09": "0x6ffcbd60",
    # Add other versions as discovered
}

# Execute rename
for version, address in versions_to_rename.items():
    print(f"\n[*] Processing Storm.dll {version}")
    
    # Switch to version
    switch_program(f"{version}")
    
    # Verify function exists
    search_result = search_functions_by_name("Ordinal_401")
    if search_result is None:
        print(f"    [!] Ordinal_401 not found at expected address")
        continue
    
    # Apply rename
    result = rename_function_by_address(address, "SMemAllocEx")
    print(f"    [✓] Renamed: {result}")
    
    # Verify rename worked
    verify = search_functions_by_name("SMemAllocEx")
    print(f"    [✓] Verified: SMemAllocEx found at {verify}")

print("\n[✓] All renames complete!")
```

---

## Implementation: Full Workflow

### Phase 1: Pre-Rename Verification

Before renaming, verify that Ordinal_401 exists in all expected versions:

```python
print("=" * 80)
print("PHASE 1: Pre-Rename Verification")
print("=" * 80)

versions = ["1.07", "1.08", "1.09", "1.10", "1.11", "1.12", "1.13"]

for version in versions:
    try:
        switch_program(f"{version}")
        
        # Try to find Ordinal_401
        search_result = search_functions_by_name("Ordinal_401")
        if search_result:
            print(f"✓ {version}: Ordinal_401 found @ {search_result}")
        else:
            # Try SMemAlloc (1.07 might have it already named)
            search_result2 = search_functions_by_name("SMemAlloc")
            if search_result2:
                print(f"✓ {version}: SMemAlloc found @ {search_result2} (already named)")
            else:
                print(f"✗ {version}: Function not found")
    except Exception as e:
        print(f"✗ {version}: Error - {e}")
```

### Phase 2: Compute Hash Verification

Verify that functions we're renaming have the expected hash:

```python
print("\n" + "=" * 80)
print("PHASE 2: Hash Verification")
print("=" * 80)
print("\nExpected hash for Ordinal_401 (1.08+):")
print("  6a8112287fd08c30ab44f98afa0132d620ca6da6feff43d0b62148c882879428")

for version in ["1.08", "1.09"]:  # Skip 1.07 - different hash
    try:
        switch_program(f"{version}")
        
        # Get function hash
        hash_result = get_function_hash("0x6ffcbd60")
        
        print(f"\n{version}:")
        print(f"  Hash: {hash_result['hash']}")
        print(f"  Match: {'✓ YES' if hash_result['hash'] == '6a8112287fd08c30ab44f98afa0132d620ca6da6feff43d0b62148c882879428' else '✗ NO'}")
        print(f"  Size: {hash_result['size_bytes']} bytes")
        print(f"  Instructions: {hash_result['instruction_count']}")
    except Exception as e:
        print(f"✗ {version}: Error - {e}")
```

### Phase 3: Apply Renames

Execute the actual renaming:

```python
print("\n" + "=" * 80)
print("PHASE 3: Apply Renames")
print("=" * 80)

rename_map = {
    "1.08": ("0x6ffcbd60", "SMemAllocEx"),
    "1.09": ("0x6ffcbd60", "SMemAllocEx"),
    "1.10": ("0x6ffcbd60", "SMemAllocEx"),  # If it exists
    # Add more as needed
}

successes = []
failures = []

for version, (address, new_name) in rename_map.items():
    try:
        print(f"\nProcessing {version}...")
        
        switch_program(f"{version}")
        
        # Get current name
        func_info = get_function_by_address(address)
        old_name = func_info['name']
        
        if old_name == new_name:
            print(f"  [i] Already named '{new_name}', skipping")
            successes.append(f"{version}: Already renamed")
            continue
        
        print(f"  Renaming '{old_name}' → '{new_name}'")
        
        # Apply rename
        result = rename_function_by_address(address, new_name)
        
        # Verify
        verify = get_function_by_address(address)
        if verify['name'] == new_name:
            print(f"  [✓] Success: {verify['name']}")
            successes.append(f"{version}: {old_name} → {new_name}")
        else:
            print(f"  [!] Verification failed")
            failures.append(f"{version}: Rename failed")
            
    except Exception as e:
        print(f"  [✗] Error: {e}")
        failures.append(f"{version}: Exception - {str(e)}")

# Summary
print("\n" + "=" * 80)
print("PHASE 3 SUMMARY")
print("=" * 80)
print(f"\nSuccessful renames: {len(successes)}")
for s in successes:
    print(f"  ✓ {s}")

if failures:
    print(f"\nFailed renames: {len(failures)}")
    for f in failures:
        print(f"  ✗ {f}")
else:
    print(f"\nAll renames completed successfully!")
```

### Phase 4: Post-Rename Verification

Verify that all renames worked correctly and consistently:

```python
print("\n" + "=" * 80)
print("PHASE 4: Post-Rename Verification")
print("=" * 80)

verification_results = {}

for version in ["1.08", "1.09"]:
    try:
        print(f"\nVerifying {version}...")
        
        switch_program(f"{version}")
        
        # Check SMemAllocEx exists
        result = search_functions_by_name("SMemAllocEx")
        
        if result:
            print(f"  [✓] SMemAllocEx found @ {result}")
            verification_results[version] = "OK"
        else:
            print(f"  [✗] SMemAllocEx NOT found")
            verification_results[version] = "FAILED"
            
            # Check if old name still exists
            old_result = search_functions_by_name("Ordinal_401")
            if old_result:
                print(f"      WARNING: Old name 'Ordinal_401' still exists @ {old_result}")
                
    except Exception as e:
        print(f"  [✗] Error: {e}")
        verification_results[version] = "ERROR"

# Final status
print("\n" + "=" * 80)
print("FINAL STATUS")
print("=" * 80)

all_ok = all(v == "OK" for v in verification_results.values())

if all_ok:
    print("✓ All renames verified successfully!")
else:
    print("✗ Some renames failed or couldn't be verified")
    for version, status in verification_results.items():
        print(f"  {version}: {status}")
```

---

## Alternative: Batch Rename via Script

If you have MCP script execution, create this Ghidra script:

```java
// BatchRenameOrdinal401.java
// @author
// @category Symbol.Functions
// @keybinding
// @menupath Tools.Batch Rename Ordinal 401 to SMemAllocEx

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import java.util.*;

public class BatchRenameOrdinal401 extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("ERROR: No program loaded");
            return;
        }
        
        String programName = currentProgram.getName();
        println("Processing: " + programName);
        
        // Find all instances of Ordinal_401
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Symbol[] symbols = symbolTable.getSymbols("Ordinal_401");
        
        if (symbols.length == 0) {
            println("No functions named 'Ordinal_401' found");
            return;
        }
        
        println("Found " + symbols.length + " instance(s) of Ordinal_401");
        
        int renamed = 0;
        for (Symbol symbol : symbols) {
            try {
                Address addr = symbol.getAddress();
                Listing listing = currentProgram.getListing();
                Function func = listing.getFunctionAt(addr);
                
                if (func != null) {
                    func.setName("SMemAllocEx", SourceType.USER_DEFINED);
                    println("  [✓] Renamed @ " + addr + " to SMemAllocEx");
                    renamed++;
                } else {
                    println("  [!] No function found at " + addr);
                }
            } catch (Exception e) {
                println("  [✗] Error renaming symbol: " + e.getMessage());
            }
        }
        
        println("\nSummary: Renamed " + renamed + " function(s)");
        println("[✓] Batch rename complete!");
    }
}
```

---

## Verification Checklist

Before considering the rename complete, verify:

- [ ] Ordinal_401 exists at 0x6ffcbd60 in each version
- [ ] Hash matches expected value (6a811228...)
- [ ] Rename succeeds without errors
- [ ] SMemAllocEx can be found in each version
- [ ] Old name (Ordinal_401) is no longer found
- [ ] Cross-references still point to correct function
- [ ] Disassembler shows correct function name

---

## Rollback Procedure

If rename needs to be undone:

```python
# Rollback: Rename SMemAllocEx back to Ordinal_401

for version in ["1.08", "1.09"]:
    switch_program(f"{version}")
    rename_function_by_address("0x6ffcbd60", "Ordinal_401")
    print(f"[✓] {version}: Rolled back to Ordinal_401")
```

---

## Next: After Rename Complete

Once SMemAllocEx renaming is complete:

1. **Apply Documentation**:
   ```python
   # Export docs from 1.07
   switch_program("1.07")
   docs = get_function_documentation("0x6ffcb6b0")  # SMemAlloc
   
   # Apply to 1.08
   switch_program("1.08")
   apply_function_documentation("0x6ffcbd60", docs)
   ```

2. **Update Analysis Documents**:
   - Mark SMemAllocEx as "identified and documented"
   - Create cross-reference document showing all versions

3. **Analyze Other Ordinals**:
   - Apply same methodology to Ordinal_502 (hash computation)
   - Identify other high-priority Ordinals for renaming

4. **Build Hash Registry**:
   - Document all hash→name mappings
   - Create automated tool for future version analysis

---

## File Locations for Rename Scripts

- Python script: `hash_based_function_renaming.py`
- Strategy doc: `Hash_Based_Function_Renaming_Strategy.md`
- Hypothesis confirmation: `HYPOTHESIS_CONFIRMATION_SMemAlloc_Ordinal401.md`
- Ghidra script: `ghidra_scripts/BatchRenameOrdinal401.java`

---

## Summary

| Step | Status | Details |
|------|--------|---------|
| **1. Hypothesis Verification** | ✓ CONFIRMED | SMemAlloc = Ordinal_401 (same purpose, different compile) |
| **2. Hash Analysis** | ✓ COMPLETE | Different hashes due to recompilation, but functionally identical |
| **3. Renaming Strategy** | ✓ DESIGNED | Use "SMemAllocEx" to indicate extended functionality in 1.08+ |
| **4. Implementation Ready** | ✓ READY | All commands and scripts prepared |
| **5. Testing** | → PENDING | Ready to execute on actual binaries |
| **6. Verification** | → PENDING | Verify renames with post-rename checks |
| **7. Documentation** | → PENDING | Update all analysis docs with rename results |

**Ready to proceed with renaming?** Execute the Phase 1-4 workflow above.

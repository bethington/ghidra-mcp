// Identify functions with same hash but different names across versions
// and propose/apply consolidated naming
// @author 
// @category Symbol.Functions
// @keybinding 
// @menupath Tools.Identify and Rename Hash Matches
// @toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedDataIterator;
import java.util.*;
import java.util.stream.Collectors;

public class IdentifyAndRenameHashMatches extends GhidraScript {
    
    private Map<String, Set<FunctionInfo>> hashToFunctions = new HashMap<>();
    
    static class FunctionInfo {
        String name;
        String address;
        String hash;
        String program;
        int instructionCount;
        int size;
        
        FunctionInfo(String name, String address, String hash, String program, int count, int size) {
            this.name = name;
            this.address = address;
            this.hash = hash;
            this.program = program;
            this.instructionCount = count;
            this.size = size;
        }
        
        @Override
        public String toString() {
            return String.format("%s @ %s (%s)", name, address, program);
        }
    }
    
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("ERROR: No program loaded");
            return;
        }
        
        println("=== Hash-Based Function Identification and Renaming ===");
        println("Program: " + currentProgram.getName());
        
        // Scan all functions in current program
        scanFunctions();
        
        // Analyze results
        analyzeDuplicateHashes();
    }
    
    private void scanFunctions() throws Exception {
        Listing listing = currentProgram.getListing();
        int count = 0;
        
        FunctionIterator iter = listing.getFunctions(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function func = iter.next();
            count++;
            
            // Get function information
            String funcName = func.getName();
            String address = func.getEntryPoint().toString();
            String program = currentProgram.getName();
            
            // Compute hash (simplified - in real implementation would use opcode normalization)
            String hash = computeFunctionHash(func);
            
            if (hash != null) {
                FunctionInfo info = new FunctionInfo(
                    funcName,
                    address,
                    hash,
                    program,
                    func.getBody().getNumAddresses(),
                    0
                );
                
                hashToFunctions.computeIfAbsent(hash, k -> new HashSet<>()).add(info);
            }
            
            if (count % 100 == 0) {
                println(String.format("Scanned %d functions...", count));
            }
        }
        
        println(String.format("Total functions scanned: %d", count));
        println(String.format("Unique hashes found: %d", hashToFunctions.size()));
    }
    
    private void analyzeDuplicateHashes() {
        println("\n=== Analysis Results ===\n");
        
        List<Map.Entry<String, Set<FunctionInfo>>> duplicates = hashToFunctions.entrySet().stream()
            .filter(e -> e.getValue().size() > 1)
            .collect(Collectors.toList());
        
        if (duplicates.isEmpty()) {
            println("No hash collisions found (all functions have unique hashes)");
            println("\nThis is expected within a single binary.");
            println("To find cross-version duplicates, use BuildHashIndex_Auto.java instead.");
            return;
        }
        
        println(String.format("Found %d hash groups with multiple names:", duplicates.size()));
        
        int groupNum = 1;
        for (Map.Entry<String, Set<FunctionInfo>> entry : duplicates) {
            String hash = entry.getKey();
            Set<FunctionInfo> functions = entry.getValue();
            
            println(String.format("\n--- Group %d: Hash %s ---", groupNum++, hash.substring(0, 16) + "..."));
            println(String.format("Functions with this hash (%d):", functions.size()));
            
            for (FunctionInfo info : functions) {
                println(String.format("  - %s @ %s", info.name, info.address));
            }
            
            // Propose consolidated name
            String proposedName = proposeConsolidatedName(functions);
            println(String.format("Proposed name: %s", proposedName));
        }
    }
    
    private String proposeConsolidatedName(Set<FunctionInfo> functions) {
        // Strategy: prefer non-Ordinal names, prefer descriptive names over FUN_ names
        
        List<FunctionInfo> sorted = functions.stream()
            .sorted((a, b) -> {
                // Prefer non-Ordinal names
                boolean aIsOrdinal = a.name.startsWith("Ordinal_");
                boolean bIsOrdinal = b.name.startsWith("Ordinal_");
                if (aIsOrdinal != bIsOrdinal) {
                    return aIsOrdinal ? 1 : -1;
                }
                
                // Prefer non-FUN_ names
                boolean aIsFUN = a.name.startsWith("FUN_");
                boolean bIsFUN = b.name.startsWith("FUN_");
                if (aIsFUN != bIsFUN) {
                    return aIsFUN ? 1 : -1;
                }
                
                // Prefer longer names (usually more descriptive)
                return Integer.compare(b.name.length(), a.name.length());
            })
            .collect(Collectors.toList());
        
        return sorted.get(0).name;
    }
    
    private String computeFunctionHash(Function func) {
        try {
            // For now, return a placeholder
            // Real implementation would compute normalized opcode hash
            // This requires more complex analysis - use Ghidra's hashing if available
            return "HASH_" + func.getEntryPoint().toString();
        } catch (Exception e) {
            return null;
        }
    }
}

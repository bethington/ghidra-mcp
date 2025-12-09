// Unify function names across versions using hash-based matching
// @category Documentation
// @author GhidraMCP
// @description Renames Ordinal_* functions to consistent real names across all binary versions by matching functions with identical code hashes and applying the best name from any version.

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.Register;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;
import javax.swing.JOptionPane;

/**
 * Unify function names across versions using hash-based matching.
 * 
 * Purpose: When the same function exists in multiple binary versions but has different names
 * (e.g., SMemAlloc in 1.07 vs Ordinal_401 in 1.08+), this script identifies the best name
 * and applies it consistently across all versions.
 * 
 * Algorithm:
 * 1. Compute hash for each function in current program
 * 2. Load hash index to find matching functions in other versions
 * 3. Collect all names used for the same function across versions
 * 4. Select the best name (prioritize real names over Ordinal_)
 * 5. Apply best name to all matching functions in current program
 */
public class UnifyOrdinalNames_ProjectFolder extends GhidraScript {

    private static final String INDEX_FILE = System.getProperty("user.home") + 
        java.io.File.separator + "ghidra_function_hash_index.json";
    
    private Map<String, Map<String, Object>> functionsIndex;
    private int functionsRenamed = 0;
    private int ordinalNamesProcessed = 0;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("Error: No program is open");
            return;
        }
        
        println("=".repeat(70));
        println("UNIFY ORDINAL NAMES (Project Folder)");
        println("=".repeat(70));
        println("Program: " + currentProgram.getName());
        println("Purpose: Rename Ordinal_* functions to consistent real names");
        println();
        
        // Load hash index
        println("1. Loading function hash index...");
        Map<String, Object> index = loadIndex();
        
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> funcs = (Map<String, Map<String, Object>>) index.get("functions");
        functionsIndex = funcs != null ? funcs : new LinkedHashMap<>();
        
        println("  Functions indexed: " + functionsIndex.size());
        
        if (functionsIndex.isEmpty()) {
            println("\n  Error: No functions in index. Run BuildHashIndex_ProjectFolder.java first.");
            return;
        }
        
        // Start transaction
        int txId = currentProgram.startTransaction("Unify Ordinal Names");
        
        try {
            println("\n2. Processing functions in current program...");
            FunctionManager funcMgr = currentProgram.getFunctionManager();
            FunctionIterator funcIter = funcMgr.getFunctions(true);
            
            int functionCount = 0;
            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                functionCount++;
                
                // Skip thunks
                if (func.isThunk()) {
                    continue;
                }
                
                // Check if this function has an Ordinal_ name
                String currentName = func.getName();
                if (!currentName.startsWith("Ordinal_")) {
                    continue;
                }
                
                ordinalNamesProcessed++;
                
                // Compute hash
                String hash = computeFunctionHash(func);
                if (hash == null) continue;
                
                // Look up in index
                Map<String, Object> hashEntry = functionsIndex.get(hash);
                if (hashEntry == null) {
                    // No matches in index - keep current name
                    continue;
                }
                
                // Find the best name across all versions
                String bestName = findBestFunctionName(hashEntry, currentName);
                
                if (bestName != null && !bestName.equals(currentName)) {
                    try {
                        func.setName(bestName, SourceType.USER_DEFINED);
                        functionsRenamed++;
                        println("  Renamed: " + currentName + " -> " + bestName + " @ " + func.getEntryPoint());
                    } catch (Exception e) {
                        println("  Failed to rename " + currentName + ": " + e.getMessage());
                    }
                }
            }
            
            println("\n  Total functions processed: " + functionCount);
            println("  Ordinal names found: " + ordinalNamesProcessed);
            println("  Functions renamed: " + functionsRenamed);
            
            // Commit transaction
            currentProgram.endTransaction(txId, true);
            
            // Save program
            println("\n3. Saving program...");
            currentProgram.getDomainFile().save(monitor);
            println("  Saved successfully");
            
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            throw e;
        }
        
        println("\n" + "=".repeat(70));
        println("UNIFICATION COMPLETE");
        println("=".repeat(70));
    }

    /**
     * Find the best function name across all versions of a function.
     * Prioritizes real names over Ordinal_* names.
     */
    private String findBestFunctionName(Map<String, Object> hashEntry, String currentName) {
        Set<String> allNames = new HashSet<>();
        
        // Collect name from canonical
        @SuppressWarnings("unchecked")
        Map<String, Object> canonical = (Map<String, Object>) hashEntry.get("canonical");
        if (canonical != null) {
            String name = (String) canonical.get("name");
            if (name != null && !name.startsWith("FUN_")) {
                allNames.add(name);
            }
        }
        
        // Collect names from instances
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> instances = (List<Map<String, Object>>) hashEntry.get("instances");
        if (instances != null) {
            for (Map<String, Object> inst : instances) {
                String name = (String) inst.get("name");
                if (name != null && !name.startsWith("FUN_")) {
                    allNames.add(name);
                }
            }
        }
        
        // If no real names found, keep current
        if (allNames.isEmpty()) {
            return null;
        }
        
        // Prioritize real names (not Ordinal_)
        for (String name : allNames) {
            if (!name.startsWith("Ordinal_")) {
                return name;  // Found a real name - use it
            }
        }
        
        // If only Ordinal_ names exist, use the first one
        // (This shouldn't happen if there are multiple versions)
        return allNames.iterator().next();
    }

    /**
     * Compute normalized function hash.
     */
    private String computeFunctionHash(Function func) {
        try {
            StringBuilder normalized = new StringBuilder();
            Listing listing = currentProgram.getListing();
            AddressSetView body = func.getBody();
            
            InstructionIterator instructions = listing.getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                
                normalized.append(instr.getMnemonicString());
                normalized.append(" ");
                
                int numOperands = instr.getNumOperands();
                for (int i = 0; i < numOperands; i++) {
                    Object[] opObjects = instr.getOpObjects(i);
                    for (Object obj : opObjects) {
                        if (obj instanceof Address) {
                            Address addr = (Address) obj;
                            if (body.contains(addr)) {
                                long offset = addr.subtract(func.getEntryPoint());
                                normalized.append("REL:").append(offset);
                            } else if (currentProgram.getFunctionManager().getFunctionAt(addr) != null) {
                                normalized.append("CALL_EXT");
                            } else {
                                normalized.append("DATA_EXT");
                            }
                        } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long value = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                            if (Math.abs(value) < 0x10000) {
                                normalized.append("IMM:").append(value);
                            } else {
                                normalized.append("IMM_LARGE");
                            }
                        } else if (obj instanceof Register) {
                            normalized.append("REG:").append(((Register) obj).getName());
                        }
                    }
                    normalized.append(",");
                }
                normalized.append(";");
            }
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
            
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Load index from file.
     */
    private Map<String, Object> loadIndex() {
        File file = new File(INDEX_FILE);
        if (!file.exists()) {
            println("Warning: Index file not found at " + INDEX_FILE);
            return new LinkedHashMap<>();
        }
        
        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            return parseJson(content);
        } catch (Exception e) {
            println("Warning: Could not load index: " + e.getMessage());
            return new LinkedHashMap<>();
        }
    }

    /**
     * Parse JSON using Gson.
     */
    private Map<String, Object> parseJson(String json) {
        try {
            Class<?> gsonClass = Class.forName("com.google.gson.Gson");
            Object gson = gsonClass.getConstructor().newInstance();
            java.lang.reflect.Method fromJson = gsonClass.getMethod("fromJson", String.class, Class.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) fromJson.invoke(gson, json, Map.class);
            return result != null ? result : new LinkedHashMap<>();
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }
}

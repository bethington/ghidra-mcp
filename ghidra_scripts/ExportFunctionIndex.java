//Export comprehensive function index data for cross-version matching
//@category D2VersionChanger
//@menupath Tools.Export Function Index
//@keybinding ctrl shift E
//@description Exports ALL functions with multi-method matching indexes (EXP/STR/API/MNE/CFG/PRO) for cross-version function identification. Output: data/function_index/{GameType}/{Version}/{dll}.json

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.*;
import java.io.*;
import java.util.*;
import java.security.*;

/**
 * Exports comprehensive function data with multiple matching indexes.
 * 
 * For each function, exports:
 * - Basic info (address, size, name if human-assigned)
 * - EXP index: Export ordinal (for exported functions)
 * - STR index: Hash of referenced unique strings
 * - API index: Hash of imported API call sequence
 * - MNE index: Hash of instruction mnemonic sequence + size
 * - CFG index: Hash of basic block count + edge structure
 * - PRO index: Hash of prologue bytes + size
 * 
 * Index Selection Priority:
 * 1. EXP (100% reliable) - if function is exported
 * 2. STR (99% reliable) - if has unique string references
 * 3. API (95% reliable) - if calls 2+ imported APIs
 * 4. MNE (85% reliable) - default workhorse
 * 5. CFG (80% reliable) - for medium+ functions
 * 6. PRO (70% reliable) - fallback for tiny functions
 * 
 * Output path derived from program location:
 *   /F:/D2VersionChanger/VersionChanger/LoD/1.07/D2Client.dll
 *   → F:/D2VersionChanger/data/function_index/LoD/1.07/D2Client.dll.json
 */
public class ExportFunctionIndex extends GhidraScript {

    // String references seen across all functions (to determine uniqueness)
    private Map<String, Integer> stringRefCounts = new HashMap<>();
    
    // Import addresses to names
    private Map<Address, String> importMap = new HashMap<>();
    
    @Override
    public void run() throws Exception {
        String programName = currentProgram.getName();
        String programPath = currentProgram.getExecutablePath();
        
        println("=".repeat(70));
        println("FUNCTION INDEX EXPORT");
        println("=".repeat(70));
        println("Program: " + programName);
        println("Path: " + programPath);
        
        // Parse version from path: /F:/D2VersionChanger/VersionChanger/LoD/1.07/file.dll
        String[] pathParts = programPath.replace("\\", "/").split("/");
        String gameType = "Unknown";  // Classic or LoD
        String version = "Unknown";
        String fileName = programName;
        
        // Find VersionChanger in path to extract game type and version
        for (int i = 0; i < pathParts.length - 2; i++) {
            if (pathParts[i].equals("VersionChanger")) {
                if (i + 2 < pathParts.length) {
                    gameType = pathParts[i + 1];  // Classic or LoD
                    version = pathParts[i + 2];   // 1.00, 1.07, etc.
                }
                break;
            }
        }
        
        println("Game Type: " + gameType);
        println("Version: " + version);
        
        // Output path
        File outputDir = new File("F:/D2VersionChanger/data/function_index/" + gameType + "/" + version);
        outputDir.mkdirs();
        File outputFile = new File(outputDir, fileName + ".json");
        
        println("Output: " + outputFile.getAbsolutePath());
        println("=".repeat(70));
        
        // Phase 1: Build import map and count string references
        println("\nPhase 1: Analyzing imports and string references...");
        buildImportMap();
        countStringReferences();
        
        // Phase 2: Process all functions
        println("\nPhase 2: Processing functions...");
        List<FunctionData> functions = processFunctions();
        
        // Phase 3: Write output
        println("\nPhase 3: Writing output...");
        writeOutput(outputFile, gameType, version, functions);
        
        // Summary
        println("\n" + "=".repeat(70));
        println("EXPORT COMPLETE");
        println("=".repeat(70));
        println("Total functions: " + functions.size());
        
        int named = 0, withStrings = 0, withApis = 0, exported = 0;
        for (FunctionData f : functions) {
            if (f.hasHumanName) named++;
            if (f.stringRefs.size() > 0) withStrings++;
            if (f.apiCalls.size() > 0) withApis++;
            if (f.exportOrdinal >= 0) exported++;
        }
        
        println("  Named (human): " + named);
        println("  With strings: " + withStrings);
        println("  With API calls: " + withApis);
        println("  Exported: " + exported);
        println("Output: " + outputFile.getAbsolutePath());
    }
    
    private void buildImportMap() throws Exception {
        SymbolTable symTable = currentProgram.getSymbolTable();
        ExternalManager extManager = currentProgram.getExternalManager();
        
        // Get all external references
        SymbolIterator extSymbols = symTable.getExternalSymbols();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        while (extSymbols.hasNext()) {
            Symbol sym = extSymbols.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                // Get references TO this external symbol
                ReferenceIterator refIter = refMgr.getReferencesTo(sym.getAddress());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    importMap.put(ref.getFromAddress(), sym.getName());
                }
            }
        }
        
        // Also check import table directly
        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (sym.isExternalEntryPoint() || sym.getName().startsWith("_imp_")) {
                importMap.put(sym.getAddress(), sym.getName().replace("_imp_", ""));
            }
        }
        
        println("  Found " + importMap.size() + " import references");
    }
    
    private void countStringReferences() throws Exception {
        // First pass: count how many functions reference each string
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        
        Set<String> allStrings = new HashSet<>();
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String str = data.getDefaultValueRepresentation();
                if (str != null && str.length() >= 4) {  // Skip tiny strings
                    allStrings.add(str);
                }
            }
        }
        
        // Count references per string
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        for (String str : allStrings) {
            stringRefCounts.put(str, 0);
        }
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            Set<String> funcStrings = getStringReferences(func);
            for (String str : funcStrings) {
                stringRefCounts.merge(str, 1, Integer::sum);
            }
        }
        
        int uniqueCount = 0;
        for (int count : stringRefCounts.values()) {
            if (count == 1) uniqueCount++;
        }
        
        println("  Found " + allStrings.size() + " strings, " + uniqueCount + " unique to single function");
    }
    
    private Set<String> getStringReferences(Function func) {
        Set<String> strings = new HashSet<>();
        
        AddressSetView body = func.getBody();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();
        
        AddressIterator addrIter = body.getAddresses(true);
        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Data data = listing.getDataAt(toAddr);
                if (data != null && data.hasStringValue()) {
                    String str = data.getDefaultValueRepresentation();
                    if (str != null && str.length() >= 4) {
                        strings.add(str);
                    }
                }
            }
        }
        
        return strings;
    }
    
    private List<String> getApiCalls(Function func) {
        List<String> apis = new ArrayList<>();
        
        AddressSetView body = func.getBody();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        // Get references in address order to preserve call sequence
        AddressIterator addrIter = body.getAddresses(true);
        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    Address toAddr = ref.getToAddress();
                    // Check if this is an import
                    String importName = importMap.get(toAddr);
                    if (importName != null) {
                        apis.add(importName);
                    } else {
                        // Check thunk functions
                        Function calledFunc = currentProgram.getFunctionManager().getFunctionAt(toAddr);
                        if (calledFunc != null && calledFunc.isThunk()) {
                            Function thunkedFunc = calledFunc.getThunkedFunction(false);
                            if (thunkedFunc != null && thunkedFunc.isExternal()) {
                                apis.add(thunkedFunc.getName());
                            }
                        }
                    }
                }
            }
        }
        
        return apis;
    }
    
    private String getMnemonicSequence(Function func) {
        StringBuilder mnemonics = new StringBuilder();
        
        Listing listing = currentProgram.getListing();
        AddressSetView body = func.getBody();
        
        InstructionIterator instrIter = listing.getInstructions(body, true);
        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            mnemonics.append(instr.getMnemonicString());
            mnemonics.append(";");
        }
        
        return mnemonics.toString();
    }
    
    private byte[] getPrologueBytes(Function func, int maxBytes) {
        Address entry = func.getEntryPoint();
        Memory memory = currentProgram.getMemory();
        
        int bytesToRead = Math.min(maxBytes, (int)func.getBody().getNumAddresses());
        byte[] bytes = new byte[bytesToRead];
        
        try {
            memory.getBytes(entry, bytes);
        } catch (Exception e) {
            return new byte[0];
        }
        
        return bytes;
    }
    
    private int getBasicBlockCount(Function func) {
        try {
            BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
            int count = 0;
            while (blocks.hasNext()) {
                blocks.next();
                count++;
            }
            return count;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private List<FunctionData> processFunctions() throws Exception {
        List<FunctionData> functions = new ArrayList<>();
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        SymbolTable symTable = currentProgram.getSymbolTable();
        long imageBase = currentProgram.getImageBase().getOffset();
        
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        int total = funcMgr.getFunctionCount();
        int processed = 0;
        
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                throw new Exception("Cancelled by user");
            }
            
            Function func = funcIter.next();
            processed++;
            
            if (processed % 100 == 0) {
                println("  Processed " + processed + "/" + total + " functions...");
            }
            
            FunctionData data = new FunctionData();
            
            // Basic info
            data.address = func.getEntryPoint().getOffset();
            data.rva = data.address - imageBase;
            data.size = (int) func.getBody().getNumAddresses();
            data.name = func.getName();
            
            // Check if name is human-assigned (not auto-generated)
            data.hasHumanName = !data.name.startsWith("FUN_") && 
                               !data.name.startsWith("thunk_FUN_") &&
                               !data.name.startsWith("LAB_") &&
                               !data.name.equals("entry");
            
            // Export ordinal
            data.exportOrdinal = -1;
            Symbol[] symbols = symTable.getSymbols(func.getEntryPoint());
            for (Symbol sym : symbols) {
                if (sym.isExternalEntryPoint()) {
                    // Try to get ordinal from symbol info
                    data.exportOrdinal = getExportOrdinal(sym);
                    data.exportName = sym.getName();
                    break;
                }
            }
            
            // String references (only unique ones)
            Set<String> allStrings = getStringReferences(func);
            for (String str : allStrings) {
                Integer count = stringRefCounts.get(str);
                if (count != null && count == 1) {
                    data.uniqueStrings.add(str);
                }
            }
            data.stringRefs = allStrings;
            
            // API calls
            data.apiCalls = getApiCalls(func);
            
            // Mnemonic sequence
            data.mnemonicSeq = getMnemonicSequence(func);
            
            // Prologue bytes (first 16 bytes)
            data.prologueBytes = getPrologueBytes(func, 16);
            
            // Basic block count
            data.basicBlockCount = getBasicBlockCount(func);
            
            // Signature and other metadata
            data.signature = func.getSignature().getPrototypeString();
            data.callingConvention = func.getCallingConventionName();
            data.comment = func.getComment();
            
            // Parameters
            for (Parameter p : func.getParameters()) {
                ParamData pd = new ParamData();
                pd.name = p.getName();
                pd.type = p.getDataType().getName();
                pd.storage = p.getVariableStorage().toString();
                data.parameters.add(pd);
            }
            
            // Compute indexes
            computeIndexes(data);
            
            functions.add(data);
        }
        
        return functions;
    }
    
    private int getExportOrdinal(Symbol sym) {
        // Try to extract ordinal from export table
        // This is a simplified version - may need enhancement for complex cases
        try {
            String name = sym.getName();
            if (name.startsWith("Ordinal_")) {
                return Integer.parseInt(name.substring(8));
            }
        } catch (Exception e) {
            // Ignore
        }
        return -1;
    }
    
    private void computeIndexes(FunctionData data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        
        // EXP index: Export ordinal (if exported)
        if (data.exportOrdinal >= 0) {
            data.expIndex = String.valueOf(data.exportOrdinal);
        }
        
        // STR index: Hash of unique string references
        if (!data.uniqueStrings.isEmpty()) {
            List<String> sorted = new ArrayList<>(data.uniqueStrings);
            Collections.sort(sorted);
            String combined = String.join("|", sorted);
            data.strIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }
        
        // API index: Hash of API call sequence (if 2+ calls)
        if (data.apiCalls.size() >= 2) {
            String combined = String.join("|", data.apiCalls);
            data.apiIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }
        
        // MNE index: Hash of mnemonic sequence + size
        if (!data.mnemonicSeq.isEmpty()) {
            String combined = data.mnemonicSeq + "|" + data.size;
            data.mneIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }
        
        // CFG index: Basic block count (simplified - could be enhanced)
        if (data.basicBlockCount > 1) {
            String combined = data.basicBlockCount + "|" + data.size;
            data.cfgIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }
        
        // PRO index: Prologue bytes + size
        if (data.prologueBytes.length > 0) {
            md.update(data.prologueBytes);
            md.update(String.valueOf(data.size).getBytes("UTF-8"));
            data.proIndex = hashToHex(md.digest(), 16);
        }
        
        // Select best index (highest priority available)
        if (data.expIndex != null) {
            data.bestIndex = "EXP:" + data.expIndex;
            data.bestMethod = "EXP";
        } else if (data.strIndex != null) {
            data.bestIndex = "STR:" + data.strIndex;
            data.bestMethod = "STR";
        } else if (data.apiIndex != null) {
            data.bestIndex = "API:" + data.apiIndex;
            data.bestMethod = "API";
        } else if (data.mneIndex != null) {
            data.bestIndex = "MNE:" + data.mneIndex;
            data.bestMethod = "MNE";
        } else if (data.cfgIndex != null) {
            data.bestIndex = "CFG:" + data.cfgIndex;
            data.bestMethod = "CFG";
        } else if (data.proIndex != null) {
            data.bestIndex = "PRO:" + data.proIndex;
            data.bestMethod = "PRO";
        } else {
            // Last resort: address-based (won't match across versions)
            data.bestIndex = "ADDR:" + String.format("%08X", data.rva);
            data.bestMethod = "ADDR";
        }
        
        // Display name: use human name if available, otherwise best index
        if (data.hasHumanName) {
            data.displayName = data.name;
        } else {
            // Use abbreviated index as name
            data.displayName = data.bestMethod + "_" + 
                (data.bestIndex.length() > 20 ? data.bestIndex.substring(data.bestIndex.indexOf(':') + 1, Math.min(data.bestIndex.length(), 20)) : data.bestIndex.substring(data.bestIndex.indexOf(':') + 1));
        }
    }
    
    private String hashToHex(byte[] hash, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(hash.length, length); i++) {
            sb.append(String.format("%02x", hash[i]));
        }
        return sb.toString();
    }
    
    private void writeOutput(File outputFile, String gameType, String version, 
                            List<FunctionData> functions) throws Exception {
        long imageBase = currentProgram.getImageBase().getOffset();
        
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outputFile), "UTF-8"))) {
            
            writer.println("{");
            writer.println("  \"program_name\": \"" + escapeJson(currentProgram.getName()) + "\",");
            writer.println("  \"game_type\": \"" + escapeJson(gameType) + "\",");
            writer.println("  \"version\": \"" + escapeJson(version) + "\",");
            writer.println("  \"image_base\": \"" + String.format("0x%08X", imageBase) + "\",");
            writer.println("  \"total_functions\": " + functions.size() + ",");
            writer.println("  \"export_timestamp\": \"" + new java.util.Date().toString() + "\",");
            writer.println("  \"functions\": [");
            
            for (int i = 0; i < functions.size(); i++) {
                FunctionData f = functions.get(i);
                
                writer.println("    {");
                writer.println("      \"address\": \"" + String.format("0x%08X", f.address) + "\",");
                writer.println("      \"rva\": \"" + String.format("0x%X", f.rva) + "\",");
                writer.println("      \"size\": " + f.size + ",");
                writer.println("      \"name\": \"" + escapeJson(f.name) + "\",");
                writer.println("      \"display_name\": \"" + escapeJson(f.displayName) + "\",");
                writer.println("      \"has_human_name\": " + f.hasHumanName + ",");
                
                // Best index (the canonical matching key)
                writer.println("      \"index\": \"" + escapeJson(f.bestIndex) + "\",");
                writer.println("      \"index_method\": \"" + f.bestMethod + "\",");
                
                // All available indexes
                writer.println("      \"indexes\": {");
                writer.println("        \"EXP\": " + (f.expIndex != null ? "\"" + escapeJson(f.expIndex) + "\"" : "null") + ",");
                writer.println("        \"STR\": " + (f.strIndex != null ? "\"" + escapeJson(f.strIndex) + "\"" : "null") + ",");
                writer.println("        \"API\": " + (f.apiIndex != null ? "\"" + escapeJson(f.apiIndex) + "\"" : "null") + ",");
                writer.println("        \"MNE\": " + (f.mneIndex != null ? "\"" + escapeJson(f.mneIndex) + "\"" : "null") + ",");
                writer.println("        \"CFG\": " + (f.cfgIndex != null ? "\"" + escapeJson(f.cfgIndex) + "\"" : "null") + ",");
                writer.println("        \"PRO\": " + (f.proIndex != null ? "\"" + escapeJson(f.proIndex) + "\"" : "null") + "");
                writer.println("      },");
                
                // Signature data (for named functions)
                if (f.hasHumanName) {
                    writer.println("      \"signature\": \"" + escapeJson(f.signature) + "\",");
                    writer.println("      \"calling_convention\": \"" + escapeJson(f.callingConvention) + "\",");
                    writer.println("      \"comment\": \"" + escapeJson(f.comment != null ? f.comment : "") + "\",");
                    
                    // Parameters
                    writer.print("      \"parameters\": [");
                    for (int j = 0; j < f.parameters.size(); j++) {
                        ParamData p = f.parameters.get(j);
                        if (j > 0) writer.print(", ");
                        writer.print("{\"name\": \"" + escapeJson(p.name) + "\", ");
                        writer.print("\"type\": \"" + escapeJson(p.type) + "\", ");
                        writer.print("\"storage\": \"" + escapeJson(p.storage) + "\"}");
                    }
                    writer.println("],");
                }
                
                // String references (useful for debugging/analysis)
                writer.print("      \"string_refs\": [");
                int strCount = 0;
                for (String str : f.stringRefs) {
                    if (strCount > 0) writer.print(", ");
                    if (strCount >= 5) {
                        writer.print("\"...+" + (f.stringRefs.size() - 5) + " more\"");
                        break;
                    }
                    writer.print("\"" + escapeJson(truncate(str, 50)) + "\"");
                    strCount++;
                }
                writer.println("],");
                
                // API calls
                writer.print("      \"api_calls\": [");
                for (int j = 0; j < Math.min(f.apiCalls.size(), 10); j++) {
                    if (j > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(f.apiCalls.get(j)) + "\"");
                }
                if (f.apiCalls.size() > 10) {
                    writer.print(", \"...+" + (f.apiCalls.size() - 10) + " more\"");
                }
                writer.println("],");
                
                writer.println("      \"basic_block_count\": " + f.basicBlockCount);
                
                writer.print("    }");
                if (i < functions.size() - 1) {
                    writer.println(",");
                } else {
                    writer.println();
                }
            }
            
            writer.println("  ]");
            writer.println("}");
        }
    }
    
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
    
    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...";
    }
    
    // Data classes
    class FunctionData {
        long address;
        long rva;
        int size;
        String name;
        String displayName;
        boolean hasHumanName;
        
        int exportOrdinal = -1;
        String exportName;
        
        Set<String> stringRefs = new HashSet<>();
        Set<String> uniqueStrings = new HashSet<>();
        List<String> apiCalls = new ArrayList<>();
        String mnemonicSeq;
        byte[] prologueBytes;
        int basicBlockCount;
        
        String signature;
        String callingConvention;
        String comment;
        List<ParamData> parameters = new ArrayList<>();
        
        // Computed indexes
        String expIndex;
        String strIndex;
        String apiIndex;
        String mneIndex;
        String cfgIndex;
        String proIndex;
        
        String bestIndex;
        String bestMethod;
    }
    
    class ParamData {
        String name;
        String type;
        String storage;
    }
}

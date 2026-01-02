//[STEP 1] Build function hash index with multi-phase matching support.
//This version adds secondary matching signals (callees, strings, signature)
//for functions that don't match by hash alone.
//The index is saved to: ~/ghidra_function_hash_index_v2.json
//@author GhidraMCP
//@category Documentation
//@keybinding
//@menupath D2.1a - Build Hash Index V2 (Multi-Phase)
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.data.*;
import ghidra.framework.model.*;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

/**
 * BuildHashIndex_V2 - Multi-phase function matching with confidence scoring.
 *
 * Improvements over V1:
 * - Stores multiple matching signals per function (hash, callees, strings, signature)
 * - Confidence scoring for match quality
 * - Minimum thresholds to reduce false positives
 * - Separate handling for documented vs undocumented functions
 *
 * Matching Phases:
 * 1. Strict hash (96% of matches)
 * 2. Signature + Callees (for hash mismatches)
 * 3. Signature + Strings (fallback)
 *
 * Confidence Scoring:
 * - Hash match: 100 points (definitive)
 * - Signature match: 20 points
 * - 3+ callee matches: 40 points
 * - 2+ string matches: 30 points
 * - Size within 10%: 10 points
 *
 * Thresholds:
 * - >= 100: Auto-propagate
 * - >= 60: Propagate with caution (documented) / Suggest (undocumented)
 * - >= 40: Suggest only
 * - < 40: Do not match
 */
public class BuildHashIndex_V2 extends GhidraScript {

    private static final String INDEX_FILE = System.getProperty("user.home") +
        File.separator + "ghidra_function_hash_index_v2.json";

    // Minimum thresholds to reduce false positives
    private static final int MIN_INSTRUCTION_COUNT = 10;  // Skip tiny functions
    private static final int MIN_CALLEES_FOR_SIGNAL = 3;  // Need 3+ callees to be meaningful
    private static final int MIN_STRINGS_FOR_SIGNAL = 2;  // Need 2+ strings to be meaningful

    // Statistics
    private int programsProcessed = 0;
    private int functionsProcessed = 0;
    private int functionsSkipped = 0;
    private int hashesComputed = 0;

    // Data type collection
    private Set<String> serializedDataTypes = new HashSet<>();
    private Map<String, Map<String, Object>> dataTypesMap = new LinkedHashMap<>();

    // Current program being processed
    private Program processingProgram;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open!");
            return;
        }

        DomainFile currentFile = currentProgram.getDomainFile();
        DomainFolder parentFolder = currentFile.getParent();

        println("=".repeat(70));
        println("BUILD FUNCTION HASH INDEX V2 (Multi-Phase Matching)");
        println("=".repeat(70));
        println("Project folder: " + parentFolder.getPathname());
        println("Index file: " + INDEX_FILE);
        println("");
        println("Matching signals collected:");
        println("  - Strict opcode hash (primary)");
        println("  - Function signature (return type, params, calling convention)");
        println("  - Callee function names (named functions called)");
        println("  - String references (string constants used)");
        println("  - Size metrics (instruction count, byte size)");
        println("");

        // Ask about merge mode
        boolean mergeMode = askMergeMode();
        if (mergeMode == false && !confirmFreshStart()) {
            println("Cancelled by user.");
            return;
        }

        // Get all programs
        List<DomainFile> programFiles = new ArrayList<>();
        for (DomainFile file : parentFolder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                programFiles.add(file);
            }
        }

        println("Found " + programFiles.size() + " programs");
        println("");

        if (programFiles.isEmpty()) {
            printerr("No programs found!");
            return;
        }

        // Load or create index
        Map<String, Object> index = mergeMode ? loadIndex() : new LinkedHashMap<>();

        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> functionsByHash = (Map<String, Map<String, Object>>)
            index.computeIfAbsent("functions_by_hash", k -> new LinkedHashMap<>());

        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> functionsByCallees = (Map<String, Map<String, Object>>)
            index.computeIfAbsent("functions_by_callees", k -> new LinkedHashMap<>());

        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> functionsBySignature = (Map<String, Map<String, Object>>)
            index.computeIfAbsent("functions_by_signature", k -> new LinkedHashMap<>());

        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> allFunctions = (Map<String, Map<String, Object>>)
            index.computeIfAbsent("all_functions", k -> new LinkedHashMap<>());

        if (!mergeMode) {
            functionsByHash.clear();
            functionsByCallees.clear();
            functionsBySignature.clear();
            allFunctions.clear();
            dataTypesMap.clear();
        } else {
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Object>> existingTypes = (Map<String, Map<String, Object>>)
                index.getOrDefault("data_types", new LinkedHashMap<>());
            dataTypesMap.putAll(existingTypes);
            serializedDataTypes.addAll(existingTypes.keySet());
        }

        println("Starting index build...");
        println("-".repeat(70));

        // Process each program
        for (DomainFile file : programFiles) {
            if (monitor.isCancelled()) break;
            processProgram(file, functionsByHash, functionsByCallees, functionsBySignature, allFunctions);
        }

        // Update metadata
        index.put("version", "2.0");
        index.put("last_updated", Instant.now().toString());
        index.put("total_functions", allFunctions.size());
        index.put("unique_hashes", functionsByHash.size());
        index.put("unique_callee_signatures", functionsByCallees.size());
        index.put("unique_signatures", functionsBySignature.size());
        index.put("data_types", dataTypesMap);

        // Add matching configuration
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("min_instruction_count", MIN_INSTRUCTION_COUNT);
        config.put("min_callees_for_signal", MIN_CALLEES_FOR_SIGNAL);
        config.put("min_strings_for_signal", MIN_STRINGS_FOR_SIGNAL);
        config.put("confidence_thresholds", Map.of(
            "auto_propagate", 100,
            "propagate_documented", 60,
            "suggest_only", 40
        ));
        index.put("config", config);

        // Save index
        println("");
        println("Saving index...");
        saveIndex(index);

        // Summary
        println("");
        println("=".repeat(70));
        println("SUMMARY");
        println("=".repeat(70));
        println("Programs processed: " + programsProcessed);
        println("Functions processed: " + functionsProcessed);
        println("Functions skipped (too small): " + functionsSkipped);
        println("Unique hashes: " + functionsByHash.size());
        println("Unique callee signatures: " + functionsByCallees.size());
        println("Unique type signatures: " + functionsBySignature.size());
        println("Total function entries: " + allFunctions.size());
        println("");
        println("Index saved to: " + INDEX_FILE);
    }

    private boolean askMergeMode() {
        File indexFile = new File(INDEX_FILE);
        if (!indexFile.exists()) {
            println("No existing index found - starting fresh.");
            return false;
        }

        // For scripted execution, default to merge mode
        // To force fresh start, delete the index file first
        println("Existing index found - merging with existing data.");
        println("(Delete " + INDEX_FILE + " first if you want a fresh start)");
        return true;
    }

    private boolean confirmFreshStart() {
        return true; // Could add confirmation dialog
    }

    private void processProgram(DomainFile file,
                                Map<String, Map<String, Object>> byHash,
                                Map<String, Map<String, Object>> byCallees,
                                Map<String, Map<String, Object>> bySignature,
                                Map<String, Map<String, Object>> allFunctions) {
        String programName = file.getName();
        String programPath = file.getPathname();

        println("Processing: " + programName);

        Program program = null;
        try {
            program = (Program) file.getDomainObject(this, false, false, monitor);
            processingProgram = program;

            FunctionManager funcMgr = program.getFunctionManager();
            Listing listing = program.getListing();
            FunctionIterator funcIter = funcMgr.getFunctions(true);

            int count = 0;
            int skipped = 0;

            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                if (func.isThunk()) continue;

                try {
                    // Check minimum size
                    int instrCount = countInstructions(listing, func);
                    if (instrCount < MIN_INSTRUCTION_COUNT) {
                        skipped++;
                        functionsSkipped++;
                        continue;
                    }

                    processFunctionV2(func, programName, programPath, instrCount,
                                      byHash, byCallees, bySignature, allFunctions);
                    count++;
                    functionsProcessed++;
                } catch (Exception e) {
                    // Log but continue with other functions
                    // println("  Warning: " + func.getName() + ": " + e.getMessage());
                }
            }

            println("  Processed: " + count + ", Skipped (small): " + skipped);
            programsProcessed++;

        } catch (Exception e) {
            printerr("  Error: " + e.getMessage());
        } finally {
            if (program != null) {
                program.release(this);
            }
            processingProgram = null;
        }
    }

    private void processFunctionV2(Function func, String programName, String programPath,
                                   int instrCount,
                                   Map<String, Map<String, Object>> byHash,
                                   Map<String, Map<String, Object>> byCallees,
                                   Map<String, Map<String, Object>> bySignature,
                                   Map<String, Map<String, Object>> allFunctions) {

        String funcName = func.getName();
        String address = func.getEntryPoint().toString();
        String funcKey = programPath + "::" + address;
        boolean isDocumented = !funcName.startsWith("FUN_") && !funcName.startsWith("thunk_");

        // === Collect all matching signals ===

        // 1. Strict hash
        String strictHash = computeStrictHash(func);
        hashesComputed++;

        // 2. Signature hash (return type + params + calling convention)
        Map<String, Object> signature = extractSignature(func);
        String signatureHash = computeSignatureHash(signature);

        // 3. Callee names (named functions called)
        List<String> calleeNames = extractCalleeNames(func);
        String calleeHash = computeCalleeHash(calleeNames);

        // 4. String references
        List<String> stringRefs = extractStringReferences(func);
        String stringHash = computeStringHash(stringRefs);

        // 5. Size metrics
        int byteSize = (int) func.getBody().getNumAddresses();
        int basicBlockCount = estimateBasicBlocks(func);

        // 6. Plate comment and completeness
        String plateComment = func.getComment();
        boolean hasPlateComment = plateComment != null && !plateComment.isEmpty();
        int completenessScore = calculateCompleteness(func, hasPlateComment, isDocumented);

        // 7. Additional documentation for propagation (only for documented functions)
        Map<String, Map<String, String>> inlineComments = null;
        List<Map<String, Object>> globalReferences = null;
        List<Map<String, Object>> calleesWithOffsets = null;
        String repeatableComment = null;
        List<String> functionTags = null;

        if (isDocumented) {
            inlineComments = extractInlineComments(func);
            globalReferences = extractGlobalReferences(func);
            calleesWithOffsets = extractCalleesWithOffsets(func);
            repeatableComment = extractRepeatableComment(func);
            functionTags = extractFunctionTags(func);
        }

        // === Build function entry ===
        Map<String, Object> funcEntry = new LinkedHashMap<>();
        funcEntry.put("name", funcName);
        funcEntry.put("address", address);
        funcEntry.put("program", programName);
        funcEntry.put("program_path", programPath);
        funcEntry.put("is_documented", isDocumented);

        // Hashes
        funcEntry.put("strict_hash", strictHash);
        funcEntry.put("signature_hash", signatureHash);
        if (calleeHash != null) funcEntry.put("callee_hash", calleeHash);
        if (stringHash != null) funcEntry.put("string_hash", stringHash);

        // Metrics
        funcEntry.put("instruction_count", instrCount);
        funcEntry.put("byte_size", byteSize);
        funcEntry.put("basic_block_count", basicBlockCount);
        funcEntry.put("completeness_score", completenessScore);

        // Signature details
        funcEntry.put("signature", signature);

        // Callees (only if enough for meaningful matching)
        if (calleeNames.size() >= MIN_CALLEES_FOR_SIGNAL) {
            funcEntry.put("callee_names", calleeNames);
        }

        // Strings (only if enough for meaningful matching)
        if (stringRefs.size() >= MIN_STRINGS_FOR_SIGNAL) {
            funcEntry.put("string_refs", stringRefs);
        }

        // Documentation
        if (hasPlateComment) {
            funcEntry.put("plate_comment", plateComment);
        }

        // Additional documentation (for propagation)
        if (repeatableComment != null && !repeatableComment.isEmpty()) {
            funcEntry.put("repeatable_comment", repeatableComment);
        }
        if (functionTags != null && !functionTags.isEmpty()) {
            funcEntry.put("tags", functionTags);
        }
        if (inlineComments != null && !inlineComments.isEmpty()) {
            funcEntry.put("inline_comments", inlineComments);
        }
        if (globalReferences != null && !globalReferences.isEmpty()) {
            funcEntry.put("global_references", globalReferences);
        }
        if (calleesWithOffsets != null && !calleesWithOffsets.isEmpty()) {
            funcEntry.put("callees", calleesWithOffsets);
        }

        // === Index by various keys ===

        // By strict hash
        if (strictHash != null) {
            addToIndex(byHash, strictHash, funcEntry, funcKey);
        }

        // By callee hash (only if sufficient callees)
        if (calleeHash != null && calleeNames.size() >= MIN_CALLEES_FOR_SIGNAL) {
            addToIndex(byCallees, calleeHash, funcEntry, funcKey);
        }

        // By signature hash
        if (signatureHash != null) {
            addToIndex(bySignature, signatureHash, funcEntry, funcKey);
        }

        // Master list
        allFunctions.put(funcKey, funcEntry);
    }

    private void addToIndex(Map<String, Map<String, Object>> index, String key,
                           Map<String, Object> funcEntry, String funcKey) {
        Map<String, Object> hashEntry = index.get(key);
        if (hashEntry == null) {
            hashEntry = new LinkedHashMap<>();
            hashEntry.put("instances", new ArrayList<Map<String, Object>>());
            index.put(key, hashEntry);
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> instances = (List<Map<String, Object>>) hashEntry.get("instances");

        // Remove existing entry for same function key
        instances.removeIf(inst -> funcKey.equals(inst.get("program_path") + "::" + inst.get("address")));
        instances.add(funcEntry);

        // Update canonical (best documented)
        updateCanonical(hashEntry, instances);
    }

    private void updateCanonical(Map<String, Object> hashEntry, List<Map<String, Object>> instances) {
        Map<String, Object> best = null;
        int bestScore = -1;

        for (Map<String, Object> inst : instances) {
            int score = ((Number) inst.getOrDefault("completeness_score", 0)).intValue();
            boolean isDoc = (Boolean) inst.getOrDefault("is_documented", false);

            // Prefer documented functions
            if (isDoc) score += 1000;

            if (score > bestScore) {
                bestScore = score;
                best = inst;
            }
        }

        if (best != null) {
            hashEntry.put("canonical", best);
        }
    }

    private int countInstructions(Listing listing, Function func) {
        int count = 0;
        InstructionIterator iter = listing.getInstructions(func.getBody(), true);
        while (iter.hasNext()) {
            iter.next();
            count++;
        }
        return count;
    }

    private int estimateBasicBlocks(Function func) {
        int blocks = 1;
        Listing listing = processingProgram.getListing();
        InstructionIterator iter = listing.getInstructions(func.getBody(), true);
        while (iter.hasNext()) {
            Instruction instr = iter.next();
            String mnem = instr.getMnemonicString().toUpperCase();
            if (mnem.startsWith("J") || mnem.startsWith("RET")) {
                blocks++;
            }
        }
        return blocks;
    }

    private Map<String, Object> extractSignature(Function func) {
        Map<String, Object> sig = new LinkedHashMap<>();

        sig.put("calling_convention", func.getCallingConventionName());

        // Full return type info for complex type propagation
        Map<String, Object> returnTypeInfo = extractReturnTypeInfo(func);
        if (!returnTypeInfo.isEmpty()) {
            sig.put("return_type", returnTypeInfo);
        } else {
            Map<String, Object> defaultType = new LinkedHashMap<>();
            defaultType.put("name", "undefined");
            defaultType.put("kind", "primitive");
            sig.put("return_type", defaultType);
        }

        // Extract parameters with full type info
        List<Map<String, Object>> params = new ArrayList<>();
        for (Parameter p : func.getParameters()) {
            Map<String, Object> param = new LinkedHashMap<>();
            param.put("name", p.getName());
            param.put("ordinal", p.getOrdinal());

            // Full parameter type info
            DataType pType = p.getDataType();
            if (pType != null) {
                Map<String, Object> typeInfo = new LinkedHashMap<>();
                typeInfo.put("name", pType.getName());
                typeInfo.put("path", pType.getPathName());
                typeInfo.put("size", pType.getLength());

                if (pType instanceof ghidra.program.model.data.Pointer) {
                    typeInfo.put("kind", "pointer");
                    DataType pointedTo = ((ghidra.program.model.data.Pointer) pType).getDataType();
                    if (pointedTo != null) {
                        Map<String, Object> pointedToInfo = new LinkedHashMap<>();
                        pointedToInfo.put("name", pointedTo.getName());
                        pointedToInfo.put("path", pointedTo.getPathName());
                        typeInfo.put("pointed_to", pointedToInfo);
                    }
                } else if (pType instanceof ghidra.program.model.data.Structure) {
                    typeInfo.put("kind", "struct");
                } else if (pType instanceof ghidra.program.model.data.Enum) {
                    typeInfo.put("kind", "enum");
                } else {
                    typeInfo.put("kind", "primitive");
                }
                param.put("type", typeInfo);
            } else {
                Map<String, Object> defaultType = new LinkedHashMap<>();
                defaultType.put("name", "undefined");
                defaultType.put("kind", "primitive");
                param.put("type", defaultType);
            }

            String comment = p.getComment();
            if (comment != null && !comment.isEmpty()) {
                param.put("comment", comment);
            }
            params.add(param);
        }
        sig.put("parameters", params);
        sig.put("param_count", params.size());

        // Extract local variables (for propagation)
        List<Map<String, Object>> locals = new ArrayList<>();
        for (Variable v : func.getLocalVariables()) {
            String varName = v.getName();
            // Only capture renamed locals (skip generic local_*, unaff_*, etc.)
            if (varName.startsWith("local_") || varName.startsWith("unaff_") ||
                varName.startsWith("in_") || varName.startsWith("extraout_") ||
                varName.matches("^[a-z]+Var[0-9]+$")) {
                continue;
            }

            Map<String, Object> local = new LinkedHashMap<>();
            local.put("name", varName);
            local.put("storage", v.getVariableStorage().toString());

            DataType vType = v.getDataType();
            if (vType != null) {
                Map<String, Object> typeInfo = new LinkedHashMap<>();
                typeInfo.put("name", vType.getName());
                typeInfo.put("path", vType.getPathName());
                typeInfo.put("size", vType.getLength());
                local.put("type", typeInfo);
            }

            String comment = v.getComment();
            if (comment != null && !comment.isEmpty()) {
                local.put("comment", comment);
            }

            // Include first use address offset for additional matching
            // Only if in same address space (skip register-based variables)
            Address firstUse = v.getMinAddress();
            Address entryPoint = func.getEntryPoint();
            if (firstUse != null && entryPoint != null &&
                firstUse.getAddressSpace().equals(entryPoint.getAddressSpace())) {
                long offset = firstUse.subtract(entryPoint);
                local.put("first_use_offset", offset);
            }

            locals.add(local);
        }

        if (!locals.isEmpty()) {
            sig.put("local_variables", locals);
        }

        return sig;
    }

    private String computeSignatureHash(Map<String, Object> sig) {
        StringBuilder sb = new StringBuilder();
        sb.append(sig.get("calling_convention")).append("|");
        sb.append(sig.get("return_type")).append("|");
        sb.append(sig.get("param_count")).append("|");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> params = (List<Map<String, Object>>) sig.get("parameters");
        for (Map<String, Object> p : params) {
            sb.append(p.get("type")).append(",");
        }

        return hashString(sb.toString());
    }

    private List<String> extractCalleeNames(Function func) {
        List<String> callees = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        try {
            FunctionManager funcMgr = processingProgram.getFunctionManager();
            Listing listing = processingProgram.getListing();
            InstructionIterator iter = listing.getInstructions(func.getBody(), true);

            while (iter.hasNext()) {
                Instruction instr = iter.next();
                if (instr.getMnemonicString().toUpperCase().startsWith("CALL")) {
                    Address[] flows = instr.getFlows();
                    if (flows != null) {
                        for (Address target : flows) {
                            Function callee = funcMgr.getFunctionAt(target);
                            if (callee != null) {
                                String name = callee.getName();
                                // Only include named (non-FUN_) functions
                                if (!name.startsWith("FUN_") && !seen.contains(name)) {
                                    callees.add(name);
                                    seen.add(name);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Continue
        }

        Collections.sort(callees);
        return callees;
    }

    private String computeCalleeHash(List<String> callees) {
        if (callees.isEmpty()) return null;
        return hashString(String.join(",", callees));
    }

    private List<String> extractStringReferences(Function func) {
        List<String> strings = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        try {
            Listing listing = processingProgram.getListing();
            InstructionIterator iter = listing.getInstructions(func.getBody(), true);

            while (iter.hasNext()) {
                Instruction instr = iter.next();
                int numOps = instr.getNumOperands();
                for (int i = 0; i < numOps; i++) {
                    for (Object obj : instr.getOpObjects(i)) {
                        if (obj instanceof Address) {
                            Address addr = (Address) obj;
                            Data data = listing.getDataAt(addr);
                            if (data != null && data.hasStringValue()) {
                                Object value = data.getValue();
                                if (value instanceof String) {
                                    String str = (String) value;
                                    // Only meaningful strings
                                    if (str.length() >= 4 && str.length() <= 200 && !seen.contains(str)) {
                                        strings.add(str);
                                        seen.add(str);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Continue
        }

        Collections.sort(strings);
        return strings;
    }

    private String computeStringHash(List<String> strings) {
        if (strings.isEmpty()) return null;
        // Hash the sorted string list
        StringBuilder sb = new StringBuilder();
        for (String s : strings) {
            sb.append(s.hashCode()).append(",");
        }
        return hashString(sb.toString());
    }

    /**
     * Extract inline comments (EOL, PRE, POST) at instruction offsets.
     */
    private Map<String, Map<String, String>> extractInlineComments(Function func) {
        Map<String, Map<String, String>> comments = new LinkedHashMap<>();

        try {
            Listing listing = processingProgram.getListing();
            Address entryPoint = func.getEntryPoint();
            AddressSetView body = func.getBody();

            InstructionIterator iter = listing.getInstructions(body, true);
            while (iter.hasNext()) {
                Instruction instr = iter.next();
                Address addr = instr.getAddress();
                CodeUnit cu = listing.getCodeUnitAt(addr);
                if (cu == null) continue;

                String eol = cu.getComment(CodeUnit.EOL_COMMENT);
                String pre = cu.getComment(CodeUnit.PRE_COMMENT);
                String post = cu.getComment(CodeUnit.POST_COMMENT);

                if (eol != null || pre != null || post != null) {
                    long offset = addr.subtract(entryPoint);
                    String offsetKey = String.format("0x%x", offset);

                    Map<String, String> commentMap = new LinkedHashMap<>();
                    if (eol != null && !eol.isEmpty()) commentMap.put("eol", eol);
                    if (pre != null && !pre.isEmpty()) commentMap.put("pre", pre);
                    if (post != null && !post.isEmpty()) commentMap.put("post", post);

                    if (!commentMap.isEmpty()) {
                        comments.put(offsetKey, commentMap);
                    }
                }
            }
        } catch (Exception e) {
            // Continue
        }

        return comments;
    }

    /**
     * Extract global references (renamed DAT_* labels) with instruction offset and operand index.
     */
    private List<Map<String, Object>> extractGlobalReferences(Function func) {
        List<Map<String, Object>> globals = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        try {
            Listing listing = processingProgram.getListing();
            SymbolTable symbolTable = processingProgram.getSymbolTable();
            Address entryPoint = func.getEntryPoint();
            AddressSetView body = func.getBody();

            InstructionIterator iter = listing.getInstructions(body, true);
            while (iter.hasNext()) {
                Instruction instr = iter.next();
                Address instrAddr = instr.getAddress();
                long offset = instrAddr.subtract(entryPoint);

                int numOps = instr.getNumOperands();
                for (int opIdx = 0; opIdx < numOps; opIdx++) {
                    for (Object obj : instr.getOpObjects(opIdx)) {
                        if (obj instanceof Address) {
                            Address refAddr = (Address) obj;

                            // Skip addresses within function body
                            if (body.contains(refAddr)) continue;

                            // Skip function addresses (handled by callees)
                            if (processingProgram.getFunctionManager().getFunctionAt(refAddr) != null) continue;

                            Symbol sym = symbolTable.getPrimarySymbol(refAddr);
                            if (sym != null && sym.getSource() == SourceType.USER_DEFINED) {
                                String name = sym.getName();

                                // Only capture user-defined non-DAT labels
                                if (!name.startsWith("DAT_") && !name.startsWith("s_") &&
                                    !seen.contains(name)) {
                                    seen.add(name);

                                    Map<String, Object> globalRef = new LinkedHashMap<>();
                                    globalRef.put("offset", offset);
                                    globalRef.put("operand", opIdx);
                                    globalRef.put("name", name);
                                    globalRef.put("address", refAddr.toString());
                                    globals.add(globalRef);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Continue
        }

        return globals;
    }

    /**
     * Extract callees with instruction offsets for precise matching.
     */
    private List<Map<String, Object>> extractCalleesWithOffsets(Function func) {
        List<Map<String, Object>> callees = new ArrayList<>();

        try {
            FunctionManager funcMgr = processingProgram.getFunctionManager();
            Listing listing = processingProgram.getListing();
            Address entryPoint = func.getEntryPoint();
            AddressSetView body = func.getBody();

            InstructionIterator iter = listing.getInstructions(body, true);
            while (iter.hasNext()) {
                Instruction instr = iter.next();
                String mnemonic = instr.getMnemonicString().toUpperCase();

                if (mnemonic.startsWith("CALL")) {
                    Address instrAddr = instr.getAddress();
                    long offset = instrAddr.subtract(entryPoint);

                    Address[] flows = instr.getFlows();
                    if (flows != null) {
                        for (Address target : flows) {
                            Function callee = funcMgr.getFunctionAt(target);
                            if (callee != null) {
                                String calleeName = callee.getName();

                                // Only capture named (non-FUN_) functions
                                if (!calleeName.startsWith("FUN_") && !calleeName.startsWith("thunk_FUN_")) {
                                    Map<String, Object> calleeInfo = new LinkedHashMap<>();
                                    calleeInfo.put("offset", offset);
                                    calleeInfo.put("name", calleeName);
                                    calleeInfo.put("address", target.toString());
                                    callees.add(calleeInfo);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Continue
        }

        return callees;
    }

    /**
     * Extract repeatable comment from function.
     */
    private String extractRepeatableComment(Function func) {
        try {
            Listing listing = processingProgram.getListing();
            CodeUnit cu = listing.getCodeUnitAt(func.getEntryPoint());
            if (cu != null) {
                return cu.getComment(CodeUnit.REPEATABLE_COMMENT);
            }
        } catch (Exception e) {
            // Continue
        }
        return null;
    }

    /**
     * Extract function tags.
     */
    private List<String> extractFunctionTags(Function func) {
        List<String> tags = new ArrayList<>();
        try {
            for (FunctionTag tag : func.getTags()) {
                tags.add(tag.getName());
            }
        } catch (Exception e) {
            // Continue
        }
        return tags;
    }

    /**
     * Extract full return type info for complex type propagation.
     */
    private Map<String, Object> extractReturnTypeInfo(Function func) {
        Map<String, Object> typeInfo = new LinkedHashMap<>();
        try {
            DataType returnType = func.getReturnType();
            if (returnType != null) {
                typeInfo.put("name", returnType.getName());
                typeInfo.put("path", returnType.getPathName());
                typeInfo.put("size", returnType.getLength());

                // Determine kind
                if (returnType instanceof ghidra.program.model.data.Pointer) {
                    typeInfo.put("kind", "pointer");
                    DataType pointedTo = ((ghidra.program.model.data.Pointer) returnType).getDataType();
                    if (pointedTo != null) {
                        Map<String, Object> pointedToInfo = new LinkedHashMap<>();
                        pointedToInfo.put("name", pointedTo.getName());
                        pointedToInfo.put("path", pointedTo.getPathName());
                        typeInfo.put("pointed_to", pointedToInfo);
                    }
                } else if (returnType instanceof ghidra.program.model.data.Structure) {
                    typeInfo.put("kind", "struct");
                } else if (returnType instanceof ghidra.program.model.data.Enum) {
                    typeInfo.put("kind", "enum");
                } else if (returnType instanceof ghidra.program.model.data.Array) {
                    typeInfo.put("kind", "array");
                } else {
                    typeInfo.put("kind", "primitive");
                }
            }
        } catch (Exception e) {
            // Continue
        }
        return typeInfo;
    }

    private int calculateCompleteness(Function func, boolean hasPlateComment, boolean isDocumented) {
        int score = 0;

        if (isDocumented) score += 30;
        if (hasPlateComment) score += 30;

        DataType returnType = func.getReturnType();
        if (returnType != null && !returnType.getName().equals("undefined")) {
            score += 15;
        }

        Parameter[] params = func.getParameters();
        int namedParams = 0;
        for (Parameter p : params) {
            if (!p.getName().startsWith("param_")) namedParams++;
        }
        if (namedParams > 0) score += 15;

        Variable[] locals = func.getLocalVariables();
        int namedLocals = 0;
        for (Variable v : locals) {
            if (!v.getName().startsWith("local_") && !v.getName().startsWith("unaff_")) {
                namedLocals++;
            }
        }
        if (namedLocals > 0) score += 10;

        return score;
    }

    private String computeStrictHash(Function func) {
        try {
            StringBuilder sb = new StringBuilder();
            Listing listing = processingProgram.getListing();
            AddressSetView body = func.getBody();
            InstructionIterator iter = listing.getInstructions(body, true);

            while (iter.hasNext()) {
                Instruction instr = iter.next();
                sb.append(instr.getMnemonicString()).append(" ");

                int numOps = instr.getNumOperands();
                for (int i = 0; i < numOps; i++) {
                    for (Object obj : instr.getOpObjects(i)) {
                        if (obj instanceof Address) {
                            Address addr = (Address) obj;
                            if (body.contains(addr)) {
                                sb.append("REL:").append(addr.subtract(func.getEntryPoint()));
                            } else if (processingProgram.getFunctionManager().getFunctionAt(addr) != null) {
                                sb.append("CALL_EXT");
                            } else {
                                sb.append("DATA_EXT");
                            }
                        } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long val = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                            if (Math.abs(val) < 0x10000) {
                                sb.append("IMM:").append(val);
                            } else {
                                sb.append("IMM_LARGE");
                            }
                        } else if (obj instanceof Register) {
                            sb.append("REG:").append(((Register) obj).getName());
                        }
                    }
                    sb.append(",");
                }
                sb.append(";");
            }

            return hashString(sb.toString());

        } catch (Exception e) {
            return null;
        }
    }

    private String hashString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (Exception e) {
            return Integer.toHexString(input.hashCode());
        }
    }

    private Map<String, Object> loadIndex() {
        File file = new File(INDEX_FILE);
        if (!file.exists()) {
            return new LinkedHashMap<>();
        }

        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            return parseJson(content);
        } catch (Exception e) {
            println("Warning: Could not load existing index: " + e.getMessage());
            return new LinkedHashMap<>();
        }
    }

    private void saveIndex(Map<String, Object> index) throws IOException {
        String json = toJson(index, 0);
        Files.write(Paths.get(INDEX_FILE), json.getBytes());
    }

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

    private String toJson(Object obj, int indent) {
        try {
            Class<?> gsonBuilderClass = Class.forName("com.google.gson.GsonBuilder");
            Object builder = gsonBuilderClass.getConstructor().newInstance();
            java.lang.reflect.Method setPrettyPrinting = gsonBuilderClass.getMethod("setPrettyPrinting");
            builder = setPrettyPrinting.invoke(builder);
            java.lang.reflect.Method create = gsonBuilderClass.getMethod("create");
            Object gson = create.invoke(builder);
            java.lang.reflect.Method toJsonMethod = gson.getClass().getMethod("toJson", Object.class);
            return (String) toJsonMethod.invoke(gson, obj);
        } catch (Exception e) {
            return simpleToJson(obj, indent);
        }
    }

    private String simpleToJson(Object obj, int indent) {
        String indentStr = "  ".repeat(indent);
        String nextIndent = "  ".repeat(indent + 1);

        if (obj == null) {
            return "null";
        } else if (obj instanceof String) {
            return "\"" + escapeJson((String) obj) + "\"";
        } else if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        } else if (obj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) obj;
            if (map.isEmpty()) return "{}";
            StringBuilder sb = new StringBuilder("{\n");
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) sb.append(",\n");
                first = false;
                sb.append(nextIndent).append("\"").append(escapeJson(entry.getKey())).append("\": ");
                sb.append(simpleToJson(entry.getValue(), indent + 1));
            }
            sb.append("\n").append(indentStr).append("}");
            return sb.toString();
        } else if (obj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) obj;
            if (list.isEmpty()) return "[]";
            StringBuilder sb = new StringBuilder("[\n");
            boolean first = true;
            for (Object item : list) {
                if (!first) sb.append(",\n");
                first = false;
                sb.append(nextIndent).append(simpleToJson(item, indent + 1));
            }
            sb.append("\n").append(indentStr).append("]");
            return sb.toString();
        }
        return "\"" + obj.toString() + "\"";
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}

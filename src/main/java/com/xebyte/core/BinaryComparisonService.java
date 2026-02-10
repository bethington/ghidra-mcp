package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Shared service for cross-binary function comparison.
 *
 * Provides fuzzy function matching and structured diff for comparing
 * functions across binaries compiled by different compilers. All methods
 * are static, stateless, and thread-safe.
 *
 * Used by both GhidraMCPPlugin (GUI) and HeadlessEndpointHandler.
 */
public class BinaryComparisonService {

    private static final int MAX_DIFF_INSTRUCTIONS = 2000;
    private static final int MAX_DIFF_ENTRIES = 500;
    private static final int MAX_PROLOGUE_INSTRUCTIONS = 5;
    private static final int MAX_EPILOGUE_INSTRUCTIONS = 3;
    private static final double INSTRUCTION_COUNT_RATIO_CUTOFF = 4.0;

    // Similarity weights optimized for cross-compiler matching
    private static final double WEIGHT_NUMERIC = 0.25;
    private static final double WEIGHT_SET = 0.60;
    private static final double WEIGHT_STRUCTURAL = 0.15;

    // Numeric sub-weights
    private static final double NW_INSTR_COUNT = 0.25;
    private static final double NW_BLOCK_COUNT = 0.25;
    private static final double NW_CALL_COUNT = 0.20;
    private static final double NW_COMPLEXITY = 0.15;
    private static final double NW_EDGE_COUNT = 0.10;
    private static final double NW_STRING_REF = 0.05;

    // Set sub-weights
    private static final double SW_CALLEES = 0.50;
    private static final double SW_STRINGS = 0.30;
    private static final double SW_IMMEDIATES = 0.20;

    // ========================================================================
    // DATA CLASSES
    // ========================================================================

    /**
     * Feature vector for a function, used for similarity scoring.
     */
    public static class FunctionSignature {
        // Numeric features
        public int instructionCount;
        public int basicBlockCount;
        public int edgeCount;
        public int callCount;
        public int stringRefCount;
        public int paramCount;
        public int cyclomaticComplexity;

        // Set features
        public Set<String> calleeNames = new HashSet<>();
        public Set<String> stringConstants = new HashSet<>();
        public Set<Long> immediateValues = new HashSet<>();

        // Structural features
        public List<String> basicBlockHashes = new ArrayList<>();

        // Metadata (not used in scoring)
        public String functionName;
        public String address;
        public String programName;
        public boolean hasPrologueStripped;
        public boolean hasEpilogueStripped;

        public String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"function_name\": \"").append(escapeJson(functionName)).append("\", ");
            sb.append("\"address\": \"").append(escapeJson(address)).append("\", ");
            sb.append("\"program\": \"").append(escapeJson(programName)).append("\", ");
            sb.append("\"instruction_count\": ").append(instructionCount).append(", ");
            sb.append("\"basic_block_count\": ").append(basicBlockCount).append(", ");
            sb.append("\"edge_count\": ").append(edgeCount).append(", ");
            sb.append("\"call_count\": ").append(callCount).append(", ");
            sb.append("\"string_ref_count\": ").append(stringRefCount).append(", ");
            sb.append("\"param_count\": ").append(paramCount).append(", ");
            sb.append("\"cyclomatic_complexity\": ").append(cyclomaticComplexity).append(", ");
            sb.append("\"prologue_stripped\": ").append(hasPrologueStripped).append(", ");
            sb.append("\"epilogue_stripped\": ").append(hasEpilogueStripped).append(", ");

            sb.append("\"callee_names\": [");
            appendStringSet(sb, calleeNames);
            sb.append("], ");

            sb.append("\"string_constants\": [");
            appendStringSet(sb, stringConstants);
            sb.append("], ");

            sb.append("\"immediate_values\": [");
            boolean first = true;
            for (Long v : immediateValues) {
                if (!first) sb.append(", ");
                sb.append(v);
                first = false;
            }
            sb.append("], ");

            sb.append("\"basic_block_hashes\": [");
            appendStringList(sb, basicBlockHashes);
            sb.append("]");

            sb.append("}");
            return sb.toString();
        }
    }

    // ========================================================================
    // PROLOGUE / EPILOGUE DETECTION
    // ========================================================================

    private static boolean isARM(Program program) {
        String processor = program.getLanguage().getProcessor().toString();
        return processor.equalsIgnoreCase("ARM");
    }

    /**
     * Check if an instruction at the given position from function start is a prologue instruction.
     */
    static boolean isPrologueInstruction(Instruction instr, int indexFromStart, Program program) {
        if (!isARM(program) || indexFromStart >= MAX_PROLOGUE_INSTRUCTIONS) {
            return false;
        }
        String mnemonic = instr.getMnemonicString().toUpperCase();
        String repr = instr.toString().toUpperCase();

        // PUSH with lr
        if (mnemonic.startsWith("PUSH") && repr.contains("LR")) {
            return true;
        }
        // SUB sp, #imm or SUB sp, sp, #imm
        if (mnemonic.equals("SUB") && repr.contains("SP")) {
            return true;
        }
        // MOV r7, sp or ADD r7, sp, #imm (frame pointer setup)
        if ((mnemonic.equals("MOV") || mnemonic.equals("ADD")) &&
            repr.contains("R7") && repr.contains("SP")) {
            return true;
        }
        // STMDB sp!, {...} (ARM mode push)
        if (mnemonic.startsWith("STMDB") && repr.contains("SP")) {
            return true;
        }
        // STR lr, [sp, #-4]! or similar lr save
        if (mnemonic.equals("STR") && repr.contains("LR") && repr.contains("SP")) {
            return true;
        }
        return false;
    }

    /**
     * Check if an instruction at the given position from function end is an epilogue instruction.
     */
    static boolean isEpilogueInstruction(Instruction instr, int indexFromEnd, Program program) {
        if (!isARM(program) || indexFromEnd >= MAX_EPILOGUE_INSTRUCTIONS) {
            return false;
        }
        String mnemonic = instr.getMnemonicString().toUpperCase();
        String repr = instr.toString().toUpperCase();

        // POP with pc
        if (mnemonic.startsWith("POP") && repr.contains("PC")) {
            return true;
        }
        // BX lr
        if (mnemonic.equals("BX") && repr.contains("LR")) {
            return true;
        }
        // ADD sp, #imm (frame teardown)
        if (mnemonic.equals("ADD") && repr.contains("SP")) {
            return true;
        }
        // LDMIA sp!, {...} (ARM mode pop)
        if (mnemonic.startsWith("LDMIA") && repr.contains("SP")) {
            return true;
        }
        // LDR pc, [sp], #4 or similar pc restore
        if (mnemonic.equals("LDR") && repr.contains("PC") && repr.contains("SP")) {
            return true;
        }
        return false;
    }

    /**
     * Get all instructions for a function as a list.
     */
    static List<Instruction> getAllInstructions(Program program, Function func) {
        List<Instruction> instructions = new ArrayList<>();
        Listing listing = program.getListing();
        InstructionIterator iter = listing.getInstructions(func.getBody(), true);
        while (iter.hasNext()) {
            instructions.add(iter.next());
        }
        return instructions;
    }

    /**
     * Strip prologue and epilogue instructions, returning body instructions.
     * Returns a 3-element array: [prologue, body, epilogue].
     */
    static List<Instruction>[] splitPrologueBodyEpilogue(Program program, Function func) {
        List<Instruction> all = getAllInstructions(program, func);
        @SuppressWarnings("unchecked")
        List<Instruction>[] result = new List[3];

        if (all.isEmpty()) {
            result[0] = Collections.emptyList();
            result[1] = Collections.emptyList();
            result[2] = Collections.emptyList();
            return result;
        }

        // Find prologue end
        int prologueEnd = 0;
        if (isARM(program)) {
            for (int i = 0; i < all.size() && i < MAX_PROLOGUE_INSTRUCTIONS; i++) {
                if (isPrologueInstruction(all.get(i), i, program)) {
                    prologueEnd = i + 1;
                } else {
                    break;
                }
            }
        }

        // Find epilogue start (scan from end)
        int epilogueStart = all.size();
        if (isARM(program)) {
            for (int i = all.size() - 1; i >= prologueEnd && (all.size() - 1 - i) < MAX_EPILOGUE_INSTRUCTIONS; i--) {
                if (isEpilogueInstruction(all.get(i), all.size() - 1 - i, program)) {
                    epilogueStart = i;
                } else {
                    break;
                }
            }
        }

        // Ensure epilogueStart >= prologueEnd
        if (epilogueStart < prologueEnd) {
            epilogueStart = prologueEnd;
        }

        result[0] = all.subList(0, prologueEnd);
        result[1] = all.subList(prologueEnd, epilogueStart);
        result[2] = all.subList(epilogueStart, all.size());
        return result;
    }

    // ========================================================================
    // FEATURE EXTRACTION
    // ========================================================================

    /**
     * Compute a function's feature signature for similarity comparison.
     * Excludes prologue/epilogue instructions for ARM binaries.
     */
    public static FunctionSignature computeFunctionSignature(Program program, Function func, TaskMonitor monitor) {
        FunctionSignature sig = new FunctionSignature();
        sig.functionName = func.getName();
        sig.address = func.getEntryPoint().toString();
        sig.programName = program.getName();
        sig.paramCount = func.getParameterCount();

        List<Instruction>[] parts = splitPrologueBodyEpilogue(program, func);
        List<Instruction> body = parts[1];
        sig.hasPrologueStripped = !parts[0].isEmpty();
        sig.hasEpilogueStripped = !parts[2].isEmpty();

        sig.instructionCount = body.size();

        // Extract features from body instructions
        AddressSetView funcBody = func.getBody();
        Address funcStart = func.getEntryPoint();

        for (Instruction instr : body) {
            // Extract string refs and immediate values from operands
            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                int opType = instr.getOperandType(i);

                // Check for scalar/immediate values
                if ((opType & OperandType.SCALAR) != 0) {
                    Object[] opObjects = instr.getOpObjects(i);
                    if (opObjects.length > 0 && opObjects[0] instanceof Scalar) {
                        long value = ((Scalar) opObjects[0]).getValue();
                        if (Math.abs(value) < 0x10000 && value != 0) {
                            sig.immediateValues.add(value);
                        }
                    }
                }

                // Check for address references (strings, calls)
                Reference[] refs = instr.getOperandReferences(i);
                for (Reference ref : refs) {
                    Address target = ref.getToAddress();
                    if (ref.getReferenceType().isCall()) {
                        Function callee = program.getFunctionManager().getFunctionAt(target);
                        if (callee != null) {
                            sig.calleeNames.add(callee.getName());
                            sig.callCount++;
                        }
                    } else if (ref.getReferenceType().isData()) {
                        // Check for string at target
                        Data data = program.getListing().getDefinedDataAt(target);
                        if (data != null && data.hasStringValue()) {
                            Object val = data.getValue();
                            if (val instanceof String) {
                                sig.stringConstants.add((String) val);
                                sig.stringRefCount++;
                            }
                        }
                    }
                }
            }
        }

        // Basic blocks and edges (count over full function body including prologue/epilogue)
        try {
            BasicBlockModel blockModel = new BasicBlockModel(program);
            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(funcBody, monitor);
            Map<Address, List<String>> blockNormalized = new LinkedHashMap<>();

            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                sig.basicBlockCount++;

                // Count outgoing edges
                CodeBlockReferenceIterator destIter = block.getDestinations(monitor);
                while (destIter.hasNext()) {
                    CodeBlockReference dest = destIter.next();
                    if (funcBody.contains(dest.getDestinationAddress())) {
                        sig.edgeCount++;
                    }
                }

                // Build normalized representation for this block
                List<String> blockInstrs = new ArrayList<>();
                InstructionIterator instrIter = program.getListing().getInstructions(block, true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    blockInstrs.add(normalizeInstruction(instr, funcBody, funcStart, program));
                }
                if (!blockInstrs.isEmpty()) {
                    blockNormalized.put(block.getFirstStartAddress(), blockInstrs);
                }
            }

            // Cyclomatic complexity: E - N + 2
            sig.cyclomaticComplexity = sig.edgeCount - sig.basicBlockCount + 2;
            if (sig.cyclomaticComplexity < 1) {
                sig.cyclomaticComplexity = 1;
            }

            // Compute per-block hashes
            for (List<String> instrs : blockNormalized.values()) {
                sig.basicBlockHashes.add(hashStrings(instrs));
            }

        } catch (Exception e) {
            // If block model fails, estimate from instruction count
            if (sig.basicBlockCount == 0) {
                sig.basicBlockCount = 1;
                sig.cyclomaticComplexity = 1;
            }
        }

        return sig;
    }

    // ========================================================================
    // SIMILARITY SCORING
    // ========================================================================

    /**
     * Compute similarity between two function signatures.
     * Returns a score between 0.0 (completely different) and 1.0 (identical).
     */
    public static double computeSimilarity(FunctionSignature a, FunctionSignature b) {
        double numericScore = computeNumericSimilarity(a, b);
        double setScore = computeSetSimilarity(a, b);
        double structuralScore = computeStructuralSimilarity(a, b);

        return WEIGHT_NUMERIC * numericScore +
               WEIGHT_SET * setScore +
               WEIGHT_STRUCTURAL * structuralScore;
    }

    private static double computeNumericSimilarity(FunctionSignature a, FunctionSignature b) {
        double score = 0;
        score += NW_INSTR_COUNT * numericFieldSimilarity(a.instructionCount, b.instructionCount);
        score += NW_BLOCK_COUNT * numericFieldSimilarity(a.basicBlockCount, b.basicBlockCount);
        score += NW_CALL_COUNT * numericFieldSimilarity(a.callCount, b.callCount);
        score += NW_COMPLEXITY * numericFieldSimilarity(a.cyclomaticComplexity, b.cyclomaticComplexity);
        score += NW_EDGE_COUNT * numericFieldSimilarity(a.edgeCount, b.edgeCount);
        score += NW_STRING_REF * numericFieldSimilarity(a.stringRefCount, b.stringRefCount);
        return score;
    }

    private static double computeSetSimilarity(FunctionSignature a, FunctionSignature b) {
        double score = 0;
        score += SW_CALLEES * jaccard(a.calleeNames, b.calleeNames);
        score += SW_STRINGS * jaccard(a.stringConstants, b.stringConstants);
        score += SW_IMMEDIATES * jaccardLong(a.immediateValues, b.immediateValues);
        return score;
    }

    private static double computeStructuralSimilarity(FunctionSignature a, FunctionSignature b) {
        return blockHashSimilarity(a.basicBlockHashes, b.basicBlockHashes);
    }

    // ========================================================================
    // FUZZY MATCHING
    // ========================================================================

    /**
     * Find functions in target program similar to the given source function.
     */
    public static String findSimilarFunctionsJson(
            Program srcProgram, Function srcFunc,
            Program tgtProgram, double threshold, int limit,
            TaskMonitor monitor) {

        FunctionSignature srcSig = computeFunctionSignature(srcProgram, srcFunc, monitor);

        List<double[]> matches = new ArrayList<>(); // [score] with parallel list for functions
        List<Function> matchFunctions = new ArrayList<>();

        FunctionIterator tgtFunctions = tgtProgram.getFunctionManager().getFunctions(true);
        while (tgtFunctions.hasNext()) {
            if (monitor.isCancelled()) break;
            Function tgtFunc = tgtFunctions.next();
            if (tgtFunc.isThunk() || tgtFunc.isExternal()) continue;

            // Early exit: instruction count ratio check
            int tgtInstrCount = countInstructions(tgtProgram, tgtFunc);
            if (srcSig.instructionCount > 0 && tgtInstrCount > 0) {
                double ratio = (double) Math.max(srcSig.instructionCount, tgtInstrCount) /
                               Math.min(srcSig.instructionCount, tgtInstrCount);
                if (ratio > INSTRUCTION_COUNT_RATIO_CUTOFF) continue;
            }

            FunctionSignature tgtSig = computeFunctionSignature(tgtProgram, tgtFunc, monitor);
            double score = computeSimilarity(srcSig, tgtSig);

            if (score >= threshold) {
                matches.add(new double[]{score});
                matchFunctions.add(tgtFunc);
            }
        }

        // Sort by score descending
        Integer[] indices = new Integer[matches.size()];
        for (int i = 0; i < indices.length; i++) indices[i] = i;
        Arrays.sort(indices, (x, y) -> Double.compare(matches.get(y)[0], matches.get(x)[0]));

        int resultCount = Math.min(limit, indices.length);

        StringBuilder sb = new StringBuilder();
        sb.append("{\"source\": ");
        sb.append("{\"name\": \"").append(escapeJson(srcFunc.getName())).append("\", ");
        sb.append("\"address\": \"").append(srcFunc.getEntryPoint()).append("\", ");
        sb.append("\"program\": \"").append(escapeJson(srcProgram.getName())).append("\"}, ");
        sb.append("\"target_program\": \"").append(escapeJson(tgtProgram.getName())).append("\", ");
        sb.append("\"threshold\": ").append(threshold).append(", ");
        sb.append("\"total_matches\": ").append(indices.length).append(", ");
        sb.append("\"matches\": [");

        for (int i = 0; i < resultCount; i++) {
            int idx = indices[i];
            Function tgtFunc = matchFunctions.get(idx);
            double score = matches.get(idx)[0];

            if (i > 0) sb.append(", ");
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(tgtFunc.getName())).append("\", ");
            sb.append("\"address\": \"").append(tgtFunc.getEntryPoint()).append("\", ");
            sb.append("\"score\": ").append(String.format("%.4f", score));
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Bulk fuzzy match: find best match for each source function in target program.
     */
    public static String bulkFuzzyMatchJson(
            Program srcProgram, Program tgtProgram,
            double threshold, int offset, int limit,
            String filter, TaskMonitor monitor) {

        // Collect source functions
        List<Function> srcFunctions = new ArrayList<>();
        FunctionIterator srcIter = srcProgram.getFunctionManager().getFunctions(true);
        while (srcIter.hasNext()) {
            Function f = srcIter.next();
            if (f.isThunk() || f.isExternal()) continue;
            if (filter != null && !filter.isEmpty()) {
                if (filter.equals("named") && (f.getName().startsWith("FUN_") || f.getName().startsWith("thunk_"))) continue;
                if (filter.equals("unnamed") && !f.getName().startsWith("FUN_")) continue;
            }
            srcFunctions.add(f);
        }

        int totalSrc = srcFunctions.size();
        int startIdx = Math.max(0, offset);
        int endIdx = Math.min(totalSrc, startIdx + limit);

        if (startIdx >= totalSrc) {
            return "{\"source_program\": \"" + escapeJson(srcProgram.getName()) +
                   "\", \"target_program\": \"" + escapeJson(tgtProgram.getName()) +
                   "\", \"total_source_functions\": " + totalSrc +
                   ", \"offset\": " + offset + ", \"limit\": " + limit +
                   ", \"matches\": []}";
        }

        // Pre-compute target signatures
        List<Function> tgtFunctions = new ArrayList<>();
        List<FunctionSignature> tgtSigs = new ArrayList<>();
        FunctionIterator tgtIter = tgtProgram.getFunctionManager().getFunctions(true);
        while (tgtIter.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = tgtIter.next();
            if (f.isThunk() || f.isExternal()) continue;
            tgtFunctions.add(f);
            tgtSigs.add(computeFunctionSignature(tgtProgram, f, monitor));
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"source_program\": \"").append(escapeJson(srcProgram.getName())).append("\", ");
        sb.append("\"target_program\": \"").append(escapeJson(tgtProgram.getName())).append("\", ");
        sb.append("\"total_source_functions\": ").append(totalSrc).append(", ");
        sb.append("\"offset\": ").append(offset).append(", ");
        sb.append("\"limit\": ").append(limit).append(", ");
        sb.append("\"matches\": [");

        boolean firstMatch = true;
        for (int i = startIdx; i < endIdx; i++) {
            if (monitor.isCancelled()) break;
            Function srcFunc = srcFunctions.get(i);
            FunctionSignature srcSig = computeFunctionSignature(srcProgram, srcFunc, monitor);

            double bestScore = 0;
            int bestIdx = -1;

            for (int j = 0; j < tgtSigs.size(); j++) {
                // Early exit on instruction count ratio
                FunctionSignature tgtSig = tgtSigs.get(j);
                if (srcSig.instructionCount > 0 && tgtSig.instructionCount > 0) {
                    double ratio = (double) Math.max(srcSig.instructionCount, tgtSig.instructionCount) /
                                   Math.min(srcSig.instructionCount, tgtSig.instructionCount);
                    if (ratio > INSTRUCTION_COUNT_RATIO_CUTOFF) continue;
                }

                double score = computeSimilarity(srcSig, tgtSig);
                if (score > bestScore) {
                    bestScore = score;
                    bestIdx = j;
                }
            }

            if (bestScore >= threshold && bestIdx >= 0) {
                Function bestFunc = tgtFunctions.get(bestIdx);
                if (!firstMatch) sb.append(", ");
                sb.append("{");
                sb.append("\"source_name\": \"").append(escapeJson(srcFunc.getName())).append("\", ");
                sb.append("\"source_address\": \"").append(srcFunc.getEntryPoint()).append("\", ");
                sb.append("\"target_name\": \"").append(escapeJson(bestFunc.getName())).append("\", ");
                sb.append("\"target_address\": \"").append(bestFunc.getEntryPoint()).append("\", ");
                sb.append("\"score\": ").append(String.format("%.4f", bestScore));
                sb.append("}");
                firstMatch = false;
            }
        }

        sb.append("]}");
        return sb.toString();
    }

    // ========================================================================
    // FUNCTION DIFF
    // ========================================================================

    /**
     * Compute a structured diff between two functions.
     */
    public static String diffFunctionsJson(
            Program progA, Function funcA,
            Program progB, Function funcB,
            TaskMonitor monitor) {

        List<Instruction>[] partsA = splitPrologueBodyEpilogue(progA, funcA);
        List<Instruction>[] partsB = splitPrologueBodyEpilogue(progB, funcB);

        AddressSetView bodyA = funcA.getBody();
        AddressSetView bodyB = funcB.getBody();
        Address startA = funcA.getEntryPoint();
        Address startB = funcB.getEntryPoint();

        // Normalize body instructions
        List<String> normA = new ArrayList<>();
        for (Instruction instr : partsA[1]) {
            normA.add(normalizeInstruction(instr, bodyA, startA, progA));
        }
        List<String> normB = new ArrayList<>();
        for (Instruction instr : partsB[1]) {
            normB.add(normalizeInstruction(instr, bodyB, startB, progB));
        }

        // Check size limits
        boolean truncated = false;
        if (normA.size() > MAX_DIFF_INSTRUCTIONS) {
            normA = normA.subList(0, MAX_DIFF_INSTRUCTIONS);
            truncated = true;
        }
        if (normB.size() > MAX_DIFF_INSTRUCTIONS) {
            normB = normB.subList(0, MAX_DIFF_INSTRUCTIONS);
            truncated = true;
        }

        // LCS diff on body
        List<DiffEntry> bodyDiff = computeLCSDiff(normA, normB);

        // Normalize and diff prologue
        List<String> prologueA = new ArrayList<>();
        for (Instruction instr : partsA[0]) {
            prologueA.add(instr.toString());
        }
        List<String> prologueB = new ArrayList<>();
        for (Instruction instr : partsB[0]) {
            prologueB.add(instr.toString());
        }
        List<DiffEntry> prologueDiff = computeLCSDiff(prologueA, prologueB);

        // Normalize and diff epilogue
        List<String> epilogueA = new ArrayList<>();
        for (Instruction instr : partsA[2]) {
            epilogueA.add(instr.toString());
        }
        List<String> epilogueB = new ArrayList<>();
        for (Instruction instr : partsB[2]) {
            epilogueB.add(instr.toString());
        }
        List<DiffEntry> epilogueDiff = computeLCSDiff(epilogueA, epilogueB);

        // Compute summary
        int bodyEqual = 0, bodyAdded = 0, bodyRemoved = 0;
        for (DiffEntry e : bodyDiff) {
            switch (e.type) {
                case "equal": bodyEqual++; break;
                case "added": bodyAdded++; break;
                case "removed": bodyRemoved++; break;
            }
        }

        // Callee name differences
        FunctionSignature sigA = computeFunctionSignature(progA, funcA, monitor);
        FunctionSignature sigB = computeFunctionSignature(progB, funcB, monitor);

        Set<String> callsOnlyA = new HashSet<>(sigA.calleeNames);
        callsOnlyA.removeAll(sigB.calleeNames);
        Set<String> callsOnlyB = new HashSet<>(sigB.calleeNames);
        callsOnlyB.removeAll(sigA.calleeNames);

        Set<String> stringsOnlyA = new HashSet<>(sigA.stringConstants);
        stringsOnlyA.removeAll(sigB.stringConstants);
        Set<String> stringsOnlyB = new HashSet<>(sigB.stringConstants);
        stringsOnlyB.removeAll(sigA.stringConstants);

        boolean prologueChanged = !prologueDiff.stream().allMatch(e -> e.type.equals("equal"));
        boolean epilogueChanged = !epilogueDiff.stream().allMatch(e -> e.type.equals("equal"));

        double similarity = computeSimilarity(sigA, sigB);

        // Build JSON
        StringBuilder sb = new StringBuilder();
        sb.append("{");

        // Function info
        sb.append("\"function_a\": {");
        sb.append("\"name\": \"").append(escapeJson(funcA.getName())).append("\", ");
        sb.append("\"address\": \"").append(funcA.getEntryPoint()).append("\", ");
        sb.append("\"program\": \"").append(escapeJson(progA.getName())).append("\", ");
        sb.append("\"instruction_count\": ").append(partsA[0].size() + partsA[1].size() + partsA[2].size());
        sb.append("}, ");

        sb.append("\"function_b\": {");
        sb.append("\"name\": \"").append(escapeJson(funcB.getName())).append("\", ");
        sb.append("\"address\": \"").append(funcB.getEntryPoint()).append("\", ");
        sb.append("\"program\": \"").append(escapeJson(progB.getName())).append("\", ");
        sb.append("\"instruction_count\": ").append(partsB[0].size() + partsB[1].size() + partsB[2].size());
        sb.append("}, ");

        // Summary
        sb.append("\"summary\": {");
        sb.append("\"similarity_score\": ").append(String.format("%.4f", similarity)).append(", ");
        sb.append("\"body_equal\": ").append(bodyEqual).append(", ");
        sb.append("\"body_added\": ").append(bodyAdded).append(", ");
        sb.append("\"body_removed\": ").append(bodyRemoved).append(", ");
        sb.append("\"prologue_changed\": ").append(prologueChanged).append(", ");
        sb.append("\"epilogue_changed\": ").append(epilogueChanged).append(", ");
        sb.append("\"truncated\": ").append(truncated).append(", ");

        sb.append("\"calls_only_in_a\": [");
        appendStringSet(sb, callsOnlyA);
        sb.append("], ");
        sb.append("\"calls_only_in_b\": [");
        appendStringSet(sb, callsOnlyB);
        sb.append("], ");
        sb.append("\"strings_only_in_a\": [");
        appendStringSet(sb, stringsOnlyA);
        sb.append("], ");
        sb.append("\"strings_only_in_b\": [");
        appendStringSet(sb, stringsOnlyB);
        sb.append("]");
        sb.append("}, ");

        // Prologue diff
        sb.append("\"prologue_diff\": [");
        appendDiffEntries(sb, prologueDiff, prologueDiff.size());
        sb.append("], ");

        // Body diff (truncated)
        sb.append("\"body_diff\": [");
        appendDiffEntries(sb, bodyDiff, MAX_DIFF_ENTRIES);
        sb.append("], ");

        // Epilogue diff
        sb.append("\"epilogue_diff\": [");
        appendDiffEntries(sb, epilogueDiff, epilogueDiff.size());
        sb.append("]");

        sb.append("}");
        return sb.toString();
    }

    // ========================================================================
    // LCS DIFF
    // ========================================================================

    static class DiffEntry {
        String type; // "equal", "added", "removed"
        String line;

        DiffEntry(String type, String line) {
            this.type = type;
            this.line = line;
        }
    }

    /**
     * Compute LCS-based diff between two string lists.
     */
    static List<DiffEntry> computeLCSDiff(List<String> a, List<String> b) {
        int m = a.size();
        int n = b.size();

        // Handle edge cases
        if (m == 0 && n == 0) return Collections.emptyList();
        if (m == 0) {
            List<DiffEntry> result = new ArrayList<>();
            for (String s : b) result.add(new DiffEntry("added", s));
            return result;
        }
        if (n == 0) {
            List<DiffEntry> result = new ArrayList<>();
            for (String s : a) result.add(new DiffEntry("removed", s));
            return result;
        }

        // Standard LCS DP - use short[][] to save memory for large functions
        // For very large inputs, use Hirschberg's linear-space algorithm
        if ((long) m * n > 4_000_000L) {
            // Fall back to simple line-by-line comparison for huge functions
            return simpleDiff(a, b);
        }

        int[][] dp = new int[m + 1][n + 1];
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (a.get(i - 1).equals(b.get(j - 1))) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }

        // Backtrack to build diff
        List<DiffEntry> diff = new ArrayList<>();
        int i = m, j = n;
        while (i > 0 || j > 0) {
            if (i > 0 && j > 0 && a.get(i - 1).equals(b.get(j - 1))) {
                diff.add(new DiffEntry("equal", a.get(i - 1)));
                i--; j--;
            } else if (j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j])) {
                diff.add(new DiffEntry("added", b.get(j - 1)));
                j--;
            } else {
                diff.add(new DiffEntry("removed", a.get(i - 1)));
                i--;
            }
        }

        Collections.reverse(diff);
        return diff;
    }

    /**
     * Simple fallback diff for very large functions (no LCS, just line-by-line).
     */
    private static List<DiffEntry> simpleDiff(List<String> a, List<String> b) {
        List<DiffEntry> diff = new ArrayList<>();
        int i = 0, j = 0;
        while (i < a.size() && j < b.size()) {
            if (a.get(i).equals(b.get(j))) {
                diff.add(new DiffEntry("equal", a.get(i)));
                i++; j++;
            } else {
                diff.add(new DiffEntry("removed", a.get(i)));
                diff.add(new DiffEntry("added", b.get(j)));
                i++; j++;
            }
        }
        while (i < a.size()) {
            diff.add(new DiffEntry("removed", a.get(i++)));
        }
        while (j < b.size()) {
            diff.add(new DiffEntry("added", b.get(j++)));
        }
        return diff;
    }

    // ========================================================================
    // INSTRUCTION NORMALIZATION
    // ========================================================================

    /**
     * Normalize an instruction for comparison (address-independent).
     * Mirrors the normalization logic in GhidraMCPPlugin.computeNormalizedFunctionHash().
     */
    static String normalizeInstruction(Instruction instr, AddressSetView funcBody, Address funcStart, Program program) {
        StringBuilder sb = new StringBuilder();
        sb.append(instr.getMnemonicString()).append(" ");

        int numOperands = instr.getNumOperands();
        for (int i = 0; i < numOperands; i++) {
            int opType = instr.getOperandType(i);

            boolean isAddressRef = (opType & OperandType.ADDRESS) != 0 ||
                                   (opType & OperandType.CODE) != 0 ||
                                   (opType & OperandType.DATA) != 0;

            if (isAddressRef) {
                Reference[] refs = instr.getOperandReferences(i);
                if (refs.length > 0) {
                    Address targetAddr = refs[0].getToAddress();
                    if (funcBody.contains(targetAddr)) {
                        long relOffset = targetAddr.subtract(funcStart);
                        sb.append("REL+").append(relOffset);
                    } else {
                        RefType refType = refs[0].getReferenceType();
                        if (refType.isCall()) {
                            sb.append("CALL_EXT");
                        } else if (refType.isData()) {
                            sb.append("DATA_EXT");
                        } else {
                            sb.append("EXT_REF");
                        }
                    }
                } else {
                    sb.append("ADDR");
                }
            } else if ((opType & OperandType.REGISTER) != 0) {
                sb.append(instr.getDefaultOperandRepresentation(i));
            } else if ((opType & OperandType.SCALAR) != 0) {
                Object[] opObjects = instr.getOpObjects(i);
                if (opObjects.length > 0 && opObjects[0] instanceof Scalar) {
                    long value = ((Scalar) opObjects[0]).getValue();
                    if (Math.abs(value) < 0x10000) {
                        sb.append("IMM:").append(value);
                    } else {
                        sb.append("IMM_LARGE");
                    }
                } else {
                    sb.append(instr.getDefaultOperandRepresentation(i));
                }
            } else {
                sb.append(instr.getDefaultOperandRepresentation(i));
            }

            if (i < numOperands - 1) {
                sb.append(",");
            }
        }

        return sb.toString();
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    private static double numericFieldSimilarity(int a, int b) {
        if (a == 0 && b == 0) return 1.0;
        return 1.0 - (double) Math.abs(a - b) / Math.max(a, b);
    }

    private static <T> double jaccard(Set<T> a, Set<T> b) {
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        Set<T> union = new HashSet<>(a);
        union.addAll(b);
        if (union.isEmpty()) return 1.0;
        Set<T> intersection = new HashSet<>(a);
        intersection.retainAll(b);
        return (double) intersection.size() / union.size();
    }

    private static double jaccardLong(Set<Long> a, Set<Long> b) {
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        Set<Long> union = new HashSet<>(a);
        union.addAll(b);
        if (union.isEmpty()) return 1.0;
        Set<Long> intersection = new HashSet<>(a);
        intersection.retainAll(b);
        return (double) intersection.size() / union.size();
    }

    private static double blockHashSimilarity(List<String> a, List<String> b) {
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        // Count matching hashes (multiset intersection)
        Map<String, Integer> countA = new HashMap<>();
        for (String h : a) countA.merge(h, 1, Integer::sum);
        Map<String, Integer> countB = new HashMap<>();
        for (String h : b) countB.merge(h, 1, Integer::sum);

        int matchCount = 0;
        for (Map.Entry<String, Integer> entry : countA.entrySet()) {
            Integer bCount = countB.get(entry.getKey());
            if (bCount != null) {
                matchCount += Math.min(entry.getValue(), bCount);
            }
        }

        int totalCount = Math.max(a.size(), b.size());
        if (totalCount == 0) return 1.0;
        return (double) matchCount / totalCount;
    }

    private static int countInstructions(Program program, Function func) {
        int count = 0;
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
        while (iter.hasNext()) {
            iter.next();
            count++;
        }
        return count;
    }

    private static String hashStrings(List<String> strings) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String s : strings) {
                digest.update(s.getBytes(StandardCharsets.UTF_8));
                digest.update((byte) '\n');
            }
            return bytesToHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            // Fallback
            return Integer.toHexString(strings.hashCode());
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) sb.append('0');
            sb.append(hex);
        }
        return sb.toString();
    }

    static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static void appendStringSet(StringBuilder sb, Set<String> set) {
        boolean first = true;
        for (String s : set) {
            if (!first) sb.append(", ");
            sb.append("\"").append(escapeJson(s)).append("\"");
            first = false;
        }
    }

    private static void appendStringList(StringBuilder sb, List<String> list) {
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(escapeJson(list.get(i))).append("\"");
        }
    }

    private static void appendDiffEntries(StringBuilder sb, List<DiffEntry> entries, int maxEntries) {
        int count = Math.min(entries.size(), maxEntries);
        for (int i = 0; i < count; i++) {
            if (i > 0) sb.append(", ");
            DiffEntry e = entries.get(i);
            sb.append("{\"type\": \"").append(e.type).append("\", ");
            sb.append("\"line\": \"").append(escapeJson(e.line)).append("\"}");
        }
    }
}

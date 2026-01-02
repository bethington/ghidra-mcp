//Test different hash strategies across binaries to measure matching effectiveness.
//Run this on a project folder with multiple versions of the same binary.
//It uses custom-named functions as ground truth to measure precision/recall.
//@author GhidraMCP
//@category Documentation
//@keybinding
//@menupath D2.Hash Strategy Tester
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.framework.model.*;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.*;

public class HashStrategyTester extends GhidraScript {

    // Results storage
    private Map<String, StrategyResults> strategyResults = new LinkedHashMap<>();

    // Ground truth: functionName -> list of (program, address) pairs
    private Map<String, List<FunctionLocation>> groundTruth = new HashMap<>();

    // All functions by strategy: strategy -> hash -> list of (program, funcName, address)
    private Map<String, Map<String, List<FunctionLocation>>> hashMaps = new HashMap<>();

    static class FunctionLocation {
        String program;
        String name;
        String address;
        int instructionCount;
        int byteSize;

        FunctionLocation(String program, String name, String address, int instrCount, int byteSize) {
            this.program = program;
            this.name = name;
            this.address = address;
            this.instructionCount = instrCount;
            this.byteSize = byteSize;
        }

        @Override
        public String toString() {
            return program + ":" + name + "@" + address;
        }
    }

    static class StrategyResults {
        String name;
        int totalHashes = 0;
        int uniqueHashes = 0;
        int truePositives = 0;      // Same name, same hash
        int falsePositives = 0;     // Different name, same hash
        int falseNegatives = 0;     // Same name, different hash
        int collisions = 0;         // Multiple different functions with same hash
        double precision = 0;
        double recall = 0;
        double f1Score = 0;
        List<String> falsePositiveExamples = new ArrayList<>();
        List<String> falseNegativeExamples = new ArrayList<>();

        void calculate() {
            if (truePositives + falsePositives > 0) {
                precision = (double) truePositives / (truePositives + falsePositives);
            }
            if (truePositives + falseNegatives > 0) {
                recall = (double) truePositives / (truePositives + falseNegatives);
            }
            if (precision + recall > 0) {
                f1Score = 2 * (precision * recall) / (precision + recall);
            }
        }
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open!");
            return;
        }

        DomainFile currentFile = currentProgram.getDomainFile();
        DomainFolder parentFolder = currentFile.getParent();

        println("=".repeat(70));
        println("HASH STRATEGY TESTER");
        println("=".repeat(70));
        println("Project folder: " + parentFolder.getPathname());
        println("");

        // Initialize strategy results
        String[] strategies = {
            "strict",           // Current full normalization
            "relaxed",          // Ignore all immediates
            "mnemonic_only",    // Just mnemonic sequence
            "structural",       // Control flow only
            "weighted",         // Instruction weighting
            "no_prologue",      // Skip prologue/epilogue
            "with_strings",     // Include string references
            "with_callees",     // Include callee names
            "ngram_3",          // 3-instruction ngrams
            "block_hash"        // Basic block hashing
        };

        for (String s : strategies) {
            strategyResults.put(s, new StrategyResults());
            strategyResults.get(s).name = s;
            hashMaps.put(s, new HashMap<>());
        }

        // Get all programs in folder
        List<DomainFile> programFiles = new ArrayList<>();
        for (DomainFile file : parentFolder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                programFiles.add(file);
            }
        }

        println("Found " + programFiles.size() + " programs");
        println("");

        if (programFiles.size() < 2) {
            printerr("Need at least 2 programs to compare!");
            return;
        }

        // Phase 1: Collect all functions and compute hashes
        println("Phase 1: Computing hashes for all strategies...");
        println("-".repeat(70));

        for (DomainFile file : programFiles) {
            if (monitor.isCancelled()) break;
            processProgram(file);
        }

        // Phase 2: Build ground truth from custom-named functions
        println("");
        println("Phase 2: Building ground truth from documented functions...");
        println("-".repeat(70));
        buildGroundTruth();

        // Phase 3: Evaluate each strategy
        println("");
        println("Phase 3: Evaluating strategies...");
        println("-".repeat(70));
        evaluateStrategies();

        // Phase 4: Report results
        println("");
        println("=".repeat(70));
        println("RESULTS");
        println("=".repeat(70));
        printResults();

        // Save detailed results to file
        saveDetailedResults();
    }

    private void processProgram(DomainFile file) {
        String programName = file.getName();
        println("Processing: " + programName);

        Program program = null;
        try {
            program = (Program) file.getDomainObject(this, false, false, monitor);

            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator funcIter = funcMgr.getFunctions(true);

            int count = 0;
            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                if (func.isThunk()) continue;

                // Get function metadata
                String funcName = func.getName();
                String address = func.getEntryPoint().toString();
                int instrCount = countInstructions(program, func);
                int byteSize = (int) func.getBody().getNumAddresses();

                FunctionLocation loc = new FunctionLocation(programName, funcName, address, instrCount, byteSize);

                // Compute hash for each strategy
                for (String strategy : hashMaps.keySet()) {
                    String hash = computeHash(program, func, strategy);
                    if (hash != null) {
                        hashMaps.get(strategy)
                            .computeIfAbsent(hash, k -> new ArrayList<>())
                            .add(loc);
                        strategyResults.get(strategy).totalHashes++;
                    }
                }

                count++;
            }

            println("  " + count + " functions processed");

        } catch (Exception e) {
            printerr("  Error: " + e.getMessage());
        } finally {
            if (program != null) {
                program.release(this);
            }
        }
    }

    private int countInstructions(Program program, Function func) {
        int count = 0;
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
        while (iter.hasNext()) {
            iter.next();
            count++;
        }
        return count;
    }

    private void buildGroundTruth() {
        // Ground truth: functions with custom names that appear in multiple programs
        Map<String, Set<String>> nameToPrograms = new HashMap<>();

        // Use the "strict" hash map to iterate all functions
        for (List<FunctionLocation> locs : hashMaps.get("strict").values()) {
            for (FunctionLocation loc : locs) {
                if (!loc.name.startsWith("FUN_") && !loc.name.startsWith("thunk_")) {
                    nameToPrograms.computeIfAbsent(loc.name, k -> new HashSet<>()).add(loc.program);
                    groundTruth.computeIfAbsent(loc.name, k -> new ArrayList<>()).add(loc);
                }
            }
        }

        // Filter to only functions that appear in 2+ programs
        int multiProgram = 0;
        int singleProgram = 0;
        for (Map.Entry<String, Set<String>> entry : nameToPrograms.entrySet()) {
            if (entry.getValue().size() >= 2) {
                multiProgram++;
            } else {
                singleProgram++;
                groundTruth.remove(entry.getKey()); // Remove single-program functions
            }
        }

        println("  Custom-named functions in 2+ programs: " + multiProgram);
        println("  Custom-named functions in 1 program only: " + singleProgram);
        println("  Ground truth pairs to match: " + groundTruth.size());
    }

    private void evaluateStrategies() {
        for (String strategy : strategyResults.keySet()) {
            evaluateStrategy(strategy);
        }
    }

    private void evaluateStrategy(String strategy) {
        StrategyResults results = strategyResults.get(strategy);
        Map<String, List<FunctionLocation>> hashMap = hashMaps.get(strategy);

        results.uniqueHashes = hashMap.size();

        // Check each hash bucket
        for (Map.Entry<String, List<FunctionLocation>> entry : hashMap.entrySet()) {
            List<FunctionLocation> bucket = entry.getValue();

            if (bucket.size() < 2) continue; // No matches possible

            // Group by function name within this hash bucket
            Map<String, List<FunctionLocation>> byName = new HashMap<>();
            for (FunctionLocation loc : bucket) {
                byName.computeIfAbsent(loc.name, k -> new ArrayList<>()).add(loc);
            }

            // Count matches
            Set<String> customNames = new HashSet<>();
            for (String name : byName.keySet()) {
                if (!name.startsWith("FUN_") && !name.startsWith("thunk_")) {
                    customNames.add(name);
                }
            }

            if (customNames.size() == 1) {
                // All custom-named functions have same name = true positive
                String theName = customNames.iterator().next();
                List<FunctionLocation> sameName = byName.get(theName);
                if (sameName.size() >= 2) {
                    // Count pairs matched correctly
                    int pairs = sameName.size() * (sameName.size() - 1) / 2;
                    results.truePositives += pairs;
                }
            } else if (customNames.size() > 1) {
                // Multiple different custom names with same hash = collision/false positive
                results.collisions++;
                for (String name : customNames) {
                    List<FunctionLocation> funcs = byName.get(name);
                    if (funcs.size() >= 2) {
                        // These are true positives within their name
                        int pairs = funcs.size() * (funcs.size() - 1) / 2;
                        results.truePositives += pairs;
                    }
                }
                // Count cross-name pairs as false positives
                List<String> nameList = new ArrayList<>(customNames);
                for (int i = 0; i < nameList.size(); i++) {
                    for (int j = i + 1; j < nameList.size(); j++) {
                        int fpPairs = byName.get(nameList.get(i)).size() * byName.get(nameList.get(j)).size();
                        results.falsePositives += fpPairs;
                        if (results.falsePositiveExamples.size() < 10) {
                            results.falsePositiveExamples.add(
                                nameList.get(i) + " vs " + nameList.get(j) + " (hash collision)");
                        }
                    }
                }
            }
        }

        // Calculate false negatives: ground truth pairs that didn't match
        for (Map.Entry<String, List<FunctionLocation>> gtEntry : groundTruth.entrySet()) {
            String funcName = gtEntry.getKey();
            List<FunctionLocation> locations = gtEntry.getValue();

            if (locations.size() < 2) continue;

            // Check how many pairs actually matched via hash
            Set<String> hashesForThisFunc = new HashSet<>();
            for (FunctionLocation loc : locations) {
                // Find hash for this function in this strategy
                for (Map.Entry<String, List<FunctionLocation>> hashEntry : hashMap.entrySet()) {
                    for (FunctionLocation hloc : hashEntry.getValue()) {
                        if (hloc.program.equals(loc.program) && hloc.address.equals(loc.address)) {
                            hashesForThisFunc.add(hashEntry.getKey());
                        }
                    }
                }
            }

            // If multiple hashes, we have false negatives
            if (hashesForThisFunc.size() > 1) {
                // These functions should match but have different hashes
                int expectedPairs = locations.size() * (locations.size() - 1) / 2;
                // Subtract pairs that DID match (within same hash)
                int matchedPairs = 0;
                for (String hash : hashesForThisFunc) {
                    int count = 0;
                    for (FunctionLocation hloc : hashMap.get(hash)) {
                        if (hloc.name.equals(funcName)) count++;
                    }
                    if (count >= 2) {
                        matchedPairs += count * (count - 1) / 2;
                    }
                }
                int missedPairs = expectedPairs - matchedPairs;
                if (missedPairs > 0) {
                    results.falseNegatives += missedPairs;
                    if (results.falseNegativeExamples.size() < 10) {
                        results.falseNegativeExamples.add(
                            funcName + " has " + hashesForThisFunc.size() + " different hashes");
                    }
                }
            }
        }

        results.calculate();
    }

    private void printResults() {
        // Sort by F1 score descending
        List<StrategyResults> sorted = new ArrayList<>(strategyResults.values());
        sorted.sort((a, b) -> Double.compare(b.f1Score, a.f1Score));

        println(String.format("%-15s %8s %8s %8s %8s %8s %8s %8s",
            "Strategy", "Unique", "TP", "FP", "FN", "Precis", "Recall", "F1"));
        println("-".repeat(79));

        for (StrategyResults r : sorted) {
            println(String.format("%-15s %8d %8d %8d %8d %7.1f%% %7.1f%% %7.1f%%",
                r.name,
                r.uniqueHashes,
                r.truePositives,
                r.falsePositives,
                r.falseNegatives,
                r.precision * 100,
                r.recall * 100,
                r.f1Score * 100));
        }

        // Print examples for best and worst
        println("");
        println("Best strategy: " + sorted.get(0).name);
        if (!sorted.get(0).falsePositiveExamples.isEmpty()) {
            println("  False positive examples:");
            for (String ex : sorted.get(0).falsePositiveExamples) {
                println("    - " + ex);
            }
        }
        if (!sorted.get(0).falseNegativeExamples.isEmpty()) {
            println("  False negative examples:");
            for (String ex : sorted.get(0).falseNegativeExamples) {
                println("    - " + ex);
            }
        }
    }

    private void saveDetailedResults() {
        try {
            String outputPath = System.getProperty("user.home") +
                File.separator + "hash_strategy_test_results.txt";

            StringBuilder sb = new StringBuilder();
            sb.append("Hash Strategy Test Results\n");
            sb.append("=".repeat(70)).append("\n\n");

            for (StrategyResults r : strategyResults.values()) {
                sb.append("Strategy: ").append(r.name).append("\n");
                sb.append("-".repeat(40)).append("\n");
                sb.append("  Unique hashes: ").append(r.uniqueHashes).append("\n");
                sb.append("  True positives: ").append(r.truePositives).append("\n");
                sb.append("  False positives: ").append(r.falsePositives).append("\n");
                sb.append("  False negatives: ").append(r.falseNegatives).append("\n");
                sb.append("  Collisions: ").append(r.collisions).append("\n");
                sb.append("  Precision: ").append(String.format("%.2f%%", r.precision * 100)).append("\n");
                sb.append("  Recall: ").append(String.format("%.2f%%", r.recall * 100)).append("\n");
                sb.append("  F1 Score: ").append(String.format("%.2f%%", r.f1Score * 100)).append("\n");

                if (!r.falsePositiveExamples.isEmpty()) {
                    sb.append("  False Positive Examples:\n");
                    for (String ex : r.falsePositiveExamples) {
                        sb.append("    - ").append(ex).append("\n");
                    }
                }
                if (!r.falseNegativeExamples.isEmpty()) {
                    sb.append("  False Negative Examples:\n");
                    for (String ex : r.falseNegativeExamples) {
                        sb.append("    - ").append(ex).append("\n");
                    }
                }
                sb.append("\n");
            }

            Files.write(Paths.get(outputPath), sb.toString().getBytes());
            println("");
            println("Detailed results saved to: " + outputPath);

        } catch (Exception e) {
            printerr("Could not save detailed results: " + e.getMessage());
        }
    }

    // ========================================================================
    // HASH COMPUTATION STRATEGIES
    // ========================================================================

    private String computeHash(Program program, Function func, String strategy) {
        try {
            String normalized = switch (strategy) {
                case "strict" -> computeStrictHash(program, func);
                case "relaxed" -> computeRelaxedHash(program, func);
                case "mnemonic_only" -> computeMnemonicOnlyHash(program, func);
                case "structural" -> computeStructuralHash(program, func);
                case "weighted" -> computeWeightedHash(program, func);
                case "no_prologue" -> computeNoPrologueHash(program, func);
                case "with_strings" -> computeWithStringsHash(program, func);
                case "with_callees" -> computeWithCalleesHash(program, func);
                case "ngram_3" -> computeNgramHash(program, func, 3);
                case "block_hash" -> computeBlockHash(program, func);
                default -> null;
            };

            if (normalized == null || normalized.isEmpty()) return null;

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();

        } catch (Exception e) {
            return null;
        }
    }

    // Strategy 1: STRICT - Current full normalization
    private String computeStrictHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
        AddressSetView body = func.getBody();

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
                        } else if (program.getFunctionManager().getFunctionAt(addr) != null) {
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
        return sb.toString();
    }

    // Strategy 2: RELAXED - Ignore all immediate values
    private String computeRelaxedHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
        AddressSetView body = func.getBody();

        while (iter.hasNext()) {
            Instruction instr = iter.next();
            sb.append(instr.getMnemonicString()).append(" ");

            int numOps = instr.getNumOperands();
            for (int i = 0; i < numOps; i++) {
                for (Object obj : instr.getOpObjects(i)) {
                    if (obj instanceof Address) {
                        Address addr = (Address) obj;
                        if (body.contains(addr)) {
                            sb.append("REL");  // Just mark as relative, no offset
                        } else if (program.getFunctionManager().getFunctionAt(addr) != null) {
                            sb.append("CALL");
                        } else {
                            sb.append("DATA");
                        }
                    } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                        sb.append("IMM");  // All immediates same
                    } else if (obj instanceof Register) {
                        sb.append("REG:").append(((Register) obj).getName());
                    }
                }
                sb.append(",");
            }
            sb.append(";");
        }
        return sb.toString();
    }

    // Strategy 3: MNEMONIC_ONLY - Just instruction sequence
    private String computeMnemonicOnlyHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);

        while (iter.hasNext()) {
            sb.append(iter.next().getMnemonicString()).append(";");
        }
        return sb.toString();
    }

    // Strategy 4: STRUCTURAL - Control flow patterns only
    private String computeStructuralHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);

        int instrCount = 0;
        int callCount = 0;
        int jumpCount = 0;
        int condJumpCount = 0;

        while (iter.hasNext()) {
            Instruction instr = iter.next();
            String mnem = instr.getMnemonicString().toUpperCase();
            instrCount++;

            if (mnem.startsWith("CALL")) {
                callCount++;
                sb.append("C");
            } else if (mnem.startsWith("J")) {
                jumpCount++;
                if (!mnem.equals("JMP")) {
                    condJumpCount++;
                    sb.append("J");  // Conditional jump
                } else {
                    sb.append("U");  // Unconditional jump
                }
            } else if (mnem.equals("RET") || mnem.startsWith("RET")) {
                sb.append("R");
            }
        }

        // Add summary stats
        sb.append("|").append(instrCount / 10);  // Instruction count bucket
        sb.append("|").append(callCount);
        sb.append("|").append(condJumpCount);

        return sb.toString();
    }

    // Strategy 5: WEIGHTED - Weight important instructions more
    private String computeWeightedHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
        AddressSetView body = func.getBody();

        while (iter.hasNext()) {
            Instruction instr = iter.next();
            String mnem = instr.getMnemonicString().toUpperCase();

            // Skip NOPs and padding
            if (mnem.equals("NOP") || mnem.equals("INT3")) continue;

            // Weight by importance
            int weight = getInstructionWeight(mnem);
            if (weight == 0) continue;

            // Repeat mnemonic by weight for hash influence
            for (int w = 0; w < weight; w++) {
                sb.append(mnem).append(" ");
            }

            // Include operands for high-weight instructions
            if (weight >= 3) {
                int numOps = instr.getNumOperands();
                for (int i = 0; i < numOps; i++) {
                    for (Object obj : instr.getOpObjects(i)) {
                        if (obj instanceof Register) {
                            sb.append(((Register) obj).getName()).append(",");
                        }
                    }
                }
            }
            sb.append(";");
        }
        return sb.toString();
    }

    private int getInstructionWeight(String mnem) {
        if (mnem.startsWith("CALL")) return 5;
        if (mnem.startsWith("J") && !mnem.equals("JMP")) return 4;  // Conditional jumps
        if (mnem.equals("CMP") || mnem.equals("TEST")) return 3;
        if (mnem.startsWith("CMOV")) return 3;
        if (mnem.equals("IMUL") || mnem.equals("IDIV") || mnem.equals("DIV") || mnem.equals("MUL")) return 3;
        if (mnem.startsWith("SET")) return 2;
        if (mnem.equals("LEA")) return 2;
        if (mnem.equals("MOV") || mnem.equals("PUSH") || mnem.equals("POP")) return 1;
        if (mnem.equals("NOP") || mnem.equals("INT3")) return 0;
        return 1;
    }

    // Strategy 6: NO_PROLOGUE - Skip function prologue/epilogue
    private String computeNoPrologueHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();
        List<Instruction> instructions = new ArrayList<>();
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);

        while (iter.hasNext()) {
            instructions.add(iter.next());
        }

        if (instructions.size() < 5) {
            // Too small, use all
            for (Instruction instr : instructions) {
                sb.append(instr.getMnemonicString()).append(";");
            }
            return sb.toString();
        }

        // Skip prologue (first 3 instructions if they match pattern)
        int start = 0;
        if (isPrologue(instructions)) {
            start = 3;
        }

        // Skip epilogue (last 2-3 instructions if they match pattern)
        int end = instructions.size();
        if (isEpilogue(instructions)) {
            end = Math.max(start, end - 3);
        }

        // Hash the middle
        AddressSetView body = func.getBody();
        for (int i = start; i < end; i++) {
            Instruction instr = instructions.get(i);
            sb.append(instr.getMnemonicString()).append(" ");

            int numOps = instr.getNumOperands();
            for (int j = 0; j < numOps; j++) {
                for (Object obj : instr.getOpObjects(j)) {
                    if (obj instanceof Register) {
                        sb.append(((Register) obj).getName());
                    } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                        sb.append("IMM");
                    }
                }
                sb.append(",");
            }
            sb.append(";");
        }
        return sb.toString();
    }

    private boolean isPrologue(List<Instruction> instrs) {
        if (instrs.size() < 3) return false;
        String m0 = instrs.get(0).getMnemonicString().toUpperCase();
        String m1 = instrs.get(1).getMnemonicString().toUpperCase();
        // PUSH EBP; MOV EBP,ESP or PUSH RBP; MOV RBP,RSP
        return m0.equals("PUSH") && m1.equals("MOV");
    }

    private boolean isEpilogue(List<Instruction> instrs) {
        if (instrs.size() < 2) return false;
        int n = instrs.size();
        String last = instrs.get(n - 1).getMnemonicString().toUpperCase();
        String prev = instrs.get(n - 2).getMnemonicString().toUpperCase();
        // POP EBP; RET or LEAVE; RET
        return last.startsWith("RET") && (prev.equals("POP") || prev.equals("LEAVE"));
    }

    // Strategy 7: WITH_STRINGS - Include string references
    private String computeWithStringsHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();

        // First, get base hash (relaxed)
        sb.append(computeRelaxedHash(program, func));

        // Then append string references
        sb.append("|STRINGS:");

        Listing listing = program.getListing();
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
                                // Hash the string content (first 32 chars)
                                if (str.length() > 32) str = str.substring(0, 32);
                                sb.append(str.hashCode()).append(",");
                            }
                        }
                    }
                }
            }
        }

        return sb.toString();
    }

    // Strategy 8: WITH_CALLEES - Include callee function names
    private String computeWithCalleesHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();

        // Base hash
        sb.append(computeRelaxedHash(program, func));

        // Append callee names
        sb.append("|CALLEES:");

        FunctionManager funcMgr = program.getFunctionManager();
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);

        while (iter.hasNext()) {
            Instruction instr = iter.next();
            if (instr.getMnemonicString().toUpperCase().startsWith("CALL")) {
                Address[] flows = instr.getFlows();
                if (flows != null) {
                    for (Address target : flows) {
                        Function callee = funcMgr.getFunctionAt(target);
                        if (callee != null) {
                            String name = callee.getName();
                            // Include custom names, use placeholder for FUN_
                            if (!name.startsWith("FUN_")) {
                                sb.append(name).append(",");
                            } else {
                                sb.append("?").append(",");
                            }
                        }
                    }
                }
            }
        }

        return sb.toString();
    }

    // Strategy 9: NGRAM - N-instruction sliding window
    private String computeNgramHash(Program program, Function func, int n) {
        List<String> mnemonics = new ArrayList<>();
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);

        while (iter.hasNext()) {
            mnemonics.add(iter.next().getMnemonicString());
        }

        if (mnemonics.size() < n) {
            return String.join(";", mnemonics);
        }

        // Create sorted set of n-grams for order-independent matching
        Set<String> ngrams = new TreeSet<>();
        for (int i = 0; i <= mnemonics.size() - n; i++) {
            StringBuilder ngram = new StringBuilder();
            for (int j = 0; j < n; j++) {
                ngram.append(mnemonics.get(i + j)).append(",");
            }
            ngrams.add(ngram.toString());
        }

        return String.join(";", ngrams);
    }

    // Strategy 10: BLOCK_HASH - Hash by basic blocks
    private String computeBlockHash(Program program, Function func) {
        StringBuilder sb = new StringBuilder();

        // Simple block detection: split at jumps and targets
        Set<Address> blockStarts = new TreeSet<>();
        blockStarts.add(func.getEntryPoint());

        AddressSetView body = func.getBody();
        InstructionIterator iter = program.getListing().getInstructions(body, true);

        while (iter.hasNext()) {
            Instruction instr = iter.next();
            String mnem = instr.getMnemonicString().toUpperCase();

            // After jumps/calls, next instruction starts new block
            if (mnem.startsWith("J") || mnem.startsWith("CALL") || mnem.startsWith("RET")) {
                Address next = instr.getAddress().add(instr.getLength());
                if (body.contains(next)) {
                    blockStarts.add(next);
                }
                // Jump targets are also block starts
                Address[] flows = instr.getFlows();
                if (flows != null) {
                    for (Address target : flows) {
                        if (body.contains(target)) {
                            blockStarts.add(target);
                        }
                    }
                }
            }
        }

        // Hash each block
        List<Address> blocks = new ArrayList<>(blockStarts);
        sb.append("BLOCKS:").append(blocks.size()).append("|");

        for (int i = 0; i < blocks.size(); i++) {
            Address start = blocks.get(i);
            Address end = (i + 1 < blocks.size()) ? blocks.get(i + 1) : body.getMaxAddress().add(1);

            // Count instructions in block and hash mnemonics
            int blockInstrCount = 0;
            StringBuilder blockHash = new StringBuilder();

            iter = program.getListing().getInstructions(body, true);
            while (iter.hasNext()) {
                Instruction instr = iter.next();
                if (instr.getAddress().compareTo(start) >= 0 && instr.getAddress().compareTo(end) < 0) {
                    blockHash.append(instr.getMnemonicString().charAt(0));
                    blockInstrCount++;
                }
            }

            sb.append(blockInstrCount).append(":").append(blockHash.toString().hashCode()).append(",");
        }

        return sb.toString();
    }
}

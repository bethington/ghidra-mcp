//Analyze functions that don't match by hash to find alternative matching strategies.
//This examines the "false negatives" - same-named functions with different hashes.
//@author GhidraMCP
//@category Analysis
//@keybinding
//@menupath D2.Analyze Unmatched Functions
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
import java.util.*;
import java.util.stream.*;

public class AnalyzeUnmatchedFunctions extends GhidraScript {

    // Function metadata for comparison
    static class FunctionInfo {
        String program;
        String name;
        String address;
        String hash;
        int instructionCount;
        int byteSize;
        String returnType;
        int paramCount;
        List<String> paramTypes;
        Set<String> calleeNames;      // Named functions called
        Set<String> stringRefs;       // String constants referenced
        Set<String> importCalls;      // External/import calls
        String callingConvention;
        int basicBlockCount;
        String signatureHash;         // Hash of signature only
        String calleeHash;            // Hash of callee names

        FunctionInfo(String program, String name, String address) {
            this.program = program;
            this.name = name;
            this.address = address;
            this.paramTypes = new ArrayList<>();
            this.calleeNames = new TreeSet<>();
            this.stringRefs = new TreeSet<>();
            this.importCalls = new TreeSet<>();
        }
    }

    // Track all functions by name
    private Map<String, List<FunctionInfo>> functionsByName = new HashMap<>();

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open!");
            return;
        }

        DomainFile currentFile = currentProgram.getDomainFile();
        DomainFolder parentFolder = currentFile.getParent();

        println("=".repeat(70));
        println("ANALYZE UNMATCHED FUNCTIONS");
        println("=".repeat(70));
        println("Finding functions with same name but different hashes...");
        println("");

        // Get all programs
        List<DomainFile> programFiles = new ArrayList<>();
        for (DomainFile file : parentFolder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                programFiles.add(file);
            }
        }

        println("Processing " + programFiles.size() + " programs...");
        println("");

        // Collect all function info
        for (DomainFile file : programFiles) {
            if (monitor.isCancelled()) break;
            collectFunctionInfo(file);
        }

        // Find functions that appear in multiple programs with different hashes
        println("");
        println("=".repeat(70));
        println("ANALYSIS OF UNMATCHED FUNCTIONS");
        println("=".repeat(70));
        println("");

        int totalUnmatched = 0;
        int matchableBySignature = 0;
        int matchableByCallees = 0;
        int matchableByStrings = 0;
        int matchableBySize = 0;
        int matchableByCombined = 0;
        int trulyDifferent = 0;

        StringBuilder detailedReport = new StringBuilder();

        for (Map.Entry<String, List<FunctionInfo>> entry : functionsByName.entrySet()) {
            String funcName = entry.getKey();
            List<FunctionInfo> instances = entry.getValue();

            // Skip if only in one program or if it's a default name
            if (instances.size() < 2 || funcName.startsWith("FUN_")) continue;

            // Check if all hashes are the same
            Set<String> uniqueHashes = instances.stream()
                .map(f -> f.hash)
                .collect(Collectors.toSet());

            if (uniqueHashes.size() == 1) continue; // All match, skip

            totalUnmatched++;

            // Analyze what DOES match
            Set<String> uniqueSignatures = instances.stream()
                .map(f -> f.signatureHash)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

            Set<String> uniqueCalleeHashes = instances.stream()
                .map(f -> f.calleeHash)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

            Set<String> uniqueStringSets = instances.stream()
                .map(f -> String.join(",", f.stringRefs))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());

            // Size similarity (within 20%)
            int minSize = instances.stream().mapToInt(f -> f.instructionCount).min().orElse(0);
            int maxSize = instances.stream().mapToInt(f -> f.instructionCount).max().orElse(0);
            boolean sizeSimilar = maxSize > 0 && (maxSize - minSize) <= maxSize * 0.2;

            boolean sigMatch = uniqueSignatures.size() == 1;
            boolean calleeMatch = uniqueCalleeHashes.size() == 1 &&
                instances.stream().anyMatch(f -> !f.calleeNames.isEmpty());
            boolean stringMatch = uniqueStringSets.size() == 1 &&
                instances.stream().anyMatch(f -> !f.stringRefs.isEmpty());

            if (sigMatch) matchableBySignature++;
            if (calleeMatch) matchableByCallees++;
            if (stringMatch) matchableByStrings++;
            if (sizeSimilar) matchableBySize++;

            // Combined: signature + (callees OR strings OR size)
            if (sigMatch && (calleeMatch || stringMatch || sizeSimilar)) {
                matchableByCombined++;
            } else if (!sigMatch && !calleeMatch && !stringMatch && !sizeSimilar) {
                trulyDifferent++;
            }

            // Detailed report for first 20
            if (totalUnmatched <= 20) {
                detailedReport.append("\n").append("-".repeat(60)).append("\n");
                detailedReport.append("Function: ").append(funcName).append("\n");
                detailedReport.append("Instances: ").append(instances.size()).append("\n");
                detailedReport.append("Unique hashes: ").append(uniqueHashes.size()).append("\n");
                detailedReport.append("Signature match: ").append(sigMatch ? "YES" : "NO").append("\n");
                detailedReport.append("Callee match: ").append(calleeMatch ? "YES" : "NO").append("\n");
                detailedReport.append("String match: ").append(stringMatch ? "YES" : "NO").append("\n");
                detailedReport.append("Size similar: ").append(sizeSimilar ? "YES" : "NO").append("\n");

                // Show details per instance
                for (FunctionInfo info : instances) {
                    detailedReport.append(String.format("  [%s] %s: %d instrs, %d params, %s return\n",
                        info.program, info.address, info.instructionCount,
                        info.paramCount, info.returnType));
                    if (!info.calleeNames.isEmpty()) {
                        detailedReport.append("    Callees: ").append(
                            info.calleeNames.stream().limit(5).collect(Collectors.joining(", ")));
                        if (info.calleeNames.size() > 5) {
                            detailedReport.append(" + ").append(info.calleeNames.size() - 5).append(" more");
                        }
                        detailedReport.append("\n");
                    }
                    if (!info.stringRefs.isEmpty()) {
                        detailedReport.append("    Strings: ").append(
                            info.stringRefs.stream().limit(3).collect(Collectors.joining(", ")));
                        if (info.stringRefs.size() > 3) {
                            detailedReport.append(" + ").append(info.stringRefs.size() - 3).append(" more");
                        }
                        detailedReport.append("\n");
                    }
                }
            }
        }

        // Summary
        println("SUMMARY");
        println("-".repeat(40));
        println("Total functions with hash mismatches: " + totalUnmatched);
        println("");
        println("Alternative matching potential:");
        println("  Matchable by signature alone:    " + matchableBySignature +
            String.format(" (%.1f%%)", 100.0 * matchableBySignature / Math.max(1, totalUnmatched)));
        println("  Matchable by callee names:       " + matchableByCallees +
            String.format(" (%.1f%%)", 100.0 * matchableByCallees / Math.max(1, totalUnmatched)));
        println("  Matchable by string refs:        " + matchableByStrings +
            String.format(" (%.1f%%)", 100.0 * matchableByStrings / Math.max(1, totalUnmatched)));
        println("  Size similar (within 20%):       " + matchableBySize +
            String.format(" (%.1f%%)", 100.0 * matchableBySize / Math.max(1, totalUnmatched)));
        println("");
        println("  Matchable by combined approach:  " + matchableByCombined +
            String.format(" (%.1f%%)", 100.0 * matchableByCombined / Math.max(1, totalUnmatched)));
        println("  Truly different (no match):      " + trulyDifferent +
            String.format(" (%.1f%%)", 100.0 * trulyDifferent / Math.max(1, totalUnmatched)));

        // Calculate overall match rate
        int totalDocumentedPairs = 0;
        int hashMatchedPairs = 0;
        for (List<FunctionInfo> instances : functionsByName.values()) {
            if (instances.size() < 2) continue;
            String firstName = instances.get(0).name;
            if (firstName.startsWith("FUN_")) continue;

            // Count pairs
            int n = instances.size();
            totalDocumentedPairs += n * (n - 1) / 2;

            // Group by hash
            Map<String, List<FunctionInfo>> byHash = instances.stream()
                .collect(Collectors.groupingBy(f -> f.hash));
            for (List<FunctionInfo> sameHash : byHash.values()) {
                int m = sameHash.size();
                if (m >= 2) {
                    hashMatchedPairs += m * (m - 1) / 2;
                }
            }
        }

        println("");
        println("OVERALL COVERAGE");
        println("-".repeat(40));
        println("Total documented function pairs: " + totalDocumentedPairs);
        println("Pairs matched by hash: " + hashMatchedPairs +
            String.format(" (%.1f%%)", 100.0 * hashMatchedPairs / Math.max(1, totalDocumentedPairs)));
        println("Pairs needing alternative match: " + (totalDocumentedPairs - hashMatchedPairs) +
            String.format(" (%.1f%%)", 100.0 * (totalDocumentedPairs - hashMatchedPairs) / Math.max(1, totalDocumentedPairs)));

        // Projected improvement
        int additionalMatches = matchableByCombined;
        int projectedTotal = hashMatchedPairs + additionalMatches;
        println("");
        println("PROJECTED MULTI-PHASE IMPROVEMENT");
        println("-".repeat(40));
        println("Phase 1 (hash): " + hashMatchedPairs + " pairs");
        println("Phase 2 (sig+callees/strings): +" + additionalMatches + " pairs");
        println("Projected total: " + projectedTotal +
            String.format(" (%.1f%%)", 100.0 * projectedTotal / Math.max(1, totalDocumentedPairs)));

        // Print detailed report
        println("");
        println("=".repeat(70));
        println("DETAILED ANALYSIS (First 20 unmatched)");
        println("=".repeat(70));
        println(detailedReport.toString());

        // Save full report
        saveReport(totalUnmatched, matchableBySignature, matchableByCallees,
                   matchableByStrings, matchableBySize, matchableByCombined, trulyDifferent,
                   totalDocumentedPairs, hashMatchedPairs, detailedReport.toString());
    }

    private void collectFunctionInfo(DomainFile file) {
        String programName = file.getName();
        println("  Processing: " + programName);

        Program program = null;
        try {
            program = (Program) file.getDomainObject(this, false, false, monitor);

            FunctionManager funcMgr = program.getFunctionManager();
            Listing listing = program.getListing();
            FunctionIterator funcIter = funcMgr.getFunctions(true);

            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                if (func.isThunk()) continue;

                String funcName = func.getName();
                FunctionInfo info = new FunctionInfo(programName, funcName,
                    func.getEntryPoint().toString());

                // Basic metrics
                info.instructionCount = countInstructions(listing, func);
                info.byteSize = (int) func.getBody().getNumAddresses();

                // Signature info
                DataType retType = func.getReturnType();
                info.returnType = retType != null ? retType.getName() : "void";
                info.paramCount = func.getParameterCount();
                info.callingConvention = func.getCallingConventionName();

                for (Parameter p : func.getParameters()) {
                    DataType pType = p.getDataType();
                    info.paramTypes.add(pType != null ? pType.getName() : "undefined");
                }

                // Compute signature hash
                info.signatureHash = computeSignatureHash(info);

                // Collect callees
                collectCallees(program, func, info);
                info.calleeHash = computeCalleeHash(info);

                // Collect string references
                collectStrings(program, func, info);

                // Compute strict hash
                info.hash = computeStrictHash(program, func);

                // Estimate basic blocks
                info.basicBlockCount = estimateBasicBlocks(listing, func);

                functionsByName.computeIfAbsent(funcName, k -> new ArrayList<>()).add(info);
            }

        } catch (Exception e) {
            printerr("    Error: " + e.getMessage());
        } finally {
            if (program != null) {
                program.release(this);
            }
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

    private int estimateBasicBlocks(Listing listing, Function func) {
        int blocks = 1;
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

    private String computeSignatureHash(FunctionInfo info) {
        StringBuilder sb = new StringBuilder();
        sb.append(info.returnType).append("|");
        sb.append(info.paramCount).append("|");
        sb.append(info.callingConvention).append("|");
        for (String pType : info.paramTypes) {
            sb.append(pType).append(",");
        }
        return Integer.toHexString(sb.toString().hashCode());
    }

    private void collectCallees(Program program, Function func, FunctionInfo info) {
        try {
            FunctionManager funcMgr = program.getFunctionManager();
            Listing listing = program.getListing();
            InstructionIterator iter = listing.getInstructions(func.getBody(), true);

            while (iter.hasNext()) {
                Instruction instr = iter.next();
                if (instr.getMnemonicString().toUpperCase().startsWith("CALL")) {
                    Address[] flows = instr.getFlows();
                    if (flows != null) {
                        for (Address target : flows) {
                            Function callee = funcMgr.getFunctionAt(target);
                            if (callee != null) {
                                String calleeName = callee.getName();
                                if (!calleeName.startsWith("FUN_")) {
                                    info.calleeNames.add(calleeName);
                                }
                                if (callee.isExternal()) {
                                    info.importCalls.add(calleeName);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Continue
        }
    }

    private String computeCalleeHash(FunctionInfo info) {
        if (info.calleeNames.isEmpty()) return null;
        return Integer.toHexString(String.join(",", info.calleeNames).hashCode());
    }

    private void collectStrings(Program program, Function func, FunctionInfo info) {
        try {
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
                                    if (str.length() >= 4 && str.length() <= 100) {
                                        info.stringRefs.add(str);
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
    }

    private String computeStrictHash(Program program, Function func) {
        try {
            StringBuilder sb = new StringBuilder();
            Listing listing = program.getListing();
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

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(sb.toString().getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();

        } catch (Exception e) {
            return "error";
        }
    }

    private void saveReport(int totalUnmatched, int matchableBySignature, int matchableByCallees,
                           int matchableByStrings, int matchableBySize, int matchableByCombined,
                           int trulyDifferent, int totalPairs, int hashMatched, String detailed) {
        try {
            String outputPath = System.getProperty("user.home") +
                File.separator + "unmatched_functions_analysis.txt";

            StringBuilder sb = new StringBuilder();
            sb.append("Unmatched Functions Analysis\n");
            sb.append("=".repeat(70)).append("\n\n");
            sb.append("Total functions with hash mismatches: ").append(totalUnmatched).append("\n\n");
            sb.append("Alternative matching potential:\n");
            sb.append("  Matchable by signature:     ").append(matchableBySignature).append("\n");
            sb.append("  Matchable by callees:       ").append(matchableByCallees).append("\n");
            sb.append("  Matchable by strings:       ").append(matchableByStrings).append("\n");
            sb.append("  Matchable by size:          ").append(matchableBySize).append("\n");
            sb.append("  Matchable by combined:      ").append(matchableByCombined).append("\n");
            sb.append("  Truly different:            ").append(trulyDifferent).append("\n\n");
            sb.append("Overall coverage:\n");
            sb.append("  Total pairs: ").append(totalPairs).append("\n");
            sb.append("  Hash matched: ").append(hashMatched).append("\n");
            sb.append("  Match rate: ").append(String.format("%.1f%%", 100.0 * hashMatched / Math.max(1, totalPairs))).append("\n\n");
            sb.append("Detailed Analysis:\n");
            sb.append(detailed);

            Files.write(Paths.get(outputPath), sb.toString().getBytes());
            println("");
            println("Full report saved to: " + outputPath);

        } catch (Exception e) {
            printerr("Could not save report: " + e.getMessage());
        }
    }
}

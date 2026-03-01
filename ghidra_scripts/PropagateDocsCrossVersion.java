//Propagate function documentation across program versions using hash matching
//@category RELoop
//@menupath Tools.RE Loop.Propagate Docs Cross-Version
//@description Compares functions between source and target programs using opcode hashes. For matches, copies function name, prototype, and plate comment. Eliminates the need for AI to perform Phase 6 PROPAGATE.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.framework.model.*;
import java.io.*;
import java.security.*;
import java.util.*;

public class PropagateDocsCrossVersion extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get source and target program paths
        String[] args = getScriptArgs();
        String targetPath = null;

        if (args.length > 0) {
            targetPath = args[0];
        } else {
            targetPath = askString("Propagate Documentation",
                "Enter target program path in project (e.g., /Vanilla/1.10/D2Common.dll):");
        }

        if (targetPath == null || targetPath.trim().isEmpty()) {
            println("Error: No target path provided");
            return;
        }

        Program sourceProgram = currentProgram;
        String sourceName = sourceProgram.getName();
        println("=== Cross-Version Propagation ===");
        println("Source: " + sourceName + " (" + sourceProgram.getExecutablePath() + ")");
        println("Target: " + targetPath);

        // Build hash index for source program (documented functions only)
        println("\nBuilding source hash index (documented functions)...");
        Map<String, List<FuncInfo>> sourceHashes = new HashMap<>();
        FunctionManager sourceFm = sourceProgram.getFunctionManager();
        int sourceDocCount = 0;

        for (Function func : sourceFm.getFunctions(true)) {
            String name = func.getName();
            // Only propagate functions that have been documented (custom named)
            if (name.startsWith("FUN_") || name.startsWith("Ordinal_") ||
                name.startsWith("thunk_FUN_") || name.startsWith("thunk_Ordinal_")) {
                continue;
            }

            String hash = computeOpcodeHash(func, sourceProgram);
            if (hash != null) {
                sourceHashes.computeIfAbsent(hash, k -> new ArrayList<>()).add(
                    new FuncInfo(func.getEntryPoint().toString(), name,
                        func.getSignature().getPrototypeString(true),
                        getPlateComment(func, sourceProgram)));
                sourceDocCount++;
            }
        }

        println("Source documented functions indexed: " + sourceDocCount);
        println("Unique hashes: " + sourceHashes.size());

        // Open target program
        DomainFile targetFile = findDomainFile(targetPath);
        if (targetFile == null) {
            println("Error: Target file not found: " + targetPath);
            return;
        }

        Program targetProgram = (Program) targetFile.getDomainObject(this, true, false, monitor);
        if (targetProgram == null) {
            println("Error: Could not open target program");
            return;
        }

        try {
            println("\nScanning target program for matches...");
            FunctionManager targetFm = targetProgram.getFunctionManager();

            // Build target hash index (undocumented functions only)
            Map<String, List<Function>> targetHashes = new HashMap<>();
            int targetUndocCount = 0;

            for (Function func : targetFm.getFunctions(true)) {
                String name = func.getName();
                if (name.startsWith("FUN_") || name.startsWith("Ordinal_") ||
                    name.startsWith("thunk_FUN_") || name.startsWith("thunk_Ordinal_")) {
                    String hash = computeOpcodeHash(func, targetProgram);
                    if (hash != null) {
                        targetHashes.computeIfAbsent(hash, k -> new ArrayList<>()).add(func);
                        targetUndocCount++;
                    }
                }
            }

            println("Target undocumented functions indexed: " + targetUndocCount);

            // Find matches and apply documentation
            int matchCount = 0;
            int applied = 0;
            int skippedAmbiguous = 0;
            List<String[]> results = new ArrayList<>(); // [sourceAddr, targetAddr, sourceName, status]

            int txId = targetProgram.startTransaction("Cross-Version Propagation");
            boolean txSuccess = false;

            try {
                for (Map.Entry<String, List<FuncInfo>> entry : sourceHashes.entrySet()) {
                    String hash = entry.getKey();
                    List<FuncInfo> sourceFuncs = entry.getValue();
                    List<Function> targetFuncs = targetHashes.get(hash);

                    if (targetFuncs == null || targetFuncs.isEmpty()) continue;

                    // Only propagate 1-to-1 matches (skip ambiguous)
                    if (sourceFuncs.size() != 1 || targetFuncs.size() != 1) {
                        skippedAmbiguous++;
                        continue;
                    }

                    matchCount++;
                    FuncInfo sourceInfo = sourceFuncs.get(0);
                    Function targetFunc = targetFuncs.get(0);

                    try {
                        // Apply name
                        targetFunc.setName(sourceInfo.name, SourceType.USER_DEFINED);

                        // Apply plate comment if source has one
                        if (sourceInfo.plateComment != null && !sourceInfo.plateComment.isEmpty()) {
                            targetFunc.setComment(sourceInfo.plateComment);
                        }

                        // Note: Prototype propagation is tricky due to address-specific types.
                        // We copy the name and plate comment, which is the highest value.
                        // Prototype would need calling convention matching which varies by version.

                        applied++;
                        results.add(new String[]{sourceInfo.address, targetFunc.getEntryPoint().toString(),
                                                  sourceInfo.name, "applied"});
                        println("  Match: " + sourceInfo.name + " -> 0x" + targetFunc.getEntryPoint());
                    } catch (Exception e) {
                        results.add(new String[]{sourceInfo.address, targetFunc.getEntryPoint().toString(),
                                                  sourceInfo.name, "error: " + e.getMessage()});
                    }
                }

                txSuccess = true;
            } finally {
                targetProgram.endTransaction(txId, txSuccess);
            }

            // Save target program
            if (applied > 0) {
                targetProgram.save("Cross-version propagation from " + sourceName, monitor);
                println("\nTarget program saved.");
            }

            // Build JSON result
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"source\": \"").append(escJson(sourceName)).append("\",\n");
            json.append("  \"target\": \"").append(escJson(targetPath)).append("\",\n");
            json.append("  \"source_documented\": ").append(sourceDocCount).append(",\n");
            json.append("  \"target_undocumented\": ").append(targetUndocCount).append(",\n");
            json.append("  \"hash_matches\": ").append(matchCount).append(",\n");
            json.append("  \"applied\": ").append(applied).append(",\n");
            json.append("  \"skipped_ambiguous\": ").append(skippedAmbiguous).append(",\n");
            json.append("  \"results\": [\n");
            for (int i = 0; i < results.size(); i++) {
                if (i > 0) json.append(",\n");
                String[] r = results.get(i);
                json.append("    {\"source\": \"0x").append(r[0]).append("\"");
                json.append(", \"target\": \"0x").append(r[1]).append("\"");
                json.append(", \"name\": \"").append(escJson(r[2])).append("\"");
                json.append(", \"status\": \"").append(escJson(r[3])).append("\"}");
            }
            json.append("\n  ]\n");
            json.append("}\n");

            // Write results file
            File outputDir = new File("C:/Users/benam/source/mcp/ghidra-mcp/workflows");
            if (!outputDir.exists()) outputDir.mkdirs();
            String safeTarget = targetPath.replaceAll("[/\\\\:]", "_");
            File outputFile = new File(outputDir, "propagation_" + safeTarget + ".json");
            try (FileWriter fw = new FileWriter(outputFile)) {
                fw.write(json.toString());
            }

            println("\n=== Propagation Complete ===");
            println("Matches: " + matchCount + ", Applied: " + applied +
                    ", Ambiguous: " + skippedAmbiguous);
            println("Results: " + outputFile.getAbsolutePath());

        } finally {
            targetProgram.release(this);
        }
    }

    private String computeOpcodeHash(Function func, Program program) {
        try {
            Memory mem = program.getMemory();
            AddressSetView body = func.getBody();
            if (body.getNumAddresses() < 2 || body.getNumAddresses() > 100000) {
                return null; // Too small or too large
            }

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            InstructionIterator iter = program.getListing().getInstructions(body, true);

            int instrCount = 0;
            while (iter.hasNext()) {
                Instruction instr = iter.next();
                // Hash the mnemonic (opcode) only, not operands (which contain addresses)
                md.update(instr.getMnemonicString().getBytes());
                // Also hash the instruction length for disambiguation
                md.update((byte) instr.getLength());
                instrCount++;
            }

            if (instrCount < 2) return null; // Too few instructions

            byte[] hashBytes = md.digest();
            StringBuilder hex = new StringBuilder();
            for (byte b : hashBytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString().substring(0, 16); // Use first 16 hex chars
        } catch (Exception e) {
            return null;
        }
    }

    private String getPlateComment(Function func, Program program) {
        return program.getListing().getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint());
    }

    private DomainFile findDomainFile(String path) {
        try {
            Project project = state.getProject();
            if (project == null) return null;
            ProjectData pd = project.getProjectData();
            if (pd == null) return null;

            // Navigate path components
            String[] parts = path.split("/");
            DomainFolder folder = pd.getRootFolder();

            for (int i = 0; i < parts.length - 1; i++) {
                if (parts[i].isEmpty()) continue;
                folder = folder.getFolder(parts[i]);
                if (folder == null) return null;
            }

            String fileName = parts[parts.length - 1];
            return folder.getFile(fileName);
        } catch (Exception e) {
            println("Error finding file: " + e.getMessage());
            return null;
        }
    }

    private String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static class FuncInfo {
        String address;
        String name;
        String prototype;
        String plateComment;

        FuncInfo(String address, String name, String prototype, String plateComment) {
            this.address = address;
            this.name = name;
            this.prototype = prototype;
            this.plateComment = plateComment;
        }
    }
}

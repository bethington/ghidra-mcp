// Full Docs
//
// Matches functions by name between source and target programs. Copies plate comments, variable names, variable types, and EOL comments from documented source to underdocumented target.
//
// Usage: Args: 'apply /source/path /target/path' (or omit 'apply' for dry run).
// Output: Copies comprehensive documentation between matched functions.
//
// @author Ben Ethington
// @category Diablo 2.Propagation
// @description Propagate full documentation between program versions
// @menupath Diablo 2.Propagation.Full Docs

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.framework.model.*;
import java.io.*;
import java.security.*;
import java.util.*;

public class Propagate_FullDocs extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        boolean dryRun = true;
        String sourcePath = null;
        String targetPath = null;

        for (String arg : args) {
            if (arg.equalsIgnoreCase("apply")) {
                dryRun = false;
            } else if (arg.startsWith("/") && sourcePath == null) {
                sourcePath = arg;
            } else if (arg.startsWith("/") && targetPath == null) {
                targetPath = arg;
            }
        }

        if (sourcePath == null || targetPath == null) {
            printerr("Usage: apply /source/path /target/path");
            printerr("Example: apply /Vanilla/1.13d/Fog.dll /Vanilla/1.13c/Fog.dll");
            return;
        }

        println("=== Propagate Full Documentation ===");
        println("Source: " + sourcePath);
        println("Target: " + targetPath);
        println("Mode: " + (dryRun ? "DRY RUN" : "APPLY"));

        // Open both programs
        DomainFolder root = state.getProject().getProjectData().getRootFolder();
        DomainFile srcFile = findDomainFile(root, sourcePath);
        DomainFile tgtFile = findDomainFile(root, targetPath);

        if (srcFile == null) { printerr("Source not found: " + sourcePath); return; }
        if (tgtFile == null) { printerr("Target not found: " + targetPath); return; }

        Program srcProg = (Program) srcFile.getDomainObject(this, true, false, monitor);
        Program tgtProg = (Program) tgtFile.getDomainObject(this, true, false, monitor);

        try {
            propagate(srcProg, tgtProg, dryRun);
        } finally {
            srcProg.release(this);
            tgtProg.release(this);
        }
    }

    private void propagate(Program srcProg, Program tgtProg, boolean dryRun) throws Exception {
        FunctionManager srcFm = srcProg.getFunctionManager();
        FunctionManager tgtFm = tgtProg.getFunctionManager();
        Listing srcListing = srcProg.getListing();
        Listing tgtListing = tgtProg.getListing();

        // Build source indices: name->function AND hash->function
        Map<String, Function> srcByName = new HashMap<>();
        Map<String, Function> srcByHash = new HashMap<>();
        int srcWithPlate = 0;
        int srcIndexed = 0;
        for (Function f : srcFm.getFunctions(true)) {
            String name = f.getName();
            if (name.startsWith("FUN_") || name.startsWith("Ordinal_")) continue;

            // Index any named function that has documentation worth propagating:
            // plate comment, resolved return type, or resolved variable types
            String plate = getPlate(f, srcListing);
            boolean hasPlate = plate != null && !plate.isEmpty();
            boolean hasReturnType = !f.getReturnType().getName().startsWith("undefined");

            if (hasPlate || hasReturnType) {
                if (!srcByName.containsKey(name)) {
                    srcByName.put(name, f);
                    srcIndexed++;
                    if (hasPlate) srcWithPlate++;
                }
                String hash = computeOpcodeHash(f, srcProg);
                if (hash != null && !srcByHash.containsKey(hash)) {
                    srcByHash.put(hash, f);
                }
            }
        }
        println("Source functions indexed: " + srcIndexed + " (" + srcWithPlate + " with plate comments)");
        println("Source unique hashes indexed: " + srcByHash.size());

        // Scan target for functions missing plate comments
        int tgtTotal = 0;
        int tgtMissingPlate = 0;
        int matched = 0;
        int matchedByName = 0;
        int matchedByHash = 0;
        int platesApplied = 0;
        int eolApplied = 0;
        int varNamesApplied = 0;
        int varTypesApplied = 0;
        int returnTypesApplied = 0;
        int callingConvsApplied = 0;

        int txId = -1;
        if (!dryRun) {
            txId = tgtProg.startTransaction("Propagate Full Docs");
        }

        try {
            for (Function tgtFunc : tgtFm.getFunctions(true)) {
                if (monitor.isCancelled()) break;
                tgtTotal++;

                String tgtName = tgtFunc.getName();
                if (tgtName.startsWith("FUN_") || tgtName.startsWith("Ordinal_")) continue;

                String tgtPlate = getPlate(tgtFunc, tgtListing);
                boolean needsPlate = (tgtPlate == null || tgtPlate.isEmpty());
                boolean needsReturnType = tgtFunc.getReturnType().getName().startsWith("undefined");
                boolean needsVarTypes = hasUndefinedVariables(tgtFunc);

                // Check if target needs any documentation at all
                if (!needsPlate && !needsReturnType && !needsVarTypes) continue;
                if (needsPlate) tgtMissingPlate++;

                // Try name match first, then hash fallback
                Function srcFunc = srcByName.get(tgtName);
                if (srcFunc != null) {
                    matchedByName++;
                } else {
                    // Hash-based fallback
                    String tgtHash = computeOpcodeHash(tgtFunc, tgtProg);
                    if (tgtHash != null) {
                        srcFunc = srcByHash.get(tgtHash);
                        if (srcFunc != null) matchedByHash++;
                    }
                }
                if (srcFunc == null) continue;
                matched++;

                if (!dryRun) {
                    // 1. Copy plate comment
                    if (needsPlate) {
                        String srcPlate = getPlate(srcFunc, srcListing);
                        if (srcPlate != null && !srcPlate.isEmpty()) {
                            tgtFunc.setComment(srcPlate);
                            platesApplied++;
                        }
                    }

                    // 2. Copy return type if target has undefined return type
                    if (needsReturnType) {
                        DataType srcReturnType = srcFunc.getReturnType();
                        if (!srcReturnType.getName().startsWith("undefined")) {
                            try {
                                tgtFunc.setReturnType(srcReturnType, SourceType.USER_DEFINED);
                                returnTypesApplied++;
                            } catch (Exception e) { /* skip */ }
                        }
                    }

                    // 3. Copy calling convention if target is missing one
                    try {
                        String srcConv = srcFunc.getCallingConventionName();
                        String tgtConv = tgtFunc.getCallingConventionName();
                        if (srcConv != null && !srcConv.equals(tgtConv) && !"unknown".equals(srcConv)) {
                            tgtFunc.setCallingConvention(srcConv);
                            callingConvsApplied++;
                        }
                    } catch (Exception e) { /* skip */ }

                    // 4. Copy EOL/PRE comments from source instructions
                    eolApplied += copyEolComments(srcFunc, tgtFunc, srcProg, tgtProg);

                    // 5. Copy variable names and types
                    int[] varResults = copyVariables(srcFunc, tgtFunc);
                    varNamesApplied += varResults[0];
                    varTypesApplied += varResults[1];
                }

                if (tgtTotal % 500 == 0) {
                    println("  Processed " + tgtTotal + " functions, " + matched + " matched...");
                }
            }
        } finally {
            if (!dryRun && txId != -1) {
                tgtProg.endTransaction(txId, true);
            }
        }

        // Save
        if (!dryRun && platesApplied > 0) {
            tgtProg.save(tgtProg.getName() + " - full doc propagation", monitor);
            println("Target program saved.");
        }

        println("\n=== " + (dryRun ? "Dry Run" : "Apply") + " Complete ===");
        println("Target functions scanned: " + tgtTotal);
        println("Missing plate comments:   " + tgtMissingPlate);
        println("Matched by name:          " + matchedByName);
        println("Matched by hash:          " + matchedByHash);
        println("Total matches:            " + matched);
        if (!dryRun) {
            println("Plate comments applied:   " + platesApplied);
            println("Return types applied:     " + returnTypesApplied);
            println("Calling convs applied:    " + callingConvsApplied);
            println("EOL comments applied:     " + eolApplied);
            println("Variable names applied:   " + varNamesApplied);
            println("Variable types applied:   " + varTypesApplied);
        }

        // Write report
        File outputDir = new File("C:/Users/benam/source/mcp/ghidra-mcp/workflows");
        if (!outputDir.exists()) outputDir.mkdirs();
        String safeName = tgtProg.getName().replaceAll("[^a-zA-Z0-9._-]", "_");
        String suffix = dryRun ? "_dryrun" : "_applied";
        File reportFile = new File(outputDir, "full_propagation_" + safeName + suffix + ".json");
        try (FileWriter fw = new FileWriter(reportFile)) {
            fw.write("{\n");
            fw.write("  \"source\": \"" + srcProg.getName() + "\",\n");
            fw.write("  \"target\": \"" + tgtProg.getName() + "\",\n");
            fw.write("  \"target_total\": " + tgtTotal + ",\n");
            fw.write("  \"missing_plate\": " + tgtMissingPlate + ",\n");
            fw.write("  \"matched\": " + matched + ",\n");
            fw.write("  \"matched_by_name\": " + matchedByName + ",\n");
            fw.write("  \"matched_by_hash\": " + matchedByHash + ",\n");
            fw.write("  \"plates_applied\": " + platesApplied + ",\n");
            fw.write("  \"return_types_applied\": " + returnTypesApplied + ",\n");
            fw.write("  \"calling_convs_applied\": " + callingConvsApplied + ",\n");
            fw.write("  \"eol_applied\": " + eolApplied + ",\n");
            fw.write("  \"var_names_applied\": " + varNamesApplied + ",\n");
            fw.write("  \"var_types_applied\": " + varTypesApplied + "\n");
            fw.write("}\n");
        }
        println("Report: " + reportFile.getAbsolutePath());
    }

    private int copyEolComments(Function srcFunc, Function tgtFunc,
                                 Program srcProg, Program tgtProg) {
        int count = 0;
        try {
            // Get instruction iterators for both functions
            Listing srcListing = srcProg.getListing();
            Listing tgtListing = tgtProg.getListing();
            InstructionIterator srcIter = srcListing.getInstructions(srcFunc.getBody(), true);
            InstructionIterator tgtIter = tgtListing.getInstructions(tgtFunc.getBody(), true);

            // Walk both iterators in parallel (same instruction sequence for hash-matched functions)
            while (srcIter.hasNext() && tgtIter.hasNext()) {
                Instruction srcInstr = srcIter.next();
                Instruction tgtInstr = tgtIter.next();

                String eol = srcInstr.getComment(CodeUnit.EOL_COMMENT);
                if (eol != null && !eol.isEmpty()) {
                    String existing = tgtInstr.getComment(CodeUnit.EOL_COMMENT);
                    if (existing == null || existing.isEmpty()) {
                        tgtInstr.setComment(CodeUnit.EOL_COMMENT, eol);
                        count++;
                    }
                }

                // Also copy PRE comments
                String pre = srcInstr.getComment(CodeUnit.PRE_COMMENT);
                if (pre != null && !pre.isEmpty()) {
                    String existing = tgtInstr.getComment(CodeUnit.PRE_COMMENT);
                    if (existing == null || existing.isEmpty()) {
                        tgtInstr.setComment(CodeUnit.PRE_COMMENT, pre);
                    }
                }
            }
        } catch (Exception e) {
            // Instruction count mismatch or other issues - skip silently
        }
        return count;
    }

    private int[] copyVariables(Function srcFunc, Function tgtFunc) {
        int namesApplied = 0;
        int typesApplied = 0;

        try {
            // Copy parameter names and types
            Parameter[] srcParams = srcFunc.getParameters();
            Parameter[] tgtParams = tgtFunc.getParameters();
            int paramCount = Math.min(srcParams.length, tgtParams.length);

            for (int i = 0; i < paramCount; i++) {
                String srcName = srcParams[i].getName();
                String tgtName = tgtParams[i].getName();

                // Copy name if target has generic name
                if (isGenericName(tgtName) && !isGenericName(srcName)) {
                    try {
                        tgtParams[i].setName(srcName, SourceType.USER_DEFINED);
                        namesApplied++;
                    } catch (Exception e) { /* skip */ }
                }

                // Copy type if target has undefined type
                String tgtType = tgtParams[i].getDataType().getName();
                if (tgtType.startsWith("undefined")) {
                    DataType srcType = srcParams[i].getDataType();
                    if (!srcType.getName().startsWith("undefined")) {
                        try {
                            tgtParams[i].setDataType(srcType, SourceType.USER_DEFINED);
                            typesApplied++;
                        } catch (Exception e) { /* skip */ }
                    }
                }
            }

            // Copy local variable names and types
            Variable[] srcLocals = srcFunc.getLocalVariables();
            Variable[] tgtLocals = tgtFunc.getLocalVariables();

            // Build lookup by storage offset for locals
            Map<String, Variable> srcLocalMap = new HashMap<>();
            for (Variable v : srcLocals) {
                srcLocalMap.put(v.getVariableStorage().toString(), v);
            }

            for (Variable tgtLocal : tgtLocals) {
                String storage = tgtLocal.getVariableStorage().toString();
                Variable srcLocal = srcLocalMap.get(storage);
                if (srcLocal == null) continue;

                // Copy name
                String tgtName = tgtLocal.getName();
                String srcName = srcLocal.getName();
                if (isGenericName(tgtName) && !isGenericName(srcName)) {
                    try {
                        tgtLocal.setName(srcName, SourceType.USER_DEFINED);
                        namesApplied++;
                    } catch (Exception e) { /* skip */ }
                }

                // Copy type
                String tgtType = tgtLocal.getDataType().getName();
                if (tgtType.startsWith("undefined")) {
                    DataType srcType = srcLocal.getDataType();
                    if (!srcType.getName().startsWith("undefined")) {
                        try {
                            tgtLocal.setDataType(srcType, SourceType.USER_DEFINED);
                            typesApplied++;
                        } catch (Exception e) { /* skip */ }
                    }
                }
            }
        } catch (Exception e) {
            // Skip on errors
        }

        return new int[]{namesApplied, typesApplied};
    }

    private String computeOpcodeHash(Function func, Program program) {
        try {
            AddressSetView body = func.getBody();
            if (body.getNumAddresses() < 2 || body.getNumAddresses() > 100000) return null;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            InstructionIterator iter = program.getListing().getInstructions(body, true);
            int instrCount = 0;
            while (iter.hasNext()) {
                Instruction instr = iter.next();
                md.update(instr.getMnemonicString().getBytes());
                md.update((byte) instr.getLength());
                instrCount++;
            }
            if (instrCount < 2) return null;
            byte[] hashBytes = md.digest();
            StringBuilder hex = new StringBuilder();
            for (byte b : hashBytes) hex.append(String.format("%02x", b));
            return hex.toString().substring(0, 16);
        } catch (Exception e) { return null; }
    }

    private boolean hasUndefinedVariables(Function func) {
        for (Parameter p : func.getParameters()) {
            if (p.getDataType().getName().startsWith("undefined")) return true;
            if (isGenericName(p.getName())) return true;
        }
        for (Variable v : func.getLocalVariables()) {
            if (v.getDataType().getName().startsWith("undefined")) return true;
            if (isGenericName(v.getName())) return true;
        }
        return false;
    }

    private boolean isGenericName(String name) {
        return name.startsWith("param_") || name.startsWith("local_") ||
               name.matches(".*Var\\d+") || name.startsWith("in_") ||
               name.matches("[a-z]Var\\d+");
    }

    private String getPlate(Function func, Listing listing) {
        // Primary: function comment (set by func.setComment() / MCP set_plate_comment)
        String comment = func.getComment();
        if (comment != null && !comment.isEmpty()) return comment;
        // Fallback: listing-level plate comment (legacy storage)
        @SuppressWarnings("deprecation")
        String listingComment = listing.getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint());
        return listingComment;
    }

    private DomainFile findDomainFile(DomainFolder folder, String path) throws Exception {
        String[] parts = path.split("/");
        DomainFolder current = folder;
        for (int i = 1; i < parts.length - 1; i++) {
            if (parts[i].isEmpty()) continue;
            current = current.getFolder(parts[i]);
            if (current == null) return null;
        }
        return current.getFile(parts[parts.length - 1]);
    }
}

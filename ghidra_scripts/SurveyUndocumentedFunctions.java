//Survey all undocumented functions and produce a JSON manifest for AI-driven RE loops
//@category RELoop
//@menupath Tools.RE Loop.Survey Undocumented Functions
//@description Scans all functions, classifies undocumented ones (thunk/leaf/worker/api), counts xrefs/callees/callers, detects register-only SSA. Outputs JSON manifest to workflows/survey_manifest.json. Eliminates the need for AI to perform Phase 1 SURVEY.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import java.io.*;
import java.util.*;

public class SurveyUndocumentedFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String programName = currentProgram.getName();
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        ReferenceManager rm = currentProgram.getReferenceManager();

        println("=== Survey Undocumented Functions ===");
        println("Program: " + programName);

        // Collect all undocumented functions
        List<Function> undocumented = new ArrayList<>();
        int totalFunctions = 0;
        int namedFunctions = 0;

        for (Function func : fm.getFunctions(true)) {
            totalFunctions++;
            String name = func.getName();
            if (isUndocumented(name)) {
                undocumented.add(func);
            } else {
                namedFunctions++;
            }
        }

        println("Total functions: " + totalFunctions);
        println("Already named: " + namedFunctions);
        println("Undocumented: " + undocumented.size());

        // Set up decompiler for classification
        DecompInterface decomp = new DecompInterface();

        // Build manifest entries
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"program\": \"").append(escJson(programName)).append("\",\n");
        json.append("  \"total_functions\": ").append(totalFunctions).append(",\n");
        json.append("  \"named_functions\": ").append(namedFunctions).append(",\n");
        json.append("  \"undocumented_count\": ").append(undocumented.size()).append(",\n");
        json.append("  \"undocumented\": [\n");

        int count = 0;
        int thunks = 0, leaves = 0, workers = 0, apis = 0;

        try {
            decomp.openProgram(currentProgram);
            decomp.setSimplificationStyle("decompile");

            for (Function func : undocumented) {
                if (monitor.isCancelled()) break;

                if (count > 0) json.append(",\n");

                String addr = func.getEntryPoint().toString();
                String name = func.getName();
                boolean isExport = func.isExternal() || isExported(func, st);

                // Count xrefs TO this function
                int xrefCount = 0;
                for (Reference ref : rm.getReferencesTo(func.getEntryPoint())) {
                    if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                        xrefCount++;
                    }
                }

                // Count callees and callers
                Set<Function> callees = func.getCalledFunctions(monitor);
                int calleeCount = callees.size();
                int undocCalleeCount = 0;
                for (Function callee : callees) {
                    if (isUndocumented(callee.getName())) undocCalleeCount++;
                }

                Set<Function> callers = func.getCallingFunctions(monitor);
                int callerCount = callers.size();

                // Classify function
                String classification;
                String bodyAddress = null;
                long bodySize = func.getBody().getNumAddresses();

                if (func.isThunk()) {
                    classification = "thunk";
                    thunks++;
                    Function thunkedFunc = func.getThunkedFunction(false);
                    if (thunkedFunc != null) {
                        bodyAddress = thunkedFunc.getEntryPoint().toString();
                    }
                } else if (bodySize <= 10 && isSimpleThunk(func)) {
                    classification = "thunk";
                    thunks++;
                    bodyAddress = findThunkTarget(func);
                } else if (calleeCount == 0) {
                    classification = "leaf";
                    leaves++;
                } else if (isExport) {
                    classification = "api";
                    apis++;
                } else {
                    classification = "worker";
                    workers++;
                }

                // Check for register-only SSA (quick heuristic: decompile and check local names)
                boolean hasRenameableVars = true;
                if (!classification.equals("thunk")) {
                    try {
                        DecompileResults results = decomp.decompileFunction(func, 5, monitor);
                        if (results != null && results.decompileCompleted()) {
                            HighFunction hf = results.getHighFunction();
                            if (hf != null) {
                                hasRenameableVars = hasRenameableLocals(hf);
                            }
                        }
                    } catch (Exception e) {
                        // Decompile failed — assume has renameable vars
                    }
                }

                // Build JSON entry
                json.append("    {");
                json.append("\"address\": \"0x").append(addr).append("\"");
                json.append(", \"name\": \"").append(escJson(name)).append("\"");
                json.append(", \"classification\": \"").append(classification).append("\"");
                json.append(", \"xref_count\": ").append(xrefCount);
                json.append(", \"callee_count\": ").append(calleeCount);
                json.append(", \"undoc_callee_count\": ").append(undocCalleeCount);
                json.append(", \"caller_count\": ").append(callerCount);
                json.append(", \"body_size\": ").append(bodySize);
                json.append(", \"is_export\": ").append(isExport);
                json.append(", \"has_renameable_vars\": ").append(hasRenameableVars);
                if (bodyAddress != null) {
                    json.append(", \"body_address\": \"0x").append(bodyAddress).append("\"");
                }
                json.append("}");

                count++;
                if (count % 100 == 0) {
                    println("  Processed " + count + "/" + undocumented.size() + "...");
                }
            }
        } finally {
            decomp.dispose();
        }

        json.append("\n  ],\n");
        json.append("  \"classification_summary\": {");
        json.append("\"thunk\": ").append(thunks);
        json.append(", \"leaf\": ").append(leaves);
        json.append(", \"worker\": ").append(workers);
        json.append(", \"api\": ").append(apis);
        json.append("}\n");
        json.append("}\n");

        // Write manifest file
        String projectRoot = System.getProperty("user.dir");
        // Try to find the ghidra-mcp project workflows directory
        String[] searchPaths = {
            "C:/Users/benam/source/mcp/ghidra-mcp/workflows",
            projectRoot + "/workflows"
        };

        File outputDir = null;
        for (String path : searchPaths) {
            File dir = new File(path);
            if (dir.exists() && dir.isDirectory()) {
                outputDir = dir;
                break;
            }
        }

        if (outputDir == null) {
            outputDir = new File("C:/Users/benam/source/mcp/ghidra-mcp/workflows");
            outputDir.mkdirs();
        }

        // Use program name in filename for multi-binary support
        String safeProgName = programName.replaceAll("[^a-zA-Z0-9._-]", "_");
        File outputFile = new File(outputDir, "survey_" + safeProgName + ".json");

        try (FileWriter fw = new FileWriter(outputFile)) {
            fw.write(json.toString());
        }

        println("\n=== Survey Complete ===");
        println("Manifest written to: " + outputFile.getAbsolutePath());
        println("Classification: " + thunks + " thunks, " + leaves + " leaves, " +
                workers + " workers, " + apis + " APIs");
        println("Total undocumented: " + count);
    }

    private boolean isUndocumented(String name) {
        return name.startsWith("FUN_") ||
               name.startsWith("Ordinal_") ||
               name.startsWith("thunk_FUN_") ||
               name.startsWith("thunk_Ordinal_");
    }

    private boolean isExported(Function func, SymbolTable st) {
        for (Symbol sym : st.getSymbols(func.getEntryPoint())) {
            if (sym.isExternalEntryPoint()) return true;
        }
        return false;
    }

    private boolean isSimpleThunk(Function func) {
        // Check if function body is just a JMP or CALL+RET
        InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);
        int instrCount = 0;
        boolean hasJump = false;
        while (iter.hasNext() && instrCount < 5) {
            Instruction instr = iter.next();
            String mnemonic = instr.getMnemonicString().toUpperCase();
            if (mnemonic.equals("JMP")) hasJump = true;
            instrCount++;
        }
        return instrCount <= 2 && hasJump;
    }

    private String findThunkTarget(Function func) {
        InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);
        while (iter.hasNext()) {
            Instruction instr = iter.next();
            String mnemonic = instr.getMnemonicString().toUpperCase();
            if (mnemonic.equals("JMP") || mnemonic.equals("CALL")) {
                Reference[] refs = instr.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                        return ref.getToAddress().toString();
                    }
                }
            }
        }
        return null;
    }

    private boolean hasRenameableLocals(HighFunction hf) {
        Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            if (sym.isParameter()) continue;
            String name = sym.getName();
            // Register-only SSA variables match pattern: [a-z]Var[0-9]+
            if (!name.matches("[a-z]+Var\\d+") && !name.startsWith("in_") &&
                !name.startsWith("extraout_") && !name.startsWith("CONCAT")) {
                return true; // Found a non-SSA, non-phantom local
            }
        }
        return false;
    }

    private String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}

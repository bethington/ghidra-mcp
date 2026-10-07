// Fix Function Parameters Headless
//
// Headless version of FixFunctionParameters that applies fixes automatically without GUI prompts. Suitable for MCP automation and batch processing.
//
// Usage: Run from MCP or headless Ghidra. Applies fixes by default.
// Output: Fixes function prototypes without user interaction.
//
// @author Ben Ethington
// @category GhidraMCP.Analysis
// @description Fix function parameters (headless/MCP version)
// @menupath GhidraMCP.Analysis.Fix Function Parameters Headless

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.data.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class Analyze_FixFunctionParametersHeadless extends GhidraScript {
    
    private int totalAnalyzed = 0;
    private int parametersFixed = 0;
    private int conventionFixed = 0;
    private int failedCount = 0;
    private long startTime;
    private boolean applyFixes = true;  // Default to true for headless execution
    
    @Override
    public void run() throws Exception {
        startTime = System.currentTimeMillis();
        
        // Check for command-line arguments
        String[] args = getScriptArgs();
        if (args != null && args.length > 0) {
            for (String arg : args) {
                if (arg.equals("--analyze-only") || arg.equals("-n") || arg.equals("--dry-run")) {
                    applyFixes = false;
                }
            }
        }
        
        println("========================================");
        println("FIX FUNCTION PARAMETERS AND CONVENTIONS");
        println("HEADLESS VERSION (SINGLE TRANSACTION)");
        println("========================================");
        println("Program: " + currentProgram.getName());
        println("Date: " + new Date());

        // The heuristics below read x86-32 registers (ECX/EDX) and 4-byte stack
        // slots; on any other architecture they would rewrite prototypes from noise.
        Language language = currentProgram.getLanguage();
        if (!"x86".equals(language.getProcessor().toString())
                || language.getLanguageDescription().getSize() != 32) {
            printerr("This script only supports 32-bit x86 programs (found "
                + language.getLanguageID() + "). Nothing was changed.");
            return;
        }
        println("Mode: " + (applyFixes ? "Analyze and Fix (AUTO)" : "Analyze Only"));
        println();
        
        // Get all functions
        FunctionManager funcManager = currentProgram.getFunctionManager();
        int totalFunctions = funcManager.getFunctionCount();
        println("Total functions to analyze: " + totalFunctions);
        println();
        
        if (applyFixes) {
            println("[AUTO-FIX] Applying fixes automatically without confirmation");
            println("[AUTO-FIX] To run in analyze-only mode, use: --analyze-only");
            println("[AUTO-FIX] Starting single transaction for all changes...");
        } else {
            println("[ANALYZE-ONLY] No changes will be made");
        }
        println();
        
        // START SINGLE TRANSACTION FOR ALL CHANGES
        int txId = -1;
        if (applyFixes) {
            txId = currentProgram.startTransaction("Fix all function parameters and conventions");
        }
        
        try {
            // Process each function
            int progress = 0;
            for (Function func : funcManager.getFunctions(true)) {
                if (monitor.isCancelled()) {
                    println("\n[CANCELLED] Analysis stopped by user");
                    break;
                }
                
                progress++;
                totalAnalyzed++;
                
                // Progress reporting every 50 functions
                if (progress % 50 == 0) {
                    long elapsed = (System.currentTimeMillis() - startTime) / 1000;
                    double rate = (double) progress / elapsed;
                    int remaining = totalFunctions - progress;
                    int eta = (int) (remaining / rate);
                    
                    println(String.format("[%d/%d] Analyzed: %d | Params Fixed: %d | Conv Fixed: %d | Failed: %d | ETA: %d sec",
                        progress, totalFunctions, totalAnalyzed, parametersFixed, conventionFixed, failedCount, eta));
                }
                
                if (applyFixes) {
                    analyzeAndFixFunction(func);
                } else {
                    analyzeFunction(func);
                }
            }
            
            // COMMIT TRANSACTION
            if (applyFixes && txId != -1) {
                currentProgram.endTransaction(txId, true);
                println("\n[TRANSACTION] All changes committed successfully");
            }
        } catch (Exception e) {
            // ROLLBACK ON ERROR
            if (applyFixes && txId != -1) {
                currentProgram.endTransaction(txId, false);
                println("\n[TRANSACTION] Changes rolled back due to error: " + e.getMessage());
            }
            throw e;
        }
        
        // Print results
        printResults();
        
        long totalTime = (System.currentTimeMillis() - startTime) / 1000;
        println("\n[COMPLETE] Analysis finished in " + totalTime + " seconds");
        
        if (applyFixes) {
            println("\n[SUMMARY] Fixed " + parametersFixed + " parameter counts, " + 
                   conventionFixed + " calling conventions, " + failedCount + " failures");
            println("\n[NOTE] Changes made - please save the program manually (File -> Save)");
        }
    }
    
    private void analyzeAndFixFunction(Function func) {
        try {
            String funcName = func.getName();
            String currentConvention = func.getCallingConventionName();
            
            // Get parameter analysis
            ParameterAnalysis analysis = analyzeParameters(func);
            
            if (analysis == null) {
                return;
            }
            
            boolean needsFix = false;
            String targetConvention = chooseConvention(analysis, currentConvention);
            int targetParamCount = paramCountFor(analysis, targetConvention);

            // Check if change needed
            if (!currentConvention.equals(targetConvention)) {
                needsFix = true;
            }
            
            // Check if parameter count matches
            int currentParamCount = func.getParameterCount();
            if (currentParamCount != targetParamCount) {
                needsFix = true;
            }
            
            if (needsFix) {
                if (applyFix(func, targetConvention, targetParamCount)) {
                    if (!currentConvention.equals(targetConvention)) {
                        conventionFixed++;
                        String evidence = "(RET 0x" + Integer.toHexString(analysis.retCleanupBytes);
                        if (analysis.hasStackLoad) {
                            evidence += ", stack loads";
                        }
                        evidence += ", regs: " + getRegisterSummary(analysis) + ")";
                        println("[FIXED CONV] " + funcName + " @ " + func.getEntryPoint() + 
                               ": " + currentConvention + " -> " + targetConvention + " " + evidence);
                    }
                    if (currentParamCount != targetParamCount) {
                        parametersFixed++;
                        println("[FIXED PARAM] " + funcName + " @ " + func.getEntryPoint() + 
                               ": " + currentParamCount + " -> " + targetParamCount + " parameters");
                    }
                } else {
                    failedCount++;
                }
            }
            
        } catch (Exception e) {
            failedCount++;
        }
    }
    
    private String getRegisterSummary(ParameterAnalysis analysis) {
        List<String> regs = new ArrayList<>();
        if (analysis.usesECX) regs.add("ECX");
        if (analysis.usesEDX) regs.add("EDX");
        return regs.isEmpty() ? "none" : String.join(", ", regs);
    }

    /**
     * Pick a standard x86-32 calling convention from the observed evidence.
     *
     * Callee cleanup (RET n): __fastcall when both ECX and EDX carry arguments,
     * __thiscall when only ECX does, otherwise __stdcall. Caller cleanup (plain
     * RET): register-only __fastcall/__thiscall when no stack arguments are read,
     * __cdecl when stack arguments are read, and the current convention when
     * there is no evidence either way.
     */
    private String chooseConvention(ParameterAnalysis analysis, String currentConvention) {
        boolean hasStackParams = analysis.stackParamCount > 0;
        if (analysis.retCleanupBytes > 0) {
            if (analysis.usesECX && analysis.usesEDX) {
                return "__fastcall";
            }
            if (analysis.usesECX && !analysis.hasStackLoad) {
                return "__thiscall";
            }
            return "__stdcall";
        }
        if (!hasStackParams) {
            if (analysis.usesECX && analysis.usesEDX) {
                return "__fastcall";
            }
            if (analysis.usesECX) {
                return "__thiscall";
            }
            return currentConvention;
        }
        return "__cdecl";
    }

    /** Stack arguments plus the register arguments the chosen convention passes. */
    private int paramCountFor(ParameterAnalysis analysis, String convention) {
        int registerParams = 0;
        if ("__fastcall".equals(convention)) {
            registerParams = analysis.usesEDX ? 2 : (analysis.usesECX ? 1 : 0);
        } else if ("__thiscall".equals(convention)) {
            registerParams = 1;
        }
        return registerParams + analysis.stackParamCount;
    }
    
    private void analyzeFunction(Function func) {
        try {
            ParameterAnalysis analysis = analyzeParameters(func);
            if (analysis != null) {
                String funcName = func.getName();
                String convention = chooseConvention(analysis, func.getCallingConventionName());
                int detected = paramCountFor(analysis, convention);
                int currentCount = func.getParameterCount();
                if (currentCount != detected) {
                    println("[MISMATCH] " + funcName + ": has " + currentCount +
                           " params, detected " + detected + " (" + convention + ")");
                }
            }
        } catch (Exception e) {
            // Ignore errors in analysis-only mode
        }
    }
    
    private ParameterAnalysis analyzeParameters(Function func) {
        ParameterAnalysis analysis = new ParameterAnalysis();
        
        Address entryPoint = func.getEntryPoint();
        Listing listing = currentProgram.getListing();
        InstructionIterator instIter = listing.getInstructions(entryPoint, true);
        
        Set<Integer> stackOffsetsUsed = new HashSet<>();
        boolean hasStandardPrologue = false;
        int stackFrameSize = 0;
        boolean hasStackLoad = false;  // NEW: Track if function loads from stack
        
        // Check RET instruction for cleanup bytes (determines stack params)
        Instruction retInst = findReturnInstruction(func);
        int retCleanupBytes = 0;
        if (retInst != null && retInst.getMnemonicString().equalsIgnoreCase("RET")) {
            if (retInst.getNumOperands() > 0) {
                try {
                    Object[] opObjs = retInst.getOpObjects(0);
                    if (opObjs != null && opObjs.length > 0 && opObjs[0] instanceof Scalar) {
                        retCleanupBytes = (int)((Scalar)opObjs[0]).getValue();
                        analysis.retCleanupBytes = retCleanupBytes;
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
        }
        
        // Analyze first 20 instructions
        int count = 0;
        boolean inPrologue = true;
        while (instIter.hasNext() && count < 30) {
            Instruction inst = instIter.next();
            
            if (!func.getBody().contains(inst.getAddress())) {
                break;
            }
            
            String mnemonic = inst.getMnemonicString().toUpperCase();
            
            // Detect standard prologue
            if (count == 0 && mnemonic.equals("PUSH") && 
                inst.getDefaultOperandRepresentation(0).toUpperCase().equals("EBP")) {
                hasStandardPrologue = true;
            }
            if (count == 1 && hasStandardPrologue && mnemonic.equals("MOV") &&
                inst.getDefaultOperandRepresentation(0).toUpperCase().equals("EBP") &&
                inst.getDefaultOperandRepresentation(1).toUpperCase().equals("ESP")) {
                // Standard "PUSH EBP; MOV EBP, ESP" prologue
                inPrologue = true;
            }
            
            // Track register usage (in first 10 non-prologue instructions)
            if (count > 2 && count < 12) {
                for (int i = 0; i < inst.getNumOperands(); i++) {
                    String op = inst.getDefaultOperandRepresentation(i).toUpperCase();
                    
                    // NEW: Check for stack loads (MOV reg,[ESP+offset]) in first 5 instructions
                    if (count < 7 && mnemonic.equals("MOV") && i == 1) {
                        if (op.contains("ESP") && op.contains("+") && op.contains("[")) {
                            hasStackLoad = true;
                        }
                    }
                    
                    // Check for parameter-register reads (ECX for __thiscall /
                    // __fastcall, EDX for __fastcall). A PUSH of the register is a
                    // save, not a use, and a memory operand is a dereference.
                    if (op.contains("ECX") && !mnemonic.equals("PUSH") && !op.contains("[")) {
                        analysis.usesECX = true;
                    }
                    if (i > 0 && op.contains("EDX") && !mnemonic.equals("PUSH") && !op.contains("[")) {
                        analysis.usesEDX = true;
                    }
                }
            }
            
            // Track stack parameter accesses [ESP+offset] or [EBP+offset]
            for (int i = 0; i < inst.getNumOperands(); i++) {
                String op = inst.getDefaultOperandRepresentation(i).toUpperCase();
                
                // Check for [ESP+offset] accesses (non-standard prologue)
                if (op.contains("ESP") && op.contains("+") && op.contains("[")) {
                    try {
                        String offsetStr = op.substring(op.indexOf("+") + 1);
                        offsetStr = offsetStr.replaceAll("[^0-9a-fA-Fx]", "");
                        if (offsetStr.startsWith("0X")) {
                            int offset = Integer.parseInt(offsetStr.substring(2), 16);
                            if (offset >= 4 && offset <= 128) {
                                stackOffsetsUsed.add(offset);
                            }
                        }
                    } catch (Exception e) {
                        // Ignore
                    }
                }
                
                // Check for [EBP+offset] accesses (standard prologue)
                if (hasStandardPrologue && op.contains("EBP") && op.contains("+") && op.contains("[")) {
                    try {
                        String offsetStr = op.substring(op.indexOf("+") + 1);
                        offsetStr = offsetStr.replaceAll("[^0-9a-fA-Fx]", "");
                        if (offsetStr.startsWith("0X")) {
                            int offset = Integer.parseInt(offsetStr.substring(2), 16);
                            // Parameters are at [EBP+8] and above (EBP+4 is return address)
                            if (offset >= 8 && offset <= 128) {
                                stackOffsetsUsed.add(offset);
                            }
                        }
                    } catch (Exception e) {
                        // Ignore
                    }
                }
            }
            
            count++;
        }
        
        // Calculate stack parameter count
        int stackParams = 0;
        
        // Use RET cleanup bytes if available (most reliable)
        if (retCleanupBytes > 0) {
            stackParams = retCleanupBytes / 4;  // Each DWORD = 4 bytes
        } else {
            // Fallback: count stack offsets
            if (!stackOffsetsUsed.isEmpty()) {
                int maxOffset = Collections.max(stackOffsetsUsed);
                if (hasStandardPrologue) {
                    stackParams = (maxOffset - 4) / 4;  // Subtract return address
                } else {
                    stackParams = maxOffset / 4;
                }
            }
        }
        
        analysis.stackParamCount = stackParams;
        analysis.hasStandardPrologue = hasStandardPrologue;
        analysis.hasStackLoad = hasStackLoad;  // NEW: Store stack load detection
        
        return analysis;
    }
    
    private Instruction findReturnInstruction(Function func) {
        Listing listing = currentProgram.getListing();
        InstructionIterator instIter = listing.getInstructions(func.getBody(), true);
        Instruction lastRet = null;
        
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            if (inst.getMnemonicString().equalsIgnoreCase("RET")) {
                lastRet = inst;
            }
        }
        
        return lastRet;
    }
    
    private boolean applyFix(Function func, String convention, int paramCount) {
        try {
            // Set calling convention if different
            if (!func.getCallingConventionName().equals(convention)) {
                func.setCallingConvention(convention);
            }
            
            // Update parameter count if needed
            int currentCount = func.getParameterCount();
            if (currentCount != paramCount) {
                // Add or remove parameters as needed
                if (paramCount > currentCount) {
                    // Add parameters
                    for (int i = currentCount; i < paramCount; i++) {
                        ParameterImpl param = new ParameterImpl("param" + (i + 1), 
                            IntegerDataType.dataType, currentProgram);
                        func.addParameter(param, SourceType.ANALYSIS);
                    }
                } else if (paramCount < currentCount) {
                    // Remove excess parameters from the end, so the indices
                    // still to be removed do not shift underneath the loop
                    for (int i = currentCount - 1; i >= paramCount; i--) {
                        func.removeParameter(i);
                    }
                }
            }
            
            return true;
        } catch (Exception e) {
            println("[ERROR] Failed to fix " + func.getName() + ": " + e.getMessage());
            return false;
        }
    }
    
    private void printResults() {
        println("\n========================================");
        println("PARAMETER ANALYSIS RESULTS");
        println("========================================");
        println();
        println("Total Analyzed: " + totalAnalyzed);
        println("Parameters Fixed: " + parametersFixed);
        println("Conventions Fixed: " + conventionFixed);
        println("Failed: " + failedCount);
    }
    
    // Inner classes
    private static class ParameterAnalysis {
        int stackParamCount = 0;
        boolean usesECX = false;
        boolean usesEDX = false;
        boolean hasStandardPrologue = false;
        boolean hasStackLoad = false;  // NEW: Track stack parameter loads
        int retCleanupBytes = 0;
    }
    
}

// Analyze and fix function parameters based on calling conventions and stack usage
// @author GhidraMCP
// @category Analysis
// @keybinding 
// @menupath Analysis.D2.Fix Function Parameters
// @toolbar 

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

public class FixFunctionParameters extends GhidraScript {
    
    private int totalAnalyzed = 0;
    private int parametersFixed = 0;
    private int conventionFixed = 0;
    private int failedCount = 0;
    private long startTime;
    private Map<String, ConventionInfo> conventionMap;
    
    @Override
    public void run() throws Exception {
        startTime = System.currentTimeMillis();
        
        // Initialize calling convention expectations
        initializeConventionMap();
        
        println("========================================");
        println("FIX FUNCTION PARAMETERS AND CONVENTIONS");
        println("========================================");
        println("Program: " + currentProgram.getName());
        println("Date: " + new Date());
        println();
        
        // Ask if user wants to apply fixes
        boolean applyFixes = askYesNo("Apply Fixes?", 
            "Analyze function parameters and calling conventions?\n\n" +
            "This will:\n" +
            "- Detect actual parameter counts from stack/register usage\n" +
            "- Fix incorrect calling conventions\n" +
            "- Update function signatures\n\n" +
            "Apply fixes automatically?");
        
        println("Mode: " + (applyFixes ? "Analyze and Fix" : "Analyze Only"));
        println();
        
        // Get all functions
        FunctionManager funcManager = currentProgram.getFunctionManager();
        int totalFunctions = funcManager.getFunctionCount();
        println("Total functions to analyze: " + totalFunctions);
        println();
        
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
        
        // Print results
        printResults();
        
        long totalTime = (System.currentTimeMillis() - startTime) / 1000;
        println("\n[COMPLETE] Analysis finished in " + totalTime + " seconds");
        
        if (applyFixes) {
            println("\n[SUMMARY] Fixed " + parametersFixed + " parameter counts, " + 
                   conventionFixed + " calling conventions, " + failedCount + " failures");
        }
    }
    
    private void initializeConventionMap() {
        conventionMap = new HashMap<>();
        
        // __cdecl: caller cleanup, parameters on stack
        conventionMap.put("__cdecl", new ConventionInfo("__cdecl", false, new String[]{}, true));
        
        // __stdcall: callee cleanup, parameters on stack
        conventionMap.put("__stdcall", new ConventionInfo("__stdcall", false, new String[]{}, true));
        
        // __fastcall: first 2 in ECX/EDX, rest on stack
        conventionMap.put("__fastcall", new ConventionInfo("__fastcall", false, new String[]{"ECX", "EDX"}, true));
        
        // __thiscall: 'this' in ECX, rest on stack
        conventionMap.put("__thiscall", new ConventionInfo("__thiscall", false, new String[]{"ECX"}, true));
        
        // D2 custom conventions
        // __d2call: First param in EBX, rest on stack
        conventionMap.put("__d2call", new ConventionInfo("__d2call", false, new String[]{"EBX"}, true));
        
        // __d2regcall: Up to 3 params in registers (EAX, EDX, ECX)
        conventionMap.put("__d2regcall", new ConventionInfo("__d2regcall", false, new String[]{"EAX", "EDX", "ECX"}, false));
        
        // __d2mixcall: Mix of registers and stack
        conventionMap.put("__d2mixcall", new ConventionInfo("__d2mixcall", false, new String[]{"EAX", "EDX"}, true));
        
        // __d2edicall: First param in EDI
        conventionMap.put("__d2edicall", new ConventionInfo("__d2edicall", false, new String[]{"EDI"}, true));
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
            String targetConvention = currentConvention;
            int targetParamCount = analysis.paramCount;
            
            // Determine correct calling convention based on evidence
            if (analysis.retCleanupBytes > 0) {
                // Has callee cleanup - check for stack loads FIRST
                if (analysis.hasStackLoad) {
                    // Stack-based parameters detected via MOV reg,[ESP+offset]
                    targetConvention = "__stdcall";
                } else if (analysis.usesEBX && !analysis.usesECX) {
                    targetConvention = "__d2call";
                } else if (analysis.usesEDI && !analysis.usesECX && !analysis.usesEBX) {
                    targetConvention = "__d2edicall";
                } else if (analysis.usesECX && !analysis.usesEBX && !analysis.usesEDI) {
                    targetConvention = "__thiscall";
                } else if ((analysis.usesEAX || analysis.usesEDX || analysis.usesECX) && 
                          !analysis.usesEBX && !analysis.usesEDI && !analysis.hasStackLoad) {
                    // Only apply __d2regcall if NO stack loads detected
                    targetConvention = "__d2regcall";
                } else {
                    // Default to __stdcall for callee cleanup with no clear pattern
                    targetConvention = "__stdcall";
                }
            } else {
                // No callee cleanup - likely __cdecl or register-only convention
                if (analysis.usesEBX) {
                    targetConvention = "__d2call";
                } else if (analysis.usesEDI) {
                    targetConvention = "__d2edicall";
                } else if (analysis.usesECX && analysis.paramCount == 1) {
                    targetConvention = "__thiscall";
                } else if ((analysis.usesEAX || analysis.usesEDX || analysis.usesECX || analysis.usesESI) &&
                          !analysis.usesEBX && !analysis.usesEDI) {
                    targetConvention = "__d2regcall";
                } else if (analysis.paramCount > 0) {
                    targetConvention = "__cdecl";
                }
            }
            
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
        if (analysis.usesEAX) regs.add("EAX");
        if (analysis.usesEBX) regs.add("EBX");
        if (analysis.usesECX) regs.add("ECX");
        if (analysis.usesEDX) regs.add("EDX");
        if (analysis.usesEDI) regs.add("EDI");
        if (analysis.usesESI) regs.add("ESI");
        return String.join(", ", regs);
    }
    
    private void analyzeFunction(Function func) {
        try {
            ParameterAnalysis analysis = analyzeParameters(func);
            if (analysis != null) {
                String funcName = func.getName();
                int currentCount = func.getParameterCount();
                if (currentCount != analysis.paramCount) {
                    println("[MISMATCH] " + funcName + ": has " + currentCount + 
                           " params, detected " + analysis.paramCount);
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
        
        Set<String> registersUsed = new HashSet<>();
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
                    
                    // Check for parameter register usage
                    if (op.contains("ECX") && !mnemonic.equals("PUSH") && !op.contains("[")) {
                        analysis.usesECX = true;
                        registersUsed.add("ECX");
                    }
                    if (op.contains("EBX") && !mnemonic.equals("PUSH") && !op.contains("[")) {
                        analysis.usesEBX = true;
                        registersUsed.add("EBX");
                    }
                    if (op.contains("EDI") && !mnemonic.equals("PUSH") && !op.contains("[")) {
                        analysis.usesEDI = true;
                        registersUsed.add("EDI");
                    }
                    if (i == 0 && op.contains("EAX") && mnemonic.equals("MOV")) {
                        // EAX being loaded (destination) suggests parameter
                        analysis.usesEAX = true;
                        registersUsed.add("EAX");
                    }
                    if (i == 0 && op.contains("EDX") && mnemonic.equals("MOV")) {
                        analysis.usesEDX = true;
                        registersUsed.add("EDX");
                    }
                    if (op.contains("ESI") && !mnemonic.equals("PUSH") && count < 8) {
                        analysis.usesESI = true;
                        registersUsed.add("ESI");
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
        
        // Calculate parameter count
        int registerParams = 0;
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
        
        // Count register parameters
        if (analysis.usesECX) registerParams++;
        if (analysis.usesEBX) registerParams++;
        if (analysis.usesEDI) registerParams++;
        if (analysis.usesESI) registerParams++;
        if (analysis.usesEAX && !analysis.usesECX) registerParams++;
        if (analysis.usesEDX && !analysis.usesECX) registerParams++;
        
        // Total parameters
        analysis.paramCount = registerParams + stackParams;
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
        int txId = currentProgram.startTransaction("Fix parameters for " + func.getName());
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
                    // Remove excess parameters
                    Parameter[] params = func.getParameters();
                    for (int i = paramCount; i < currentCount; i++) {
                        func.removeParameter(i);
                    }
                }
            }
            
            currentProgram.endTransaction(txId, true);
            return true;
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
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
        int paramCount = 0;
        boolean usesECX = false;
        boolean usesEBX = false;
        boolean usesEDI = false;
        boolean usesEAX = false;
        boolean usesEDX = false;
        boolean usesESI = false;
        boolean hasStandardPrologue = false;
        boolean hasStackLoad = false;  // NEW: Track stack parameter loads
        int retCleanupBytes = 0;
    }
    
    private static class ConventionInfo {
        String name;
        boolean callerCleanup;
        String[] registerParams;
        boolean usesStack;
        
        ConventionInfo(String name, boolean callerCleanup, String[] registerParams, boolean usesStack) {
            this.name = name;
            this.callerCleanup = callerCleanup;
            this.registerParams = registerParams;
            this.usesStack = usesStack;
        }
    }
}

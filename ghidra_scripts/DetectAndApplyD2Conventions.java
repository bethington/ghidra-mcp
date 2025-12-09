// Detect D2 custom calling conventions and apply them automatically
// @author GhidraMCP
// @category Analysis
// @keybinding 
// @menupath Analysis.D2.Detect and Apply Calling Conventions
// @toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import java.io.*;
import java.util.*;
import com.google.gson.*;

public class DetectAndApplyD2Conventions extends GhidraScript {
    
    private static final String[] D2_CONVENTIONS = {
        "__d2call", "__d2regcall", "__d2mixcall", "__d2edicall"
    };
    
    private Map<String, List<FunctionResult>> detections;
    private int standardCount = 0;
    private int unknownCount = 0;
    private int totalAnalyzed = 0;
    private int appliedCount = 0;
    private int failedCount = 0;
    private long startTime;
    private boolean applyMode = false;
    
    @Override
    public void run() throws Exception {
        startTime = System.currentTimeMillis();
        detections = new HashMap<>();
        for (String conv : D2_CONVENTIONS) {
            detections.put(conv, new ArrayList<>());
        }
        
        // Ask user if they want to apply conventions
        applyMode = askYesNo("Apply Conventions?", 
            "Do you want to automatically apply detected calling conventions?\n\n" +
            "Yes = Detect AND apply conventions\n" +
            "No = Detection only (no changes)");
        
        println("========================================");
        println("D2 CALLING CONVENTION DETECTION" + (applyMode ? " AND APPLICATION" : ""));
        println("========================================");
        println("Program: " + currentProgram.getName());
        println("Mode: " + (applyMode ? "Detect and Apply" : "Detect Only"));
        println("Date: " + new Date());
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
            
            // Progress reporting every 100 functions
            if (progress % 100 == 0) {
                long elapsed = (System.currentTimeMillis() - startTime) / 1000;
                double rate = (double) progress / elapsed;
                int remaining = totalFunctions - progress;
                int eta = (int) (remaining / rate);
                
                println(String.format("[%d/%d] Analyzed: %d | Standard: %d | Unknown: %d | D2: %d | Applied: %d | ETA: %d sec",
                    progress, totalFunctions, totalAnalyzed, standardCount, unknownCount, 
                    getTotalD2Detections(), appliedCount, eta));
            }
            
            analyzeFunction(func);
        }
        
        // Print results
        printResults();
        
        // Export to JSON
        exportResults();
        
        long totalTime = (System.currentTimeMillis() - startTime) / 1000;
        println("\n[COMPLETE] Analysis finished in " + totalTime + " seconds");
        
        if (applyMode) {
            println("\n[SUMMARY] Applied " + appliedCount + " conventions, " + failedCount + " failed");
        }
    }
    
    private void analyzeFunction(Function func) throws Exception {
        String funcName = func.getName();
        Address entryPoint = func.getEntryPoint();
        
        // Get disassembly listing
        Listing listing = currentProgram.getListing();
        InstructionIterator instIter = listing.getInstructions(entryPoint, true);
        
        // Collect first 10 instructions
        List<String> instructions = new ArrayList<>();
        int count = 0;
        while (instIter.hasNext() && count < 10) {
            Instruction inst = instIter.next();
            
            // Check if still in this function
            if (!func.getBody().contains(inst.getAddress())) {
                break;
            }
            
            instructions.add(inst.getMnemonicString().toUpperCase() + " " + 
                           inst.getDefaultOperandRepresentation(0) + " " +
                           (inst.getNumOperands() > 1 ? inst.getDefaultOperandRepresentation(1) : ""));
            count++;
        }
        
        if (instructions.size() < 3) {
            unknownCount++;
            return;
        }
        
        // Check for standard prologue - FILTER OUT
        if (hasStandardPrologue(instructions)) {
            standardCount++;
            return;
        }
        
        // Detect D2 pattern
        String pattern = detectD2Pattern(instructions);
        
        if (pattern != null) {
            FunctionResult result = new FunctionResult();
            result.name = funcName;
            result.address = entryPoint.toString();
            result.convention = pattern;
            result.confidence = calculateConfidence(instructions, pattern);
            result.prologueSnippet = String.join("; ", instructions.subList(0, Math.min(5, instructions.size())));
            
            detections.get(pattern).add(result);
            
            // Apply convention if in apply mode
            if (applyMode) {
                if (applyCallingConvention(func, pattern)) {
                    appliedCount++;
                    result.applied = true;
                } else {
                    failedCount++;
                    result.applied = false;
                }
            }
        } else {
            unknownCount++;
        }
    }
    
    private boolean applyCallingConvention(Function func, String convention) {
        try {
            int txId = currentProgram.startTransaction("Apply " + convention + " to " + func.getName());
            try {
                // Set calling convention
                func.setCallingConvention(convention);
                currentProgram.endTransaction(txId, true);
                return true;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                println("[WARNING] Failed to apply " + convention + " to " + func.getName() + ": " + e.getMessage());
                return false;
            }
        } catch (Exception e) {
            println("[ERROR] Transaction failed for " + func.getName() + ": " + e.getMessage());
            return false;
        }
    }
    
    private boolean hasStandardPrologue(List<String> instructions) {
        if (instructions.size() < 2) {
            return false;
        }
        
        String inst1 = instructions.get(0).toUpperCase();
        String inst2 = instructions.get(1).toUpperCase();
        
        // Standard: PUSH EBP; MOV EBP, ESP
        return inst1.contains("PUSH") && inst1.contains("EBP") &&
               inst2.contains("MOV") && inst2.contains("EBP") && inst2.contains("ESP");
    }
    
    private String detectD2Pattern(List<String> instructions) {
        // Get first 5 instructions for pattern matching
        List<String> first5 = instructions.subList(0, Math.min(5, instructions.size()));
        String allInstructions = String.join(" ", first5).toUpperCase();
        
        // Pattern detection logic (from v2.0)
        
        // __d2call: Immediate stack allocation with SUB ESP
        if (first5.get(0).contains("SUB") && first5.get(0).contains("ESP")) {
            return "__d2call";
        }
        
        // __d2regcall: Register parameters (EAX/EDX/ECX) used immediately
        if (hasRegisterUsage(first5, new String[]{"EAX", "EDX", "ECX"})) {
            // Check if it's using registers for parameters (not just saving them)
            String firstInst = first5.get(0);
            if (firstInst.contains("MOV") && !firstInst.startsWith("PUSH")) {
                return "__d2regcall";
            }
            if (firstInst.contains("TEST") || firstInst.contains("CMP") || 
                firstInst.contains("ADD") || firstInst.contains("SUB")) {
                return "__d2regcall";
            }
        }
        
        // __d2edicall: EDI register usage (special purpose register)
        if (hasRegisterUsage(first5, new String[]{"EDI"})) {
            return "__d2edicall";
        }
        
        // __d2mixcall: Mix of register and stack operations
        boolean hasRegOps = hasRegisterUsage(first5, new String[]{"EAX", "EDX", "ECX", "EBX"});
        boolean hasStackOps = allInstructions.contains("ESP") || allInstructions.contains("EBP");
        
        if (hasRegOps && hasStackOps) {
            // Ensure it's not just saving registers to stack (standard prologue variant)
            if (!first5.get(0).startsWith("PUSH")) {
                return "__d2mixcall";
            }
        }
        
        return null;
    }
    
    private boolean hasRegisterUsage(List<String> instructions, String[] registers) {
        for (int i = 0; i < Math.min(3, instructions.size()); i++) {
            String inst = instructions.get(i).toUpperCase();
            for (String reg : registers) {
                if (inst.contains(reg)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    private double calculateConfidence(List<String> instructions, String pattern) {
        // Simple confidence calculation based on pattern strength
        int matches = 0;
        int checks = 0;
        
        String allInst = String.join(" ", instructions).toUpperCase();
        
        switch (pattern) {
            case "__d2call":
                checks = 2;
                if (allInst.contains("SUB ESP")) matches++;
                if (!hasStandardPrologue(instructions)) matches++;
                break;
                
            case "__d2regcall":
                checks = 3;
                if (hasRegisterUsage(instructions, new String[]{"EAX", "EDX", "ECX"})) matches++;
                if (!allInst.startsWith("PUSH")) matches++;
                if (instructions.get(0).contains("MOV") || instructions.get(0).contains("TEST")) matches++;
                break;
                
            case "__d2edicall":
                checks = 2;
                if (hasRegisterUsage(instructions, new String[]{"EDI"})) matches++;
                if (!hasStandardPrologue(instructions)) matches++;
                break;
                
            case "__d2mixcall":
                checks = 3;
                if (hasRegisterUsage(instructions, new String[]{"EAX", "EDX", "ECX"})) matches++;
                if (allInst.contains("ESP") || allInst.contains("EBP")) matches++;
                if (!hasStandardPrologue(instructions)) matches++;
                break;
        }
        
        return (double) matches / checks;
    }
    
    private int getTotalD2Detections() {
        int total = 0;
        for (List<FunctionResult> list : detections.values()) {
            total += list.size();
        }
        return total;
    }
    
    private void printResults() {
        println("\n========================================");
        println("DETECTION RESULTS");
        println("========================================");
        println();
        println("Total Analyzed: " + totalAnalyzed);
        println("Standard Conventions (filtered): " + standardCount);
        println("Unknown: " + unknownCount);
        println();
        println("D2 CUSTOM CONVENTIONS FOUND: " + getTotalD2Detections());
        
        if (applyMode) {
            println("Applied: " + appliedCount);
            println("Failed: " + failedCount);
        }
        
        println("----------------------------------------");
        
        for (String conv : D2_CONVENTIONS) {
            List<FunctionResult> results = detections.get(conv);
            if (!results.isEmpty()) {
                println();
                println(conv + ": " + results.size() + " functions");
                
                // Show first 20
                for (int i = 0; i < Math.min(20, results.size()); i++) {
                    FunctionResult r = results.get(i);
                    String appliedStr = applyMode ? (r.applied ? " [APPLIED]" : " [FAILED]") : "";
                    println(String.format("  - %s @ %s (%.0f%% confidence)%s",
                        r.name, r.address, r.confidence * 100, appliedStr));
                }
                
                if (results.size() > 20) {
                    println("  ... and " + (results.size() - 20) + " more");
                }
            }
        }
    }
    
    private void exportResults() throws IOException {
        // Export to JSON file on Desktop
        String userHome = System.getProperty("user.home");
        File outputFile = new File(userHome + "\\Desktop\\d2_convention_detections.json");
        
        println("\n[EXPORT] Saving results to: " + outputFile.getAbsolutePath());
        
        // Build JSON structure
        Map<String, Object> jsonData = new LinkedHashMap<>();
        jsonData.put("program", currentProgram.getName());
        jsonData.put("analysisDate", new Date().toString());
        jsonData.put("mode", applyMode ? "detect_and_apply" : "detect_only");
        jsonData.put("totalAnalyzed", totalAnalyzed);
        jsonData.put("standardFiltered", standardCount);
        jsonData.put("unknown", unknownCount);
        jsonData.put("totalD2Detections", getTotalD2Detections());
        
        if (applyMode) {
            jsonData.put("applied", appliedCount);
            jsonData.put("failed", failedCount);
        }
        
        Map<String, List<FunctionResult>> detectionsData = new LinkedHashMap<>();
        for (String conv : D2_CONVENTIONS) {
            detectionsData.put(conv, detections.get(conv));
        }
        jsonData.put("detections", detectionsData);
        
        // Write JSON with Gson
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(outputFile)) {
            gson.toJson(jsonData, writer);
        }
        
        println("[EXPORT] Results saved successfully");
        println("[EXPORT] File size: " + outputFile.length() + " bytes");
    }
    
    // Inner class for function results
    private static class FunctionResult {
        String name;
        String address;
        String convention;
        double confidence;
        String prologueSnippet;
        boolean applied = false;
    }
}

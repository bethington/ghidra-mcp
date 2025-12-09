// Analyze calling convention distribution across all functions
// @author GhidraMCP
// @category Analysis
// @keybinding 
// @menupath Analysis.D2.Analyze Convention Distribution
// @toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class AnalyzeConventionDistribution extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        println("========================================");
        println("CALLING CONVENTION DISTRIBUTION ANALYSIS");
        println("========================================");
        println("Program: " + currentProgram.getName());
        println("Date: " + new Date());
        println();
        
        // Count conventions
        Map<String, Integer> conventionCounts = new HashMap<>();
        Map<String, List<String>> conventionExamples = new HashMap<>();
        Map<String, Integer> paramCountDistribution = new HashMap<>();
        
        int totalFunctions = 0;
        int functionsWithParams = 0;
        int functionsNoParams = 0;
        int undefined = 0;
        
        FunctionManager funcManager = currentProgram.getFunctionManager();
        
        println("Analyzing all functions...");
        println();
        
        for (Function func : funcManager.getFunctions(true)) {
            if (monitor.isCancelled()) {
                break;
            }
            
            totalFunctions++;
            String convention = func.getCallingConventionName();
            int paramCount = func.getParameterCount();
            
            // Count conventions
            conventionCounts.put(convention, 
                conventionCounts.getOrDefault(convention, 0) + 1);
            
            // Store examples (up to 5 per convention)
            if (!conventionExamples.containsKey(convention)) {
                conventionExamples.put(convention, new ArrayList<>());
            }
            List<String> examples = conventionExamples.get(convention);
            if (examples.size() < 5) {
                examples.add(func.getName() + " @ " + func.getEntryPoint());
            }
            
            // Track parameter counts
            if (paramCount > 0) {
                functionsWithParams++;
            } else {
                functionsNoParams++;
            }
            
            String paramKey = paramCount + " params";
            paramCountDistribution.put(paramKey, 
                paramCountDistribution.getOrDefault(paramKey, 0) + 1);
            
            // Track undefined conventions
            if (convention == null || convention.equals("unknown") || 
                convention.equals("undefined")) {
                undefined++;
            }
        }
        
        // Sort conventions by count
        List<Map.Entry<String, Integer>> sortedConventions = 
            new ArrayList<>(conventionCounts.entrySet());
        sortedConventions.sort((a, b) -> b.getValue().compareTo(a.getValue()));
        
        // Print results
        println("========================================");
        println("CONVENTION DISTRIBUTION");
        println("========================================");
        println("Total Functions: " + totalFunctions);
        println();
        
        for (Map.Entry<String, Integer> entry : sortedConventions) {
            String convention = entry.getKey();
            int count = entry.getValue();
            double percentage = (count * 100.0) / totalFunctions;
            
            println(String.format("%-20s: %5d (%5.2f%%)", 
                convention, count, percentage));
            
            // Show examples
            List<String> examples = conventionExamples.get(convention);
            if (examples != null && examples.size() > 0) {
                println("  Examples:");
                for (String example : examples) {
                    println("    " + example);
                }
            }
            println();
        }
        
        // Parameter count distribution
        println("========================================");
        println("PARAMETER COUNT DISTRIBUTION");
        println("========================================");
        println("Functions with params: " + functionsWithParams + 
               " (" + String.format("%.2f%%", 
               (functionsWithParams * 100.0) / totalFunctions) + ")");
        println("Functions without params: " + functionsNoParams + 
               " (" + String.format("%.2f%%", 
               (functionsNoParams * 100.0) / totalFunctions) + ")");
        println();
        
        // Sort param counts
        List<Map.Entry<String, Integer>> sortedParams = 
            new ArrayList<>(paramCountDistribution.entrySet());
        sortedParams.sort((a, b) -> {
            int aNum = Integer.parseInt(a.getKey().split(" ")[0]);
            int bNum = Integer.parseInt(b.getKey().split(" ")[0]);
            return Integer.compare(aNum, bNum);
        });
        
        println("Distribution by parameter count:");
        for (Map.Entry<String, Integer> entry : sortedParams) {
            if (entry.getValue() > 10) { // Only show counts > 10
                double percentage = (entry.getValue() * 100.0) / totalFunctions;
                println(String.format("  %-15s: %5d (%5.2f%%)", 
                    entry.getKey(), entry.getValue(), percentage));
            }
        }
        println();
        
        // Analysis and recommendations
        println("========================================");
        println("ANALYSIS");
        println("========================================");
        
        int customConventions = 0;
        int standardConventions = 0;
        
        for (Map.Entry<String, Integer> entry : conventionCounts.entrySet()) {
            String conv = entry.getKey();
            if (conv.startsWith("__d2")) {
                customConventions += entry.getValue();
            } else if (conv.equals("__cdecl") || conv.equals("__stdcall") || 
                      conv.equals("__fastcall") || conv.equals("__thiscall")) {
                standardConventions += entry.getValue();
            }
        }
        
        println("Standard conventions: " + standardConventions + 
               " (" + String.format("%.2f%%", 
               (standardConventions * 100.0) / totalFunctions) + ")");
        println("Custom D2 conventions: " + customConventions + 
               " (" + String.format("%.2f%%", 
               (customConventions * 100.0) / totalFunctions) + ")");
        println();
        
        // Check for suspicious patterns
        int d2regcallCount = conventionCounts.getOrDefault("__d2regcall", 0);
        int stdcallCount = conventionCounts.getOrDefault("__stdcall", 0);
        
        println("POTENTIAL ISSUES:");
        if (d2regcallCount > stdcallCount * 0.5) {
            println("⚠️  WARNING: High __d2regcall count (" + d2regcallCount + 
                   ") relative to __stdcall (" + stdcallCount + ")");
            println("   This may indicate misclassification of stack-based functions.");
            println("   Consider running FixFunctionParameters with updated detection.");
        } else {
            println("✓ Convention distribution looks reasonable.");
        }
        
        if (undefined > totalFunctions * 0.1) {
            println("⚠️  WARNING: " + undefined + " functions with undefined conventions");
            println("   (" + String.format("%.2f%%", (undefined * 100.0) / totalFunctions) + 
                   " of total)");
        }
        
        println();
        println("========================================");
        println("RECOMMENDATIONS");
        println("========================================");
        
        if (d2regcallCount > 100) {
            println("1. Review sample __d2regcall functions for false positives");
            println("2. Check if they have MOV reg,[ESP+offset] patterns");
            println("3. Run FixFunctionParameters with stack load detection");
        }
        
        if (functionsNoParams > totalFunctions * 0.3) {
            println("4. Many functions show 0 parameters - consider parameter detection");
        }
        
        println();
        println("[COMPLETE] Analysis finished");
    }
}

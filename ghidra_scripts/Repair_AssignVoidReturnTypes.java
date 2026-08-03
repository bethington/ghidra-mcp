// Assign Void Return Types
//
// Scans all functions and assigns void return type to any function with undefined or unassigned return types. Prevents misleading decompiler output from undefined returns.
//
// Usage: Run from Script Manager on any program.
// Output: Sets void return type on functions with undefined returns.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Assign void return type to undefined functions
// @menupath Diablo 2.Repair.Assign Void Return Types

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.symbol.SourceType;

public class Repair_AssignVoidReturnTypes extends GhidraScript {

    @Override
    protected void run() throws Exception {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);
        
        DataType voidType = VoidDataType.dataType;
        
        int modifiedCount = 0;
        int totalFunctions = 0;
        
        monitor.setMessage("Scanning functions for undefined return types...");
        
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            totalFunctions++;
            
            DataType returnType = func.getReturnType();
            
            // Check if return type is undefined or default undefined type
            if (returnType == null || 
                returnType.getName().equals("undefined") ||
                returnType.getName().startsWith("undefined") ||
                returnType.getName().equals("unknown")) {
                
                try {
                    func.setReturnType(voidType, SourceType.USER_DEFINED);
                    modifiedCount++;
                    
                    if (modifiedCount % 100 == 0) {
                        monitor.setMessage("Modified " + modifiedCount + " functions...");
                    }
                } catch (Exception e) {
                    println("Failed to set return type for function: " + func.getName() + 
                            " at " + func.getEntryPoint() + " - " + e.getMessage());
                }
            }
        }
        
        if (monitor.isCancelled()) {
            println("Operation cancelled by user.");
        }
        
        println("=== Summary ===");
        println("Total functions scanned: " + totalFunctions);
        println("Functions modified to void: " + modifiedCount);
    }
}

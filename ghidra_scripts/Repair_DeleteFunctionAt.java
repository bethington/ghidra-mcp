// Delete Function At
//
// Deletes the function at a specific hardcoded address (0x6ffb5cb8). One-off repair script for removing an erroneously created function.
//
// Usage: Run from Script Manager. Edit source to change target address.
// Output: Removes the function at the specified address.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Delete a function at a hardcoded address
// @menupath Diablo 2.Repair.Delete Function At

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class Repair_DeleteFunctionAt extends GhidraScript {
    @Override
    protected void run() throws Exception {
        // Target address - GetOrCreateCachedBlitCode
        Address addr = toAddr("0x6ffb5cb8");
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function func = funcMgr.getFunctionAt(addr);
        
        if (func == null) {
            println("No function found at " + addr);
            return;
        }
        
        String funcName = func.getName();
        
        int txId = currentProgram.startTransaction("Delete function " + funcName);
        try {
            boolean success = funcMgr.removeFunction(addr);
            if (success) {
                println("Deleted function: " + funcName + " at " + addr);
            } else {
                println("Failed to delete function at " + addr);
            }
            currentProgram.endTransaction(txId, success);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            throw e;
        }
    }
}

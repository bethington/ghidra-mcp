//Delete a function at a specific address
//@author GhidraMCP
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class DeleteFunctionAt extends GhidraScript {
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

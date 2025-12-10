//Fixes function FUN_6fae4270 to include proper boundaries
//@category Fix
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class FixFunction_6fae4270 extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Address startAddr = toAddr(0x6fae4270L);
        Address endAddr = toAddr(0x6fae428dL);
        
        // Get the existing function
        Function func = funcMgr.getFunctionAt(startAddr);
        if (func != null) {
            println("Found function: " + func.getName());
            println("Current body: " + func.getBody());
            
            // Remove and recreate with correct body
            funcMgr.removeFunction(startAddr);
            println("Removed old function");
            
            // Create address set for full function
            AddressSet body = new AddressSet(startAddr, endAddr);
            
            // Create the function with correct body
            Function newFunc = funcMgr.createFunction("FUN_6fae4270", startAddr, body, null);
            if (newFunc != null) {
                println("Created new function: " + newFunc.getName());
                println("New body: " + newFunc.getBody());
            }
        } else {
            println("No function at address");
        }
    }
}

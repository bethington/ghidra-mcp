// RecreateFunction_6fa06a80.java
// Deletes and recreates a function at 0x6fa06a80
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6fa06a80 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6fa06a80L);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Removing: " + existingFunc.getName());
            funcMgr.removeFunction(targetAddr);
        }
        
        // Create function - Ghidra will find the extent
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed");
        }
    }
}

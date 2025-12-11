// Recreate_6fc814d0.java
// Creates function at 0x6fc814d0
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Recreate_6fc814d0 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6fc814d0L);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        if (existingFunc != null) {
            funcMgr.removeFunction(targetAddr);
            println("Removed existing function");
        }
        
        // Disassemble and create
        disassemble(targetAddr);
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created: " + newFunc.getName() + " Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

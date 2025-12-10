// RecreateFunction_6f90f580.java
// Recreates function at 0x6f90f580 with proper boundaries
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6f90f580 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6f90f580L);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            funcMgr.removeFunction(targetAddr);
        }
        
        // Clear and disassemble (RET 4 at 0x6f90f5c3)
        Address endAddr = targetAddr.add(0x50);
        clearListing(targetAddr, endAddr);
        println("Cleared listing from " + targetAddr + " to " + endAddr);
        
        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);
        
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

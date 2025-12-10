// RecreateFunction_6f90f420.java
// Deletes and recreates function at 0x6f90f420
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6f90f420 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6f90f420L);
        Address endAddr = toAddr(0x6f90f44bL); // RET 4 ends at 0x6f90f44a
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Removing: " + existingFunc.getName() + " body=" + existingFunc.getBody());
            funcMgr.removeFunction(targetAddr);
        }
        
        // Clear and disassemble
        clearListing(targetAddr, endAddr);
        println("Cleared " + targetAddr + " to " + endAddr);
        
        disassemble(targetAddr);
        println("Disassembled");
        
        // Create function
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

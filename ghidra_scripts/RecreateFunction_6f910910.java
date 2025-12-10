// RecreateFunction_6f910910.java
// Recreates function at 0x6f910910
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6f910910 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6f910910L);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Found existing function: " + existingFunc.getName());
            println("Body: " + existingFunc.getBody());
            funcMgr.removeFunction(targetAddr);
            println("Removed existing function");
        }
        
        // Clear and disassemble - function ends around 0x6f91098f (two RET instructions at ~0x87-0x8a)
        Address endAddr = targetAddr.add(0x90);
        clearListing(targetAddr, endAddr);
        println("Cleared listing from " + targetAddr + " to " + endAddr);
        
        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);
        
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created new function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

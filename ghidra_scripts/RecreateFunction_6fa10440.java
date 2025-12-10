// RecreateFunction_6fa10440.java
// Recreates function at 0x6fa10440
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6fa10440 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6fa10440L);
        Address endAddr = targetAddr.add(0x5f); // End before 0x6fa104a0
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Found existing function: " + existingFunc.getName());
            println("Body: " + existingFunc.getBody());
            funcMgr.removeFunction(targetAddr);
            println("Removed existing function");
        }
        
        clearListing(targetAddr, endAddr);
        println("Cleared listing from " + targetAddr + " to " + endAddr);
        
        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);
        
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created new function: " + newFunc.getName());
            println("Entry: " + newFunc.getEntryPoint());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

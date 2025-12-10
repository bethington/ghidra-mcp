// RecreateFunction_6fc320a0.java
// Deletes and recreates a function at address 0x6fc320a0
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6fc320a0 extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Target address for FUN_6fc320a0
        Address targetAddr = toAddr(0x6fc320a0L);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Found existing function: " + existingFunc.getName());
            println("Entry: " + existingFunc.getEntryPoint());
            println("Body: " + existingFunc.getBody());
            
            // Delete the existing function
            funcMgr.removeFunction(targetAddr);
            println("Removed existing function");
        }
        
        // Clear listing from 0x6fc320a0 to 0x6fc320c2 (function ends with RET 8)
        Address endAddr = toAddr(0x6fc320c3L);
        clearListing(targetAddr, endAddr);
        println("Cleared listing from " + targetAddr + " to " + endAddr);
        
        // Disassemble
        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);
        
        // Create function
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

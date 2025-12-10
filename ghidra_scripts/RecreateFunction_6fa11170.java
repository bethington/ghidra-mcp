// RecreateFunction_6fa11170.java
// Deletes and recreates function at 0x6fa11170
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6fa11170 extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Target address
        Address targetAddr = toAddr(0x6fa11170L);
        
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
        
        // Clear any existing instructions/data at the target range
        // RET 4 (C2 04 00) appears at around offset 0x40-0x43
        Address endAddr = targetAddr.add(0x47); // End before next function
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

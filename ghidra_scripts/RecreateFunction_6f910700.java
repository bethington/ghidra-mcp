// RecreateFunction_6f910700.java
// Deletes and recreates a function at 0x6f910700 (popup render handler)
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6f910700 extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Target address for popup render handler
        Address targetAddr = toAddr(0x6f910700L);
        
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
        // Function appears to be roughly 150-200 bytes based on decompiler output
        Address endAddr = targetAddr.add(0xC0); // 192 bytes should be enough
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

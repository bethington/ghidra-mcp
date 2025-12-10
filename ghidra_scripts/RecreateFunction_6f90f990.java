// RecreateFunction_6f90f990.java
// Deletes and recreates a function at address 0x6f90f990
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6f90f990 extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Target address
        Address targetAddr = toAddr(0x6f90f990L);
        
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
        
        // Clear any existing instructions/data - function ends around 0x6f90fb07 based on decompiler
        Address endAddr = targetAddr.add(0x180); // ~384 bytes should cover it
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

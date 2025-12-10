// RecreateFunction_6fa0e150.java
// Deletes and recreates function FormatIncomingWhisperWithTitle at 0x6fa0e150
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6fa0e150 extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Target address
        Address targetAddr = toAddr(0x6fa0e150L);
        
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
        
        // Clear listing - function ends around 0x6fa0e40d with RETN 8
        Address endAddr = toAddr(0x6fa0e420L);
        clearListing(targetAddr, endAddr);
        println("Cleared listing from " + targetAddr + " to " + endAddr);
        
        // Disassemble
        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);
        
        // Create function
        Function newFunc = createFunction(targetAddr, "FormatIncomingWhisperWithTitle");
        if (newFunc != null) {
            println("Created new function: " + newFunc.getName());
            println("Entry: " + newFunc.getEntryPoint());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

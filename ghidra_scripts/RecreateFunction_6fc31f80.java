// RecreateFunction_6fc31f80.java
// Recreates FUN_6fc31f80 with correct boundaries
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6fc31f80 extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Target address for the network callback function
        Address targetAddr = toAddr(0x6fc31f80L);
        
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
        
        // Clear the listing for the function range (0x6fc31f80 to 0x6fc31f92 inclusive = RET 4)
        // Function bytes: 8B CA 8B 54 24 04 E8 A5 F8 FF FF B8 01 00 00 00 C2 04 00
        // = 19 bytes, ending at 0x6fc31f92
        Address endAddr = targetAddr.add(0x20); // Clear a bit more to be safe
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

// Recreate function at 0x6fc956a0
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class RecreateFunction6fc956a0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc956a0L);
        
        // Remove existing function if present
        Function existingFunc = getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function at " + addr);
            removeFunction(existingFunc);
        }
        
        // Clear any existing code/data
        println("Clearing listing at " + addr);
        clearListing(addr, addr.add(255));
        
        // Disassemble
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create function
        println("Creating function at " + addr);
        Function newFunc = createFunction(addr, "FUN_6fc956a0");
        
        if (newFunc != null) {
            println("SUCCESS: Function created at " + addr);
            println("Function body: " + newFunc.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

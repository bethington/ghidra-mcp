//Recreate function at 0x6fa110c0 with correct boundaries
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6fa110c0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fa110c0);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existingFunc = fm.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the bytes first
        clearListing(addr, toAddr(0x6fa110c7));
        disassemble(addr);
        
        // Create new function
        Function newFunc = createFunction(addr, "FUN_6fa110c0");
        if (newFunc != null) {
            println("Created function at " + addr + " with body ending at " + newFunc.getBody().getMaxAddress());
        } else {
            println("Failed to create function");
        }
    }
}

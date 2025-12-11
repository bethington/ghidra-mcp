//Recreate function at 0x6fc98b00
//@category Fix
//@menupath

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class RecreateFunc6fc98b00 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc98b00);
        
        // Remove existing function
        Function func = getFunctionAt(addr);
        if (func != null) {
            removeFunction(func);
            println("Removed existing function at " + addr);
        }
        
        // Clear any existing code/data
        clearListing(addr, toAddr(0x6fc98bc0));
        
        // Disassemble
        disassemble(addr);
        
        // Create function
        func = createFunction(addr, "FUN_6fc98b00");
        if (func != null) {
            println("Created function: " + func.getName() + " at " + func.getEntryPoint());
            println("Body: " + func.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

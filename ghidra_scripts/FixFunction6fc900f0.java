//Recreate function at 0x6fc900f0
//@author GhidraMCP
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class FixFunction6fc900f0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc900f0L);
        
        // Remove existing function
        Function func = getFunctionAt(addr);
        if (func != null) {
            println("Removing existing function at " + addr);
            removeFunction(func);
        }
        
        // Clear flow references that may interfere
        clearListing(addr, addr.add(127));
        
        // Disassemble
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create function
        println("Creating function at " + addr);
        func = createFunction(addr, null);
        
        if (func != null) {
            println("Function created: " + func.getName() + " at " + func.getEntryPoint());
            println("Body: " + func.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

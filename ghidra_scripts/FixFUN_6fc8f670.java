//Fix FUN_6fc8f670 - Recreate function with proper disassembly
//@category Repair
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class FixFUN_6fc8f670 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8f670);
        
        // Remove existing function if present
        Function existingFunc = getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function at " + addr);
            removeFunction(existingFunc);
        }
        
        // Clear any existing instructions in the area
        println("Clearing and disassembling from " + addr);
        clearListing(addr, addr.add(127));
        
        // Disassemble
        disassemble(addr);
        
        // Create function
        println("Creating function at " + addr);
        Function func = createFunction(addr, null);
        
        if (func != null) {
            println("SUCCESS: Created function " + func.getName() + " at " + addr);
            println("Function body: " + func.getBody());
        } else {
            println("FAILED: Could not create function at " + addr);
        }
    }
}

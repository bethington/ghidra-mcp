// Fix Function at 6fc83ca0
// @category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class FixFun6fc83ca0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc83ca0L);
        
        // Remove existing function
        Function func = getFunctionAt(addr);
        if (func != null) {
            println("Removing existing function at " + addr);
            removeFunction(func);
        }
        
        // Disassemble from start
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create new function
        println("Creating function at " + addr);
        func = createFunction(addr, null);
        
        if (func != null) {
            println("SUCCESS: Created function " + func.getName() + " at " + func.getEntryPoint());
            println("Body: " + func.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

//Fix truncated function at 6fc89070
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class Fix6fc89070 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc89070L);
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(addr);
        
        if (func != null) {
            println("Removing: " + func.getName() + " body: " + func.getBody());
            fm.removeFunction(addr);
        }
        
        // Disassemble
        disassemble(addr);
        
        // Create function - let Ghidra auto-detect boundaries
        func = createFunction(addr, null);
        if (func != null) {
            println("Created: " + func.getName() + " body: " + func.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

//Recreate function at 0x6fc968a0
//@category Fix
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class RecreateFunc6fc968a0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc968a0L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if any
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble bytes
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create function
        println("Creating function at " + addr);
        Function newFunc = createFunction(addr, "FUN_6fc968a0");
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName());
            println("Range: " + newFunc.getBody());
        } else {
            println("FAILED: Could not create function");
        }
    }
}

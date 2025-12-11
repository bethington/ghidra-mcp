//Recreate function at 0x6fc84d10
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class FixFUN_6fc84d10 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc84d10L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the area first
        disassemble(addr);
        
        // Create new function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        cmd.applyTo(currentProgram);
        
        Function newFunc = fm.getFunctionAt(addr);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

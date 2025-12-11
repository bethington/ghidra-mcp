// Recreate FUN_6fc982d0 with proper bounds
// @category Fix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class RecreateFUN_6fc982d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc982d0);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the area
        clearListing(addr, toAddr(0x6fc98320));
        disassemble(addr);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        cmd.applyTo(currentProgram);
        
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            println("Created function: " + func.getName());
            println("Body: " + func.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

// Fix FUN_6fc982d0 by recreating with proper bounds
// @category Fix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFUN_6fc982d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc982d0);
        Address endAddr = toAddr(0x6fc98320);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existing = fm.getFunctionAt(startAddr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(startAddr);
        }
        
        // Clear and disassemble
        clearListing(startAddr, endAddr);
        disassemble(startAddr);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(startAddr);
        cmd.applyTo(currentProgram);
        
        Function func = fm.getFunctionAt(startAddr);
        if (func != null) {
            println("SUCCESS: Created function " + func.getName());
            println("Body: " + func.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

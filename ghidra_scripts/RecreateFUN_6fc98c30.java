//Recreate function at 0x6fc98c30
//@author GhidraMCP
//@category Fix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class RecreateFUN_6fc98c30 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc98c30);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Clear and disassemble
        clearListing(addr, toAddr(0x6fc98c73));
        disassemble(addr);
        
        // Create new function
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

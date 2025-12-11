// Recreate function at 0x6fc982d0 with proper bounds
// @category Fix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFunc6fc982d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc982d0);
        Address endAddr = toAddr(0x6fc98328);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existing = fm.getFunctionAt(startAddr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(startAddr);
        }
        
        // Clear listing and disassemble
        clearListing(startAddr, endAddr);
        disassemble(startAddr);
        
        // Create function using command
        CreateFunctionCmd cmd = new CreateFunctionCmd(startAddr);
        boolean success = cmd.applyTo(currentProgram);
        
        if (success) {
            Function func = fm.getFunctionAt(startAddr);
            if (func != null) {
                func.setName("ApplyManaRechargeShrineEffect", ghidra.program.model.symbol.SourceType.USER_DEFINED);
                println("Created function: " + func.getName());
                println("Body: " + func.getBody());
            }
        } else {
            println("Failed to create function: " + cmd.getStatusMsg());
        }
    }
}

//Recreate function at 6fc89070 with proper boundaries
//@category Analysis
//@author GhidraMCP

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class RecreateFUN_6fc89070 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc89070L);
        
        // Get existing function
        Function existingFunc = getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            removeFunction(existingFunc);
        }
        
        // Clear and disassemble the range
        Address endAddr = toAddr(0x6fc890a0L);
        println("Disassembling from " + startAddr + " to " + endAddr);
        
        // Clear any existing code units first
        clearListing(startAddr, endAddr);
        
        // Disassemble the range
        DisassembleCommand disCmd = new DisassembleCommand(startAddr, null, true);
        disCmd.applyTo(currentProgram, monitor);
        
        // Create the function
        CreateFunctionCmd cmd = new CreateFunctionCmd(startAddr);
        boolean success = cmd.applyTo(currentProgram, monitor);
        
        if (success) {
            Function newFunc = getFunctionAt(startAddr);
            if (newFunc != null) {
                println("Created function: " + newFunc.getName());
                println("Body: " + newFunc.getBody());
            }
        } else {
            println("Failed to create function");
        }
    }
}

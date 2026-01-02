//Clear and disassemble range for FUN_6f876960
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class ClearAndDisasm6f876960 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x6f876960L);
        Address end = toAddr(0x6f876a4fL);
        
        // Remove existing function first
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(start);
        if (func != null) {
            fm.removeFunction(start);
            println("Removed function at " + start);
        }
        
        // Clear the listing
        clearListing(start, end);
        println("Cleared " + start + " to " + end);
        
        // Disassemble
        disassemble(start);
        println("Disassembled from " + start);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(start);
        cmd.applyTo(currentProgram, monitor);
        
        func = fm.getFunctionAt(start);
        if (func != null) {
            println("Created function: " + func.getName());
            println("Body: " + func.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

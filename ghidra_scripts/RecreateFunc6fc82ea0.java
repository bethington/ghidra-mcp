// Recreate function at 0x6fc82ea0
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class RecreateFunc6fc82ea0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc82ea0);
        Address endAddr = toAddr(0x6fc82fa0); // Estimate ~256 bytes
        
        // First clear any code/data in the range
        clearListing(startAddr, endAddr);
        println("Cleared listing from " + startAddr + " to " + endAddr);
        
        // Disassemble
        DisassembleCommand cmd = new DisassembleCommand(startAddr, null, true);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembled starting at " + startAddr);
        
        // Create function
        createFunction(startAddr, null);
        
        Function func = getFunctionAt(startAddr);
        if (func != null) {
            println("Function created: " + func.getName());
            println("Body: " + func.getBody());
        } else {
            println("Function creation failed");
        }
    }
}

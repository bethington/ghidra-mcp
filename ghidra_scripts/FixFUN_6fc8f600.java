// Fix FUN_6fc8f600 - recreate function with proper bounds
// @category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class FixFUN_6fc8f600 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8f600);
        Address endAddr = toAddr(0x6fc8f61d); // RET 8 at 6fc8f61a + 3 bytes
        
        // Remove existing function
        Function existingFunc = getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            removeFunction(existingFunc);
        }
        
        // Clear and disassemble
        println("Clearing code units from " + addr + " to " + endAddr);
        clearListing(addr, endAddr);
        
        println("Disassembling...");
        disassemble(addr);
        
        // Create function
        println("Creating function...");
        Function newFunc = createFunction(addr, "FUN_6fc8f600");
        if (newFunc != null) {
            println("SUCCESS: Function created at " + addr);
            println("Body: " + newFunc.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

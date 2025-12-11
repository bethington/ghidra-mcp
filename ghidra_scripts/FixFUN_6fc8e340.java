// Fix FUN_6fc8e340 - recreate with proper boundaries
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class FixFUN_6fc8e340 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8e340);
        
        // Remove existing function
        Function existingFunc = getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function at " + addr);
            removeFunction(existingFunc);
        }
        
        // Disassemble the area
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create new function
        println("Creating function at " + addr);
        Function newFunc = createFunction(addr, null);
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + " at " + addr);
            println("Body: " + newFunc.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

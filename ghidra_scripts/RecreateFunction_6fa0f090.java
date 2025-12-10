// Recreate function at 0x6fa0f090 with correct boundaries
// @category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class RecreateFunction_6fa0f090 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fa0f090);
        Address endAddr = toAddr(0x6fa0f21a);  // After last RET instruction
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(startAddr);
        
        // Remove existing function if present
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            funcMgr.removeFunction(startAddr);
        }
        
        // Disassemble the range first
        println("Disassembling range: " + startAddr + " to " + endAddr);
        disassemble(startAddr);
        
        // Create the function
        println("Creating function at: " + startAddr);
        Function newFunc = createFunction(startAddr, null);
        
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + " at " + startAddr);
            println("Function body: " + newFunc.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

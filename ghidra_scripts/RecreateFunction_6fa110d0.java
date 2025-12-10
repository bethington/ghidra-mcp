// Recreate function at 0x6fa110d0 with correct boundaries
// @category Repair
// @author Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class RecreateFunction_6fa110d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fa110d0);
        Address endAddr = toAddr(0x6fa11123);  // RET 4 at 0x6fa11120 (3 bytes: C2 04 00)
        
        println("=== Recreating function at 0x6fa110d0 ===");
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Function existingFunc = fm.getFunctionAt(startAddr);
        
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(startAddr);
        }
        
        // Clear any existing instructions and disassemble
        println("Disassembling range 0x6fa110d0 - 0x6fa11123");
        disassemble(startAddr);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(startAddr);
        cmd.applyTo(currentProgram);
        
        Function newFunc = fm.getFunctionAt(startAddr);
        if (newFunc != null) {
            println("SUCCESS: Function created at " + startAddr);
            println("Body: " + newFunc.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

// Recreate FUN_6fc890a0 which has a broken function body
// @category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class RecreateFUN_6fc890a0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc890a0);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing broken function
        Function existingFunc = fm.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing broken function at " + addr);
            fm.removeFunction(addr);
        }
        
        // Disassemble the bytes
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create new function
        println("Creating function at " + addr);
        Function newFunc = createFunction(addr, "FUN_6fc890a0");
        
        if (newFunc != null) {
            println("Successfully recreated function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

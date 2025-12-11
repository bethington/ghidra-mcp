// Fix function FUN_6fc845e0 by recreating it with proper disassembly
//@category Repair
//@author GhidraMCP

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class FixFUN_6fc845e0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc845e0L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing broken function
        Function existingFunc = fm.getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(startAddr);
        }
        
        // Disassemble from start address
        println("Disassembling from " + startAddr);
        disassemble(startAddr);
        
        // Create function
        println("Creating function at " + startAddr);
        Function newFunc = createFunction(startAddr, null);
        
        if (newFunc != null) {
            println("Successfully created function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

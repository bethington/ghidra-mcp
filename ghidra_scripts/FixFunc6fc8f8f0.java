//Fix function at 0x6fc8f8f0 by removing and recreating
//@category Repair
//@author GhidraMCP

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class FixFunc6fc8f8f0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        long startAddr = 0x6fc8f8f0L;
        Address addr = toAddr(startAddr);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Step 1: Remove existing broken function
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing: " + existing.getName() + " body=" + existing.getBody());
            fm.removeFunction(addr);
            println("Removed.");
        }
        
        // Step 2: Clear any undefined bytes and disassemble
        println("Clearing and disassembling range...");
        AddressSet range = new AddressSet(addr, toAddr(startAddr + 0x400));
        clearListing(range);
        disassemble(addr);
        
        // Step 3: Create function
        println("Creating function...");
        Function newFunc = createFunction(addr, "FUN_6fc8f8f0");
        if (newFunc != null) {
            println("SUCCESS: " + newFunc.getName() + " body=" + newFunc.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

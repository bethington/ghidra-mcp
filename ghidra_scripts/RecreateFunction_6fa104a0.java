// RecreateFunction_6fa104a0.java
// Deletes and recreates function at 0x6fa104a0
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6fa104a0 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6fa104a0L);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Found existing function: " + existingFunc.getName());
            println("Body: " + existingFunc.getBody());
            funcMgr.removeFunction(targetAddr);
            println("Removed existing function");
        }
        
        // End at 0x6fa104fa (before jump table data at 0x6fa104f8)
        // XOR EAX,EAX; RET 0xC is at 0x6fa104f5-0x6fa104fa
        Address endAddr = targetAddr.add(0x5a); // 0x6fa104fa
        clearListing(targetAddr, endAddr);
        println("Cleared listing from " + targetAddr + " to " + endAddr);
        
        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);
        
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created new function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

//Fix function at 0x6fc96aa0 - clear range and recreate
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class FixFunction6fc96aa0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc96aa0L);
        Address endAddr = toAddr(0x6fc96f6fL);  // Just before next function
        
        println("Working on: " + currentProgram.getName());
        println("Start: " + startAddr);
        println("End: " + endAddr);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existingFunc = funcMgr.getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            funcMgr.removeFunction(startAddr);
        }
        
        // Clear the entire range
        println("Clearing listing...");
        AddressSet rangeSet = new AddressSet(startAddr, endAddr);
        clearListing(rangeSet);
        
        // Disassemble the range
        println("Disassembling range...");
        disassemble(startAddr);
        
        // Create function
        println("Creating function...");
        Function newFunc = createFunction(startAddr, null);
        
        if (newFunc != null) {
            println("SUCCESS: " + newFunc.getName());
            println("Body: " + newFunc.getBody().getNumAddresses() + " bytes");
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

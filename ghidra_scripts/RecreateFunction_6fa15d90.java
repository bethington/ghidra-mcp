// RecreateFunction_6fa15d90.java
// Recreates strcmp function at 0x6fa15d90
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6fa15d90 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6fa15d90L);
        Address endAddr = toAddr(0x6fa15e1fL);  // Before StrCSpn at 0x6fa15e20
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Found existing function: " + existingFunc.getName());
            println("Entry: " + existingFunc.getEntryPoint());
            println("Body: " + existingFunc.getBody());
            funcMgr.removeFunction(targetAddr);
            println("Removed existing function");
        }
        
        // Clear and disassemble
        clearListing(targetAddr, endAddr);
        println("Cleared listing from " + targetAddr + " to " + endAddr);
        
        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);
        
        // Create function
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

// RecreateFunction_6f910c90.java
// Recreate FUN_6f910c90 (RenderScrollbarControl) with proper boundaries
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6f910c90 extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Target address for RenderScrollbarControl
        Address targetAddr = toAddr(0x6f910c90L);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            println("Found existing function: " + existingFunc.getName());
            println("Body: " + existingFunc.getBody());
            
            // Delete the existing truncated function
            funcMgr.removeFunction(targetAddr);
            println("Removed existing function");
        }
        
        // Clear and disassemble from 0x6f910c90 to 0x6f910e28 (past the last RET)
        // Based on decompiled code showing multiple returns
        Address endAddr = toAddr(0x6f910e30L);
        clearListing(targetAddr, endAddr);
        println("Cleared listing from " + targetAddr + " to " + endAddr);
        
        // Disassemble the entire range
        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);
        
        // Create function - Ghidra will auto-detect boundaries
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("SUCCESS: Created function: " + newFunc.getName());
            println("Entry: " + newFunc.getEntryPoint());
            println("Body: " + newFunc.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

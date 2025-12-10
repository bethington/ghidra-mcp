// RecreateFunction_6f90f520.java
// Recreates function at 0x6f90f520 with correct body range
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6f90f520 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6f90f520L);
        Address endAddr = toAddr(0x6f90f538L); // Just past RET 4 at 0x6f90f535

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);

        if (existingFunc != null) {
            println("Found existing function: " + existingFunc.getName());
            funcMgr.removeFunction(targetAddr);
            println("Removed existing function");
        }

        // Clear and disassemble
        clearListing(targetAddr, endAddr);
        println("Cleared listing");

        boolean didDisasm = disassemble(targetAddr);
        println("Disassembly result: " + didDisasm);

        // Create function
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created: " + newFunc.getName() + " Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

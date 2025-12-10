// RecreateFunction_6fc36470.java
// Recreates the _aullrem function at address 0x6fc36470
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class RecreateFunction_6fc36470 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6fc36470L);
        Address endAddr = toAddr(0x6fc364e7L); // RET 0x10 is at this address (last byte of instruction)
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing broken function
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            funcMgr.removeFunction(targetAddr);
        }
        
        // Clear listing in the range
        println("Clearing listing from " + targetAddr + " to " + endAddr);
        clearListing(targetAddr, endAddr);
        
        // Force disassembly using DisassembleCommand
        DisassembleCommand cmd = new DisassembleCommand(targetAddr, null, true);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembly applied");
        
        // Create the function
        Function newFunc = createFunction(targetAddr, "_aullrem");
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName());
            println("Entry: " + newFunc.getEntryPoint());
            println("Body: " + newFunc.getBody());
        } else {
            println("FAILED: Could not create function");
        }
    }
}

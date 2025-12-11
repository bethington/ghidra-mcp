//Recreate function at 0x6fc90160
//@category MCP
//@author Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction6fc90160 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc90160L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if any
        Function existingFunc = fm.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the bytes - function is about 300 bytes based on hex dump
        println("Disassembling at " + addr);
        clearListing(addr, addr.add(511));
        disassemble(addr);
        
        // Create function
        println("Creating function at " + addr);
        Function newFunc = createFunction(addr, null);
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + " at " + addr);
            println("Body: " + newFunc.getBody());
        } else {
            println("FAILED: Could not create function");
        }
    }
}

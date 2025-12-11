//Recreate function at 0x6fc85470
//@category Repair
//@author AI Assistant

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction6fc85470 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc85470L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existingFunc = fm.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the area
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create fresh function
        println("Creating new function at " + addr);
        Function newFunc = createFunction(addr, null);
        
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + 
                    " spanning " + newFunc.getBody().getMinAddress() + 
                    " to " + newFunc.getBody().getMaxAddress());
        } else {
            println("FAILED: Could not create function at " + addr);
        }
    }
}

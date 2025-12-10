//Recreate function at 0x6fa10710
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6fa10710 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fa10710L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the range
        println("Disassembling range...");
        disassemble(addr);
        
        // Create the function
        println("Creating function at " + addr);
        Function newFunc = fm.createFunction(null, addr, null, SourceType.USER_DEFINED);
        
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + 
                    " at " + newFunc.getEntryPoint() +
                    " body: " + newFunc.getBody());
        } else {
            println("FAILED: Could not create function");
        }
    }
}

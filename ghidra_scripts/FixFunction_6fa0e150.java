// FixFunction_6fa0e150.java
// Fix function at 0x6fa0e150 by clearing code units and recreating
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.CodeUnit;

public class FixFunction_6fa0e150 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fa0e150L);
        Address endAddr = toAddr(0x6fa0e40fL);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove any functions in range
        AddressSet range = new AddressSet(startAddr, endAddr);
        for (Function f : funcMgr.getFunctions(range, true)) {
            println("Removing function: " + f.getName() + " at " + f.getEntryPoint());
            funcMgr.removeFunction(f.getEntryPoint());
        }
        
        // Clear all code units in the range
        currentProgram.getListing().clearCodeUnits(startAddr, endAddr, false);
        println("Cleared code units from " + startAddr + " to " + endAddr);
        
        // Disassemble the range
        disassemble(startAddr);
        println("Disassembled starting at " + startAddr);
        
        // Create the function
        Function newFunc = createFunction(startAddr, "FormatIncomingWhisperWithTitle");
        if (newFunc != null) {
            println("SUCCESS: Created " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

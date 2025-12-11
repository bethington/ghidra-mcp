//Expand function at 0x6fc96f70 to proper bounds
//@category Fix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.disassemble.*;
import ghidra.app.cmd.function.*;

public class ExpandFunc6fc96f70 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x6fc96f70L);
        Address end = toAddr(0x6fc970bfL);
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        
        // Step 1: Remove current truncated function
        Function existing = fm.getFunctionAt(start);
        if (existing != null) {
            println("Removing truncated function: " + existing.getName() + " body: " + existing.getBody());
            fm.removeFunction(start);
        }
        
        // Step 2: Clear and disassemble the entire range
        println("Clearing and disassembling range " + start + " to " + end);
        AddressSet range = new AddressSet(start, end);
        
        // Clear the range first
        try {
            listing.clearCodeUnits(start, end, false, monitor);
        } catch (Exception e) {
            println("Clear warning: " + e.getMessage());
        }
        
        // Disassemble from start
        DisassembleCommand disCmd = new DisassembleCommand(start, range, true);
        disCmd.applyTo(currentProgram, monitor);
        println("Disassembled " + disCmd.getDisassembledAddressSet());
        
        // Step 3: Create function - let Ghidra auto-detect bounds
        CreateFunctionCmd createCmd = new CreateFunctionCmd(start);
        boolean success = createCmd.applyTo(currentProgram, monitor);
        
        Function newFunc = fm.getFunctionAt(start);
        if (newFunc != null) {
            println("SUCCESS: Created " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("FAILED to create function. Trying manual creation...");
        }
    }
}

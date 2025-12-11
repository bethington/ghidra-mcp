//Expand ApplyManaRechargeShrineEffect function body
//@category Fix
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.symbol.*;

public class ExpandFunction6fc982d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc982d0);
        Address endAddr = toAddr(0x6fc98330);
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        
        println("=== Expanding function at 0x6fc982d0 ===");
        
        // Get existing function
        Function existing = fm.getFunctionAt(startAddr);
        if (existing != null) {
            println("Found existing function: " + existing.getName());
            println("Current body: " + existing.getBody());
            
            // Delete the function
            fm.removeFunction(startAddr);
            println("Removed existing function");
        }
        
        // Clear any existing code/data in the range
        AddressSet clearRange = new AddressSet(startAddr, endAddr);
        listing.clearCodeUnits(startAddr, endAddr, false);
        println("Cleared code units from " + startAddr + " to " + endAddr);
        
        // Disassemble the range
        disassemble(startAddr);
        println("Disassembled starting at " + startAddr);
        
        // Create the function
        CreateFunctionCmd cmd = new CreateFunctionCmd(startAddr);
        boolean success = cmd.applyTo(currentProgram);
        println("CreateFunctionCmd success: " + success);
        
        // Get the newly created function
        Function newFunc = fm.getFunctionAt(startAddr);
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName());
            println("New body: " + newFunc.getBody());
        } else {
            println("ERROR: Function not created");
        }
    }
}

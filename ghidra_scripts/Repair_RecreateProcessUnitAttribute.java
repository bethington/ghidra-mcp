// Recreate Process Unit Attribute
//
// Removes and recreates a specific function (ProcessUnitAttribute at 0x6fcf2660) with correct body boundaries. One-off repair for a function with incorrect size.
//
// Usage: Run from Script Manager. Hardcoded address range.
// Output: Recreates the function with correct boundaries.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Recreate ProcessUnitAttribute with proper boundaries
// @menupath Diablo 2.Repair.Recreate Process Unit Attribute

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class Repair_RecreateProcessUnitAttribute extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fcf2660L);
        Address endAddr = toAddr(0x6fcf272fL);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            String oldName = func.getName();
            fm.removeFunction(addr);
            println("Removed function: " + oldName);
        }
        
        // Clear and disassemble the range
        clearListing(addr, endAddr);
        disassemble(addr);
        
        // Create new function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        cmd.applyTo(currentProgram);
        
        Function newFunc = fm.getFunctionAt(addr);
        if (newFunc != null) {
            newFunc.setName("ProcessUnitAttribute", ghidra.program.model.symbol.SourceType.USER_DEFINED);
            println("Created function: " + newFunc.getName() + " at " + addr);
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function at " + addr);
        }
    }
}

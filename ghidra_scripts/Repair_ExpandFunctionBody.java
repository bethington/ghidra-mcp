// Expand Function Body
//
// Expands a function's body to include all code up to a specified end address. One-off repair for functions where Ghidra truncated the body before the actual RET instruction.
//
// Usage: Run from Script Manager. Edit source to change start/end addresses.
// Output: Resizes the function body to the correct boundaries.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Expand function body to correct end address
// @menupath Diablo 2.Repair.Expand Function Body

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class Repair_ExpandFunctionBody extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fcb98d0L);
        Address endAddr = toAddr(0x6fcb9a36L);  // Last RET instruction
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(startAddr);
        
        if (func == null) {
            println("ERROR: No function at " + startAddr);
            return;
        }
        
        println("Current function: " + func.getName());
        println("Current body: " + func.getBody());
        
        // Create address set from start to end
        AddressSet newBody = new AddressSet(startAddr, endAddr);
        
        try {
            func.setBody(newBody);
            println("SUCCESS: Set new body: " + func.getBody());
        } catch (Exception e) {
            println("ERROR setting body: " + e.getMessage());
        }
    }
}

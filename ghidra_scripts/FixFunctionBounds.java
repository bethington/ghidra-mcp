//Fix function bounds at 0x6fcb8040
//@author Claude
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FixFunctionBounds extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fcb8040);
        Address endAddr = toAddr(0x6fcb8093);
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(addr);
        
        if (func != null) {
            fm.removeFunction(addr);
            println("Removed existing function at " + addr);
        }
        
        // Disassemble the range first
        disassemble(addr);
        
        // Create function
        func = createFunction(addr, "FUN_6fcb8040");
        if (func != null) {
            println("Created function: " + func.getName() + " at " + func.getEntryPoint());
            println("Body: " + func.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

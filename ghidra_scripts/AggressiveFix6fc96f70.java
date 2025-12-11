//Aggressively fix function at 0x6fc96f70
//@category Fix
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.*;
import ghidra.app.cmd.disassemble.*;
import ghidra.program.model.symbol.*;

public class AggressiveFix6fc96f70 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x6fc96f70L);
        Address end = toAddr(0x6fc97070L);  // ~256 bytes should cover the function
        FunctionManager fm = currentProgram.getFunctionManager();
        
        println("Step 1: Clear all instructions in range");
        // Clear existing listings
        clearListing(start, end);
        
        println("Step 2: Disassemble from start");
        // Disassemble
        DisassembleCommand cmd = new DisassembleCommand(start, null, true);
        cmd.applyTo(currentProgram, monitor);
        
        println("Step 3: Create function");
        // Create function
        CreateFunctionCmd createCmd = new CreateFunctionCmd(start);
        createCmd.applyTo(currentProgram, monitor);
        
        // Check result
        Function func = fm.getFunctionAt(start);
        if (func != null) {
            println("SUCCESS: " + func.getName() + " body: " + func.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

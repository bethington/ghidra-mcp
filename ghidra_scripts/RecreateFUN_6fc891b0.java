//Recreate FUN_6fc891b0 with proper disassembly
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class RecreateFUN_6fc891b0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc891b0);
        
        // Remove existing broken function
        Function func = getFunctionAt(addr);
        if (func != null) {
            println("Removing existing function: " + func.getName());
            removeFunction(func);
        }
        
        // Clear any existing code/data at the location
        clearListing(addr, addr.add(0x150));
        
        // Disassemble the bytes
        DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
        disCmd.applyTo(currentProgram, monitor);
        println("Disassembly applied");
        
        // Create function
        CreateFunctionCmd funcCmd = new CreateFunctionCmd(addr);
        funcCmd.applyTo(currentProgram, monitor);
        
        // Verify
        func = getFunctionAt(addr);
        if (func != null) {
            println("Successfully created function: " + func.getName());
            println("Function body: " + func.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

// Fix function at 0x6fc82ea0
// @category Analysis
// @author GhidraMCP

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFunction6fc82ea0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc82ea0);
        
        // Clear existing function if any
        Function existingFunc = getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function at " + addr);
            removeFunction(existingFunc);
        }
        
        // Disassemble the area
        println("Disassembling at " + addr);
        DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
        cmd.applyTo(currentProgram, monitor);
        
        // Create function
        println("Creating function at " + addr);
        CreateFunctionCmd createCmd = new CreateFunctionCmd(addr);
        createCmd.applyTo(currentProgram, monitor);
        
        Function newFunc = getFunctionAt(addr);
        if (newFunc != null) {
            println("Success! Function created: " + newFunc.getName());
            println("Body size: " + newFunc.getBody().getNumAddresses() + " bytes");
        } else {
            println("Failed to create function");
        }
    }
}

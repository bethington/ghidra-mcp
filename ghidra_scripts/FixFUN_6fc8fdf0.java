//Fix function at 0x6fc8fdf0
//@author Claude
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.symbol.SourceType;

public class FixFUN_6fc8fdf0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8fdf0L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existingFunc = fm.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the range
        Address endAddr = toAddr(0x6fc8fe05L);
        println("Disassembling from " + addr + " to " + endAddr);
        disassemble(addr);
        
        // Create new function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        boolean success = cmd.applyTo(currentProgram, monitor);
        
        if (success) {
            Function newFunc = fm.getFunctionAt(addr);
            println("Created function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function: " + cmd.getStatusMsg());
        }
    }
}

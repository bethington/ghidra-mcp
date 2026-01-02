//Recreate ProcessUnitAttribute function with proper boundaries
//@category Repair
//@author GhidraMCP

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class RecreateProcessUnitAttribute extends GhidraScript {
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

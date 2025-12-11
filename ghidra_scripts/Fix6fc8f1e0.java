//Fix function 0x6fc8f1e0
//@category Repair
//@author Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class Fix6fc8f1e0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x6fc8f1e0L);
        Address end = toAddr(0x6fc8f1fcL);
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctionAt(start);
        
        if (f != null) {
            println("Removing old function");
            fm.removeFunction(start);
        }
        
        // Clear the range
        currentProgram.getListing().clearCodeUnits(start, end, false);
        
        // Disassemble
        disassemble(start);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(start);
        cmd.applyTo(currentProgram);
        
        f = fm.getFunctionAt(start);
        if (f != null) {
            println("Created: " + f.getName());
            println("Body: " + f.getBody());
        }
    }
}

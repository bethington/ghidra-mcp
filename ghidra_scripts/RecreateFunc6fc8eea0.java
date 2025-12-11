//Recreate function at 0x6fc8eea0
//@category Repair
//@menupath

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunc6fc8eea0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8eea0);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existingFunc = fm.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the area
        println("Disassembling from " + addr);
        disassemble(addr);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        cmd.applyTo(currentProgram);
        
        Function newFunc = fm.getFunctionAt(addr);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName() + " @ " + newFunc.getEntryPoint());
            println("Body: " + newFunc.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

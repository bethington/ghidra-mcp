//Recreate function at 0x6fc8f8f0
//@category Repair
//@author GhidraMCP

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunc6fc8f8f0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8f8f0L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing broken function at " + addr);
            fm.removeFunction(addr);
        }
        
        // Disassemble from start address
        println("Disassembling from " + addr);
        disassemble(addr);
        
        // Create new function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        if (cmd.applyTo(currentProgram)) {
            Function newFunc = fm.getFunctionAt(addr);
            if (newFunc != null) {
                println("SUCCESS: Created function " + newFunc.getName());
                println("Body: " + newFunc.getBody());
            }
        } else {
            println("FAILED to create function");
        }
    }
}

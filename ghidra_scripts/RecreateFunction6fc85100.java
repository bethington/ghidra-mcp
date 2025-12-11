//Recreate function at 0x6fc85100
//@category Fix
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction6fc85100 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc85100);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existingFunc = funcMgr.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing malformed function at " + addr);
            funcMgr.removeFunction(addr);
        }
        
        // Disassemble the range
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create new function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        if (cmd.applyTo(currentProgram, monitor)) {
            Function newFunc = funcMgr.getFunctionAt(addr);
            if (newFunc != null) {
                println("Created function: " + newFunc.getName());
                println("Body: " + newFunc.getBody());
            }
        } else {
            println("Failed to create function");
        }
    }
}

//Recreate function at 0x6fc8e2b0
//@category MCP
//@author Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.AddressSet;

public class RecreateFunction6fc8e2b0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8e2b0);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existingFunc = funcMgr.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function at " + addr);
            funcMgr.removeFunction(addr);
        }
        
        // Disassemble from start to 0x6fc8e340 (next function)
        Address endAddr = toAddr(0x6fc8e340);
        println("Disassembling from " + addr + " to " + endAddr);
        disassemble(addr);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        boolean success = cmd.applyTo(currentProgram);
        
        if (success) {
            Function newFunc = funcMgr.getFunctionAt(addr);
            if (newFunc != null) {
                println("SUCCESS: Created function at " + addr);
                println("Function body: " + newFunc.getBody());
            }
        } else {
            println("FAILED to create function: " + cmd.getStatusMsg());
        }
    }
}

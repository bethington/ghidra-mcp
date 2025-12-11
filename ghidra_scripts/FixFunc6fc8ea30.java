//Recreate function at 0x6fc8ea30 - simpler approach
//@category Fix
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFunc6fc8ea30 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8ea30);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Use CreateFunctionCmd which auto-detects boundaries
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        boolean success = cmd.applyTo(currentProgram, monitor);
        
        if (success) {
            Function newFunc = fm.getFunctionAt(addr);
            if (newFunc != null) {
                println("Created function: " + newFunc.getName() + " body: " + newFunc.getBody());
            }
        } else {
            println("Failed to create function: " + cmd.getStatusMsg());
        }
    }
}

//Recreate function at 0x6fc8f1e0
//@category Repair
//@author Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.listing.Listing;

public class RecreateFUN_6fc8f1e0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8f1e0L);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        
        // Remove existing function if present
        Function existing = funcMgr.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            funcMgr.removeFunction(addr);
        }
        
        // Clear and disassemble
        listing.clearCodeUnits(addr, addr.add(0x1C), false);
        disassemble(addr);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        if (cmd.applyTo(currentProgram)) {
            Function func = funcMgr.getFunctionAt(addr);
            println("SUCCESS: Created function " + func.getName() + " at " + addr);
            println("Body: " + func.getBody());
        } else {
            println("FAILED to create function at " + addr);
        }
    }
}

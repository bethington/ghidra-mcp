// Recreate FUN_6fc8f240
//@author Claude
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class RecreateFUN_6fc8f240 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8f240);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing broken function
        Function existing = funcMgr.getFunctionAt(addr);
        if (existing != null) {
            println("Removing broken function: " + existing.getName());
            funcMgr.removeFunction(addr);
        }
        
        // Disassemble from 0x6fc8f240 to 0x6fc8f2a2 (RETN 8 at 0x6fc8f29f)
        DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembled at " + addr);
        
        // Create function
        Function func = funcMgr.createFunction(null, addr, null, SourceType.USER_DEFINED);
        if (func != null) {
            println("Created function at " + addr + ": " + func.getName());
            println("Body: " + func.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

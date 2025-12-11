//Recreate function at 0x6fc8ea30
//@category Fix
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class FixFUN_6fc8ea30 extends GhidraScript {
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
        
        // Disassemble the range
        Address endAddr = toAddr(0x6fc8ea8f);
        DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembled from " + addr + " to " + endAddr);
        
        // Create new function
        Function newFunc = fm.createFunction(null, addr, 
            currentProgram.getAddressFactory().getAddressSet(addr, endAddr),
            SourceType.USER_DEFINED);
        
        if (newFunc != null) {
            println("Created function: " + newFunc.getName() + " at " + addr);
        } else {
            println("Failed to create function at " + addr);
        }
    }
}

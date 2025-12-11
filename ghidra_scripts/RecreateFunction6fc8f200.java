//Recreate function at 0x6fc8f200
//@category Custom
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;

public class RecreateFunction6fc8f200 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc8f200);
        Address endAddr = toAddr(0x6fc8f234);  // End at RETN instruction
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existingFunc = funcMgr.getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing existing function at " + startAddr);
            funcMgr.removeFunction(startAddr);
        }
        
        // Clear code at the range
        clearListing(startAddr, endAddr);
        
        // Disassemble the bytes
        DisassembleCommand cmd = new DisassembleCommand(startAddr, new AddressSet(startAddr, endAddr), true);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembled from " + startAddr + " to " + endAddr);
        
        // Create function
        Function newFunc = funcMgr.createFunction(null, startAddr, new AddressSet(startAddr, endAddr), ghidra.program.model.symbol.SourceType.USER_DEFINED);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName() + " at " + newFunc.getEntryPoint());
        } else {
            println("Failed to create function");
        }
    }
}

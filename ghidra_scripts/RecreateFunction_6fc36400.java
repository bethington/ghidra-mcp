//Recreate function at 0x6fc36400 with proper boundaries
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction_6fc36400 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc36400L);
        Address endAddr = toAddr(0x6fc36467L);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existingFunc = funcMgr.getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            funcMgr.removeFunction(startAddr);
        }
        
        // Disassemble the range first
        println("Disassembling range 0x6fc36400 - 0x6fc36467");
        disassemble(startAddr);
        
        // Create new function
        println("Creating function at 0x6fc36400");
        Function newFunc = createFunction(startAddr, "_aulldiv");
        
        if (newFunc != null) {
            println("Successfully created function: " + newFunc.getName());
            println("Entry: " + newFunc.getEntryPoint());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

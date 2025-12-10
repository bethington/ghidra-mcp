// RecreateFunction_6fa0f810.java
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6fa0f810 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address targetAddr = toAddr(0x6fa0f810L);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(targetAddr);
        
        if (existingFunc != null) {
            funcMgr.removeFunction(targetAddr);
            println("Removed function");
        }
        
        Address endAddr = targetAddr.add(0x60);
        clearListing(targetAddr, endAddr);
        disassemble(targetAddr);
        
        Function newFunc = createFunction(targetAddr, null);
        if (newFunc != null) {
            println("Created: " + newFunc.getName() + " Body: " + newFunc.getBody());
        }
    }
}

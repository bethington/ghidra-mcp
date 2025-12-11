//Recreates function at 6fc8f9e0 by clearing and re-analyzing
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction6fc8f9e0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String addrString = "6fc8f9e0";
        
        Address addr = currentProgram.getAddressFactory().getAddress(addrString);
        if (addr == null) {
            println("ERROR: Invalid address: " + addrString);
            return;
        }
        
        println("Working on program: " + currentProgram.getName());
        println("Target address: " + addr);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(addr);
        
        if (existingFunc != null) {
            println("Existing function: " + existingFunc.getName());
            println("Current body: " + existingFunc.getBody().getNumAddresses() + " bytes");
            
            println("Removing broken function...");
            funcMgr.removeFunction(existingFunc.getEntryPoint());
        }
        
        println("Disassembling at " + addrString + "...");
        clearListing(addr);
        disassemble(addr);
        
        println("Creating function at " + addrString + "...");
        Function newFunc = createFunction(addr, null);
        
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + " at " + addr);
            println("Entry point: " + newFunc.getEntryPoint());
            println("Body size: " + newFunc.getBody().getNumAddresses() + " bytes");
        } else {
            println("ERROR: Failed to create function at " + addrString);
        }
    }
}

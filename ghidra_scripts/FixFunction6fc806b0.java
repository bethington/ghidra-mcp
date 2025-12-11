//Recreates a function at 0x6fc806b0 by clearing and re-analyzing
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class FixFunction6fc806b0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String addrString = "6fc806b0";
        
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
            println("Function exists at " + addrString + ": " + existingFunc.getName());
            println("Body size: " + existingFunc.getBody().getNumAddresses() + " bytes");
            
            println("Removing malformed function...");
            funcMgr.removeFunction(addr);
        }
        
        // Clear and disassemble
        Address endAddr = addr.add(0x40);
        println("Clearing listing from " + addr + " to " + endAddr);
        clearListing(addr, endAddr);
        
        println("Disassembling at " + addrString + "...");
        disassemble(addr);
        
        // Create function
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

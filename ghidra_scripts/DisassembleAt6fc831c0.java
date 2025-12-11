//Disassembles and creates function at 0x6fc831c0
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class DisassembleAt6fc831c0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String addrString = "6fc831c0";
        Address startAddr = currentProgram.getAddressFactory().getAddress(addrString);
        Address endAddr = currentProgram.getAddressFactory().getAddress("6fc832c0"); // 256 bytes
        
        println("Disassembling range: " + startAddr + " - " + endAddr);
        
        // Clear existing function if truncated
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing truncated function: " + existingFunc.getName());
            funcMgr.removeFunction(startAddr);
        }
        
        // Clear instructions in range first
        clearListing(startAddr, endAddr);
        
        // Disassemble
        AddressSet addrSet = new AddressSet(startAddr, endAddr);
        DisassembleCommand cmd = new DisassembleCommand(addrSet, null, true);
        cmd.applyTo(currentProgram);
        
        println("Disassembly completed");
        
        // Now create function
        Function newFunc = createFunction(startAddr, null);
        if (newFunc != null) {
            println("SUCCESS: Created " + newFunc.getName() + " with " + 
                    newFunc.getBody().getNumAddresses() + " bytes");
        } else {
            println("ERROR: Could not create function");
        }
    }
}

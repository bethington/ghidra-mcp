//Fix and recreate FUN_6fc8f6c0
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFunction6fc8f6c0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc8f6c0);
        Address endAddr = toAddr(0x6fc8f83c);
        
        println("Program: " + currentProgram.getName());
        println("Fixing function at: " + startAddr);
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(startAddr);
        
        // Remove existing broken function
        if (func != null) {
            println("Removing broken function: " + func.getName());
            fm.removeFunction(startAddr);
        }
        
        // Clear the entire range
        println("Clearing range " + startAddr + " to " + endAddr);
        AddressSet addrSet = new AddressSet(startAddr, endAddr);
        clearListing(addrSet);
        
        // Disassemble the range
        println("Disassembling...");
        DisassembleCommand disCmd = new DisassembleCommand(startAddr, addrSet, true);
        disCmd.applyTo(currentProgram, monitor);
        
        // Create function
        println("Creating function...");
        CreateFunctionCmd createCmd = new CreateFunctionCmd(startAddr);
        createCmd.applyTo(currentProgram, monitor);
        
        // Verify
        func = fm.getFunctionAt(startAddr);
        if (func != null) {
            println("SUCCESS: " + func.getName());
            println("Body size: " + func.getBody().getNumAddresses() + " bytes");
        } else {
            println("ERROR: Function not created");
        }
    }
}

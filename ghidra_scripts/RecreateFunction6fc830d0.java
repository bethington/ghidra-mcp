// Recreate function at 0x6fc830d0
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;

public class RecreateFunction6fc830d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc830d0L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(existing.getEntryPoint());
        }
        
        // Clear existing instructions in the range
        Address endAddr = toAddr(0x6fc83200L);
        AddressSet range = new AddressSet(addr, endAddr);
        
        // Disassemble
        DisassembleCommand cmd = new DisassembleCommand(range, null);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembled range: " + addr + " to " + endAddr);
        
        // Create function
        Function newFunc = fm.createFunction(null, addr, range, ghidra.program.model.symbol.SourceType.ANALYSIS);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName() + " at " + newFunc.getEntryPoint());
        } else {
            println("Failed to create function at " + addr);
        }
    }
}

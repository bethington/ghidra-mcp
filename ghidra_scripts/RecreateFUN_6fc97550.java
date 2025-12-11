//Recreate function at 0x6fc97550
//@category Analysis
//@author ghidra-mcp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.symbol.SourceType;

public class RecreateFUN_6fc97550 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc97550);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the range
        DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembled at " + addr);
        
        // Create function
        Function func = fm.createFunction(null, addr, null, SourceType.ANALYSIS);
        if (func != null) {
            println("Created function: " + func.getName() + " at " + func.getEntryPoint());
            println("Body: " + func.getBody());
        } else {
            println("ERROR: Could not create function at " + addr);
        }
    }
}

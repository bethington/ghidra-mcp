//Fix truncated function at 0x6fc97210
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFUN_6fc97210 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc97210);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existingFunc = fm.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble from the address
        DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
        disCmd.applyTo(currentProgram, monitor);
        println("Disassembled at " + addr);
        
        // Create function
        CreateFunctionCmd createCmd = new CreateFunctionCmd(addr);
        createCmd.applyTo(currentProgram, monitor);
        
        Function newFunc = fm.getFunctionAt(addr);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName() + " body: " + newFunc.getBody());
        } else {
            println("ERROR: Could not create function at " + addr);
        }
    }
}

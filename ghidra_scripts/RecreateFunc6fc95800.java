// Fix function at 0x6fc95800
//@author Claude
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class RecreateFunc6fc95800 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc95800L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existingFunc = fm.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing truncated function at " + addr);
            fm.removeFunction(addr);
        }
        
        // Clear and disassemble
        clearListing(addr, addr.add(255));
        DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
        disCmd.applyTo(currentProgram, monitor);
        println("Disassembled at " + addr);
        
        // Create function
        CreateFunctionCmd createCmd = new CreateFunctionCmd(addr);
        createCmd.applyTo(currentProgram, monitor);
        
        Function newFunc = fm.getFunctionAt(addr);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName() + " at " + newFunc.getEntryPoint());
            println("Body: " + newFunc.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

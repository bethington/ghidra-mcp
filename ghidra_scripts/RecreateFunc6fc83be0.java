//Recreate function at 0x6fc83be0
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class RecreateFunc6fc83be0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc83be0L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Clear and disassemble
        println("Clearing and disassembling at " + addr);
        clearListing(addr, addr.add(300));
        
        DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
        disCmd.applyTo(currentProgram);
        
        // Create function
        CreateFunctionCmd createCmd = new CreateFunctionCmd(addr);
        boolean success = createCmd.applyTo(currentProgram);
        
        if (success) {
            Function func = fm.getFunctionAt(addr);
            println("SUCCESS: Created function " + func.getName() + " at " + addr);
            println("Body: " + func.getBody());
        } else {
            println("FAILED to create function at " + addr);
        }
    }
}

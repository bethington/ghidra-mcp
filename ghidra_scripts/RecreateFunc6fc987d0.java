//Recreate function at 0x6fc987d0
//@category Repair
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class RecreateFunc6fc987d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc987d0L);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the range
        DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
        disCmd.applyTo(currentProgram, monitor);
        println("Disassembled at " + addr);
        
        // Create function
        CreateFunctionCmd createCmd = new CreateFunctionCmd(addr);
        boolean success = createCmd.applyTo(currentProgram, monitor);
        
        if (success) {
            Function newFunc = fm.getFunctionAt(addr);
            if (newFunc != null) {
                println("SUCCESS: Created function " + newFunc.getName() + " at " + addr);
                println("Body: " + newFunc.getBody());
            }
        } else {
            println("FAILED to create function at " + addr);
        }
    }
}

//Fix function at 0x6fc987d0
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFUN_6fc987d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x6fc987d0L);
        Address end = toAddr(0x6fc9884fL);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing broken function
        Function existing = fm.getFunctionAt(start);
        if (existing != null) {
            println("Removing: " + existing.getName());
            fm.removeFunction(start);
        }
        
        // Disassemble the range
        AddressSet range = new AddressSet(start, end);
        DisassembleCommand cmd = new DisassembleCommand(range, range, true);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembled range");
        
        // Create function
        CreateFunctionCmd createCmd = new CreateFunctionCmd(start);
        if (createCmd.applyTo(currentProgram, monitor)) {
            Function f = fm.getFunctionAt(start);
            println("Created: " + f.getName() + " Body: " + f.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

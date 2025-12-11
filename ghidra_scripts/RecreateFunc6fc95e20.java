//RecreateFunc6fc95e20.java
//@category Repair
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class RecreateFunc6fc95e20 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc95e20);
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(addr);
        
        if (func != null) {
            println("Removing existing function at " + addr);
            fm.removeFunction(addr);
        }
        
        // Disassemble first
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create function
        println("Creating function at " + addr);
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        cmd.applyTo(currentProgram, monitor);
        
        func = fm.getFunctionAt(addr);
        if (func != null) {
            println("SUCCESS: Function created: " + func.getName());
            println("Body: " + func.getBody());
        } else {
            println("FAILED: No function at " + addr);
        }
    }
}

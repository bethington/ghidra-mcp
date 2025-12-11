//FixFunc6fc95e20.java
//@category Repair
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFunc6fc95e20 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc95e20);
        Address endAddr = toAddr(0x6fc96020);  // ~512 bytes should cover the function
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(startAddr);
        
        // Remove existing broken function
        if (func != null) {
            println("Removing broken function at " + startAddr);
            fm.removeFunction(startAddr);
        }
        
        // Clear and disassemble the range
        println("Clearing listing from " + startAddr + " to " + endAddr);
        clearListing(startAddr, endAddr);
        
        println("Disassembling range...");
        disassemble(startAddr);
        
        // Wait for analysis
        analyzeAll(currentProgram);
        
        // Create function
        println("Creating function at " + startAddr);
        CreateFunctionCmd cmd = new CreateFunctionCmd(startAddr);
        boolean success = cmd.applyTo(currentProgram, monitor);
        println("CreateFunctionCmd success: " + success);
        
        func = fm.getFunctionAt(startAddr);
        if (func != null) {
            println("SUCCESS: Function created: " + func.getName());
            println("Body: " + func.getBody());
            println("Entry: " + func.getEntryPoint());
        } else {
            println("FAILED: No function at " + startAddr);
        }
    }
}

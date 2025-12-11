//Fix truncated function at 0x6fc97240
//@category Repair
//@author Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class Fix6fc97240 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc97240);
        
        // Remove existing broken function
        Function func = getFunctionAt(addr);
        if (func != null) {
            println("Removing broken function: " + func.getName());
            removeFunction(func);
        }
        
        // Disassemble the range
        Address endAddr = toAddr(0x6fc972d0);
        println("Disassembling from " + addr + " to " + endAddr);
        disassemble(addr);
        
        // Create new function
        println("Creating function at " + addr);
        Function newFunc = createFunction(addr, null);
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + " body: " + newFunc.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

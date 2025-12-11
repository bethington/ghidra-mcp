//ClearAndRecreate6fc95e20.java
//@category Repair
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class ClearAndRecreate6fc95e20 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x6fc95e20);
        Address end = toAddr(0x6fc95fc0);
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        
        // Remove any existing function
        Function f = fm.getFunctionAt(start);
        if (f != null) {
            println("Removing function: " + f.getName());
            fm.removeFunction(start);
        }
        
        // Clear undefined data in the range
        println("Clearing listing from " + start + " to " + end);
        try {
            listing.clearCodeUnits(start, end, false);
        } catch (Exception e) {
            println("Clear error: " + e.getMessage());
        }
        
        // Disassemble
        println("Disassembling at " + start);
        AddressSet disasmSet = disassemble(start);
        println("Disassembled: " + disasmSet);
        
        // Create function
        println("Creating function...");
        f = createFunction(start, null);
        if (f != null) {
            println("SUCCESS: " + f.getName() + " body: " + f.getBody());
        } else {
            println("FAILED to create function");
        }
    }
}

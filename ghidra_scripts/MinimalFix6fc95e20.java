//MinimalFix6fc95e20.java
//@category Repair
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class MinimalFix6fc95e20 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc95e20);
        println("Attempting to disassemble at " + addr);
        disassemble(addr);
        println("Disassembly complete, creating function...");
        createFunction(addr, "FUN_6fc95e20");
        println("Done");
    }
}

//Quick fix for function 0x6fc98210
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class QuickFix6fc98210 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc98210);
        Function func = getFunctionAt(addr);
        if (func != null) {
            println("Removing: " + func.getName() + " body=" + func.getBody());
            removeFunction(func);
            println("Removed");
        }
        disassemble(addr);
        println("Disassembled");
        func = createFunction(addr, null);
        println("Created: " + (func != null ? func.getName() + " body=" + func.getBody() : "FAILED"));
    }
}

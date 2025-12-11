// Simple disassemble at 0x6fc956a0
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SimpleDisasm6fc956a0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc956a0L);
        println("Disassembling from " + addr);
        disassemble(addr);
        println("Done");
    }
}

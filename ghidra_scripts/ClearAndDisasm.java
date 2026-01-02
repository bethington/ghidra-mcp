//Clear and disassemble a range
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class ClearAndDisasm extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x6fccaf41L);
        Address end = toAddr(0x6fccb0ffL);
        clearListing(start, end);
        println("Cleared " + start + " to " + end);
        disassemble(toAddr(0x6fccaf40L));
        println("Disassembled from 0x6fccaf40");
    }
}

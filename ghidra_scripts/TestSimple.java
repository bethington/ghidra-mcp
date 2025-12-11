//Simple test script
//@category Test

import ghidra.app.script.GhidraScript;

public class TestSimple extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Script started");
        println("Program: " + currentProgram.getName());
        println("Script complete");
    }
}

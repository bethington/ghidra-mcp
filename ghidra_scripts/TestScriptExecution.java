//Test script execution
//@author GhidraMCP
//@category D2
//@keybinding
//@menupath D2.Test Script Execution
//@toolbar

import ghidra.app.script.GhidraScript;
import java.io.*;
import java.nio.file.*;

public class TestScriptExecution extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Script execution test started!");
        println("Current program: " + currentProgram.getName());

        // Try to write a test file
        String homeDir = System.getProperty("user.home");
        File testFile = new File(homeDir, "ghidra_test_output.txt");

        Files.write(testFile.toPath(), "Script executed successfully!".getBytes());
        println("Test file written to: " + testFile.getAbsolutePath());

        println("Script execution test completed!");
    }
}

import ghidra.app.script.GhidraScript;

public class HelloMcpTest extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Hello from HelloMcpTest");
        if (currentProgram != null) {
            println("Current program: " + currentProgram.getName());
        }
    }
}

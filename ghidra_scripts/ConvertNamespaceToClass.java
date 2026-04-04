// Create a GhidraClass and move a function into it, so __thiscall 'this' gets typed.
// Usage: run with args = "ClassName 0xAddress"
//@category MCP
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class ConvertNamespaceToClass extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("ERROR: Pass className and functionAddress as arguments");
            return;
        }
        String className = args[0];
        String funcAddr = args[1];

        SymbolTable st = currentProgram.getSymbolTable();
        Namespace global = currentProgram.getGlobalNamespace();

        // Find the function
        Address addr = currentProgram.getAddressFactory().getAddress(funcAddr);
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            println("ERROR: No function at " + funcAddr);
            return;
        }
        println("Found function: " + func.getName() + " at " + funcAddr);

        // Check if class already exists
        Namespace ns = st.getNamespace(className, global);
        GhidraClass cls;
        if (ns != null && ns instanceof GhidraClass) {
            cls = (GhidraClass) ns;
            println("Using existing GhidraClass: " + className);
        } else if (ns != null) {
            // Convert existing namespace to class
            cls = (GhidraClass) st.convertNamespaceToClass(ns);
            println("Converted namespace to GhidraClass: " + className);
        } else {
            // Create new class
            cls = st.createClass(global, className, SourceType.USER_DEFINED);
            println("Created new GhidraClass: " + className);
        }

        // Move function into the class
        func.setParentNamespace(cls);
        println("SUCCESS: Moved " + func.getName() + " into class " + cls.getName());
        println("This type should now be: " + className + " *");
    }
}
